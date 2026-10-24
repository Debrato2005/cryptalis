"""Operational CLI composition over the existing protection APIs."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib
import inspect
import json
import os
import re
import sys
import tempfile
from types import CoroutineType
from uuid import UUID


_HOST = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*\Z')
_CODE = re.compile(r'[A-Za-z][A-Za-z0-9_.:,-]{0,127}\Z')
_SQLSTATE = re.compile(r'[0-9A-Z]{5}\Z')
_DENIED = frozenset(('external_policy_mismatch', 'wrong_database_target', 'invalid_plan',
    'maintenance_approval_required', 'writer_exclusion_or_pause_not_approved',
    'invalid_target_or_runtime_role', 'invalid_apply_bound', 'missing_measured_rates',
    'missing_measured_storage_or_wal_costs', 'unsafe_runtime_role', 'maintenance_requires_table_owner'))
_OPERATIONAL = frozenset(('database_effect_requires_inspection', 'operation_failed_requires_inspection',
    'connection_cleanup_requires_inspection', 'KeyUnavailable', 'CryptoBackendUnavailable'))


def _known_result(failure, result):
    failure.error.update(known_result=dict(result), operation_id=result['operation_id'], effects=result['effects'])
    failure.error['remedy'] = (f'Last returned phase={result["phase"]}, '
        f'committed_rows={result["committed_rows"]}, committed_chunks={result["committed_chunks"]}, '
        f'effects={result["effects"]}. Inspect the original artifact and current host authority before retry.')


def _failure(operation, code, stage, *, exit_code=2, result=None, primary=None):
    from cryptalis.cli import _CommandFailure
    failure = _CommandFailure('Inspect the supplied inputs, trusted host context and original operation before retry.',
        family='Transition', code=code, operation=operation, stage=stage,
        cause=code, exit_code=exit_code)
    failure.error.update(host_configuration_effects='UNKNOWN',
                         remedy='Keep writers stopped. Inspect the original artifact and current host authority before retry.')
    if result is not None:
        _known_result(failure, result)
    if primary is not None:
        failure.error['related_error'] = primary.error
    return failure


@contextmanager
def _quiet():
    # Native descriptor writes and pre-existing log handlers are trusted-host effects.
    with open(os.devnull, 'w', encoding='utf-8') as discard, \
            redirect_stdout(discard), redirect_stderr(discard):
        yield


def _load_host(specification, operation):
    if type(specification) is not str or _HOST.fullmatch(specification) is None:
        raise _failure(operation, 'HostContextInvalid', 'host_context')
    module_name, factory_name = specification.split(':')
    try:
        with _quiet():
            factory = getattr(importlib.import_module(module_name), factory_name)
            if not callable(factory) or inspect.iscoroutinefunction(factory) or inspect.isasyncgenfunction(factory):
                raise TypeError
            context = factory()
            if isinstance(context, CoroutineType):
                context.close()
                raise TypeError
            if inspect.isawaitable(context) or inspect.isasyncgen(context):
                raise TypeError
    except BaseException:
        # Neither exception text nor a host-defined exception class is a diagnostic.
        raise _failure(operation, 'HostContextUnavailable', 'host_context', exit_code=4) from None
    return context


def _summary(plan, progress=None):
    result = dict(scope='protection_plan' if progress is None else 'protection_transition',
        operation_id=str(plan.operation_id), target_id=str(plan.target_id), plan_digest=plan.digest,
        phase='PREPARED' if progress is None else progress.phase,
        committed_rows=0 if progress is None else progress.committed_rows,
        committed_chunks=0 if progress is None else progress.committed_chunks,
        remedy='Persist this proposal and obtain host approval before apply.' if progress is None else progress.remedy,
        authority='HOST_SUPPLIED_CONTEXT' if progress is None else 'HOST_SUPPLIED_PIN',
        host_configuration_effects='UNKNOWN',
        effects='NONE' if progress is None else 'COMMITTED_PROGRESS')
    if progress is None:
        result.update(artifact_published=False, artifact_directory_durable=False,
                      artifact_temporary_retained=False)
    return result


def _publish(path, raw, result, operation):
    """Publish a complete private artifact without replacing any destination."""
    descriptor = temporary = None
    stage = 'artifact_create'
    try:
        descriptor, temporary = tempfile.mkstemp(prefix='.cryptalis-plan-', dir=path.parent)
        result.update(artifact_temporary_retained=True, effects='ARTIFACT_TEMPORARY')
        os.fchmod(descriptor, 0o600)
        stage = 'artifact_write'
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError
            remaining = remaining[written:]
        os.fsync(descriptor)
        stage = 'artifact_close'
        closing, descriptor = descriptor, None
        os.close(closing)
        stage = 'artifact_publish'
        os.link(temporary, path, follow_symlinks=False)
        result.update(artifact_published=True, effects='ARTIFACT_PUBLISHED')
        stage = 'artifact_cleanup'
        os.unlink(temporary)
        temporary = None
        result['artifact_temporary_retained'] = False
        stage = 'artifact_directory_sync'
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        os.fsync(descriptor)
        closing, descriptor = descriptor, None
        os.close(closing)
        result['artifact_directory_durable'] = True
    except Exception as error:
        exists = isinstance(error, FileExistsError) and stage == 'artifact_publish'
        raise _failure(operation, 'ArtifactExists' if exists else 'ArtifactOutputUnavailable',
                       stage, exit_code=2 if exists else 4, result=result) from None
    finally:
        primary = sys.exception()
        cleanup_failed = False
        if descriptor is not None:
            try:
                os.close(descriptor)
            except Exception:
                cleanup_failed = True
        if temporary is not None:
            try:
                os.unlink(temporary)
                result['artifact_temporary_retained'] = False
                if not result['artifact_published']:
                    result['effects'] = 'NONE'
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            from cryptalis.cli import _CommandFailure
            raise _failure(operation, 'ArtifactCleanupUnavailable', 'artifact_cleanup',
                exit_code=4, result=result,
                primary=primary if isinstance(primary, _CommandFailure) else None) from None


def run(arguments):
    """Run one protection plan/apply command with explicit host authority."""
    from cryptalis.cli import _CommandFailure, _read_local_file, _write_output
    operation = 'transition.plan' if arguments.command == 'plan' else 'transition.apply'
    try:
        from sqlalchemy.engine import Engine
        from sqlalchemy.orm import registry
        from cryptalis import migration as m
        from cryptalis.cli_host import PlanningContext, ApplyContext
        from cryptalis.crypto.keys import Keyring
        from cryptalis.manifest.compiler import WriterInventory, SearchReview, PlanningRejected
        from cryptalis.manifest.declaration import parse_protection_declaration
        from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid
    except ImportError:
        raise _failure(operation, 'DependenciesUnavailable', 'load_runtime', exit_code=4) from None

    planning = arguments.command == 'plan'
    plan = result = engine = None
    try:
        if type(arguments.host_context) is not str or _HOST.fullmatch(arguments.host_context) is None:
            raise ValueError
        if planning:
            if arguments.layout not in (None, 'preserve-public-slots/v1'):
                raise ValueError
            if os.path.lexists(arguments.out):
                raise _failure(operation, 'ArtifactExists', 'inputs')
            raw = _read_local_file(arguments.manifest, 'manifest', operation=operation)
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise ValueError
            parse_protection_declaration(raw)
        else:
            if arguments.command != 'apply' or (arguments.resume is not None and arguments.abort is not None):
                raise ValueError
            if arguments.abort is not None and arguments.until is not None:
                raise ValueError
            if arguments.until not in (None, 'EXPANDED', 'BACKFILLED', 'VERIFIED', 'PENDING', 'ACTIVE'):
                raise ValueError
            if type(arguments.chunk_size) is not int or not 1 <= arguments.chunk_size <= 5000:
                raise ValueError
            raw = _read_local_file(arguments.plan, 'plan', operation=operation)
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise ValueError
            plan = m.MigrationPlan(raw)
            if plan.document['kind'] != 'protect':
                raise ValueError
            for selected in (arguments.resume, arguments.abort):
                if selected is not None and (type(selected) is not UUID or selected != plan.operation_id):
                    raise ValueError
    except _CommandFailure:
        raise
    except (ManifestInvalid, m.TransitionFailure, TypeError, ValueError, AttributeError):
        failure = _failure(operation, 'InvalidInput', 'inputs')
        if plan is not None:
            failure.error['operation_id'] = str(plan.operation_id)
        raise failure from None

    try:
        context = _load_host(arguments.host_context, operation)
        if type(context) in (PlanningContext, ApplyContext) and isinstance(context.engine, Engine):
            engine = context.engine
        with _quiet():
            expected = PlanningContext if planning else ApplyContext
            if type(context) is not expected or engine is None:
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if (engine.dialect.name != 'postgresql' or engine.dialect.driver != 'psycopg'
                    or engine.dialect.is_async or (engine.echo is not False and engine.echo is not None)
                    or engine.hide_parameters is not True):
                raise _failure(operation, 'UnsafeEngine', 'host_context')
            key_call = getattr(context.keys, '__call__', None)
            if (not isinstance(context.keys, Keyring) and not callable(context.keys)
                    or inspect.iscoroutinefunction(context.keys) or inspect.isasyncgenfunction(context.keys)
                    or inspect.iscoroutinefunction(key_call) or inspect.isasyncgenfunction(key_call)):
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if planning:
                if (not isinstance(context.mapping, registry) or not isinstance(context.writers, WriterInventory)
                        or type(context.search_reviews) is not tuple
                        or any(not isinstance(review, SearchReview) for review in context.search_reviews)):
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
                plan = m.plan(raw, context.mapping, engine, writers=context.writers,
                    search_reviews=context.search_reviews, keys=context.keys,
                    runtime_role=context.runtime_role, target_id=context.target_id,
                    backfill_rows_per_second=context.backfill_rows_per_second,
                    verify_rows_per_second=context.verify_rows_per_second,
                    temporary_bytes_per_row=context.temporary_bytes_per_row,
                    wal_bytes_per_row=context.wal_bytes_per_row, layout=arguments.layout)
                result = _summary(plan)
            else:
                if arguments.abort is not None:
                    progress = m.abort(plan, engine, pin=context.pin, approval=context.approval)
                else:
                    progress = m.apply(plan, engine, keys=context.keys, pin=context.pin,
                        approval=context.approval, chunk_size=arguments.chunk_size,
                        until=arguments.until or 'PENDING')
                result = _summary(plan, progress)
        if planning:
            _publish(arguments.out, plan.artifact, result, operation)
    except _CommandFailure as failure:
        if result is not None:
            _known_result(failure, result)
        elif not planning:
            failure.error.update(operation_id=str(plan.operation_id), effects='INSPECT_JOURNAL')
        raise
    except m.TransitionFailure as error:
        code = error.code if type(error.code) is str and _CODE.fullmatch(error.code) else 'TransitionRejected'
        operational = bool(error.cleanup_errors) or code in _OPERATIONAL
        failure = _failure(operation, code, 'transition', exit_code=4 if operational else 2 if code in _DENIED else 3,
                           result=result)
        failure.error.update(effects='NONE' if planning else 'INSPECT_JOURNAL')
        if plan is not None:
            failure.error['operation_id'] = str(plan.operation_id)
        failure.error['sqlstate'] = error.sqlstate if type(error.sqlstate) is str and _SQLSTATE.fullmatch(error.sqlstate) else None
        if error.cleanup_errors:
            failure.error['cleanup_errors'] = [dict(stage=stage if stage in ('rollback', 'invalidate', 'close', 'driver_close')
                else 'cleanup', cause='CleanupError', sqlstate=state if type(state) is str and _SQLSTATE.fullmatch(state) else None)
                for stage, _, state in error.cleanup_errors]
        raise failure from None
    except PlanningRejected:
        raise _failure(operation, 'SchemaIncompatible', 'planning', exit_code=3) from None
    except BaseException:
        failure = _failure(operation, 'OperationUnavailable', 'operation', exit_code=4, result=result)
        failure.error['effects'] = result['effects'] if result is not None else 'NONE' if planning else 'INSPECT_JOURNAL'
        if plan is not None:
            failure.error['operation_id'] = str(plan.operation_id)
        raise failure from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                with _quiet():
                    engine.dispose()
            except BaseException:
                failure = _failure(operation, 'CleanupUnavailable', 'engine_cleanup', exit_code=4,
                    result=result, primary=primary if isinstance(primary, _CommandFailure) else None)
                if result is None:
                    failure.error['effects'] = 'NONE' if planning else 'INSPECT_JOURNAL'
                if plan is not None:
                    failure.error['operation_id'] = str(plan.operation_id)
                raise failure from None

    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {value}' for key, value in result.items())
    try:
        _write_output(output + '\n', sys.stdout, 'stdout')
    except _CommandFailure as failure:
        _known_result(failure, result)
        raise
    return 0
