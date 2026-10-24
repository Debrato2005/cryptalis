"""Operational CLI composition over the existing protection APIs."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib
import inspect
import json
import os
import re
import stat
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
    'missing_measured_storage_or_wal_costs', 'unsafe_runtime_role', 'maintenance_requires_table_owner',
    'invalid_reverse_plan', 'external_reverse_policy_mismatch', 'source_pin_must_be_active',
    'plaintext_approval_required', 'removal_approval_required', 'distinct_plaintext_runtime_role_required',
    'restore_binding_mismatch', 'restore_binding_required'))
_REWRAP_DENIED = _DENIED | frozenset(('invalid_rewrap_plan', 'rewrap_prepublication_pin_required',
    'matching_external_publication_required', 'rewrap_executor_required'))
_PAYLOAD_DENIED = _DENIED | frozenset(('invalid_payload_rotation_plan', 'payload_operation_pin_mismatch',
    'invalid_payload_apply_bound', 'invalid_payload_batch_bound', 'payload_activation_binding_mismatch',
    'rotation_activation_binding_mismatch', 'payload_switch_requires_prepared_or_pending_pin',
    'matching_external_publication_required', 'payload_rotation_executor_required'))
_SEARCH_DENIED = _DENIED | frozenset(('invalid_search_rotation_plan', 'search_operation_pin_mismatch',
    'invalid_payload_apply_bound', 'invalid_payload_batch_bound', 'search_activation_binding_mismatch',
    'rotation_activation_binding_mismatch', 'search_switch_requires_prepared_or_pending_pin',
    'matching_external_publication_required', 'search_rotation_executor_required',
    'search_rotation_requires_searchable_fields'))
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


def _owned_engine(context, engine_type):
    from cryptalis import cli_host as h
    contexts = (h.PlanningContext, h.ApplyContext, h.ReversePlanningContext, h.ReverseApplyContext,
        h.RemovalContext, h.RewrapPlanningContext, h.RewrapApplyContext,
        h.RewrapActivationContext, h.RewrapAbortContext, h.PayloadPlanningContext,
        h.PayloadApplyContext, h.PayloadStatusContext, h.PayloadSealingContext,
        h.PayloadSwitchContext, h.PayloadActivationContext, h.PayloadAbortContext, h.SearchPlanningContext,
        h.SearchApplyContext, h.SearchStatusContext, h.SearchSealingContext,
        h.SearchSwitchContext, h.SearchActivationContext, h.SearchAbortContext, h.InitializationContext)
    return context.engine if type(context) in contexts and isinstance(context.engine, engine_type) else None


def _summary(plan, progress=None):
    reversing = plan.document['kind'] == 'deprotect'
    prefix = 'reverse' if reversing else 'protection'
    result = dict(scope=prefix + ('_plan' if progress is None else '_transition'),
        operation_id=str(plan.operation_id), target_id=str(plan.target_id), plan_digest=plan.digest,
        phase='PREPARED' if progress is None else progress.phase,
        committed_rows=0 if progress is None else progress.committed_rows,
        committed_chunks=0 if progress is None else progress.committed_chunks,
        remedy='Persist this proposal and obtain host approval before apply.' if progress is None else progress.remedy,
        authority='HOST_SUPPLIED_CONTEXT' if progress is None else 'HOST_SUPPLIED_PIN',
        host_configuration_effects='UNKNOWN',
        effects='NONE' if progress is None else 'COMMITTED_PROGRESS')
    if reversing:
        result['source_operation_id'] = str(plan.source.operation_id)
    if progress is None:
        result.update(artifact_published=False, artifact_directory_durable=False,
                      artifact_temporary_retained=False)
    return result


def _publish(path, raw, result, operation, *, artifact_only=False):
    """Publish a complete private artifact without replacing any destination."""
    def failure(code, stage, *, exit_code=4, primary=None):
        error = _failure(operation, code, stage, exit_code=exit_code,
            result=None if artifact_only else result, primary=primary)
        if artifact_only:
            error.error.update(artifact_result=dict(result), effects='NONE')
        return error

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
        raise failure('ArtifactExists' if exists else 'ArtifactOutputUnavailable',
                      stage, exit_code=2 if exists else 4) from None
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
            raise failure('ArtifactCleanupUnavailable', 'artifact_cleanup',
                primary=primary if isinstance(primary, _CommandFailure) else None) from None


def run(arguments):
    """Compose protection, current-value reverse or approved removal APIs."""
    if arguments.command == 'init':
        return run_init(arguments)
    if arguments.command == 'keys':
        return (run_generation(arguments, arguments.rotation_kind) if arguments.rotation_kind in ('payload', 'search')
                else run_rewrap(arguments))
    from cryptalis.cli import _CommandFailure, _read_local_file, _write_output
    operation = {'plan': 'transition.plan', 'apply': 'transition.apply',
                 'rollback': 'reverse.apply', 'remove': 'reverse.remove'}.get(arguments.command, 'transition')
    try:
        from sqlalchemy.engine import Engine
        from sqlalchemy.orm import registry
        from cryptalis import migration as m, deprotection as d
        from cryptalis.cli_host import (PlanningContext, ApplyContext, ReversePlanningContext,
            ReverseApplyContext, RemovalContext, RewrapPlanningContext, RewrapApplyContext,
            RewrapActivationContext, RewrapAbortContext)
        from cryptalis.crypto.keys import Keyring
        from cryptalis.manifest.compiler import WriterInventory, SearchReview, PlanningRejected
        from cryptalis.manifest.declaration import parse_protection_declaration
        from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid
        from cryptalis.restore import RestoreBinding
    except ImportError:
        raise _failure(operation, 'DependenciesUnavailable', 'load_runtime', exit_code=4) from None

    planning = arguments.command == 'plan'
    removing = arguments.command == 'remove'
    reversing = False
    plan = result = engine = None
    try:
        if type(arguments.host_context) is not str or _HOST.fullmatch(arguments.host_context) is None:
            raise ValueError
        if planning:
            source_path = getattr(arguments, 'reverse', None)
            if (arguments.manifest is None) == (source_path is None):
                raise ValueError
            reversing = source_path is not None
            if reversing:
                operation = 'reverse.plan'
            if arguments.layout not in (None, 'preserve-public-slots/v1'):
                raise ValueError
            if reversing and arguments.layout is not None:
                raise ValueError
            if os.path.lexists(arguments.out):
                raise _failure(operation, 'ArtifactExists', 'inputs')
            raw = _read_local_file(source_path if reversing else arguments.manifest,
                                   'source_plan' if reversing else 'manifest', operation=operation)
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise ValueError
            if reversing:
                plan = m.MigrationPlan(raw)
            else:
                parse_protection_declaration(raw)
        else:
            if arguments.command not in ('apply', 'rollback', 'remove'):
                raise ValueError
            raw = _read_local_file(arguments.plan, 'plan', operation=operation)
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise ValueError
            reversing = m._decode_transition_json(raw).get('format') == d.FORMAT
            plan = d.DeprotectionPlan(raw) if reversing else m.MigrationPlan(raw)
            if not reversing and (removing or arguments.command == 'rollback' or plan.document['kind'] != 'protect'):
                raise ValueError
            if reversing:
                operation = 'reverse.remove' if removing else 'reverse.apply'
            if not removing:
                if arguments.resume is not None and arguments.abort is not None:
                    raise ValueError
                if arguments.abort is not None and arguments.until is not None:
                    raise ValueError
                allowed = d.PHASES[1:] if reversing else m.PHASES[1:]
                if arguments.until is not None and arguments.until not in allowed:
                    raise ValueError
                if type(arguments.chunk_size) is not int or not 1 <= arguments.chunk_size <= 5000:
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
        engine = _owned_engine(context, Engine)
        with _quiet():
            expected = (ReversePlanningContext if reversing else PlanningContext) if planning else (
                RemovalContext if removing else ReverseApplyContext if reversing else ApplyContext)
            if type(context) is not expected or engine is None:
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if (engine.dialect.name != 'postgresql' or engine.dialect.driver != 'psycopg'
                    or engine.dialect.is_async or (engine.echo is not False and engine.echo is not None)
                    or engine.hide_parameters is not True):
                raise _failure(operation, 'UnsafeEngine', 'host_context')
            if not removing:
                key_call = getattr(context.keys, '__call__', None)
                if (not isinstance(context.keys, Keyring) and not callable(context.keys)
                        or inspect.iscoroutinefunction(context.keys) or inspect.isasyncgenfunction(context.keys)
                        or inspect.iscoroutinefunction(key_call) or inspect.isasyncgenfunction(key_call)):
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
            if planning:
                if reversing:
                    if context.restore is not None and type(context.restore) is not RestoreBinding:
                        raise _failure(operation, 'HostContextInvalid', 'host_context')
                    plan = d.plan(plan, engine, source_pin=context.source_pin, keys=context.keys,
                        plaintext_runtime_role=context.plaintext_runtime_role,
                        backfill_rows_per_second=context.backfill_rows_per_second,
                        verify_rows_per_second=context.verify_rows_per_second,
                        temporary_bytes_per_row=context.temporary_bytes_per_row,
                        wal_bytes_per_row=context.wal_bytes_per_row, restore=context.restore)
                else:
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
                if removing:
                    progress = d.remove(plan, engine, pin=context.pin, approval=context.approval,
                                        consent=context.consent, removal=context.removal)
                elif reversing:
                    if arguments.abort is not None:
                        progress = d.abort(plan, engine, pin=context.pin, approval=context.approval,
                                           consent=context.consent)
                    else:
                        progress = d.apply(plan, engine, keys=context.keys, pin=context.pin,
                            approval=context.approval, consent=context.consent,
                            chunk_size=arguments.chunk_size, until=arguments.until or 'PLAINTEXT_PENDING')
                elif arguments.abort is not None:
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


def run_init(arguments):
    """Inspect explicit declaration intent and save its canonical bytes."""
    from cryptalis.cli import _CommandFailure, _write_output
    operation = 'initialization'
    engine = inspection = artifact = None

    def annotate(failure):
        failure.error.pop('known_result', None)
        failure.error.update(effects='NONE', effects_scope='compiler_inspection', host_configuration_effects='UNKNOWN',
            remedy='Inspect the declaration, schema inspection and artifact facts before retry. Existing files are never replaced.')
        if inspection is not None:
            failure.error['inspection'] = inspection
        if artifact is not None:
            failure.error.update(manifest_digest=artifact['manifest_digest'], artifact_result=dict(artifact))
        return failure


    try:
        from sqlalchemy.engine import Engine
        from sqlalchemy.orm import registry
        from cryptalis.cli_host import InitializationContext
        from cryptalis.doctor import preflight
        from cryptalis.manifest.compiler import WriterInventory, SearchReview
        from cryptalis.manifest.declaration import parse_protection_declaration
        from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid
    except ImportError:
        raise annotate(_failure(operation, 'DependenciesUnavailable', 'load_runtime', exit_code=4)) from None

    try:
        if type(arguments.host_context) is not str or _HOST.fullmatch(arguments.host_context) is None:
            raise _failure(operation, 'InvalidInput', 'inputs')
        if os.path.lexists(arguments.out):
            raise _failure(operation, 'ArtifactExists', 'inputs')
        context = _load_host(arguments.host_context, operation)
        engine = _owned_engine(context, Engine)
        with _quiet():
            if type(context) is not InitializationContext or engine is None:
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if (engine.dialect.name != 'postgresql' or engine.dialect.driver != 'psycopg'
                    or engine.dialect.is_async or (engine.echo is not False and engine.echo is not None)
                    or engine.hide_parameters is not True):
                raise _failure(operation, 'UnsafeEngine', 'host_context')
            if (not isinstance(context.mapping, registry) or not isinstance(context.writers, WriterInventory)
                    or type(context.search_reviews) is not tuple or type(context.declaration) is not bytes
                    or any(not isinstance(review, SearchReview) for review in context.search_reviews)):
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if len(context.declaration) > MAX_DOCUMENT_BYTES:
                raise _failure(operation, 'Manifest.Invalid', 'declaration')
            canonical = parse_protection_declaration(context.declaration).canonical_bytes()
            artifact = dict(scope='initialization_artifact', manifest_digest=hashlib.sha256(canonical).hexdigest(),
                artifact_published=False, artifact_reused=False, artifact_directory_durable=False,
                artifact_temporary_retained=False, effects='NONE')
            inspection = preflight(canonical, context.mapping, engine, writers=context.writers,
                                   search_reviews=context.search_reviews)
            if inspection['checks']['manifest_schema'] != 'PASS':
                incompatible = inspection['checks']['manifest_schema'] == 'FAIL'
                raise _failure(operation, 'SchemaIncompatible' if incompatible else 'InspectionUnavailable',
                               'inspection', exit_code=2 if incompatible else 4)
        _publish(arguments.out, canonical, artifact, operation, artifact_only=True)
        result = dict(scope='initialization', status=inspection['status'], manifest_digest=artifact['manifest_digest'],
            inspection=inspection, effects='NONE', effects_scope='compiler_inspection',
            host_configuration_effects='UNKNOWN', artifact_result=dict(artifact))
    except _CommandFailure as failure:
        raise annotate(failure)
    except ManifestInvalid:
        raise annotate(_failure(operation, 'Manifest.Invalid', 'declaration')) from None
    except BaseException:
        raise annotate(_failure(operation, 'InspectionUnavailable', 'inspection', exit_code=4)) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                with _quiet():
                    engine.dispose()
            except BaseException:
                raise annotate(_failure(operation, 'CleanupUnavailable', 'engine_cleanup', exit_code=4,
                    primary=primary if isinstance(primary, _CommandFailure) else None)) from None
    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {value}' for key, value in result.items())
    try:
        _write_output(output + '\n', sys.stdout, 'stdout')
    except _CommandFailure as failure:
        raise annotate(failure)
    return 0


def _sync_activation(path, expected, artifact, operation):
    """Verify and sync an existing private activation file without replacing it."""
    from cryptalis.cli import _CommandFailure
    descriptor = directory = None
    stage = 'artifact_verify'
    try:
        if not hasattr(os, 'O_NOFOLLOW'):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
        initial = os.fstat(descriptor)
        if (not stat.S_ISREG(initial.st_mode) or stat.S_IMODE(initial.st_mode) != 0o600
                or initial.st_size != len(expected)):
            raise ValueError
        contents = bytearray()
        while len(contents) <= len(expected):
            chunk = os.read(descriptor, min(65536, len(expected) + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
        if contents != expected:
            raise ValueError
        named = os.lstat(path)
        if (not stat.S_ISREG(named.st_mode)
                or (named.st_dev, named.st_ino) != (initial.st_dev, initial.st_ino)):
            raise ValueError
        artifact.update(artifact_published=True, artifact_reused=True, effects='ARTIFACT_REUSED')
        stage = 'artifact_file_sync'
        os.fsync(descriptor)
        stage = 'artifact_directory_sync'
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        os.fsync(directory)
        stage = 'artifact_verify'
        current, named = os.fstat(descriptor), os.lstat(path)
        if (not stat.S_ISREG(named.st_mode) or stat.S_IMODE(current.st_mode) != 0o600
                or (named.st_dev, named.st_ino) != (initial.st_dev, initial.st_ino)
                or (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                    != (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)):
            raise ValueError
        artifact['artifact_directory_durable'] = True
    except (OSError, ValueError):
        invalid = stage == 'artifact_verify'
        raise _failure(operation, 'ActivationArtifactInvalid' if invalid else 'ArtifactDurabilityUnavailable',
                       stage, exit_code=2 if invalid else 4) from None
    finally:
        primary = sys.exception()
        failed = False
        for resource in (descriptor, directory):
            if resource is not None:
                try:
                    os.close(resource)
                except Exception:
                    failed = True
        if failed:
            raise _failure(operation, 'ArtifactCleanupUnavailable', 'artifact_cleanup', exit_code=4,
                primary=primary if isinstance(primary, _CommandFailure) else None) from None


def _rewrap_summary(successor, proposal=None, progress=None):
    result = _summary(successor, progress)
    result.update(scope='rewrap_plan' if progress is None else 'rewrap_transition',
        proposal_digest=proposal.digest if proposal is not None else successor.document['rewrap_plan_digest'],
        activation_plan_digest=successor.digest,
        source_operation_id=successor.document['predecessors'][-1]['operation_id'])
    if proposal is not None and progress is None:
        result['artifact_digest'] = proposal.digest
    return result


def run_rewrap(arguments):
    """Compose the existing root-rewrap lifecycle without inferring authority."""
    from cryptalis.cli import _CommandFailure, _read_local_file, _write_output
    operation = 'rewrap.' + str(getattr(arguments, 'rewrap_action', 'invalid'))
    try:
        from sqlalchemy.engine import Engine
        from cryptalis import migration as m, rotation as r, cli_host as h
        from cryptalis.crypto.keys import Keyring
        from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid
        from cryptalis.restore import RestoreBinding
    except ImportError:
        raise _failure(operation, 'DependenciesUnavailable', 'load_runtime', exit_code=4) from None

    proposal = successor = engine = result = artifact = None
    attempted = False
    action = getattr(arguments, 'rewrap_action', None)
    try:
        if (arguments.keys_command != 'rotate' or arguments.rotation_kind != 'rewrap'
                or action not in ('plan', 'apply', 'activate', 'abort')
                or type(arguments.host_context) is not str or _HOST.fullmatch(arguments.host_context) is None):
            raise ValueError
        if action == 'plan' and os.path.lexists(arguments.out):
            raise _failure(operation, 'ArtifactExists', 'inputs')
        raw = _read_local_file(arguments.source if action == 'plan' else arguments.plan,
                               'source_plan' if action == 'plan' else 'plan', operation=operation)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError
        if action == 'plan':
            source = m.MigrationPlan(raw)
        elif action == 'activate':
            successor = m.MigrationPlan(raw)
            if successor.document['kind'] != 'rewrap':
                raise ValueError
        else:
            proposal = r.RewrapPlan(raw)
            successor = proposal.activation_plan
            if action == 'apply':
                if arguments.resume is not None and (
                        type(arguments.resume) is not UUID or arguments.resume != proposal.operation_id):
                    raise ValueError
                if os.path.lexists(arguments.out) and arguments.resume is None:
                    raise _failure(operation, 'ArtifactExists', 'inputs')
    except _CommandFailure:
        raise
    except (ManifestInvalid, m.TransitionFailure, AttributeError, TypeError, ValueError):
        failure = _failure(operation, 'InvalidInput', 'inputs')
        if successor is not None:
            failure.error['operation_id'] = str(successor.operation_id)
        raise failure from None

    def annotate(failure):
        if artifact is not None:
            failure.error['artifact_result'] = dict(artifact)
        if result is not None:
            _known_result(failure, result)
        else:
            failure.error.pop('known_result', None)
            failure.error['effects'] = 'INSPECT_JOURNAL' if attempted and action != 'plan' else 'NONE'
            if successor is not None:
                failure.error['operation_id'] = str(successor.operation_id)
        if proposal is not None:
            failure.error['proposal_digest'] = proposal.digest
        if artifact is not None:
            failure.error['remedy'] += (f' Activation artifact published={artifact["artifact_published"]}, '
                f'reused={artifact["artifact_reused"]}, durable={artifact["artifact_directory_durable"]}; '
                f'database effects={failure.error["effects"]}.')
        return failure

    try:
        if action == 'apply':
            artifact = dict(scope='rewrap_activation_artifact', operation_id=str(successor.operation_id),
                plan_digest=successor.digest, artifact_published=False, artifact_reused=False,
                artifact_directory_durable=False, artifact_temporary_retained=False, effects='NONE')
            if os.path.lexists(arguments.out):
                if arguments.resume is None:
                    raise _failure(operation, 'ArtifactExists', 'artifact_publish')
                _sync_activation(arguments.out, successor.artifact, artifact, operation)
            else:
                _publish(arguments.out, successor.artifact, artifact, operation, artifact_only=True)
        context = _load_host(arguments.host_context, operation)
        engine = _owned_engine(context, Engine)
        with _quiet():
            expected = {'plan': h.RewrapPlanningContext, 'apply': h.RewrapApplyContext,
                        'activate': h.RewrapActivationContext, 'abort': h.RewrapAbortContext}[action]
            if type(context) is not expected or engine is None:
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if (engine.dialect.name != 'postgresql' or engine.dialect.driver != 'psycopg'
                    or engine.dialect.is_async or (engine.echo is not False and engine.echo is not None)
                    or engine.hide_parameters is not True):
                raise _failure(operation, 'UnsafeEngine', 'host_context')
            resolvers = ((context.source_keys,) if action == 'abort' else
                         (context.target_keys,) if action == 'activate' else
                         (context.source_keys, context.target_keys))
            for keys in resolvers:
                key_call = getattr(keys, '__call__', None)
                if (not isinstance(keys, Keyring) and not callable(keys)
                        or inspect.iscoroutinefunction(keys) or inspect.isasyncgenfunction(keys)
                        or inspect.iscoroutinefunction(key_call) or inspect.isasyncgenfunction(key_call)):
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
            if action == 'plan':
                if context.restore is not None and type(context.restore) is not RestoreBinding:
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
                attempted = True
                proposal = r.plan_rewrap(source, engine, source_pin=context.source_pin,
                    keys=context.source_keys, target_keys=context.target_keys,
                    verify_rows_per_second=context.verify_rows_per_second, restore=context.restore)
                successor = proposal.activation_plan
                result = _rewrap_summary(successor, proposal)
            else:
                attempted = True
                if action == 'apply':
                    progress = r.apply_rewrap(proposal, engine, keys=context.source_keys,
                        target_keys=context.target_keys, pin=context.pin, approval=context.approval)
                elif action == 'activate':
                    progress = m.apply(successor, engine, keys=context.target_keys,
                                       pin=context.pin, approval=context.approval, until='ACTIVE')
                else:
                    progress = r.abort_rewrap(proposal, engine, keys=context.source_keys,
                                             pin=context.source_pin, approval=context.approval)
                result = _rewrap_summary(successor, proposal, progress)
                if artifact is not None:
                    result['artifact_result'] = dict(artifact)
        if action == 'plan':
            _publish(arguments.out, proposal.artifact, result, operation)
    except _CommandFailure as failure:
        raise annotate(failure)
    except m.TransitionFailure as error:
        code = error.code if type(error.code) is str and _CODE.fullmatch(error.code) else 'TransitionRejected'
        operational = bool(error.cleanup_errors) or code in _OPERATIONAL
        failure = _failure(operation, code, 'transition', exit_code=4 if operational else 2 if code in _REWRAP_DENIED else 3)
        failure.error['sqlstate'] = error.sqlstate if type(error.sqlstate) is str and _SQLSTATE.fullmatch(error.sqlstate) else None
        if error.cleanup_errors:
            failure.error['cleanup_errors'] = [dict(stage=stage if stage in ('rollback', 'invalidate', 'close', 'driver_close')
                else 'cleanup', cause='CleanupError', sqlstate=state if type(state) is str and _SQLSTATE.fullmatch(state) else None)
                for stage, _, state in error.cleanup_errors]
        raise annotate(failure) from None
    except BaseException:
        raise annotate(_failure(operation, 'OperationUnavailable', 'operation', exit_code=4)) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                with _quiet():
                    engine.dispose()
            except BaseException:
                failure = _failure(operation, 'CleanupUnavailable', 'engine_cleanup', exit_code=4,
                    primary=primary if isinstance(primary, _CommandFailure) else None)
                raise annotate(failure) from None

    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {value}' for key, value in result.items())
    try:
        _write_output(output + '\n', sys.stdout, 'stdout')
    except _CommandFailure as failure:
        raise annotate(failure)
    return 0


def _generation_summary(proposal, activation=None, progress=None, *, status=False, purpose):
    document = activation.document if activation is not None else proposal.document
    identity = activation.operation_id if activation is not None else proposal.operation_id
    digest = activation.digest if activation is not None else proposal.digest
    target = activation.target_id if activation is not None else proposal.source.target_id
    if status:
        scope = purpose + '_activation_status' if activation is not None else purpose + '_preparation_status'
    else:
        scope = (purpose + '_transition' if activation is not None else
                 purpose + '_preparation_plan' if progress is None else purpose + '_preparation_transition')
    result = dict(scope=scope,
        operation_id=str(identity), target_id=str(target), plan_digest=digest,
        proposal_digest=proposal.digest if proposal is not None else document[purpose + '_rotation_plan_digest'],
        phase='PREPARED' if progress is None else progress.phase,
        committed_rows=0 if progress is None else progress.committed_rows,
        committed_chunks=0 if progress is None else progress.committed_chunks,
        authority='HOST_SUPPLIED_CONTEXT' if progress is None else 'HOST_SUPPLIED_PIN',
        host_configuration_effects='UNKNOWN', effects='NONE' if progress is None or status else 'COMMITTED_PROGRESS',
        remedy='Persist this proposal and obtain host approval before apply.' if progress is None else progress.remedy)
    if activation is not None:
        result.update(activation_plan_digest=activation.digest,
            source_operation_id=document['predecessors'][-2]['operation_id'])
    else:
        result.update(source_operation_id=str(proposal.source.operation_id),
                      successor_operation_id=document['successor_operation_id'])
    if status:
        result.update(external_phase=progress.external_phase,
                      runtime_metadata_matches=progress.runtime_metadata_matches, verification=progress.verification)
    if progress is None:
        result['artifact_digest'] = proposal.digest
    return result


def run_generation(arguments, purpose):
    """Compose admitted generation preparation, authenticated sealing and publication."""
    from cryptalis.cli import _CommandFailure, _read_local_file, _write_output
    operation = purpose + '.' + str(getattr(arguments, purpose + '_action', 'invalid'))
    if purpose not in ('payload', 'search'):
        raise _failure(operation, 'InvalidInput', 'inputs')
    try:
        from sqlalchemy.engine import Engine
        from cryptalis import migration as m, rotation as r, cli_host as h
        from cryptalis.crypto.keys import Keyring
        from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid
        from cryptalis.restore import RestoreBinding
    except ImportError:
        raise _failure(operation, 'DependenciesUnavailable', 'load_runtime', exit_code=4) from None

    proposal = activation = engine = result = known = artifact = None
    attempted = False
    action = getattr(arguments, purpose + '_action', None)
    plan_type = r.PayloadRotationPlan if purpose == 'payload' else r.SearchRotationPlan
    prefix = 'Payload' if purpose == 'payload' else 'Search'
    denied = _PAYLOAD_DENIED if purpose == 'payload' else _SEARCH_DENIED
    functions = {name: getattr(r, name + '_' + purpose + '_rotation')
                 for name in ('plan', 'apply', 'status', 'abort', 'seal', 'switch')}
    try:
        if (arguments.keys_command != 'rotate' or arguments.rotation_kind != purpose
                or action not in ('plan', 'apply', 'status', 'seal', 'switch', 'activate', 'abort')
                or type(arguments.host_context) is not str or _HOST.fullmatch(arguments.host_context) is None):
            raise ValueError
        if action in ('plan', 'seal') and os.path.lexists(arguments.out):
            raise _failure(operation, 'ArtifactExists', 'inputs')
        raw = _read_local_file(arguments.source if action == 'plan' else arguments.plan,
                               'source_plan' if action == 'plan' else 'plan', operation=operation)
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise ValueError
        if action == 'plan':
            source = m.MigrationPlan(raw)
            for name, bound in (('max_batch_rows', r.MAX_BATCH_ROWS), ('max_batch_bytes', r.MAX_BATCH_BYTES)):
                value = getattr(arguments, name)
                if value is not None and (type(value) is not int or not 1 <= value <= bound):
                    raise ValueError
        elif action in ('activate', 'status'):
            if action == 'status' and m._decode_transition_json(raw).get('format') in (
                    plan_type.format, plan_type.restore_format):
                proposal = plan_type(raw)
            else:
                activation = m.MigrationPlan(raw)
                if activation.document['kind'] != purpose + '_rotation':
                    raise ValueError
        else:
            proposal = plan_type(raw)
        if action == 'switch':
            raw = _read_local_file(arguments.activation, 'activation', operation=operation)
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise ValueError
            activation = m.MigrationPlan(raw)
            if (activation.document['kind'] != purpose + '_rotation'
                    or str(activation.operation_id) != proposal.document['successor_operation_id']
                    or activation.document[purpose + '_rotation_plan_digest'] != proposal.digest):
                raise ValueError
        if action in ('apply', 'switch'):
            identity = proposal.operation_id if action == 'apply' else activation.operation_id
            if arguments.resume is not None and (type(arguments.resume) is not UUID or arguments.resume != identity):
                raise ValueError
        if action == 'apply':
            if (arguments.until not in (None, 'EXPANDED', 'BACKFILLED') or arguments.max_chunks is not None
                    and (type(arguments.max_chunks) is not int or arguments.max_chunks < 1)):
                raise ValueError
    except _CommandFailure:
        raise
    except (ManifestInvalid, m.TransitionFailure, AttributeError, KeyError, TypeError, ValueError):
        raise _failure(operation, 'InvalidInput', 'inputs') from None

    def annotate(failure):
        if artifact is not None:
            failure.error['artifact_result'] = dict(artifact)
        if known is not None:
            _known_result(failure, known)
        else:
            failure.error.pop('known_result', None)
            failure.error['effects'] = 'INSPECT_JOURNAL' if attempted and action in (
                'apply', 'switch', 'activate', 'abort') else 'NONE'
            if activation is not None or proposal is not None:
                failure.error['operation_id'] = str(activation.operation_id if activation is not None else proposal.operation_id)
        if proposal is not None:
            failure.error['proposal_digest'] = proposal.digest
        if artifact is not None:
            failure.error['remedy'] = failure.error.get('remedy', 'Retain the exact artifacts and inspect the reported outcome.') + (f' Artifact published={artifact["artifact_published"]}, '
                f'reused={artifact["artifact_reused"]}, durable={artifact["artifact_directory_durable"]}; '
                f'database effects={failure.error["effects"]}.')
        return failure

    try:
        if action == 'switch':
            artifact = dict(scope=purpose + '_activation_artifact', operation_id=str(activation.operation_id),
                plan_digest=activation.digest, activation_plan_digest=activation.digest, proposal_digest=proposal.digest,
                artifact_published=False, artifact_reused=False, artifact_directory_durable=False,
                artifact_temporary_retained=False, effects='NONE')
            _sync_activation(arguments.activation, activation.artifact, artifact, operation)
        context = _load_host(arguments.host_context, operation)
        engine = _owned_engine(context, Engine)
        with _quiet():
            expected = {'plan': getattr(h, prefix + 'PlanningContext'), 'apply': getattr(h, prefix + 'ApplyContext'),
                'status': getattr(h, prefix + 'StatusContext'), 'seal': getattr(h, prefix + 'SealingContext'),
                'switch': getattr(h, prefix + 'SwitchContext'), 'activate': getattr(h, prefix + 'ActivationContext'),
                'abort': getattr(h, prefix + 'AbortContext')}[action]
            if type(context) is not expected or engine is None:
                raise _failure(operation, 'HostContextInvalid', 'host_context')
            if (engine.dialect.name != 'postgresql' or engine.dialect.driver != 'psycopg'
                    or engine.dialect.is_async or (engine.echo is not False and engine.echo is not None)
                    or engine.hide_parameters is not True):
                raise _failure(operation, 'UnsafeEngine', 'host_context')
            resolvers = (() if action == 'status' else (context.source_keys,) if action == 'abort' else
                         (context.target_keys,) if action == 'activate' else (context.source_keys, context.target_keys))
            for keys in resolvers:
                key_call = getattr(keys, '__call__', None)
                if (not isinstance(keys, Keyring) and not callable(keys)
                        or inspect.iscoroutinefunction(keys) or inspect.isasyncgenfunction(keys)
                        or inspect.iscoroutinefunction(key_call) or inspect.isasyncgenfunction(key_call)):
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
            if action == 'plan':
                if context.restore is not None and type(context.restore) is not RestoreBinding:
                    raise _failure(operation, 'HostContextInvalid', 'host_context')
                limits = {name: getattr(arguments, name) for name in ('max_batch_rows', 'max_batch_bytes')
                          if getattr(arguments, name) is not None}
                attempted = True
                proposal = functions['plan'](source, engine, source_pin=context.source_pin,
                    keys=context.source_keys, target_keys=context.target_keys,
                    backfill_rows_per_second=context.backfill_rows_per_second,
                    verify_rows_per_second=context.verify_rows_per_second,
                    temporary_bytes_per_row=context.temporary_bytes_per_row,
                    wal_bytes_per_row=context.wal_bytes_per_row, restore=context.restore, **limits)
                result = _generation_summary(proposal, purpose=purpose)
            elif action == 'seal':
                attempted = True
                activation = functions['seal'](proposal, engine, keys=context.source_keys,
                    target_keys=context.target_keys, pin=context.pin, approval=context.approval,
                    copy_rows_per_second=context.copy_rows_per_second,
                    copy_wal_bytes_per_row=context.copy_wal_bytes_per_row)
            else:
                attempted = True
                if action == 'apply':
                    progress = functions['apply'](proposal, engine, keys=context.source_keys,
                        target_keys=context.target_keys, pin=context.pin, approval=context.approval,
                        until=arguments.until or 'BACKFILLED', max_chunks=arguments.max_chunks)
                elif action == 'switch':
                    progress = functions['switch'](proposal, activation, engine, keys=context.source_keys,
                        target_keys=context.target_keys, pin=context.pin, approval=context.approval)
                elif action == 'activate':
                    progress = m.apply(activation, engine, keys=context.target_keys,
                                       pin=context.pin, approval=context.approval, until='ACTIVE')
                elif action == 'abort':
                    progress = functions['abort'](proposal, engine, keys=context.source_keys,
                                                       source_pin=context.source_pin, approval=context.approval)
                else:
                    progress = (m.status(activation, engine, pin=context.pin) if activation is not None else
                                functions['status'](proposal, engine, pin=context.pin))
                result = known = _generation_summary(proposal, activation, progress, status=action == 'status', purpose=purpose)
                if artifact is not None:
                    result['artifact_result'] = dict(artifact)
        if action in ('plan', 'seal'):
            output_plan = activation if action == 'seal' else proposal
            artifact = dict(scope=purpose + '_activation_artifact' if action == 'seal' else purpose + '_preparation_artifact',
                operation_id=str(output_plan.operation_id), plan_digest=output_plan.digest, proposal_digest=proposal.digest,
                artifact_published=False, artifact_reused=False, artifact_directory_durable=False,
                artifact_temporary_retained=False, effects='NONE')
            if action == 'seal':
                artifact.update(activation_plan_digest=activation.digest, artifact_sealed=True)
            _publish(arguments.out, output_plan.artifact, artifact, operation, artifact_only=True)
            if action == 'seal':
                result = dict(artifact, authority='HOST_SUPPLIED_PIN', host_configuration_effects='UNKNOWN', database_effects='NONE')
            else:
                result.update({name: artifact[name] for name in ('artifact_published', 'artifact_reused',
                    'artifact_directory_durable', 'artifact_temporary_retained')})
            result['artifact_result'] = dict(artifact)
    except _CommandFailure as failure:
        raise annotate(failure)
    except m.TransitionFailure as error:
        code = error.code if type(error.code) is str and _CODE.fullmatch(error.code) else 'TransitionRejected'
        operational = bool(error.cleanup_errors) or code in _OPERATIONAL
        failure = _failure(operation, code, 'transition', exit_code=4 if operational else 2 if code in denied else 3)
        failure.error['sqlstate'] = error.sqlstate if type(error.sqlstate) is str and _SQLSTATE.fullmatch(error.sqlstate) else None
        if error.cleanup_errors:
            failure.error['cleanup_errors'] = [dict(stage=stage if stage in ('rollback', 'invalidate', 'close', 'driver_close')
                else 'cleanup', cause='CleanupError', sqlstate=state if type(state) is str and _SQLSTATE.fullmatch(state) else None)
                for stage, _, state in error.cleanup_errors]
        raise annotate(failure) from None
    except BaseException:
        raise annotate(_failure(operation, 'OperationUnavailable', 'operation', exit_code=4)) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                with _quiet():
                    engine.dispose()
            except BaseException:
                raise annotate(_failure(operation, 'CleanupUnavailable', 'engine_cleanup', exit_code=4,
                    primary=primary if isinstance(primary, _CommandFailure) else None)) from None

    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {value}' for key, value in result.items())
    try:
        _write_output(output + '\n', sys.stdout, 'stdout')
    except _CommandFailure as failure:
        raise annotate(failure)
    return 0
