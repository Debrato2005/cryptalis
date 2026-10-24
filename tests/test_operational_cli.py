"""Operational CLI delegates real lifecycle work to explicit host authority."""
from dataclasses import replace
from pathlib import Path
import errno
import io
import json
import os
import stat
import sys
from types import ModuleType
from uuid import uuid4

import pytest
from sqlalchemy import event

from cryptalis import cli, migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_migration import application, engine, frames, keys, run, FIELD_ID, TABLE_ID
from test_owned_sequences import _snapshot


PRIVATE = 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER'


def invoke(capsys, *arguments):
    code = cli.main(list(arguments))
    captured = capsys.readouterr()
    assert PRIVATE not in captured.out + captured.err
    assert 'Traceback' not in captured.out + captured.err
    for variable in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
        assert os.environ[variable] not in captured.out + captured.err
    return code, captured.out, captured.err


def success(result, plan, phase):
    code, output, error = result
    assert code == 0 and error == '', (code, error)
    summary = json.loads(output)
    assert summary['operation_id'] == str(plan.operation_id)
    assert summary['target_id'] == str(plan.target_id) and summary['plan_digest'] == plan.digest
    authority = 'HOST_SUPPLIED_CONTEXT' if summary['scope'] == 'protection_plan' else 'HOST_SUPPLIED_PIN'
    assert summary['phase'] == phase and summary['authority'] == authority
    assert summary['host_configuration_effects'] == 'UNKNOWN'
    return summary


def host(app, monkeypatch, *, planning=False, **options):
    """Each invocation transfers one fresh engine to the CLI, never app.owner."""
    module = ModuleType('operational_cli_host_' + uuid4().hex)
    observed = {'factory': 0, 'connect': 0, 'keys': 0, 'dispose': 0}
    configuration = dict(pin=app.pin, approval=app.approval, resolver=keys)
    configuration.update(options)

    def factory():
        observed['factory'] += 1
        if configuration.get('factory_failure'):
            print(PRIVATE)
            raise RuntimeError(PRIVATE)
        # Lazy import preserves genuine old-command RED before the new API exists.
        from cryptalis.cli_host import ApplyContext, PlanningContext
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        if configuration.get('echo'):
            owned.echo = True
        if configuration.get('visible_parameters'):
            owned.hide_parameters = False
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        def disposed(*args):
            observed['dispose'] += 1
            if configuration.get('dispose_failure'):
                print(PRIVATE)
                raise OSError(PRIVATE)
        event.listen(owned, 'engine_disposed', disposed)
        def resolver(tenant):
            observed['keys'] += 1
            return configuration['resolver'](tenant)
        if planning:
            return PlanningContext(engine=owned, mapping=app.mapping,
                writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned synthetic application'),)),
                search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),),
                keys=resolver, runtime_role=app.role, target_id=app.plan.target_id,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        return ApplyContext(engine=owned, keys=resolver, pin=configuration['pin'], approval=configuration['approval'])
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


def inputs(app, directory):
    plan = directory / 'plan.json'
    manifest = directory / 'manifest.json'
    plan.write_bytes(app.plan.artifact)
    manifest.write_bytes(m._canonical(app.plan.document['lock']['declaration']))
    return plan, manifest


def test_plan_is_read_only_and_atomically_publishes_private_exact_artifact(tmp_path, monkeypatch, capsys):
    with application() as app:
        _, manifest = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, planning=True)
        output = tmp_path / 'new-plan.json'
        before = _snapshot(app)
        result = invoke(capsys, 'plan', str(manifest), '--host-context', reference,
                        '--out', str(output), '--layout', 'preserve-public-slots/v1', '--json')
        assert result[0] == 0, result[2]
        plan = m.MigrationPlan(output.read_bytes())
        summary = success(result, plan, 'PREPARED')
        assert summary['scope'] == 'protection_plan'
        assert summary['artifact_published'] is summary['artifact_directory_durable'] is True
        assert summary['committed_rows'] == 0 and plan.document['lock']['schema'] == 'cryptalis.lock/v6'
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert _snapshot(app) == before and observed['factory'] == observed['dispose'] == 1
        original = output.read_bytes()
        prior_calls = observed['factory']
        refused = invoke(capsys, 'plan', str(manifest), '--host-context', reference, '--out', str(output), '--json')
        assert refused[0] != 0 and refused[1] == ''
        assert output.read_bytes() == original and observed['factory'] == prior_calls
        assert _snapshot(app) == before


def test_apply_committed_chunks_resume_pending_and_explicit_host_publication(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        reference, configuration, observed = host(app, monkeypatch)
        summary = success(invoke(capsys, 'apply', str(path), '--host-context', reference,
            '--until', 'BACKFILLED', '--chunk-size', '2', '--json'), app.plan, 'BACKFILLED')
        assert summary['committed_rows'] == 7
        prefix = frames(app)
        success(invoke(capsys, 'apply', str(path), '--host-context', reference, '--resume', str(app.plan.operation_id),
            '--until', 'VERIFIED', '--chunk-size', '2', '--json'), app.plan, 'VERIFIED')
        assert frames(app) == prefix
        success(invoke(capsys, 'apply', str(path), '--host-context', reference, '--resume', str(app.plan.operation_id),
            '--until', 'PENDING', '--json'), app.plan, 'PENDING')
        assert frames(app, True) == prefix
        pending = _snapshot(app)
        refused = invoke(capsys, 'apply', str(path), '--host-context', reference, '--until', 'ACTIVE', '--json')
        assert refused[0] != 0 and refused[1] == '' and _snapshot(app) == pending
        configuration['pin'] = replace(app.pin, phase='ACTIVATING')
        success(invoke(capsys, 'apply', str(path), '--host-context', reference, '--until', 'ACTIVE', '--json'), app.plan, 'ACTIVE')
        assert frames(app, True) == prefix
        assert m.status(app.plan, app.owner, pin=replace(app.pin, phase='ACTIVE')).runtime_metadata_matches
        assert observed['factory'] == observed['dispose']


def test_abort_uses_host_source_pin_without_provider_work_and_is_terminal(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        run(app, until='EXPANDED')
        def unavailable(tenant): pytest.fail('pre-switch abort must not resolve provider keys')
        reference, _, observed = host(app, monkeypatch, resolver=unavailable)
        summary = success(invoke(capsys, 'apply', str(path), '--host-context', reference,
            '--abort', str(app.plan.operation_id), '--json'), app.plan, 'ABORTED')
        assert summary['committed_rows'] == 0 and observed['keys'] == 0
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'ABORTED'
        before = _snapshot(app)
        success(invoke(capsys, 'apply', str(path), '--host-context', reference,
            '--abort', str(app.plan.operation_id), '--json'), app.plan, 'ABORTED')
        assert _snapshot(app) == before and observed['factory'] == observed['dispose']


@pytest.mark.parametrize('fault', ['manifest', 'plan', 'resume_identity', 'chunk_size'])
def test_invalid_input_refuses_before_host_code_and_database(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        path, manifest = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, planning=fault == 'manifest')
        before = _snapshot(app)
        if fault == 'manifest':
            manifest.write_text('{"PRIVATE_OPERATIONAL_HOST_OR_PROVIDER":true}')
            arguments = ('plan', str(manifest), '--host-context', reference, '--out', str(tmp_path / 'unused.json'))
        else:
            extra = ('--resume', str(uuid4())) if fault == 'resume_identity' else ('--chunk-size', '0') if fault == 'chunk_size' else ()
            if fault == 'plan': path.write_text('{"PRIVATE_OPERATIONAL_HOST_OR_PROVIDER":true}')
            arguments = ('apply', str(path), '--host-context', reference, *extra)
        code, output, error = invoke(capsys, *arguments, '--json')
        assert code == 2 and output == '' and json.loads(error)['error']
        assert observed['factory'] == observed['connect'] == observed['keys'] == 0
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['pin', 'approval', 'echo', 'visible_parameters'])
def test_host_authority_or_unsafe_engine_denial_has_no_database_effects(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        reference, configuration, observed = host(app, monkeypatch)
        if fault == 'pin': configuration['pin'] = replace(app.pin, plan_digest='0' * 64)
        elif fault == 'approval': configuration['approval'] = m.MaintenanceApproval('', 0)
        else: configuration[fault] = True
        before = _snapshot(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        assert code == 2 and output == '' and json.loads(error)['error']
        assert observed['connect'] == observed['keys'] == 0
        assert observed['factory'] == observed['dispose'] == 1 and _snapshot(app) == before


def test_provider_outage_retains_native_expanded_checkpoint_then_resumes(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        run(app, until='EXPANDED')
        def unavailable(tenant): raise RuntimeError(PRIVATE)
        reference, configuration, observed = host(app, monkeypatch, resolver=unavailable)
        before, old_frames = _snapshot(app), frames(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference,
                                    '--until', 'BACKFILLED', '--json')
        assert code == 4 and output == '' and json.loads(error)['error']
        assert _snapshot(app) == before and frames(app) == old_frames
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'EXPANDED'
        configuration['resolver'] = keys
        success(invoke(capsys, 'apply', str(path), '--host-context', reference,
            '--resume', str(app.plan.operation_id), '--until', 'BACKFILLED', '--json'), app.plan, 'BACKFILLED')
        assert observed['factory'] == observed['dispose']


def test_host_private_exception_is_safe_and_does_not_start_operation(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, factory_failure=True)
        before = _snapshot(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        assert code == 4 and output == '' and json.loads(error)['error']['code'] == 'HostContextUnavailable'
        assert observed['connect'] == observed['keys'] == 0 and _snapshot(app) == before


def test_output_failure_after_commit_reports_known_progress_and_safe_retry(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch)
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as output:
            output.setattr(sys, 'stdout', unavailable)
            code = cli.main(['apply', str(path), '--host-context', reference, '--until', 'PENDING', '--json'])
        captured = capsys.readouterr()
        assert code == 4 and PRIVATE not in captured.err
        error = json.loads(captured.err)['error']
        assert error['code'] == 'OutputUnavailable'
        assert error['known_result']['phase'] == 'PENDING'
        assert error['known_result']['operation_id'] == str(app.plan.operation_id)
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'PENDING'
        before = frames(app, True)
        success(invoke(capsys, 'apply', str(path), '--host-context', reference, '--until', 'PENDING', '--json'), app.plan, 'PENDING')
        assert frames(app, True) == before and observed['factory'] == observed['dispose']


def test_directory_sync_failure_reports_exact_published_artifact_without_database_transition(tmp_path, monkeypatch, capsys):
    with application() as app:
        _, manifest = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, planning=True)
        destination = tmp_path / 'durability-unknown-plan.json'
        before, directories = _snapshot(app), []
        native_sync = os.fsync
        def fail_directory_sync(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                directories.append(True)
                raise OSError(errno.EIO, PRIVATE)
            return native_sync(descriptor)
        with monkeypatch.context() as fault:
            fault.setattr(os, 'fsync', fail_directory_sync)
            code, output, error = invoke(capsys, 'plan', str(manifest), '--host-context', reference,
                                        '--out', str(destination), '--json')
        assert code == 4 and output == '' and directories == [True]
        diagnostic = json.loads(error)['error']
        known = diagnostic['known_result']
        plan = m.MigrationPlan(destination.read_bytes())
        assert known['artifact_published'] is True and known['artifact_directory_durable'] is False
        assert known['operation_id'] == str(plan.operation_id) and known['plan_digest'] == plan.digest
        assert known['effects'] == 'ARTIFACT_PUBLISHED' and known['artifact_temporary_retained'] is False
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        assert not list(tmp_path.glob('.cryptalis-plan-*'))
        assert _snapshot(app) == before and observed['factory'] == observed['dispose'] == 1


def test_final_atomic_link_refuses_a_racing_destination_and_cleans_owned_temporary(tmp_path, monkeypatch, capsys):
    with application() as app:
        _, manifest = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, planning=True)
        destination, winner = tmp_path / 'raced-plan.json', b'PUBLIC concurrent destination must survive'
        before, raced = _snapshot(app), []
        native_link = os.link
        def destination_wins(source, target, **options):
            assert Path(target) == destination
            raced.append(True)
            with destination.open('xb') as stream:
                stream.write(winner)
            return native_link(source, target, **options)
        with monkeypatch.context() as fault:
            fault.setattr(os, 'link', destination_wins)
            code, output, error = invoke(capsys, 'plan', str(manifest), '--host-context', reference,
                                        '--out', str(destination), '--json')
        assert code == 2 and output == '' and raced == [True]
        diagnostic = json.loads(error)['error']
        assert diagnostic['code'] == 'ArtifactExists' and destination.read_bytes() == winner
        assert diagnostic['known_result']['artifact_published'] is False
        assert diagnostic['known_result']['artifact_temporary_retained'] is False
        assert not list(tmp_path.glob('.cryptalis-plan-*'))
        assert _snapshot(app) == before and observed['factory'] == observed['dispose'] == 1


@pytest.mark.parametrize('provider_failure', [False, True])
def test_disposal_failure_preserves_returned_progress_or_primary_error_and_healthy_retry(tmp_path, monkeypatch, capsys, provider_failure):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        if provider_failure:
            run(app, until='EXPANDED')
        def unavailable(tenant): raise RuntimeError(PRIVATE)
        reference, configuration, observed = host(app, monkeypatch, dispose_failure=True,
            resolver=unavailable if provider_failure else keys)
        before = _snapshot(app) if provider_failure else None
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference,
                                    '--until', 'PENDING', '--json')
        assert code == 4 and output == ''
        diagnostic = json.loads(error)['error']
        assert diagnostic['code'] == 'CleanupUnavailable'
        if provider_failure:
            assert diagnostic['effects'] == 'INSPECT_JOURNAL' and 'known_result' not in diagnostic
            assert diagnostic['related_error']['effects'] == 'INSPECT_JOURNAL'
            assert diagnostic['related_error']['code'] == 'operation_failed_requires_inspection'
            assert _snapshot(app) == before
            assert m.status(app.plan, app.owner, pin=app.pin).phase == 'EXPANDED'
        else:
            assert diagnostic['known_result']['phase'] == 'PENDING'
            assert diagnostic['known_result']['operation_id'] == str(app.plan.operation_id)
            assert diagnostic['effects'] == 'COMMITTED_PROGRESS'
            assert m.status(app.plan, app.owner, pin=app.pin).phase == 'PENDING'
        previous = frames(app, True) if not provider_failure else None
        configuration.update(dispose_failure=False, resolver=keys)
        success(invoke(capsys, 'apply', str(path), '--host-context', reference,
            '--resume', str(app.plan.operation_id), '--until', 'PENDING', '--json'), app.plan, 'PENDING')
        if previous is not None:
            assert frames(app, True) == previous
        assert observed['factory'] == observed['dispose'] == 2


def test_wrong_typed_context_disposes_recognized_engine_before_connection_or_keys(tmp_path, monkeypatch, capsys):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        # A valid PlanningContext cannot authorize apply even with the same owner.
        reference, _, observed = host(app, monkeypatch, planning=True)
        before = _snapshot(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        assert code == 2 and output == '' and json.loads(error)['error']['code'] == 'HostContextInvalid'
        assert observed['connect'] == observed['keys'] == 0
        assert observed['factory'] == observed['dispose'] == 1 and _snapshot(app) == before


def test_async_factory_is_not_called_and_does_not_leak_unawaited_coroutine(tmp_path, monkeypatch, capsys, recwarn):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        module, calls = ModuleType('operational_async_factory_' + uuid4().hex), []
        async def factory():
            calls.append(True)
            raise RuntimeError(PRIVATE)
        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', module.__name__ + ':factory', '--json')
        assert code == 4 and output == '' and json.loads(error)['error']['code'] == 'HostContextUnavailable'
        assert calls == [] and _snapshot(app) == before
        assert not [warning for warning in recwarn if 'never awaited' in str(warning.message)]


def test_async_callable_key_resolver_refuses_before_connection_keys_or_journal(tmp_path, monkeypatch, capsys, recwarn):
    with application() as app:
        path, _ = inputs(app, tmp_path)
        module = ModuleType('operational_async_resolver_' + uuid4().hex)
        observed = {'connect': 0, 'keys': 0, 'dispose': 0}
        class Resolver:
            async def __call__(self, tenant):
                observed['keys'] += 1
                return keys(tenant)
        def factory():
            from cryptalis.cli_host import ApplyContext
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return ApplyContext(engine=owned, keys=Resolver(), pin=app.pin, approval=app.approval)
        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', module.__name__ + ':factory', '--json')
        assert code == 2 and output == '' and json.loads(error)['error']['code'] == 'HostContextInvalid'
        assert observed == {'connect': 0, 'keys': 0, 'dispose': 1} and _snapshot(app) == before
        assert not [warning for warning in recwarn if 'never awaited' in str(warning.message)]
