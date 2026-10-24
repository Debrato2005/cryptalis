"""Root-rewrap CLI preserves saved proposals and independent host authority."""
from dataclasses import replace
import errno
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType
from uuid import UUID, uuid4

import pytest
import psycopg
from sqlalchemy import create_engine, event

from cryptalis import cli, migration as m, rotation as r
from cryptalis.rotation import RewrapPlan
from cryptalis.sqlalchemy import attach
from migration_commit_proxy import lost_commit_reply
from rewrap_worker import target_keys
from test_migration import application, engine, frames, keys, publish, run, TENANT
from test_operational_cli import invoke
from test_owned_sequences import _snapshot
from test_rewrap_abort import index_identity


def test_rewrap_cli_plan_persists_exact_read_only_proposal_without_changing_current_frames(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app)
        publish(app)
        source, output = tmp_path / 'active-source.json', tmp_path / 'rewrap-proposal.json'
        source.write_bytes(app.plan.artifact)
        module = ModuleType('rewrap_cli_planning_' + uuid4().hex)
        observed = {'factory': 0, 'dispose': 0}
        def factory():
            # Preserve a behavioral old-command RED instead of a collection error.
            from cryptalis.cli_host import RewrapPlanningContext
            observed['factory'] += 1
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return RewrapPlanningContext(engine=owned, source_keys=keys, target_keys=target_keys,
                source_pin=app.pin, verify_rows_per_second=1000, restore=None)
        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before, original_frames, original_index = _snapshot(app), frames(app, True), index_identity(app)
        code, output_json, error = invoke(capsys, 'keys', 'rotate', 'rewrap', 'plan', str(source),
            '--host-context', module.__name__ + ':factory', '--out', str(output), '--json')
        assert code == 0 and error == '', (code, error)
        proposal = RewrapPlan(output.read_bytes())
        summary = json.loads(output_json)
        assert summary['phase'] == 'PREPARED' and summary['operation_id'] == str(proposal.operation_id)
        assert summary['proposal_digest'] == proposal.digest
        assert summary['activation_plan_digest'] == proposal.activation_plan.digest
        assert summary['authority'] == 'HOST_SUPPLIED_CONTEXT'
        assert summary['artifact_published'] is summary['artifact_directory_durable'] is True
        assert summary['host_configuration_effects'] == 'UNKNOWN'
        assert proposal.source.artifact == app.plan.artifact
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert _snapshot(app) == before and frames(app, True) == original_frames
        assert index_identity(app) == original_index and observed == {'factory': 1, 'dispose': 1}


def pin(plan, phase='PREPARED'):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def artifact(plan, directory, name=None):
    path = directory / (name or (plan.operation_id.hex + '.json'))
    path.write_bytes(plan.artifact)
    return path


def host(app, monkeypatch, proposal=None, *, kind='apply', **overrides):
    successor = proposal.activation_plan if proposal is not None else None
    configuration = dict(source_keys=keys, target_keys=target_keys, source_pin=app.pin,
        pin=pin(successor) if successor is not None else None, approval=app.approval, restore=None)
    configuration.update(overrides)
    observed = {'factory': 0, 'source': 0, 'target': 0, 'connect': 0, 'dispose': 0}
    module = ModuleType('rewrap_cli_context_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import (RewrapPlanningContext, RewrapApplyContext,
                                       RewrapActivationContext, RewrapAbortContext)
        observed['factory'] += 1
        if configuration.get('factory_failure'):
            raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        if configuration.get('connection'):
            owned = create_engine('postgresql+psycopg://', hide_parameters=True,
                creator=lambda: psycopg.connect(configuration['connection'], connect_timeout=5))
        else:
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        def disposed(*args):
            observed['dispose'] += 1
            if configuration.get('dispose_failure'):
                print('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
                raise OSError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        event.listen(owned, 'engine_disposed', disposed)
        def source(tenant):
            observed['source'] += 1
            return configuration['source_keys'](tenant)
        def target(tenant):
            observed['target'] += 1
            return configuration['target_keys'](tenant)
        if kind == 'plan':
            return RewrapPlanningContext(engine=owned, source_keys=source, target_keys=target,
                source_pin=configuration['source_pin'], verify_rows_per_second=1000, restore=configuration['restore'])
        if kind == 'activate':
            return RewrapActivationContext(engine=owned, target_keys=target,
                pin=configuration['pin'], approval=configuration['approval'])
        if kind == 'abort':
            return RewrapAbortContext(engine=owned, source_keys=source,
                source_pin=configuration['source_pin'], approval=configuration['approval'])
        if configuration.get('expected_activation'):
            saved = Path(configuration['expected_activation']).read_bytes()
            assert m.MigrationPlan(saved).artifact == proposal.activation_plan.artifact
        return RewrapApplyContext(engine=owned, source_keys=source, target_keys=target,
            pin=configuration['pin'], approval=configuration['approval'])
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


def result(observed, proposal, phase):
    code, output, error = observed
    assert code == 0 and error == '', (code, error)
    summary = json.loads(output)
    assert summary['scope'] == 'rewrap_transition' and summary['phase'] == phase
    assert summary['operation_id'] == str(proposal.operation_id)
    assert summary['proposal_digest'] == proposal.digest and summary['plan_digest'] == proposal.activation_plan.digest
    assert summary['activation_plan_digest'] == proposal.activation_plan.digest
    assert summary['authority'] == 'HOST_SUPPLIED_PIN'
    return summary


def command(action, path, reference, *extra):
    return ('keys', 'rotate', 'rewrap', action, str(path), '--host-context', reference, *extra, '--json')


@pytest.fixture
def active():
    with application() as app:
        run(app); publish(app)
        yield app


def preparation(app):
    return r.plan_rewrap(app.plan, app.owner, source_pin=app.pin,
                         keys=keys, target_keys=target_keys, verify_rows_per_second=1000)


def test_saved_successor_explicit_resume_and_target_only_publication(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'activation.json'
    reference, configuration, observed = host(app, monkeypatch, proposal, expected_activation=successor)
    original, indexes = frames(app, True), index_identity(app)
    summary = result(invoke(capsys, *command('apply', path, reference, '--out', str(successor))), proposal, 'PENDING')
    assert summary['artifact_result']['artifact_published'] is True
    assert m.MigrationPlan(successor.read_bytes()).artifact == proposal.activation_plan.artifact
    assert stat.S_IMODE(successor.stat().st_mode) == 0o600
    before = _snapshot(app)
    denied = invoke(capsys, *command('apply', path, reference, '--out', str(successor)))
    assert denied[0] == 2 and denied[1] == '' and observed['factory'] == 1 and _snapshot(app) == before
    summary = result(invoke(capsys, *command('apply', path, reference, '--out', str(successor),
        '--resume', str(proposal.operation_id))), proposal, 'PENDING')
    assert summary['artifact_result']['artifact_reused'] is True
    def forbidden(tenant): pytest.fail('target-only activation must not resolve source custody')
    activation, authority, activated = host(app, monkeypatch, proposal, kind='activate',
        pin=pin(proposal.activation_plan, 'ACTIVATING'), source_keys=forbidden)
    result(invoke(capsys, *command('activate', successor, activation)), proposal, 'ACTIVE')
    assert activated['source'] == 0 and activated['target'] > 0
    assert frames(app, True) == original and index_identity(app) == indexes
    aborting, _, aborted = host(app, monkeypatch, proposal, kind='abort')
    rejected = invoke(capsys, *command('abort', path, aborting))
    assert rejected[0] == 3 and rejected[1] == '' and aborted['target'] == 0
    assert observed['factory'] == observed['dispose'] and activated['factory'] == activated['dispose']


def test_source_only_cancellation_and_terminal_retry_preserve_later_edits(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'cancelled-activation.json'
    applying, _, _ = host(app, monkeypatch, proposal)
    original, indexes = frames(app, True), index_identity(app)
    result(invoke(capsys, *command('apply', path, applying, '--out', str(successor))), proposal, 'PENDING')
    def unavailable(tenant): pytest.fail('cancellation must not need target custody')
    reference, configuration, observed = host(app, monkeypatch, proposal, kind='abort', target_keys=unavailable)
    result(invoke(capsys, *command('abort', path, reference)), proposal, 'ABORTED')
    assert frames(app, True) == original and index_identity(app) == indexes and observed['target'] == 0
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
    with factory(tenant_id=TENANT) as session:
        session.get(app.Customer, UUID(int=101)).name = 'later source edit after CLI cancellation'
        session.commit()
    before = _snapshot(app)
    configuration['source_keys'] = unavailable
    result(invoke(capsys, *command('abort', path, reference)), proposal, 'ABORTED')
    assert _snapshot(app) == before and observed['target'] == 0
    assert path.read_bytes() == proposal.artifact and successor.read_bytes() == proposal.activation_plan.artifact


def test_resume_requires_exact_private_regular_activation_before_host(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path = artifact(proposal, tmp_path)
    reference, _, observed = host(app, monkeypatch, proposal)
    before = _snapshot(app)
    for fault in ('different_bytes', 'symlink', 'directory', 'public_mode', 'wrong_operation'):
        successor = tmp_path / ('activation-' + fault)
        if fault == 'symlink': successor.symlink_to(path)
        elif fault == 'directory': successor.mkdir()
        else:
            successor.write_bytes(app.plan.artifact if fault == 'different_bytes' else proposal.activation_plan.artifact)
            successor.chmod(0o644 if fault == 'public_mode' else 0o600)
        operation = uuid4() if fault == 'wrong_operation' else proposal.operation_id
        code, output, error = invoke(capsys, *command('apply', path, reference,
            '--out', str(successor), '--resume', str(operation)))
        assert code == 2 and output == '' and json.loads(error)['error']
        assert observed['factory'] == 0 and _snapshot(app) == before
    missing = tmp_path / 'missing-activation.json'
    summary = result(invoke(capsys, *command('apply', path, reference, '--out', str(missing),
        '--resume', str(proposal.operation_id))), proposal, 'PENDING')
    assert summary['artifact_result']['artifact_published'] is True and missing.read_bytes() == proposal.activation_plan.artifact


def test_failed_successor_directory_sync_has_only_artifact_facts_then_explicit_resume_resyncs(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'sync-activation.json'
    reference, _, observed = host(app, monkeypatch, proposal)
    before, synced = _snapshot(app), []
    native_sync = os.fsync
    def unavailable(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode): raise OSError(errno.EIO, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        return native_sync(descriptor)
    with monkeypatch.context() as fault:
        fault.setattr(os, 'fsync', unavailable)
        code, output, error = invoke(capsys, *command('apply', path, reference, '--out', str(successor)))
    diagnostic = json.loads(error)['error']
    assert code == 4 and output == '' and 'known_result' not in diagnostic
    assert diagnostic['artifact_result']['artifact_published'] is True
    assert diagnostic['artifact_result']['artifact_directory_durable'] is False
    assert 'phase' not in diagnostic['artifact_result'] and 'committed_rows' not in diagnostic['artifact_result']
    assert observed['factory'] == 0 and _snapshot(app) == before
    assert successor.read_bytes() == proposal.activation_plan.artifact
    def tracked(descriptor):
        synced.append('directory' if stat.S_ISDIR(os.fstat(descriptor).st_mode) else 'file')
        return native_sync(descriptor)
    with monkeypatch.context() as inspect:
        inspect.setattr(os, 'fsync', tracked)
        result(invoke(capsys, *command('apply', path, reference, '--out', str(successor),
            '--resume', str(proposal.operation_id))), proposal, 'PENDING')
    assert {'file', 'directory'} <= set(synced)


@pytest.mark.parametrize('fault', ['target_outage', 'source_outage', 'host_unavailable'])
def test_published_artifact_never_invents_known_database_progress_on_failure(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'retained-activation.json'
    def unavailable(tenant): raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    options = {'factory_failure': True} if fault == 'host_unavailable' else {
        'target_keys' if fault == 'target_outage' else 'source_keys': unavailable}
    reference, _, _ = host(app, monkeypatch, proposal, **options)
    before = _snapshot(app)
    code, output, error = invoke(capsys, *command('apply', path, reference, '--out', str(successor)))
    diagnostic = json.loads(error)['error']
    assert code == 4 and output == '' and 'known_result' not in diagnostic
    assert diagnostic['artifact_result']['artifact_published'] is True
    assert diagnostic['artifact_result']['artifact_directory_durable'] is True
    assert 'phase' not in diagnostic['artifact_result']
    if fault != 'host_unavailable': assert diagnostic['effects'] == 'INSPECT_JOURNAL'
    assert successor.read_bytes() == proposal.activation_plan.artifact and _snapshot(app) == before


def test_stale_successor_pin_and_changed_source_refuse_without_overwriting_current_data(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'denied-activation.json'
    reference, configuration, observed = host(app, monkeypatch, proposal,
        pin=replace(pin(proposal.activation_plan), plan_digest='0' * 64))
    before = _snapshot(app)
    denied = invoke(capsys, *command('apply', path, reference, '--out', str(successor)))
    assert denied[0] == 2 and denied[1] == '' and observed['source'] == observed['target'] == 0
    assert _snapshot(app) == before
    configuration['pin'] = pin(proposal.activation_plan)
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
    with factory(tenant_id=TENANT) as session:
        session.get(app.Customer, UUID(int=101)).name = 'new authenticated source after stale proposal'
        session.commit()
    before = _snapshot(app)
    denied = invoke(capsys, *command('apply', path, reference, '--out', str(successor), '--resume', str(proposal.operation_id)))
    assert denied[0] == 3 and json.loads(denied[2])['error']['effects'] == 'INSPECT_JOURNAL'
    assert _snapshot(app) == before and successor.read_bytes() == proposal.activation_plan.artifact


def test_real_lost_pending_commit_reply_retains_exact_activation_and_inspected_resume(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'commit-activation.json'
    reference, configuration, _ = host(app, monkeypatch, proposal)
    original, indexes = frames(app, True), index_identity(app)
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
        configuration['connection'] = url
        code, output, error = invoke(capsys, *command('apply', path, reference, '--out', str(successor)))
        assert code == 4 and output == '' and dropped.wait(5)
        diagnostic = json.loads(error)['error']
        assert diagnostic['effects'] == 'INSPECT_JOURNAL' and 'known_result' not in diagnostic
        assert diagnostic['artifact_result']['artifact_directory_durable'] is True
    configuration.pop('connection')
    assert m.status(proposal.activation_plan, app.owner, pin=pin(proposal.activation_plan)).phase == 'PENDING'
    summary = result(invoke(capsys, *command('apply', path, reference, '--out', str(successor),
        '--resume', str(proposal.operation_id))), proposal, 'PENDING')
    assert summary['artifact_result']['artifact_reused'] is True
    assert frames(app, True) == original and index_identity(app) == indexes


@pytest.mark.parametrize('fault', ['output', 'cleanup'])
def test_postpending_output_or_cleanup_failure_preserves_real_progress_and_artifact(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    proposal = preparation(app)
    path, successor = artifact(proposal, tmp_path), tmp_path / 'known-activation.json'
    reference, configuration, _ = host(app, monkeypatch, proposal, dispose_failure=fault == 'cleanup')
    arguments = command('apply', path, reference, '--out', str(successor))
    if fault == 'output':
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', unavailable)
            code = cli.main(list(arguments))
        captured = capsys.readouterr()
        output, error = captured.out, captured.err
        assert 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in error
    else:
        code, output, error = invoke(capsys, *arguments)
    diagnostic = json.loads(error)['error']
    assert code == 4 and output == ''
    assert diagnostic['known_result']['phase'] == 'PENDING'
    assert diagnostic['known_result']['plan_digest'] == proposal.activation_plan.digest
    assert diagnostic['artifact_result']['artifact_directory_durable'] is True
    assert m.status(proposal.activation_plan, app.owner, pin=pin(proposal.activation_plan)).phase == 'PENDING'
    configuration['dispose_failure'] = False
    before = _snapshot(app)
    result(invoke(capsys, *command('apply', path, reference, '--out', str(successor),
        '--resume', str(proposal.operation_id))), proposal, 'PENDING')
    assert _snapshot(app) == before


if 'CRYPTALIS_FRESH_CLUSTER_DIR' in os.environ:
    import test_adopted_rewrap as recovery
    adopted = recovery.adopted
else:
    @pytest.fixture
    def adopted():
        pytest.skip('run the --rewrap-cli genuine fresh-cluster profile')


def test_genuine_adopted_rewrap_cli_preserves_binding_and_byte_identity(adopted, tmp_path, monkeypatch, capsys):
    app = adopted
    app.plan, app.pin, app.schema = app.source, app.source_pin, recovery.fresh.SCHEMA
    app.approval, app.role = recovery.MAINTENANCE, recovery.fresh.MANIFEST['runtime_role']
    reference, configuration, observed = host(app, monkeypatch, kind='plan', restore=app.binding)
    from cryptalis.restore import RestoreBinding
    changed = app.binding.document
    changed['source']['plan_digest'] = '0' * 64
    configuration['restore'] = RestoreBinding(m._canonical(changed))
    def forbidden(tenant): pytest.fail('wrong binding reached provider work')
    configuration.update(source_keys=forbidden, target_keys=forbidden)
    source, path = artifact(app.plan, tmp_path), tmp_path / 'adopted-rewrap.json'
    before, original, indexes = _snapshot(app), frames(app, True), index_identity(app)
    denied = invoke(capsys, *command('plan', source, reference, '--out', str(path)))
    assert denied[0] == 2 and observed['source'] == observed['target'] == 0 and _snapshot(app) == before
    configuration.update(source_keys=keys, target_keys=target_keys, restore=app.binding)
    code, output, error = invoke(capsys, *command('plan', source, reference, '--out', str(path)))
    assert code == 0 and error == ''
    proposal = RewrapPlan(path.read_bytes())
    assert proposal.document['format'] == 'cryptalis.rewrap/v2' and proposal.document['restore'] == app.binding.document
    successor = tmp_path / 'adopted-activation.json'
    applying, _, _ = host(app, monkeypatch, proposal)
    result(invoke(capsys, *command('apply', path, applying, '--out', str(successor))), proposal, 'PENDING')
    activation, _, _ = host(app, monkeypatch, proposal, kind='activate', pin=pin(proposal.activation_plan, 'ACTIVATING'))
    result(invoke(capsys, *command('activate', successor, activation)), proposal, 'ACTIVE')
    assert frames(app, True) == original and index_identity(app) == indexes
    active_plan = proposal.activation_plan
    assert active_plan.document['restore_lineage'] == [app.binding.document]
    recovery.current_edit(app, active_plan, target_keys, 'latest adopted CLI rewrap value')
    from test_reverse_operational_cli import artifact as reverse_artifact, reverse_host, finish_cli
    from cryptalis import deprotection as d
    reverse = d.plan(active_plan, app.owner, source_pin=pin(active_plan, 'ACTIVE'), keys=target_keys,
        plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'], backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    reverse_path = reverse_artifact(reverse, tmp_path)
    execution, authority, _ = reverse_host(app, monkeypatch, plan=reverse, resolver=target_keys)
    finish_cli(app, reverse, reverse_path, execution, authority, monkeypatch, capsys)
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest adopted CLI rewrap value']
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT id,tenant_id,name FROM "{app.schema}".customer').all()
    assert {str(identity): [str(tenant), value] for identity, tenant, value in rows} == expected


def test_wrong_rewrap_artifact_kinds_and_stale_source_authority_refuse_before_providers(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = preparation(app)
    source, path = artifact(app.plan, tmp_path), artifact(proposal, tmp_path)
    reference, _, observed = host(app, monkeypatch, proposal)
    before = _snapshot(app)
    for action, supplied in [('apply', source), ('abort', source), ('activate', path), ('activate', source)]:
        output = tmp_path / ('unpublished-' + action)
        extra = ('--out', str(output)) if action == 'apply' else ()
        code, text, error = invoke(capsys, *command(action, supplied, reference, *extra))
        assert code == 2 and text == '' and json.loads(error)['error']
        assert observed['factory'] == 0 and _snapshot(app) == before and not output.exists()
    planning, _, planned = host(app, monkeypatch, kind='plan',
        source_pin=replace(app.pin, plan_digest='0' * 64))
    output = tmp_path / 'stale-source-proposal.json'
    denied = invoke(capsys, *command('plan', source, planning, '--out', str(output)))
    assert denied[0] == 2 and denied[1] == ''
    assert planned['source'] == planned['target'] == 0 and _snapshot(app) == before and not output.exists()
