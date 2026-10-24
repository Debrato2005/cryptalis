"""Payload CLI retains immutable artifacts and independent host authority."""
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

import psycopg
import pytest
from sqlalchemy import create_engine, event

from cryptalis import cli, migration as m, rotation as r
from cryptalis.crypto import Keyring
from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
from cryptalis.sqlalchemy import attach
from migration_commit_proxy import lost_commit_reply
from payload_rotation_worker import target_keys
from test_migration import application, engine, frames, keys, publish, run, TENANT
from test_operational_cli import invoke
from test_owned_sequences import _snapshot
from test_rewrap_abort import index_identity
from test_payload_rotation_plan import plan as api_plan
from test_payload_rotation_execution import staged_frames


def test_payload_cli_plan_persists_exact_read_only_proposal_without_staging(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app)
        publish(app)
        source, output = tmp_path / 'active-source.json', tmp_path / 'payload-proposal.json'
        source.write_bytes(app.plan.artifact)
        module = ModuleType('payload_cli_planning_' + uuid4().hex)
        observed = {'factory': 0, 'dispose': 0}

        def factory():
            # Keep the old-command RED behavioral rather than a collection failure.
            from cryptalis.cli_host import PayloadPlanningContext
            observed['factory'] += 1
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return PayloadPlanningContext(engine=owned, source_keys=keys, target_keys=target_keys,
                source_pin=app.pin, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048, restore=None)

        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before, original_frames, original_index = _snapshot(app), frames(app, True), index_identity(app)
        code, output_json, error = invoke(capsys, 'keys', 'rotate', 'payload', 'plan', str(source),
            '--host-context', module.__name__ + ':factory', '--out', str(output), '--json')
        assert code == 0 and error == '', (code, error)
        proposal = r.PayloadRotationPlan(output.read_bytes())
        summary = json.loads(output_json)
        assert summary['scope'] == 'payload_preparation_plan' and summary['phase'] == 'PREPARED'
        assert summary['operation_id'] == str(proposal.operation_id) and summary['proposal_digest'] == proposal.digest
        assert summary['successor_operation_id'] == proposal.document['successor_operation_id']
        assert summary['authority'] == 'HOST_SUPPLIED_CONTEXT'
        assert summary['artifact_published'] is summary['artifact_directory_durable'] is True
        assert summary['host_configuration_effects'] == 'UNKNOWN'
        assert proposal.source.artifact == app.plan.artifact
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert _snapshot(app) == before and frames(app, True) == original_frames
        assert index_identity(app) == original_index and observed == {'factory': 1, 'dispose': 1}


def pin(plan, phase='PREPARED'):
    target = plan.source.target_id if isinstance(plan, r.PayloadRotationPlan) else plan.target_id
    return m.DeploymentPin(target, plan.operation_id, plan.digest, phase)


def artifact(plan, directory, name=None):
    path = directory / (name or plan.operation_id.hex + '.json')
    path.write_bytes(plan.artifact)
    path.chmod(0o600)
    return path


def command(action, path, reference, *extra):
    return ('keys', 'rotate', 'payload', action, str(path), '--host-context', reference, *extra, '--json')


def progress(observed, plan, phase):
    code, output, error = observed
    assert code == 0 and error == '', (code, error)
    result = json.loads(output)
    assert result['phase'] == phase and result['operation_id'] == str(plan.operation_id)
    assert result['plan_digest'] == plan.digest and result['authority'] == 'HOST_SUPPLIED_PIN'
    return result


def host(app, monkeypatch, proposal, *, kind='apply', **options):
    configuration = dict(source_keys=keys, target_keys=target_keys, source_pin=app.pin,
        pin=pin(proposal) if proposal is not None else None, approval=app.approval, restore=None)
    configuration.update(options)
    observed = {'factory': 0, 'source': 0, 'target': 0, 'connect': 0, 'dispose': 0}
    module = ModuleType('payload_cli_context_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import (PayloadPlanningContext, PayloadApplyContext, PayloadStatusContext,
            PayloadSealingContext, PayloadSwitchContext, PayloadActivationContext, PayloadAbortContext)
        observed['factory'] += 1
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
        shared = dict(engine=owned, pin=configuration['pin'])
        if kind == 'status': return PayloadStatusContext(**shared)
        if kind == 'plan':
            return PayloadPlanningContext(engine=owned, source_keys=source, target_keys=target,
                source_pin=configuration['source_pin'], restore=configuration['restore'],
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        if kind == 'abort':
            return PayloadAbortContext(engine=owned, source_keys=source,
                source_pin=configuration['source_pin'], approval=configuration['approval'])
        shared['approval'] = configuration['approval']
        if kind == 'activate': return PayloadActivationContext(target_keys=target, **shared)
        shared.update(source_keys=source, target_keys=target)
        if kind == 'seal': return PayloadSealingContext(copy_rows_per_second=0.5,
            copy_wal_bytes_per_row=2048, **shared)
        return (PayloadSwitchContext if kind == 'switch' else PayloadApplyContext)(**shared)
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


@pytest.fixture
def active():
    with application() as app:
        run(app); publish(app)
        yield app


def prepared(app, tmp_path, monkeypatch, capsys):
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    reference, _, _ = host(app, monkeypatch, proposal)
    progress(invoke(capsys, *command('apply', path, reference)), proposal, 'BACKFILLED')
    return proposal, path


def sealed(app, tmp_path, monkeypatch, capsys):
    proposal, path = prepared(app, tmp_path, monkeypatch, capsys)
    reference, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'activation.json'
    code, text, error = invoke(capsys, *command('seal', path, reference, '--out', str(output)))
    assert code == 0 and error == ''
    activation = m.MigrationPlan(output.read_bytes())
    summary = json.loads(text)
    assert summary['artifact_sealed'] is True and summary['plan_digest'] == activation.digest
    assert 'phase' not in summary and 'known_result' not in summary
    assert 'phase' not in summary['artifact_result']
    return proposal, path, activation, output


def test_staging_resume_sealed_artifact_keyless_status_and_target_only_publication(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    original, indexes = frames(app, True), index_identity(app)
    reference, _, _ = host(app, monkeypatch, proposal)
    first = progress(invoke(capsys, *command('apply', path, reference, '--max-chunks', '1')), proposal, 'EXPANDED')
    prefix = staged_frames(app, proposal)
    assert first['committed_rows'] == 3 and frames(app, True) == original
    progress(invoke(capsys, *command('apply', path, reference, '--resume', str(proposal.operation_id))), proposal, 'BACKFILLED')
    complete = staged_frames(app, proposal)
    for identity in (UUID(int=100), UUID(int=101), UUID(int=102)): assert complete[identity] == prefix[identity]
    inspector, state, observed = host(app, monkeypatch, proposal, kind='status')
    def forbidden(*args, **kwargs): pytest.fail('key-free status resolved provider keys')
    with monkeypatch.context() as no_keys:
        no_keys.setattr(Keyring, 'prepare', forbidden)
        report = progress(invoke(capsys, *command('status', path, inspector)), proposal, 'BACKFILLED')
    assert report['verification'] == 'NOT_PERFORMED' and report['runtime_metadata_matches'] is False
    assert observed['source'] == observed['target'] == 0
    sealer, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'saved-activation.json'
    before = _snapshot(app), staged_frames(app, proposal)
    assert invoke(capsys, *command('seal', path, sealer, '--out', str(output)))[0] == 0
    activation = m.MigrationPlan(output.read_bytes())
    duplicate = tmp_path / 'identical-reseal.json'
    assert invoke(capsys, *command('seal', path, sealer, '--out', str(duplicate)))[0] == 0
    assert output.read_bytes() == duplicate.read_bytes() and (_snapshot(app), staged_frames(app, proposal)) == before
    switching, authority, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
    progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output))), activation, 'PENDING')
    assert frames(app, True) == {identity: values[0] for identity, values in complete.items()}
    assert frames(app, True) != original and index_identity(app) == indexes
    for identity, frame in frames(app, True).items():
        if frame is not None:
            assert int.from_bytes(frame[6:10], 'big') == 2 and frame[10:46] == original[identity][10:46]
    authority['source_keys'] = forbidden
    progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output),
        '--resume', str(activation.operation_id))), activation, 'PENDING')
    output.unlink()
    before = _snapshot(app)
    denied = invoke(capsys, *command('switch', path, switching, '--activation', str(output),
        '--resume', str(activation.operation_id)))
    assert denied[0] == 2 and _snapshot(app) == before and not output.exists()
    output = artifact(activation, tmp_path, 'externally-retained-activation.json')
    activating, _, _ = host(app, monkeypatch, proposal, kind='activate', pin=pin(activation, 'ACTIVATING'), source_keys=forbidden)
    progress(invoke(capsys, *command('activate', output, activating)), activation, 'ACTIVE')
    state['pin'] = pin(activation, 'ACTIVE')
    with monkeypatch.context() as no_keys:
        no_keys.setattr(Keyring, 'prepare', forbidden)
        report = progress(invoke(capsys, *command('status', output, inspector)), activation, 'ACTIVE')
    assert report['verification'] == 'NOT_PERFORMED' and report['runtime_metadata_matches'] is True


@pytest.mark.parametrize('staged', [False, True])
def test_source_only_cancel_then_terminal_retry_preserves_later_source_edit(active, tmp_path, monkeypatch, capsys, staged):
    app = active
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    if staged:
        reference, _, _ = host(app, monkeypatch, proposal)
        progress(invoke(capsys, *command('apply', path, reference, '--max-chunks', '1')), proposal, 'EXPANDED')
    original = frames(app, True)
    def forbidden(tenant): pytest.fail('cancellation reached target custody')
    cancelling, _, observed = host(app, monkeypatch, proposal, kind='abort', target_keys=forbidden)
    progress(invoke(capsys, *command('abort', path, cancelling)), proposal, 'ABORTED')
    assert frames(app, True) == original and observed['target'] == 0
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
    with factory(tenant_id=TENANT) as session:
        session.get(app.Customer, UUID(int=101)).name = 'latest source edit after payload cancellation'
        session.commit()
    before = _snapshot(app)
    progress(invoke(capsys, *command('abort', path, cancelling)), proposal, 'ABORTED')
    assert _snapshot(app) == before and observed['target'] == 0


@pytest.mark.parametrize('fault', ['output', 'directory_sync', 'cleanup'])
def test_lost_seal_output_has_only_artifact_facts_and_authenticated_identical_reseal(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    proposal, path = prepared(app, tmp_path, monkeypatch, capsys)
    reference, _, _ = host(app, monkeypatch, proposal, kind='seal', dispose_failure=fault == 'cleanup')
    output = tmp_path / 'retained-seal.json'
    before = _snapshot(app), staged_frames(app, proposal)
    arguments = command('seal', path, reference, '--out', str(output))
    if fault == 'output':
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', unavailable)
            code = cli.main(list(arguments))
        captured = capsys.readouterr()
        error = captured.err
    elif fault == 'directory_sync':
        native = os.fsync
        def broken(descriptor):
            if stat.S_ISDIR(os.fstat(descriptor).st_mode): raise OSError(errno.EIO, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
            return native(descriptor)
        with monkeypatch.context() as broken_sync:
            broken_sync.setattr(os, 'fsync', broken)
            code, text, error = invoke(capsys, *arguments)
            assert text == ''
    else:
        code, text, error = invoke(capsys, *arguments)
        assert text == ''
    diagnostic = json.loads(error)['error']
    assert code == 4 and 'known_result' not in diagnostic and 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in error
    assert diagnostic['artifact_result']['artifact_published'] is True
    assert diagnostic['artifact_result']['artifact_directory_durable'] is (fault != 'directory_sync')
    assert 'phase' not in diagnostic['artifact_result'] and output.exists()
    assert (_snapshot(app), staged_frames(app, proposal)) == before
    retry, _, _ = host(app, monkeypatch, proposal, kind='seal')
    repeated = tmp_path / 'authenticated-reseal.json'
    assert invoke(capsys, *command('seal', path, retry, '--out', str(repeated)))[0] == 0
    assert output.read_bytes() == repeated.read_bytes()


def test_switch_syncs_private_activation_before_host_and_refuses_changed_staged_proof(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal, path, activation, output = sealed(app, tmp_path, monkeypatch, capsys)
    reference, _, observed = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
    before = _snapshot(app), staged_frames(app, proposal)
    native = os.fsync
    def broken(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode): raise OSError(errno.EIO, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        return native(descriptor)
    with monkeypatch.context() as failure:
        failure.setattr(os, 'fsync', broken)
        code, text, error = invoke(capsys, *command('switch', path, reference, '--activation', str(output)))
    assert code == 4 and text == '' and observed['factory'] == 0
    assert 'known_result' not in json.loads(error)['error'] and (_snapshot(app), staged_frames(app, proposal)) == before
    for mode in ('public', 'symlink', 'different'):
        supplied = tmp_path / ('bad-' + mode)
        if mode == 'symlink': supplied.symlink_to(output)
        elif mode == 'different': supplied.write_bytes(app.plan.artifact); supplied.chmod(0o600)
        else: supplied.write_bytes(output.read_bytes()); supplied.chmod(0o644)
        denied = invoke(capsys, *command('switch', path, reference, '--activation', str(supplied)))
        assert denied[0] == 2 and observed['factory'] == 0 and (_snapshot(app), staged_frames(app, proposal)) == before
    field = proposal.source.document['lock']['models'][0]['fields'][0]
    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
    replacement = seal_text(app.source[UUID(int=101)][1], descriptor, TENANT, UUID(int=101), target_keys(TENANT).prepare())
    original = staged_frames(app, proposal)[UUID(int=101)][0]
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{field["payload_column"]}_rotation"=%s WHERE id=%s',
                                   (replacement, UUID(int=101)))
    changed = _snapshot(app), staged_frames(app, proposal)
    assert invoke(capsys, *command('switch', path, reference, '--activation', str(output)))[0] == 3
    assert (_snapshot(app), staged_frames(app, proposal)) == changed
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{field["payload_column"]}_rotation"=%s WHERE id=%s',
                                   (original, UUID(int=101)))
    progress(invoke(capsys, *command('switch', path, reference, '--activation', str(output))), activation, 'PENDING')


@pytest.mark.parametrize('boundary,commit_number', [('chunk', 3), ('switch', 2)])
def test_real_lost_commit_reply_is_inspected_and_resumed_from_saved_artifacts(active, tmp_path, monkeypatch, capsys, boundary, commit_number):
    app = active
    if boundary == 'switch':
        proposal, path, activation, output = sealed(app, tmp_path, monkeypatch, capsys)
        reference, configuration, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
        arguments = command('switch', path, reference, '--activation', str(output))
    else:
        proposal = api_plan(app, target_keys)
        path = artifact(proposal, tmp_path)
        reference, configuration, _ = host(app, monkeypatch, proposal)
        arguments = command('apply', path, reference, '--max-chunks', '1')
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=commit_number) as (url, dropped):
        configuration['connection'] = url
        code, text, error = invoke(capsys, *arguments)
        assert code == 4 and text == '' and dropped.wait(5)
        diagnostic = json.loads(error)['error']
        assert diagnostic['effects'] == 'INSPECT_JOURNAL' and 'known_result' not in diagnostic
    configuration.pop('connection')
    if boundary == 'switch':
        assert output.read_bytes() == activation.artifact
        def forbidden(tenant): pytest.fail('committed switch retry reached source custody')
        configuration['source_keys'] = forbidden
        progress(invoke(capsys, *command('switch', path, reference, '--activation', str(output),
            '--resume', str(activation.operation_id))), activation, 'PENDING')
    else:
        assert r.status_payload_rotation(proposal, app.owner, pin=pin(proposal)).committed_rows == 3
        prefix = staged_frames(app, proposal)
        progress(invoke(capsys, *command('apply', path, reference, '--resume', str(proposal.operation_id))), proposal, 'BACKFILLED')
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)): assert staged_frames(app, proposal)[identity] == prefix[identity]


def test_wrong_kind_resume_and_pin_refuse_without_provider_or_data_effects(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = api_plan(app, target_keys)
    path, source = artifact(proposal, tmp_path), artifact(app.plan, tmp_path)
    reference, configuration, observed = host(app, monkeypatch, proposal)
    before = _snapshot(app)
    for arguments in (command('apply', source, reference), command('activate', path, reference),
            command('apply', path, reference, '--resume', str(uuid4())),
            command('apply', path, reference, '--max-chunks', '0')):
        assert invoke(capsys, *arguments)[0] == 2 and observed['factory'] == 0 and _snapshot(app) == before
    configuration['pin'] = replace(pin(proposal), plan_digest='0' * 64)
    assert invoke(capsys, *command('apply', path, reference))[0] == 2
    assert observed['source'] == observed['target'] == observed['connect'] == 0 and _snapshot(app) == before


if 'CRYPTALIS_FRESH_CLUSTER_DIR' in os.environ:
    import test_adopted_rewrap as recovery
    adopted = recovery.adopted
else:
    @pytest.fixture
    def adopted():
        pytest.skip('run the --payload-cli genuine fresh-cluster profile')


def test_genuine_adopted_payload_cli_seals_saved_activation_and_latest_native_exit(adopted, tmp_path, monkeypatch, capsys):
    app = adopted
    app.plan, app.pin, app.schema = app.source, app.source_pin, recovery.fresh.SCHEMA
    app.approval, app.role = recovery.MAINTENANCE, recovery.fresh.MANIFEST['runtime_role']
    source, path = artifact(app.plan, tmp_path), tmp_path / 'adopted-payload.json'
    reference, configuration, observed = host(app, monkeypatch, None, kind='plan', restore=app.binding)
    from cryptalis.restore import RestoreBinding
    changed = app.binding.document
    changed['source']['plan_digest'] = '0' * 64
    configuration['restore'] = RestoreBinding(m._canonical(changed))
    def forbidden(tenant): pytest.fail('wrong restored authority reached custody')
    configuration.update(source_keys=forbidden, target_keys=forbidden)
    before = _snapshot(app)
    assert invoke(capsys, *command('plan', source, reference, '--out', str(path)))[0] == 2
    assert _snapshot(app) == before and observed['source'] == observed['target'] == 0 and not path.exists()
    configuration.update(source_keys=keys, target_keys=target_keys, restore=app.binding)
    assert invoke(capsys, *command('plan', source, reference, '--out', str(path)))[0] == 0
    proposal = r.PayloadRotationPlan(path.read_bytes())
    assert proposal.document['format'] == 'cryptalis.payload-rotation/v2' and proposal.restore_binding.artifact == app.binding.artifact
    applying, _, _ = host(app, monkeypatch, proposal)
    progress(invoke(capsys, *command('apply', path, applying, '--max-chunks', '1')), proposal, 'EXPANDED')
    progress(invoke(capsys, *command('apply', path, applying, '--resume', str(proposal.operation_id))), proposal, 'BACKFILLED')
    sealer, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'adopted-activation.json'
    assert invoke(capsys, *command('seal', path, sealer, '--out', str(output)))[0] == 0
    activation = m.MigrationPlan(output.read_bytes())
    assert activation.document['format'] == 'cryptalis.transition/v6'
    switching, _, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
    progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output))), activation, 'PENDING')
    activating, _, _ = host(app, monkeypatch, proposal, kind='activate', pin=pin(activation, 'ACTIVATING'))
    progress(invoke(capsys, *command('activate', output, activating)), activation, 'ACTIVE')
    assert activation.document['restore_lineage'] == [app.binding.document]
    recovery.current_edit(app, activation, target_keys, 'latest adopted CLI payload value')
    from cryptalis import deprotection as d
    from test_reverse_operational_cli import artifact as reverse_artifact, reverse_host, finish_cli
    reverse = d.plan(activation, app.owner, source_pin=pin(activation, 'ACTIVE'), keys=target_keys,
        plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'], backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    reverse_path = reverse_artifact(reverse, tmp_path)
    execution, authority, _ = reverse_host(app, monkeypatch, plan=reverse, resolver=target_keys)
    finish_cli(app, reverse, reverse_path, execution, authority, monkeypatch, capsys)
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest adopted CLI payload value']
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT id,tenant_id,name FROM "{app.schema}".customer').all()
    assert {str(identity): [str(tenant), value] for identity, tenant, value in rows} == expected


def test_target_outage_preserves_committed_shadow_prefix_and_source_only_abort(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    reference, configuration, _ = host(app, monkeypatch, proposal)
    progress(invoke(capsys, *command('apply', path, reference, '--max-chunks', '1')), proposal, 'EXPANDED')
    before = _snapshot(app), staged_frames(app, proposal)
    def unavailable(tenant): raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    configuration['target_keys'] = unavailable
    code, output, error = invoke(capsys, *command('apply', path, reference, '--resume', str(proposal.operation_id)))
    diagnostic = json.loads(error)['error']
    assert code == 4 and output == '' and diagnostic['effects'] == 'INSPECT_JOURNAL' and 'known_result' not in diagnostic
    assert (_snapshot(app), staged_frames(app, proposal)) == before
    aborting, _, _ = host(app, monkeypatch, proposal, kind='abort', target_keys=unavailable)
    progress(invoke(capsys, *command('abort', path, aborting)), proposal, 'ABORTED')
    assert m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches


@pytest.mark.parametrize('fault', ['output', 'cleanup'])
def test_returned_switch_progress_survives_output_or_disposal_failure(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    proposal, path, activation, output = sealed(app, tmp_path, monkeypatch, capsys)
    reference, configuration, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation),
        dispose_failure=fault == 'cleanup')
    arguments = command('switch', path, reference, '--activation', str(output))
    if fault == 'output':
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', unavailable)
            code = cli.main(list(arguments))
        captured = capsys.readouterr()
        text, error = captured.out, captured.err
    else:
        code, text, error = invoke(capsys, *arguments)
    diagnostic = json.loads(error)['error']
    assert code == 4 and text == '' and 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in error
    assert diagnostic['known_result']['phase'] == 'PENDING' and diagnostic['known_result']['plan_digest'] == activation.digest
    assert diagnostic['artifact_result']['artifact_directory_durable'] is True
    assert m.status(activation, app.owner, pin=pin(activation)).phase == 'PENDING'
    configuration['dispose_failure'] = False
    before = _snapshot(app)
    progress(invoke(capsys, *command('switch', path, reference, '--activation', str(output),
        '--resume', str(activation.operation_id))), activation, 'PENDING')
    assert _snapshot(app) == before


def test_direct_async_payload_resolver_refuses_before_connection_or_coroutine_creation(active, tmp_path, monkeypatch, capsys, recwarn):
    app = active
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    module = ModuleType('payload_async_resolver_' + uuid4().hex)
    observed = {'connect': 0, 'dispose': 0, 'resolver': 0}
    class AsyncResolver:
        async def __call__(self, tenant):
            observed['resolver'] += 1
            return target_keys(tenant)
    def factory():
        from cryptalis.cli_host import PayloadApplyContext
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
        return PayloadApplyContext(engine=owned, source_keys=keys, target_keys=AsyncResolver(),
            pin=pin(proposal), approval=app.approval)
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    before = _snapshot(app)
    code, output, error = invoke(capsys, *command('apply', path, module.__name__ + ':factory'))
    assert code == 2 and output == '' and json.loads(error)['error']['code'] == 'HostContextInvalid'
    assert observed == {'connect': 0, 'dispose': 1, 'resolver': 0} and _snapshot(app) == before
    import gc
    gc.collect()
    assert not any('was never awaited' in str(warning.message) for warning in recwarn)


def test_wrong_known_payload_context_disposes_owned_engine_before_connection_or_keys(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = api_plan(app, target_keys)
    path = artifact(proposal, tmp_path)
    module = ModuleType('payload_wrong_context_' + uuid4().hex)
    observed = {'connect': 0, 'dispose': 0, 'keys': 0}
    def factory():
        from cryptalis.cli_host import ApplyContext
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
        def resolver(tenant):
            observed['keys'] += 1
            pytest.fail('wrong context family reached provider work')
        return ApplyContext(engine=owned, keys=resolver, pin=pin(proposal), approval=app.approval)
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    before = _snapshot(app)
    code, output, error = invoke(capsys, *command('apply', path, module.__name__ + ':factory'))
    assert code == 2 and output == '' and json.loads(error)['error']['code'] == 'HostContextInvalid'
    assert observed == {'connect': 0, 'dispose': 1, 'keys': 0} and _snapshot(app) == before
