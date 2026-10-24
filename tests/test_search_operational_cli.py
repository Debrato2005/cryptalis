"""Search CLI retains saved proposals and independent host authority."""
from dataclasses import replace
import io
import json
import os
import stat
import sys
from types import ModuleType
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import IntegrityError

from cryptalis import cli, migration as m, rotation as r
from cryptalis.crypto import Keyring
from cryptalis.sqlalchemy import attach
from migration_commit_proxy import lost_commit_reply
from search_rotation_worker import target_keys
from payload_rotation_worker import target_keys as payload_keys
from test_migration import application, engine, frames, keys, publish, run, TENANT
from test_operational_cli import invoke
from test_owned_sequences import _snapshot
from test_rewrap_abort import index_identity
from test_payload_operational_cli import artifact, progress
from test_payload_rotation_execution import staged_frames
from test_search_rotation_lifecycle import plan as api_plan
from test_migration_multitable import multiple_tables, OTHER_TENANT


def test_search_cli_plan_persists_exact_read_only_proposal_without_staging(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app)
        publish(app)
        source, output = tmp_path / 'active-source.json', tmp_path / 'search-proposal.json'
        source.write_bytes(app.plan.artifact)
        module = ModuleType('search_cli_planning_' + uuid4().hex)
        observed = {'factory': 0, 'dispose': 0}

        def factory():
            # Keep the old-command RED behavioral rather than a collection failure.
            from cryptalis.cli_host import SearchPlanningContext
            observed['factory'] += 1
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return SearchPlanningContext(engine=owned, source_keys=keys, target_keys=target_keys,
                source_pin=app.pin, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048, restore=None)

        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before, original_frames, original_index = _snapshot(app), frames(app, True), index_identity(app)
        code, output_json, error = invoke(capsys, 'keys', 'rotate', 'search', 'plan', str(source),
            '--host-context', module.__name__ + ':factory', '--out', str(output), '--json')
        assert code == 0 and error == '', (code, error)
        proposal = r.SearchRotationPlan(output.read_bytes())
        summary = json.loads(output_json)
        assert summary['scope'] == 'search_preparation_plan' and summary['phase'] == 'PREPARED'
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
    target = plan.source.target_id if isinstance(plan, r.SearchRotationPlan) else plan.target_id
    return m.DeploymentPin(target, plan.operation_id, plan.digest, phase)


def command(action, path, reference, *extra):
    return ('keys', 'rotate', 'search', action, str(path), '--host-context', reference, *extra, '--json')


def host(app, monkeypatch, proposal, *, kind='apply', **options):
    configuration = dict(source_keys=keys, target_keys=target_keys, source_pin=app.pin,
        pin=pin(proposal) if proposal is not None else None, approval=app.approval, restore=None)
    configuration.update(options)
    observed = {'factory': 0, 'source': 0, 'target': 0, 'connect': 0, 'dispose': 0}
    module = ModuleType('search_cli_context_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import (SearchPlanningContext, SearchApplyContext, SearchStatusContext,
            SearchSealingContext, SearchSwitchContext, SearchActivationContext, SearchAbortContext)
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
        if kind == 'status': return SearchStatusContext(**shared)
        if kind == 'plan':
            return SearchPlanningContext(engine=owned, source_keys=source, target_keys=target,
                source_pin=configuration['source_pin'], restore=configuration['restore'],
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        if kind == 'abort':
            return SearchAbortContext(engine=owned, source_keys=source,
                source_pin=configuration['source_pin'], approval=configuration['approval'])
        shared['approval'] = configuration['approval']
        if kind == 'activate': return SearchActivationContext(target_keys=target, **shared)
        shared.update(source_keys=source, target_keys=target)
        if kind == 'seal': return SearchSealingContext(copy_rows_per_second=0.5,
            copy_wal_bytes_per_row=2048, **shared)
        return (SearchSwitchContext if kind == 'switch' else SearchApplyContext)(**shared)
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


@pytest.fixture
def active():
    with application() as app:
        run(app); publish(app)
        yield app


def prepared(app, tmp_path, monkeypatch, capsys):
    proposal = api_plan(app)
    path = artifact(proposal, tmp_path)
    reference, _, _ = host(app, monkeypatch, proposal)
    progress(invoke(capsys, *command('apply', path, reference)), proposal, 'BACKFILLED')
    return proposal, path


def sealed(app, tmp_path, monkeypatch, capsys):
    proposal, path = prepared(app, tmp_path, monkeypatch, capsys)
    reference, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'search-activation.json'
    code, text, error = invoke(capsys, *command('seal', path, reference, '--out', str(output)))
    assert code == 0 and error == ''
    summary = json.loads(text)
    assert summary['scope'] == 'search_activation_artifact' and 'phase' not in summary and 'known_result' not in summary
    return proposal, path, m.MigrationPlan(output.read_bytes()), output


def table_frames(app, proposal, *, staged=False):
    result = {}
    with app.owner.connect() as connection:
        quote = connection.dialect.identifier_preparer.quote
        for model in proposal.source.document['lock']['models']:
            columns = [quote(field['payload_column'] + '_rotation' if staged else field['column']) for field in model['fields']]
            rows = connection.exec_driver_sql(f'SELECT id,' + ','.join(columns) + f' FROM "{app.schema}".' + quote(model['table']) + ' ORDER BY id')
            result[model['table_id']] = {identity: tuple(None if value is None else bytes(value) for value in values)
                for identity, *values in rows}
    return result


def index_inventory(app):
    with app.owner.connect() as connection:
        return connection.exec_driver_sql('SELECT c.relname,c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind=%s ORDER BY c.relname',
            (app.schema, 'i')).all()


def search_after_payload(tenant):
    return target_keys(tenant, source=payload_keys)


def test_mixed_search_cli_preserves_payload_two_and_exact_storage_bytes_through_publication(tmp_path, monkeypatch, capsys):
    with multiple_tables(boolean_note=True) as app:
        run(app); publish(app)
        from test_payload_rotation_plan import plan as payload_plan
        from test_payload_rotation_cutover import seal as seal_payload, switch as switch_payload, activate as activate_payload
        payload = payload_plan(app, payload_keys)
        assert r.apply_payload_rotation(payload, app.owner, keys=keys, target_keys=payload_keys,
            pin=m.DeploymentPin(payload.source.target_id, payload.operation_id, payload.digest, 'PREPARED'), approval=app.approval).phase == 'BACKFILLED'
        payload_activation = seal_payload(app, payload)
        assert switch_payload(app, payload, payload_activation).phase == 'PENDING'
        activate_payload(app, payload_activation)
        proposal = api_plan(app, target=search_after_payload, source=payload_keys)
        path = artifact(proposal, tmp_path)
        original, indexes = table_frames(app, proposal), index_inventory(app)
        reference, _, _ = host(app, monkeypatch, proposal, source_keys=payload_keys, target_keys=search_after_payload)
        progress(invoke(capsys, *command('apply', path, reference, '--max-chunks', '1')), proposal, 'EXPANDED')
        prefix = table_frames(app, proposal, staged=True)
        assert table_frames(app, proposal) == original
        progress(invoke(capsys, *command('apply', path, reference, '--resume', str(proposal.operation_id))), proposal, 'BACKFILLED')
        complete = table_frames(app, proposal, staged=True)
        first_model = proposal.source.document['lock']['models'][0]['table_id']
        for identity in sorted(prefix[first_model])[:3]: assert complete[first_model][identity] == prefix[first_model][identity]
        storage_fields = 0
        for model in proposal.source.document['lock']['models']:
            for identity, values in complete[model['table_id']].items():
                for field, old, frame in zip(model['fields'], original[model['table_id']][identity], values):
                    if field['descriptor']['representation'] != 'cf1-packed-equality/v1':
                        assert frame == old
                        storage_fields += 1
                    elif frame is not None:
                        assert frame[:10] == old[:10] and int.from_bytes(frame[6:10], 'big') == 2
                        assert int.from_bytes(frame[10:14], 'big') == 2 and frame[14:46] != old[14:46]
                        assert frame[46:58] != old[46:58]
                    else: assert old is None
        assert storage_fields > 0
        inspector, status_configuration, observed = host(app, monkeypatch, proposal, kind='status')
        def forbidden(*args, **kwargs): pytest.fail('key-free status or target-only retry reached source keys')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            summary = progress(invoke(capsys, *command('status', path, inspector)), proposal, 'BACKFILLED')
        assert summary['runtime_metadata_matches'] is False and summary['verification'] == 'NOT_PERFORMED'
        assert observed['source'] == observed['target'] == 0
        sealer, _, _ = host(app, monkeypatch, proposal, kind='seal', source_keys=payload_keys, target_keys=search_after_payload)
        output, repeated = tmp_path / 'search-a.json', tmp_path / 'search-a-repeated.json'
        before = _snapshot(app), table_frames(app, proposal, staged=True)
        for destination in (output, repeated): assert invoke(capsys, *command('seal', path, sealer, '--out', str(destination)))[0] == 0
        assert output.read_bytes() == repeated.read_bytes() and (_snapshot(app), table_frames(app, proposal, staged=True)) == before
        activation = m.MigrationPlan(output.read_bytes())
        switching, authority, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation),
            source_keys=payload_keys, target_keys=search_after_payload)
        progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output))), activation, 'PENDING')
        assert table_frames(app, proposal) == complete and index_inventory(app) == indexes
        authority['source_keys'] = forbidden
        progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output),
            '--resume', str(activation.operation_id))), activation, 'PENDING')
        activating, _, _ = host(app, monkeypatch, proposal, kind='activate', pin=pin(activation, 'ACTIVATING'),
            source_keys=forbidden, target_keys=search_after_payload)
        progress(invoke(capsys, *command('activate', output, activating)), activation, 'ACTIVE')
        status_configuration['pin'] = pin(activation, 'ACTIVE')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            summary = progress(invoke(capsys, *command('status', output, inspector)), activation, 'ACTIVE')
        assert summary['runtime_metadata_matches'] is True and summary['verification'] == 'NOT_PERFORMED'
        sessions = attach(app.mapping, app.runtime, lock=activation.lock_bytes, keys=search_after_payload,
                          deployment=(activation, pin(activation, 'ACTIVE')))
        for tenant in (TENANT, OTHER_TENANT):
            with sessions(tenant_id=tenant) as session:
                for model, expected in ((app.Customer, app.source), (app.other, app.other_source)):
                    rows = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(model).where(model.tenant_id == tenant))}
                    assert rows == {identity: value for identity, value in expected.items() if value[0] == tenant}
                    found = set(session.scalars(select(model.id).where(model.tenant_id == tenant, model.name.in_(['雪😀', '']))))
                    assert found == {identity for identity, value in expected.items() if value[0] == tenant and value[1] in ('雪😀', '')}
                assert {row.id: row.note for row in session.scalars(select(app.other).where(app.other.tenant_id == tenant))} == {
                    identity: app.notes[identity] for identity, value in app.other_source.items() if value[0] == tenant}
        with sessions(tenant_id=TENANT) as session:
            session.add(app.Customer(id=UUID(int=2000), tenant_id=TENANT, name='', label='duplicate'))
            with pytest.raises(IntegrityError) as duplicate: session.commit()
            assert duplicate.value.orig.sqlstate == '23505'
            session.rollback()
        assert table_frames(app, proposal) == complete and index_inventory(app) == indexes


@pytest.mark.parametrize('staged', [False, True])
def test_search_cli_source_only_cancel_and_terminal_retry_preserve_later_edit(active, tmp_path, monkeypatch, capsys, staged):
    app = active
    proposal = api_plan(app)
    path = artifact(proposal, tmp_path)
    if staged:
        applying, _, _ = host(app, monkeypatch, proposal)
        progress(invoke(capsys, *command('apply', path, applying, '--max-chunks', '1')), proposal, 'EXPANDED')
    original = frames(app, True)
    def forbidden(tenant): pytest.fail('search cancellation reached target keys')
    cancelling, _, observed = host(app, monkeypatch, proposal, kind='abort', target_keys=forbidden)
    progress(invoke(capsys, *command('abort', path, cancelling)), proposal, 'ABORTED')
    assert frames(app, True) == original and observed['target'] == 0
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
    with factory(tenant_id=TENANT) as session:
        session.get(app.Customer, UUID(int=101)).name = 'latest source edit after search cancellation'
        session.commit()
    before = _snapshot(app)
    progress(invoke(capsys, *command('abort', path, cancelling)), proposal, 'ABORTED')
    assert _snapshot(app) == before and observed['target'] == 0


def test_search_seal_lost_output_preserves_artifact_only_facts_and_identical_reseal(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal, path = prepared(app, tmp_path, monkeypatch, capsys)
    sealer, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'retained-search-a.json'
    before = _snapshot(app), staged_frames(app, proposal)
    with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
        stream.setattr(sys, 'stdout', unavailable)
        code = cli.main(list(command('seal', path, sealer, '--out', str(output))))
    captured = capsys.readouterr()
    diagnostic = json.loads(captured.err)['error']
    assert code == 4 and captured.out == '' and 'known_result' not in diagnostic
    assert diagnostic['artifact_result']['artifact_published'] is True and diagnostic['artifact_result']['artifact_directory_durable'] is True
    assert 'phase' not in diagnostic['artifact_result'] and (_snapshot(app), staged_frames(app, proposal)) == before
    repeated = tmp_path / 'resealed-search-a.json'
    assert invoke(capsys, *command('seal', path, sealer, '--out', str(repeated)))[0] == 0
    assert repeated.read_bytes() == output.read_bytes()


def test_search_switch_lost_commit_reply_retries_saved_activation_with_target_custody_only(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal, path, activation, output = sealed(app, tmp_path, monkeypatch, capsys)
    reference, configuration, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
        configuration['connection'] = url
        code, text, error = invoke(capsys, *command('switch', path, reference, '--activation', str(output)))
        diagnostic = json.loads(error)['error']
        assert code == 4 and text == '' and dropped.wait(5) and diagnostic['effects'] == 'INSPECT_JOURNAL'
        assert 'known_result' not in diagnostic and output.read_bytes() == activation.artifact
    configuration.pop('connection')
    def forbidden(tenant): pytest.fail('committed search switch retry called source resolver')
    configuration['source_keys'] = forbidden
    before = _snapshot(app)
    progress(invoke(capsys, *command('switch', path, reference, '--activation', str(output),
        '--resume', str(activation.operation_id))), activation, 'PENDING')
    assert _snapshot(app) == before


def test_search_cli_kind_resume_and_stale_pin_refuse_without_key_or_data_effects(active, tmp_path, monkeypatch, capsys):
    app = active
    proposal = api_plan(app)
    path, source = artifact(proposal, tmp_path), artifact(app.plan, tmp_path)
    reference, configuration, observed = host(app, monkeypatch, proposal)
    before = _snapshot(app)
    for arguments in (command('apply', source, reference), command('activate', path, reference),
            command('apply', path, reference, '--resume', str(uuid4()))):
        assert invoke(capsys, *arguments)[0] == 2 and observed['factory'] == 0 and _snapshot(app) == before
    configuration['pin'] = replace(pin(proposal), plan_digest='0' * 64)
    assert invoke(capsys, *command('apply', path, reference))[0] == 2
    assert observed['source'] == observed['target'] == observed['connect'] == 0 and _snapshot(app) == before


@pytest.mark.parametrize('wrong', ['async_resolver', 'known_context'])
def test_search_cli_host_shape_refusal_disposes_before_connection_or_keys(active, tmp_path, monkeypatch, capsys, wrong, recwarn):
    app = active
    proposal = api_plan(app)
    path = artifact(proposal, tmp_path)
    module = ModuleType('search_host_shape_' + uuid4().hex)
    observed = {'connect': 0, 'dispose': 0, 'keys': 0}
    class AsyncResolver:
        async def __call__(self, tenant):
            observed['keys'] += 1
            return target_keys(tenant)
    def factory():
        from cryptalis.cli_host import SearchApplyContext, PayloadStatusContext
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
        if wrong == 'known_context': return PayloadStatusContext(engine=owned, pin=pin(proposal))
        return SearchApplyContext(engine=owned, source_keys=keys, target_keys=AsyncResolver(), pin=pin(proposal), approval=app.approval)
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    before = _snapshot(app)
    code, text, error = invoke(capsys, *command('apply', path, module.__name__ + ':factory'))
    assert code == 2 and text == '' and json.loads(error)['error']['code'] == 'HostContextInvalid'
    assert observed == {'connect': 0, 'dispose': 1, 'keys': 0} and _snapshot(app) == before
    import gc
    gc.collect()
    assert not any('was never awaited' in str(warning.message) for warning in recwarn)


if 'CRYPTALIS_FRESH_CLUSTER_DIR' in os.environ:
    import test_adopted_rewrap as recovery
    adopted = recovery.adopted
else:
    @pytest.fixture
    def adopted():
        pytest.skip('run the --search-cli genuine fresh-cluster profile')


def test_genuine_adopted_search_cli_seals_saved_activation_and_latest_native_exit(adopted, tmp_path, monkeypatch, capsys):
    app = adopted
    app.plan, app.pin, app.schema = app.source, app.source_pin, recovery.fresh.SCHEMA
    app.approval, app.role = recovery.MAINTENANCE, recovery.fresh.MANIFEST['runtime_role']
    source, path = artifact(app.plan, tmp_path), tmp_path / 'adopted-search.json'
    reference, configuration, observed = host(app, monkeypatch, None, kind='plan', restore=app.binding)
    from cryptalis.restore import RestoreBinding
    changed = app.binding.document
    changed['source']['plan_digest'] = '0' * 64
    configuration['restore'] = RestoreBinding(m._canonical(changed))
    def forbidden(tenant): pytest.fail('wrong restored search authority reached keys')
    configuration.update(source_keys=forbidden, target_keys=forbidden)
    before = _snapshot(app)
    assert invoke(capsys, *command('plan', source, reference, '--out', str(path)))[0] == 2
    assert observed['source'] == observed['target'] == 0 and _snapshot(app) == before and not path.exists()
    configuration.update(source_keys=keys, target_keys=target_keys, restore=app.binding)
    assert invoke(capsys, *command('plan', source, reference, '--out', str(path)))[0] == 0
    proposal = r.SearchRotationPlan(path.read_bytes())
    assert proposal.document['format'] == 'cryptalis.search-rotation/v2' and proposal.restore_binding.artifact == app.binding.artifact
    applying, _, _ = host(app, monkeypatch, proposal)
    progress(invoke(capsys, *command('apply', path, applying, '--max-chunks', '1')), proposal, 'EXPANDED')
    progress(invoke(capsys, *command('apply', path, applying, '--resume', str(proposal.operation_id))), proposal, 'BACKFILLED')
    sealer, _, _ = host(app, monkeypatch, proposal, kind='seal')
    output = tmp_path / 'adopted-search-a.json'
    assert invoke(capsys, *command('seal', path, sealer, '--out', str(output)))[0] == 0
    activation = m.MigrationPlan(output.read_bytes())
    assert activation.document['format'] == 'cryptalis.transition/v7'
    switching, _, _ = host(app, monkeypatch, proposal, kind='switch', pin=pin(activation))
    progress(invoke(capsys, *command('switch', path, switching, '--activation', str(output))), activation, 'PENDING')
    activating, _, _ = host(app, monkeypatch, proposal, kind='activate', pin=pin(activation, 'ACTIVATING'))
    progress(invoke(capsys, *command('activate', output, activating)), activation, 'ACTIVE')
    assert activation.document['restore_lineage'] == [app.binding.document]
    recovery.current_edit(app, activation, target_keys, 'latest adopted CLI search value')
    from cryptalis import deprotection as d
    from test_reverse_operational_cli import artifact as reverse_artifact, reverse_host, finish_cli
    reverse = d.plan(activation, app.owner, source_pin=pin(activation, 'ACTIVE'), keys=target_keys,
        plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'], backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    reverse_path = reverse_artifact(reverse, tmp_path)
    execution, authority, _ = reverse_host(app, monkeypatch, plan=reverse, resolver=target_keys)
    finish_cli(app, reverse, reverse_path, execution, authority, monkeypatch, capsys)
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest adopted CLI search value']
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT id,tenant_id,name FROM "{app.schema}".customer').all()
    assert {str(identity): [str(tenant), value] for identity, tenant, value in rows} == expected
