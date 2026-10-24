"""Operational reverse CLI uses persisted proposals and separate host authority."""
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event

from cryptalis import cli, deprotection as d, migration as m
from cryptalis.crypto import Keyring
from cryptalis.sqlalchemy import attach
from test_deprotection import least_privilege_role, proposal as api_proposal, native_rows
from test_migration import application, engine, frames, keys, publish, run, TENANT, FIELD_ID
from test_operational_cli import invoke
from test_owned_sequences import _snapshot


def test_reverse_plan_persists_exact_read_only_proposal_for_current_active_values(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = 'latest value before CLI reverse proposal 雪'
            session.commit()
        source, output = tmp_path / 'active-source.json', tmp_path / 'reverse-plan.json'
        source.write_bytes(app.plan.artifact)
        role = least_privilege_role(app)
        module = ModuleType('reverse_cli_host_' + uuid4().hex)
        observed = {'factory': 0, 'dispose': 0}
        def host():
            # Keep RED a real old-command failure, not a missing-context import failure.
            from cryptalis.cli_host import ReversePlanningContext
            observed['factory'] += 1
            owned = engine('CRYPTALIS_TEST_DATABASE_URL')
            event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
            return ReversePlanningContext(engine=owned, keys=keys, source_pin=app.pin,
                plaintext_runtime_role=role, backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=700,
                wal_bytes_per_row=700, restore=None)
        module.factory = host
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        code, result, error = invoke(capsys, 'plan', '--reverse', str(source),
            '--host-context', module.__name__ + ':factory', '--out', str(output), '--json')
        assert code == 0 and error == '', (code, error)
        proposal = d.DeprotectionPlan(output.read_bytes())
        summary = json.loads(result)
        assert summary['scope'] == 'reverse_plan' and summary['phase'] == 'PREPARED'
        assert summary['source_operation_id'] == str(app.plan.operation_id)
        assert summary['operation_id'] == str(proposal.operation_id)
        assert summary['plan_digest'] == proposal.digest and summary['target_id'] == str(proposal.target_id)
        assert summary['authority'] == 'HOST_SUPPLIED_CONTEXT'
        assert summary['artifact_published'] is summary['artifact_directory_durable'] is True
        assert summary['host_configuration_effects'] == 'UNKNOWN'
        assert proposal.document['source_plan'] == app.plan.document
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        assert _snapshot(app) == before and observed == {'factory': 1, 'dispose': 1}
        assert m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches


def pin(plan, phase='PREPARED'):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def result(observed, plan, phase):
    code, output, error = observed
    assert code == 0 and error == '', (code, error)
    summary = json.loads(output)
    assert summary['scope'] == 'reverse_transition' and summary['phase'] == phase
    assert summary['operation_id'] == str(plan.operation_id) and summary['plan_digest'] == plan.digest
    assert summary['source_operation_id'] == str(plan.source.operation_id)
    assert summary['authority'] == 'HOST_SUPPLIED_PIN' and summary['host_configuration_effects'] == 'UNKNOWN'
    return summary


def reverse_host(app, monkeypatch, *, kind='apply', plan=None, **overrides):
    role = least_privilege_role(app) if kind == 'plan' else None
    configuration = dict(resolver=keys, source_pin=app.pin, restore=None, plaintext_role=role,
        pin=pin(plan) if plan else None, approval=app.approval,
        consent=d.PlaintextApproval(plan.target_id, plan.operation_id, plan.digest, True,
            'public disposable fixture backup obligations') if plan else None,
        removal=d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'native package-free fixture workload', 'public disposable retained fixtures', True) if plan else None)
    configuration.update(overrides)
    observed = {'factory': 0, 'keys': 0, 'connect': 0, 'dispose': 0}
    module = ModuleType('reverse_cli_context_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import ReversePlanningContext, ReverseApplyContext, RemovalContext
        observed['factory'] += 1
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        def dispose(*args):
            observed['dispose'] += 1
            if configuration.get('dispose_failure'):
                print('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
                raise OSError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        event.listen(owned, 'engine_disposed', dispose)
        def resolver(tenant):
            observed['keys'] += 1
            return configuration['resolver'](tenant)
        if kind == 'plan':
            return ReversePlanningContext(engine=owned, keys=resolver, source_pin=configuration['source_pin'],
                plaintext_runtime_role=configuration['plaintext_role'], backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700,
                restore=configuration['restore'])
        if kind == 'remove':
            return RemovalContext(engine=owned, pin=configuration['pin'], approval=configuration['approval'],
                                  consent=configuration['consent'], removal=configuration['removal'])
        return ReverseApplyContext(engine=owned, keys=resolver, pin=configuration['pin'],
            approval=configuration['approval'], consent=configuration['consent'])
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


def artifact(plan, directory):
    path = directory / (plan.operation_id.hex + '.json')
    path.write_bytes(plan.artifact)
    return path


def staged(app):
    with app.owner.connect() as connection:
        return dict(connection.exec_driver_sql(f'SELECT id,"_cryptalis_{FIELD_ID.hex}_plain" '
                                               f'FROM "{app.schema}".customer ORDER BY id').all())


@pytest.fixture
def active():
    with application() as app:
        run(app)
        publish(app)
        yield app


def finish_cli(app, plan, path, reference, configuration, monkeypatch, capsys):
    result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--json'), plan, 'PLAINTEXT_PENDING')
    refused = invoke(capsys, 'rollback', str(path), '--host-context', reference,
                     '--until', 'PLAINTEXT_ACTIVE', '--json')
    assert refused[0] == 3 and refused[1] == ''
    configuration['pin'] = pin(plan, 'PLAINTEXT_ACTIVATING')
    result(invoke(capsys, 'apply', str(path), '--host-context', reference,
        '--until', 'PLAINTEXT_ACTIVE', '--json'), plan, 'PLAINTEXT_ACTIVE')
    removal, approved, observed = reverse_host(app, monkeypatch, kind='remove', plan=plan,
        pin=pin(plan, 'REMOVING'), consent=configuration['consent'])
    def forbidden(*args, **kwargs): pytest.fail('approved removal must never prepare provider keys')
    with monkeypatch.context() as no_keys:
        no_keys.setattr(Keyring, 'prepare', forbidden)
        valid_removal = approved['removal']
        approved['removal'] = None
        before = _snapshot(app)
        rejected = invoke(capsys, 'remove', str(path), '--host-context', removal, '--json')
        assert rejected[0] == 2 and rejected[1] == ''
        assert json.loads(rejected[2])['error']['code'] == 'removal_approval_required'
        assert _snapshot(app) == before
        approved['removal'] = valid_removal
        result(invoke(capsys, 'remove', str(path), '--host-context', removal, '--json'), plan, 'REMOVED')
        approved['pin'] = pin(plan, 'REMOVED')
        result(invoke(capsys, 'remove', str(path), '--host-context', removal, '--json'), plan, 'REMOVED')
    assert d.check_removed(plan, app.owner, pin=pin(plan, 'REMOVED')) is None
    assert observed['factory'] == observed['dispose'] == 3


def test_current_value_rollback_resume_publication_and_keyless_removal(active, tmp_path, monkeypatch, capsys):
    app = active
    original = frames(app, True)
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
    result(invoke(capsys, 'rollback', str(path), '--host-context', reference,
        '--until', 'BACKFILLED', '--chunk-size', '2', '--json'), plan, 'BACKFILLED')
    complete = staged(app)
    assert complete == {identity: value for identity, (_, value) in app.source.items()}
    result(invoke(capsys, 'apply', str(path), '--host-context', reference, '--resume', str(plan.operation_id),
        '--until', 'VERIFIED', '--json'), plan, 'VERIFIED')
    assert staged(app) == complete and frames(app, True) == original
    result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--json'), plan, 'PLAINTEXT_PENDING')
    before = _snapshot(app)
    refused = invoke(capsys, 'rollback', str(path), '--host-context', reference,
                     '--abort', str(plan.operation_id), '--json')
    assert refused[0] == 3 and refused[1] == '' and _snapshot(app) == before
    finish_cli(app, plan, path, reference, configuration, monkeypatch, capsys)
    assert native_rows(app) == app.source and observed['factory'] == observed['dispose']
    # Original native uniqueness remains enforced after current-value decryption.
    from sqlalchemy.exc import IntegrityError
    with app.owner.connect() as connection:
        with pytest.raises(IntegrityError) as collision:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s', ('', UUID(int=102)))
        assert collision.value.orig.sqlstate == '23505'
        connection.rollback()
    assert native_rows(app) == app.source


@pytest.mark.parametrize('expanded', [False, True])
def test_reverse_abort_needs_no_provider_and_terminal_retry_survives_later_source_edit(active, tmp_path, monkeypatch, capsys, expanded):
    app = active
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
    if expanded:
        result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--until', 'EXPANDED', '--json'), plan, 'EXPANDED')
    def forbidden(tenant): pytest.fail('reverse abort must not resolve keys')
    configuration['resolver'] = forbidden
    old_frames = frames(app, True)
    result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--abort', str(plan.operation_id), '--json'), plan, 'ABORTED')
    assert frames(app, True) == old_frames and observed['keys'] == 0
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
    with factory(tenant_id=TENANT) as session:
        session.get(app.Customer, UUID(int=101)).name = 'latest source value after reverse cancellation'
        session.commit()
    before = _snapshot(app)
    result(invoke(capsys, 'apply', str(path), '--host-context', reference, '--abort', str(plan.operation_id), '--json'), plan, 'ABORTED')
    assert _snapshot(app) == before and observed['keys'] == 0
    assert m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches
    assert api_proposal(app).operation_id != plan.operation_id


@pytest.mark.parametrize('fault', ['source_pin', 'missing_consent', 'wrong_consent'])
def test_reverse_pin_and_consent_denials_precede_connection_and_keys(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
    if fault == 'source_pin': configuration['pin'] = app.pin
    elif fault == 'missing_consent': configuration['consent'] = None
    else: configuration['consent'] = replace(configuration['consent'], plan_digest='0' * 64)
    before = _snapshot(app)
    code, output, error = invoke(capsys, 'rollback', str(path), '--host-context', reference, '--json')
    assert code == 2 and output == ''
    assert json.loads(error)['error']['code'] == ('external_reverse_policy_mismatch' if fault == 'source_pin' else 'plaintext_approval_required')
    assert observed['connect'] == observed['keys'] == 0 and observed['dispose'] == 1
    assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['protection_kind', 'remove_kind', 'wrong_phase', 'conflict'])
def test_reverse_grammar_refuses_before_host_import(active, tmp_path, monkeypatch, capsys, fault):
    app = active
    plan = api_proposal(app)
    source, reverse = artifact(app.plan, tmp_path), artifact(plan, tmp_path)
    reference, _, observed = reverse_host(app, monkeypatch, plan=plan)
    if fault == 'protection_kind': arguments = ('rollback', str(source))
    elif fault == 'remove_kind': arguments = ('remove', str(source))
    elif fault == 'wrong_phase': arguments = ('rollback', str(reverse), '--until', 'ACTIVE')
    else: arguments = ('rollback', str(reverse), '--abort', str(plan.operation_id), '--until', 'BACKFILLED')
    before = _snapshot(app)
    code, output, error = invoke(capsys, *arguments, '--host-context', reference, '--json')
    assert code == 2 and output == '' and json.loads(error)['error']
    assert observed['factory'] == 0 and _snapshot(app) == before


def test_later_provider_outage_preserves_committed_plaintext_prefix_and_resumes(tmp_path, monkeypatch, capsys):
    with application(rows=3, protected_values=('public alpha', 'public beta', 'public gamma')) as app:
        run(app); publish(app)
        plan = api_proposal(app)
        path = artifact(plan, tmp_path)
        reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
        calls = []
        def later_outage(tenant):
            calls.append(tenant)
            if len(calls) == 2: raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
            return keys(tenant)
        configuration['resolver'] = later_outage
        original = frames(app, True)
        code, output, error = invoke(capsys, 'rollback', str(path), '--host-context', reference,
                                    '--until', 'BACKFILLED', '--chunk-size', '1', '--json')
        assert code == 4 and output == '' and json.loads(error)['error']['effects'] == 'INSPECT_JOURNAL'
        progress = d.status(plan, app.owner, pin=pin(plan))
        assert progress.phase == 'EXPANDED' and progress.committed_rows == progress.committed_chunks == 1
        prefix = staged(app)
        assert prefix[UUID(int=100)] == 'public alpha' and prefix[UUID(int=101)] is None
        assert frames(app, True) == original
        configuration['resolver'] = keys
        result(invoke(capsys, 'apply', str(path), '--host-context', reference, '--resume', str(plan.operation_id),
            '--until', 'BACKFILLED', '--chunk-size', '1', '--json'), plan, 'BACKFILLED')
        assert staged(app)[UUID(int=100)] == prefix[UUID(int=100)] and frames(app, True) == original
        assert observed['factory'] == observed['dispose']


def test_corrupt_source_refusal_retains_prefix_then_abort_allows_exact_repair(tmp_path, monkeypatch, capsys):
    with application(rows=3, protected_values=('public alpha', 'public beta', 'public gamma')) as app:
        run(app); publish(app)
        plan = api_proposal(app)
        path = artifact(plan, tmp_path)
        reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
        original = frames(app, True)
        with app.owner.begin() as connection:
            raw = original[UUID(int=101)]
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                (raw[:-1] + bytes([raw[-1] ^ 1]), UUID(int=101)))
        code, output, error = invoke(capsys, 'rollback', str(path), '--host-context', reference,
                                    '--until', 'BACKFILLED', '--chunk-size', '1', '--json')
        assert code in (3, 4) and output == '' and json.loads(error)['error']['effects'] == 'INSPECT_JOURNAL'
        assert d.status(plan, app.owner, pin=pin(plan)).committed_rows == 1
        assert staged(app)[UUID(int=100)] == 'public alpha'
        def forbidden(tenant): pytest.fail('corrupt source abort must not need keys')
        configuration['resolver'] = forbidden
        result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--abort', str(plan.operation_id), '--json'), plan, 'ABORTED')
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s', (original[UUID(int=101)], UUID(int=101)))
        assert frames(app, True) == original
        healthy = api_proposal(app)
        healthy_path = artifact(healthy, tmp_path)
        healthy_host, _, _ = reverse_host(app, monkeypatch, plan=healthy)
        result(invoke(capsys, 'rollback', str(healthy_path), '--host-context', healthy_host,
            '--until', 'BACKFILLED', '--json'), healthy, 'BACKFILLED')


@pytest.mark.parametrize('expanded', [False, True])
def test_late_expression_statistics_refuse_before_provider_then_exact_repair(active, tmp_path, monkeypatch, capsys, expanded):
    app = active
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan)
    if expanded:
        result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--until', 'EXPANDED', '--json'), plan, 'EXPANDED')
    name = f'"{app.schema}".cli_late_expression'
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'CREATE STATISTICS {name} ON (pg_catalog.octet_length(name)) FROM "{app.schema}".customer')
    def forbidden(tenant): pytest.fail('changed catalog must refuse before provider work')
    configuration['resolver'] = forbidden
    before = _snapshot(app)
    code, output, error = invoke(capsys, 'rollback', str(path), '--host-context', reference, '--until', 'BACKFILLED', '--json')
    assert code == 3 and output == '' and json.loads(error)['error']
    assert observed['keys'] == 0 and _snapshot(app) == before
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'DROP STATISTICS {name}')
    configuration['resolver'] = keys
    result(invoke(capsys, 'rollback', str(path), '--host-context', reference, '--until', 'BACKFILLED', '--json'), plan, 'BACKFILLED')


def test_reverse_planning_refuses_original_runtime_role_before_provider_work(active, tmp_path, monkeypatch, capsys):
    app = active
    source = artifact(app.plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, kind='plan', plaintext_role=app.role)
    def forbidden(tenant): pytest.fail('unsafe reverse role must not reach provider work')
    configuration['resolver'] = forbidden
    before = _snapshot(app)
    code, output, error = invoke(capsys, 'plan', '--reverse', str(source), '--host-context', reference,
                                '--out', str(tmp_path / 'denied.json'), '--json')
    assert code == 2 and output == '' and json.loads(error)['error']['code'] == 'distinct_plaintext_runtime_role_required'
    assert observed['keys'] == 0 and _snapshot(app) == before


@pytest.mark.parametrize('failure', ['output', 'dispose'])
def test_reverse_postcommit_output_or_cleanup_keeps_known_plaintext_progress(active, tmp_path, monkeypatch, capsys, failure):
    app = active
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, plan=plan, dispose_failure=failure == 'dispose')
    arguments = ['rollback', str(path), '--host-context', reference, '--json']
    if failure == 'output':
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', unavailable)
            code = cli.main(arguments)
        captured = capsys.readouterr()
        output, error = captured.out, captured.err
        assert 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in error
    else:
        code, output, error = invoke(capsys, *arguments)
    assert code == 4 and output == ''
    diagnostic = json.loads(error)['error']
    assert diagnostic['code'] == ('OutputUnavailable' if failure == 'output' else 'CleanupUnavailable')
    assert diagnostic['known_result']['phase'] == 'PLAINTEXT_PENDING'
    assert diagnostic['known_result']['operation_id'] == str(plan.operation_id)
    assert d.status(plan, app.owner, pin=pin(plan)).phase == 'PLAINTEXT_PENDING'
    before = _snapshot(app)
    configuration['dispose_failure'] = False
    result(invoke(capsys, *arguments), plan, 'PLAINTEXT_PENDING')
    assert _snapshot(app) == before and observed['factory'] == observed['dispose']


if 'CRYPTALIS_FRESH_CLUSTER_DIR' in os.environ:
    import test_adopted_rewrap as recovery
    adopted = recovery.adopted
else:
    @pytest.fixture
    def adopted():
        pytest.skip('run the --reverse-cli genuine fresh-cluster profile')


def test_genuine_adopted_source_reverse_cli_uses_explicit_binding_and_latest_native_exit(adopted, tmp_path, monkeypatch, capsys):
    app = adopted
    app.plan, app.pin, app.schema = app.source, app.source_pin, recovery.fresh.SCHEMA
    app.approval, app.role = recovery.MAINTENANCE, recovery.fresh.MANIFEST['runtime_role']
    source = artifact(app.plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, kind='plan',
        restore=app.binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
    from cryptalis.restore import RestoreBinding
    altered = app.binding.document
    altered['source']['plan_digest'] = '0' * 64
    configuration['restore'] = RestoreBinding(m._canonical(altered))
    def forbidden(tenant): pytest.fail('wrong explicit restored authority reached provider work')
    configuration['resolver'] = forbidden
    before = _snapshot(app)
    rejected = invoke(capsys, 'plan', '--reverse', str(source), '--host-context', reference,
                      '--out', str(tmp_path / 'wrong.json'), '--json')
    assert rejected[0] == 2 and rejected[1] == '' and observed['keys'] == 0 and _snapshot(app) == before
    configuration.update(restore=app.binding, resolver=keys)
    path = tmp_path / 'adopted-reverse.json'
    code, output, error = invoke(capsys, 'plan', '--reverse', str(source), '--host-context', reference,
                                '--out', str(path), '--json')
    assert code == 0 and error == '' and json.loads(output)['phase'] == 'PREPARED'
    plan = d.DeprotectionPlan(path.read_bytes())
    assert plan.document['restore'] == app.binding.document
    execution, authority, _ = reverse_host(app, monkeypatch, plan=plan)
    result(invoke(capsys, 'rollback', str(path), '--host-context', execution, '--until', 'BACKFILLED', '--json'), plan, 'BACKFILLED')
    prefix = staged(app)
    result(invoke(capsys, 'apply', str(path), '--host-context', execution, '--resume', str(plan.operation_id),
        '--until', 'VERIFIED', '--json'), plan, 'VERIFIED')
    assert staged(app) == prefix
    finish_cli(app, plan, path, execution, authority, monkeypatch, capsys)
    expected = recovery.fresh.MANIFEST['expected']
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT id,tenant_id,name FROM "{app.schema}".customer').all()
    assert {str(identity): [str(tenant), value] for identity, tenant, value in rows} == expected


def test_lost_removal_output_retains_removed_proof_and_explicit_keyless_retry(active, tmp_path, monkeypatch, capsys):
    app = active
    plan = api_proposal(app)
    path = artifact(plan, tmp_path)
    reference, configuration, observed = reverse_host(app, monkeypatch, kind='remove', plan=plan,
                                                      pin=pin(plan, 'REMOVING'))
    assert d.apply(plan, app.owner, keys=keys, pin=pin(plan), approval=app.approval,
                   consent=configuration['consent']).phase == 'PLAINTEXT_PENDING'
    assert d.apply(plan, app.owner, keys=keys, pin=pin(plan, 'PLAINTEXT_ACTIVATING'),
        approval=app.approval, consent=configuration['consent'], until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    def forbidden(*args, **kwargs): pytest.fail('lost removal reply must not require provider keys')
    with monkeypatch.context() as no_keys:
        no_keys.setattr(Keyring, 'prepare', forbidden)
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as unavailable, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', unavailable)
            code = cli.main(['remove', str(path), '--host-context', reference, '--json'])
        captured = capsys.readouterr()
        assert code == 4 and captured.out == '' and 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in captured.err
        diagnostic = json.loads(captured.err)['error']
        assert diagnostic['code'] == 'OutputUnavailable'
        assert diagnostic['known_result']['phase'] == 'REMOVED'
        assert diagnostic['known_result']['operation_id'] == str(plan.operation_id)
        assert diagnostic['known_result']['plan_digest'] == plan.digest
        assert diagnostic['effects'] == 'COMMITTED_PROGRESS'
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
                (f'"{app.schema}"."{m.JOURNAL}"',)).scalar_one() is None
            columns = dict(connection.exec_driver_sql('SELECT column_name,data_type FROM information_schema.columns '
                "WHERE table_schema=%s AND table_name='customer'", (app.schema,)).all())
        assert columns == {'id': 'uuid', 'tenant_id': 'uuid', 'name': 'text', 'label': 'text'}
        assert native_rows(app) == app.source
        assert d.check_removed(plan, app.owner, pin=pin(plan, 'REMOVED')) is None
        before = _snapshot(app)
        configuration['pin'] = pin(plan, 'REMOVED')
        result(invoke(capsys, 'remove', str(path), '--host-context', reference, '--json'), plan, 'REMOVED')
        assert _snapshot(app) == before
    assert observed['factory'] == observed['dispose'] == 2
