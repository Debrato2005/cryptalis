"""Root rewrap on an explicitly adopted, genuinely restored PG16 target."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, restore, rotation
from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.crypto.keys import WrappedRoot
from cryptalis.sqlalchemy import attach
from rewrap_worker import PublicRewrapProvider, TARGET_WRAPPER, target_keys
from migration_commit_proxy import lost_commit_reply
from test_fresh_cluster_export import dump, environment as dump_environment
import test_fresh_cluster_restore as fresh

MAINTENANCE = m.MaintenanceApproval('fresh target quarantined; all inventoried writers stopped', 3600)


def pin(plan, phase):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


@pytest.fixture
def adopted():
    owner = fresh.engine('CRYPTALIS_TEST_DATABASE_URL')
    runtime = fresh.engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    with owner.begin() as connection:
        connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{fresh.SCHEMA}" CASCADE')
    fresh.restore(fresh.WORKDIR / 'protected.sql', 'CRYPTALIS_TEST_DATABASE_URL')
    source, source_pin = fresh.artifacts()
    binding = restore.plan(source, owner, pin=source_pin, keys=fresh.keys, approval=fresh.approval())
    try:
        yield SimpleNamespace(owner=owner, runtime=runtime, source=source,
                              source_pin=source_pin, binding=binding)
    finally:
        runtime.dispose()
        owner.dispose()


def snapshot(app):
    with app.owner.connect() as connection:
        journal = connection.exec_driver_sql(f'SELECT operation_id,plan_digest,state FROM "{fresh.SCHEMA}".'
            f'"{m.JOURNAL}" ORDER BY operation_id').all()
        rows = connection.exec_driver_sql(f'SELECT id,tenant_id,name,label FROM "{fresh.SCHEMA}".customer ORDER BY id').all()
        facts = m._facts(connection, app.source.document['lock']['models'][0])
    return journal, rows, facts


def frame_bytes(app):
    with app.owner.connect() as connection:
        return {identity: bytes(frame) if frame is not None else None for identity, frame in
            connection.exec_driver_sql(f'SELECT id,name FROM "{fresh.SCHEMA}".customer')}


def index_identity(app):
    name = app.source.document['lock']['models'][0]['fields'][0]['payload_column'] + '_eq'
    with app.owner.connect() as connection:
        return tuple(connection.exec_driver_sql('SELECT oid::text,relfilenode::text FROM pg_catalog.pg_class '
            'WHERE oid=pg_catalog.to_regclass(%s)', (f'"{fresh.SCHEMA}"."{name}"',)).one())


def proposal(app):
    return rotation.plan_rewrap(app.source, app.owner, source_pin=app.source_pin,
        keys=fresh.keys, target_keys=target_keys, verify_rows_per_second=1000, restore=app.binding)


def pending(app, plan):
    return rotation.apply_rewrap(plan, app.owner, keys=fresh.keys, target_keys=target_keys,
                                pin=pin(plan.activation_plan, 'PREPARED'), approval=MAINTENANCE)


def test_adopted_plan_is_read_only_and_retains_original_authority(adopted):
    app = adopted
    original = app.source.artifact
    before = snapshot(app)
    plan = proposal(app)
    assert snapshot(app) == before and app.source.artifact == original
    assert plan.document['format'] == 'cryptalis.rewrap/v2'
    assert plan.document['restore'] == app.binding.document
    assert plan.source.artifact == original
    successor = plan.activation_plan
    assert successor.document['format'] == 'cryptalis.transition/v5'
    assert successor.document['target'] == app.binding.target
    assert successor.document['target'] != app.source.document['target']
    assert successor.document['predecessors'] == app.source.document.get('predecessors', []) + [
        {'operation_id': str(app.source.operation_id), 'plan_digest': app.source.digest}]
    assert successor.document['restore_lineage'] == [app.binding.document]
    assert m.MigrationPlan(successor.artifact).artifact == successor.artifact
    assert restore.RestoreBinding(app.binding.artifact).digest == app.binding.digest
    for fault in ('empty', 'duplicate', 'target', 'probe', 'downgrade'):
        document = successor.document
        if fault == 'empty': document['restore_lineage'] = []
        elif fault == 'duplicate': document['restore_lineage'] *= 2
        elif fault == 'target': document['target'][3] += 1
        elif fault == 'probe':
            assert document['restore_lineage'][0]['restatements']
            document['restore_lineage'][0]['restatements'][0].pop('probe')
        else: document.update(format='cryptalis.transition/v1', kind='protect')
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(document))
    document = plan.document
    document['format'] = 'cryptalis.rewrap/v1'
    with pytest.raises(m.TransitionFailure): rotation.RewrapPlan(m._canonical(document))
    document = plan.document
    document.pop('restore')
    with pytest.raises(m.TransitionFailure): rotation.RewrapPlan(m._canonical(document))
    assert snapshot(app) == before


def test_adopted_pending_retry_publication_preserves_frames_and_search(adopted):
    app = adopted
    plan = proposal(app)
    successor = plan.activation_plan
    before, index = frame_bytes(app), index_identity(app)
    assert pending(app, plan).phase == 'PENDING'
    paused = snapshot(app)
    assert pending(app, rotation.RewrapPlan(plan.artifact)).phase == 'PENDING'
    assert snapshot(app) == paused
    assert frame_bytes(app) == before and index_identity(app) == index
    with app.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as blocked:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}".customer SET label=%s', ('blocked',))
        assert blocked.value.orig.sqlstate == '55000'
    assert m.apply(successor, app.owner, keys=target_keys, pin=pin(successor, 'ACTIVATING'),
                   approval=MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    assert frame_bytes(app) == before and index_identity(app) == index
    mapping, Customer = fresh.customer_mapping()
    try:
        sessions = attach(mapping, app.runtime, lock=successor.lock_bytes, keys=target_keys,
                          deployment=(successor, pin(successor, 'ACTIVE')))
        with sessions(tenant_id=fresh.TENANT) as session:
            assert session.scalar(select(Customer.id).where(Customer.name == 'edited while protected')) == UUID(int=101)
            assert {str(row.id): [str(row.tenant_id), row.name] for row in session.scalars(select(Customer))} == fresh.MANIFEST['expected']
            session.get(Customer, UUID(int=101)).name = 'latest adopted rewrap value'
            session.commit()
        with sessions(tenant_id=fresh.TENANT) as session:
            assert session.scalar(select(Customer.id).where(Customer.name.in_(['latest adopted rewrap value']))) == UUID(int=101)
    finally:
        mapping.dispose()


def test_adopted_pending_cancellation_restores_source_without_target_keys(adopted, monkeypatch, tmp_path):
    app = adopted
    plan = proposal(app)
    before, index = frame_bytes(app), index_identity(app)
    assert pending(app, plan).phase == 'PENDING'
    monkeypatch.setattr(PublicRewrapProvider, 'unwrap', lambda *args: pytest.fail('cancellation used target custody'))
    assert rotation.abort_rewrap(plan, app.owner, keys=fresh.keys, pin=app.source_pin,
                                 approval=MAINTENANCE).phase == 'ABORTED'
    assert frame_bytes(app) == before and index_identity(app) == index
    assert m.check_deployment(app.source, app.owner, pin=app.source_pin, restore=app.binding) is None
    mapping, Customer = fresh.customer_mapping()
    try:
        sessions = attach(mapping, app.runtime, lock=app.source.lock_bytes, keys=fresh.keys,
                          deployment=(app.source, app.source_pin, app.binding))
        with sessions(tenant_id=fresh.TENANT) as session:
            session.get(Customer, UUID(int=101)).name = 'latest after adopted cancellation'
            session.commit()
        edited = snapshot(app)
        assert rotation.abort_rewrap(rotation.RewrapPlan(plan.artifact), app.owner, keys=fresh.keys,
                                     pin=app.source_pin, approval=MAINTENANCE).phase == 'ABORTED'
        assert snapshot(app) == edited
        abort_in_fresh_process(plan, app.source_pin, tmp_path)
        assert snapshot(app) == edited
    finally:
        mapping.dispose()


@pytest.mark.parametrize('fault', ['binding_identity', 'target', 'journal', 'pin', 'custody',
                                  'probe', 'unselected_generation', 'authentication', 'root_material'])
def test_adopted_authority_and_frame_failures_have_no_effects_and_recover(adopted, fault):
    app = adopted
    binding, source_pin = app.binding, app.source_pin
    original = frame_bytes(app)[UUID(int=101)]
    if fault in ('binding_identity', 'target', 'custody', 'probe'):
        document = binding.document
        if fault == 'binding_identity': document['source']['plan_digest'] = '0' * 64
        elif fault == 'target': document['target'][3] += 1
        elif fault == 'custody': document['custody'][str(fresh.TENANT)] = '0' * 64
        else:
            assert document['restatements'], 'fresh restore must exercise a real restated CHECK'
            document['restatements'][0].pop('probe')
        binding = restore.RestoreBinding(m._canonical(document))
    elif fault == 'pin':
        source_pin = replace(source_pin, plan_digest='0' * 64)
    elif fault == 'journal':
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}"."{m.JOURNAL}" SET state=state || %s::jsonb '
                'WHERE operation_id=%s', ('{"unplanned":true}', app.source.operation_id))
    elif fault in ('unselected_generation', 'authentication'):
        changed = bytearray(original)
        if fault == 'unselected_generation': changed[6:10] = (2).to_bytes(4, 'big')
        else: changed[-1] ^= 1
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}".customer SET name=%s WHERE id=%s',
                                      (bytes(changed), UUID(int=101)))
    before, calls = snapshot(app), []
    source_policy = fresh.keys(fresh.TENANT).policy
    def source_keys(tenant):
        calls.append(tenant)
        return fresh.keys(tenant)
    target = target_keys
    if fault == 'root_material':
        class WrongRoot(PublicRewrapProvider):
            def unwrap(self, wrapper, context): return b'\x17' * 32
        def target(tenant):
            ring = target_keys(tenant)
            return Keyring(ring.policy, {WrongRoot.provider_id: WrongRoot()})
    class ClosedEngine:
        def connect(self): pytest.fail('missing restore probe reached a database connection')
    checked_engine = ClosedEngine() if fault == 'probe' else app.owner
    with pytest.raises((m.TransitionFailure, CryptoFailure)):
        rotation.plan_rewrap(app.source, checked_engine, source_pin=source_pin, keys=source_keys,
            target_keys=target, verify_rows_per_second=1000, restore=binding)
    assert snapshot(app) == before and fresh.keys(fresh.TENANT).policy == source_policy
    if fault in ('binding_identity', 'target', 'journal', 'pin', 'custody', 'probe'):
        assert calls == []
    if fault == 'journal':
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}"."{m.JOURNAL}" SET state=state - %s '
                'WHERE operation_id=%s', ('unplanned', app.source.operation_id))
    elif fault in ('unselected_generation', 'authentication'):
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}".customer SET name=%s WHERE id=%s',
                                      (original, UUID(int=101)))
    assert proposal(app).source.digest == app.source.digest


def disk_artifacts(plan, directory, phase):
    artifact, deployment, approval = (directory / name for name in ('rewrap.json', 'pin.json', 'approval.json'))
    artifact.write_bytes(plan.artifact)
    deployment.write_text(json.dumps(asdict(pin(plan.activation_plan, phase)), default=str))
    approval.write_text(json.dumps(asdict(MAINTENANCE)))
    return artifact, deployment, approval


def test_adopted_sigkill_after_pending_reloads_same_artifacts_and_publishes(adopted, tmp_path):
    app = adopted
    plan = proposal(app)
    before, index = frame_bytes(app), index_identity(app)
    paths = disk_artifacts(plan, tmp_path, 'PREPARED')
    command = [sys.executable, str(Path(__file__).with_name('rewrap_worker.py')), *map(str, paths)]
    child = subprocess.Popen(command + ['pending', 'pause'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=30), 'worker did not report committed PENDING'
        assert json.loads(child.stdout.readline()) == {'phase': 'PENDING'}
        child.kill()
        child.communicate(timeout=20)
        assert child.returncode == -signal.SIGKILL
        assert frame_bytes(app) == before and index_identity(app) == index
        paths[1].write_text(json.dumps(asdict(pin(plan.activation_plan, 'ACTIVATING')), default=str))
        resumed = subprocess.run(command + ['activate', 'exit'], capture_output=True, text=True, timeout=45)
        assert resumed.returncode == 0, 'fresh rewrap publication failed; diagnostics suppressed'
        assert json.loads(resumed.stdout) == {'observed': 'PENDING', 'phase': 'ACTIVE',
            'operation_id': str(plan.operation_id), 'digest': plan.activation_plan.digest}
        assert paths[0].read_bytes() == plan.artifact
        assert frame_bytes(app) == before and index_identity(app) == index
        assert m.check_deployment(plan.activation_plan, app.owner,
                                  pin=pin(plan.activation_plan, 'ACTIVE')) is None
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


@pytest.mark.parametrize('action', ['pending', 'abort'])
def test_adopted_lost_commit_reply_inspects_committed_identity(adopted, action):
    app = adopted
    plan = proposal(app)
    if action == 'abort': assert pending(app, plan).phase == 'PENDING'
    before, index = frame_bytes(app), index_identity(app)
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
        proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                creator=lambda: psycopg.connect(url, connect_timeout=5))
        try:
            with pytest.raises(m.TransitionFailure):
                if action == 'pending':
                    rotation.apply_rewrap(plan, proxied, keys=fresh.keys, target_keys=target_keys,
                                          pin=pin(plan.activation_plan, 'PREPARED'), approval=MAINTENANCE)
                else:
                    rotation.abort_rewrap(plan, proxied, keys=fresh.keys,
                                          pin=app.source_pin, approval=MAINTENANCE)
            assert dropped.wait(5), 'proxy did not discard terminal COMMIT reply'
        finally:
            proxied.dispose()
    committed = snapshot(app)
    if action == 'pending': assert pending(app, plan).phase == 'PENDING'
    else:
        assert rotation.abort_rewrap(plan, app.owner, keys=fresh.keys, pin=app.source_pin,
                                     approval=MAINTENANCE).phase == 'ABORTED'
    assert snapshot(app) == committed
    assert frame_bytes(app) == before and index_identity(app) == index


class SecondPublicProvider(PublicRewrapProvider):
    provider_id = UUID(int=9502)


def second_keys(tenant):
    source = target_keys(tenant)
    provider = SecondPublicProvider()
    wrappers = tuple(WrappedRoot(provider.provider_id, root.context, TARGET_WRAPPER)
                     for root in source.policy.wrappers)
    return Keyring(replace(source.policy, wrappers=wrappers), {provider.provider_id: provider})


def publish_rewrap(app, plan, source, target):
    successor = plan.activation_plan
    assert rotation.apply_rewrap(plan, app.owner, keys=source, target_keys=target,
                                pin=pin(successor, 'PREPARED'), approval=MAINTENANCE).phase == 'PENDING'
    assert m.apply(successor, app.owner, keys=target, pin=pin(successor, 'ACTIVATING'),
                   approval=MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    return successor


def current_edit(app, active, key_resolver, value, binding=None):
    mapping, Customer = fresh.customer_mapping()
    runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**fresh.environment(
            'CRYPTALIS_TEST_RUNTIME_DATABASE_URL', active.document['target'][0]
            if binding is None else binding.target[0])))
    deployment = (active, pin(active, 'ACTIVE'), binding) if binding is not None else (active, pin(active, 'ACTIVE'))
    try:
        sessions = attach(mapping, runtime, lock=active.lock_bytes, keys=key_resolver, deployment=deployment)
        with sessions(tenant_id=fresh.TENANT) as session:
            assert session.get(Customer, UUID(int=101)).name is not None
            session.get(Customer, UUID(int=101)).name = value
            session.commit()
        with sessions(tenant_id=fresh.TENANT) as session:
            assert session.scalar(select(Customer.id).where(Customer.name == value)) == UUID(int=101)
            assert session.scalar(select(Customer.id).where(Customer.name.in_([value, 'absent public value']))) == UUID(int=101)
    finally:
        runtime.dispose()
        mapping.dispose()


def test_repeated_rewrap_backup_and_new_adoption_extend_flat_lineage(adopted, tmp_path):
    app = adopted
    first = publish_rewrap(app, proposal(app), fresh.keys, target_keys)
    class ClosedEngine:
        def connect(self): pytest.fail('unsupported generation rotation connected')
    def forbidden(tenant): pytest.fail('unsupported generation rotation prepared keys')
    stable = snapshot(app)
    for prepare in (rotation.plan_search_rotation,):
        with pytest.raises(m.TransitionFailure, match='adopted_generation_rotation_unsupported'):
            prepare(first, ClosedEngine(), source_pin=pin(first, 'ACTIVE'), keys=forbidden,
                target_keys=forbidden, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=700, wal_bytes_per_row=700)
    assert snapshot(app) == stable
    current_edit(app, first, target_keys, 'latest before second rewrap')
    before = frame_bytes(app)
    next_plan = rotation.plan_rewrap(first, app.owner, source_pin=pin(first, 'ACTIVE'), keys=target_keys,
                                    target_keys=second_keys, verify_rows_per_second=1000)
    assert next_plan.document['restore'] is None
    second = publish_rewrap(app, next_plan, target_keys, second_keys)
    assert second.document['restore_lineage'] == first.document['restore_lineage'] == [app.binding.document]
    assert frame_bytes(app) == before
    current_edit(app, second, second_keys, 'latest before v5 backup')
    backup = fresh.WORKDIR / ('adopted-v5-' + second.operation_id.hex + '.sql')
    dump(backup, fresh.SCHEMA, dump_environment('CRYPTALIS_TEST_DATABASE_URL'))
    fresh.restore(backup, 'CRYPTALIS_TEST_DATABASE_URL', fresh.PLAIN_DATABASE)
    owner = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**fresh.environment('CRYPTALIS_TEST_DATABASE_URL', fresh.PLAIN_DATABASE)))
    runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**fresh.environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', fresh.PLAIN_DATABASE)))
    restored = SimpleNamespace(owner=owner, runtime=runtime, source=second)
    try:
        binding = restore.plan(second, owner, pin=pin(second, 'ACTIVE'), keys=second_keys, approval=fresh.approval())
        assert binding.source_target == second.document['target'] and binding.target != binding.source_target
        assert binding.document['restatements'] == []  # Only inherited CHECK spelling is needed here.
        assert m.check_deployment(second, owner, pin=pin(second, 'ACTIVE'), restore=binding) is None
        current_edit(restored, second, second_keys, 'latest after v5 adoption', binding)
        third_plan = rotation.plan_rewrap(second, owner, source_pin=pin(second, 'ACTIVE'), keys=second_keys,
            target_keys=fresh.keys, verify_rows_per_second=1000, restore=binding)
        third = publish_rewrap(restored, third_plan, second_keys, fresh.keys)
        assert third.document['restore_lineage'] == [app.binding.document, binding.document]
        assert third.document['target'] == binding.target
        document = third.document
        document['restore_lineage'].reverse()
        stable = snapshot(restored)
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(document))
        assert snapshot(restored) == stable
        assert third.document['predecessors'] == second.document['predecessors'] + [
            {'operation_id': str(second.operation_id), 'plan_digest': second.digest}]
        current_edit(restored, third, fresh.keys, 'latest after second adoption')
        expected = dict(fresh.MANIFEST['expected'])
        expected[str(UUID(int=101))] = [str(fresh.TENANT), 'latest after second adoption']
        decrypt_remove_and_restart(restored, third, fresh.keys, expected)
    finally:
        runtime.dispose()
        owner.dispose()


def decrypt_remove_and_restart(app, active, key_resolver, expected):
    import cryptalis.deprotection as d
    reverse = d.plan(active, app.owner, source_pin=pin(active, 'ACTIVE'), keys=key_resolver,
        plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=700)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                  'public disposable latest values; no retained protected backup authority')
    assert d.apply(reverse, app.owner, keys=key_resolver, pin=pin(reverse, 'PREPARED'),
                   approval=MAINTENANCE, consent=consent).phase == 'PLAINTEXT_PENDING'
    assert d.apply(reverse, app.owner, keys=key_resolver, pin=pin(reverse, 'PLAINTEXT_ACTIVATING'),
                   approval=MAINTENANCE, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'fresh native child refuses Cryptalis imports', 'public fixture backup kept quarantined', True)
    assert d.remove(reverse, app.owner, pin=pin(reverse, 'REMOVING'), approval=MAINTENANCE,
                    removal=removal, consent=consent).phase == 'REMOVED'
    assert d.check_removed(reverse, app.owner, pin=pin(reverse, 'REMOVED')) is None
    from test_fresh_cluster_export import assert_source_metadata
    assert_source_metadata(SimpleNamespace(owner=app.owner, schema=fresh.SCHEMA), fresh.MANIFEST['runtime_role'])
    script = r'''
import importlib.abc, json, os, sys
from uuid import UUID
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import refused after removal')
sys.meta_path.insert(0, DenyCryptalis())
sys.path[:0] = json.loads(os.environ['NATIVE_RESTART_PATHS'])
try:
    import cryptalis
except ImportError:
    pass
else:
    raise AssertionError('Cryptalis import unexpectedly succeeded')
import psycopg
from psycopg import sql
expected = json.loads(sys.stdin.read())
table = sql.SQL('{}.customer').format(sql.Identifier(os.environ['NATIVE_RESTART_SCHEMA']))
with psycopg.connect(os.environ['NATIVE_RESTART_URL'], connect_timeout=5) as connection:
    actual = {str(identity): [str(tenant), value] for identity, tenant, value in
              connection.execute(sql.SQL('SELECT id,tenant_id,name FROM {}').format(table))}
    assert actual == expected
    assert all(value[1] is None or type(value[1]) is str for value in actual.values())
    assert connection.execute(sql.SQL('SELECT id FROM {} WHERE tenant_id=%s AND name=%s').format(table),
        (UUID(int=504), expected[str(UUID(int=101))][1])).fetchall() == [(UUID(int=101),)]
    added = UUID(int=29001)
    connection.execute(sql.SQL('INSERT INTO {} (id,tenant_id,name,label) VALUES (%s,%s,%s,%s)').format(table),
        (added, UUID(int=504), 'native restart public value', 'native'))
    assert connection.execute(sql.SQL('SELECT name FROM {} WHERE id=%s').format(table), (added,)).fetchone() == ('native restart public value',)
    connection.execute(sql.SQL('DELETE FROM {} WHERE id=%s').format(table), (added,))
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print(json.dumps({'native_latest_values': 'PASS', 'native_search_and_crud': 'PASS', 'cryptalis_imported': False}))
'''
    child_url = psycopg.conninfo.make_conninfo(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                                              dbname=active.document['target'][0])
    child = subprocess.run([sys.executable, '-B', '-I', '-c', script], input=json.dumps(expected),
        env=dict(os.environ, NATIVE_RESTART_PATHS=json.dumps(sys.path), NATIVE_RESTART_URL=child_url,
                 NATIVE_RESTART_SCHEMA=fresh.SCHEMA), capture_output=True, text=True, timeout=45)
    assert child.returncode == 0, 'native import-denied restart failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_latest_values': 'PASS',
        'native_search_and_crud': 'PASS', 'cryptalis_imported': False}


def abort_in_fresh_process(plan, source_pin, directory):
    paths = disk_artifacts(plan, directory, 'PREPARED')
    paths[1].write_text(json.dumps(asdict(source_pin), default=str))
    script = r'''
import json, pathlib, sys
from uuid import UUID
sys.path.insert(0, sys.argv[1])
from cryptalis import migration as m, rotation
from test_migration import engine, keys
try:
    plan = rotation.RewrapPlan(pathlib.Path(sys.argv[2]).read_bytes())
    raw = json.loads(pathlib.Path(sys.argv[3]).read_text())
    raw.update(target_id=UUID(raw['target_id']), operation_id=UUID(raw['operation_id']))
    pin = m.DeploymentPin(**raw)
    approval = m.MaintenanceApproval(**json.loads(pathlib.Path(sys.argv[4]).read_text()))
    connection_engine = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        result = rotation.abort_rewrap(plan, connection_engine, keys=keys, pin=pin, approval=approval)
    finally:
        connection_engine.dispose()
    print(json.dumps({'phase': result.phase, 'operation_id': str(result.operation_id)}))
except Exception as failure:
    print(json.dumps({'type': type(failure).__name__}))
    raise SystemExit(2)
'''
    child = subprocess.run([sys.executable, '-B', '-c', script, str(Path(__file__).parent), *map(str, paths)],
                           capture_output=True, text=True, timeout=45)
    assert child.returncode == 0, 'independent cancellation inspection failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'phase': 'ABORTED', 'operation_id': str(plan.operation_id)}


def test_adopted_cancel_wrong_authority_and_post_guard_drop_rollback(adopted, monkeypatch):
    app = adopted
    plan = proposal(app)
    assert pending(app, plan).phase == 'PENDING'
    paused = snapshot(app)
    for source_keys, source_pin, engine in (
            (fresh.keys, replace(app.source_pin, plan_digest='0' * 64), app.owner),
            (target_keys, app.source_pin, app.owner),
            (fresh.keys, app.source_pin, app.runtime)):
        with pytest.raises((m.TransitionFailure, CryptoFailure)):
            rotation.abort_rewrap(plan, engine, keys=source_keys, pin=source_pin, approval=MAINTENANCE)
        assert snapshot(app) == paused
    original = m._drop_guards
    dropped = []
    def interrupted(connection, successor):
        original(connection, successor)
        dropped.append(True)
        raise RuntimeError('private interruption after guard drop')
    with monkeypatch.context() as patch:
        patch.setattr(m, '_drop_guards', interrupted)
        with pytest.raises(m.TransitionFailure) as failure:
            rotation.abort_rewrap(plan, app.owner, keys=fresh.keys, pin=app.source_pin, approval=MAINTENANCE)
        assert 'private interruption' not in str(failure.value)
    assert dropped == [True] and snapshot(app) == paused
    with app.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as fenced:
            connection.exec_driver_sql(f'UPDATE "{fresh.SCHEMA}".customer SET label=%s', ('still fenced',))
        assert fenced.value.orig.sqlstate == '55000'
    assert rotation.abort_rewrap(plan, app.owner, keys=fresh.keys, pin=app.source_pin,
                                 approval=MAINTENANCE).phase == 'ABORTED'
    assert m.check_deployment(app.source, app.owner, pin=app.source_pin, restore=app.binding) is None
