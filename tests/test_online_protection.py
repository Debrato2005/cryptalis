"""Native-write capture and online protection on real PostgreSQL 16."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, create_engine, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import deprotection as d
from cryptalis import migration as m
from cryptalis import online
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_migration import DOMAIN, FIELD_ID, TABLE_ID, keys


def _engine(variable):
    return create_engine(
        'postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(os.environ[variable]))


@pytest.fixture
def app(request):
    required = ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL',
                'CRYPTALIS_TEST_SOURCE_URL')
    if any(not os.environ.get(name) for name in required):
        pytest.skip('run through scripts/test_postgres.py --source-role with all three private URLs')
    owner = _engine(required[0])
    target = _engine(required[1])
    source = _engine(required[2])
    schema = 'cryptalis_online_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    parameters = getattr(request, 'param', (Text(collation='C'), ('body-10', 'body-20', 'body-30')))
    dtype, values = parameters[:2]
    scalar = not isinstance(dtype, Text)
    queries = parameters[2] if len(parameters) == 3 else [] if scalar else ['equality']
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('body', dtype, nullable=True),
        Column('label', String(64, collation='C'), nullable=True))

    class Customer:
        pass

    mapping.map_imperatively(Customer, table)
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with owner.connect() as connection:
            owner_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with target.connect() as connection:
            target_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with source.connect() as connection:
            source_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        assert len({owner_role, target_role, source_role}) == 3
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            for role in (source_role, target_role):
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
            connection.exec_driver_sql(
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{schema}"."customer" TO {quote(source_role)}')
        owner_factory = sessionmaker(owner, expire_on_commit=False)
        with owner_factory() as session:
            session.add_all((Customer(id=UUID(int=i), body=value, label=f'label-{i}')
                             for i, value in zip((10, 20, 30), values)))
            session.commit()
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1',
            'domain_id': str(DOMAIN), 'models': [{'model': 'Customer', 'table_id': str(TABLE_ID),
                'tenancy': {'single_tenant': True}, 'fields': [
                    {'name': 'body', 'field_id': str(FIELD_ID), 'protect': True,
                     'queries': list(queries), 'accept_leakage': list(queries)},
                    {'name': 'label', 'field_id': str(UUID(int=FIELD_ID.int + 1)), 'protect': True,
                     'queries': [], 'accept_leakage': []}]}]}
        inventory = WriterInventory(True, (Writer(TABLE_ID, 'native application', 'sqlalchemy',
            evidence='independent source-role ORM sessions over the declared table'),))
        proposal = online.plan(json.dumps(declaration).encode(), mapping, owner,
            source_role=source_role, writers=inventory, max_rows=1, max_bytes=4096,
            search_reviews=(SearchReview(FIELD_ID, False,
                'Disposable fixture values; declared order, equality and frequency leakage accepted.'),) if queries else (),
            keys=keys, runtime_role=target_role, target_id=uuid4(),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
        pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
        approval = online.OnlineApproval(
            'Only the declared owner performs maintenance; native source writers use the capture trigger.',
            True, 3600)
        yield SimpleNamespace(owner=owner, target=target, source=source, schema=schema,
            mapping=mapping, table=table, Customer=Customer,
            source_factory=sessionmaker(source, expire_on_commit=False),
            source_role=source_role, target_role=target_role, inventory=inventory,
            plan=proposal, pin=pin, approval=approval)
    finally:
        source.dispose()
        target.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()


def _source_rows(app):
    with app.source_factory() as session:
        return {row.id: (row.body, row.label)
                for row in session.scalars(select(app.Customer).order_by(app.Customer.id))}


def _payloads(app, proposal):
    fields = proposal.document['lock']['models'][0]['fields']
    columns = ', '.join('"' + field['payload_column'] + '"' for field in fields)
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(
            f'SELECT id, {columns} FROM "{app.schema}"."customer" ORDER BY id').all()
    return {row[0]: tuple(None if value is None else bytes(value) for value in row[1:])
            for row in rows}


def _pin(proposal, phase):
    return m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, phase)


def _assert_source_denied(connection, schema, identity):
    with pytest.raises(DBAPIError) as caught:
        connection.exec_driver_sql(
            f'UPDATE "{schema}"."customer" SET label=%s WHERE id=%s', ('blocked', identity))
    assert getattr(caught.value.orig, 'sqlstate', None) in ('42501', '55000')
    connection.rollback()


def test_native_writes_are_captured_fenced_caught_up_and_published(app):
    original = _source_rows(app)
    source_connection = app.source.connect()
    try:
        wrong_pin = replace(app.pin, plan_digest='f' * 64)
        with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
            online.apply(app.plan, app.owner, keys=keys, pin=wrong_pin,
                         approval=app.approval, max_chunks=1)
        assert online.status(app.plan, app.owner, pin=app.pin).phase == 'PREPARED'

        first = online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                             approval=app.approval, max_chunks=1)
        assert first.phase == 'CAPTURING' and first.committed_chunks == 1
        after_first = _payloads(app, app.plan)
        stable_id = UUID(int=10)
        assert all(after_first[stable_id])

        online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                     approval=app.approval, max_chunks=1)
        after_second = _payloads(app, app.plan)
        stable_bytes = after_second[UUID(int=20)]
        assert all(stable_bytes)

        with app.source_factory() as session:
            row = session.get(app.Customer, stable_id)
            row.body = 'edited below the completed backfill position'
            row.label = 'edited-label'
            session.add(app.Customer(id=UUID(int=5), body='inserted below cursor', label='new'))
            session.commit()
        with app.source_factory() as session:
            session.delete(session.get(app.Customer, UUID(int=30)))
            session.commit()
        with app.source_factory() as session:
            session.add(app.Customer(id=UUID(int=30), body=None, label='reinserted'))
            session.commit()

        assert _source_rows(app)[UUID(int=5)] == ('inserted below cursor', 'new')
        assert _source_rows(app)[UUID(int=30)] == (None, 'reinserted')
        dirty = _payloads(app, app.plan)
        assert dirty[stable_id] == (None, None)
        assert dirty[UUID(int=20)] == stable_bytes

        with pytest.raises(DBAPIError) as denied:
            with app.target.connect() as connection:
                connection.exec_driver_sql(f'SELECT id FROM "{app.schema}"."customer"').all()
        assert getattr(denied.value.orig, 'sqlstate', None) == '42501'

        online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                     approval=app.approval, max_chunks=1, fence=True)
        assert online.status(app.plan, app.owner, pin=app.pin).phase == 'FENCED'
        _assert_source_denied(source_connection, app.schema, stable_id)
        with pytest.raises(DBAPIError) as fresh_denied:
            with app.source.connect() as connection:
                connection.exec_driver_sql(
                    f'UPDATE "{app.schema}"."customer" SET label=%s WHERE id=%s',
                    ('blocked', stable_id))
        assert getattr(fresh_denied.value.orig, 'sqlstate', None) in ('42501', '55000')

        with pytest.raises(m.TransitionFailure):
            online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                     approval=app.approval, max_chunks=12)
        sealed = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(
                f'UPDATE "{app.schema}"."customer" SET body=%s WHERE id=%s',
                ('owner-side mutation invalidates sealed artifact', stable_id))
        with pytest.raises(m.TransitionFailure):
            online.switch(app.plan, app.owner, successor=sealed, keys=keys,
                          pin=app.pin, approval=app.approval)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(
                f'UPDATE "{app.schema}"."customer" SET body=%s WHERE id=%s',
                ('edited below the completed backfill position', stable_id))
        successor = online.switch(app.plan, app.owner, successor=sealed, keys=keys,
                                  pin=app.pin, approval=app.approval)
        activating = _pin(successor, 'ACTIVATING')
        assert m.apply(successor, app.owner, keys=keys, pin=activating,
                       approval=m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600),
                       until='ACTIVE').phase == 'ACTIVE'
        active = _pin(successor, 'ACTIVE')

        _assert_source_denied(source_connection, app.schema, stable_id)
        with pytest.raises(DBAPIError) as fresh_source_denied:
            with app.source.connect() as connection:
                connection.exec_driver_sql(f'SELECT id FROM "{app.schema}"."customer"').all()
        assert getattr(fresh_source_denied.value.orig, 'sqlstate', None) == '42501'

        attached = attach(app.mapping, app.target, lock=successor.lock_bytes,
                          keys=keys, deployment=(successor, active))
        expected = dict(original)
        expected[stable_id] = ('edited below the completed backfill position', 'edited-label')
        expected[UUID(int=5)] = ('inserted below cursor', 'new')
        expected[UUID(int=30)] = (None, 'reinserted')
        with attached(tenant_id=TABLE_ID, expire_on_commit=False) as session:
            observed = {row.id: (row.body, row.label)
                        for row in session.scalars(select(app.Customer).order_by(app.Customer.id))}
            assert observed == expected
            assert session.scalar(select(app.Customer.id).where(
                app.Customer.body == 'edited below the completed backfill position')) == stable_id
            row = session.get(app.Customer, UUID(int=20))
            row.body = 'edited while protected'
            row.label = 'protected-edit'
            session.commit()
            expected[row.id] = ('edited while protected', 'protected-edit')
            assert session.scalar(select(app.Customer.body).where(
                app.Customer.body == 'edited while protected')) == 'edited while protected'

        reverse = d.plan(successor, app.owner, source_pin=active, keys=keys,
            plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            True, 'Public disposable online-protection fixture; no protected backup retained.')
        reverse_approval = m.MaintenanceApproval(
            'Only the declared owner performs maintenance; application writers pause for reversal.', 3600)
        assert d.apply(reverse, app.owner, keys=keys,
            pin=_pin(reverse, 'PREPARED'), approval=reverse_approval, consent=consent,
            until='PLAINTEXT_PENDING').phase == 'PLAINTEXT_PENDING'
        activating_reverse = _pin(reverse, 'PLAINTEXT_ACTIVATING')
        assert d.apply(reverse, app.owner, keys=keys, pin=activating_reverse,
            approval=reverse_approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        assert _source_rows(app) == expected
        fresh_target = _engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        try:
            with pytest.raises(DBAPIError) as target_revoked:
                with fresh_target.connect() as connection:
                    connection.exec_driver_sql(f'SELECT id FROM "{app.schema}"."customer"').all()
            assert getattr(target_revoked.value.orig, 'sqlstate', None) == '42501'
        finally:
            fresh_target.dispose()
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'Original native source-role ORM reads current rows after decrypt-back.',
            'No historical protected backup retained.', True)
        assert d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'),
            approval=reverse_approval, removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, app.owner, pin=_pin(reverse, 'REMOVED')) is None
        assert _source_rows(app) == expected
    finally:
        source_connection.close()


@pytest.mark.parametrize('fence', [False, True], ids=['before-fence', 'after-fence'])
def test_abort_preserves_committed_native_edits_and_restores_source_access(app, fence):
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1)
    identity = UUID(int=10)
    with app.source_factory() as session:
        row = session.get(app.Customer, identity)
        row.body = 'latest native edit survives abort'
        session.commit()
    if fence:
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                     approval=app.approval, max_chunks=0, fence=True)
    result = online.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
    assert result.phase == 'ABORTED'
    rows = _source_rows(app)
    assert rows[identity][0] == 'latest native edit survives abort'
    with app.source.connect() as connection:
        assert connection.exec_driver_sql(
            f'SELECT body FROM "{app.schema}"."customer" WHERE id=%s', (identity,)).scalar_one() == rows[identity][0]
    with pytest.raises(DBAPIError) as target_denied:
        with app.target.connect() as connection:
            connection.exec_driver_sql(f'SELECT id FROM "{app.schema}"."customer"').all()
    assert getattr(target_denied.value.orig, 'sqlstate', None) == '42501'


def test_native_update_waits_for_backfill_row_then_invalidates_its_shadow(app):
    online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=0)
    locked,release,writer_ready = threading.Event(),threading.Event(),threading.Event()
    writer_pid = []
    def held_keys(tenant):
        locked.set()
        assert release.wait(10), 'test did not release the locked backfill row'
        return keys(tenant)
    def backfill():
        return online.apply(app.plan,app.owner,keys=held_keys,pin=app.pin,
                            approval=app.approval,max_chunks=1)
    def write():
        with app.source.connect() as c:
            writer_pid.append(c.exec_driver_sql('SELECT pg_backend_pid()').scalar_one())
            c.commit()
            writer_ready.set()
            c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET body=%s WHERE id=%s',
                             ('concurrent native version',UUID(int=10)))
            c.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        batch = pool.submit(backfill)
        try:
            assert locked.wait(5)
            writer = pool.submit(write)
            assert writer_ready.wait(5)
            waiting = False
            deadline = time.monotonic()+5
            while time.monotonic()<deadline:
                with app.owner.connect() as c:
                    waiting = c.exec_driver_sql('SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=%s AND NOT granted)',
                                               (writer_pid[0],)).scalar_one()
                if waiting: break
                time.sleep(.02)
            assert waiting and not writer.done(), 'native update must wait for the backfill row lock'
        finally:
            release.set()
        assert batch.result(timeout=10).committed_rows == 1
        writer.result(timeout=10)
    assert _source_rows(app)[UUID(int=10)][0] == 'concurrent native version'
    assert _payloads(app,app.plan)[UUID(int=10)] == (None,None)
    online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=10,fence=True)
    sealed = online.seal(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval)
    assert sealed.document['online_verification'][str(TABLE_ID)]['rows'] == 3


def test_killed_executor_resumes_same_chunks_and_retained_activation_artifact(app,tmp_path):
    artifact = tmp_path/'capture.json'
    artifact.write_bytes(app.plan.artifact)
    successor_path = tmp_path/'activation.json'
    worker = '''
import os,signal,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from test_migration import engine,keys
from cryptalis import online,migration as m
p=online.OnlineProtectionPlan(Path(sys.argv[2]).read_bytes())
pin=m.DeploymentPin(p.target_id,p.operation_id,p.digest,'PREPARED')
approval=online.OnlineApproval('Exclude owner and DDL writers for the public fixture.',True,3600)
owner=engine('CRYPTALIS_TEST_DATABASE_URL')
if sys.argv[4]=='chunk':
    online.apply(p,owner,keys=keys,pin=pin,approval=approval,max_chunks=1)
elif sys.argv[4]=='fence':
    online.apply(p,owner,keys=keys,pin=pin,approval=approval,max_chunks=0,fence=True)
elif sys.argv[4]=='switch':
    a=m.MigrationPlan(Path(sys.argv[3]).read_bytes())
    online.switch(p,owner,successor=a,keys=keys,pin=pin,approval=approval)
elif sys.argv[4]=='activate':
    a=m.MigrationPlan(Path(sys.argv[3]).read_bytes())
    current=m.DeploymentPin(a.target_id,a.operation_id,a.digest,'ACTIVATING')
    m.apply(a,owner,keys=keys,pin=current,approval=m.MaintenanceApproval(approval.owner_writer_exclusion,3600),until='ACTIVE')
    owner.dispose()
    raise SystemExit(0)
owner.dispose()
os.kill(os.getpid(),signal.SIGKILL)
'''
    def child(phase):
        result = subprocess.run([sys.executable,'-c',worker,str(Path(__file__).parent),
                                 str(artifact),str(successor_path),phase],
                                capture_output=True,text=True,timeout=20)
        assert result.returncode == (0 if phase=='activate' else -signal.SIGKILL), result.stderr
    child('chunk')
    prefix = _payloads(app,app.plan)[UUID(int=10)]
    assert all(prefix)
    assert online.status(app.plan,app.owner,pin=app.pin).committed_rows == 1
    child('chunk')
    assert _payloads(app,app.plan)[UUID(int=10)] == prefix
    child('fence')
    with app.source.connect() as c: _assert_source_denied(c,app.schema,UUID(int=10))
    online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=10)
    activation = online.seal(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval)
    successor_path.write_bytes(activation.artifact)
    child('switch')
    assert m.status(activation,app.owner,pin=_pin(activation,'PENDING')).phase == 'PENDING'
    with app.source.connect() as c: _assert_source_denied(c,app.schema,UUID(int=10))
    child('activate')
    assert m.status(activation,app.owner,pin=_pin(activation,'ACTIVE')).phase == 'ACTIVE'


def test_capture_and_key_authority_failures_preserve_the_committed_prefix(app):
    from test_online_recovery import generation
    online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=1)
    before = _payloads(app,app.plan)
    progress = online.status(app.plan,app.owner,pin=app.pin)
    stale = generation(keys,'payload')
    with pytest.raises(m.TransitionFailure,match='key_policy_changed'):
        online.apply(app.plan,app.owner,keys=stale,pin=app.pin,approval=app.approval,max_chunks=1)
    assert _payloads(app,app.plan) == before
    assert online.status(app.plan,app.owner,pin=app.pin) == progress
    capture = online._names(app.plan)[1]
    with app.owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER "{capture}"')
    with pytest.raises(m.TransitionFailure,match='online_capture_changed'):
        online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=1)
    assert _payloads(app,app.plan) == before
    with app.owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ENABLE ALWAYS TRIGGER "{capture}"')
        c.exec_driver_sql(f'GRANT SELECT ON "{app.schema}".customer TO PUBLIC')
    with pytest.raises(m.TransitionFailure,match='access_contract_changed'):
        online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=1)
    with app.owner.begin() as c:
        c.exec_driver_sql(f'REVOKE SELECT ON "{app.schema}".customer FROM PUBLIC')
    assert _payloads(app,app.plan) == before
    assert online.status(app.plan,app.owner,pin=app.pin) == progress
    with app.source_factory() as session:
        session.get(app.Customer,UUID(int=20)).body='x'*app.plan.document['batch_limits']['max_bytes']
        session.commit()
    with pytest.raises(m.TransitionFailure,match='online_row_exceeds_batch_bytes'):
        online.apply(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval,max_chunks=1)
    assert _payloads(app,app.plan)[UUID(int=10)] == before[UUID(int=10)]
    assert online.status(app.plan,app.owner,pin=app.pin) == progress
