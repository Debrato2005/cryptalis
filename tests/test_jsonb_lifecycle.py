"""Native JSONB wire bytes survive rotations, capture and current-value removal."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
import subprocess
import sys
from uuid import UUID

import pytest
from sqlalchemy import JSON, null, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from cryptalis import deprotection as d, migration as m, online
from cryptalis.crypto.cf1 import FieldDescriptor, open_value
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
from test_jsonb_storage import BASE, LATEST, RAW_DOCUMENTS, current_edits, state, values, wire
from test_migration import FIELD_ID, TABLE_ID, TENANT, keys, publish, run
from test_online_protection import app, _payloads, _pin


VALUES = (BASE, [None, True, {'雪': '😀'}], 'json scalar', None, False, 17, 1.25)


@contextmanager
def jsonb_application(*, public_slots=False, none_as_null=False, value_default=None):
    with date_application(public_slots=public_slots, value_type=JSONB(none_as_null=none_as_null),
                          values=deepcopy(VALUES), value_default=value_default) as current:
        seed_native(current)
        yield current


def seed_native(app, *, column='name', scoped=True):
    """Include native numbers that the default Python JSON loader cannot retain."""
    assert column in ('name', 'body')
    with app.owner.begin() as connection:
        for index, document in enumerate(RAW_DOCUMENTS):
            columns = f'id,{column},label' + (',tenant_id' if scoped else '')
            placeholders = '%s,%s::pg_catalog.jsonb,%s' + (',%s' if scoped else '')
            parameters = (UUID(int=300 + index), document, 'native precise JSONB') + ((TENANT,) if scoped else ())
            connection.exec_driver_sql(f'INSERT INTO "{app.schema}".customer({columns}) VALUES ({placeholders})',
                                      parameters)
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET {column}=NULL WHERE id=%s',
                                  (UUID(int=104 if scoped else 30),))


def native_wire(app, *, column='name', connection=None):
    if column == 'name':
        return wire(app, connection)
    assert column == 'body'
    if connection is None:
        with app.owner.connect() as current:
            return native_wire(app, column=column, connection=current)
    return {identity: (sql_null, None if encoded is None else bytes(encoded))
            for identity, sql_null, encoded in connection.exec_driver_sql(
                f'SELECT id,body IS NULL,pg_catalog.jsonb_send(body) FROM "{app.schema}".customer ORDER BY id')}


def protected_wire(app, resolver, *, column='name', scoped=True):
    """Compare authenticated documents to the earlier native wire oracle."""
    field = next(field for model in app.plan.document['lock']['models'] for field in model['fields']
                 if field['field_id'] == str(FIELD_ID))
    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
    assert field['column'] == column and descriptor.value_codec == 'pg-jsonb-text/v1'
    prepared = {}
    result = {}
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT id,' + ('tenant_id,' if scoped else '')
            + f'{column} FROM "{app.schema}".customer ORDER BY id').all()
    for row in rows:
        tenant = row[1] if scoped else TABLE_ID
        if tenant not in prepared:
            prepared[tenant] = resolver(tenant).prepare()
        raw = row[2 if scoped else 1]
        value = open_value(None if raw is None else bytes(raw), descriptor, tenant, row[0], prepared[tenant])
        result[row[0]] = (value is None, None if value is None else b'\x01' + value.data)
    return result


def encoded_wire(rows):
    return {str(identity): [sql_null, None if body is None else body.hex()]
            for identity, (sql_null, body) in rows.items()}


def document_wire(connection, value):
    raw = connection.exec_driver_sql('SELECT pg_catalog.jsonb_send(%s::pg_catalog.jsonb)',
                                    (json.dumps(value),)).scalar_one()
    return False, bytes(raw)


def native_restart(schema, expected, *, none_as_null=False, column='name', scoped=True,
                   directory='/tmp', database_variable='CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
    child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from uuid import UUID
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from sqlalchemy import Column, JSON, MetaData, Table, Text, Uuid, create_engine, null, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, registry
schema, column = os.environ['JSONB_SCHEMA'], os.environ['JSONB_COLUMN']
expected = json.loads(os.environ['JSONB_EXPECTED'])
database = create_engine('postgresql+psycopg://', hide_parameters=True,
    creator=lambda: psycopg.connect(os.environ[os.environ['JSONB_DATABASE_VARIABLE']]))
mapping = registry(metadata=MetaData(schema=schema))
columns = [Column('id', Uuid, primary_key=True, autoincrement=False),
           Column(column, JSONB(none_as_null=os.environ['JSONB_NONE_AS_NULL'] == '1')), Column('label', Text)]
if os.environ['JSONB_SCOPED'] == '1': columns.append(Column('tenant_id', Uuid, nullable=False))
table = Table('customer', mapping.metadata, *columns)
class Customer: pass
mapping.map_imperatively(Customer, table, properties={'name': table.c[column]})
def frozen(value):
    if isinstance(value, dict): return ('dict', tuple((key, frozen(part)) for key, part in value.items()))
    if type(value) is list: return ('list', tuple(frozen(part) for part in value))
    return (type(value).__name__, value.hex() if type(value) is float else value)
def observed(connection):
    return {str(identity): [sql_null, None if body is None else bytes(body).hex()]
        for identity, sql_null, body in connection.exec_driver_sql(
            f'SELECT id,{column} IS NULL,pg_catalog.jsonb_send({column}) FROM "{schema}".customer')}
with Session(database) as session:
    assert observed(session.connection()) == expected
    for row in session.scalars(select(Customer)):
        body = expected[str(row.id)][1]
        assert frozen(row.name) == frozen(None if body is None else json.loads(bytes.fromhex(body)[1:]))
    dtype, typmod = session.connection().exec_driver_sql(
        'SELECT a.atttypid::regtype::text,a.atttypmod FROM pg_catalog.pg_attribute a '
        'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
        ('"' + schema + '".customer', column)).one()
    assert dtype == 'jsonb' and typmod == -1
    row = session.get(Customer, UUID(next(iter(expected))))
    row.name = JSON.NULL
    session.flush(); session.refresh(row)
    assert row.name is None and observed(session.connection())[str(row.id)] == [False, b'\\x01null'.hex()]
    row.name = null()
    session.flush(); session.refresh(row)
    assert row.name is None and observed(session.connection())[str(row.id)] == [True, None]
    session.rollback()
with database.connect() as connection: assert observed(connection) == expected
database.dispose(); mapping.dispose()
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native JSONB SQLAlchemy package-free restart passed')
'''], env=dict(os.environ, JSONB_SCHEMA=schema, JSONB_COLUMN=column,
        JSONB_SCOPED='1' if scoped else '0', JSONB_NONE_AS_NULL='1' if none_as_null else '0',
        JSONB_DATABASE_VARIABLE=database_variable, JSONB_EXPECTED=json.dumps(encoded_wire(expected))),
        cwd=directory, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native JSONB restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native JSONB SQLAlchemy package-free restart passed'


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_both_null_modes_and_layouts_all_rotations_current_wire_and_native_exit(public_slots, none_as_null):
    with jsonb_application(public_slots=public_slots, none_as_null=none_as_null) as app:
        from test_public_slots import slots
        original_slots = slots(app)
        source = native_wire(app)
        with Session(app.runtime) as session:
            original = values(session, app.Customer)
            current_edits(session, app.Customer)
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.flush()
            latest = native_wire(app, connection=session.connection())
            latest_values = values(session, app.Customer)
            session.rollback()
        run(app); publish(app)
        assert protected_wire(app, keys) == source
        rotate_all(app)
        assert protected_wire(app, date_keys) == source
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert values(session, app.Customer) == original
            assert state(session.scalar(select(app.Customer.name).where(app.Customer.label == 'label-100'))) == dict(original)[UUID(int=100)]
            current_edits(session, app.Customer)
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.commit()
            assert values(session, app.Customer) == latest_values
        assert protected_wire(app, date_keys) == latest
        remove_date(app)
        assert native_wire(app) == latest
        if public_slots:
            assert slots(app) == original_slots
        native_restart(app.schema, latest, none_as_null=none_as_null)


@pytest.mark.parametrize('app', [(JSONB(), (deepcopy(BASE), JSON.NULL, None), [])], indirect=True)
@pytest.mark.parametrize('workers', [1, 2])
def test_online_jsonb_precision_capture_pause_catchup_current_values_and_native_exit(app, workers):
    seed_native(app, column='body', scoped=False)
    first = online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                         max_chunks=1, workers=workers)
    assert first.phase == 'CAPTURING' and first.committed_chunks == 1
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=10)).body = None
        session.get(app.Customer, UUID(int=20)).body = null()
        session.add(app.Customer(id=UUID(int=5), body=deepcopy(LATEST), label='captured below cursor'))
        session.delete(session.get(app.Customer, UUID(int=30)))
        session.commit()
    expected = native_wire(app, column='body')
    assert _payloads(app, app.plan)[UUID(int=10)] == (None, None)
    online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1, workers=workers)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=0, fence=True)
    with pytest.raises(m.TransitionFailure) as pending:
        online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    assert pending.value.code == 'online_catchup_required'
    assert online.status(app.plan, app.owner, pin=app.pin).phase == 'FENCED'
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                 max_chunks=20, workers=workers)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys, pin=app.pin, approval=app.approval)
    maintenance = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'), approval=maintenance, until='ACTIVE')
    app.plan = successor
    assert protected_wire(app, keys, column='body', scoped=False) == expected
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    with factory(tenant_id=TABLE_ID) as session:
        assert state(session.get(app.Customer, UUID(int=5)).body) == state(json.loads(expected[UUID(int=5)][1][1:]))
        session.get(app.Customer, UUID(int=20)).body = deepcopy(LATEST)
        session.get(app.Customer, UUID(int=10)).body = null()
        session.commit()
    with app.owner.connect() as connection:
        expected[UUID(int=20)] = document_wire(connection, LATEST)
    expected[UUID(int=10)] = (True, None)
    assert protected_wire(app, keys, column='body', scoped=False) == expected
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=4096, wal_bytes_per_row=8192)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                                 True, 'Disposable JSONB exact-wire capture fixture.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'), approval=maintenance, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Native current JSONB wire matches.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=maintenance,
             removal=removal, consent=consent)
    assert native_wire(app, column='body') == expected
    native_restart(app.schema, expected, column='body', scoped=False,
                   database_variable='CRYPTALIS_TEST_SOURCE_URL')


@pytest.mark.parametrize('app', [(JSONB(), (deepcopy(BASE), JSON.NULL, None), [])], indirect=True)
@pytest.mark.parametrize('fence', [False, True])
def test_online_jsonb_abort_retains_exact_current_native_document(app, fence):
    seed_native(app, column='body', scoped=False)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                 max_chunks=1, workers=2)
    with app.source.begin() as connection:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET body=%s::pg_catalog.jsonb WHERE id=%s',
                                  (RAW_DOCUMENTS[1], UUID(int=10)))
    expected = native_wire(app, column='body')
    if fence:
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=0, fence=True)
    assert online.abort(app.plan, app.owner, pin=app.pin, approval=app.approval).phase == 'ABORTED'
    assert native_wire(app, column='body') == expected
    with app.source_factory() as session:
        assert session.get(app.Customer, UUID(int=10)).body == json.loads(RAW_DOCUMENTS[1])
