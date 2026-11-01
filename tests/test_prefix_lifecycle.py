"""Exact prefixes retain native data, uniqueness and indexes through public workflows."""
from contextlib import contextmanager
from decimal import Decimal
import json
import os
import subprocess
import sys
from uuid import UUID

import pytest

from sqlalchemy import Column, MetaData, Numeric, String, Table, Text, Uuid, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, registry

from cryptalis import deprotection as d, migration as m, online
from cryptalis.application import ApplicationConfig
from cryptalis.crypto import CryptoFailure
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
from test_deprotection import app_pin
from test_migration import application, engine, keys, publish, run, TENANT, FIELD_ID, TABLE_ID
from test_prefix_search import BOUNDS, LONG_VALUE, WRITE, observe
from test_online_protection import app, _pin, _payloads

pytestmark = pytest.mark.prefix_qualification


VALUES = (None, 'alpha', 'a%b', 'a_b', 'éclair', 'e\u0301clair', LONG_VALUE)


def configuration(app, queries, bounds=None):
    lock = app.plan.document['lock']
    declaration = lock['declaration']
    field = next(field for model in declaration['models'] for field in model['fields']
                 if field['field_id'] == str(FIELD_ID))
    field.update(queries=sorted(queries), accept_leakage=sorted(queries))
    field.pop('prefix_lengths', None)
    if bounds is not None:
        field['prefix_lengths'] = dict(bounds)
    writers = lock['writer_inventory']
    inventory = WriterInventory(writers['complete'], tuple(Writer(UUID(item['table_id']), item['name'],
        item['route'], item['excluded'], item['evidence']) for item in writers['writers']))
    reviews = {item['field_id']: SearchReview(UUID(item['field_id']), item['small_domain'], item['evidence'])
               for item in lock['search_reviews']}
    if queries:
        reviews.setdefault(str(FIELD_ID), SearchReview(FIELD_ID, False, 'Public synthetic prefix population.'))
    else:
        reviews.pop(str(FIELD_ID), None)
    return ApplicationConfig(json.dumps(declaration).encode(), app.mapping, inventory, tuple(reviews.values()))


def native_indexes(connection, schema):
    return [tuple(row) for row in connection.exec_driver_sql(
        'SELECT indexname,indexdef FROM pg_catalog.pg_indexes WHERE schemaname=%s ORDER BY indexname', (schema,))]


@contextmanager
def prefix_application(*, public_slots=False, dtype=None, queries=('equality', 'prefix'), pattern_ops=True):
    dtype = Text(collation='C') if dtype is None else dtype
    with date_application(public_slots=public_slots, value_type=dtype, values=VALUES, value_default=None,
                          value_queries=queries, value_prefix_bounds=BOUNDS if 'prefix' in queries else None) as app:
        if pattern_ops:
            native = 'varchar' if isinstance(dtype, String) and not isinstance(dtype, Text) else 'text'
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'CREATE INDEX native_prefix_pattern ON "{app.schema}".customer '
                                          f'(name pg_catalog.{native}_pattern_ops)')
            configured = configuration(app, queries, BOUNDS if 'prefix' in queries else None)
            app.plan = configured.plan(app.owner, keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
                layout='preserve-public-slots/v1' if public_slots else None,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=4096, wal_bytes_per_row=8192)
            app.pin = app_pin(app.plan, 'PREPARED')
        yield app


@contextmanager
def attached_prefix(app, dtype=None, resolver=keys, *, restore=None):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False), Column('tenant_id', Uuid, nullable=False),
        Column('name', Text(collation='C') if dtype is None else dtype), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        deployment = (app.plan, app.pin) if restore is None else (app.plan, app.pin, restore)
        yield Customer, attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolver, deployment=deployment)
    finally:
        runtime.dispose(); mapping.dispose()


def native_restart(schema, expected, directory='/tmp', *, column='name',
                   database_variable='CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
    child = subprocess.run([sys.executable, '-I', '-B', '-c', '''
import importlib.abc, json, os, sys
from uuid import UUID
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from psycopg import sql
schema, column = os.environ['PREFIX_SCHEMA'], os.environ['PREFIX_COLUMN']
expected = json.loads(os.environ['PREFIX_EXPECTED'])
with psycopg.connect(os.environ[os.environ['PREFIX_DATABASE_VARIABLE']]) as connection:
    rows = connection.execute(sql.SQL('SELECT id,{} FROM {}.customer').format(
        sql.Identifier(column), sql.Identifier(schema))).fetchall()
    assert {str(identity): value for identity,value in rows} == expected
    assert all(value is None or type(value) is str for _,value in rows)
    matches = connection.execute(sql.SQL('SELECT id FROM {}.customer WHERE {} LIKE %s ORDER BY id').format(
        sql.Identifier(schema), sql.Identifier(column)), ('a%',)).fetchall()
    assert [str(row[0]) for row in matches] == sorted(key for key,value in expected.items()
        if value is not None and value.startswith('a'))
    connection.execute(sql.SQL('UPDATE {}.customer SET {}=%s WHERE id=%s').format(
        sql.Identifier(schema), sql.Identifier(column)), ('native after removal', UUID(next(iter(expected)))))
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native prefix package-free restart passed')
    '''], env=dict(os.environ, PREFIX_SCHEMA=schema, PREFIX_COLUMN=column,
               PREFIX_DATABASE_VARIABLE=database_variable,
               PREFIX_EXPECTED=json.dumps({str(key): value for key, value in expected.items()})),
        cwd=directory, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native prefix restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native prefix package-free restart passed'


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('dtype', [Text(collation='C'), String(4096, collation='C')])
def test_prefix_all_rotations_native_pattern_indexes_current_edits_and_both_exits(public_slots, dtype):
    with prefix_application(public_slots=public_slots, dtype=dtype) as app:
        with app.owner.connect() as connection:
            indexes = native_indexes(connection, app.schema)
        with Session(app.runtime) as session:
            before = observe(session, app.Customer)
            session.get(app.Customer, UUID(int=102)).name = WRITE
            session.flush()
            changed = observe(session, app.Customer)
            expected = {row.id: row.name for row in session.scalars(select(app.Customer))}
            session.rollback()
        run(app); publish(app); rotate_all(app)
        with attached_prefix(app, dtype, date_keys) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Customer) == before
                session.get(Customer, UUID(int=102)).name = WRITE
                session.commit()
                assert observe(session, Customer) == changed
        remove_date(app)
        with Session(app.runtime) as session:
            assert observe(session, app.Customer) == changed
        with app.owner.connect() as connection:
            assert native_indexes(connection, app.schema) == indexes
        native_restart(app.schema, expected)


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('initial,pattern_ops', [([], False), (['equality'], False),
    (['equality', 'unique'], False), (['equality', 'prefix'], True)])
def test_prefix_enable_bounds_change_disable_preserves_current_values_and_unique(public_slots, initial, pattern_ops):
    from test_application_modification import activate_change, propose
    from test_search_retained_readers import remove_current
    with prefix_application(public_slots=public_slots, queries=tuple(initial), pattern_ops=pattern_ops) as app:
        with app.owner.connect() as connection:
            indexes = native_indexes(connection, app.schema)
        with Session(app.runtime) as session:
            session.get(app.Customer, UUID(int=102)).name = WRITE
            session.flush()
            expected = {row.id: row.name for row in session.scalars(select(app.Customer))}
            session.rollback()
        run(app); publish(app)
        searched = ['equality', 'prefix'] + (['unique'] if 'unique' in initial else [])
        if 'prefix' not in initial:
            configured = configuration(app, searched, BOUNDS)
            activate_change(configured, app, propose(configured, app))
        for bounds in (BOUNDS, {'min': 2, 'max': 8}):
            if bounds != BOUNDS:
                configured = configuration(app, searched, bounds)
                activate_change(configured, app, propose(configured, app))
            with attached_prefix(app) as (Customer, factory):
                with factory(tenant_id=TENANT) as session:
                    assert session.scalar(select(Customer.id).where(Customer.tenant_id == TENANT,
                        Customer.name.like('al%'))) == UUID(int=101)
                    if 'unique' in initial:
                        savepoint = session.begin_nested()
                        with pytest.raises(IntegrityError) as failure:
                            session.execute(insert(Customer), [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': 'alpha'}])
                        assert failure.value.orig.sqlstate == '23505'
                        savepoint.rollback()
                    if bounds['max'] == 8:
                        with pytest.raises(CryptoFailure):
                            session.execute(select(Customer).where(Customer.tenant_id == TENANT,
                                Customer.name.like('a' * 9 + '%')))
                    session.get(Customer, UUID(int=102)).name = WRITE
                    session.commit()
        final = ['equality', 'unique'] if 'unique' in initial else ['equality'] if initial else []
        configured = configuration(app, final)
        activate_change(configured, app, propose(configured, app))
        if pattern_ops:
            assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v14'
        with attached_prefix(app) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert {row.id: row.name for row in session.scalars(select(Customer))} == expected
                with pytest.raises(CryptoFailure):
                    session.execute(select(Customer).where(Customer.tenant_id == TENANT, Customer.name.like('al%')))
                if 'unique' in initial:
                    savepoint = session.begin_nested()
                    with pytest.raises(IntegrityError) as failure:
                        session.execute(insert(Customer), [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': 'alpha'}])
                    assert failure.value.orig.sqlstate == '23505'
                    savepoint.rollback()
        remove_current(app, keys)
        with app.owner.connect() as connection:
            assert native_indexes(connection, app.schema) == indexes
        native_restart(app.schema, expected)


def online_results(session, model):
    return {name: [tuple(row) for row in session.execute(select(model.id, model.body).where(predicate).order_by(model.id))]
        for name, predicate in {'all': model.body.like('%'), 'null': model.body.is_(None),
            'prefix': model.body.like('a%'), 'literal': model.body.startswith('a%', autoescape=True),
            'unicode': model.body.startswith('é', autoescape=True), 'not': ~model.body.like('a%')}.items()}


@pytest.mark.parametrize('workers', [1, 2])
def test_online_prefix_failed_byte_budget_resume_current_values_and_native_exit(app, workers):
    declaration = app.plan.document['lock']['declaration']
    field = next(field for model in declaration['models'] for field in model['fields']
                 if field['field_id'] == str(FIELD_ID))
    field.update(queries=['equality', 'prefix'], accept_leakage=['equality', 'prefix'], prefix_lengths=BOUNDS)
    app.plan = online.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        source_role=app.source_role, writers=app.inventory, keys=keys, runtime_role=app.target_role,
        target_id=app.plan.target_id, max_rows=1, max_bytes=4096,
        search_reviews=(SearchReview(FIELD_ID, False, 'Public synthetic prefix capture fixture.'),),
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=4096, wal_bytes_per_row=8192)
    app.pin = _pin(app.plan, 'PREPARED')
    assert online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                        max_chunks=1, workers=workers).committed_chunks == 1
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=10)).body = 'a%captured'
        session.add(app.Customer(id=UUID(int=5), body='x' * 5000, label='oversized for approved chunk'))
        session.delete(session.get(app.Customer, UUID(int=30)))
        session.commit()
    before = _payloads(app, app.plan)
    with pytest.raises(m.TransitionFailure):
        online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                     max_chunks=1, workers=workers)
    assert _payloads(app, app.plan) == before
    assert online.status(app.plan, app.owner, pin=app.pin).committed_chunks == 1
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=5)).body = 'éclair'
        session.commit()
        expected = online_results(session, app.Customer)
    online.apply(type(app.plan)(app.plan.artifact), app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=1, workers=workers)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, fence=True)
    with pytest.raises(m.TransitionFailure, match='online_catchup_required'):
        online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    assert online.status(app.plan, app.owner, pin=app.pin).phase == 'FENCED'
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=10)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys, pin=app.pin, approval=app.approval)
    maintenance = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'), approval=maintenance, until='ACTIVE')
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    with factory(tenant_id=TABLE_ID) as session:
        assert online_results(session, app.Customer) == expected
        with pytest.raises(CryptoFailure):
            session.execute(select(app.Customer).where(app.Customer.body.like('x' * 17 + '%')))
        session.get(app.Customer, UUID(int=20)).body = WRITE
        session.commit()
        latest = online_results(session, app.Customer)
        current = {row.id: row.body for row in session.scalars(select(app.Customer))}
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=4096, wal_bytes_per_row=8192)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                                 True, 'Public disposable prefix capture fixture.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'), approval=maintenance, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Native prefix results and current values match.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=maintenance, removal=removal, consent=consent)
    with app.source_factory() as session:
        assert online_results(session, app.Customer) == latest
    native_restart(app.schema, current, column='body', database_variable='CRYPTALIS_TEST_SOURCE_URL')


@pytest.mark.parametrize('prefix', [False, True])
def test_retained_v13_reader_accepts_numeric_and_refuses_prefix_before_sql(tmp_path, prefix):
    reader = os.environ.get('CRYPTALIS_PREFIX_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v13 reader interpreter')
    with application(value_type=Text(collation='C') if prefix else Numeric(), unique=False,
        queries=['equality', 'prefix'] if prefix else ['equality'],
        value_prefix_bounds=BOUNDS if prefix else None,
        protected_values=('alpha', None) if prefix else (Decimal('1.2300'), None)) as source:
        artifact = tmp_path / 'saved-plan.json'
        artifact.write_bytes(source.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis.migration import MigrationPlan, TransitionFailure
try:
    MigrationPlan(Path(sys.argv[1]).read_bytes()).document
except TransitionFailure as failure:
    assert sys.argv[2] == 'prefix' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'numeric'
print('reader boundary passed')
''', str(artifact), 'prefix' if prefix else 'numeric'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'historical reader boundary failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'
