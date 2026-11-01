"""PostgreSQL JSONB values, NULL semantics and exact native wire bytes are oracles."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import math
import os
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb
import pytest
from sqlalchemy import Column, JSON, MetaData, Table, Text, Uuid, event, insert, inspect, null, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Session, registry
from sqlalchemy.sql.elements import Null

from cryptalis import migration as m
from cryptalis.crypto import CryptoFailure
from cryptalis.manifest.compiler import Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import DOMAIN, FIELD_ID, TABLE_ID, TENANT, engine, keys, publish, run


BASE = {'longer_key': [True, None, {'雪': '😀'}], 'b': 1.0, 'a': 'e\u0301'}
LATEST = {'latest': {'é': [1.0, 1e20, None], 'longer': False}, 'a': 'e\u0301'}
COERCIONS = {'é': 1.0, 'zz': 2, '雪': -0.0, 'bbb': 1e20, '🐍': 5e-324,
             '1': 'overwritten string key', 1: 'native last duplicate key',
             None: 'null key', False: 'false key', float('nan'): 'NaN string key'}
PRECISE = '0.' + ('1234567890' * 120) + '1'
LARGE = '1' + ('0' * 399) + '.1234567890123456789012345'
RAW_DOCUMENTS = (
    '{"longer_key":1.2300,"b":10E+2,"a":1.2300,"b":2.00}',
    '{"precise":' + PRECISE + ',"nested":[1.2300,-0.0000,1e-20]}',
    '{"large":' + LARGE + '}',
)


def mapping_for(schema, none_as_null, mutable=False):
    mapping = registry(metadata=MetaData(schema=schema))
    dtype = JSONB(none_as_null=none_as_null)
    if mutable:
        dtype = MutableDict.as_mutable(dtype)
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', dtype), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    return mapping, table, Customer


@contextmanager
def application(*, none_as_null=False, mutable=False):
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'cryptalis_jsonb_' + uuid4().hex
    mapping, table, Customer = mapping_for(schema, none_as_null, mutable)
    declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
        'models': [{'model': 'Customer', 'table_id': str(TABLE_ID), 'tenancy': {'column': 'tenant_id'},
            'fields': [{'name': 'name', 'field_id': str(FIELD_ID), 'protect': True,
                        'queries': [], 'accept_leakage': []}]}]}
    try:
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(role)
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quoted}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON "{schema}".customer TO {quoted}')
        with Session(runtime) as session:
            session.add_all((Customer(id=UUID(int=100), tenant_id=TENANT, name=deepcopy(BASE)),
                Customer(id=UUID(int=101), tenant_id=TENANT, name=None),
                Customer(id=UUID(int=102), tenant_id=TENANT)))
            if not mutable:
                session.add_all((Customer(id=UUID(int=103), tenant_id=TENANT, name=JSON.NULL),
                                 Customer(id=UUID(int=104), tenant_id=TENANT, name=null())))
                session.add_all(Customer(id=UUID(int=110 + index), tenant_id=TENANT, name=value)
                    for index, value in enumerate(('json scalar sentinel', True, False, 17, 1.0, -0.0, 1e20, 1e-7,
                                                   [1, True, None, '雪', {'b': 2, 'a': 1}])))
            session.commit()
        with owner.begin() as connection:
            if mutable:
                connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name) '
                    'VALUES (%s,%s,\'null\'::jsonb),(%s,%s,NULL)',
                    (UUID(int=103), TENANT, UUID(int=104), TENANT))
            for index, document in enumerate(RAW_DOCUMENTS):
                connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) '
                    'VALUES (%s,%s,%s::jsonb,%s)', (UUID(int=300 + index), TENANT, document, 'exact native wire'))
        yield SimpleNamespace(m=m, owner=owner, runtime=runtime, schema=schema, mapping=mapping, table=table,
            Customer=Customer, role=role, declaration=declaration, none_as_null=none_as_null,
            approval=m.MaintenanceApproval('Disposable JSONB fixture writers are stopped.', 3600))
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose(); mapping.dispose()


def state(value):
    if value is JSON.NULL:
        return ('JSON.NULL',)
    if isinstance(value, Null):
        return ('SQL_NULL',)
    if isinstance(value, dict):
        return (type(value).__name__, tuple((key, state(part)) for key, part in value.items()))
    if type(value) is list:
        return ('list', tuple(state(part) for part in value))
    if type(value) is float:
        return ('float', value.hex())
    return type(value).__name__, value


def values(session, model):
    return [(identity, state(value)) for identity, value in session.execute(
        select(model.id, model.name).order_by(model.id))]


def wire(app, connection=None):
    if connection is None:
        with app.owner.connect() as current:
            return wire(app, current)
    return {identity: (sql_null, None if encoded is None else bytes(encoded))
            for identity, sql_null, encoded in connection.exec_driver_sql(
                f'SELECT id,name IS NULL,pg_catalog.jsonb_send(name) FROM "{app.schema}".customer ORDER BY id')}


def protect(app):
    app.plan = m.plan(json.dumps(app.declaration).encode(), app.mapping, app.owner,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'JSONB native fixture', 'sqlalchemy',
                                              evidence='Public disposable JSONB application oracle.'),)),
        keys=keys, runtime_role=app.role, target_id=uuid4(), backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=16384, wal_bytes_per_row=32768)
    app.pin = app_pin(app.plan, 'PREPARED')
    run(app); publish(app)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                  deployment=(app.plan, app.pin))


def exercise(factory, model):
    assignments = (deepcopy(BASE), [None, True, {'雪': '😀'}], 'json scalar sentinel', True, False,
                   17, 1.0, -0.0, 1e20, 1e-7, (None, {'nested tuple': (True, 1.0)}),
                   deepcopy(COERCIONS), None, JSON.NULL, null())
    with factory() as session:
        original = values(session, model)
        savepoint = session.begin_nested()
        row = session.get(model, UUID(int=100))
        result = []
        for value in assignments:
            row.name = value if value is JSON.NULL or isinstance(value, Null) else deepcopy(value)
            session.flush()
            expired = tuple(sorted(inspect(row).expired_attributes))
            assigned = state(row.name)
            session.refresh(row)
            result.append((expired, assigned, state(row.name)))
        created = session.execute(insert(model).returning(model.id, model.name),
            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': None},
             {'id': UUID(int=901), 'tenant_id': TENANT, 'name': JSON.NULL},
             {'id': UUID(int=902), 'tenant_id': TENANT, 'name': deepcopy(BASE)}]).all()
        result.append([(identity, state(value)) for identity, value in created])
        changed = session.execute(update(model).where(model.id == row.id, model.tenant_id == TENANT)
            .values(name=JSON.NULL).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        result.append(state(changed.changed))
        savepoint.rollback()
        session.expire_all()
        assert values(session, model) == original
        session.rollback()
        return result


def current_edits(session, model):
    session.get(model, UUID(int=100)).name = deepcopy(LATEST)
    session.get(model, UUID(int=101)).name = None
    session.get(model, UUID(int=102)).name = JSON.NULL
    session.get(model, UUID(int=103)).name = null()
    session.execute(insert(model), [{'id': UUID(int=910), 'tenant_id': TENANT, 'name': None},
        {'id': UUID(int=911), 'tenant_id': TENANT, 'name': JSON.NULL},
        {'id': UUID(int=912), 'tenant_id': TENANT}])
    session.flush()


async def async_exercise(app, protected):
    mapping, _, Customer = mapping_for(app.schema, app.none_as_null)
    database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    try:
        factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=keys,
            deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
        async with factory(**({'tenant_id': TENANT} if protected else {}), expire_on_commit=False) as session:
            before = [(identity, state(value)) for identity, value in (await session.execute(
                select(Customer.id, Customer.name).order_by(Customer.id))).all()]
            row = await session.get(Customer, UUID(int=100))
            row.name = deepcopy(LATEST)
            await session.flush(); await session.refresh(row)
            observed = [state(row.name)]
            savepoint = await session.begin_nested()
            created = (await session.execute(insert(Customer).returning(Customer.id, Customer.name),
                [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': None},
                 {'id': UUID(int=901), 'tenant_id': TENANT, 'name': JSON.NULL}])).all()
            observed.append([(identity, state(value)) for identity, value in created])
            changed = (await session.execute(update(Customer).where(Customer.id == row.id,
                Customer.tenant_id == TENANT).values(name=JSON.NULL).returning(Customer.name),
                execution_options={'synchronize_session': False})).scalar_one()
            observed.append(state(changed))
            await savepoint.rollback()
            await session.refresh(row)
            observed.append(state(row.name))
            await session.rollback()
            after = [(identity, state(value)) for identity, value in (await session.execute(
                select(Customer.id, Customer.name).order_by(Customer.id))).all()]
            assert after == before
            return observed
    finally:
        await database.dispose(); mapping.dispose()


def remove(app):
    backward = proposal(app)
    reverse(app, backward)
    reverse(app, backward, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
    exposure, _ = consent(backward, 'PLAINTEXT_ACTIVATING')
    removal = d.RemovalApproval(backward.target_id, backward.operation_id, backward.digest,
        'Native JSONB current values and exact wire verified.', 'Disposable fixture has no retained backup.', True)
    d.remove(backward, app.owner, pin=app_pin(backward, 'REMOVING'), approval=app.approval,
             removal=removal, consent=exposure)


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_native_null_types_normalization_and_lossy_python_wire_boundary(none_as_null):
    with application(none_as_null=none_as_null) as app:
        source = wire(app)
        assert source[UUID(int=101)][0] is none_as_null
        assert source[UUID(int=102)] == (True, None)
        assert source[UUID(int=103)] == (False, b'\x01null')
        assert source[UUID(int=104)] == (True, None)
        with Session(app.runtime) as session:
            exponent = session.get(app.Customer, UUID(int=116)).name
            assert type(exponent) is int and exponent == 10**20
            precise = session.get(app.Customer, UUID(int=301)).name
            large = session.get(app.Customer, UUID(int=302)).name
            assert type(precise['precise']) is float
            assert type(large['large']) is float and math.isinf(large['large'])
            assert session.get(app.Customer, UUID(int=103)).name is None
            assert session.get(app.Customer, UUID(int=104)).name is None
        with app.owner.connect() as connection:
            lossy = bytes(connection.exec_driver_sql('SELECT pg_catalog.jsonb_send(%s::jsonb)',
                (json.dumps(precise),)).scalar_one())
        assert lossy != source[UUID(int=301)][1]
        exercise(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
        assert wire(app) == source


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_protected_crud_null_modes_async_and_latest_wire_exit(none_as_null):
    with application(none_as_null=none_as_null) as app:
        expected = exercise(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
        expected_async = asyncio.run(async_exercise(app, False))
        with Session(app.runtime) as session:
            null_queries = [list(session.scalars(select(app.Customer.id).where(predicate).order_by(app.Customer.id)))
                            for predicate in (app.Customer.name.is_(None), app.Customer.name.is_not(None))]
            current_edits(session, app.Customer)
            expected_wire = wire(app, session.connection())
            session.rollback()
        factory = protect(app)
        seen = []
        def no_plaintext(connection, cursor, statement, parameters, context, executemany):
            for group in parameters if isinstance(parameters, list) else [parameters]:
                for value in group.values() if isinstance(group, dict) else group:
                    assert not isinstance(value, (dict, list, Jsonb))
                    assert value != 'json scalar sentinel'
            seen.append(True)
        event.listen(app.runtime, 'before_cursor_execute', no_plaintext)
        try:
            with factory(tenant_id=TENANT) as session:
                assert [list(session.scalars(select(app.Customer.id).where(predicate).order_by(app.Customer.id)))
                        for predicate in (app.Customer.name.is_(None), app.Customer.name.is_not(None))] == null_queries
            assert exercise(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer) == expected
            assert asyncio.run(async_exercise(app, True)) == expected_async
            with factory(tenant_id=TENANT) as session:
                current_edits(session, app.Customer)
                session.commit()
            assert seen
        finally:
            event.remove(app.runtime, 'before_cursor_execute', no_plaintext)
        remove(app)
        assert wire(app) == expected_wire


def test_jsonb_native_invalid_unicode_and_numbers_refuse_and_valid_surrogate_pair_normalizes():
    bad_values = ({'bad': '\x00'}, {'bad': '\ud800'}, {'bad': '\udc00'}, {'bad': float('nan')},
                  {'bad': float('inf')}, {'bad': float('-inf')})
    with application() as app:
        def invalid(factory, protected):
            failures = []
            with factory() as session:
                for value in bad_values:
                    savepoint = session.begin_nested()
                    session.get(app.Customer, UUID(int=100)).name = value
                    with pytest.raises(CryptoFailure if protected else DBAPIError) as failure:
                        session.flush()
                    if not protected:
                        failures.append(failure.value.orig.sqlstate)
                    savepoint.rollback()
                row = session.get(app.Customer, UUID(int=100))
                row.name = {'glyph': '\ud83d\ude00'}
                session.flush(); session.refresh(row)
                assert row.name == {'glyph': '😀'}
                session.rollback()
            return failures
        failures = invalid(lambda: Session(app.runtime), False)
        assert all(code in ('22P02', '22P05') for code in failures)
        before = wire(app)
        factory = protect(app)
        invalid(lambda: factory(tenant_id=TENANT), True)
        remove(app)
        assert wire(app) == before


def test_jsonb_mutable_dict_keeps_native_shallow_tracking_and_untouched_exact_wire():
    with application(mutable=True) as app:
        def mutate(factory):
            with factory() as session:
                row = session.get(app.Customer, UUID(int=100))
                assert isinstance(row.name, MutableDict)
                row.name['added'] = ['雪', None]
                session.flush(); session.refresh(row)
                first = state(row.name)
                row.name['longer_key'].append('shallow mutation is not tracked')
                session.flush(); session.refresh(row)
                second = state(row.name)
                assert first == second
                row.name['longer_key'] = ['tracked top-level replacement']
                session.flush(); session.refresh(row)
                third = state(row.name)
                session.rollback()
                return first, second, third
        expected = mutate(lambda: Session(app.runtime))
        before = wire(app)
        factory = protect(app)
        assert mutate(lambda: factory(tenant_id=TENANT)) == expected
        with factory(tenant_id=TENANT) as session:
            for identity in (UUID(int=301), UUID(int=302)):
                row = session.get(app.Customer, identity)
                row.label = 'Public-only edit must not rewrite a rounded Python JSON value.'
            session.commit()
        remove(app)
        assert wire(app) == before


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_not_null_errors_and_json_null_match_native_savepoints(none_as_null):
    with application(none_as_null=none_as_null) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE name IS NULL')
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name SET NOT NULL')
        app.table.c.name.nullable = False
        before = wire(app)
        def outcomes(factory):
            observed = []
            with factory() as session:
                for index, assignment in enumerate(({}, {'name': None}, {'name': JSON.NULL}, {'name': null()})):
                    savepoint = session.begin_nested()
                    row = app.Customer(id=UUID(int=950 + index), tenant_id=TENANT, **assignment)
                    session.add(row)
                    try:
                        session.flush(); session.refresh(row)
                    except DBAPIError as failure:
                        assert failure.orig.sqlstate == '23502'
                        observed.append(('error', failure.orig.sqlstate))
                    else:
                        observed.append(('value', state(row.name)))
                    savepoint.rollback()
                session.rollback()
            return observed
        expected = outcomes(lambda: Session(app.runtime))
        assert expected[0] == expected[3] == ('error', '23502')
        assert expected[2] == ('value', ('NoneType', None))
        factory = protect(app)
        assert outcomes(lambda: factory(tenant_id=TENANT)) == expected
        remove(app)
        assert wire(app) == before


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_explicit_async_transactions_commit_rollback_and_pending_savepoint(none_as_null):
    committed_id, json_null_id, pending_id, rolled_back_id = (UUID(int=value) for value in (960, 961, 962, 963))
    with application(none_as_null=none_as_null) as app:
        original_wire = wire(app)

        async def exercise(protected):
            # Separate native/protected mappings prevent attachment from changing
            # the native oracle's processors or cached omission semantics.
            mapping, _, Customer = mapping_for(app.schema, none_as_null)
            database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = (await attach(mapping, database, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin))) if protected else lambda **options: AsyncSession(database, **options)
                options = {'tenant_id': TENANT} if protected else {}

                async def observed(session):
                    return [(identity, state(value)) for identity, value in (await session.execute(
                        select(Customer.id, Customer.name).order_by(Customer.id))).all()]

                class RollBackRoot(Exception):
                    pass

                async with factory(expire_on_commit=False, **options) as session:
                    assert not session.in_transaction()
                    # No connection acquisition/query precedes begin(): preparing
                    # JSON keys must not autobegin the transaction on its behalf.
                    async with session.begin():
                        before = await observed(session)
                        row = await session.get(Customer, UUID(int=100))
                        row.name = {'root': ['committed', None, 1.0]}
                        session.add_all((
                            Customer(id=committed_id, tenant_id=TENANT, name=None),
                            Customer(id=json_null_id, tenant_id=TENANT, name=JSON.NULL),
                            Customer(id=pending_id, tenant_id=TENANT, name={'pending': [True, None, 1.0]}),
                        ))
                        # begin_nested() must flush these pending JSON values
                        # before establishing the savepoint, as native SQLAlchemy does.
                        async with session.begin_nested():
                            pending_row = await session.get(Customer, pending_id)
                            await session.refresh(pending_row)
                            pending = state(pending_row.name)
                            row.name = {'root': ['nested commit', None, 1.0]}
                            await session.flush()
                            await session.refresh(row)
                            nested_value = state(row.name)
                            null_ids = tuple((await session.scalars(select(Customer.id).where(
                                Customer.id.in_((committed_id, json_null_id)),
                                Customer.name.is_(None)).order_by(Customer.id))).all())
                            assert null_ids == ((committed_id,) if none_as_null else ())
                        committed = await observed(session)
                    assert not session.in_transaction()

                    # A new SQL read succeeds after the explicit root has closed.
                    after_commit = await observed(session)
                    assert after_commit == committed
                    await session.rollback()
                    assert not session.in_transaction()

                    with pytest.raises(RollBackRoot):
                        async with session.begin():
                            row = await session.get(Customer, UUID(int=100))
                            row.name = {'root': ['must roll back']}
                            session.add(Customer(id=rolled_back_id, tenant_id=TENANT, name=JSON.NULL))
                            async with session.begin_nested():
                                # Pending writes flush before this savepoint too;
                                # committing it cannot escape the enclosing rollback.
                                assert await session.get(Customer, rolled_back_id) is not None
                                row.name = None
                                await session.flush()
                                await session.refresh(row)
                                assert row.name is None
                            raise RollBackRoot()
                    assert not session.in_transaction()
                    after_rollback = await observed(session)
                    assert after_rollback == committed
                    assert await session.get(Customer, rolled_back_id) is None
                    await session.rollback()
                    assert not session.in_transaction()
                    return before, pending, nested_value, null_ids, after_commit, after_rollback
            finally:
                await database.dispose()
                mapping.dispose()

        expected = asyncio.run(exercise(False))
        # The native workflow genuinely commits. Restore its original source
        # before protection without passing any precise JSON number through float.
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id IN (%s,%s,%s,%s)',
                (committed_id, json_null_id, pending_id, rolled_back_id))
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s::pg_catalog.jsonb WHERE id=%s',
                (original_wire[UUID(int=100)][1][1:].decode('utf8'), UUID(int=100)))
        assert wire(app) == original_wire
        protect(app)
        assert asyncio.run(exercise(True)) == expected
