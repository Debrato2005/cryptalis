"""Native type, identity-map and async oracles for point UPDATE RETURNING."""
import asyncio
from datetime import date
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Boolean, Date, SmallInteger, String, Text, Uuid, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TENANT


CASES = [
    (Text(collation='C'), 'PUBLIC unicode 雪😀', 'PUBLIC unicode 雪😀'),
    (String(4, collation='C'), 'abcd   ', 'abcd'),
    (Boolean(), True, True), (SmallInteger(), -32768, -32768),
    (Date(), date(2040, 2, 29), date(2040, 2, 29)),
    (Uuid(), UUID(int=987654), UUID(int=987654)),
]


def query(app, kind):
    columns = (app.Customer,) if kind == 'entity' else (app.Customer.name, app.Customer.label)
    return update(app.Customer).where(app.Customer.id == UUID(int=100),
        app.Customer.tenant_id == TENANT).returning(*columns)


def consume(app, session, result, kind, expected):
    assert tuple(result.keys()) == (('Customer',) if kind == 'entity' else ('name', 'label'))
    if kind == 'entity':
        obj = result.scalar_one()
        assert obj in session and (obj.name, obj.label) == (expected, 'public')
        assert type(obj.name) is type(expected)
        return obj
    row = result.one()
    assert tuple(row) == (expected, 'public') and type(row[0]) is type(expected)


@pytest.mark.parametrize('dtype,value,stored', CASES)
@pytest.mark.parametrize('kind', ['tuple', 'entity'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_native_returning_types_entities_transactions_and_async(dtype, value, stored, kind, mode):
    with application(rows=2, value_type=dtype, protected_values=(None, None), queries=[]) as app:
        values = {'name': value, 'label': 'public'}
        def sync(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                obj = consume(app, session, session.execute(query(app, kind), values,
                    execution_options={'synchronize_session': False}), kind, stored)
                if obj is not None:
                    assert session.get(app.Customer, UUID(int=100)) is obj
                    session.expire(obj)
                    session.refresh(obj)
                    assert obj.name == stored
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name is None
        async def asynchronous(protected):
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if factory else AsyncSession(runtime)) as session:
                    result = await session.execute(query(app, kind), values,
                        execution_options={'synchronize_session': False})
                    obj = consume(app, session, result, kind, stored)
                    if obj is not None:
                        assert await session.get(app.Customer, UUID(int=100)) is obj
                        session.expire(obj)
                        await session.refresh(obj)
                        assert obj.name == stored
                    await session.rollback()
                    assert (await session.get(app.Customer, UUID(int=100))).name is None
            finally:
                await runtime.dispose()
        sync() if mode == 'sync' else asyncio.run(asynchronous(False))
        with fresh_mapping(app):
            run(app); publish(app)
            if mode == 'sync':
                sync(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                            deployment=(app.plan, app.pin)))
            else:
                asyncio.run(asynchronous(True))
        assert values == {'name': value, 'label': 'public'}


@pytest.mark.parametrize('dtype,bad,sqlstate', [(String(4, collation='C'), 'abcde', '22001'),
                                             (SmallInteger(), 32768, '22003')])
def test_missing_rows_and_assignment_failures_preserve_native_transaction_state(dtype, bad, sqlstate):
    with application(rows=2, value_type=dtype, protected_values=(None, None), queries=[]) as app:
        def scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                observations = []
                for identity in (UUID(int=9999), UUID(int=100)):
                    statement = update(app.Customer).where(app.Customer.id == identity,
                        app.Customer.tenant_id == TENANT).returning(app.Customer.name)
                    try:
                        rows = session.execute(statement, {'name': bad},
                            execution_options={'synchronize_session': False}).all()
                    except (CryptoFailure, DBAPIError) as error:
                        code = getattr(error, 'sqlstate', None) or getattr(getattr(error, 'orig', None), 'sqlstate', None)
                        assert code == sqlstate
                        observations.append(('error', code))
                        with pytest.raises(DBAPIError) as aborted:
                            session.scalar(select(app.Customer.id))
                        assert aborted.value.orig.sqlstate == '25P02'
                    else:
                        observations.append(('rows', rows))
                    session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name is None
                return observations
        expected = scenario()
        with fresh_mapping(app):
            run(app); publish(app)
            assert scenario(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                            deployment=(app.plan, app.pin))) == expected


def test_public_assignments_unchanged_protected_outputs_and_outstanding_results():
    from test_migration import frames
    with application(rows=3) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        before = frames(app, True)
        with factory(tenant_id=TENANT) as session:
            assert session.execute(query(app, 'tuple'), {'label': 'public'},
                execution_options={'synchronize_session': False}).one() == (None, 'public')
            session.commit()
            assert frames(app, True) == before
            first = session.execute(query(app, 'tuple'), {'name': 'PUBLIC first'},
                execution_options={'synchronize_session': False})
            second = session.execute(query(app, 'tuple'), {'name': 'PUBLIC second'},
                execution_options={'synchronize_session': False})
            assert first.one() == ('PUBLIC first', 'public')
            assert second.one() == ('PUBLIC second', 'public')
            session.rollback()


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel_async'])
def test_fixed_scope_renamed_outputs_match_native_and_survive_current_value_removal(mode):
    from sqlalchemy.orm import registry
    from test_single_tenant_update import single_application
    from test_search_retained_readers import remove_current
    from test_migration import TABLE_ID
    with single_application() as app:
        def statement():
            return update(app.Customer).where(app.Customer.record == UUID(int=101)).returning(
                app.Customer.record, app.Customer.value)
        def sync(factory=None):
            with (factory(tenant_id=TABLE_ID) if factory else Session(app.runtime)) as session:
                result = session.execute(statement(), {'name': 'PUBLIC fixed'},
                    execution_options={'synchronize_session': False})
                assert tuple(result.keys()) == ('record', 'value')
                assert result.one() == (UUID(int=101), 'PUBLIC fixed')
                session.commit() if factory else session.rollback()
        async def asynchronous(protected):
            selected_attach, native = attach, AsyncSession
            if mode == 'sqlmodel_async':
                from cryptalis.sqlmodel import attach as selected_attach
                from sqlmodel.ext.asyncio.session import AsyncSession as native
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected_attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TABLE_ID) if factory else native(runtime)) as session:
                    method = session.exec if mode == 'sqlmodel_async' else session.execute
                    result = await method(statement(), params={'name': 'PUBLIC fixed'},
                        execution_options={'synchronize_session': False})
                    assert tuple(result.keys()) == ('record', 'value')
                    assert result.one() == (UUID(int=101), 'PUBLIC fixed')
                    await session.commit() if protected else await session.rollback()
            finally:
                await runtime.dispose()
        sync() if mode == 'sync' else asyncio.run(asynchronous(False))
        # Preserve renamed mapped attributes in a fresh attachment mapping.
        previous = app.mapping, app.Customer
        mapping = registry(metadata=app.table.metadata)
        class Customer: pass
        mapping.map_imperatively(Customer, app.table, properties={
            'record': app.table.c.id, 'value': app.table.c.name, 'public': app.table.c.label})
        app.mapping, app.Customer = mapping, Customer
        try:
            run(app); publish(app)
            if mode == 'sync':
                sync(attach(mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                            deployment=(app.plan, app.pin)))
            else:
                asyncio.run(asynchronous(True))
            remove_current(app, keys)
            with app.owner.connect() as connection:
                assert connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
                                                  (UUID(int=101),)).scalar_one() == 'PUBLIC fixed'
        finally:
            app.mapping, app.Customer = previous
            mapping.dispose()


@pytest.mark.parametrize('fault,code', [('unique', '23505'), ('not_null', '23502')])
def test_native_constraint_failure_savepoint_recovery_and_autoflush(fault, code):
    from sqlalchemy.exc import IntegrityError
    with application(rows=3, value_nullable=False, protected_values=('first', 'second', 'third')) as app:
        def scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                session.get(app.Customer, UUID(int=102)).label = 'PUBLIC outer edit'
                savepoint = session.begin_nested()  # Native autoflush preserves the outer edit.
                values = {'name': 'second' if fault == 'unique' else None}
                with pytest.raises(IntegrityError) as failed:
                    session.execute(query(app, 'tuple'), values,
                        execution_options={'synchronize_session': False}).all()
                assert failed.value.orig.sqlstate == code
                savepoint.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == 'first'
                assert session.get(app.Customer, UUID(int=102)).label == 'PUBLIC outer edit'
                assert session.execute(query(app, 'tuple'), {'name': 'PUBLIC retry'},
                    execution_options={'synchronize_session': False}).one()[0] == 'PUBLIC retry'
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == 'first'
        scenario()
        with fresh_mapping(app):
            run(app); publish(app)
            scenario(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                            deployment=(app.plan, app.pin)))


from test_sqlalchemy_adapter import (app as adapter_app, db, factory as adapter_factory,
                                     TENANT as ADAPTER_TENANT)


@pytest.mark.parametrize('adapter_app', [{'bigint': True}], indirect=True)
def test_signed_int64_records_and_multiple_protected_outputs_match_native(adapter_app):
    from sqlalchemy.orm import registry
    app = adapter_app
    identities = (-2**63, -1, 0, 2**63 - 1)
    def scenario(factory):
        with factory(tenant_id=ADAPTER_TENANT) as session:
            session.add_all([app.Customer(id=identity, tenant_id=ADAPTER_TENANT,
                name=f'public {index}', note='old note', secret='unchanged secret', rank=index)
                for index, identity in enumerate(identities)])
            session.flush()
            observed = []
            for identity in identities:
                statement = update(app.Customer).where(app.Customer.id == identity,
                    app.Customer.tenant_id == ADAPTER_TENANT).returning(
                        app.Customer.id, app.Customer.note, app.Customer.secret)
                values = {'note': f'PUBLIC {identity}'}
                if identity == 0: values['secret'] = None
                result = session.execute(statement, values,
                    execution_options={'synchronize_session': False})
                row = result.one()
                assert tuple(result.keys()) == ('id', 'note', 'secret') and type(row[0]) is int
                assert row == (identity, f'PUBLIC {identity}', None if identity == 0 else 'unchanged secret')
                observed.append(tuple(row))
            session.rollback()
            return observed
    expected = scenario(adapter_factory(app, False))
    original_mapping, original_model = app.mapping, app.Customer
    mapping = registry(metadata=original_mapping.metadata)
    class Customer: pass
    mapping.map_imperatively(Customer, original_model.__table__)
    app.mapping, app.Customer = mapping, Customer
    try:
        assert scenario(adapter_factory(app, True)) == expected
    finally:
        app.mapping, app.Customer = original_mapping, original_model
        mapping.dispose()
