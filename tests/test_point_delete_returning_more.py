"""DELETE RETURNING through typed storage, fixed scope, removal and constraints."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, registry

from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TABLE_ID, TENANT
from test_point_delete_returning import statement
from test_point_update_returning_more import CASES
from test_search_retained_readers import remove_current
from test_single_tenant_update import single_application, snapshot
from test_sqlalchemy_adapter import (app as adapter_app, db, factory as adapter_factory,
                                     TENANT as ADAPTER_TENANT)


@pytest.mark.parametrize('dtype,value,stored', CASES)
def test_delete_returns_native_typed_current_values(dtype, value, stored):
    with application(rows=2, value_type=dtype, protected_values=(stored, None), queries=[]) as app:
        def scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                result = session.execute(statement(app, UUID(int=100)),
                    execution_options={'synchronize_session': False})
                observed = result.scalar_one()
                assert observed == stored and type(observed) is type(stored)
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == stored
        scenario()
        with fresh_mapping(app):
            run(app); publish(app)
            scenario(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)))


@pytest.mark.parametrize('public_only', [False, True])
def test_public_only_and_repeated_returned_columns_keep_native_keys(public_only):
    with application(rows=3) as app:
        def scenario(factory=None):
            columns = ((app.Customer.id, app.Customer.label) if public_only else
                       (app.Customer.name, app.Customer.name))
            query = delete(app.Customer).where(app.Customer.id == UUID(int=101),
                app.Customer.tenant_id == TENANT).returning(*columns)
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                result = session.execute(query, execution_options={'synchronize_session': False})
                observed = tuple(result.keys()), result.all()
                session.rollback()
                return observed
        expected = scenario()
        with fresh_mapping(app):
            run(app); publish(app)
            assert scenario(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))) == expected


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel_async'])
def test_fixed_scope_renamed_delete_outputs_and_latest_survivor_removal(mode):
    with single_application() as app:
        def query(identity):
            return delete(app.Customer).where(app.Customer.record == identity).returning(
                app.Customer.record, app.Customer.value)
        def consume(result):
            assert tuple(result.keys()) == ('record', 'value')
            assert result.one() == (UUID(int=101), '')
        def sync(factory=None):
            with (factory(tenant_id=TABLE_ID) if factory else Session(app.runtime)) as session:
                session.get(app.Customer, UUID(int=102)).value = 'latest survivor'
                consume(session.execute(query(UUID(int=101)), execution_options={'synchronize_session': False}))
                assert session.execute(query(UUID(int=999)), execution_options={'synchronize_session': False}).all() == []
                session.commit() if factory else session.rollback()
        async def asynchronous(protected):
            selected, native = attach, AsyncSession
            if mode == 'sqlmodel_async':
                from cryptalis.sqlmodel import attach as selected
                from sqlmodel.ext.asyncio.session import AsyncSession as native
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TABLE_ID) if factory else native(runtime)) as session:
                    (await session.get(app.Customer, UUID(int=102))).value = 'latest survivor'
                    execute = session.exec if mode == 'sqlmodel_async' else session.execute
                    consume(await execute(query(UUID(int=101)), execution_options={'synchronize_session': False}))
                    assert (await execute(query(UUID(int=999)), execution_options={'synchronize_session': False})).all() == []
                    await session.commit() if protected else await session.rollback()
            finally:
                await runtime.dispose()
        sync() if mode == 'sync' else asyncio.run(asynchronous(False))
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
            assert [(row[0], row[1]) for row in snapshot(app)] == [
                (UUID(int=100), None), (UUID(int=102), 'latest survivor')]
        finally:
            app.mapping, app.Customer = previous
            mapping.dispose()


@pytest.mark.parametrize('protected', [False, True])
def test_delete_returning_fk_failure_savepoint_recovery_and_autoflush(adapter_app, protected):
    app = adapter_app
    factory = adapter_factory(app, protected)
    parent, child, outer = UUID(int=1000), UUID(int=1001), UUID(int=1002)
    query = delete(app.Customer).where(app.Customer.id == parent,
        app.Customer.tenant_id == ADAPTER_TENANT).returning(app.Customer.note, app.Customer.secret)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        customer = app.Customer(id=parent, tenant_id=ADAPTER_TENANT, name='parent',
            note='current note', secret='current secret', rank=1)
        customer.articles = [app.Article(id=child, title='FK reference')]
        session.add(customer)
        session.commit()
        session.add(app.Customer(id=outer, tenant_id=ADAPTER_TENANT, name='outer', note='survivor', rank=2))
        savepoint = session.begin_nested()
        with pytest.raises(IntegrityError) as failed:
            session.execute(query, execution_options={'synchronize_session': False}).all()
        assert failed.value.orig.sqlstate == '23503'
        savepoint.rollback()
        assert session.get(app.Customer, outer).note == 'survivor'
        session.delete(session.get(app.Article, child))
        assert session.execute(query, execution_options={'synchronize_session': False}).one() == (
            'current note', 'current secret')
        session.commit()
    with factory(tenant_id=ADAPTER_TENANT) as session:
        assert session.get(app.Customer, parent) is None
        assert session.get(app.Customer, outer).note == 'survivor'


@pytest.mark.parametrize('adapter_app', [{'bigint': True}], indirect=True)
@pytest.mark.parametrize('protected', [False, True])
def test_delete_returning_signed_int64_and_multiple_protected_outputs(adapter_app, protected):
    app = adapter_app
    factory = adapter_factory(app, protected)
    identities = (-2**63, -1, 0, 2**63 - 1)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        session.add_all([app.Customer(id=identity, tenant_id=ADAPTER_TENANT, name=str(identity),
            note=None if identity == 0 else 'note', secret='secret', rank=index)
            for index, identity in enumerate(identities)])
        session.flush()
        results = []
        for identity in identities:
            query = delete(app.Customer).where(app.Customer.id == identity,
                app.Customer.tenant_id == ADAPTER_TENANT).returning(
                    app.Customer.id, app.Customer.note, app.Customer.secret)
            results.append(session.execute(query, execution_options={'synchronize_session': False}))
        for identity, result in zip(identities, results):
            assert result.one() == (identity, None if identity == 0 else 'note', 'secret')
        session.rollback()
