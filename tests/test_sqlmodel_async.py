"""Native SQLModel async execution remains guarded through current-value exit."""

import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, insert, select as sqlalchemy_select, update
from sqlalchemy.exc import DataError, PendingRollbackError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

sqlmodel = pytest.importorskip('sqlmodel', reason='optional SQLModel async profile')
pytestmark = pytest.mark.skipif(sqlmodel.__version__ != '0.0.48', reason='exact SQLModel 0.0.48 profile')

from sqlmodel import Session, select
from sqlmodel.ext.asyncio.session import AsyncSession as NativeSession

from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from cryptalis.sqlmodel import attach
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import PROVIDER, TENANT, PublicFixtureProvider, application, keys, publish, run
from test_sqlmodel_bridge import protect, record_application


def async_engine():
    return create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))


def seed(app):
    with Session(app.runtime) as session:
        session.add(app.Record(id=UUID(int=900), tenant_id=TENANT, name='seed', public='seed'))
        session.commit()


async def workflow(factory, model, protected):
    async with factory() as session:
        assert isinstance(session, NativeSession)
        record = model(id=UUID(int=901), tenant_id=TENANT, name='雪😀', public='visible')
        session.add(record)
        await session.flush()
        await session.refresh(record)
        assert (await session.exec(select(model).where(model.id == record.id))).one() is record
        assert (await session.exec(select(model.name).where(model.id == record.id))).one() == '雪😀'
        pair = (await session.exec(select(model.id, model.name).where(model.id == record.id))).one()
        assert tuple(pair) == (record.id, '雪😀')
        assert (await session.exec(sqlalchemy_select(model).where(model.id == record.id))).one()[0] is record
        inserted = await session.exec(insert(model).returning(model.id, model.name),
            params=[{'id': UUID(int=902), 'tenant_id': TENANT, 'name': 'inserted', 'public': 'bulk'}])
        assert tuple(inserted.one()) == (UUID(int=902), 'inserted')
        await session.exec(update(model).where(model.tenant_id == TENANT),
            params=[{'id': UUID(int=902), 'name': None}], execution_options={'synchronize_session': False})
        assert (await session.exec(select(model.name).where(model.id == UUID(int=902)))).one() is None
        savepoint = await session.begin_nested()
        record.name = 'x' * 13
        with pytest.raises(CryptoFailure if protected else DataError) as failure:
            await session.flush()
        assert (failure.value.sqlstate if protected else failure.value.orig.sqlstate) == '22001'
        assert session.is_active is False
        with pytest.raises(PendingRollbackError):
            await session.exec(select(model.id))
        await savepoint.rollback()
        await session.refresh(record)
        assert record.name == '雪😀'
        record.sqlmodel_update({'name': 'latest value'})
        await session.flush()
        removed = await session.exec(delete(model).where(model.tenant_id == TENANT, model.id == UUID(int=902)),
            execution_options={'synchronize_session': False})
        assert removed.rowcount == 1
        values = (await session.exec(select(model.id, model.name).order_by(model.id))).all()
        assert [tuple(row) for row in values] == [(UUID(int=900), 'seed'), (UUID(int=901), 'latest value')]
        await session.commit() if protected else await session.rollback()
        return tuple(pair), tuple(inserted.keys()), type(pair).__name__, [tuple(row) for row in values]


def test_async_sqlmodel_native_exec_crud_savepoint_and_latest_value_removal():
    with record_application() as app:
        seed(app)
        async def native():
            engine = async_engine()
            try:
                return await workflow(async_sessionmaker(engine, class_=NativeSession, expire_on_commit=False), app.Record, False)
            finally:
                await engine.dispose()
        expected = asyncio.run(native())
        protect(app, attach_runtime=False)
        captured = []
        async def protected():
            engine = async_engine()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                       deployment=(app.plan, app.pin))
                event.listen(engine.sync_engine, 'before_cursor_execute',
                    lambda connection, cursor, statement, parameters, context, many: captured.append(repr(parameters)))
                return await workflow(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Record, True)
            finally:
                await engine.dispose()
        assert asyncio.run(protected()) == expected
        assert captured and all(value not in ''.join(captured) for value in ('雪😀', 'inserted', 'latest value', 'x' * 13))
        with app.owner.connect() as connection:
            body = bytes(connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".record WHERE id=%s',
                (UUID(int=901),)).scalar_one())
            assert body.startswith(b'CF1\0') and b'latest value' not in body
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert reverse(app, plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING').phase == 'PLAINTEXT_ACTIVE'
        approval, _ = consent(plan, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'native async SQLModel current-value read', 'no retained fixture copies', True)
        assert d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=approval).phase == 'REMOVED'
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(f'SELECT id,name FROM "{app.schema}".record ORDER BY id').all() == expected[-1]


def test_async_exec_equality_in_and_interleaved_tenants_match_native():
    other = UUID(int=777)
    def foreign(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
            (UUID(int=990), other, 'shared', 'foreign'))
    with application(rows=5, unique=False, setup=foreign,
                     protected_values=('shared', '', None, '雪😀', 'shared')) as app:
        statements = (select(app.Customer.id, app.Customer.name).where(app.Customer.name == 'shared').order_by(app.Customer.id),
                      select(app.Customer.name).where(app.Customer.name.in_(['shared', '雪😀', None])).order_by(app.Customer.id))
        scopes = (TENANT, other, TENANT)
        async def scenario(protected):
            engine = async_engine()
            try:
                factory = (await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                       deployment=(app.plan, app.pin)) if protected else
                           async_sessionmaker(engine, class_=NativeSession))
                observed = []
                for tenant in scopes:
                    async with (factory(tenant_id=tenant) if protected else factory()) as session:
                        observed.append([(await session.exec(statement if protected else
                            statement.where(app.Customer.tenant_id == tenant))).all() for statement in statements])
                return observed
            finally:
                await engine.dispose()
        expected = asyncio.run(scenario(False))
        run(app)
        publish(app)
        assert asyncio.run(scenario(True)) == expected


def test_async_exec_admission_and_cancelled_key_preparation_have_no_sql_effects():
    with record_application() as app:
        seed(app)
        protect(app, attach_runtime=False)
        async def scenario():
            entered, release = asyncio.Event(), asyncio.Event()
            class AwaitedProvider:
                provider_id = PROVIDER
                def unwrap(self, *args):
                    raise AssertionError('async SQLModel must prepare keys outside synchronous hooks')
                async def unwrap_async(self, wrapper, context):
                    entered.set()
                    await release.wait()
                    return PublicFixtureProvider().unwrap(wrapper, context)
            ring = Keyring(keys(TENANT).policy, {PROVIDER: AwaitedProvider()})
            engine = async_engine()
            task = None
            statements = []
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=ring,
                                       deployment=(app.plan, app.pin))
                event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: statements.append(True))
                async with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsupportedProtectedOperation):
                        await session.exec(select(app.Record).order_by(app.Record.name))
                    assert not entered.is_set() and statements == []
                    session.add(app.Record(id=UUID(int=901), tenant_id=TENANT, name='cancelled', public='pending'))
                    task = asyncio.create_task(session.exec(select(app.Record.name)))
                    await asyncio.wait_for(entered.wait(), 3)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                    await session.rollback()
                    assert statements == []
                    with app.owner.connect() as connection:
                        assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".record').scalar_one() == 1
                    release.set()
                    session.add(app.Record(id=UUID(int=902), tenant_id=TENANT, name='retry', public='fresh'))
                    await session.commit()
                    assert (await session.exec(select(app.Record.name).where(app.Record.id == UUID(int=902)))).one() == 'retry'
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                await engine.dispose()
        asyncio.run(scenario())


def test_async_exec_update_captures_request_before_awaited_provider_mutation():
    with record_application() as app:
        seed(app)
        protect(app, attach_runtime=False)
        rows = [{'id': UUID(int=901), 'name': 'original'}]
        async def scenario():
            class MutatingProvider:
                provider_id = PROVIDER
                def unwrap(self, *args):
                    raise AssertionError('synchronous key preparation is forbidden')
                async def unwrap_async(self, wrapper, context):
                    rows[0]['name'] = 'mutated'
                    return PublicFixtureProvider().unwrap(wrapper, context)
            ring = Keyring(keys(TENANT).policy, {PROVIDER: MutatingProvider()})
            engine = async_engine()
            statements = []
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=ring,
                                       deployment=(app.plan, app.pin))
                event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: statements.append(True))
                async with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsupportedProtectedOperation):
                        await session.exec(update(app.Record).where(app.Record.tenant_id == TENANT),
                            params=rows, execution_options={'synchronize_session': False})
                    await session.rollback()
                assert statements == [] and rows[0]['name'] == 'mutated'
            finally:
                await engine.dispose()
        asyncio.run(scenario())
