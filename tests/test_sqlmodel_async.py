"""Pinned native SQLModel async behavior through the existing guarded adapter."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest

sqlmodel = pytest.importorskip('sqlmodel', reason='optional SQLModel 0.0.48 async profile')
pytestmark = pytest.mark.skipif(sqlmodel.__version__ != '0.0.48', reason='exact SQLModel 0.0.48 profile')

from sqlalchemy import delete, event, insert, select as sqlalchemy_select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import Session, select
from sqlmodel.ext.asyncio.session import AsyncSession

from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.sqlmodel import attach
from test_migration import keys, TENANT, PublicFixtureProvider
from test_sqlmodel_bridge import record_application, protect


def runtime_engine():
    return create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))


def seed(app):
    # Planning binds this existing tenant's exact key policy.
    with Session(app.runtime) as session:
        session.add(app.Record(id=UUID(int=100), tenant_id=TENANT, name='seed', public='seed'))
        session.commit()


def test_async_exec_retains_native_models_scalar_tuple_refresh_and_rollback():
    with record_application() as app:
        seed(app)
        async def workflow(protected):
            engine = runtime_engine()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                sent = []
                event.listen(engine.sync_engine, 'before_cursor_execute',
                             lambda connection, cursor, sql, parameters, context, many: sent.append(repr(parameters)))
                async with (factory(tenant_id=TENANT, expire_on_commit=False) if protected else
                            AsyncSession(engine, expire_on_commit=False)) as session:
                    assert isinstance(session, AsyncSession) and isinstance(session.sync_session, Session)
                    row = app.Record.model_validate(dict(id=UUID(int=1000), tenant_id=TENANT,
                                                        name='雪😀', public='visible'))
                    session.add(row)
                    await session.flush()
                    await session.refresh(row)
                    assert (await session.exec(select(app.Record).where(app.Record.id == row.id))).one() is row
                    scalar = await session.exec(select(app.Record.name).where(app.Record.id == row.id))
                    pair = await session.exec(select(app.Record.id, app.Record.name).where(app.Record.id == row.id))
                    value = app.Record.name.label('protected value')
                    labeled = (await session.exec(sqlalchemy_select(value).where(app.Record.id == row.id))).one()
                    observed = (type(scalar).__name__, scalar.one(), type(pair).__name__,
                                tuple(pair.one()), labeled._mapping[value])
                    row.name = 'é' * 12 + '   '
                    await session.flush()
                    pending = row.name
                    await session.refresh(row)
                    stored = row.name
                    await session.rollback()
                    assert (await session.exec(select(app.Record.id))).all() == [UUID(int=100)]
                    session.add(app.Record(id=UUID(int=1001), tenant_id=TENANT, name='retained', public='committed'))
                    await session.commit()
                    await session.refresh((await session.exec(select(app.Record).where(app.Record.id == UUID(int=1001)))).one())
                    assert ('雪😀' in ''.join(sent)) is (not protected)
                    return observed, pending, stored
            finally:
                await engine.dispose()

        expected = asyncio.run(workflow(False))
        with app.runtime.begin() as connection:
            connection.execute(delete(app.Record).where(app.Record.id == UUID(int=1001)))
        protect(app, attach_runtime=False)
        assert asyncio.run(workflow(True)) == expected
        with app.owner.connect() as connection:
            stored = connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".record WHERE id=%s',
                                                (UUID(int=1001),)).scalar_one()
            assert bytes(stored).startswith(b'CF1\0') and b'retained' not in bytes(stored)


@pytest.mark.parametrize('projection', ['entity', 'columns', 'labeled'])
def test_async_exec_bulk_returning_matches_native_result_shapes(projection):
    with record_application() as app:
        seed(app)
        rows = [dict(id=UUID(int=1000 + index), tenant_id=TENANT, name=value, public='visible')
                for index, value in enumerate(['雪😀', None, '', 'é'])]

        async def workflow(protected):
            engine = runtime_engine()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    model = app.Record
                    value = model.name.label('protected value')
                    columns = {'entity': (model,), 'columns': (model.id, model.name),
                               'labeled': (value, model)}[projection]
                    result = await session.exec(insert(model).returning(*columns,
                        sort_by_parameter_order=True), params=rows, execution_options={'render_nulls': True})
                    observed = []
                    returned = result.all()
                    for row in returned:
                        observed.append(tuple((item.id, item.name, item.public) if isinstance(item, model)
                                              else item for item in row))
                        if projection == 'labeled':
                            assert row._mapping[value] == row[0]
                    assert len(session.identity_map) == (0 if projection == 'columns' else 4)
                    await session.rollback()
                    return type(result).__name__, tuple(result.keys()), observed
            finally:
                await engine.dispose()

        expected = asyncio.run(workflow(False))
        protect(app, attach_runtime=False)
        assert asyncio.run(workflow(True)) == expected


def test_async_exec_refuses_unsupported_select_before_preparation_or_sql(monkeypatch):
    with record_application() as app:
        seed(app)
        protect(app, attach_runtime=False)
        async def workflow():
            engine = runtime_engine()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                       deployment=(app.plan, app.pin))
                calls = []
                event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: calls.append(True))
                async def forbidden(tenant):
                    pytest.fail('unsupported exec prepared keys')
                async with factory(tenant_id=TENANT) as session:
                    with monkeypatch.context() as patch:
                        patch.setattr(factory._owner, 'prepare_async', forbidden)
                        with pytest.raises(CryptoFailure):
                            await session.exec(select(app.Record.name).where(app.Record.name.like('%private%')))
                    assert calls == []
                    assert (await session.exec(select(app.Record.id))).all() == [UUID(int=100)]
            finally:
                await engine.dispose()
        asyncio.run(workflow())


def test_async_exec_scoped_update_delete_and_rollback_match_native():
    with record_application() as app:
        seed(app)
        async def workflow(protected):
            engine = runtime_engine()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    result = await session.exec(update(app.Record).where(app.Record.tenant_id == TENANT),
                        params=[dict(id=UUID(int=100), name='edited雪')],
                        execution_options={'synchronize_session': False})
                    updated = (await session.exec(select(app.Record.name))).one()
                    await session.rollback()
                    assert (await session.exec(select(app.Record.name))).one() == 'seed'
                    removed = await session.exec(delete(app.Record).where(
                        app.Record.tenant_id == TENANT, app.Record.id == UUID(int=100)),
                        execution_options={'synchronize_session': False})
                    assert (await session.exec(select(app.Record.id))).all() == []
                    await session.rollback()
                    return type(result).__name__, updated, removed.rowcount
            finally:
                await engine.dispose()
        expected = asyncio.run(workflow(False))
        protect(app, attach_runtime=False)
        assert asyncio.run(workflow(True)) == expected


def test_async_exec_cancellation_awaits_provider_before_autoflush_and_recovers():
    with record_application() as app:
        seed(app)
        protect(app, attach_runtime=False)
        async def workflow():
            entered, release = asyncio.Event(), asyncio.Event()
            original = PublicFixtureProvider()
            class AwaitedProvider:
                provider_id = original.provider_id
                def unwrap(self, wrapper, context):
                    pytest.fail('SQLModel async exec called synchronous provider preparation')
                async def unwrap_async(self, wrapper, context):
                    entered.set()
                    await release.wait()
                    return original.unwrap(wrapper, context)
            provider = AwaitedProvider()
            ring = Keyring(keys(TENANT).policy, {provider.provider_id: provider})
            engine, task = runtime_engine(), None
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=ring,
                    deployment=(app.plan, app.pin))
                sent = []
                event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: sent.append(True))
                async with factory(tenant_id=TENANT) as session:
                    session.add(app.Record(id=UUID(int=1001), tenant_id=TENANT, name='pending', public='pending'))
                    task = asyncio.create_task(session.exec(select(app.Record.name)))
                    await asyncio.wait_for(entered.wait(), timeout=5)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                    assert sent == []
                    await session.rollback()
                    release.set()
                    assert (await session.exec(select(app.Record.name))).all() == ['seed']
            finally:
                if task is not None and not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                await engine.dispose()
        asyncio.run(workflow())
