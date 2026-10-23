"""Native/attached cancellation hands one shared connection to a queued tenant."""
import asyncio
import os
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from cryptalis.sqlalchemy import attach
from test_migration import application, keys, publish, run, TENANT


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
def test_cancelled_shared_pool_writer_rolls_back_before_queued_tenant_reuses_pool(protected, caplog):
    neighbor_tenant = UUID(int=933)
    def admitted_neighbor(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES(%s,%s,%s,%s)',
            (UUID(int=9330), neighbor_tenant, None, 'PUBLIC admitted neighbor scope'))
    with application(rows=1, unique=False, queries=[], setup=admitted_neighbor) as app:
        if protected:
            run(app)
            publish(app)

        async def scenario():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                pool_size=1, max_overflow=0, pool_timeout=5,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], connect_timeout=5,
                    options='-cstatement_timeout=15000'))
            try:
                if protected:
                    sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                        keys=keys, deployment=(app.plan, app.pin))
                else:
                    native = async_sessionmaker(engine, expire_on_commit=False)
                    sessions = lambda *, tenant_id: native()
                shared_identity, later_identity = uuid4(), uuid4()
                holder_pid = asyncio.get_running_loop().create_future()
                neighbor_started, neighbor_acquired = asyncio.Event(), asyncio.Event()

                async def holder():
                    # Each task owns its Session, including rollback and close.
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(app.Customer(id=shared_identity, tenant_id=TENANT,
                            name='PUBLIC canceled uncommitted value', label='canceled'))
                        await session.flush()
                        holder_pid.set_result(await session.scalar(select(func.pg_backend_pid())))
                        await session.scalar(select(func.pg_sleep(30)))

                async def neighbor():
                    async with sessions(tenant_id=neighbor_tenant) as session:
                        neighbor_started.set()
                        await session.connection()
                        neighbor_acquired.set()
                        # The same primary key can commit only after the first
                        # task's flushed, uncommitted insertion rolls back.
                        session.add(app.Customer(id=shared_identity, tenant_id=neighbor_tenant,
                            name='PUBLIC committed neighbor value', label='neighbor'))
                        await session.commit()
                        assert await session.scalar(select(app.Customer.name).where(
                            app.Customer.id == shared_identity,
                            app.Customer.tenant_id == neighbor_tenant)) == 'PUBLIC committed neighbor value'

                async with asyncio.timeout(20):
                    # TaskGroup closes and awaits both task-owned Sessions on
                    # every assertion, timeout or unexpected child exception.
                    async with asyncio.TaskGroup() as tasks:
                        pending = tasks.create_task(holder())
                        pid = await asyncio.wait_for(holder_pid, timeout=5)
                        async with await psycopg.AsyncConnection.connect(
                                os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                                connect_timeout=5, autocommit=True) as observer:
                            async with asyncio.timeout(5):
                                while True:
                                    cursor = await observer.execute(
                                        'SELECT wait_event FROM pg_catalog.pg_stat_activity WHERE pid=%s', (pid,))
                                    if await cursor.fetchone() == ('PgSleep',):
                                        break
                                    await asyncio.sleep(0.01)
                            queued = tasks.create_task(neighbor())
                            await asyncio.wait_for(neighbor_started.wait(), timeout=5)
                            await asyncio.sleep(0)
                            assert not neighbor_acquired.is_set() and not queued.done()
                            assert engine.pool.checkedout() == 1
                            pending.cancel()
                            with pytest.raises(asyncio.CancelledError):
                                await asyncio.wait_for(pending, timeout=5)
                            await asyncio.wait_for(queued, timeout=5)
                            assert neighbor_acquired.is_set()
                            cursor = await observer.execute(sql.SQL(
                                'SELECT tenant_id,name FROM {}.customer WHERE id=%s').format(
                                    sql.Identifier(app.schema)), (shared_identity,))
                            stored = await cursor.fetchall()
                            assert len(stored) == 1 and stored[0][0] == neighbor_tenant
                            if protected:
                                assert bytes(stored[0][1]).startswith(b'CF1\0')
                            else:
                                assert stored[0][1] == 'PUBLIC committed neighbor value'
                assert engine.pool.checkedout() == 0
                async with sessions(tenant_id=TENANT) as session:
                    session.add(app.Customer(id=later_identity, tenant_id=TENANT,
                        name='PUBLIC healthy original tenant', label='recovered'))
                    await session.commit()
                    assert await session.scalar(select(app.Customer.name).where(
                        app.Customer.id == later_identity,
                        app.Customer.tenant_id == TENANT)) == 'PUBLIC healthy original tenant'
                    assert await session.scalar(select(app.Customer.name).where(
                        app.Customer.id == shared_identity,
                        app.Customer.tenant_id == TENANT)) is None
                async with sessions(tenant_id=neighbor_tenant) as session:
                    assert await session.scalar(select(app.Customer.name).where(
                        app.Customer.id == shared_identity,
                        app.Customer.tenant_id == neighbor_tenant)) == 'PUBLIC committed neighbor value'
                assert engine.pool.checkedout() == 0
            finally:
                await engine.dispose()

        asyncio.run(scenario())
        assert not [record for record in caplog.records if record.levelno >= 40], 'Cancellation cleanup logged an error'
