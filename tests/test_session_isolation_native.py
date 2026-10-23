"""Independent sessions preserve native state under bounded connection reuse."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from threading import Barrier, Lock
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import bindparam, create_engine, event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

from cryptalis.sqlalchemy import attach
from test_migration import TENANT, application, frames, independent_open, keys, publish, run

OTHER = UUID(int=99001)
TENANTS = (TENANT, OTHER)


def track_pool(engine):
    state = {'active': 0, 'peak': 0, 'checkouts': 0, 'connections': set()}
    lock = Lock()
    @event.listens_for(engine, 'checkout')
    def checkout(connection, record, proxy):
        with lock:
            state['active'] += 1
            state['checkouts'] += 1
            state['connections'].add(id(connection))
            state['peak'] = max(state['peak'], state['active'])
            assert state['active'] <= 4
    @event.listens_for(engine, 'checkin')
    def checkin(connection, record):
        with lock:
            state['active'] -= 1
            assert state['active'] >= 0
    return state


def setup(connection, schema, role):
    # Both actual tenant policies must exist before the public plan is built.
    connection.exec_driver_sql(f'INSERT INTO "{schema}".customer (id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
        [(UUID(int=9000 + index), tenant, 'public seed', 'seed')
         for index, tenant in enumerate(TENANTS)])


def query(customer):
    return select(customer.name).where(customer.id == bindparam('point'),
                                      customer.tenant_id == bindparam('scope'))


def sync_work(app, engine, protected, count, rings):
    if protected:
        sessions = attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=rings.__getitem__,
                          deployment=(app.plan, app.pin))
    else:
        native = sessionmaker(engine)
        sessions = lambda **options: native()
    statement, ready = query(app.Customer), Barrier(count, timeout=10)
    def worker(index):
        tenant, identity = TENANTS[index % 2], UUID(int=10000 + index)
        original, latest = f'public worker {index} 雪😀', f'public latest {index} e\u0301'
        ready.wait()  # No transaction or connection exists at this barrier.
        with sessions(tenant_id=tenant) as session:
            row = app.Customer(id=identity, tenant_id=tenant, name=original, label=f'label-{index}')
            session.add(row)
            session.commit()
            session.refresh(row)
            assert row.name == original
            assert session.scalar(statement, {'point': identity, 'scope': tenant}) == original
            assert session.scalar(statement, {'point': UUID(int=9000 + (1 - index % 2)), 'scope': tenant}) is None
            row.name = 'public rolled back ' + str(index)
            session.flush()
            assert session.scalar(statement, {'point': identity, 'scope': tenant}) == row.name
            session.rollback()
            session.refresh(row)
            assert row.name == original
            row.name = latest
            session.commit()
        with sessions(tenant_id=tenant) as session:
            row = session.get(app.Customer, identity)
            assert row.tenant_id == tenant and row.name == latest
            session.refresh(row)
            assert session.scalar(statement, {'point': identity, 'scope': tenant}) == latest
            return index, row.name, row.label
    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(worker, index) for index in range(count)]
        return [future.result(timeout=45) for future in futures]


async def async_work(app, engine, protected, count, rings):
    if protected:
        sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
            keys=rings.__getitem__, deployment=(app.plan, app.pin))
    else:
        native = async_sessionmaker(engine)
        sessions = lambda **options: native()
    statement = query(app.Customer)
    async def worker(index):
        tenant, identity = TENANTS[index % 2], UUID(int=10000 + index)
        original, latest = f'public worker {index} 雪😀', f'public latest {index} e\u0301'
        async with sessions(tenant_id=tenant) as session:
            row = app.Customer(id=identity, tenant_id=tenant, name=original, label=f'label-{index}')
            session.add(row)
            await session.commit()
            await asyncio.sleep(0)
            await session.refresh(row)
            assert row.name == original
            assert await session.scalar(statement, {'point': identity, 'scope': tenant}) == original
            await asyncio.sleep(0)
            assert await session.scalar(statement,
                {'point': UUID(int=9000 + (1 - index % 2)), 'scope': tenant}) is None
            row.name = 'public rolled back ' + str(index)
            await session.flush()
            assert await session.scalar(statement, {'point': identity, 'scope': tenant}) == row.name
            await session.rollback()
            await session.refresh(row)
            assert row.name == original
            row.name = latest
            await session.commit()
        async with sessions(tenant_id=tenant) as session:
            row = await session.get(app.Customer, identity)
            assert row.tenant_id == tenant and row.name == latest
            await session.refresh(row)
            assert await session.scalar(statement, {'point': identity, 'scope': tenant}) == latest
            return index, row.name, row.label
    async with asyncio.timeout(45):
        async with asyncio.TaskGroup() as group:
            tasks = [group.create_task(worker(index)) for index in range(count)]
    return [task.result() for task in tasks]


@pytest.mark.parametrize('count', [1, 4, 16])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_independent_sessions_match_native_across_bounded_pool(mode, count, record_property):
    results = []
    for protected in (False, True):
        with application(rows=0, queries=[], setup=setup) as app:
            rings = {tenant: keys(tenant) for tenant in TENANTS}
            if protected:
                assert run(app, key_resolver=rings.__getitem__).phase == 'PENDING'
                assert publish(app).phase == 'ACTIVE'
            options = dict(hide_parameters=True, pool_size=4, max_overflow=0, pool_timeout=10)
            connect_options = '-cstatement_timeout=10000 -clock_timeout=5000'
            if mode == 'sync':
                engine = create_engine('postgresql+psycopg://', **options,
                    creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], options=connect_options, connect_timeout=5))
                pool = track_pool(engine)
                try:
                    current = sync_work(app, engine, protected, count, rings)
                    assert engine.pool.checkedout() == 0
                finally:
                    engine.dispose()
            else:
                async def scenario():
                    engine = create_async_engine('postgresql+psycopg://', **options,
                        async_creator=lambda: psycopg.AsyncConnection.connect(
                            os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], options=connect_options, connect_timeout=5))
                    pool = track_pool(engine.sync_engine)
                    try:
                        current = await async_work(app, engine, protected, count, rings)
                        assert engine.pool.checkedout() == 0
                        return current, pool
                    finally:
                        await engine.dispose()
                current, pool = asyncio.run(scenario())
            assert pool['active'] == 0 and 1 <= pool['peak'] <= 4
            assert pool['checkouts'] > len(pool['connections'])
            record_property(('attached' if protected else 'native') + '_pool_peak', pool['peak'])
            if protected:
                descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
                stored = frames(app, True)
                for index, value, label in current:
                    assert independent_open(stored[UUID(int=10000 + index)], descriptor,
                                            TENANTS[index % 2], UUID(int=10000 + index)) == value
            results.append(current)
    assert results[0] == results[1]
