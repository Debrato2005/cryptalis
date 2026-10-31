"""Inherited runtime objects must not commit/close a parent's live transaction."""
import asyncio
from contextlib import nullcontext
import multiprocessing
import os
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry
from sqlalchemy.ext.asyncio import create_async_engine

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_migration import application, engine, keys, publish, run, TENANT


def fresh_mapping(app):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
        Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    return mapping, Customer


def fresh_runtime(app):
    mapping, Customer = fresh_mapping(app)
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    factory = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                     deployment=(app.plan, app.pin))
    return runtime, factory, Customer


def child_probe(sender, operation, app, calls, before, child_record):
    try:
        try:
            operation()
        except CryptoFailure as error:
            if error.code != 'ForkedRuntime':
                sender.send_bytes(b'WRONG_TYPED_ERROR'); return
        except BaseException:
            sender.send_bytes(b'UNTYPED_ERROR'); return
        else:
            sender.send_bytes(b'INHERITED_OPERATION_SUCCEEDED'); return
        if len(calls) != before:
            sender.send_bytes(b'INHERITED_RESOLVER_CALLED'); return
        runtime, factory, Customer = fresh_runtime(app)
        try:
            with factory(tenant_id=TENANT) as session:
                assert session.get(Customer, UUID(int=101)).name == app.source[UUID(int=101)][1]
                session.add(Customer(id=child_record, tenant_id=TENANT,
                    name='PUBLIC fresh child', label='fresh'))
                session.commit()
                assert session.scalar(select(Customer.id).where(Customer.tenant_id == TENANT,
                    Customer.name == 'PUBLIC fresh child')) == child_record
        finally:
            runtime.dispose()
        sender.send_bytes(b'REFUSED_AND_FRESH_CHILD_COMMITTED')
    except BaseException as error:
        sender.send_bytes(b'FRESH_CHILD_FAILED:' + type(error).__name__.encode('ascii'))
    finally:
        sender.close()


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires POSIX fork')
@pytest.mark.parametrize('route', ['factory', 'query', 'cached_get', 'commit', 'rollback', 'close',
    'captured_driver_commit', 'captured_driver_rollback', 'captured_driver_close',
    'captured_cursor_close', 'captured_transaction_commit', 'engine_connect', 'engine_raw_connection'])
def test_inherited_scope_refuses_and_fresh_child_preserves_parent_transaction(route):
    with application(rows=2) as app:
        run(app); publish(app)
        calls = []
        def resolve(tenant):
            calls.append(os.getpid())
            return keys(tenant)  # Fresh child keyrings must not validate inherited ORM state.
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT, expire_on_commit=False) as session:
            original = session.get(app.Customer, UUID(int=101))
            pending, committed = uuid4(), uuid4()
            session.add(app.Customer(id=pending, tenant_id=TENANT, name='PUBLIC parent pending', label='parent'))
            session.flush()
            driver = session.connection().connection.driver_connection
            cursor = driver.cursor()
            operation = {
                'factory': lambda: factory(tenant_id=TENANT),
                'query': lambda: session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))),
                'cached_get': lambda: session.get(app.Customer, UUID(int=101)),
                'commit': session.commit, 'rollback': session.rollback, 'close': session.close,
                'captured_driver_commit': driver.commit,
                'captured_driver_rollback': driver.rollback,
                'captured_driver_close': driver.close,
                'captured_cursor_close': cursor.close,
                'captured_transaction_commit': session.get_transaction().commit,
                'engine_connect': app.runtime.connect,
                'engine_raw_connection': app.runtime.raw_connection,
            }[route]
            context = multiprocessing.get_context('fork')
            receiver, sender = context.Pipe(duplex=False)
            child = context.Process(target=child_probe, args=(sender, operation, app, calls, len(calls), committed))
            try:
                # A native pool lock inherited while held must not be acquired
                # by these entrypoints before process ownership is checked.
                with app.runtime.pool._pool.mutex if route.startswith('engine_') else nullcontext():
                    child.start(); sender.close()
                    child.join(timeout=20)
                assert not child.is_alive(), 'forked runtime operation or fresh bootstrap blocked'
                assert child.exitcode == 0 and receiver.poll(0), 'child returned no safe outcome'
                assert receiver.recv_bytes(128) == b'REFUSED_AND_FRESH_CHILD_COMMITTED'
            finally:
                receiver.close(); sender.close()
                if child.pid is not None:
                    if child.is_alive(): child.kill()
                    child.join(timeout=5)
                    assert not child.is_alive(), 'child cleanup did not finish'
                child.close()
                cursor.close()
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as observer:
                rows = observer.execute(sql.SQL('SELECT id,name FROM {}.customer WHERE id IN (%s,%s)').format(
                    sql.Identifier(app.schema)), (pending, committed)).fetchall()
                assert len(rows) == 1 and rows[0][0] == committed and bytes(rows[0][1]).startswith(b'CF1\0')
            assert session.get(app.Customer, UUID(int=101)) is original
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == pending)) == 'PUBLIC parent pending'
            session.rollback()
            with factory(tenant_id=TENANT) as clean:
                assert clean.get(app.Customer, pending) is None
                assert clean.get(app.Customer, committed).name == 'PUBLIC fresh child'


def async_runtime():
    return create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))


def async_child_probe(sender, app, Customer, factory, session, calls, before, child_record):
    async def check():
        try:
            factory(tenant_id=TENANT)
        except CryptoFailure as error:
            assert error.code == 'ForkedRuntime'
        else:
            raise AssertionError('inherited async factory succeeded')
        operations = [
            lambda: session.scalar(select(Customer.name)),
            lambda: session.get(Customer, UUID(int=101)),
            session.commit, session.rollback, session.close, session.connection,
            session.flush, session.get_transaction().commit,
        ]
        for operation in operations:
            try:
                await operation()
            except CryptoFailure as error:
                assert error.code == 'ForkedRuntime'
            else:
                raise AssertionError('inherited async operation succeeded')
        assert len(calls) == before
        runtime = async_runtime()
        mapping, FreshCustomer = fresh_mapping(app)
        try:
            fresh = await attach(mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                                 deployment=(app.plan, app.pin))
            async with fresh(tenant_id=TENANT) as own:
                assert (await own.get(FreshCustomer, UUID(int=101))).name == app.source[UUID(int=101)][1]
                own.add(FreshCustomer(id=child_record, tenant_id=TENANT, name='PUBLIC async child', label='fresh'))
                await own.commit()
                assert await own.scalar(select(FreshCustomer.id).where(FreshCustomer.tenant_id == TENANT,
                    FreshCustomer.name == 'PUBLIC async child')) == child_record
        finally:
            await runtime.dispose()
    try:
        asyncio.run(check())
        sender.send_bytes(b'REFUSED_AND_FRESH_ASYNC_CHILD_COMMITTED')
    except BaseException as error:
        sender.send_bytes(b'ASYNC_CHILD_FAILED:' + type(error).__name__.encode('ascii'))
    finally:
        sender.close()


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires POSIX fork')
def test_async_inherited_cache_and_transactions_refuse_before_fresh_child_bootstrap():
    with application(rows=2) as app, asyncio.Runner() as runner:
        run(app); publish(app)
        runtime, calls = async_runtime(), []
        mapping, Customer = fresh_mapping(app)
        def resolve(tenant):
            calls.append(os.getpid())
            return keys(tenant)
        pending, committed = uuid4(), uuid4()
        async def prepare():
            factory = await attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolve,
                                   deployment=(app.plan, app.pin))
            session = factory(tenant_id=TENANT, expire_on_commit=False)
            original = await session.get(Customer, UUID(int=101))
            session.add(Customer(id=pending, tenant_id=TENANT, name='PUBLIC async parent', label='parent'))
            await session.flush()
            return factory, session, original
        factory, session, original = runner.run(prepare())
        # Fork outside the running loop; the parent's Runner and connection
        # remain alive. The child creates a separate loop for a fresh runtime.
        context = multiprocessing.get_context('fork')
        receiver, sender = context.Pipe(duplex=False)
        child = context.Process(target=async_child_probe,
            args=(sender, app, Customer, factory, session, calls, len(calls), committed))
        try:
            child.start(); sender.close(); child.join(timeout=20)
            assert not child.is_alive(), 'async fork probe blocked'
            assert child.exitcode == 0 and receiver.poll(0)
            assert receiver.recv_bytes(128) == b'REFUSED_AND_FRESH_ASYNC_CHILD_COMMITTED'
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as observer:
                rows = observer.execute(sql.SQL('SELECT id,name FROM {}.customer WHERE id IN (%s,%s)').format(
                    sql.Identifier(app.schema)), (pending, committed)).fetchall()
                assert len(rows) == 1 and rows[0][0] == committed and bytes(rows[0][1]).startswith(b'CF1\0')
            async def verify():
                assert await session.get(Customer, UUID(int=101)) is original
                assert await session.scalar(select(Customer.name).where(Customer.id == pending)) == 'PUBLIC async parent'
                await session.rollback()
                async with factory(tenant_id=TENANT) as clean:
                    assert await clean.get(Customer, pending) is None
                    assert (await clean.get(Customer, committed)).name == 'PUBLIC async child'
            runner.run(verify())
        finally:
            sender.close(); receiver.close()
            if child.pid is not None:
                if child.is_alive(): child.kill()
                child.join(timeout=5)
                assert not child.is_alive()
            child.close()
            runner.run(session.close())
            runner.run(runtime.dispose())
