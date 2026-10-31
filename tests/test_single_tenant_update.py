"""Bare mapped bulk UPDATE retains native fixed-scope behavior and failures."""

import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, Text, Uuid, event, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, registry
from sqlalchemy.orm.exc import StaleDataError

from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_bulk_update_native import empty_result
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import (FIELD_ID, PROVIDER, TABLE_ID, TENANT, PublicFixtureProvider,
                            application, keys, publish, run)


@contextmanager
def single_application(dtype=None, values=(None, '', 'seed')):
    dtype = Text(collation='C') if dtype is None else dtype
    queries = ['equality'] if isinstance(dtype, (Text, String)) else []
    with application(rows=3, unique=False, queries=queries, value_type=dtype, protected_values=values) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DROP COLUMN tenant_id')
        mapping = registry(metadata=MetaData(schema=app.schema))
        table = Table('customer', mapping.metadata,
            Column('id', Uuid, primary_key=True, autoincrement=False), Column('name', dtype.copy()), Column('label', Text))
        class Customer:
            pass
        mapping.map_imperatively(Customer, table, properties={
            'record': table.c.id, 'value': table.c.name, 'public': table.c.label})
        declaration = app.plan.document['lock']['declaration']
        declaration['models'][0]['tenancy'] = {'single_tenant': True}
        declaration['models'][0]['fields'][0]['name'] = 'value'
        app.mapping, app.table, app.Customer = mapping, table, Customer
        app.plan = app.m.plan(json.dumps(declaration).encode(), mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned fixed-scope native table'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded text'),) if queries else (),
            keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.pin = app.m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        try:
            yield app
        finally:
            mapping.dispose()


def snapshot(app):
    with app.owner.connect() as connection:
        return connection.exec_driver_sql(f'SELECT id,name,label FROM "{app.schema}".customer ORDER BY id').all()


def selection(app):
    return select(app.Customer.record, app.Customer.value, app.Customer.public).order_by(app.Customer.record)


def protect(app):
    run(app)
    publish(app)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel_async'])
def test_single_tenant_partial_null_repeated_groups_refresh_and_native_exit(mode):
    with single_application() as app:
        rows = [{'record': UUID(int=100), 'value': 'first', 'public': 'public first'},
                {'record': UUID(int=101), 'public': 'public only'},
                {'record': UUID(int=100), 'value': '雪😀'}, {'record': UUID(int=102), 'value': None}]
        original = deepcopy(rows)
        def sync(factory, protected):
            with factory() as session:
                loaded = session.get(app.Customer, UUID(int=100))
                empty_result(session.execute(update(app.Customer), rows, execution_options={'synchronize_session': False}))
                assert loaded.value is None
                session.refresh(loaded)
                assert loaded.value == '雪😀'
                result = session.execute(selection(app)).all()
                session.commit() if protected else session.rollback()
                return result
        expected = sync(lambda: Session(app.runtime), False)
        run(app)
        publish(app)
        sent = []
        def observe(connection, cursor, statement, parameters, context, many):
            if statement.lstrip().upper().startswith('UPDATE '):
                sent.append(repr(parameters))
                assert 'tenant_id' not in statement and 'WHERE' in statement
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            event.listen(app.runtime, 'before_cursor_execute', observe)
            try:
                assert sync(lambda: factory(tenant_id=TABLE_ID), True) == expected
            finally:
                event.remove(app.runtime, 'before_cursor_execute', observe)
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    selected_attach = attach
                    if mode == 'sqlmodel_async':
                        pytest.importorskip('sqlmodel', reason='optional SQLModel async fixed-scope route')
                        from cryptalis.sqlmodel import attach as selected_attach
                    factory = await selected_attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                                    deployment=(app.plan, app.pin))
                    event.listen(engine.sync_engine, 'before_cursor_execute', observe)
                    async with factory(tenant_id=TABLE_ID) as session:
                        loaded = await session.get(app.Customer, UUID(int=100))
                        method = session.exec if mode == 'sqlmodel_async' else session.execute
                        empty_result(await method(update(app.Customer), params=rows,
                            execution_options={'synchronize_session': False}))
                        assert loaded.value is None
                        await session.refresh(loaded)
                        assert loaded.value == '雪😀'
                        assert (await method(selection(app))).all() == expected
                        await session.commit()
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert rows == original and sent and '雪😀' not in ''.join(sent) and 'first' not in ''.join(sent).replace('public first', '')
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert reverse(app, plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING').phase == 'PLAINTEXT_ACTIVE'
        approval, _ = consent(plan, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'single-tenant mapped updates retain latest values', 'no retained fixture copies', True)
        assert d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=approval).phase == 'REMOVED'
        assert snapshot(app) == expected


def test_missing_records_preserve_native_stale_error_partial_effects_and_savepoint_recovery():
    with single_application() as app:
        changes = [[{'record': UUID(int=999), 'value': 'missing'}],
                   [{'record': UUID(int=100), 'value': 'first'}, {'record': UUID(int=999), 'value': 'missing'}],
                   [{'record': UUID(int=100), 'public': 'first group'},
                    {'record': UUID(int=999), 'value': 'missing'}, {'record': UUID(int=101), 'value': 'not reached'}]]
        def scenario(factory):
            observations = []
            with factory() as session:
                for rows in changes:
                    savepoint = session.begin_nested()
                    with pytest.raises(StaleDataError):
                        session.execute(update(app.Customer), rows, execution_options={'synchronize_session': False})
                    driver = session.connection().connection.driver_connection
                    observations.append((session.is_active, driver.info.transaction_status.name,
                                         session.execute(selection(app)).all()))
                    savepoint.rollback()
                empty_result(session.execute(update(app.Customer), [{'record': UUID(int=101), 'value': 'retry'}],
                                             execution_options={'synchronize_session': False}))
                observations.append(session.execute(selection(app)).all())
                session.rollback()
            return observations
        expected = scenario(lambda: Session(app.runtime))
        factory = protect(app)
        assert scenario(lambda: factory(tenant_id=TABLE_ID)) == expected


@pytest.mark.parametrize('dtype,values,bad,code', [
    (String(4, collation='C'), (None, '', 'seed'), 'abcde', '22001'),
    (Integer(), (None, 0, 1), 2 ** 31 + 37, '22003')])
@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
def test_fixed_scope_overflow_carriers_preserve_native_errors_stale_checks_and_partial_effects(dtype, values, bad, code, mode):
    from test_bulk_update_varchar import plan_mode
    with single_application(dtype, values) as app, plan_mode(app.runtime, mode):
        def scenario(factory, protected):
            observations = []
            with factory() as session:
                for identity in (UUID(int=100), UUID(int=999)):
                    savepoint = session.begin_nested()
                    try:
                        session.execute(update(app.Customer), [{'record': UUID(int=101), 'public': 'before error'},
                            {'record': identity, 'value': bad}], execution_options={'synchronize_session': False})
                    except (CryptoFailure, DBAPIError, StaleDataError) as failure:
                        outcome = (failure.sqlstate if isinstance(failure, CryptoFailure) else
                                   failure.orig.sqlstate if isinstance(failure, DBAPIError) else 'stale')
                    else:
                        pytest.fail('invalid assignment or missing record returned success')
                    if outcome != 'stale':
                        assert outcome == code
                    driver = session.connection().connection.driver_connection
                    observations.append((outcome, session.is_active, driver.info.transaction_status.name))
                    savepoint.rollback()
                    assert session.execute(selection(app)).all() == baseline
                session.rollback()
            return observations
        baseline = snapshot(app)
        expected = scenario(lambda: Session(app.runtime), False)
        factory = protect(app)
        assert scenario(lambda: factory(tenant_id=TABLE_ID), True) == expected


def test_fixed_scope_request_and_context_refusals_precede_provider_work():
    with single_application() as app:
        run(app)
        publish(app)
        calls = []
        def resolve(tenant):
            calls.append(tenant)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with pytest.raises(PolicyMismatch):
            factory(tenant_id=TENANT)
        assert calls == []
        statements = []
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: statements.append(True))
        with factory(tenant_id=TABLE_ID) as session:
            calls.clear()
            for statement, rows in ((update(app.Customer).where(app.Customer.record == UUID(int=100)),
                                     [{'record': UUID(int=100), 'value': 'blocked'}]),
                                    (update(app.Customer), [{'value': 'missing identity'}]),
                                    (update(app.Customer), [{'record': 'not typed', 'value': 'blocked'}])):
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement, rows, execution_options={'synchronize_session': False})
            assert calls == statements == []


def test_fixed_scope_async_request_mutation_during_provider_await_refuses_without_sql():
    with single_application() as app:
        run(app)
        publish(app)
        rows = [{'record': UUID(int=100), 'value': 'original'}]
        async def scenario():
            class MutatingProvider:
                provider_id = PROVIDER
                def unwrap(self, *args):
                    raise AssertionError('async preparation must await the provider')
                async def unwrap_async(self, wrapper, context):
                    rows[0]['record'] = UUID(int=101)
                    return PublicFixtureProvider().unwrap(wrapper, context)
            ring = Keyring(keys(TABLE_ID).policy, {PROVIDER: MutatingProvider()})
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            statements = []
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=ring,
                                       deployment=(app.plan, app.pin))
                event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: statements.append(True))
                async with factory(tenant_id=TABLE_ID) as session:
                    with pytest.raises(UnsupportedProtectedOperation):
                        await session.execute(update(app.Customer), rows, execution_options={'synchronize_session': False})
                    await session.rollback()
                assert statements == [] and rows[0]['record'] == UUID(int=101)
            finally:
                await engine.dispose()
        before = snapshot(app)
        asyncio.run(scenario())
        assert snapshot(app) == before
