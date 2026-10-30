"""Fixed-scope mapped DELETE retains native rowcounts and immutable context."""

import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, func, inspect
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.crypto import Keyring
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_driver_event_boundary import raw_calls
from test_migration import PROVIDER, TABLE_ID, TENANT, PublicFixtureProvider, keys, publish, run
from test_scoped_delete import no_rows
from test_single_tenant_update import single_application, selection, snapshot


def statement(app, identity=UUID(int=101)):
    return delete(app.Customer).where(app.Customer.record == identity)


def sync_workflow(app, factory, protected):
    with factory() as session:
        loaded = session.get(app.Customer, UUID(int=101))
        counts = []
        for identity in (UUID(int=101), UUID(int=101), UUID(int=999)):
            result = session.execute(statement(app, identity), execution_options={'synchronize_session': False})
            counts.append(result.rowcount)
            no_rows(result, counts[-1])
        assert counts == [1, 0, 0] and inspect(loaded).persistent and not inspect(loaded).deleted
        assert session.get(app.Customer, UUID(int=101)) is loaded
        savepoint = session.begin_nested()
        no_rows(session.execute(statement(app, UUID(int=102)), execution_options={'synchronize_session': False}), 1)
        savepoint.rollback()
        assert session.get(app.Customer, UUID(int=102)).value == 'seed'
        session.rollback()
        assert session.get(app.Customer, UUID(int=101)).value == ''
        session.get(app.Customer, UUID(int=102)).value = 'latest value'
        no_rows(session.execute(statement(app), execution_options={'synchronize_session': False}), 1)
        values = session.execute(selection(app)).all()
        session.commit() if protected else session.rollback()
        return counts, values


async def async_workflow(app, protected, sqlmodel):
    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    try:
        selected_attach, native = attach, AsyncSession
        if sqlmodel:
            pytest.importorskip('sqlmodel', reason='optional SQLModel async fixed-scope DELETE')
            from cryptalis.sqlmodel import attach as selected_attach
            from sqlmodel.ext.asyncio.session import AsyncSession as native
        factory = (await selected_attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                        deployment=(app.plan, app.pin)) if protected else lambda **kwargs: native(engine))
        async with (factory(tenant_id=TABLE_ID) if protected else factory()) as session:
            method = session.exec if sqlmodel else session.execute
            loaded = await session.get(app.Customer, UUID(int=101))
            counts = []
            for identity in (UUID(int=101), UUID(int=101), UUID(int=999)):
                result = await method(statement(app, identity), execution_options={'synchronize_session': False})
                counts.append(result.rowcount)
                no_rows(result, counts[-1])
            assert counts == [1, 0, 0] and inspect(loaded).persistent and not inspect(loaded).deleted
            assert await session.get(app.Customer, UUID(int=101)) is loaded
            savepoint = await session.begin_nested()
            no_rows(await method(statement(app, UUID(int=102)), execution_options={'synchronize_session': False}), 1)
            await savepoint.rollback()
            assert (await session.get(app.Customer, UUID(int=102))).value == 'seed'
            await session.rollback()
            assert (await session.get(app.Customer, UUID(int=101))).value == ''
            (await session.get(app.Customer, UUID(int=102))).value = 'latest value'
            no_rows(await method(statement(app), execution_options={'synchronize_session': False}), 1)
            values = (await method(selection(app))).all()
            await session.commit() if protected else await session.rollback()
            return counts, values
    finally:
        await engine.dispose()


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel_async'])
def test_fixed_scope_delete_matches_native_transactions_and_current_value_exit(mode):
    with single_application() as app:
        expected = (sync_workflow(app, lambda: Session(app.runtime), False) if mode == 'sync' else
                    asyncio.run(async_workflow(app, False, mode == 'sqlmodel_async')))
        run(app)
        publish(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            observed = sync_workflow(app, lambda: factory(tenant_id=TABLE_ID), True)
        else:
            observed = asyncio.run(async_workflow(app, True, mode == 'sqlmodel_async'))
        assert observed == expected
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert reverse(app, plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING').phase == 'PLAINTEXT_ACTIVE'
        approval, _ = consent(plan, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'fixed-scope DELETE and latest-value exit', 'no retained fixture copies', True)
        assert d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=approval).phase == 'REMOVED'
        assert snapshot(app) == expected[1]


def test_fixed_scope_delete_shape_and_authority_refusals_precede_keys_and_sql():
    with single_application() as app:
        run(app)
        publish(app)
        calls, statements = [], []
        def resolve(tenant):
            calls.append(tenant)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with pytest.raises(PolicyMismatch):
            factory(tenant_id=TENANT)
        assert calls == []
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: statements.append(True))
        with factory(tenant_id=TABLE_ID) as session:
            calls.clear()
            for selected, parameters in ((delete(app.Customer), None),
                    (statement(app).where(app.Customer.public == 'extra'), None),
                    (statement(app).returning(func.lower(app.Customer.public).label('unsupported')), None),
                    (delete(app.table).where(app.table.c.id == UUID(int=101)), None),
                    (statement(app), {}), (statement(app), []),
                    (statement(app, 'not a typed UUID'), None)):
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(selected, params=parameters, execution_options={'synchronize_session': False})
            assert calls == statements == []


def test_fixed_scope_delete_late_record_bind_replacement_never_reaches_driver(monkeypatch):
    with single_application() as app:
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        before = snapshot(app)
        attempted = []
        def replace(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('DELETE '):
                attempted.append(True)
                assert len(parameters) == 1
                return sql, {next(iter(parameters)): UUID(int=102)}
            return sql, parameters
        event.listen(app.runtime, 'before_cursor_execute', replace, retval=True)
        with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with factory(tenant_id=TABLE_ID) as session:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement(app), execution_options={'synchronize_session': False})
                session.rollback()
            assert sent == [] and attempted == [True]
        assert snapshot(app) == before


def test_fixed_scope_delete_freezes_identity_before_awaited_provider_mutation():
    with single_application() as app:
        run(app)
        publish(app)
        selected = statement(app)
        async def scenario():
            class MutatingProvider:
                provider_id = PROVIDER
                def unwrap(self, *args):
                    raise AssertionError('async DELETE must await custody outside synchronous hooks')
                async def unwrap_async(self, wrapper, context):
                    selected.whereclause.right.value = UUID(int=102)
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
                        await session.execute(selected, execution_options={'synchronize_session': False})
                    await session.rollback()
                assert statements == [] and selected.whereclause.right.value == UUID(int=102)
            finally:
                await engine.dispose()
        before = snapshot(app)
        asyncio.run(scenario())
        assert snapshot(app) == before
