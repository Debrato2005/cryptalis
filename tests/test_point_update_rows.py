"""Point UPDATE without returned columns retains native row counts and state."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import event, select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from cryptalis.crypto import CryptoFailure
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TABLE_ID, TENANT
from test_scoped_delete import no_rows
from test_search_retained_readers import remove_current
from test_single_tenant_update import single_application, snapshot
from test_point_update_returning_more import CASES
from test_point_update_returning_boundary import protect
from test_driver_event_boundary import raw_calls
from test_rewrap_plan import _snapshot


def columns(app, fixed):
    model = app.Customer
    return (model.record, model.value, model.public) if fixed else (model.id, model.name, model.label)


def query(app, fixed, identity):
    statement = update(app.Customer).where(columns(app, fixed)[0] == identity)
    return statement if fixed else statement.where(app.Customer.tenant_id == TENANT)


def selection(app, fixed):
    return select(*columns(app, fixed)).order_by(columns(app, fixed)[0])


@pytest.mark.parametrize('fixed', [False, True])
@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_point_counts_identity_savepoints_and_current_value_exit_match_native(fixed, mode):
    with (single_application() if fixed else application(rows=3)) as app:
        tenant = TABLE_ID if fixed else TENANT
        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            with (factory(tenant_id=tenant) if factory else native(app.runtime)) as session:
                execute = session.exec if mode == 'sqlmodel' else session.execute
                original = session.get(app.Customer, UUID(int=101))
                counts = []
                for identity in (101, 101, 999):
                    result = execute(query(app, fixed, UUID(int=identity)), params={'name': 'updated'},
                        execution_options={'synchronize_session': False})
                    counts.append(result.rowcount)
                    no_rows(result, 0 if identity == 999 else 1)
                assert counts == [1, 1, 0]
                assert session.get(app.Customer, UUID(int=101)) is original
                assert getattr(original, 'value' if fixed else 'name') == ''
                session.refresh(original)
                assert getattr(original, 'value' if fixed else 'name') == 'updated'
                savepoint = session.begin_nested()
                no_rows(execute(query(app, fixed, UUID(int=102)), params={'name': None},
                    execution_options={'synchronize_session': False}), 1)
                savepoint.rollback()
                assert getattr(session.get(app.Customer, UUID(int=102)), 'value' if fixed else 'name') == ('seed' if fixed else '雪😀')
                session.rollback()
                no_rows(execute(query(app, fixed, UUID(int=102)), params={'name': 'latest no-return value'},
                    execution_options={'synchronize_session': False}), 1)
                observed = [tuple(value) for value in execute(selection(app, fixed)).all()]
                session.commit() if factory else session.rollback()
                return observed

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=tenant) if protected else native(engine)) as session:
                    execute = session.exec if mode == 'sqlmodel_async' else session.execute
                    original = await session.get(app.Customer, UUID(int=101))
                    counts = []
                    for identity in (101, 101, 999):
                        result = await execute(query(app, fixed, UUID(int=identity)), params={'name': 'updated'},
                            execution_options={'synchronize_session': False})
                        counts.append(result.rowcount)
                        no_rows(result, 0 if identity == 999 else 1)
                    assert counts == [1, 1, 0]
                    assert await session.get(app.Customer, UUID(int=101)) is original
                    assert getattr(original, 'value' if fixed else 'name') == ''
                    await session.refresh(original)
                    assert getattr(original, 'value' if fixed else 'name') == 'updated'
                    savepoint = await session.begin_nested()
                    no_rows(await execute(query(app, fixed, UUID(int=102)), params={'name': None},
                        execution_options={'synchronize_session': False}), 1)
                    await savepoint.rollback()
                    assert getattr(await session.get(app.Customer, UUID(int=102)), 'value' if fixed else 'name') == ('seed' if fixed else '雪😀')
                    await session.rollback()
                    no_rows(await execute(query(app, fixed, UUID(int=102)), params={'name': 'latest no-return value'},
                        execution_options={'synchronize_session': False}), 1)
                    observed = [tuple(value) for value in (await execute(selection(app, fixed))).all()]
                    await session.commit() if protected else await session.rollback()
                    return observed
            finally:
                await engine.dispose()

        expected = asyncio.run(asynchronous(False)) if 'async' in mode else sync()
        # Fixed-scope mappings intentionally rename attributes; retain those
        # names with a fresh registry before protected attachment.
        from sqlalchemy.orm import registry
        previous = app.mapping, app.Customer
        mapping = registry(metadata=app.table.metadata)
        class Customer: pass
        mapping.map_imperatively(Customer, app.table, properties={
            'record': app.table.c.id, 'value': app.table.c.name, 'public': app.table.c.label} if fixed else {})
        app.mapping, app.Customer = mapping, Customer
        try:
            run(app); publish(app)
            if 'async' in mode:
                observed = asyncio.run(asynchronous(True))
            else:
                selected = attach
                if mode == 'sqlmodel':
                    from cryptalis.sqlmodel import attach as selected
                observed = sync(selected(mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)))
            assert observed == expected
            remove_current(app, keys)
            assert [tuple(value) for value in snapshot(app)] == expected
        finally:
            app.mapping, app.Customer = previous
            mapping.dispose()


@pytest.mark.parametrize('dtype,value,stored', CASES)
def test_point_without_returning_keeps_native_storage_types_and_missing_row_counts(dtype, value, stored):
    with application(rows=2, value_type=dtype, protected_values=(None, None), queries=[]) as app:
        def exercise(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                for identity, count in ((100, 1), (999, 0)):
                    no_rows(session.execute(query(app, False, UUID(int=identity)), {'name': value},
                        execution_options={'synchronize_session': False}), count)
                actual = session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=100)))
                assert actual == stored and type(actual) is type(stored)
                session.rollback()
                return actual
        expected = exercise()
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))
            assert exercise(factory) == expected


@pytest.mark.parametrize('fault', ['sql', 'payload', 'identity'])
def test_point_without_returning_rejects_final_driver_replacement(fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        injected = []
        def mutate(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('UPDATE '):
                injected.append(True)
                if fault == 'sql': sql += ' /* PUBLIC changed */'
                elif fault == 'payload': parameters['name'] = b'PUBLIC invalid'
                else:
                    name = next(k for k, v in parameters.items() if v == UUID(int=101))
                    parameters[name] = UUID(int=102)
            return sql, parameters
        before = _snapshot(app)
        event.listen(app.runtime, 'before_cursor_execute', mutate, retval=True)
        try:
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with pytest.raises(CryptoFailure):
                    session.execute(query(app, False, UUID(int=101)), {'name': 'PUBLIC updated'},
                        execution_options={'synchronize_session': False})
                assert injected == [True] and sent == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', mutate)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['identity', 'returning', 'values'])
def test_point_without_returning_captures_request_before_provider_callback(fault, monkeypatch):
    with application(rows=3) as app:
        armed = []
        def resolve(tenant):
            if armed:
                armed.clear()
                if fault == 'identity': selected._where_criteria = query(app, False, UUID(int=102))._where_criteria
                elif fault == 'returning': selected._returning = (app.Customer.name.__clause_element__(),)
                else: values['name'] = 'PRIVATE changed after admission'
            return keys(tenant)
        factory = protect(app, resolve)
        selected, values = query(app, False, UUID(int=101)), {'name': 'updated'}
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            armed.append(True)
            with pytest.raises(CryptoFailure):
                session.execute(selected, values, execution_options={'synchronize_session': False})
            assert not armed and sent == []
            session.rollback()
        assert _snapshot(app) == before
