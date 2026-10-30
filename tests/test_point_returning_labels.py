"""Named direct-column RETURNING keeps native result keys and authenticated values."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, Text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import quoted_name

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_point_update_returning_boundary import protect
from test_point_update_returning_more import CASES
from test_rewrap_plan import _snapshot


def query(app, operation, label='display_name', identity=UUID(int=101), *, public_label='public_value'):
    return (update if operation == 'UPDATE' else delete)(app.Customer).where(
        app.Customer.id == identity, app.Customer.tenant_id == TENANT).returning(
            app.Customer.name.label(label), app.Customer.label.label(public_label))


def parameters(operation, value='PRIVATE_LABEL_VALUE'):
    return {'name': value} if operation == 'UPDATE' else None


def consume(result):
    names = tuple(result.keys())
    rows = [tuple(row) for row in result.all()]
    return names, rows, [tuple(type(value) for value in row) for row in rows]


LABELS = [('display_name', 'public value'), (quoted_name('select', True), '表示名'),
          ('same', 'same'), ('long_' + 'x' * 80, 'public_value'),
          (quoted_name('safe_name', False), 'quoted; name')]


@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE'])
@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_labels_match_native_keys_types_nulls_missing_rows_and_transactions(operation, mode):
    with application(rows=3) as app:
        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            observed = []
            for label, public in LABELS:
                with (factory(tenant_id=TENANT) if factory else native(app.runtime)) as session:
                    execute = session.exec if mode == 'sqlmodel' else session.execute
                    with session.begin_nested():
                        observed.append(consume(execute(query(app, operation, label, public_label=public),
                            params=parameters(operation), execution_options={'synchronize_session': False})))
                    observed.append(consume(execute(query(app, operation, label, UUID(int=100)),
                        params=parameters(operation, None), execution_options={'synchronize_session': False})))
                    observed.append(consume(execute(query(app, operation, label, UUID(int=999)),
                        params=parameters(operation), execution_options={'synchronize_session': False})))
                    session.rollback()
                    assert session.get(app.Customer, UUID(int=101)).name == ''
            return observed

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                observed = []
                for label, public in LABELS:
                    async with (factory(tenant_id=TENANT) if factory else native(runtime)) as session:
                        execute = session.exec if mode == 'sqlmodel_async' else session.execute
                        async with session.begin_nested():
                            observed.append(consume(await execute(query(app, operation, label, public_label=public),
                                params=parameters(operation), execution_options={'synchronize_session': False})))
                        observed.append(consume(await execute(query(app, operation, label, UUID(int=100)),
                            params=parameters(operation, None), execution_options={'synchronize_session': False})))
                        observed.append(consume(await execute(query(app, operation, label, UUID(int=999)),
                            params=parameters(operation), execution_options={'synchronize_session': False})))
                        await session.rollback()
                        assert (await session.get(app.Customer, UUID(int=101))).name == ''
                return observed
            finally:
                await runtime.dispose()

        expected = asyncio.run(asynchronous(False)) if 'async' in mode else sync()
        with fresh_mapping(app):
            run(app); publish(app)
            if 'async' in mode:
                actual = asyncio.run(asynchronous(True))
            else:
                selected = attach
                if mode == 'sqlmodel':
                    from cryptalis.sqlmodel import attach as selected
                actual = sync(selected(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)))
            assert actual == expected


@pytest.mark.parametrize('dtype,value,stored', CASES)
@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE'])
def test_named_returning_preserves_native_supported_value_types(dtype, value, stored, operation):
    with application(rows=2, value_type=dtype, protected_values=(stored, None), queries=[]) as app:
        def exercise(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                result = session.execute(query(app, operation, identity=UUID(int=100)),
                    params=parameters(operation, value), execution_options={'synchronize_session': False})
                observed = consume(result)
                assert observed[1][0][0] == stored and observed[2][0][0] is type(stored)
                session.rollback()
                return observed
        expected = exercise()
        with fresh_mapping(app):
            run(app); publish(app)
            assert exercise(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))) == expected


@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE'])
@pytest.mark.parametrize('fault', ['type', 'dispatch', 'name', 'key', 'anonymous', 'missing_name', 'unquoted_sql'])
def test_forged_label_refuses_before_keys_or_driver(operation, fault, monkeypatch):
    with application(rows=3) as app:
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = protect(app, resolve)
        statement = query(app, operation, None if fault == 'anonymous' else 'display_name')
        label = statement._returning[0]
        if fault == 'type': label.type = Text()
        if fault == 'dispatch': label._compiler_dispatch = lambda *a, **k: 'PRIVATE_DISPATCH'
        if fault == 'name': label.name = 'PRIVATE\x00NAME'
        if fault == 'key': label.key = 'PRIVATE_CHANGED_KEY'
        if fault == 'missing_name': label.name = label.key = None
        if fault == 'unquoted_sql': label.name = label.key = quoted_name('display_name, 1', False)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, operation) as sent:
            calls.clear()
            with pytest.raises(CryptoFailure):
                session.execute(statement, params=parameters(operation), execution_options={'synchronize_session': False})
            assert calls == sent == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE'])
@pytest.mark.parametrize('fault', ['name', 'element', 'type'])
@pytest.mark.parametrize('timing', ['provider', 'before_execute', 'before_cursor_execute'])
def test_callbacks_cannot_change_captured_label(operation, fault, timing, monkeypatch):
    with application(rows=3) as app:
        armed, mutations = [], []
        def mutate(statement):
            label = statement._returning[0]
            if fault == 'name': label.name = label.key = 'changed_name'
            if fault == 'element': label._element = app.Customer.label.__clause_element__()
            if fault == 'type': label.type = Text()
            mutations.append(True)
        def resolve(tenant):
            if armed:
                armed.clear()
                mutate(statement)
            return keys(tenant)
        factory = protect(app, resolve)
        statement = query(app, operation)
        def before_execute(connection, clause, multiparams, params, execution_options):
            if getattr(clause, 'is_update', False) or getattr(clause, 'is_delete', False): mutate(clause)
        def before_cursor_execute(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith(operation + ' '): mutate(context.compiled.statement)
        observer = before_execute if timing == 'before_execute' else before_cursor_execute
        before = _snapshot(app)
        if timing != 'provider': event.listen(app.runtime, timing, observer)
        try:
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, operation) as sent:
                if timing == 'provider': armed.append(True)
                with pytest.raises(CryptoFailure):
                    session.execute(statement, params=parameters(operation), execution_options={'synchronize_session': False})
                assert mutations == [True] and armed == sent == []
                session.rollback()
        finally:
            if timing != 'provider': event.remove(app.runtime, timing, observer)
        assert _snapshot(app) == before


@pytest.mark.parametrize('operation', ['UPDATE', 'DELETE'])
def test_fixed_tenant_renamed_columns_and_current_value_removal(operation):
    from sqlalchemy.orm import registry
    from test_single_tenant_update import single_application, snapshot
    from test_search_retained_readers import remove_current
    from test_migration import TABLE_ID
    with single_application() as app:
        def statement():
            return (update if operation == 'UPDATE' else delete)(app.Customer).where(
                app.Customer.record == UUID(int=101)).returning(app.Customer.record.label('record_id'),
                    app.Customer.value.label('display_value'))
        def exercise(factory=None):
            with (factory(tenant_id=TABLE_ID) if factory else Session(app.runtime)) as session:
                observed = consume(session.execute(statement(), params=parameters(operation, 'latest named value'),
                    execution_options={'synchronize_session': False}))
                session.commit() if factory else session.rollback()
                return observed
        expected = exercise()
        original = app.mapping, app.Customer
        mapping = registry(metadata=app.table.metadata)
        class Customer: pass
        mapping.map_imperatively(Customer, app.table, properties={
            'record': app.table.c.id, 'value': app.table.c.name, 'public': app.table.c.label})
        app.mapping, app.Customer = mapping, Customer
        try:
            run(app); publish(app)
            assert exercise(attach(mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))) == expected
            remove_current(app, keys)
            values = {identity: value for identity, value, _ in snapshot(app)}
            assert values[UUID(int=100)] is None and values[UUID(int=102)] == 'seed'
            if operation == 'UPDATE': assert values[UUID(int=101)] == 'latest named value'
            else: assert UUID(int=101) not in values
        finally:
            app.mapping, app.Customer = original
            mapping.dispose()


def test_reused_named_statement_and_results_keep_their_own_readers():
    with application(rows=3) as app:
        factory = protect(app)
        statement = query(app, 'UPDATE')
        label = statement._returning[0]
        original = label.type, label._element, label.name, label.key
        with factory(tenant_id=TENANT) as session:
            first = session.execute(statement, params={'name': 'first'}, execution_options={'synchronize_session': False})
            second = session.execute(statement, params={'name': 'second'}, execution_options={'synchronize_session': False})
            assert first.scalar_one() == 'first' and second.scalar_one() == 'second'
            assert (label.type, label._element, label.name, label.key) == original
            session.commit()
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement, params={'name': 'third'},
                execution_options={'synchronize_session': False}).scalar_one() == 'third'
            session.rollback()
            assert session.get(app.Customer, UUID(int=101)).name == 'second'
