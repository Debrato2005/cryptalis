"""Native named INSERT results retain page-bound prepared-frame authentication."""
import asyncio
from copy import deepcopy
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Text, event, insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import quoted_name

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import native_application, row
from test_bulk_returning import fresh_mapping, returning_rows, stored_selection
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_point_returning_labels import consume, LABELS
from test_point_update_returning_more import CASES
from test_rewrap_plan import _snapshot


def statement(app, ordered=False, name='display_name', public='public_value'):
    return insert(app.Customer).returning(app.Customer.name.label(name),
        app.Customer.label.label(public), sort_by_parameter_order=ordered)


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
@pytest.mark.parametrize('ordered', [False, True])
def test_named_bulk_results_match_native_paging_nulls_keys_and_transactions(mode, ordered):
    with native_application(True) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        rows = returning_rows()
        original = deepcopy(rows)

        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            observed = []
            for name, public in LABELS:
                with (factory(tenant_id=TENANT) if factory else native(app.runtime)) as session:
                    execute = session.exec if mode == 'sqlmodel' else session.execute
                    saved = session.begin_nested()
                    result = execute(statement(app, ordered, name, public), params=rows,
                        execution_options={'render_nulls': ordered})
                    observed.append(consume(result))
                    observed.append([tuple(value) for value in execute(stored_selection(app)).all()])
                    assert not session.identity_map
                    saved.rollback()
                    assert execute(stored_selection(app)).all() == []
                    session.rollback()
            return observed

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                insertmanyvalues_page_size=2, async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                observed = []
                for name, public in LABELS:
                    async with (factory(tenant_id=TENANT) if protected else native(engine)) as session:
                        execute = session.exec if mode == 'sqlmodel_async' else session.execute
                        saved = await session.begin_nested()
                        result = await execute(statement(app, ordered, name, public), params=rows,
                            execution_options={'render_nulls': ordered})
                        observed.append(consume(result))
                        observed.append([tuple(value) for value in (await execute(stored_selection(app))).all()])
                        assert not session.identity_map
                        await saved.rollback()
                        assert (await execute(stored_selection(app))).all() == []
                        await session.rollback()
                return observed
            finally:
                await engine.dispose()

        expected = asyncio.run(asynchronous(False)) if 'async' in mode else sync()
        with fresh_mapping(app):
            run(app); publish(app)
            if 'async' in mode:
                observed = asyncio.run(asynchronous(True))
            else:
                selected = attach
                if mode == 'sqlmodel':
                    from cryptalis.sqlmodel import attach as selected
                observed = sync(selected(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)))
            assert observed == expected
        assert rows == original


@pytest.mark.parametrize('dtype,value,stored', CASES)
def test_named_insert_preserves_native_supported_types(dtype, value, stored):
    with application(rows=2, value_type=dtype, protected_values=(None, None), queries=[]) as app:
        rows = [row(1000, value), row(1001, None)]
        def exercise(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                result = consume(session.execute(statement(app, True), rows,
                    execution_options={'render_nulls': True}))
                assert result[1] == [(stored, None), (None, None)]
                assert result[2][0][0] is type(stored)
                session.rollback()
                return result
        expected = exercise()
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))
            assert exercise(factory) == expected


@pytest.mark.parametrize('fault', ['type', 'dispatch', 'name', 'key', 'anonymous', 'missing_name', 'unquoted_sql'])
def test_forged_insert_label_refuses_before_keys_or_driver(fault, monkeypatch):
    with native_application(False) as app:
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        selected = statement(app, name=None if fault == 'anonymous' else 'display_name')
        label = selected._returning[0]
        if fault == 'type': label.type = Text()
        if fault == 'dispatch': label._compiler_dispatch = lambda *a, **k: 'PRIVATE_DISPATCH'
        if fault == 'name': label.name = 'PRIVATE\x00NAME'
        if fault == 'key': label.key = 'PRIVATE_CHANGED_KEY'
        if fault == 'missing_name': label.name = label.key = None
        if fault == 'unquoted_sql': label.name = label.key = quoted_name('display_name, 1', False)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
            calls.clear()
            with pytest.raises(CryptoFailure):
                session.execute(selected, [row(1000, 'new')])
            assert calls == sent == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['name', 'element', 'type'])
@pytest.mark.parametrize('timing', ['provider', 'before_execute', 'before_cursor_execute'])
def test_callbacks_cannot_change_captured_insert_label(fault, timing, monkeypatch):
    with native_application(False) as app:
        armed, mutations = [], []
        def mutate(selected):
            label = selected._returning[0]
            if fault == 'name': label.name = label.key = 'changed_name'
            if fault == 'element': label._element = app.Customer.label.__clause_element__()
            if fault == 'type': label.type = Text()
            mutations.append(True)
        def resolve(tenant):
            if armed:
                armed.clear()
                mutate(selected)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        selected = statement(app)
        def before_execute(connection, clause, multiparams, params, execution_options):
            if getattr(clause, 'is_insert', False): mutate(clause)
        def before_cursor_execute(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('INSERT '): mutate(context.compiled.statement)
        observer = before_execute if timing == 'before_execute' else before_cursor_execute
        before = _snapshot(app)
        if timing != 'provider': event.listen(app.runtime, timing, observer)
        try:
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                if timing == 'provider': armed.append(True)
                with pytest.raises(CryptoFailure):
                    session.execute(selected, [row(1000, 'new')])
                assert mutations == [True] and armed == sent == []
                session.rollback()
        finally:
            if timing != 'provider': event.remove(app.runtime, timing, observer)
        assert _snapshot(app) == before


def test_mixed_entity_named_output_and_reused_statement_keep_native_identity_and_readers():
    with native_application(False) as app:
        factory = protect(app)
        selected = insert(app.Customer).returning(app.Customer, app.Customer.name.label('display_name'))
        label = selected._returning[1]
        original = label.name, label.key, label.type, label._element
        with factory(tenant_id=TENANT) as session:
            first = session.execute(selected, [row(1000, 'first')])
            second = session.execute(selected, [row(1001, 'second')])
            assert tuple(first.keys()) == tuple(second.keys()) == ('Customer', 'display_name')
            for result, identity, value in ((first, 1000, 'first'), (second, 1001, 'second')):
                entity, named = result.one()
                assert entity is session.get(app.Customer, UUID(int=identity))
                assert entity.name == named == value
            assert (label.name, label.key, label.type, label._element) == original
            session.rollback()
