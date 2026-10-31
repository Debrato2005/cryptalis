"""Literal UPDATE admission, provider mutation and native statement reuse."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import bindparam, event, literal, null, Text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.util import immutabledict

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_point_update_returning_boundary import protect
from test_point_update_rows import query
from test_rewrap_plan import _snapshot


@pytest.mark.parametrize('fault', ['literal', 'null_node', 'bind', 'sql_expression', 'ordered',
    'identity', 'tenant', 'unknown', 'duplicate', 'column_dispatch', 'column_name',
    'bind_dispatch', 'bind_type', 'bind_processor', 'callable', 'required',
    'expanding', 'literal_execute', 'empty', 'external'])
def test_unsupported_embedded_inputs_refuse_before_keys_and_driver(fault, monkeypatch):
    with application(rows=3) as app:
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = protect(app, resolve)
        base = query(app, False, UUID(int=101))
        statement = base.values(name='PUBLIC captured')
        target, bind = next(iter(statement._values.items()))
        parameters = None
        if fault == 'literal': statement = base.values(name=literal('PUBLIC value'))
        elif fault == 'null_node': statement = base.values(name=null())
        elif fault == 'bind': statement = base.values(name=bindparam('value', 'PUBLIC value'))
        elif fault == 'sql_expression': statement = base.values(name=app.Customer.label)
        elif fault == 'ordered': statement = base.ordered_values((app.Customer.name, 'PUBLIC value'))
        elif fault == 'identity': statement = statement.values(id=UUID(int=102))
        elif fault == 'tenant': statement = statement.values(tenant_id=TENANT)
        elif fault == 'unknown': statement = statement.values(unmapped='PUBLIC value')
        elif fault == 'duplicate': statement._values = immutabledict({target: bind, 'name': bind})
        elif fault == 'column_dispatch': target._compiler_dispatch = lambda *a, **k: 'PUBLIC custom'
        elif fault == 'column_name': target.name = 'label'
        elif fault == 'bind_dispatch': bind._compiler_dispatch = lambda *a, **k: 'PUBLIC custom'
        elif fault == 'bind_type': bind.type = Text()
        elif fault == 'bind_processor':
            # Each statement must retain its own type; never alter shared NULLTYPE.
            from sqlalchemy.types import NullType
            bind.type = NullType()
            bind.type.bind_processor = lambda dialect: lambda value: value
        elif fault == 'callable': bind.callable = lambda: 'PUBLIC callback'
        elif fault == 'required': bind.required = True
        elif fault == 'expanding': bind.expanding = True
        elif fault == 'literal_execute': bind.literal_execute = True
        elif fault == 'empty': statement = base.values()
        elif fault == 'external': parameters = {'name': 'PUBLIC external'}
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            calls.clear()
            with pytest.raises(CryptoFailure):
                session.execute(statement, parameters, execution_options={'synchronize_session': False})
            assert calls == sent == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['value', 'target', 'identity', 'returning', 'dispatch', 'callable'])
@pytest.mark.parametrize('asynchronous', [False, True])
def test_provider_cannot_change_original_literal_request(fault, asynchronous, monkeypatch):
    with application(rows=3) as app:
        armed, changed = [], []
        def resolve(tenant):
            if armed:
                armed.clear()
                target, bind = next(iter(statement._values.items()))
                if fault == 'value': bind.value = 'PUBLIC changed'
                elif fault == 'target': statement._values = immutabledict({app.Customer.label.__clause_element__(): bind})
                elif fault == 'identity': statement._where_criteria = query(app, False, UUID(int=102))._where_criteria
                elif fault == 'returning': statement._returning = (app.Customer.label.__clause_element__(),)
                elif fault == 'dispatch': bind._compiler_dispatch = lambda *a, **k: 'PUBLIC changed'
                else: bind.callable = lambda: 'PUBLIC changed'
                changed.append(True)
            return keys(tenant)
        run(app); publish(app)
        statement = query(app, False, UUID(int=101)).values(name='PUBLIC captured').returning(app.Customer.name)
        before = _snapshot(app)
        if not asynchronous:
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                armed.append(True)
                with pytest.raises(CryptoFailure):
                    session.execute(statement, execution_options={'synchronize_session': False})
                assert changed == [True] and armed == sent == []
                session.rollback()
        else:
            async def exercise():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=resolve,
                                           deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as sent:
                        async with factory(tenant_id=TENANT) as session:
                            armed.append(True)
                            with pytest.raises(CryptoFailure):
                                await session.execute(statement, execution_options={'synchronize_session': False})
                            assert changed == [True] and armed == sent == []
                            await session.rollback()
                finally:
                    await engine.dispose()
            asyncio.run(exercise())
        assert _snapshot(app) == before


@pytest.mark.parametrize('form', ['keywords', 'mapped_columns', 'physical_columns'])
def test_native_literal_statement_reuse_result_keys_and_driver_plaintext_boundary(form):
    with application(rows=3) as app:
        def exercise(factory=None):
            value = 'PRIVATE embedded Unicode 雪😀'
            output = app.Customer.name.label('display_name')
            statement = query(app, False, UUID(int=101)).returning(output, app.Customer.label)
            if form == 'keywords': statement = statement.values(name=value, label='public')
            elif form == 'mapped_columns': statement = statement.values({app.Customer.name: value, app.Customer.label: 'public'})
            else: statement = statement.values({app.table.c.name: value, app.table.c.label: 'public'})
            original = statement._values
            captured = [(target, bind, bind.value, bind.type) for target, bind in original.items()]
            sent = []
            def observe(connection, cursor, sql, parameters, context, many):
                if sql.lstrip().upper().startswith('UPDATE '):
                    sent.append((sql, repr(parameters)))
            event.listen(app.runtime, 'before_cursor_execute', observe)
            try:
                with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                    first = session.execute(statement, execution_options={'synchronize_session': False})
                    second = session.execute(statement.values(name='second'), execution_options={'synchronize_session': False})
                    row = first.one()
                    assert row._mapping[output] == row._mapping['display_name'] == value
                    assert row._mapping[app.Customer.label] == 'public'
                    assert second.one()._mapping[output] == 'second'
                    assert session.execute(statement, execution_options={'synchronize_session': False}).one()[0] == value
                    assert statement._values is original
                    assert [(target, bind, bind.value, bind.type) for target, bind in original.items()] == captured
                    assert all(value not in sql for sql, _ in sent)
                    assert (value in repr(sent)) is (factory is None)
                    assert len(sent) == 3
                    session.rollback()
            finally:
                event.remove(app.runtime, 'before_cursor_execute', observe)
        exercise()
        with fresh_mapping(app):
            run(app); publish(app)
            exercise(attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                            deployment=(app.plan, app.pin)))


@pytest.mark.parametrize('operation', ['INSERT', 'UPDATE', 'DELETE'])
@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_original_returning_labels_are_native_result_keys(operation, mode):
    from sqlalchemy import delete, insert
    from sqlalchemy.ext.asyncio import AsyncSession
    with application(rows=3) as app:
        options = {} if operation == 'INSERT' else {'synchronize_session': False}
        def inputs():
            protected = app.Customer.name.label('display_name')
            public = app.Customer.label.label('public_name')
            if operation == 'INSERT':
                statement = insert(app.Customer)
                params = [dict(id=UUID(int=1000), tenant_id=TENANT, name='PRIVATE result key', label='public')]
            elif operation == 'UPDATE':
                statement = query(app, False, UUID(int=101))
                params = dict(name='PRIVATE result key', label='public')
            else:
                statement = delete(app.Customer).where(app.Customer.id == UUID(int=101), app.Customer.tenant_id == TENANT)
                params = None
            return statement.returning(protected, public), params, protected, public
        def consume(result, protected, public):
            row = result.one()
            assert row._mapping[protected] == row[0]
            assert row._mapping[public] == row[1]
            return tuple(result.keys()), tuple(row), tuple(type(value) for value in row)
        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            with (factory(tenant_id=TENANT) if factory else native(app.runtime)) as session:
                statement, params, protected, public = inputs()
                execute = session.exec if mode == 'sqlmodel' else session.execute
                original = protected.type, protected._element, public.type, public._element
                result = execute(statement, params=params, execution_options=options)
                observed = consume(result, protected, public)
                assert (protected.type, protected._element, public.type, public._element) == original
                session.rollback()
                return observed
        async def asynchronous(protected_run):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected_run else None
                async with (factory(tenant_id=TENANT) if factory else native(engine)) as session:
                    statement, params, protected, public = inputs()
                    execute = session.exec if mode == 'sqlmodel_async' else session.execute
                    original = protected.type, protected._element, public.type, public._element
                    result = await execute(statement, params=params, execution_options=options)
                    observed = consume(result, protected, public)
                    assert (protected.type, protected._element, public.type, public._element) == original
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
