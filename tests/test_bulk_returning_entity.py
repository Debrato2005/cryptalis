"""ORM INSERT RETURNING must retain native objects, loading and transactions."""
import asyncio
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, inspect, insert, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, deferred

from cryptalis.sqlalchemy import attach
from cryptalis.crypto import AuthenticationFailed, CryptoFailure, FieldDescriptor, open_text, seal_text
from test_bulk_insert import protect
from test_bulk_insert_native import native_application
from test_bulk_returning import fresh_mapping, returning_rows, stored_selection
from test_migration import keys, publish, run, TENANT
from test_driver_event_boundary import raw_calls
from test_rewrap_plan import _snapshot
from test_sqlalchemy_adapter import (app as adapter_app, db, factory as adapter_factory,
                                     TENANT as ADAPTER_TENANT)


def statement(app, projection, ordered):
    model = app.Customer
    columns = {'entity': (model,), 'mixed': (model.name, model, model.label),
               'repeated': (model, model, model.name),
               'labeled': (model.name.label('protected value'), model,
                           model.id.label('record reference'), model.tenant_id.label('tenant reference'))}[projection]
    return insert(model).returning(*columns, sort_by_parameter_order=ordered)


def consume(result, session, model, projection):
    scalar = projection == 'entity'
    names = None if scalar else tuple(result.keys())
    rows = result.all()
    observed, retained = [], []
    for row in rows:
        values = (row,) if scalar else tuple(row)
        entries = []
        for value in values:
            if isinstance(value, model):
                state = inspect(value)
                assert state.persistent and state.session is session
                assert session.identity_map[state.key] is value
                entries.append(('entity', value.id, value.tenant_id, value.name, value.label,
                                tuple(sorted(state.unloaded)), tuple(sorted(state.expired_attributes))))
                retained.append(value)
            else:
                entries.append(('scalar', type(value), value))
        if projection == 'repeated':
            assert row[0] is row[1]
        observed.append(tuple(entries))
    assert len(session.identity_map) == len({value.id for value in retained})
    return names, observed


@pytest.mark.parametrize('projection', ['entity', 'mixed', 'repeated', 'labeled'])
@pytest.mark.parametrize('ordered', [False, True])
@pytest.mark.parametrize('mode,varchar', [('sync', False), ('sync', True), ('async', False), ('async', True)])
def test_entity_returning_matches_native_objects_results_and_committed_reads(mode, varchar, ordered, projection):
    with native_application(varchar) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        rows, original = returning_rows(), deepcopy(returning_rows())

        def sync_observation(factory=None):
            with (Session(app.runtime) if factory is None else factory(tenant_id=TENANT)) as session:
                query = statement(app, projection, ordered)
                result = session.scalars(query, rows) if projection == 'entity' else session.execute(query, rows)
                observed = consume(result, session, app.Customer, projection)
                stored = [tuple(value) for value in session.execute(stored_selection(app))]
                if factory is None:
                    session.rollback()
                else:
                    session.commit()
                    assert [tuple(value) for value in session.execute(stored_selection(app))] == stored
                return observed, stored

        async def async_observation(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                insertmanyvalues_page_size=2,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = (await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin))) if protected else None
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    query = statement(app, projection, ordered)
                    result = (await session.scalars(query, rows) if projection == 'entity' else
                              await session.execute(query, rows))
                    observed = consume(result, session.sync_session, app.Customer, projection)
                    stored = [tuple(value) for value in (await session.execute(stored_selection(app))).all()]
                    if protected:
                        await session.commit()
                        assert [tuple(value) for value in (await session.execute(stored_selection(app))).all()] == stored
                    else:
                        await session.rollback()
                    return observed, stored
            finally:
                await engine.dispose()

        if mode == 'sync':
            expected = sync_observation()
            with fresh_mapping(app):
                actual = sync_observation(protect(app))
        else:
            expected = asyncio.run(async_observation(False))
            with fresh_mapping(app):
                run(app)
                publish(app)
                actual = asyncio.run(async_observation(True))
        assert actual == expected
        assert rows == original


@pytest.mark.parametrize('populate', [False, True])
def test_entity_returning_reuses_loaded_identity_with_native_populate_existing_and_rollback(populate):
    with native_application(False) as app:
        identity = UUID(int=102)

        def scenario(factory=None):
            with (Session(app.runtime) if factory is None else factory(tenant_id=TENANT)) as session:
                model = app.Customer
                previous = session.get(model, identity)
                before = previous.name, previous.label
                session.execute(delete(model).where(model.tenant_id == TENANT, model.id == identity),
                                execution_options={'synchronize_session': False})
                values = [{'id': identity, 'tenant_id': TENANT, 'name': 'updated', 'label': 'new label'}]
                current = session.scalars(insert(model).returning(model), values,
                                         execution_options={'populate_existing': populate}).one()
                assert current is previous
                returned = current.name, current.label
                assert returned == (('updated', 'new label') if populate else before)
                session.expire(current)
                assert (current.name, current.label) == ('updated', 'new label')
                session.rollback()
                assert (current.name, current.label) == before
                assert inspect(current).persistent and len(session.identity_map) == 1
                return returned

        expected = scenario()
        with fresh_mapping(app):
            assert scenario(protect(app)) == expected


@pytest.mark.parametrize('fault', ['columns', 'defaults'])
def test_late_entity_to_same_columns_change_refuses_before_driver(fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        before, changed = _snapshot(app), []

        def change(connection, current, multiparams, params, options):
            if current.is_insert:
                current = (insert(app.Customer).returning(*app.table.c) if fault == 'columns' else
                           insert(app.Customer).return_defaults(*app.table.primary_key,
                                                                supplemental_cols=list(app.table.c)))
                changed.append(True)
            return current, multiparams, params

        event.listen(app.runtime, 'before_execute', change, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(insert(app.Customer).returning(app.Customer), returning_rows())
                    session.rollback()
                assert changed and sent == []
        finally:
            event.remove(app.runtime, 'before_execute', change)
        assert _snapshot(app) == before


def test_entity_second_protected_field_requires_its_own_prepared_frame(adapter_app, monkeypatch):
    app = adapter_app
    factory = adapter_factory(app, True)
    identity = UUID(int=1000)
    field = next(field for field in json.loads(app.plan.lock_bytes)['models'][0]['fields']
                 if field['column'] == 'secret')
    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
    material = app.rings[ADAPTER_TENANT].prepare()
    alternate = seal_text('valid but never inserted', descriptor, ADAPTER_TENANT, identity, material)
    assert open_text(alternate, descriptor, ADAPTER_TENANT, identity, material) == 'valid but never inserted'
    native_fetchall, armed, changed = psycopg.Cursor.fetchall, [], []

    def arm(connection, cursor, sql, parameters, context, executemany):
        if sql.lstrip().upper().startswith('INSERT '):
            armed.append(True)

    def replace_second_field(cursor):
        rows = native_fetchall(cursor)
        if armed and not changed and rows:
            index = next(index for index, column in enumerate(cursor.description) if column.name == 'secret')
            values = list(rows[0])
            packed = list(values[index])
            assert packed[1] == str(identity) and packed[0] != alternate.hex()
            packed[0] = alternate.hex()
            values[index] = packed
            rows[0] = tuple(values)
            changed.append(True)
        return rows

    event.listen(app.engine, 'after_cursor_execute', arm)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(psycopg.Cursor, 'fetchall', replace_second_field)
            with factory(tenant_id=ADAPTER_TENANT) as session:
                with pytest.raises(AuthenticationFailed):
                    session.execute(insert(app.Customer).returning(app.Customer),
                        [{'id': identity, 'tenant_id': ADAPTER_TENANT, 'name': 'public',
                          'note': 'first field', 'secret': 'actual second field', 'rank': 1}])
                assert len(session.identity_map) == 0
                session.rollback()
        assert changed == [True]
    finally:
        event.remove(app.engine, 'after_cursor_execute', arm)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        assert session.scalars(select(app.Customer.id).where(app.Customer.tenant_id == ADAPTER_TENANT)).all() == []


@pytest.mark.parametrize('fault', ['id', 'tenant', 'swap_companions'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('projection', ['entity', 'labeled_columns', 'labeled_entity'])
def test_entity_identity_columns_must_match_authenticated_frame_context(fault, mode, projection, monkeypatch):
    with native_application(False) as app:
        if mode == 'sync':
            factory = protect(app)
        else:
            run(app)
            publish(app)
        before, changed = _snapshot(app), []

        def query():
            model = app.Customer
            columns = (model.name.label('returned_name'), model.id.label('returned_id'),
                       model.tenant_id.label('returned_tenant_id'))
            if projection == 'entity':
                columns = (model,)
            elif projection == 'labeled_entity':
                columns = (model, *columns)
            return insert(model).returning(*columns)

        def change_identity(cursor, rows):
            if rows and not changed and cursor.statusmessage.startswith('INSERT '):
                field = {'id': 'id', 'tenant': 'tenant_id', 'swap_companions': 'name'}[fault]
                if projection != 'entity':
                    field = 'returned_' + field
                index = next(index for index, column in enumerate(cursor.description) if column.name == field)
                first = list(rows[0])
                if fault == 'swap_companions':
                    assert len(rows) == 2 and type(first[index]) is list
                    second = list(rows[1])
                    first[index], second[index] = second[index], first[index]
                    rows[1] = tuple(second)
                else:
                    first[index] = UUID(int=9999)
                rows[0] = tuple(first)
                changed.append(True)
            return rows

        inputs = [{'id': UUID(int=1000), 'tenant_id': TENANT, 'name': 'first', 'label': 'one'},
                  {'id': UUID(int=1001), 'tenant_id': TENANT, 'name': 'second', 'label': 'two'}]
        if mode == 'sync':
            native_fetchall = psycopg.Cursor.fetchall
            def fetchall(cursor):
                return change_identity(cursor, native_fetchall(cursor))
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, 'fetchall', fetchall)
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(AuthenticationFailed):
                        session.execute(query(), inputs)
                    assert len(session.identity_map) == 0
                    session.rollback()
        else:
            native_fetchall = psycopg.AsyncCursor.fetchall
            async def fetchall(cursor):
                return change_identity(cursor, await native_fetchall(cursor))
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                           deployment=(app.plan, app.pin))
                    with monkeypatch.context() as patch:
                        patch.setattr(psycopg.AsyncCursor, 'fetchall', fetchall)
                        async with factory(tenant_id=TENANT) as session:
                            with pytest.raises(AuthenticationFailed):
                                await session.execute(query(), inputs)
                            assert len(session.identity_map) == 0
                            await session.rollback()
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert changed == [True]
        assert _snapshot(app) == before


@pytest.mark.parametrize('method', ['fetchone', 'fetchmany', 'iteration'])
def test_returning_identity_check_precedes_each_native_cursor_fetch_route(method, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        before, changed = _snapshot(app), []
        name = '__iter__' if method == 'iteration' else method
        native = getattr(psycopg.Cursor, name)
        native_fetchone = psycopg.Cursor.fetchone

        def change(cursor, row):
            index = next(index for index, column in enumerate(cursor.description) if column.name == 'id')
            values = list(row)
            values[index] = UUID(int=9999)
            changed.append(True)
            return tuple(values)

        def fetch(cursor, *args, **kwargs):
            values = native(cursor, *args, **kwargs)
            if cursor.statusmessage.startswith('INSERT '):
                if method == 'fetchone':
                    return change(cursor, values) if values is not None else None
                return [change(cursor, row) for row in values]
            return values

        def iterate(cursor):
            while (row := native_fetchone(cursor)) is not None:
                yield change(cursor, row)

        def observe(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                if method == 'iteration':
                    next(iter(cursor))
                else:
                    getattr(cursor, method)()

        event.listen(app.runtime, 'after_cursor_execute', observe)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, name, iterate if method == 'iteration' else fetch)
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(AuthenticationFailed):
                        session.execute(insert(app.Customer).returning(app.Customer),
                            [{'id': UUID(int=1000), 'tenant_id': TENANT, 'name': 'first', 'label': 'one'}])
                    session.rollback()
            assert changed
        finally:
            event.remove(app.runtime, 'after_cursor_execute', observe)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['healthy', 'forged_id'])
def test_deferred_protected_field_cannot_load_through_a_forged_returned_identity(fault, monkeypatch):
    with native_application(False) as app:
        inputs = [{'id': UUID(int=1000), 'tenant_id': TENANT, 'name': 'new value', 'label': 'public'}]
        with fresh_mapping(app, properties={'name': deferred(app.table.c.name)}):
            with Session(app.runtime) as session:
                value = session.scalars(insert(app.Customer).returning(app.Customer), inputs).one()
                assert inspect(value).unloaded == {'name'}
                expected = value.id, value.name
                session.rollback()
        with fresh_mapping(app, properties={'name': deferred(app.table.c.name)}):
            factory = protect(app)
            before, changed = _snapshot(app), []
            native_fetchall = psycopg.Cursor.fetchall
            def fetchall(cursor):
                rows = native_fetchall(cursor)
                if rows and not changed and cursor.statusmessage.startswith('INSERT '):
                    assert all(column.name != 'name' for column in cursor.description)
                    index = next(index for index, column in enumerate(cursor.description) if column.name == 'id')
                    values = list(rows[0])
                    values[index] = UUID(int=102)  # Existing row outside this INSERT.
                    rows[0] = tuple(values)
                    changed.append(True)
                return rows
            with monkeypatch.context() as patch:
                if fault == 'forged_id':
                    patch.setattr(psycopg.Cursor, 'fetchall', fetchall)
                with factory(tenant_id=TENANT) as session:
                    if fault == 'forged_id':
                        with pytest.raises(AuthenticationFailed):
                            session.execute(insert(app.Customer).returning(app.Customer), inputs)
                        assert len(session.identity_map) == 0
                    else:
                        value = session.scalars(insert(app.Customer).returning(app.Customer), inputs).one()
                        assert inspect(value).unloaded == {'name'}
                        assert (value.id, value.name) == expected
                    session.rollback()
            assert bool(changed) is (fault == 'forged_id')
            assert _snapshot(app) == before
