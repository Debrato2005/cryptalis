"""Final native-driver admission for ordinary flush and protected reads."""
import asyncio
from contextlib import contextmanager
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import DefaultClause, bindparam, event, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, registry

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_migration import application, frames, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


def protect(app):
    run(app); publish(app)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                  keys=keys, deployment=(app.plan, app.pin))


@contextmanager
def raw_calls(monkeypatch, schema, verb, asynchronous=False):
    calls = []
    cursor_class = psycopg.AsyncCursor if asynchronous else psycopg.Cursor
    with monkeypatch.context() as patch:
        for name in ('execute', 'executemany'):
            original = getattr(cursor_class, name)

            def observe(cursor, query, *args, _original=original, _name=name, **kwargs):
                sql = str(query)
                if schema in sql and sql.lstrip().upper().startswith(verb + ' '):
                    calls.append(_name)
                return _original(cursor, query, *args, **kwargs)

            patch.setattr(cursor_class, name, observe)
        yield calls


def first_group(parameters):
    return parameters if isinstance(parameters, dict) else parameters[0]


@pytest.mark.parametrize('count,fault', [
    (1, 'plaintext_inplace'), (1, 'valid_frame'), (1, 'id'),
    (3, 'tenant_id'), (3, 'sql'),
])
def test_late_flush_insert_mutations_refuse_before_raw_driver_and_retry(count, fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        replacement = frames(app, True)[UUID(int=101)]
        before, injected = _snapshot(app), []

        def replace_late(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('INSERT '):
                injected.append(True)
                sent = first_group(parameters)
                if fault == 'plaintext_inplace':
                    assert type(sent['name']) is psycopg.Binary
                    sent['name'].obj = b'PUBLIC_DRIVER_PLAINTEXT'
                elif fault == 'valid_frame':
                    copied = dict(sent, name=psycopg.Binary(replacement))
                    parameters = copied if isinstance(parameters, dict) else [copied, *parameters[1:]]
                elif fault in ('id', 'tenant_id'):
                    sent[fault] = UUID(int=9999)
                else:
                    statement += ' /* public late flush SQL */'
            return statement, parameters

        event.listen(app.runtime, 'before_cursor_execute', replace_late, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as driver:
                with factory(tenant_id=TENANT) as session:
                    session.add_all(app.Customer(id=UUID(int=1000 + index), tenant_id=TENANT,
                        name=f'private flush fixture {index}', label=f'public {index}') for index in range(count))
                    with pytest.raises(CryptoFailure):
                        session.flush()
                    session.rollback()
                assert injected and driver == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', replace_late)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            session.add_all(app.Customer(id=UUID(int=1000 + index), tenant_id=TENANT,
                name=f'private flush fixture {index}', label=f'public {index}') for index in range(count))
            session.commit()
            assert session.scalars(select(app.Customer.id).where(app.Customer.id.in_(
                [UUID(int=1000 + index) for index in range(count)])).order_by(app.Customer.id)).all() == [
                    UUID(int=1000 + index) for index in range(count)]


def test_late_flush_update_payload_mutation_refuses_without_changing_current_value(monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        replacement = frames(app, True)[UUID(int=102)]
        before, injected = _snapshot(app), []

        def replace_late(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('UPDATE '):
                injected.append(True)
                sent = first_group(parameters)
                assert type(sent['name']) is psycopg.Binary
                sent['name'].obj = replacement
            return statement, parameters

        with factory(tenant_id=TENANT) as session:
            current = session.get(app.Customer, UUID(int=101))
            current.name = 'ordinary updated plaintext'
            event.listen(app.runtime, 'before_cursor_execute', replace_late, retval=True)
            try:
                with raw_calls(monkeypatch, app.schema, 'UPDATE') as driver:
                    with pytest.raises(CryptoFailure):
                        session.flush()
                    session.rollback()
                    assert injected and driver == []
            finally:
                event.remove(app.runtime, 'before_cursor_execute', replace_late)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=101)).name == ''
            session.get(app.Customer, UUID(int=101)).name = 'ordinary updated plaintext'
            session.commit()


@pytest.mark.parametrize('fault', ['point', 'equality_term', 'sql', 'sql_subclass'])
def test_late_protected_read_mutation_refuses_before_raw_select_and_observers_still_work(fault, monkeypatch):
    with application(rows=3) as app:
        with Session(app.runtime) as native:
            expected = native.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101)))
        factory = protect(app)
        before, injected, observed = _snapshot(app), [], []
        statement = select(app.Customer.name).where(app.Customer.id == bindparam('point'))
        parameters = {'point': UUID(int=101)}
        if fault == 'equality_term':
            statement = select(app.Customer.name).where(app.Customer.name == bindparam('value'))
            parameters = {'value': ''}

        def observer(connection, cursor, sql, values, context, executemany):
            observed.append(sql)

        class MaskedSQL(str):
            def __eq__(self, other):
                return True
            def __ne__(self, other):
                return False
            __hash__ = str.__hash__

        def replace_late(connection, cursor, sql, values, context, executemany):
            if sql.lstrip().upper().startswith('SELECT ') and app.schema in sql:
                injected.append(True)
                if fault == 'point':
                    values = dict(values, point=UUID(int=102))
                elif fault == 'equality_term':
                    terms = [value for value in values.values() if type(value) is psycopg.Binary]
                    assert len(terms) == 1 and len(terms[0].obj) == 32
                    terms[0].obj = b'\xff' * 32
                elif fault == 'sql_subclass':
                    sql = MaskedSQL(sql + ' /* public masked SQL replacement */')
                else:
                    sql += ' /* public late read SQL */'
            return sql, values

        event.listen(app.runtime, 'before_cursor_execute', observer)
        event.listen(app.runtime, 'before_cursor_execute', replace_late, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'SELECT') as driver:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.scalar(statement, parameters)
                    session.rollback()
                assert injected and observed and driver == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', replace_late)
        try:
            observed.clear()
            with factory(tenant_id=TENANT) as session:
                assert session.scalar(statement, parameters) == expected
            assert observed
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observer)
        assert _snapshot(app) == before


def test_preexisting_cursor_observer_refuses_attachment_before_connection_or_keys(monkeypatch):
    with application(rows=3) as app:
        run(app); publish(app)
        before, connections, resolutions, observed = _snapshot(app), [], [], []
        original_connect = app.runtime.connect

        def connect(*args, **kwargs):
            connections.append(True)
            return original_connect(*args, **kwargs)

        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)

        def observer(*args):
            observed.append(True)

        event.listen(app.runtime, 'before_cursor_execute', observer)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(app.runtime, 'connect', connect)
                with pytest.raises(CryptoFailure):
                    attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                           keys=resolve, deployment=(app.plan, app.pin))
            assert connections == resolutions == observed == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observer)
        assert _snapshot(app) == before
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=101)).name == ''


def test_connection_local_listener_cannot_change_a_point_before_engine_capture(monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        before, injected = _snapshot(app), []

        def replace_local(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('SELECT ') and app.schema in sql:
                injected.append(True)
                parameters = dict(parameters, point=UUID(int=102))
            return sql, parameters

        with factory(tenant_id=TENANT) as session:
            connection = session.connection()
            event.listen(connection, 'before_cursor_execute', replace_local, retval=True)
            try:
                with raw_calls(monkeypatch, app.schema, 'SELECT') as driver:
                    with pytest.raises(CryptoFailure):
                        session.scalar(select(app.Customer.name).where(
                            app.Customer.id == bindparam('point')), {'point': UUID(int=101)})
                    assert injected and driver == []
            finally:
                event.remove(connection, 'before_cursor_execute', replace_local)
            session.rollback()
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=101)).name == ''


def default_label(connection, schema, role):
    connection.exec_driver_sql(f"ALTER TABLE \"{schema}\".customer ALTER COLUMN label SET DEFAULT 'PUBLIC_SERVER_LABEL'")


@contextmanager
def returning_mapping(app):
    previous_mapping, previous_model = app.mapping, app.Customer
    app.table.c.label.server_default = DefaultClause(text("'PUBLIC_SERVER_LABEL'"))
    mapping = registry(metadata=previous_mapping.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, app.table, eager_defaults=True)
    app.mapping, app.Customer = mapping, Customer
    try:
        yield
    finally:
        app.mapping, app.Customer = previous_mapping, previous_model
        mapping.dispose()


def returning_rows(app):
    return [app.Customer(id=UUID(int=1000 + index), tenant_id=TENANT,
                         name=f'page value {index}') for index in range(5)]


def test_native_and_protected_flush_keep_returning_pages_and_observer_listeners():
    with application(rows=3, setup=default_label) as app, returning_mapping(app):
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        native_pages, protected_pages = [], []

        def observe(target):
            def collect(connection, cursor, sql, parameters, context, executemany):
                if sql.lstrip().upper().startswith('INSERT '):
                    target.append('RETURNING' in sql.upper())
            return collect

        native_observer = observe(native_pages)
        event.listen(app.runtime, 'before_cursor_execute', native_observer)
        try:
            with Session(app.runtime) as session:
                rows = returning_rows(app)
                session.add_all(rows)
                session.flush()
                assert [entry.label for entry in rows] == ['PUBLIC_SERVER_LABEL'] * 5
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', native_observer)
        assert native_pages == [True, True, True]
        factory = protect(app)
        protected_observer = observe(protected_pages)
        event.listen(app.runtime, 'before_cursor_execute', protected_observer)
        try:
            with factory(tenant_id=TENANT) as session:
                rows = returning_rows(app)
                session.add_all(rows)
                session.flush()
                assert [entry.label for entry in rows] == ['PUBLIC_SERVER_LABEL'] * 5
                assert [entry.name for entry in rows] == [f'page value {index}' for index in range(5)]
                session.commit()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', protected_observer)
        assert protected_pages == native_pages


def test_late_insertmanyvalues_page_mutation_refuses_before_first_raw_page(monkeypatch):
    with application(rows=3, setup=default_label) as app, returning_mapping(app):
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        factory = protect(app)
        before, injected = _snapshot(app), []
        replacement = frames(app, True)[UUID(int=101)]

        def replace_late(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                assert 'RETURNING' in sql.upper()
                injected.append(True)
                payloads = [value for key, value in parameters.items()
                            if key.startswith('name') and type(value) is psycopg.Binary]
                assert payloads
                payloads[0].obj = replacement
            return sql, parameters

        event.listen(app.runtime, 'before_cursor_execute', replace_late, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as driver:
                with factory(tenant_id=TENANT) as session:
                    session.add_all(returning_rows(app))
                    with pytest.raises(CryptoFailure):
                        session.flush()
                    session.rollback()
                assert injected and driver == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', replace_late)
        assert _snapshot(app) == before


def test_async_ordinary_flush_uses_the_same_final_driver_boundary(monkeypatch):
    with application(rows=3) as app:
        run(app); publish(app)
        before = _snapshot(app)

        async def scenario():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            injected = []

            def replace_late(connection, cursor, sql, parameters, context, executemany):
                if sql.lstrip().upper().startswith('UPDATE '):
                    injected.append(True)
                    sent = first_group(parameters)
                    assert type(sent['name']) is psycopg.Binary
                    sent['name'].obj = b'PUBLIC_ASYNC_PLAINTEXT'
                return sql, parameters

            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                    keys=keys, deployment=(app.plan, app.pin))
                async with factory(tenant_id=TENANT) as session:
                    current = await session.get(app.Customer, UUID(int=101))
                    current.name = 'async ordinary update'
                    event.listen(engine.sync_engine, 'before_cursor_execute', replace_late, retval=True)
                    try:
                        with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as driver:
                            with pytest.raises(CryptoFailure):
                                await session.flush()
                            await session.rollback()
                            assert injected and driver == []
                    finally:
                        event.remove(engine.sync_engine, 'before_cursor_execute', replace_late)
                assert _snapshot(app) == before
                async with factory(tenant_id=TENANT) as session:
                    current = await session.get(app.Customer, UUID(int=101))
                    assert current.name == ''
                    current.name = 'async ordinary update'
                    await session.commit()
            finally:
                await engine.dispose()
        asyncio.run(scenario())


def test_preexisting_dialect_handler_cannot_silently_skip_protected_insert():
    with application(rows=3) as app:
        run(app)
        publish(app)
        before, skipped = _snapshot(app), []

        def skip_insert(cursor, statement, parameters, context):
            if statement.lstrip().upper().startswith('INSERT ') and app.schema in statement:
                skipped.append(True)
                return True

        event.listen(app.runtime.dialect, 'do_execute', skip_insert)
        try:
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                             keys=keys, deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT, expire_on_commit=False) as session:
                session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT,
                                         name='must reach guarded execution'))
                with pytest.raises(CryptoFailure):
                    session.flush()
                session.rollback()
            assert skipped == [True]
        finally:
            event.remove(app.runtime.dialect, 'do_execute', skip_insert)
        assert _snapshot(app) == before

def test_late_cursor_callback_cannot_install_a_dialect_skip_handler():
    with application(rows=3) as app:
        factory = protect(app)
        before, installed, skipped = _snapshot(app), [], []
        dialect_class = type(app.runtime.dialect)

        def skip_insert(cursor, statement, parameters, context):
            if statement.lstrip().upper().startswith('INSERT ') and app.schema in statement:
                skipped.append(True)
                return True

        def install_late(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('INSERT ') and not installed:
                event.listen(dialect_class, 'do_execute', skip_insert)
                installed.append(True)
            return statement, parameters

        event.listen(app.runtime, 'before_cursor_execute', install_late, retval=True)
        try:
            with factory(tenant_id=TENANT, expire_on_commit=False) as session:
                session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT,
                                         name='must not silently disappear'))
                with pytest.raises(CryptoFailure):
                    session.flush()
                session.rollback()
            assert installed and skipped
        finally:
            event.remove(app.runtime, 'before_cursor_execute', install_late)
            if installed:
                event.remove(dialect_class, 'do_execute', skip_insert)
        assert _snapshot(app) == before



def test_binary_object_cannot_mask_replaced_native_buffer(monkeypatch):
    with application(rows=3, unique=False) as app:
        factory = protect(app)
        replacement = frames(app, True)[UUID(int=102)]
        before, injected = _snapshot(app), []

        def replace_late(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                sent = first_group(parameters)
                original = bytes(sent['name'].obj)

                class MaskedBuffer(bytearray):
                    def __bytes__(self):
                        return original

                sent['name'].obj = MaskedBuffer(replacement)
                assert bytes(sent['name'].obj) == original
                assert memoryview(sent['name'].obj).tobytes() == replacement
                injected.append(True)
            return sql, parameters

        event.listen(app.runtime, 'before_cursor_execute', replace_late, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as driver:
                with factory(tenant_id=TENANT) as session:
                    session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT,
                                             name='must retain its own sealed frame'))
                    with pytest.raises(CryptoFailure):
                        session.flush()
                    session.rollback()
                assert injected == [True] and driver == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', replace_late)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT,
                                     name='must retain its own sealed frame'))
            session.commit()
            assert session.get(app.Customer, UUID(int=1000)).name == 'must retain its own sealed frame'
