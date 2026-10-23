"""Scoped mapped TEXT dictionary UPDATE compared with native PostgreSQL."""
import asyncio
from copy import deepcopy
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Text, event, select, update
from sqlalchemy.exc import IntegrityError, PendingRollbackError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import assert_aborted, native_application
from test_bulk_returning import fresh_mapping
from test_bulk_update_native import (changes, empty_result, execute, add_foreign,
                                     FOREIGN, MISSING)
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot
from test_sqlalchemy_adapter import app as adapter_app, db


def selection(app):
    return select(app.Customer.id, app.Customer.tenant_id, app.Customer.name,
                  app.Customer.label).where(app.Customer.id.in_(
                      [UUID(int=value) for value in (100, 101, 102)])).order_by(app.Customer.id)


@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('heterogeneous', [False, True])
def test_scoped_bulk_update_preserves_native_values_order_inputs_and_result(mode, heterogeneous):
    with native_application(False) as app:
        rows = ([changes(100, name='first', label='PUBLIC_LABEL'), changes(101, label=None),
                 changes(100, name='e\u0301😀界'), changes(102, name=None)] if heterogeneous else
                [changes(100, name='first'), changes(101, name=None), changes(100, name='e\u0301😀界')])
        original, parameters = deepcopy(rows), []

        def collect(connection, cursor, sql, values, context, executemany):
            if sql.lstrip().upper().startswith('UPDATE '):
                parameters.append(repr(values))

        event.listen(app.runtime, 'before_cursor_execute', collect)
        try:
            with Session(app.runtime) as session:
                empty_result(execute(session, app, rows))
                expected = session.execute(selection(app)).all()
                assert len(session.identity_map) == 0
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', collect)
        assert 'e\u0301😀界' in repr(parameters)
        parameters.clear()
        with fresh_mapping(app):
            if mode == 'sync':
                factory = protect(app)
                event.listen(app.runtime, 'before_cursor_execute', collect)
                try:
                    with factory(tenant_id=TENANT) as session:
                        empty_result(execute(session, app, rows))
                        assert session.execute(selection(app)).all() == expected
                        assert len(session.identity_map) == 0
                        session.commit()
                finally:
                    event.remove(app.runtime, 'before_cursor_execute', collect)
            else:
                run(app)
                publish(app)

                async def scenario():
                    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                        async_creator=lambda: psycopg.AsyncConnection.connect(
                            os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                    try:
                        factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                               keys=keys, deployment=(app.plan, app.pin))
                        event.listen(engine.sync_engine, 'before_cursor_execute', collect)
                        try:
                            async with factory(tenant_id=TENANT) as session:
                                result = await session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                                    rows, execution_options={'synchronize_session': False})
                                empty_result(result)
                                assert (await session.execute(selection(app))).all() == expected
                                assert len(session.identity_map) == 0
                                await session.commit()
                        finally:
                            event.remove(engine.sync_engine, 'before_cursor_execute', collect)
                    finally:
                        await engine.dispose()
                asyncio.run(scenario())
        assert rows == original and parameters
        assert 'e\u0301😀界' not in repr(parameters) and 'first' not in repr(parameters)


def test_scoped_bulk_update_leaves_loaded_state_stale_until_native_refresh():
    with native_application(False) as app:
        rows = [changes(100, name='updated')]

        def scenario(session, commit):
            loaded = session.get(app.Customer, UUID(int=100))
            assert loaded.name is None
            empty_result(execute(session, app, rows))
            assert loaded.name is None and len(session.identity_map) == 1
            session.refresh(loaded)
            assert loaded.name == 'updated'
            session.commit() if commit else session.rollback()

        with Session(app.runtime) as session:
            scenario(session, False)
        with fresh_mapping(app):
            factory = protect(app)
            with factory(tenant_id=TENANT) as session:
                scenario(session, True)


def test_scoped_bulk_update_missing_and_foreign_ids_remain_native_zero_matches():
    def foreign_seed(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
            (FOREIGN, UUID(int=999), 'else', 'foreign'))

    with application(rows=3, setup=foreign_seed) as app:
        rows = [changes(100, name='own'), {'id': MISSING, 'name': 'missing'},
                {'id': FOREIGN, 'name': 'must not move foreign'}]
        original = deepcopy(rows)
        with Session(app.runtime) as session:
            empty_result(execute(session, app, rows))
            expected = session.execute(selection(app)).all()
            session.rollback()
        with fresh_mapping(app):
            factory = protect(app)
            foreign_frame = _snapshot(app)[1][-1]
            with factory(tenant_id=TENANT) as session:
                empty_result(execute(session, app, rows))
                assert session.execute(selection(app)).all() == expected
                session.commit()
            assert _snapshot(app)[1][-1] == foreign_frame
            # A later tenant's legitimate UPDATE must not inherit the first
            # tenant's cached literal, sealed registry, or compiler context.
            with factory(tenant_id=UUID(int=999)) as session:
                empty_result(session.execute(update(app.Customer).where(app.Customer.tenant_id == UUID(int=999)),
                    [{'id': FOREIGN, 'name': 'foreign own update'}], execution_options={'synchronize_session': False}))
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == FOREIGN)) == 'foreign own update'
                session.commit()
        assert rows == original


def test_scoped_bulk_update_savepoint_failure_keeps_outer_work_and_recovers():
    with native_application(False) as app:
        rows = [changes(101, name='dupe', label='inner prefix'), changes(102, name='dupe')]
        original = deepcopy(rows)

        def scenario(session, commit):
            empty_result(execute(session, app, [changes(100, label='outer')]))
            savepoint = session.begin_nested()
            with pytest.raises(IntegrityError) as failed:
                execute(session, app, rows)
            assert failed.value.orig.sqlstate == '23505'
            assert_aborted(session)
            savepoint.rollback()
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == ''
            empty_result(execute(session, app, [changes(101, name='retry')]))
            result = session.execute(selection(app)).all()
            session.commit() if commit else session.rollback()
            return result

        with Session(app.runtime) as session:
            expected = scenario(session, False)
        with fresh_mapping(app):
            factory = protect(app)
            with factory(tenant_id=TENANT) as session:
                assert scenario(session, True) == expected
        assert rows == original


def test_scoped_bulk_update_preserves_autoflush_and_failed_flush_order():
    with native_application(False) as app:
        def scenario(session):
            loaded = session.get(app.Customer, UUID(int=101))
            loaded.label = 'autoflush first'
            empty_result(execute(session, app, [changes(100, name='bulk next')]))
            assert session.scalar(select(app.Customer.label).where(app.Customer.id == UUID(int=101))) == 'autoflush first'
            session.rollback()
            session.add(app.Customer(id=UUID(int=100), tenant_id=TENANT, name='duplicate'))
            with pytest.raises(IntegrityError):
                execute(session, app, [changes(101, name='must not execute')])
            assert session.is_active is False
            with pytest.raises(PendingRollbackError):
                session.execute(select(app.Customer.id))
            session.rollback()

        with Session(app.runtime) as session:
            scenario(session)
        with fresh_mapping(app):
            factory = protect(app)
            before = _snapshot(app)
            with factory(tenant_id=TENANT) as session:
                scenario(session)
            assert _snapshot(app) == before


def test_scoped_bulk_update_keeps_native_public_bind_processing():
    class PublicUpper(TypeDecorator):
        impl = Text
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return None if value is None else value.upper()

    with native_application(False) as app:
        app.table.c.label.type = PublicUpper()
        rows = [changes(100, name='protected text', label='public Mixed Case')]
        original = deepcopy(rows)
        with Session(app.runtime) as session:
            empty_result(execute(session, app, rows))
            expected = session.execute(selection(app)).all()
            assert expected[0].label == 'PUBLIC MIXED CASE'
            session.rollback()
        with fresh_mapping(app):
            factory = protect(app)
            with factory(tenant_id=TENANT) as session:
                empty_result(execute(session, app, rows))
                assert session.execute(selection(app)).all() == expected
                session.commit()
        assert rows == original


@pytest.mark.parametrize('adapter_app', [{'bigint': False}, {'bigint': True}], indirect=True)
def test_scoped_bulk_update_preserves_multiple_fields_and_signed_identity_context(adapter_app):
    from sqlalchemy.orm import registry
    from test_sqlalchemy_adapter import factory as adapter_factory
    app = adapter_app
    bigint = app.Customer.__table__.c.id.type.python_type is int
    identities = [-2**63, -1, 0, 2**63 - 1] if bigint else [UUID(int=value) for value in range(4)]
    tenant = next(iter(app.rings))
    rows = [{'id': identity, 'note': ['雪😀', None, '', 'e\u0301'][index],
             'secret': ['a', '', None, 'd'][index]} for index, identity in enumerate(identities)]
    rows.append({'id': identities[0], 'note': 'latest occurrence', 'rank': 8})
    original = deepcopy(rows)

    def scenario(factory):
        C = app.Customer
        with factory(tenant_id=tenant) as session:
            session.add_all([C(id=identity, tenant_id=tenant, name=f'public name {index}', rank=index)
                             for index, identity in enumerate(identities)])
            session.flush()
            empty_result(session.execute(update(C).where(C.tenant_id == tenant), rows,
                         execution_options={'synchronize_session': False}))
            assert len(session.identity_map) == 0
            result = session.execute(select(C.id, C.note, C.secret, C.rank).where(
                C.id.in_(identities)).order_by(C.id)).all()
            session.rollback()
            return result

    expected = scenario(adapter_factory(app, False))
    previous_mapping, previous_model = app.mapping, app.Customer
    mapping = registry(metadata=previous_mapping.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, previous_model.__table__)
    app.mapping, app.Customer = mapping, Customer
    try:
        assert scenario(adapter_factory(app, True)) == expected
    finally:
        app.mapping, app.Customer = previous_mapping, previous_model
        mapping.dispose()
    assert rows == original
