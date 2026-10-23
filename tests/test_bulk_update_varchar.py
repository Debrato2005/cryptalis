"""Scoped VARCHAR dictionary UPDATE compared with native PostgreSQL behavior."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import BigInteger, Column, Index, String, event, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError, PendingRollbackError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter

from cryptalis.crypto import CryptoFailure, KeyUnavailable, Keyring
from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import assert_aborted, native_application
from test_bulk_returning import fresh_mapping
from test_bulk_update_native import FOREIGN, MISSING, changes, empty_result, execute
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT, PROVIDER, PublicFixtureProvider, DOMAIN, TABLE_ID, FIELD_ID, WriterInventory, Writer, SearchReview
from test_rewrap_plan import _snapshot


def selection(app):
    return select(app.Customer.id, app.Customer.name, app.Customer.label).where(
        app.Customer.id.in_([UUID(int=i) for i in (100, 101, 102)])).order_by(app.Customer.id)


@contextmanager
def plan_mode(engine, mode):
    def configure(driver, record):
        driver.prepare_threshold = 5 if mode == 'auto' else 0
        with driver.cursor() as cursor:
            cursor.execute(f'SET plan_cache_mode = {mode}')
        driver.commit()
    engine.dispose()
    event.listen(engine, 'connect', configure)
    try:
        yield
    finally:
        event.remove(engine, 'connect', configure)
        engine.dispose()


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_varchar_updates_preserve_unicode_spaces_null_omission_repeated_ids_and_results(mode):
    with native_application(True) as app:
        rows = [changes(100, name='good', label='public prefix'),
                changes(101, name='ab    '), changes(100, name='e\u0301😀界'),
                changes(101, label='public label only'), changes(102, name=None)]
        original = deepcopy(rows)
        with Session(app.runtime) as native:
            loaded = native.get(app.Customer, UUID(int=100))
            empty_result(execute(native, app, rows))
            assert loaded.name is None
            native.refresh(loaded)
            assert loaded.name == 'e\u0301😀界'
            expected = native.execute(selection(app)).all()
            native.rollback()
        parameters = []
        def observe(connection, cursor, sql, values, context, executemany):
            if sql.lstrip().upper().startswith('UPDATE '):
                parameters.append(repr(values))
        with fresh_mapping(app):
            if mode == 'sync':
                factory = protect(app)
                event.listen(app.runtime, 'before_cursor_execute', observe)
                try:
                    with factory(tenant_id=TENANT) as session:
                        loaded = session.get(app.Customer, UUID(int=100))
                        empty_result(execute(session, app, rows))
                        assert loaded.name is None and len(session.identity_map) == 1
                        session.refresh(loaded)
                        assert loaded.name == 'e\u0301😀界'
                        assert session.execute(selection(app)).all() == expected
                        session.commit()
                finally:
                    event.remove(app.runtime, 'before_cursor_execute', observe)
            else:
                run(app); publish(app)
                async def scenario():
                    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                        async_creator=lambda: psycopg.AsyncConnection.connect(
                            os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                    try:
                        factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                            keys=keys, deployment=(app.plan, app.pin))
                        event.listen(engine.sync_engine, 'before_cursor_execute', observe)
                        async with factory(tenant_id=TENANT) as session:
                            empty_result(await session.execute(update(app.Customer).where(
                                app.Customer.tenant_id == TENANT), rows,
                                execution_options={'synchronize_session': False}))
                            assert len(session.identity_map) == 0
                            assert (await session.execute(selection(app))).all() == expected
                            await session.commit()
                    finally:
                        await engine.dispose()
                asyncio.run(scenario())
        assert rows == original and parameters
        assert 'public prefix' in repr(parameters)
        assert 'e\u0301😀界' not in repr(parameters) and 'ab    ' not in repr(parameters)


@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan', 'auto'])
def test_attached_varchar_errors_and_zero_matches_follow_native_server_plans(mode):
    def seed(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
            (FOREIGN, UUID(int=999), 'else', 'public foreign'))
    with application(rows=3, value_type=String(4, collation='C'), setup=seed) as app:
        def scenario(session):
            outcomes = []
            for identity in (UUID(int=100), MISSING, FOREIGN):
                if mode == 'auto':
                    for _ in range(12):
                        empty_result(execute(session, app, [changes(101, name='good')]))
                savepoint = session.begin_nested()
                try:
                    empty_result(execute(session, app, [{'id': identity, 'name': 'abcde'}]))
                except (DBAPIError, CryptoFailure) as failure:
                    state = failure.orig.sqlstate if isinstance(failure, DBAPIError) else failure.sqlstate
                    assert state == '22001'
                    assert_aborted(session)
                else:
                    state = None
                outcomes.append(state)
                savepoint.rollback()
            session.rollback()
            return outcomes
        with plan_mode(app.runtime, mode):
            with Session(app.runtime) as native:
                expected = scenario(native)
        assert expected == (['22001'] * 3 if mode == 'force_custom_plan' else ['22001', None, None])
        with fresh_mapping(app):
            factory = protect(app)
            before = _snapshot(app)
            with plan_mode(app.runtime, mode):
                with factory(tenant_id=TENANT) as session:
                    assert scenario(session) == expected
            assert _snapshot(app) == before


@pytest.mark.parametrize('length_first', [False, True])
def test_varchar_update_preserves_first_native_unique_or_length_failure(length_first):
    with native_application(True) as app:
        conflict, length = changes(100, name='', label='public conflict'), changes(102, name='abcde', label='public length')
        rows = [length, conflict] if length_first else [conflict, length]
        original = deepcopy(rows)
        def scenario(session):
            with pytest.raises((DBAPIError, CryptoFailure)) as failed:
                execute(session, app, rows)
            actual = failed.value.orig.sqlstate if isinstance(failed.value, DBAPIError) else failed.value.sqlstate
            assert actual == ('22001' if length_first else '23505')
            assert_aborted(session)
            session.rollback()
            return actual
        with Session(app.runtime) as native:
            expected = scenario(native)
        with fresh_mapping(app):
            factory = protect(app)
            before = _snapshot(app)
            with factory(tenant_id=TENANT) as session:
                assert scenario(session) == expected
            assert _snapshot(app) == before and rows == original


@pytest.mark.parametrize('fault', ['length', 'unique'])
def test_varchar_update_savepoint_keeps_outer_work_and_native_recovery(fault):
    with native_application(True) as app:
        rows = [changes(101, name='good', label='public inner prefix'),
                changes(102, name='abcde' if fault == 'length' else 'good')]
        original = deepcopy(rows)
        def scenario(session, commit):
            empty_result(execute(session, app, [changes(100, label='public outer')]))
            savepoint = session.begin_nested()
            with pytest.raises((DBAPIError, CryptoFailure)) as failed:
                execute(session, app, rows)
            actual = failed.value.orig.sqlstate if isinstance(failed.value, DBAPIError) else failed.value.sqlstate
            assert actual == ('22001' if fault == 'length' else '23505')
            assert_aborted(session)
            savepoint.rollback()
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == ''
            empty_result(execute(session, app, [changes(101, name='done')]))
            actual = session.execute(selection(app)).all()
            session.commit() if commit else session.rollback()
            return actual
        with Session(app.runtime) as native:
            expected = scenario(native, False)
        with fresh_mapping(app):
            factory = protect(app)
            with factory(tenant_id=TENANT) as session:
                assert scenario(session, True) == expected
        assert rows == original


def test_varchar_bulk_length_does_not_preempt_native_autoflush_failure():
    with native_application(True) as app:
        def scenario(session):
            session.add(app.Customer(id=UUID(int=100), tenant_id=TENANT, name='good'))
            with pytest.raises(IntegrityError) as failed:
                execute(session, app, [changes(101, name='abcde')])
            assert failed.value.orig.sqlstate == '23505' and session.is_active is False
            with pytest.raises(PendingRollbackError):
                session.execute(selection(app))
            session.rollback()
        with Session(app.runtime) as native:
            scenario(native)
        with fresh_mapping(app):
            factory = protect(app)
            before = _snapshot(app)
            with factory(tenant_id=TENANT) as session:
                scenario(session)
            assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['constant', 'record', 'frame'])
def test_owned_varchar_case_bind_mutations_refuse_before_raw_update(fault, monkeypatch):
    with native_application(True) as app:
        factory = protect(app)
        before, changed = _snapshot(app), []
        replacement = before[1][2][2]
        def execute_change(connection, statement, multiparams, params, options):
            if getattr(statement, 'is_update', False):
                if fault == 'constant':
                    for node in visitors.iterate(statement):
                        if isinstance(node, BindParameter) and node.value == 'xx':
                            node.value = 'zz'
                            changed.append(True)
                elif fault == 'record':
                    groups = multiparams if multiparams else [params]
                    for group in groups:
                        for name, value in tuple(group.items()):
                            if value == UUID(int=100):
                                group[name] = UUID(int=102)
                                changed.append(True)
            return statement, multiparams, params
        def cursor_change(connection, cursor, sql, values, context, executemany):
            if sql.lstrip().upper().startswith('UPDATE '):
                group = values[0] if executemany else values
                for value in group.values():
                    if type(value) is psycopg.Binary and value.obj.startswith(b'CF1\x00'):
                        value.obj = replacement
                        changed.append(True)
                        break
            return sql, values
        name, callback = ('before_cursor_execute', cursor_change) if fault == 'frame' else ('before_execute', execute_change)
        event.listen(app.runtime, name, callback, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        execute(session, app, [changes(100, name='good')])
                    session.rollback()
                assert changed and sent == []
        finally:
            event.remove(app.runtime, name, callback)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            empty_result(execute(session, app, [changes(100, name='good')]))
            session.rollback()
        assert _snapshot(app) == before


def test_varchar_update_provider_outage_does_not_execute_a_valid_prefix(monkeypatch):
    with native_application(True) as app:
        run(app); publish(app)
        class Offline(PublicFixtureProvider):
            def unwrap(self, wrapper, context):
                raise OSError('PRIVATE Varchar UPDATE provider detail')
        ring = Keyring(keys(TENANT).policy, {PROVIDER: Offline()})
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
            keys=lambda tenant: ring, deployment=(app.plan, app.pin))
        before = _snapshot(app)
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(KeyUnavailable) as failed:
                    execute(session, app, [changes(100, name='good'), changes(101, name='abcde')])
                assert 'PRIVATE Varchar' not in str(failed.value)
                session.rollback()
            assert sent == []
        assert _snapshot(app) == before


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_update_entrypoints_without_native_empty_result_contract_refuse_before_keys(mode, monkeypatch):
    with native_application(True) as app:
        run(app); publish(app)
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        statement = update(app.Customer).where(app.Customer.tenant_id == TENANT)
        before = _snapshot(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                keys=resolve, deployment=(app.plan, app.pin))
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    for name in ('scalar', 'scalars'):
                        with pytest.raises(CryptoFailure):
                            getattr(session, name)(statement, [changes(100, name='good')],
                                execution_options={'synchronize_session': False})
                    assert resolutions == []
                assert sent == []
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                        keys=resolve, deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as sent:
                        async with factory(tenant_id=TENANT) as session:
                            resolutions.clear()
                            for name in ('scalar', 'scalars', 'stream', 'stream_scalars'):
                                with pytest.raises(CryptoFailure):
                                    await getattr(session, name)(statement, [changes(100, name='good')],
                                        execution_options={'synchronize_session': False})
                            assert resolutions == []
                        assert sent == []
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert _snapshot(app) == before


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_key_callback_cannot_retarget_original_varchar_update_rows(mode, monkeypatch):
    with native_application(True) as app:
        run(app); publish(app)
        rows, armed, changed = [changes(100, name='good')], [False], []
        def resolve(tenant):
            if armed[0] and not changed:
                rows[0]['id'] = UUID(int=102)
                changed.append(True)
            return keys(tenant)
        statement = update(app.Customer).where(app.Customer.tenant_id == TENANT)
        before = _snapshot(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                keys=resolve, deployment=(app.plan, app.pin))
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with factory(tenant_id=TENANT) as session:
                    armed[0] = True
                    with pytest.raises(CryptoFailure):
                        session.execute(statement, rows, execution_options={'synchronize_session': False})
                    session.rollback()
                assert changed and sent == []
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                        keys=resolve, deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as sent:
                        async with factory(tenant_id=TENANT) as session:
                            armed[0] = True
                            with pytest.raises(CryptoFailure):
                                await session.execute(statement, rows, execution_options={'synchronize_session': False})
                            await session.rollback()
                        assert changed and sent == []
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert _snapshot(app) == before


def test_async_varchar_generic_length_failure_and_zero_match_recover_in_savepoint():
    with native_application(True) as app:
        run(app); publish(app)
        before = _snapshot(app)
        async def scenario():
            async def connection():
                driver = await psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], prepare_threshold=0)
                await driver.execute('SET plan_cache_mode = force_generic_plan')
                await driver.commit()
                return driver
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True, async_creator=connection)
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                    keys=keys, deployment=(app.plan, app.pin))
                async with factory(tenant_id=TENANT) as session:
                    savepoint = await session.begin_nested()
                    statement = update(app.Customer).where(app.Customer.tenant_id == TENANT)
                    with pytest.raises(CryptoFailure) as failed:
                        await session.execute(statement, [changes(100, name='abcde')],
                            execution_options={'synchronize_session': False})
                    assert failed.value.sqlstate == '22001' and session.is_active is True
                    with pytest.raises(DBAPIError) as blocked:
                        await session.execute(select(app.Customer.id).where(app.Customer.id == UUID(int=100)))
                    assert blocked.value.orig.sqlstate == '25P02'
                    await savepoint.rollback()
                    empty_result(await session.execute(statement, [{'id': MISSING, 'name': 'abcde'}],
                        execution_options={'synchronize_session': False}))
                    await session.rollback()
            finally:
                await engine.dispose()
        asyncio.run(scenario())
        assert _snapshot(app) == before


def test_two_varchar_limits_signed_ids_search_and_second_field_failure_keep_group_binding():
    with application(rows=0, value_type=String(4, collation='C')) as app:
        app.table.c.id.type = BigInteger()
        app.table.append_column(Column('note', String(6, collation='C')))
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN id TYPE bigint USING NULL::bigint')
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN note varchar(6) COLLATE "C"')
        Index('native_note', app.table.c.tenant_id, app.table.c.note, unique=True).create(app.owner)
        with fresh_mapping(app):
            identities = [-2**63, 0, 2**63 - 1]
            with Session(app.runtime) as native:
                native.add_all(app.Customer(id=identity, tenant_id=TENANT, name=f'n{index}',
                    note=f's{index}', label='public source') for index, identity in enumerate(identities))
                native.commit()
            note_id = UUID(int=545)
            declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
                'models': [{'model': 'Customer', 'table_id': str(TABLE_ID), 'tenancy': {'column': 'tenant_id'},
                    'fields': [{'name': name, 'field_id': str(identity), 'protect': True,
                        'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']}
                        for name, identity in (('name', FIELD_ID), ('note', note_id))]}]}
            app.plan = app.m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
                writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned two-VARCHAR fixture'),)),
                search_reviews=tuple(SearchReview(identity, False, 'public bounded fixture values')
                    for identity in (FIELD_ID, note_id)), keys=keys, runtime_role=app.role,
                target_id=app.plan.target_id, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=700, wal_bytes_per_row=2000)
            app.pin = app.m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
            rows = [{'id': identities[0], 'name': 'e\u0301😀界', 'note': 'ab      ', 'label': 'public both'},
                {'id': 0, 'note': None}, {'id': identities[2], 'label': 'public omitted'},
                {'id': identities[0], 'name': 'last'}, {'id': 0, 'note': 'tail'}]
            original = deepcopy(rows)
            query = select(app.Customer.id, app.Customer.name, app.Customer.note, app.Customer.label).where(
                app.Customer.id.in_(identities)).order_by(app.Customer.id)
            def scenario(session, commit):
                loaded = session.get(app.Customer, identities[0])
                empty_result(execute(session, app, rows))
                assert (loaded.name, loaded.note) == ('n0', 's0')
                session.refresh(loaded)
                assert (loaded.name, loaded.note) == ('last', 'ab    ')
                assert session.scalars(select(app.Customer.id).where(app.Customer.name == 'last')).all() == [identities[0]]
                assert session.scalars(select(app.Customer.id).where(app.Customer.note == 'ab    ')).all() == [identities[0]]
                assert session.scalars(select(app.Customer.id).where(
                    app.Customer.note.in_(['tail', 's2'])).order_by(app.Customer.id)).all() == identities[1:]
                before_error = session.execute(query).all()
                savepoint = session.begin_nested()
                with pytest.raises((DBAPIError, CryptoFailure)) as failed:
                    execute(session, app, [{'id': identities[0], 'note': 'inner', 'label': 'public failed prefix'},
                        {'id': identities[2], 'note': '1234567'}])
                state = failed.value.orig.sqlstate if isinstance(failed.value, DBAPIError) else failed.value.sqlstate
                assert state == '22001'
                assert_aborted(session)
                savepoint.rollback()
                assert session.execute(query).all() == before_error
                empty_result(execute(session, app, [{'id': identities[2], 'note': 'redone'}]))
                result = session.execute(query).all()
                session.commit() if commit else session.rollback()
                return result
            with Session(app.runtime) as native:
                expected = scenario(native, False)
            factory = protect(app)
            with app.owner.connect() as connection:
                frames_before = {row[0]: row[1:] for row in connection.exec_driver_sql(
                    f'SELECT id,name,note FROM "{app.schema}".customer').all()}
            with factory(tenant_id=TENANT) as session:
                assert scenario(session, True) == expected
            with app.owner.connect() as connection:
                frames_after = {row[0]: row[1:] for row in connection.exec_driver_sql(
                    f'SELECT id,name,note FROM "{app.schema}".customer').all()}
            assert frames_after[0][0] == frames_before[0][0]
            assert frames_after[identities[2]][0] == frames_before[identities[2]][0]
            assert rows == original
