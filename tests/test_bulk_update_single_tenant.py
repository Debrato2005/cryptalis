"""Single-tenant dictionary UPDATE retains native state, errors and current exit."""
import asyncio
from copy import deepcopy
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String, Text, event, literal, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm.exc import StaleDataError

from cryptalis import deprotection as d, migration as m, online
from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_bulk_update_native import empty_result
from test_driver_event_boundary import raw_calls
from test_migration import keys, TABLE_ID
from test_online_protection import app, _pin, _source_rows
from test_online_scalars import SCALARS


def activate(app):
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin,
                 approval=app.approval, max_chunks=10, fence=True)
    successor = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    online.switch(app.plan, app.owner, successor=successor, keys=keys,
                  pin=app.pin, approval=app.approval)
    approval = m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
            approval=approval, until='ACTIVE')
    return successor, approval


def remove(app, successor, approval):
    reverse = d.plan(successor, app.owner, source_pin=_pin(successor, 'ACTIVE'), keys=keys,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1000, wal_bytes_per_row=2000)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                                 True, 'Public disposable single-tenant UPDATE fixture.')
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PREPARED'),
            approval=approval, consent=consent)
    d.apply(reverse, app.owner, keys=keys, pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=approval, consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Current updated native values match.', 'No retained protected fixture.', True)
    d.remove(reverse, app.owner, pin=_pin(reverse, 'REMOVING'), approval=approval,
             removal=removal, consent=consent)


def selection(app):
    return select(app.Customer.id, app.Customer.body, app.Customer.label).order_by(app.Customer.id)


def active_frames(app):
    with app.owner.connect() as connection:
        return {row[0]: tuple(None if value is None else bytes(value) for value in row[1:])
                for row in connection.exec_driver_sql(
                    f'SELECT id,body,label FROM "{app.schema}".customer ORDER BY id')}


def observe_updates(engine, samples):
    def observe(connection, cursor, sql, values, context, executemany):
        if sql.lstrip().upper().startswith('UPDATE '):
            samples.append(repr(values))
    event.listen(engine, 'before_cursor_execute', observe)
    return observe


@pytest.mark.parametrize('app', [(Text(collation='C'), ('first', 'e\u0301😀界', None)),
    (String(8, collation='C'), ('first', 'e\u0301😀界', None)), *SCALARS], indirect=True)
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_single_tenant_updates_match_native_state_and_latest_value_exit(app, mode):
    initial = _source_rows(app)
    value = initial[UUID(int=20)][0]
    rows = [{'id': UUID(int=10), 'body': value},
            {'id': UUID(int=20), 'body': None, 'label': 'private update label'},
            {'id': UUID(int=10), 'body': initial[UUID(int=10)][0]},
            {'id': UUID(int=10), 'body': value},
            {'id': UUID(int=30), 'label': 'private tail'}]
    original, native_samples, protected_samples = deepcopy(rows), [], []
    listener = observe_updates(app.source, native_samples)
    try:
        with app.source_factory() as session:
            loaded = session.get(app.Customer, UUID(int=10))
            session.get(app.Customer, UUID(int=30)).label = 'private autoflush'
            empty_result(session.execute(update(app.Customer), rows,
                                         execution_options={'synchronize_session': False}))
            assert loaded.body == initial[loaded.id][0]
            session.refresh(loaded)
            assert loaded.body == value and type(loaded.body) is type(value)
            expected = session.execute(selection(app)).all()
            session.rollback()
    finally:
        event.remove(app.source, 'before_cursor_execute', listener)
    assert 'private update label' in repr(native_samples)
    assert _source_rows(app) == initial
    with fresh_mapping(app):
        successor, approval = activate(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                             deployment=(successor, _pin(successor, 'ACTIVE')))
            listener = observe_updates(app.target, protected_samples)
            try:
                with factory(tenant_id=TABLE_ID) as session:
                    loaded = session.get(app.Customer, UUID(int=10))
                    session.get(app.Customer, UUID(int=30)).label = 'private autoflush'
                    empty_result(session.execute(update(app.Customer), rows,
                                                 execution_options={'synchronize_session': False}))
                    assert loaded.body == initial[loaded.id][0]
                    session.refresh(loaded)
                    assert loaded.body == value and type(loaded.body) is type(value)
                    assert session.execute(selection(app)).all() == expected
                    session.rollback()
                    assert session.get(app.Customer, UUID(int=10)).body == initial[UUID(int=10)][0]
                    empty_result(session.execute(update(app.Customer), rows,
                                                 execution_options={'synchronize_session': False}))
                    session.commit()
            finally:
                event.remove(app.target, 'before_cursor_execute', listener)
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=successor.lock_bytes, keys=keys,
                                           deployment=(successor, _pin(successor, 'ACTIVE')))
                    listener = observe_updates(engine.sync_engine, protected_samples)
                    async with factory(tenant_id=TABLE_ID) as session:
                        loaded = await session.get(app.Customer, UUID(int=10))
                        (await session.get(app.Customer, UUID(int=30))).label = 'private autoflush'
                        empty_result(await session.execute(update(app.Customer), rows,
                            execution_options={'synchronize_session': False}))
                        assert loaded.body == initial[loaded.id][0]
                        await session.refresh(loaded)
                        assert loaded.body == value and type(loaded.body) is type(value)
                        assert (await session.execute(selection(app))).all() == expected
                        await session.rollback()
                        assert (await session.get(app.Customer, UUID(int=10))).body == initial[UUID(int=10)][0]
                        empty_result(await session.execute(update(app.Customer), rows,
                            execution_options={'synchronize_session': False}))
                        await session.commit()
                    event.remove(engine.sync_engine, 'before_cursor_execute', listener)
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert rows == original and protected_samples
        assert 'private update label' not in repr(protected_samples)
        assert 'private autoflush' not in repr(protected_samples)
        assert 'private tail' not in repr(protected_samples)
        remove(app, successor, approval)
    assert _source_rows(app) == {row.id: (row.body, row.label) for row in expected}


@pytest.mark.parametrize('app,fault', [
    ((Text(collation='C'), ('first', 'second', None)), 'missing'),
    ((Text(collation='C'), ('first', 'second', None)), 'varchar'),
    (SCALARS[2], 'integer'),
], indirect=['app'])
def test_single_tenant_update_failures_match_native_savepoint_recovery(app, fault):
    # SQLAlchemy checks row counts only when the caller supplies no WHERE clause.
    rows = [{'id': UUID(int=10), 'label': 'prefix before error'},
            {'id': UUID(int=999 if fault == 'missing' else 20),
             'label': 'x' * 65 if fault == 'varchar' else 'valid'}]
    if fault == 'integer':
        rows[1]['body'] = 2**31 + 37
    initial = _source_rows(app)
    def scenario(session):
        session.get(app.Customer, UUID(int=30)).label = 'outer saved'
        savepoint = session.begin_nested()
        with pytest.raises((StaleDataError, DBAPIError, CryptoFailure)) as failure:
            session.execute(update(app.Customer), rows,
                            execution_options={'synchronize_session': False})
        observed = ('missing' if isinstance(failure.value, StaleDataError) else
                    failure.value.orig.sqlstate if isinstance(failure.value, DBAPIError) else failure.value.sqlstate)
        status = session.connection().connection.driver_connection.info.transaction_status.name
        savepoint.rollback()
        assert session.get(app.Customer, UUID(int=10)).label == initial[UUID(int=10)][1]
        assert session.get(app.Customer, UUID(int=30)).label == 'outer saved'
        empty_result(session.execute(update(app.Customer), [{'id': UUID(int=20), 'label': 'recovered'}],
                                     execution_options={'synchronize_session': False}))
        session.rollback()
        return observed, status
    with app.source_factory() as session:
        expected = scenario(session)
    assert expected[0] == {'missing': 'missing', 'varchar': '22001', 'integer': '22003'}[fault]
    with fresh_mapping(app):
        successor, _ = activate(app)
        factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                         deployment=(successor, _pin(successor, 'ACTIVE')))
        before = active_frames(app)
        with factory(tenant_id=TABLE_ID) as session:
            assert scenario(session) == expected
        assert active_frames(app) == before


@pytest.mark.parametrize('fault', ['where', 'returning', 'expression', 'missing_id', 'wrong_id', 'wrong_scope'])
def test_single_tenant_update_unadmitted_requests_refuse_before_keys_or_sql(app, fault, monkeypatch):
    successor, _ = activate(app)
    resolutions = []
    def resolve(tenant):
        resolutions.append(tenant)
        return keys(tenant)
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=resolve,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    statement = update(app.Customer)
    rows = [{'id': UUID(int=10), 'body': 'private value'}]
    if fault == 'where': statement = statement.where(app.Customer.id == UUID(int=10))
    elif fault == 'returning': statement = statement.returning(app.Customer.body)
    elif fault == 'expression': rows[0]['body'] = literal('private expression')
    elif fault == 'missing_id': del rows[0]['id']
    elif fault == 'wrong_id': rows[0]['id'] = str(rows[0]['id'])
    with factory(tenant_id=TABLE_ID) as session:
        if fault == 'wrong_scope': session._tenant = UUID(int=999)
        resolutions.clear()
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as calls:
            with pytest.raises(CryptoFailure):
                session.execute(statement, rows, execution_options={'synchronize_session': False})
            assert resolutions == calls == []


@pytest.mark.parametrize('fault', ['record', 'frame', 'sql'])
def test_single_tenant_update_late_mutations_refuse_before_driver_and_retry(app, fault, monkeypatch):
    successor, _ = activate(app)
    factory = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
                     deployment=(successor, _pin(successor, 'ACTIVE')))
    before = active_frames(app)
    injected = []
    def mutate(connection, cursor, sql, parameters, context, executemany):
        if sql.lstrip().upper().startswith('UPDATE '):
            injected.append(True)
            group = parameters[0] if executemany else parameters
            if fault == 'record':
                name = next(name for name, value in group.items() if type(value) is UUID)
                group[name] = UUID(int=20)
            elif fault == 'frame': group['body'].obj = before[UUID(int=20)][0]
            else: sql += ' /* changed UPDATE */'
        return sql, parameters
    event.listen(app.target, 'before_cursor_execute', mutate, retval=True)
    try:
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as calls:
            with factory(tenant_id=TABLE_ID) as session:
                with pytest.raises(CryptoFailure):
                    session.execute(update(app.Customer), [{'id': UUID(int=10), 'body': 'changed'}],
                                    execution_options={'synchronize_session': False})
                session.rollback()
            assert injected and not calls
    finally:
        event.remove(app.target, 'before_cursor_execute', mutate)
    assert active_frames(app) == before
    with factory(tenant_id=TABLE_ID) as session:
        empty_result(session.execute(update(app.Customer), [{'id': UUID(int=10), 'body': 'changed'}],
                                     execution_options={'synchronize_session': False}))
        session.commit()
        assert session.get(app.Customer, UUID(int=10)).body == 'changed'
