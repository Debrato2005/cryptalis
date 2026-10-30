"""DELETE RETURNING binds final dispatch and authenticates each protected output."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, func
from sqlalchemy.ext.asyncio import create_async_engine

from cryptalis.crypto import AuthenticationFailed, CryptoFailure, Keyring
from cryptalis.sqlalchemy import attach
from test_bulk_returning_boundary import leased_factory
from test_driver_event_boundary import raw_calls
from test_migration import (application, keys, publish, run, PROVIDER, PublicFixtureProvider,
                            TABLE_ID, TENANT)
from test_point_delete_returning import statement
from test_point_update_returning_boundary import protect
from test_rewrap_plan import _snapshot
from test_single_tenant_update import single_application, snapshot


@pytest.mark.parametrize('fault', ['label', 'expression', 'alias', 'auto', 'fetch'])
def test_unadmitted_delete_returning_refuses_before_keys_and_driver(fault, monkeypatch):
    with application(rows=3) as app:
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = protect(app, resolve)
        output = app.Customer.name
        if fault == 'label': output = output.label('unsupported')
        elif fault == 'expression': output = func.lower(output)
        elif fault == 'alias': output = app.table.alias().c.name
        query = delete(app.Customer).where(app.Customer.id == UUID(int=101),
            app.Customer.tenant_id == TENANT).returning(output)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            calls.clear()
            with pytest.raises(CryptoFailure):
                session.execute(query, execution_options={'synchronize_session': fault if fault in ('auto', 'fetch') else False})
            assert calls == sent == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['identity', 'returning', 'result_shape'])
def test_provider_cannot_change_captured_delete_or_returned_shape(fault, monkeypatch):
    with application(rows=3) as app:
        armed = []
        def resolve(tenant):
            if armed:
                armed.clear()
                if fault == 'identity': query._where_criteria = statement(app, UUID(int=102))._where_criteria
                elif fault == 'returning': query._returning = (app.Customer.label.__clause_element__(),)
                else: query._returning = tuple(app.table.c)
            return keys(tenant)
        factory = protect(app, resolve)
        query = statement(app, UUID(int=101), 'entity' if fault == 'result_shape' else 'scalar')
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            armed.append(True)
            with pytest.raises(CryptoFailure):
                session.execute(query, execution_options={'synchronize_session': False})
            assert not sent and not armed
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['sql', 'identity', 'tenant', 'projection_constant'])
def test_final_delete_driver_changes_are_refused_before_execution(fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        attempted = []
        def mutate(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('DELETE '):
                attempted.append(True)
                if fault == 'sql': sql += ' /* changed */'
                else:
                    old = UUID(int=101) if fault == 'identity' else TENANT if fault == 'tenant' else 'hex'
                    name = next(k for k, v in parameters.items() if v == old)
                    parameters[name] = 'escape' if fault == 'projection_constant' else UUID(int=999)
            return sql, parameters
        before = _snapshot(app)
        event.listen(app.runtime, 'before_cursor_execute', mutate, retval=True)
        try:
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with pytest.raises(CryptoFailure):
                    session.execute(statement(app, UUID(int=101)), execution_options={'synchronize_session': False}).all()
                assert attempted == [True] and sent == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', mutate)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['record', 'tenant', 'ciphertext', 'malformed'])
def test_delete_returning_rejects_tampered_authenticated_values_and_rolls_back(fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        native, armed, injected = psycopg.Cursor.fetchall, [], []
        def arm(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('DELETE '): armed.append(True)
        def mutate(cursor):
            rows = native(cursor)
            if armed and not injected and rows:
                packed = list(rows[0][0])
                if fault == 'record': packed[1] = str(UUID(int=102))
                elif fault == 'tenant': packed[2] = str(UUID(int=999))
                elif fault == 'ciphertext': packed[0] = ('ff' if packed[0][:2] != 'ff' else '00') + packed[0][2:]
                else: packed.pop()
                rows[0] = (packed,)
                injected.append(True)
            return rows
        before = _snapshot(app)
        event.listen(app.runtime, 'after_cursor_execute', arm)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, 'fetchall', mutate)
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement(app, UUID(int=101)), execution_options={'synchronize_session': False}).all()
                    session.rollback()
            assert injected == [True]
        finally:
            event.remove(app.runtime, 'after_cursor_execute', arm)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fixed', [False, True])
@pytest.mark.parametrize('identity', [UUID(int=100), UUID(int=101)])
def test_delete_returning_cannot_substitute_an_outer_join_null_row(fixed, identity, monkeypatch):
    with (single_application() if fixed else application(rows=3)) as app:
        factory = protect(app)
        tenant = TABLE_ID if fixed else TENANT
        query = (delete(app.Customer).where(app.Customer.record == identity).returning(app.Customer.value)
                 if fixed else statement(app, identity))
        read = snapshot if fixed else _snapshot
        before = read(app)
        native, armed, injected = psycopg.Cursor.fetchall, [], []
        def arm(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('DELETE '): armed.append(True)
        def mutate(cursor):
            rows = native(cursor)
            if armed and not injected and rows:
                rows[0] = ([None, None, str(TABLE_ID) if fixed else None],)
                injected.append(True)
            return rows
        event.listen(app.runtime, 'after_cursor_execute', arm)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, 'fetchall', mutate)
                with factory(tenant_id=tenant) as session:
                    with pytest.raises(AuthenticationFailed):
                        session.execute(query, execution_options={'synchronize_session': False}).all()
                    session.rollback()
            assert injected == [True]
        finally:
            event.remove(app.runtime, 'after_cursor_execute', arm)
        assert read(app) == before


def test_delete_result_key_expiry_releases_no_plaintext_and_rollback_restores_row(monkeypatch):
    with application(rows=3) as app:
        factory, now, _, _ = leased_factory(app, monkeypatch)
        def expire(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('DELETE '): now[0] += 2
        before = _snapshot(app)
        event.listen(app.runtime, 'after_cursor_execute', expire)
        try:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(CryptoFailure):
                    session.execute(statement(app, UUID(int=101)), execution_options={'synchronize_session': False}).all()
                session.rollback()
        finally:
            event.remove(app.runtime, 'after_cursor_execute', expire)
        assert _snapshot(app) == before


def test_async_provider_cannot_replace_entity_returning_with_same_flattened_columns():
    with application(rows=3) as app:
        run(app); publish(app)
        query = statement(app, UUID(int=101), 'entity')
        async def scenario():
            class MutatingProvider:
                provider_id = PROVIDER
                def unwrap(self, *args): raise AssertionError('must await provider')
                async def unwrap_async(self, wrapper, context):
                    query._returning = tuple(app.table.c)
                    return PublicFixtureProvider().unwrap(wrapper, context)
            ring = Keyring(keys(TENANT).policy, {PROVIDER: MutatingProvider()})
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            sent = []
            try:
                factory = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=ring,
                    deployment=(app.plan, app.pin))
                event.listen(runtime.sync_engine, 'before_cursor_execute', lambda *args: sent.append(True))
                async with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        await session.execute(query, execution_options={'synchronize_session': False})
                    await session.rollback()
                assert sent == []
            finally:
                await runtime.dispose()
        before = _snapshot(app)
        asyncio.run(scenario())
        assert _snapshot(app) == before
