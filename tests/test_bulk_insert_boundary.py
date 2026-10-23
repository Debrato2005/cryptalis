"""Native adversarial controls for the admitted mapped bulk INSERT route."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import ColumnDefault, event, insert, literal, select
from sqlalchemy.exc import DBAPIError, IntegrityError, PendingRollbackError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, registry

from cryptalis import migration as m
from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_bulk_insert import native_failure, native_success, protect
from test_bulk_insert_native import assert_aborted, native_application, row
from test_deprotection import native_rows
from test_migration import (application, frames, keys, publish, run, TENANT,
                            TABLE_ID, FIELD_ID, PROVIDER, PublicFixtureProvider)
from test_rewrap_plan import _snapshot
from test_search_retained_readers import remove_current
from test_sqlalchemy_adapter import app as adapter_app, db, factory as adapter_factory


def selection(app):
    return select(app.Customer.id, app.Customer.tenant_id, app.Customer.name,
                  app.Customer.label).where(app.Customer.id.in_(
                      [UUID(int=identity) for identity in range(1000, 1004)])).order_by(app.Customer.id)


@contextmanager
def driver_insert_calls(monkeypatch):
    calls = []
    with monkeypatch.context() as patch:
        for name in ('execute', 'executemany'):
            original = getattr(psycopg.Cursor, name)

            def observe(cursor, query, *args, _original=original, _name=name, **kwargs):
                if str(query).lstrip().upper().startswith('INSERT '):
                    calls.append(_name)
                return _original(cursor, query, *args, **kwargs)

            patch.setattr(psycopg.Cursor, name, observe)
        yield calls


@pytest.mark.parametrize('boundary,fault', [
    ('cursor', 'payload'), ('cursor', 'payload_inplace'),
    ('cursor', 'sql'), ('cursor', 'compiled_row'),
    ('cursor', 'id'), ('cursor', 'tenant_id'),
    ('execute', 'id'), ('execute', 'tenant_id'),
])
def test_late_listener_cannot_replace_sealed_payload_or_context_before_driver(boundary, fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        replacement = frames(app, True)[UUID(int=101)]
        rows = [row(1000, 'first protected', label='first'),
                row(1001, 'second protected', label='second')]
        original, before, injected = deepcopy(rows), _snapshot(app), []

        def changed(group):
            output = dict(group)
            key = 'name' if fault == 'payload' else fault
            output[key] = psycopg.Binary(replacement) if fault == 'payload' else UUID(int=9999)
            return output

        def cursor_listener(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('INSERT '):
                injected.append(True)
                if fault == 'sql':
                    statement += ' /* public late SQL replacement */'
                elif fault == 'payload_inplace':
                    sent = parameters if isinstance(parameters, dict) else parameters[0]
                    assert type(sent['name']) is psycopg.Binary
                    sent['name'].obj = replacement
                elif fault == 'compiled_row':
                    # Both views now describe another admitted, correctly sealed
                    # row. The independent pre-listener batch must reject it.
                    assert context.executemany and len(context.compiled_parameters) == 2
                    group, other = context.compiled_parameters
                    sent, other_sent = parameters
                    group.update(id=other['id'], name=other['name'])
                    sent.update(id=other_sent['id'], name=other_sent['name'])
                elif isinstance(parameters, dict):
                    parameters = changed(parameters)
                else:
                    parameters = [changed(parameters[0]), *parameters[1:]]
            return statement, parameters

        def execute_listener(connection, statement, multiparams, params, options):
            if getattr(statement, 'is_insert', False):
                injected.append(True)
                if multiparams:
                    multiparams = [changed(multiparams[0]), *multiparams[1:]]
                else:
                    params = changed(params)
            return statement, multiparams, params

        name = 'before_cursor_execute' if boundary == 'cursor' else 'before_execute'
        listener = cursor_listener if boundary == 'cursor' else execute_listener
        event.listen(app.runtime, name, listener, retval=True)
        try:
            with driver_insert_calls(monkeypatch) as raw_calls:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(insert(app.Customer), rows)
                    session.rollback()
                assert injected and raw_calls == []
        finally:
            event.remove(app.runtime, name, listener)
        assert rows == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            session.execute(insert(app.Customer), rows)
            session.commit()
            assert [entry[0] for entry in session.execute(selection(app))] == [UUID(int=1000), UUID(int=1001)]



def test_savepoint_sql_replacement_cannot_grant_a_data_write_permit(monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        before, injected = _snapshot(app), []
        forged = (f'INSERT INTO "{app.schema}".customer (id,tenant_id,label) '
                  f"VALUES ('{UUID(int=1000)}','{TENANT}','public forged control')")

        def replace_savepoint(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('SAVEPOINT '):
                injected.append(True)
                return forged, {}
            return statement, parameters

        with factory(tenant_id=TENANT) as session:
            connection = session.connection()
            with driver_insert_calls(monkeypatch) as raw_calls:
                event.listen(app.runtime, 'before_cursor_execute', replace_savepoint, retval=True)
                try:
                    with pytest.raises(CryptoFailure):
                        connection.begin_nested()
                finally:
                    event.remove(app.runtime, 'before_cursor_execute', replace_savepoint)
                # A control statement must not leave a general data permit.
                with pytest.raises(CryptoFailure):
                    connection.execute(insert(app.table), [row(1000, 'public data')])
                assert injected and raw_calls == []
            session.rollback()
        assert _snapshot(app) == before


def test_aliased_input_dictionary_keeps_native_duplicate_failure_and_caller_identity():
    with native_application(False) as app:
        shared = row(1000, 'same protected value', label='shared dictionary')
        rows, original = [shared, shared], deepcopy(shared)
        assert native_failure(app, rows) == '23505'
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(IntegrityError) as failed:
                session.execute(insert(app.Customer), rows)
            assert failed.value.orig.sqlstate == '23505'
            assert_aborted(session)
            session.rollback()
        assert rows[0] is rows[1] is shared and shared == original
        assert _snapshot(app) == before


def test_varchar_error_savepoint_rollback_preserves_outer_work_like_native():
    with native_application(True) as app:
        rows = [row(1001, 'good', label='inner prefix'), row(1002, 'abcde')]
        original = deepcopy(rows)

        def scenario(session, protected):
            session.execute(insert(app.Customer), [row(1000, 'keep', label='outer')])
            savepoint = session.begin_nested()
            with pytest.raises(CryptoFailure if protected else DBAPIError) as failed:
                session.execute(insert(app.Customer), rows)
            assert (failed.value.sqlstate if protected else failed.value.orig.sqlstate) == '22001'
            assert_aborted(session)
            savepoint.rollback()
            assert session.execute(selection(app)).all() == [(UUID(int=1000), TENANT, 'keep', 'outer')]
            session.execute(insert(app.Customer), [row(1003, 'done', label='recovered')])
            observed = session.execute(selection(app)).all()
            session.commit() if protected else session.rollback()
            return observed

        with Session(app.runtime) as session:
            expected = scenario(session, False)
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            assert scenario(session, True) == expected
        assert rows == original


def test_pending_orm_autoflush_failure_precedes_bulk_varchar_failure_like_native():
    with native_application(True) as app:
        rows = [row(1000, 'abcde', label='bulk must not run')]
        original = deepcopy(rows)

        def scenario(session):
            session.add(app.Customer(id=UUID(int=100), tenant_id=TENANT, name='good', label='pending duplicate'))
            with pytest.raises(IntegrityError) as failed:
                session.execute(insert(app.Customer), rows)
            assert failed.value.orig.sqlstate == '23505'
            assert session.is_active is False
            with pytest.raises(PendingRollbackError):
                session.execute(select(literal(1)))
            session.rollback()

        with Session(app.runtime) as session:
            scenario(session)
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            scenario(session)
        assert rows == original and _snapshot(app) == before


def test_used_callable_default_refuses_but_explicit_unprotected_value_remains_admitted():
    with native_application(False) as app:
        defaults = []

        def generate_label(context):
            defaults.append(True)
            return 'public generated label'

        app.table.c.label.default = ColumnDefault(generate_label)
        omitted = [row(1000, 'native default input')]
        expected, _ = native_success(app, omitted, False)
        assert defaults == [True] and expected[0][3] == 'public generated label'
        defaults.clear()
        factory = protect(app)
        before, statements = _snapshot(app), []
        def collect(*args):
            statements.append(True)
        event.listen(app.runtime, 'before_cursor_execute', collect)
        try:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(CryptoFailure):
                    session.execute(insert(app.Customer), omitted)
                assert statements == [] and defaults == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', collect)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            session.execute(insert(app.Customer), [row(1000, 'explicit input', label='explicit public value')])
            session.commit()
            assert session.scalar(select(app.Customer.label).where(
                app.Customer.id == UUID(int=1000))) == 'explicit public value'
        assert defaults == []


def test_async_provider_cancellation_reaches_no_sql_and_fresh_retry_commits():
    with native_application(False) as app:
        run(app); publish(app)
        before = _snapshot(app)
        rows = [row(1000, 'first canceled value'), row(1001, 'second canceled value')]
        original = deepcopy(rows)

        async def scenario():
            entered, release = asyncio.Event(), asyncio.Event()

            class AwaitedProvider:
                provider_id = PROVIDER
                def unwrap(self, *args):
                    raise AssertionError('Async bulk preparation must not use synchronous custody')
                async def unwrap_async(self, wrapper, context):
                    entered.set()
                    await release.wait()
                    return PublicFixtureProvider().unwrap(wrapper, context)

            selected = [Keyring(keys(TENANT).policy, {PROVIDER: AwaitedProvider()})]
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            statements = []
            def collect(*args):
                statements.append(True)
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                    keys=lambda tenant: selected[0], deployment=(app.plan, app.pin))
                event.listen(engine.sync_engine, 'before_cursor_execute', collect)
                async with factory(tenant_id=TENANT) as session:
                    task = asyncio.create_task(session.execute(insert(app.Customer), rows))
                    await asyncio.wait_for(entered.wait(), 3)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                    await session.rollback()
                assert statements == [] and _snapshot(app) == before
                selected[0] = keys(TENANT)
                async with factory(tenant_id=TENANT) as session:
                    await session.execute(insert(app.Customer), rows)
                    await session.commit()
                    assert len((await session.execute(selection(app))).all()) == 2
            finally:
                await engine.dispose()
        asyncio.run(scenario())
        assert rows == original


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_single_tenant_renamed_attributes_bulk_edit_and_native_exit(varchar):
    from sqlalchemy import String
    with application(rows=3, unique=False, queries=['equality'],
                     value_type=String(4, collation='C') if varchar else None) as app:
        mapping = registry(metadata=app.mapping.metadata)
        class Customer:
            pass
        mapping.map_imperatively(Customer, app.table, properties={
            'record': app.table.c.id, 'scope': app.table.c.tenant_id,
            'value': app.table.c.name, 'public': app.table.c.label})
        app.mapping, app.Customer = mapping, Customer
        declaration = app.plan.document['lock']['declaration']
        declaration['models'][0]['tenancy'] = {'single_tenant': True}
        declaration['models'][0]['fields'][0]['name'] = 'value'
        app.plan = m.plan(json.dumps(declaration).encode(), mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy',
                evidence='native single-tenant renamed bulk fixture'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'public synthetic values'),),
            keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.pin = m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        rows = [dict(record=UUID(int=1000), scope=TENANT, value='new', public='renamed'),
                dict(record=UUID(int=1001), scope=TENANT, value='next')]
        original = deepcopy(rows)
        try:
            with Session(app.runtime) as session:
                session.execute(insert(Customer), rows)
                expected = session.execute(select(Customer.record, Customer.value).where(
                    Customer.record.in_([UUID(int=1000), UUID(int=1001)])).order_by(Customer.record)).all()
                session.rollback()
            factory = protect(app)
            with factory(tenant_id=TABLE_ID) as session:
                session.execute(insert(Customer), rows)
                session.commit()
                assert session.execute(select(Customer.record, Customer.value).where(
                    Customer.record.in_([UUID(int=1000), UUID(int=1001)])).order_by(Customer.record)).all() == expected
                session.get(Customer, UUID(int=1000)).value = 'late'
                session.commit()
            assert rows == original
            remove_current(app, keys)
            final = native_rows(app)
            assert final == {**app.source, UUID(int=1000): (TENANT, 'late'), UUID(int=1001): (TENANT, 'next')}
        finally:
            mapping.dispose()


@pytest.mark.parametrize('adapter_app', [{'bigint': False}, {'bigint': True}], indirect=True)
def test_multiple_protected_fields_keep_uuid_and_signed_int64_row_context(adapter_app):
    app = adapter_app
    C = app.Customer
    bigint = C.__table__.c.id.type.python_type is int
    identities = [-2**63, -1, 0, 2**63-1] if bigint else [UUID(int=value) for value in range(4)]
    tenant = next(iter(app.rings))
    rows = [dict(id=identity, tenant_id=tenant, name=f'public name {index}', rank=index,
                 note=['雪😀', None, '', 'e\u0301'][index], secret=['a', '', None, 'd'][index])
            for index, identity in enumerate(identities)]
    original = deepcopy(rows)
    statement = select(C.id, C.note, C.secret).where(C.id.in_(identities)).order_by(C.id)
    with adapter_factory(app, False)(tenant_id=tenant) as session:
        session.execute(insert(C), rows, execution_options={'render_nulls': True})
        expected = session.execute(statement).all()
        session.rollback()
    with adapter_factory(app, True)(tenant_id=tenant) as session:
        session.execute(insert(C), rows, execution_options={'render_nulls': True})
        session.commit()
        assert session.execute(statement).all() == expected
        for index, identity in enumerate(identities):
            instance = session.get(C, identity)
            assert (instance.note, instance.secret) == (rows[index]['note'], rows[index]['secret'])
    assert rows == original
