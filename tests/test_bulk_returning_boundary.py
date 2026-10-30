"""Native driver and result controls for mapped protected scalar RETURNING."""
from copy import deepcopy
import importlib
import json
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import event, select

from cryptalis.crypto import (AuthenticationFailed, FieldDescriptor, Keyring,
                              KeyUnavailable, open_text, seal_text)
from cryptalis.sqlalchemy import attach, UnsafeDriverEvent
from test_bulk_insert import protect
from test_bulk_insert_native import native_application, row
from test_bulk_returning import statement, stored_selection
from test_driver_event_boundary import raw_calls
from test_migration import (frames, keys, publish, run, TENANT, PROVIDER,
                            PublicFixtureProvider)
from test_rewrap_plan import _snapshot


def descriptor(app):
    field = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]
    return FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])


def sample_rows():
    return [row(1000 + index, f'v{index}', label='same group') for index in range(4)]


@pytest.mark.parametrize('fault', ['sql', 'payload', 'id'])
def test_returning_current_page_mutation_refuses_before_raw_insert_and_retries(fault, monkeypatch):
    with native_application(False) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        factory = protect(app)
        rows = sample_rows()
        original, before, injected = deepcopy(rows), _snapshot(app), []
        replacement = frames(app, True)[UUID(int=102)]

        def change_page(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                injected.append(True)
                assert isinstance(parameters, dict)
                if fault == 'sql':
                    sql += ' /* public changed RETURNING page */'
                elif fault == 'payload':
                    payloads = [value for value in parameters.values() if type(value) is psycopg.Binary]
                    assert payloads
                    payloads[0].obj = replacement
                else:
                    identity = next(key for key in parameters if key == 'id' or key.startswith('id__'))
                    parameters[identity] = UUID(int=9999)
            return sql, parameters

        event.listen(app.runtime, 'before_cursor_execute', change_page, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsafeDriverEvent):
                        session.execute(statement(app, False), rows)
                    session.rollback()
                assert injected and sent == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', change_page)
        assert rows == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, True), rows).scalars().all() == ['v0', 'v1', 'v2', 'v3']
            session.commit()


def test_page_one_observer_cannot_change_a_future_page_buffer(monkeypatch):
    with native_application(False) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        factory = protect(app)
        rows = sample_rows()
        original, before, injected, pages = deepcopy(rows), _snapshot(app), [], []
        replacement = frames(app, True)[UUID(int=102)]

        def change_future(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                pages.append(True)
                if not injected:
                    # ExecutionContext.parameters exposes the native processed
                    # rows that the dialect has not yet paged. Do not touch
                    # guard state or the private prepared-frame registry.
                    future = next(group for group in context.parameters if group['id'] == UUID(int=1002))
                    assert type(future['name']) is psycopg.Binary
                    future['name'].obj = replacement
                    injected.append(True)
            return sql, parameters

        event.listen(app.runtime, 'before_cursor_execute', change_future, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsafeDriverEvent):
                        session.execute(statement(app, False), rows)
                    session.rollback()
                # Page one was valid. Page two must refuse before raw dispatch.
                assert injected == [True] and len(sent) == 1
        finally:
            event.remove(app.runtime, 'before_cursor_execute', change_future)
        assert rows == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, True), rows).scalars().all() == ['v0', 'v1', 'v2', 'v3']
            session.commit()


@pytest.mark.parametrize('fault', [
    'null_identity', 'outside_input', 'fresh_same_context', 'wrong_frame',
    'nonnull_to_null', 'null_to_nonnull', 'tenant',
])
@pytest.mark.parametrize('labelled', [False, True])
def test_returning_packed_companion_must_match_exact_prepared_input(fault, monkeypatch, labelled):
    with native_application(False) as app:
        factory = protect(app)
        field = descriptor(app)
        outside = frames(app, True)[UUID(int=102)]
        alternate = seal_text('first', field, TENANT, UUID(int=1000), keys(TENANT).prepare())
        assert open_text(alternate, field, TENANT, UUID(int=1000), keys(TENANT).prepare()) == 'first'
        value = None if fault == 'null_to_nonnull' else 'first'
        rows = [row(1000, value, label='public')]
        original, before, armed, injected = deepcopy(rows), _snapshot(app), [], []
        native_fetchall = psycopg.Cursor.fetchall

        def arm(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT ') and app.schema in sql:
                armed.append(True)

        def changed_fetchall(cursor):
            fetched = native_fetchall(cursor)
            if armed and not injected and fetched:
                first = fetched[0]
                assert type(first[0]) is list and len(first[0]) == 3
                packed = list(first[0])
                if fault == 'null_identity':
                    packed = [None, None, str(TENANT)]
                elif fault == 'outside_input':
                    packed = [outside.hex(), str(UUID(int=102)), str(TENANT)]
                elif fault == 'fresh_same_context':
                    assert packed[0] != alternate.hex()
                    packed[0] = alternate.hex()
                elif fault == 'wrong_frame':
                    packed[0] = outside.hex()
                elif fault == 'nonnull_to_null':
                    assert packed[0] is not None
                    packed[0] = None
                elif fault == 'null_to_nonnull':
                    assert packed[0] is None
                    packed[0] = alternate.hex()
                else:
                    packed[2] = str(UUID(int=9999))
                fetched[0] = (packed, *first[1:])
                injected.append(True)
            return fetched

        event.listen(app.runtime, 'after_cursor_execute', arm)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, 'fetchall', changed_fetchall)
                with factory(tenant_id=TENANT) as session:
                    # ORM bulk execution eagerly consumes native RETURNING.
                    # No partial Result reaches the caller on proof failure.
                    with pytest.raises(AuthenticationFailed):
                        session.execute(statement(app, False, labelled=labelled), rows,
                                        execution_options={'render_nulls': True})
                    session.rollback()
                assert armed and injected == [True]
        finally:
            event.remove(app.runtime, 'after_cursor_execute', arm)
        assert rows == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, False, labelled=labelled), rows,
                execution_options={'render_nulls': True}).scalars().all() == [value]
            session.commit()


def leased_factory(app, monkeypatch):
    run(app)
    publish(app)
    now, unwrapped = [100.0], []
    module = importlib.import_module('cryptalis.crypto.keys')
    monkeypatch.setattr(module, 'time', SimpleNamespace(
        monotonic=lambda: now[0], monotonic_ns=lambda: int(now[0] * 1e9)))

    class ObservedProvider(PublicFixtureProvider):
        def unwrap(self, wrapper, context):
            unwrapped.append(context)
            return super().unwrap(wrapper, context)

    ring = Keyring(keys(TENANT).policy, {PROVIDER: ObservedProvider()}, max_age=1)
    factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                     keys=lambda tenant: ring, deployment=(app.plan, app.pin))
    return factory, now, unwrapped, ring


def test_key_expiry_after_raw_returning_refuses_eager_plaintext_and_rolls_back(monkeypatch):
    with native_application(False) as app:
        factory, now, unwrapped, ring = leased_factory(app, monkeypatch)
        before, expired = _snapshot(app), []

        def expire(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('INSERT '):
                now[0] += 2
                expired.append(True)

        event.listen(app.runtime, 'after_cursor_execute', expire)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(KeyUnavailable):
                        session.execute(statement(app, False), [row(1000, 'first')])
                    session.rollback()
                assert expired == [True] and len(sent) == 1
                assert len(unwrapped) == len(ring.policy.wrappers)
        finally:
            event.remove(app.runtime, 'after_cursor_execute', expire)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, False), [row(1000, 'first')]).scalars().all() == ['first']
            session.commit()


def test_returned_plaintext_remains_available_after_key_expiry_without_provider_work(monkeypatch):
    with native_application(False) as app:
        factory, now, unwrapped, ring = leased_factory(app, monkeypatch)
        with factory(tenant_id=TENANT) as session:
            result = session.execute(statement(app, False), [row(1000, 'first'), row(1001, 'next')])
            admitted = tuple(unwrapped)
            assert len(admitted) == len(ring.policy.wrappers)
            now[0] += 2
            assert result.scalars().all() == ['first', 'next']
            assert tuple(unwrapped) == admitted
            assert len(session.identity_map) == 0
            session.rollback()


def test_outstanding_returning_result_keeps_its_own_proof_after_a_later_operation():
    with native_application(False) as app:
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            first = session.execute(statement(app, True), [row(1000, 'first'), row(1001, None)],
                                    execution_options={'render_nulls': True})
            second = session.execute(statement(app, True), [row(1002, 'next')])
            assert second.scalars().all() == ['next']
            assert first.scalars().all() == ['first', None]
            assert len(session.identity_map) == 0
            assert len(session.execute(stored_selection(app)).all()) == 3
            session.commit()
