"""Point UPDATE must bind both the final driver call and every protected result."""
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import event, func, literal, or_, update

from cryptalis.crypto import AuthenticationFailed, CryptoFailure, seal_text
from cryptalis.sqlalchemy import attach
from test_bulk_returning_boundary import descriptor, leased_factory
from test_driver_event_boundary import raw_calls
from test_migration import application, frames, keys, publish, run, TENANT
from test_point_update_returning import statement
from test_rewrap_plan import _snapshot


def protect(app, resolver=keys):
    run(app); publish(app)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolver,
                  deployment=(app.plan, app.pin))


@pytest.mark.parametrize('fault', ['missing_scope', 'missing_id', 'wrong_scope', 'or_scope',
    'id_type', 'core', 'entity_alias', 'label', 'expression', 'embedded', 'value_expression',
    'tenant_assignment', 'id_assignment', 'unknown_column', 'sync_auto', 'sync_zero'])
def test_invalid_point_returning_refuses_before_resolver_or_native_update(fault, monkeypatch):
    with application(rows=3) as app:
        calls = []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = protect(app, resolve)
        query, values = statement(app, UUID(int=101), 'scalar'), {'name': 'PUBLIC updated'}
        options = {'synchronize_session': False}
        if fault == 'missing_scope': query = update(app.Customer).where(app.Customer.id == UUID(int=101)).returning(app.Customer.name)
        elif fault == 'missing_id': query = update(app.Customer).where(app.Customer.tenant_id == TENANT).returning(app.Customer.name)
        elif fault == 'wrong_scope': query = update(app.Customer).where(app.Customer.id == UUID(int=101), app.Customer.tenant_id == UUID(int=999)).returning(app.Customer.name)
        elif fault == 'or_scope': query = update(app.Customer).where(or_(app.Customer.id == UUID(int=101), app.Customer.tenant_id == TENANT)).returning(app.Customer.name)
        elif fault == 'id_type': query = statement(app, str(UUID(int=101)), 'scalar')
        elif fault == 'core': query = update(app.table).where(app.table.c.id == UUID(int=101), app.table.c.tenant_id == TENANT).returning(app.table.c.name)
        elif fault in ('entity_alias', 'label', 'expression'):
            output = app.table.alias().c.name if fault == 'entity_alias' else func.lower(app.Customer.name).label('renamed') if fault == 'label' else func.lower(app.Customer.name)
            query = update(app.Customer).where(app.Customer.id == UUID(int=101), app.Customer.tenant_id == TENANT).returning(output)
        elif fault == 'embedded': query = query.values(name='PUBLIC embedded')
        elif fault == 'value_expression': values['name'] = literal('PUBLIC expression')
        elif fault == 'tenant_assignment': values['tenant_id'] = TENANT
        elif fault == 'id_assignment': values['id'] = UUID(int=101)
        elif fault == 'unknown_column': values['unmapped'] = 'PUBLIC'
        elif fault == 'sync_auto': options['synchronize_session'] = 'auto'
        elif fault == 'sync_zero': options['synchronize_session'] = 0
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            calls.clear()
            with pytest.raises(CryptoFailure): session.execute(query, values, execution_options=options)
            assert calls == sent == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['identity', 'returning', 'result_shape', 'values'])
def test_provider_callback_cannot_change_captured_point_request(fault, monkeypatch):
    with application(rows=3) as app:
        armed = []
        def resolve(tenant):
            if armed:
                armed.clear()
                if fault == 'identity': query._where_criteria = statement(app, UUID(int=102), 'scalar')._where_criteria
                elif fault == 'returning': query._returning = (app.Customer.label.__clause_element__(),)
                elif fault == 'result_shape': query._returning = tuple(app.table.c)
                else: values['name'] = 'PUBLIC changed'
            return keys(tenant)
        factory = protect(app, resolve)
        query, values = statement(app, UUID(int=101), 'scalar'), {'name': 'PUBLIC updated'}
        if fault == 'result_shape':
            query = update(app.Customer).where(app.Customer.id == UUID(int=101), app.Customer.tenant_id == TENANT).returning(app.Customer)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            armed.append(True)
            with pytest.raises(CryptoFailure):
                session.execute(query, values, execution_options={'synchronize_session': False})
            assert not sent and not armed
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['sql', 'payload', 'identity', 'projection_constant'])
def test_point_driver_mutation_refuses_before_native_update(fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        injected = []
        def mutate(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith('UPDATE '):
                injected.append(True)
                if fault == 'sql': sql += ' /* PUBLIC changed */'
                elif fault == 'payload': parameters['name'] = b'PUBLIC invalid'
                elif fault == 'identity':
                    name = next(k for k, v in parameters.items() if v == UUID(int=101))
                    parameters[name] = UUID(int=102)
                else:
                    name = next(k for k, v in parameters.items() if v == 'hex')
                    parameters[name] = 'escape'
            return sql, parameters
        before = _snapshot(app)
        event.listen(app.runtime, 'before_cursor_execute', mutate, retval=True)
        try:
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with pytest.raises(CryptoFailure):
                    session.execute(statement(app, UUID(int=101), 'scalar'), {'name': 'PUBLIC updated'},
                        execution_options={'synchronize_session': False}).all()
                assert injected == [True] and sent == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', mutate)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['wrong_record', 'wrong_tenant', 'old_frame', 'fresh_frame',
    'null_frame', 'null_identity', 'malformed'])
@pytest.mark.parametrize('labelled', [False, True])
def test_returning_authenticates_context_and_exact_new_frame(fault, monkeypatch, labelled):
    with application(rows=3) as app:
        factory = protect(app)
        query = statement(app, UUID(int=101), 'scalar')
        if labelled:
            query = update(app.Customer).where(app.Customer.id == UUID(int=101),
                app.Customer.tenant_id == TENANT).returning(app.Customer.name.label('display_name'))
        old = frames(app, True)[UUID(int=101)]
        fresh = seal_text('PUBLIC updated', descriptor(app), TENANT, UUID(int=101), keys(TENANT).prepare())
        native_fetch, armed, injected = psycopg.Cursor.fetchall, [], []
        def arm(connection, cursor, query, parameters, context, many):
            if query.lstrip().upper().startswith('UPDATE '): armed.append(True)
        def mutate(cursor):
            rows = native_fetch(cursor)
            if armed and not injected and rows:
                packed = list(rows[0][0])
                if fault == 'wrong_record': packed[1] = str(UUID(int=102))
                elif fault == 'wrong_tenant': packed[2] = str(UUID(int=999))
                elif fault == 'old_frame': packed[0] = old.hex()
                elif fault == 'fresh_frame': packed[0] = fresh.hex()
                elif fault == 'null_frame': packed[0] = None
                elif fault == 'null_identity': packed = [None, None, str(TENANT)]
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
                    with pytest.raises(AuthenticationFailed):
                        session.execute(query, {'name': 'PUBLIC updated'},
                            execution_options={'synchronize_session': False}).all()
                    session.rollback()
            assert injected == [True]
        finally:
            event.remove(app.runtime, 'after_cursor_execute', arm)
        assert _snapshot(app) == before


@pytest.mark.parametrize('identity', [UUID(int=100), UUID(int=101)])
def test_unchanged_returning_requires_row_identity_even_for_null(identity, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        native_fetch, armed, injected = psycopg.Cursor.fetchall, [], []
        def arm(connection, cursor, query, parameters, context, many):
            if query.lstrip().upper().startswith('UPDATE '): armed.append(True)
        def mutate(cursor):
            rows = native_fetch(cursor)
            if armed and not injected and rows:
                rows[0] = ([None, None, None],)
                injected.append(True)
            return rows
        before = _snapshot(app)
        event.listen(app.runtime, 'after_cursor_execute', arm)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(psycopg.Cursor, 'fetchall', mutate)
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(AuthenticationFailed):
                        session.execute(statement(app, identity, 'scalar'), {'label': 'public changed'},
                            execution_options={'synchronize_session': False}).all()
                    session.rollback()
            assert injected == [True]
        finally:
            event.remove(app.runtime, 'after_cursor_execute', arm)
        assert _snapshot(app) == before


def test_expired_returning_keys_do_not_release_plaintext_or_commit(monkeypatch):
    with application(rows=3) as app:
        factory, now, _, _ = leased_factory(app, monkeypatch)
        def expire(connection, cursor, query, parameters, context, many):
            if query.lstrip().upper().startswith('UPDATE '): now[0] += 2
        before = _snapshot(app)
        event.listen(app.runtime, 'after_cursor_execute', expire)
        try:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(CryptoFailure):
                    session.execute(statement(app, UUID(int=101), 'scalar'), {'name': 'PUBLIC updated'},
                        execution_options={'synchronize_session': False}).all()
                session.rollback()
        finally:
            event.remove(app.runtime, 'after_cursor_execute', expire)
        assert _snapshot(app) == before
