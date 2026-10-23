"""Native failure boundaries for the scoped mapped TEXT UPDATE route."""
from copy import deepcopy
import importlib
import hashlib
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, bindparam, cast, event, func, literal, or_, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session, column_property
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure, Keyring, KeyUnavailable
from cryptalis.sqlalchemy import attach, PolicyMismatch, UnsupportedProtectedOperation
from test_bulk_insert import protect
from test_bulk_insert_native import native_application
from test_bulk_update_native import changes, empty_result, execute
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT, PROVIDER, PublicFixtureProvider
from test_rewrap_plan import _snapshot


@pytest.mark.parametrize('fault', ['scope', 'wrong_scope', 'or_scope', 'returning', 'core',
    'embedded', 'expression', 'tenant_assignment', 'missing_id', 'id_type', 'unknown',
    'not_list', 'empty', 'sync_zero', 'sync_auto', 'scope_codec'])
def test_unadmitted_bulk_updates_refuse_before_keys_or_driver(fault):
    with native_application(False) as app:
        resolutions, statements = [], []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        values = [changes(100, name='first')]
        statement = update(app.Customer).where(app.Customer.tenant_id == TENANT)
        options = {'synchronize_session': False}
        if fault == 'scope': statement = update(app.Customer)
        elif fault == 'wrong_scope': statement = update(app.Customer).where(app.Customer.tenant_id == UUID(int=999))
        elif fault == 'or_scope': statement = update(app.Customer).where(or_(app.Customer.tenant_id == TENANT, app.Customer.id == UUID(int=100)))
        elif fault == 'returning': statement = statement.returning(app.Customer.name)
        elif fault == 'core': statement = update(app.table).where(app.table.c.tenant_id == TENANT)
        elif fault == 'embedded': statement = statement.values(name='embedded')
        elif fault == 'expression': values[0]['name'] = literal('row expression')
        elif fault == 'tenant_assignment': values[0]['tenant_id'] = TENANT
        elif fault == 'missing_id': del values[0]['id']
        elif fault == 'id_type': values[0]['id'] = str(values[0]['id'])
        elif fault == 'unknown': values[0]['not_mapped'] = 'public'
        elif fault == 'not_list': values = values[0]
        elif fault == 'empty': values = []
        elif fault == 'sync_zero': options['synchronize_session'] = 0
        elif fault == 'sync_auto': options['synchronize_session'] = 'auto'
        elif fault == 'scope_codec': statement = update(app.Customer).where(
            app.Customer.tenant_id == bindparam('scope', TENANT, type_=String))
        def observe(*args): statements.append(True)
        before = _snapshot(app)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                with pytest.raises(CryptoFailure):
                    session.execute(statement, values, execution_options=options)
                assert resolutions == statements == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert _snapshot(app) == before


@pytest.mark.parametrize('boundary,fault', [
    ('early_execute', 'swap_same_id'), ('execute', 'swap_same_id'), ('execute', 'scope'),
    ('cursor', 'payload'), ('cursor', 'id'), ('cursor', 'scope'), ('cursor', 'sql'),
])
def test_late_bulk_update_mutation_refuses_before_raw_dispatch_and_retries(boundary, fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        values = [changes(100, name='first'), changes(100, name='last')]
        original, before, injected = deepcopy(values), _snapshot(app), []

        def execute_change(connection, statement, multiparams, params, options):
            if getattr(statement, 'is_update', False):
                injected.append(True)
                if fault == 'swap_same_id':
                    assert len(multiparams) == 2
                    multiparams = [dict(multiparams[0], name=multiparams[1]['name']),
                                   dict(multiparams[1], name=multiparams[0]['name'])]
                else:
                    statement = update(app.Customer).where(app.Customer.tenant_id == UUID(int=999))
            return statement, multiparams, params

        def cursor_change(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('UPDATE '):
                injected.append(True)
                group = parameters[0] if isinstance(parameters, (list, tuple)) else parameters
                if fault == 'payload': group['name'].obj = b'PUBLIC_PLAINTEXT_REPLACEMENT'
                elif fault in ('id', 'scope'):
                    target = UUID(int=100) if fault == 'id' else TENANT
                    key = next(key for key, value in group.items() if type(value) is UUID and value == target)
                    group[key] = UUID(int=9999)
                else: sql += ' /* changed UPDATE SQL */'
            return sql, parameters

        name = 'before_execute' if boundary.endswith('execute') else 'before_cursor_execute'
        callback = execute_change if boundary.endswith('execute') else cursor_change
        target = Connection if boundary == 'early_execute' else app.runtime
        event.listen(target, name, callback, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        execute(session, app, values)
                    session.rollback()
                assert injected and sent == []
        finally:
            event.remove(target, name, callback)
        assert values == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            empty_result(execute(session, app, values))
            session.commit()


def test_repeated_dictionary_reference_keeps_independent_per_occurrence_frames():
    with native_application(False) as app:
        factory = protect(app)
        shared = changes(100, name='same value')
        values, original, bodies = [shared, shared], deepcopy(shared), []
        def observe(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('UPDATE '):
                assert executemany and len(parameters) == 2
                bodies.extend(bytes(group['name'].obj) for group in parameters)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                empty_result(execute(session, app, values))
                session.commit()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert values[0] is values[1] is shared and shared == original
        assert len(bodies) == 2 and bodies[0] != bodies[1]


@pytest.mark.parametrize('fault', ['provider', 'expiry'])
def test_unavailable_bulk_update_keys_leave_no_sql_or_partial_update(fault, monkeypatch):
    with native_application(False) as app:
        run(app)
        publish(app)
        clock = [100.0]
        module = importlib.import_module('cryptalis.crypto.keys')
        monkeypatch.setattr(module, 'time', SimpleNamespace(
            monotonic=lambda: clock[0], monotonic_ns=lambda: int(clock[0]*1e9)))
        class UnavailableProvider(PublicFixtureProvider):
            def unwrap(self, wrapper, context):
                raise OSError('PRIVATE_BULK_UPDATE_PROVIDER_DETAIL')
        class ExpiredRing(Keyring):
            def prepare(self):
                result = super().prepare()
                clock[0] += 2
                return result
        policy = keys(TENANT).policy
        ring = (Keyring(policy, {PROVIDER: UnavailableProvider()}) if fault == 'provider' else
                ExpiredRing(policy, {PROVIDER: PublicFixtureProvider()}, max_age=1))
        selected = [ring]
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=lambda tenant: selected[0], deployment=(app.plan, app.pin))
        values = [changes(100, name='first'), changes(101, name='last')]
        original, before = deepcopy(values), _snapshot(app)
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(KeyUnavailable) as failed:
                    execute(session, app, values)
                assert 'PRIVATE_BULK_UPDATE' not in str(failed.value)
                session.rollback()
            assert sent == []
        assert values == original and _snapshot(app) == before
        selected[0] = keys(TENANT)
        with factory(tenant_id=TENANT) as session:
            empty_result(execute(session, app, values))
            session.commit()


def test_scoped_varchar_update_returning_remains_explicitly_unadmitted():
    with native_application(True) as app:
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT).returning(app.Customer.name),
                    [changes(100, name='fits')], execution_options={'synchronize_session': False})
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('kind', ['expression', 'foreign_column'])
def test_readonly_mapper_properties_refuse_before_keys_and_any_update(kind):
    with native_application(False) as app:
        def add_readonly():
            expression = (func.length(app.table.c.label) if kind == 'expression' else
                          Table('unpersisted_public_table', MetaData(), Column('value', Text)).c.value)
            app.Customer.__mapper__.add_property('read_only', column_property(expression))

        add_readonly()
        values = [changes(100, name='first valid update'), changes(101, read_only=7)]
        original = deepcopy(values)
        # Native persistence ignores the second mapping's read-only property.
        with Session(app.runtime) as session:
            empty_result(execute(session, app, values))
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=100))) == 'first valid update'
            session.rollback()
        with fresh_mapping(app):
            add_readonly()
            resolutions, sent = [], []
            def resolve(tenant):
                resolutions.append(tenant)
                return keys(tenant)
            factory = protect(app, resolver=resolve)
            before = _snapshot(app)
            def collect(connection, cursor, sql, parameters, context, executemany):
                if sql.lstrip().upper().startswith('UPDATE '): sent.append(True)
            event.listen(app.runtime, 'before_cursor_execute', collect)
            try:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    with pytest.raises(UnsupportedProtectedOperation):
                        execute(session, app, values)
                    session.rollback()
                    assert resolutions == sent == []
            finally:
                event.remove(app.runtime, 'before_cursor_execute', collect)
            assert _snapshot(app) == before
        assert values == original


@pytest.mark.parametrize('hook', ['bind_expression', 'load_dialect_impl'])
def test_public_sql_type_hooks_refuse_before_key_work_or_data_sql(hook):
    with native_application(False) as app:
        class PublicProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def bind_expression(self, value):
                return func.concat(value, cast(app.table.c.name, Text))

        dialect_calls = []
        class DialectProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def load_dialect_impl(self, dialect):
                dialect_calls.append(True)
                return Text()

        app.table.c.label.type = (PublicProtectedRead() if hook == 'bind_expression' else DialectProtectedRead())
        values = [changes(101, label='PUBLIC_PREFIX')]
        original = deepcopy(values)
        with Session(app.runtime) as session:
            empty_result(execute(session, app, values))
            assert session.scalar(select(app.Customer.label).where(app.Customer.id == UUID(int=101))) == 'PUBLIC_PREFIX'
            session.rollback()
        with fresh_mapping(app):
            resolutions, sent = [], []
            def resolve(tenant):
                resolutions.append(tenant)
                return keys(tenant)
            factory = protect(app, resolver=resolve)
            before = _snapshot(app)
            def collect(connection, cursor, sql, parameters, context, executemany):
                if sql.lstrip().upper().startswith('UPDATE '): sent.append(True)
            event.listen(app.runtime, 'before_cursor_execute', collect)
            try:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    dialect_calls.clear()
                    with pytest.raises(UnsupportedProtectedOperation):
                        execute(session, app, values)
                    session.rollback()
                    assert resolutions == sent == dialect_calls == []
            finally:
                event.remove(app.runtime, 'before_cursor_execute', collect)
            assert _snapshot(app) == before
        assert values == original


@pytest.mark.parametrize('identity', ['tenant_id', 'id'])
def test_identity_dialect_variant_cannot_retarget_authenticated_update(identity, monkeypatch):
    class EncodedUuid(TypeDecorator):
        impl = Uuid
        cache_ok = True

        def bind_expression(self, value):
            return cast(func.md5(cast(value, Text())), Uuid())

    encoded = lambda value: UUID(hashlib.md5(str(value).encode()).hexdigest())
    input_record = UUID(int=9000)
    target_record = input_record if identity == 'tenant_id' else encoded(input_record)
    target_tenant = encoded(TENANT) if identity == 'tenant_id' else TENANT
    def seed(connection, schema, role):
        connection.exec_driver_sql(
            f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
            (target_record, target_tenant, 'foreign name', 'foreign original'))

    with application(rows=3, setup=seed) as app:
        app.table.c[identity].type = Uuid().with_variant(EncodedUuid(), 'postgresql')
        values = [{'id': input_record, 'label': 'native transformed target'}]
        with fresh_mapping(app):
            with Session(app.runtime) as session:
                empty_result(execute(session, app, values))
                assert session.connection().exec_driver_sql(
                    f'SELECT label FROM "{app.schema}".customer WHERE id=%s', (target_record,)).scalar_one() == 'native transformed target'
                session.rollback()
        with fresh_mapping(app):
            resolutions = []
            def resolve(tenant):
                resolutions.append(tenant)
                return keys(tenant)
            run(app)
            publish(app)
            before = _snapshot(app)
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with pytest.raises(PolicyMismatch):
                    attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                           keys=resolve, deployment=(app.plan, app.pin))
                assert resolutions == sent == []
            assert _snapshot(app) == before


def test_late_public_sql_type_hook_refuses_before_raw_dispatch_without_data_effects(monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        previous = app.table.c.label.type
        class PublicProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def bind_expression(self, value):
                return func.concat(value, cast(app.table.c.name, Text))

        injected = []
        def change(connection, statement, multiparams, params, options):
            if getattr(statement, 'is_update', False):
                injected.append(True)
                app.table.c.label.type = PublicProtectedRead()
            return statement, multiparams, params

        before = _snapshot(app)
        event.listen(app.runtime, 'before_execute', change, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsupportedProtectedOperation):
                        execute(session, app, [changes(101, label='must not expose storage')])
                    session.rollback()
                assert injected and sent == []
        finally:
            event.remove(app.runtime, 'before_execute', change)
            app.table.c.label.type = previous
        assert _snapshot(app) == before
