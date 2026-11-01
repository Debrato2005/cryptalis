"""Native JSON hooks and mutable assignments cannot bypass protected admission."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.types import json as json_adapters
import pytest
from sqlalchemy import create_engine, event, insert, select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_driver_event_boundary import raw_calls
from test_jsonb_storage import application, mapping_for, protect, state
from test_migration import PROVIDER, TENANT, PublicFixtureProvider, engine, keys


TARGET, ADDED = UUID(int=100), UUID(int=950)
OPTIONS = {'synchronize_session': False}


def stored_rows(app):
    with app.owner.connect() as connection:
        return connection.exec_driver_sql(
            f'SELECT id,tenant_id,name,label FROM "{app.schema}".customer ORDER BY id').all()


class CallbackProvider(PublicFixtureProvider):
    def __init__(self, change=lambda: None):
        self.change, self.armed = change, False
        self.changed, self.preparations = [], []

    def mutate(self):
        if self.armed and not self.changed:
            self.change()
            self.changed.append(True)

    def unwrap(self, wrapper, context):
        self.preparations.append('sync')
        self.mutate()
        return super().unwrap(wrapper, context)

    async def unwrap_async(self, wrapper, context):
        await asyncio.sleep(0)
        self.preparations.append('async')
        self.mutate()
        return super().unwrap(wrapper, context)

    def resolve(self, tenant):
        return Keyring(keys(tenant).policy, {PROVIDER: self})


@contextmanager
def attached(app, provider, *, mutable=False, database=None):
    mapping, _, Model = mapping_for(app.schema, app.none_as_null, mutable)
    database = database if database is not None else engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        factory = attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                         deployment=(app.plan, app.pin))
        yield Model, factory, database
    finally:
        database.dispose()
        mapping.dispose()


def request(Model, route, value):
    if route == 'bulk_insert':
        return insert(Model), [{'id': ADDED, 'tenant_id': TENANT, 'name': value}]
    clause = update(Model).where(Model.tenant_id == TENANT)
    if route == 'scoped_parameters':
        return clause, [{'id': TARGET, 'name': value}]
    clause = clause.where(Model.id == TARGET)
    return (clause.values(name=value), None) if route == 'point_values' else (clause, {'name': value})


def write(session, Model, route, value):
    if route == 'flush':
        session.get(Model, TARGET).name = value
        session.flush()
    else:
        clause, parameters = request(Model, route, value)
        session.execute(clause, parameters, execution_options={} if route == 'bulk_insert' else OPTIONS)


def written_value(session, Model, route):
    session.expire_all()
    return state(session.get(Model, ADDED if route == 'bulk_insert' else TARGET).name)


def mutation(route, value):
    if route == 'flush':
        value['nested'][0] = 1  # Python equality hides bool -> int.
    elif route == 'bulk_insert':
        value['nested'][1] = 1  # Python equality hides float -> int.
    elif route == 'point_values':
        value['nested'][2] = 0.0  # Preserve the distinction in captured input state.
    else:
        value['first'] = value.pop('first')  # Same mapping, different input order.


@pytest.mark.parametrize('route', ['flush', 'bulk_insert', 'point_values', 'external_parameters'])
def test_jsonb_provider_cannot_mutate_captured_sync_assignment(route, monkeypatch):
    original = {'first': 'unchanged', 'nested': [True, 1.0, -0.0]}
    with application(mutable=route == 'flush') as app:
        with Session(app.runtime) as native:
            write(native, app.Customer, route, deepcopy(original))
            expected = written_value(native, app.Customer, route)
            native.rollback()
        protect(app)
        value = deepcopy(original)
        provider = CallbackProvider(lambda: mutation(route, value))
        before = stored_rows(app)
        verb = 'INSERT' if route == 'bulk_insert' else 'UPDATE'
        with attached(app, provider, mutable=route == 'flush') as (Model, factory, _):
            with raw_calls(monkeypatch, app.schema, verb) as calls:
                with factory(tenant_id=TENANT) as session:
                    if route == 'flush':
                        row = session.get(Model, TARGET)
                        row.name = value
                        value = row.name  # MutableDict wraps the assigned dictionary.
                    provider.armed = True
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.flush() if route == 'flush' else write(session, Model, route, value)
                    provider.armed = False
                    session.rollback()
                    assert provider.changed == [True] and value == original and calls == []
                    assert stored_rows(app) == before
                    write(session, Model, route, deepcopy(original))
                    session.commit()
                    assert written_value(session, Model, route) == expected
                assert calls  # The same native collector observes the healthy write.


def test_jsonb_scoped_update_refuses_nested_mutation_after_provider_await(monkeypatch):
    original = {'nested': [1, True, -0.0], 'other': 'unchanged'}
    with application() as app:
        with Session(app.runtime) as native:
            write(native, app.Customer, 'scoped_parameters', deepcopy(original))
            expected = written_value(native, app.Customer, 'scoped_parameters')
            native.rollback()
        protect(app)
        value = deepcopy(original)
        provider = CallbackProvider(lambda: value.update(nested=tuple(value['nested'])))
        before = stored_rows(app)

        async def run():
            mapping, _, Model = mapping_for(app.schema, app.none_as_null)
            database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                                       deployment=(app.plan, app.pin))
                clause, parameters = request(Model, 'scoped_parameters', value)
                with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as calls:
                    async with factory(tenant_id=TENANT) as session:
                        provider.armed = True
                        with pytest.raises(UnsupportedProtectedOperation):
                            await session.execute(clause, parameters, execution_options=OPTIONS)
                        provider.armed = False
                        await session.rollback()
                        assert provider.changed == [True] and 'async' in provider.preparations and calls == []
                        assert json.dumps(value) == json.dumps(original)  # The nested Python type still changed.
                        assert stored_rows(app) == before
                        healthy, parameters = request(Model, 'scoped_parameters', deepcopy(original))
                        await session.execute(healthy, parameters, execution_options=OPTIONS)
                        await session.commit()
                        session.expire_all()
                        row = await session.get(Model, TARGET)
                        assert state(row.name) == expected
                    assert calls
            finally:
                await database.dispose()
                mapping.dispose()
        asyncio.run(run())


def native_hook_use(app, database, *, loader):
    with Session(database) as native:
        if loader:
            assert native.scalar(select(app.Customer.name).where(app.Customer.id == TARGET)) is not None
        else:
            native.execute(update(app.Customer).where(app.Customer.id == TARGET).values(name={'native hook': True}))
        native.rollback()


def test_jsonb_global_json_hooks_are_native_but_refuse_before_protected_keys(monkeypatch):
    seen = []
    def loads(data):
        seen.append('load')
        return json.loads(data)
    def dumps(value):
        seen.append('dump')
        return json.dumps(value)
    try:
        with application() as app:
            for loader, setter, hook, default in (
                (True, json_adapters.set_json_loads, loads, json.loads),
                (False, json_adapters.set_json_dumps, dumps, json.dumps),
            ):
                setter(hook)
                try:
                    native_hook_use(app, app.runtime, loader=loader)
                finally:
                    setter(default)
            assert 'load' in seen and 'dump' in seen
            protect(app)
            before = stored_rows(app)
            provider = CallbackProvider()
            with attached(app, provider) as (Model, factory, _):
                with factory(tenant_id=TENANT) as session:
                    with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                        for setter, hook, default in (
                            (json_adapters.set_json_loads, loads, json.loads),
                            (json_adapters.set_json_dumps, dumps, json.dumps),
                        ):
                            provider.preparations.clear(); seen.clear()
                            setter(hook)
                            try:
                                with pytest.raises(CryptoFailure):
                                    session.execute(select(Model.name).where(Model.id == TARGET))
                            finally:
                                setter(default)
                            session.rollback()
                            assert provider.preparations == [] and seen == [] and calls == []
                            assert stored_rows(app) == before
                            calls.clear()  # Exclude the owner observation from the next protected attempt.
                        json_adapters.register_default_adapters(psycopg)
                        assert session.scalar(select(Model.name).where(Model.id == TARGET)) is not None
                        assert provider.preparations and calls
    finally:
        json_adapters.set_json_loads(json.loads)
        json_adapters.set_json_dumps(json.dumps)
        json_adapters.register_default_adapters(psycopg)


def test_jsonb_sqlalchemy_json_options_refuse_before_protected_keys(monkeypatch):
    with application() as app:
        seen, databases = [], []
        def loads(data):
            seen.append('load')
            return json.loads(data)
        def dumps(value):
            seen.append('dump')
            return json.dumps(value)
        try:
            for option, hook, loader in (('json_deserializer', loads, True), ('json_serializer', dumps, False)):
                database = create_engine('postgresql+psycopg://', hide_parameters=True,
                    connect_args=conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']),
                    **{option: hook})
                databases.append(database)
                previous = len(seen)
                native_hook_use(app, database, loader=loader)
                assert ('load' if loader else 'dump') in seen[previous:]
            assert 'load' in seen and 'dump' in seen
            protect(app)
            before = stored_rows(app)
            provider = CallbackProvider()
            for database in databases:
                with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                    with pytest.raises(CryptoFailure):
                        with attached(app, provider, database=database):
                            pytest.fail('Custom JSON engine options were admitted.')
                    assert provider.preparations == [] and calls == [] and stored_rows(app) == before
            with attached(app, provider) as (Model, factory, _):
                with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                    with factory(tenant_id=TENANT) as session:
                        assert session.scalar(select(Model.name).where(Model.id == TARGET)) is not None
                    assert provider.preparations and calls
        finally:
            for database in databases:
                database.dispose()


def test_jsonb_connection_hooks_refuse_initial_attach_and_reconnect_before_keys(monkeypatch):
    with application() as app:
        armed, installed, loaded = [True], [], []
        def loads(data):
            loaded.append(True)
            return json.loads(data)
        def configure(connection, record):
            json_adapters.register_default_adapters(connection)
            if armed[0]:
                json_adapters.set_json_loads(loads, connection)
            installed.append(armed[0])
        database = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        event.listen(database, 'connect', configure)
        mapping, _, Model = mapping_for(app.schema, app.none_as_null)
        provider = CallbackProvider()
        try:
            native_hook_use(app, database, loader=True)
            assert installed and loaded
            protect(app)
            before = stored_rows(app)
            with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                with pytest.raises(CryptoFailure):
                    attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                           deployment=(app.plan, app.pin))
                assert provider.preparations == [] and calls == []
                armed[0] = False
                database.dispose()
                factory = attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                                 deployment=(app.plan, app.pin))
                with factory(tenant_id=TENANT) as session:
                    assert session.scalar(select(Model.name).where(Model.id == TARGET)) is not None
                assert calls and provider.preparations and False in installed
                calls.clear(); provider.preparations.clear()
                database.dispose()
                armed[0] = True
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(select(Model.name).where(Model.id == TARGET))
                    session.rollback()
                assert calls == [] and provider.preparations == [] and installed[-1] is True
                assert stored_rows(app) == before
                calls.clear()  # The raw owner SELECT is not the protected query's positive control.
                armed[0] = False
                database.dispose()
                with factory(tenant_id=TENANT) as session:
                    assert session.scalar(select(Model.name).where(Model.id == TARGET)) is not None
                assert calls and provider.preparations and installed[-1] is False
        finally:
            event.remove(database, 'connect', configure)
            database.dispose(); mapping.dispose()


def test_jsonb_cursor_local_hook_refuses_before_dispatch_and_default_cursor_retries(monkeypatch):
    with application() as app:
        armed, installed, loaded = [True], [], []
        def loads(data):
            loaded.append(True)
            return json.loads(data)
        class HookCursor(psycopg.Cursor):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                json_adapters.register_default_adapters(self)
                if armed[0]:
                    json_adapters.set_json_loads(loads, self)
                    installed.append(True)
        database = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], cursor_factory=HookCursor))
        provider = CallbackProvider()
        try:
            native_hook_use(app, database, loader=True)
            assert installed and loaded
            protect(app)
            before = stored_rows(app)
            armed[0] = False
            database.dispose()
            with attached(app, provider, database=database) as (Model, factory, _):
                installed.clear(); loaded.clear()
                with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                    armed[0] = True
                    with factory(tenant_id=TENANT) as session:
                        with pytest.raises(CryptoFailure):
                            session.execute(select(Model.name).where(Model.id == TARGET))
                        session.rollback()
                    # This hook is installed on cursor creation, after key admission.
                    assert installed and loaded == [] and calls == []
                    assert stored_rows(app) == before
                    calls.clear()
                    armed[0] = False
                    with factory(tenant_id=TENANT) as session:
                        assert session.scalar(select(Model.name).where(Model.id == TARGET)) is not None
                    assert calls
        finally:
            database.dispose()
