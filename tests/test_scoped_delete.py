"""Mapped scoped DELETE preserves native results and immutable request context."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String, Uuid, bindparam, cast, delete, event, func, inspect, or_, select
from sqlalchemy.exc import DBAPIError, PendingRollbackError, ResourceClosedError
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.ext.compiler import compiles, deregister
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import ObjectDeletedError
from sqlalchemy.types import TypeDecorator
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter
from sqlalchemy.sql.dml import Delete
from sqlalchemy.sql import operators

from cryptalis.crypto import CryptoFailure, Keyring, KeyUnavailable
from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import assert_aborted, native_application
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT, PROVIDER, PublicFixtureProvider
from test_rewrap_plan import _snapshot
from test_sqlalchemy_adapter import app as adapter_app, db, factory as adapter_factory, TENANT as ADAPTER_TENANT


def scoped(app, identity=UUID(int=101)):
    return delete(app.Customer).where(app.Customer.tenant_id == TENANT, app.Customer.id == identity)


def execute(session, statement):
    return session.execute(statement, execution_options={'synchronize_session': False})


def no_rows(result, count):
    assert result.rowcount == count and result.returns_rows is False
    with pytest.raises(ResourceClosedError):
        result.all()


@pytest.mark.parametrize('varchar', [False, True])
def test_scoped_delete_matches_native_results_and_preserves_other_current_values(varchar):
    def foreign_row(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES(%s,%s,%s,%s)',
            (UUID(int=103), UUID(int=333), None, 'public foreign row'))
    with application(rows=3, value_type=String(4, collation='C') if varchar else None,
                     setup=foreign_row) as app:
        targets = (UUID(int=101), UUID(int=101), UUID(int=999), UUID(int=103))
        with Session(app.runtime) as session:
            expected = [execute(session, scoped(app, identity)).rowcount for identity in targets]
            session.rollback()
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            for identity, count in zip(targets, expected):
                no_rows(execute(session, scoped(app, identity)), count)
            assert len(session.identity_map) == 0
            session.rollback()
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            loaded = session.get(app.Customer, UUID(int=102))
            loaded.name = 'late'
            session.commit()
            no_rows(execute(session, scoped(app)), 1)
            session.commit()
        after = _snapshot(app)
        assert after[0] == before[0] and after[2] == before[2]
        with factory(tenant_id=TENANT) as session:
            assert session.execute(select(app.Customer.id, app.Customer.name).where(
                app.Customer.id.in_([UUID(int=100), UUID(int=102)])).order_by(app.Customer.id)).all() == [
                    (UUID(int=100), None), (UUID(int=102), 'late')]
            assert session.get(app.Customer, UUID(int=101)) is None


def test_false_synchronization_keeps_loaded_identity_until_native_expiry():
    with native_application(False) as app:
        factory = protect(app)
        with factory(tenant_id=TENANT, expire_on_commit=False) as session:
            loaded = session.get(app.Customer, UUID(int=101))
            no_rows(execute(session, scoped(app)), 1)
            assert inspect(loaded).persistent and not inspect(loaded).deleted
            assert session.get(app.Customer, UUID(int=101)) is loaded
            session.commit()
            assert loaded.name == ''
            session.expire(loaded)
            with pytest.raises(ObjectDeletedError):
                _ = loaded.name


@pytest.mark.parametrize('adapter_app', [{'bigint': True}], indirect=True)
def test_scoped_delete_preserves_signed_int64_point_context(adapter_app):
    app = adapter_app
    factory = adapter_factory(app, True)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        session.add_all([app.Customer(id=-(2**63), tenant_id=ADAPTER_TENANT,
            name='public minimum', note='minimum value', rank=0),
            app.Customer(id=0, tenant_id=ADAPTER_TENANT,
            name='public zero', note='zero value', rank=1)])
        session.commit()
        statement = delete(app.Customer).where(app.Customer.tenant_id == ADAPTER_TENANT,
                                                app.Customer.id == -(2**63))
        no_rows(execute(session, statement), 1)
        session.rollback()
        assert session.get(app.Customer, -(2**63)).note == 'minimum value'
        no_rows(execute(session, statement), 1)
        session.commit()
        assert session.get(app.Customer, -(2**63)) is None
        assert session.get(app.Customer, 0).note == 'zero value'


def test_delete_autoflush_failure_and_savepoint_recovery_keep_outer_work(monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT, name='outer', label='kept'))
            session.flush()
            savepoint = session.begin_nested()
            session.add(app.Customer(id=UUID(int=1001), tenant_id=TENANT, name='outer'))
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with pytest.raises(DBAPIError) as failed:
                    execute(session, scoped(app))
                assert failed.value.orig.sqlstate == '23505'
                assert session.is_active is False and sent == []
                with pytest.raises(PendingRollbackError):
                    session.scalar(select(app.Customer.id).where(app.Customer.id == UUID(int=1000)))
            savepoint.rollback()
            assert session.get(app.Customer, UUID(int=1000)).name == 'outer'
            no_rows(execute(session, scoped(app)), 1)
            session.commit()
        with factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=1000)).name == 'outer'
            assert session.get(app.Customer, UUID(int=101)) is None


def test_scoped_delete_native_foreign_key_failure_rolls_back_savepoint_and_retries(adapter_app):
    app = adapter_app
    factory = adapter_factory(app, True)
    parent, child, outer = UUID(int=1000), UUID(int=1001), UUID(int=1002)
    statement = delete(app.Customer).where(app.Customer.tenant_id == ADAPTER_TENANT,
                                            app.Customer.id == parent)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        customer = app.Customer(id=parent, tenant_id=ADAPTER_TENANT, name='referenced', note='value', rank=1)
        customer.articles = [app.Article(id=child, title='native FK')]
        session.add(customer)
        session.commit()
        session.add(app.Customer(id=outer, tenant_id=ADAPTER_TENANT, name='outer', note='kept', rank=2))
        session.flush()
        savepoint = session.begin_nested()
        with pytest.raises(DBAPIError) as failed:
            execute(session, statement)
        assert failed.value.orig.sqlstate == '23503'
        assert_aborted(session)
        savepoint.rollback()
        assert session.get(app.Customer, outer).note == 'kept'
        session.delete(session.get(app.Article, child))
        session.flush()
        no_rows(execute(session, statement), 1)
        session.commit()
    with factory(tenant_id=ADAPTER_TENANT) as session:
        assert session.get(app.Customer, parent) is None
        assert session.get(app.Customer, outer).note == 'kept'


@pytest.mark.parametrize('autoflush', [False, True])
def test_scoped_delete_successful_autoflush_matches_native(autoflush):
    with native_application(False) as app:
        statement = scoped(app, UUID(int=1000))
        options = {'synchronize_session': False, 'autoflush': autoflush}
        with Session(app.runtime) as session:
            session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT, name='kept'))
            expected = session.execute(statement, execution_options=options).rowcount
            session.rollback()
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT, name='kept'))
            no_rows(session.execute(statement, execution_options=options), expected)
            session.commit()
        with factory(tenant_id=TENANT) as session:
            result = session.get(app.Customer, UUID(int=1000))
            assert result is None if autoflush else result.name == 'kept'


def test_async_scoped_delete_keeps_native_result_and_rollback():
    with native_application(True) as app:
        run(app); publish(app)
        before = _snapshot(app)

        async def scenario():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                       keys=keys, deployment=(app.plan, app.pin))
                async with factory(tenant_id=TENANT) as session:
                    no_rows(await session.execute(scoped(app), execution_options={'synchronize_session': False}), 1)
                    await session.rollback()
                    no_rows(await session.execute(scoped(app), execution_options={'synchronize_session': False}), 1)
                    await session.commit()
                async with factory(tenant_id=TENANT) as session:
                    assert await session.get(app.Customer, UUID(int=101)) is None
                    assert (await session.get(app.Customer, UUID(int=102))).name == '雪😀'
            finally:
                await engine.dispose()

        asyncio.run(scenario())
        after = _snapshot(app)
        assert after[0] == before[0] and after[2] == before[2]


@pytest.mark.parametrize('fault', ['missing_scope', 'missing_id', 'wrong_scope', 'or', 'extra',
    'returning', 'core', 'params', 'list', 'sync_zero', 'option', 'id_type', 'scope_hook',
    'required', 'callable', 'expanding', 'literal_execute', 'id_subclass'])
def test_unadmitted_delete_shapes_refuse_before_key_preparation_or_sql(fault):
    with native_application(False) as app:
        resolutions, statements = [], []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        statement, parameters, options = scoped(app), None, {'synchronize_session': False}
        if fault == 'missing_scope': statement = delete(app.Customer).where(app.Customer.id == UUID(int=101))
        elif fault == 'missing_id': statement = delete(app.Customer).where(app.Customer.tenant_id == TENANT)
        elif fault == 'wrong_scope': statement = delete(app.Customer).where(
            app.Customer.tenant_id == UUID(int=999), app.Customer.id == UUID(int=101))
        elif fault == 'or': statement = delete(app.Customer).where(or_(
            app.Customer.tenant_id == TENANT, app.Customer.id == UUID(int=101)))
        elif fault == 'extra': statement = statement.where(app.Customer.label == 'label-101')
        elif fault == 'returning': statement = statement.returning(app.Customer.name.label('unadmitted'))
        elif fault == 'core': statement = delete(app.table).where(
            app.table.c.tenant_id == TENANT, app.table.c.id == UUID(int=101))
        elif fault == 'params': parameters = {'public_extra': UUID(int=101)}
        elif fault == 'list': parameters = [{'public_extra': UUID(int=101)}]
        elif fault == 'sync_zero': options['synchronize_session'] = 0
        elif fault == 'option': options['preserve_rowcount'] = True
        elif fault == 'id_type': statement = scoped(app, str(UUID(int=101)))
        elif fault == 'id_subclass':
            class MutableUUID(UUID):
                def __setattr__(self, name, value):
                    object.__setattr__(self, name, value)
            statement = scoped(app, MutableUUID(int=101))
        elif fault in ('required', 'callable', 'expanding', 'literal_execute'):
            bind = bindparam('record', UUID(int=101), type_=Uuid,
                             **({'required': True} if fault == 'required' else
                                {'callable_': lambda: UUID(int=101)} if fault == 'callable' else
                                {'expanding': True} if fault == 'expanding' else {'literal_execute': True}))
            statement = scoped(app, bind)
        else:
            class Hook(TypeDecorator):
                impl, cache_ok = Uuid, True
                def bind_expression(self, bind):
                    return cast(func.md5(cast(bind, String)), Uuid)
            dtype = Uuid().with_variant(Hook(), 'postgresql')
            statement = delete(app.Customer).where(
                app.Customer.tenant_id == bindparam('scope', TENANT, type_=dtype),
                app.Customer.id == UUID(int=101))
        before = _snapshot(app)
        def observe(*args): statements.append(True)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                with pytest.raises(CryptoFailure):
                    session.execute(statement, parameters, execution_options=options)
                assert resolutions == statements == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert _snapshot(app) == before


def test_distinct_scope_and_record_binds_cannot_share_a_native_placeholder():
    foreign = UUID(int=777)
    def seed(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES(%s,%s,%s,%s)',
                                  (foreign, foreign, None, 'public collision target'))
    with application(rows=3, setup=seed) as app:
        statement = delete(app.Customer).where(
            app.Customer.tenant_id == bindparam('same', TENANT, type_=Uuid),
            app.Customer.id == bindparam('same', foreign, type_=Uuid))
        with Session(app.runtime) as session:
            # Native name merging turns both predicates into the foreign UUID.
            assert execute(session, statement).rowcount == 1
            session.rollback()
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            resolutions.clear()
            with pytest.raises(CryptoFailure):
                execute(session, statement)
            assert resolutions == []
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('boundary,fault', [('early_execute', 'id'), ('execute', 'id'), ('cursor', 'id'),
    ('cursor', 'scope'), ('cursor', 'compiled_and_actual'), ('cursor', 'sql')])
def test_late_delete_mutations_refuse_before_raw_driver_and_retry(boundary, fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        before, injected = _snapshot(app), []

        def execute_change(connection, statement, multiparams, params, options):
            if getattr(statement, 'is_delete', False):
                injected.append(True)
                statement = scoped(app, UUID(int=102))
            return statement, multiparams, params

        def cursor_change(connection, cursor, sql, parameters, context, executemany):
            if sql.lstrip().upper().startswith('DELETE '):
                injected.append(True)
                assert not executemany and type(parameters) is dict
                if fault == 'sql':
                    sql += ' /* public changed DELETE */'
                else:
                    original = TENANT if fault == 'scope' else UUID(int=101)
                    name = next(key for key, value in parameters.items() if value == original)
                    parameters[name] = UUID(int=999) if fault == 'scope' else UUID(int=102)
                    if fault == 'compiled_and_actual':
                        context.compiled_parameters[0][name] = parameters[name]
            return sql, parameters

        event_name = 'before_execute' if boundary.endswith('execute') else 'before_cursor_execute'
        callback = execute_change if boundary.endswith('execute') else cursor_change
        target = Connection if boundary == 'early_execute' else app.runtime
        event.listen(target, event_name, callback, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        execute(session, scoped(app))
                    session.rollback()
                assert injected and sent == []
        finally:
            event.remove(target, event_name, callback)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            no_rows(execute(session, scoped(app)), 1)
            session.rollback()
        assert _snapshot(app) == before


def test_scoped_delete_keeps_existing_provider_preparation_boundary(monkeypatch):
    with native_application(False) as app:
        run(app); publish(app)
        class Unavailable(PublicFixtureProvider):
            def unwrap(self, wrapper, context):
                raise OSError('PRIVATE_DELETE_PROVIDER_DETAIL')
        selected = [Keyring(keys(TENANT).policy, {PROVIDER: Unavailable()})]
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
            keys=lambda tenant: selected[0], deployment=(app.plan, app.pin))
        before = _snapshot(app)
        with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(KeyUnavailable) as failed:
                    execute(session, scoped(app))
                assert 'PRIVATE_DELETE' not in str(failed.value)
                session.rollback()
            assert sent == []
        assert _snapshot(app) == before
        selected[0] = keys(TENANT)
        with factory(tenant_id=TENANT) as session:
            no_rows(execute(session, scoped(app)), 1)
            session.rollback()


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_provider_callback_cannot_retarget_original_delete_before_permit(mode, monkeypatch):
    with native_application(False) as app:
        run(app); publish(app)
        statement, armed, retargeted = scoped(app), [False], []
        def resolve(tenant):
            if armed[0] and not retargeted:
                for node in visitors.iterate(statement):
                    if isinstance(node, BindParameter) and node.value == UUID(int=101):
                        node.value = UUID(int=102)
                        retargeted.append(True)
            return keys(tenant)
        before = _snapshot(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                             keys=resolve, deployment=(app.plan, app.pin))
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with factory(tenant_id=TENANT) as session:
                    armed[0] = True
                    with pytest.raises(CryptoFailure):
                        execute(session, statement)
                    session.rollback()
                assert retargeted == [True] and sent == []
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                           keys=resolve, deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, 'DELETE', asynchronous=True) as sent:
                        async with factory(tenant_id=TENANT) as session:
                            armed[0] = True
                            with pytest.raises(CryptoFailure):
                                await session.execute(statement, execution_options={'synchronize_session': False})
                            await session.rollback()
                        assert retargeted == [True] and sent == []
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert _snapshot(app) == before


@pytest.mark.parametrize('kind', ['bind', 'predicate', 'statement'])
def test_sql_producing_ast_subclasses_cannot_weaken_original_delete_scope(kind, monkeypatch):
    foreign = UUID(int=777)
    def seed(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES(%s,%s,%s,%s)',
                                  (foreign, foreign, None, 'public AST target'))
    with application(rows=3, setup=seed) as app:
        base = {'bind': BindParameter, 'predicate': BinaryExpression, 'statement': Delete}[kind]
        custom = type('PublicDeleteInjection', (base,), {'inherit_cache': False})
        @compiles(custom, 'postgresql')
        def render(node, compiler, **kw):
            if kind == 'bind': return compiler.visit_bindparam(node, **kw) + ' OR TRUE'
            if kind == 'predicate': return '(' + compiler.visit_binary(node, **kw) + ' OR TRUE)'
            return compiler.visit_delete(node, **kw) + ' OR TRUE'
        try:
            if kind == 'bind':
                statement = delete(app.Customer).where(
                    app.Customer.tenant_id == custom('scope', TENANT, type_=Uuid),
                    app.Customer.id == foreign)
            elif kind == 'predicate':
                statement = delete(app.Customer).where(custom(app.table.c.tenant_id,
                    bindparam('scope', TENANT, type_=Uuid), operators.eq), app.Customer.id == foreign)
            else:
                statement = custom(app.Customer).where(app.Customer.tenant_id == TENANT,
                                                        app.Customer.id == foreign)
            with Session(app.runtime) as session:
                assert execute(session, statement).rowcount > 0
                session.rollback()
            resolutions = []
            def resolve(tenant):
                resolutions.append(tenant)
                return keys(tenant)
            factory = protect(app, resolver=resolve)
            before = _snapshot(app)
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    with pytest.raises(CryptoFailure):
                        execute(session, statement)
                    assert resolutions == []
                    session.rollback()
                assert sent == []
            assert _snapshot(app) == before
        finally:
            deregister(custom)


@pytest.mark.parametrize('method', ['scalar', 'scalars', 'stream', 'stream_scalars'])
def test_async_non_execute_delete_refuses_before_provider_or_sql(method, monkeypatch):
    with native_application(False) as app:
        run(app); publish(app)
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        before = _snapshot(app)
        async def scenario():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                       keys=resolve, deployment=(app.plan, app.pin))
                with raw_calls(monkeypatch, app.schema, 'DELETE', asynchronous=True) as sent:
                    async with factory(tenant_id=TENANT) as session:
                        resolutions.clear()
                        with pytest.raises(CryptoFailure):
                            await getattr(session, method)(scoped(app), execution_options={'synchronize_session': False})
                        assert resolutions == []
                        await session.rollback()
                    assert sent == []
            finally:
                await engine.dispose()
        asyncio.run(scenario())
        assert _snapshot(app) == before


@pytest.mark.parametrize('method', ['scalar', 'scalars'])
def test_sync_non_execute_delete_refuses_before_provider_or_sql(method, monkeypatch):
    with native_application(False) as app:
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        before = _snapshot(app)
        with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                with pytest.raises(CryptoFailure):
                    getattr(session, method)(scoped(app), execution_options={'synchronize_session': False})
                assert resolutions == []
                session.rollback()
            assert sent == []
        assert _snapshot(app) == before
