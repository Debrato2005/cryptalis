"""Reusable mapped point UPDATE binds compared with native PostgreSQL."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone, tzinfo
from decimal import Decimal
from inspect import isawaitable
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import BigInteger, DateTime, Numeric, SmallInteger, String, Text, Uuid, bindparam, event, func, select, update
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP
from sqlalchemy.exc import DBAPIError, IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, registry
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_jsonb_boundaries import CallbackProvider, stored_rows
from test_jsonb_storage import state
from test_migration import TABLE_ID, TENANT, application, engine as native_engine, keys, publish, run
from test_point_update_rows import columns, selection
from test_point_update_returning_more import CASES
from test_rewrap_plan import _snapshot
from test_scoped_delete import no_rows
from test_search_retained_readers import remove_current
from test_single_tenant_update import single_application
from test_sqlalchemy_adapter import (app as adapter_app, db, factory as adapter_factory,
                                     TENANT as ADAPTER_TENANT)


OPTIONS = {'synchronize_session': False}


async def completed(value):
    return await value if isawaitable(value) else value


@contextmanager
def observed_updates(engine, protected):
    def actual(value):
        if type(value) is psycopg.Binary:
            return bytes(value.obj)
        if type(value) is dict:
            return {key: actual(part) for key, part in value.items()}
        if type(value) in (list, tuple):
            return tuple(actual(part) for part in value)
        return value
    sent = []
    def observe(connection, cursor, sql, values, context, many):
        if sql.lstrip().upper().startswith('UPDATE '):
            sent.append((sql, repr(actual(values))))
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        yield
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
    assert sent
    marker = 'PUBLIC first'
    assert all(marker not in sql for sql, _ in sent)
    assert any(marker in values for _, values in sent) is (not protected)


def point(app, fixed=False):
    identity, _, _ = columns(app, fixed)
    statement = update(app.Customer).where(identity == bindparam('row_id', UUID(int=101), type_=Uuid()))
    return statement if fixed else statement.where(
        app.Customer.tenant_id == bindparam('scope_id', TENANT, type_=Uuid()))


def assignments(app, fixed=False):
    return point(app, fixed).values(**{
        'value' if fixed else 'name': bindparam('replacement', 'PUBLIC default', type_=Text()),
        'public' if fixed else 'label': bindparam('public_value', 'public default'),
    })


async def journey(app, session, fixed, execute, *, commit):
    """The same request is reused across identities and a recovered savepoint."""
    identity, protected, public = columns(app, fixed)
    attribute = 'value' if fixed else 'name'
    statement = assignments(app, fixed)
    compiled = statement.compile()
    original_statement = str(compiled), deepcopy(compiled.params)
    loaded = await completed(session.get(app.Customer, UUID(int=101)))
    original = getattr(loaded, attribute)
    no_rows(await completed(execute(statement, execution_options=OPTIONS)), 1)
    assert getattr(loaded, attribute) == original
    assert await completed(session.get(app.Customer, UUID(int=101))) is loaded
    await completed(session.refresh(loaded))
    assert getattr(loaded, attribute) == 'PUBLIC default'
    no_rows(await completed(execute(statement, params={'row_id': UUID(int=999)},
        execution_options=OPTIONS)), 0)

    display, visible = protected.label('display_value'), public.label('visible_label')
    labelled = statement.returning(identity, display, visible)
    observations = []
    for number, replacement in ((100, 'PUBLIC first'), (100, 'PUBLIC second'), (999, 'PUBLIC missing')):
        parameters = {'row_id': UUID(int=number), 'replacement': replacement, 'public_value': 'public override'}
        captured = deepcopy(parameters)
        result = await completed(execute(labelled, params=parameters,
            execution_options=OPTIONS))
        names, rows = tuple(result.keys()), result.all()
        assert names == ('record' if fixed else 'id', 'display_value', 'visible_label')
        if rows:
            row = rows[0]
            assert row._mapping[display] == replacement
            assert row._mapping[visible] == 'public override'
        observations.append((names, [tuple(row) for row in rows],
                             [tuple(type(value) for value in row) for row in rows]))
        assert parameters == captured

    entity = await completed(execute(statement.returning(app.Customer), params={
        'row_id': UUID(int=102), 'replacement': 'PUBLIC entity', 'public_value': 'public entity'},
        execution_options=OPTIONS))
    assert tuple(entity.keys()) == ('Customer',)
    returned = entity.scalar_one()
    assert returned in session and getattr(returned, attribute) == 'PUBLIC entity'
    assert await completed(session.get(app.Customer, UUID(int=102))) is returned

    mixed = point(app, fixed).values(**{
        attribute: bindparam('replacement', type_=String()), 'public' if fixed else 'label': 'public literal'})
    no_rows(await completed(execute(mixed, params={'row_id': UUID(int=100), 'replacement': 'PUBLIC mixed'},
        execution_options=OPTIONS)), 1)
    no_rows(await completed(execute(mixed, params={'row_id': UUID(int=100), 'replacement': None},
        execution_options=OPTIONS)), 1)
    assert await completed(session.scalar(select(protected).where(identity == UUID(int=100)))) is None

    # Native single-statement dictionaries use physical keys even on a renamed mapping.
    no_rows(await completed(execute(point(app, fixed), params={
        'row_id': UUID(int=100), 'name': 'PUBLIC external', 'label': 'public external'},
        execution_options=OPTIONS)), 1)
    literal = point(app, fixed).values(**{attribute: 'PUBLIC initial',
                                        'public' if fixed else 'label': 'public initial'})
    no_rows(await completed(execute(literal, params={
        'row_id': UUID(int=100), 'name': 'PUBLIC literal override', 'label': 'public literal override'},
        execution_options=OPTIONS)), 1)

    if not fixed:
        # begin_nested() flushes unrelated outer work before the unique failure.
        outer = await completed(session.get(app.Customer, UUID(int=100)))
        outer.label = 'public outer edit'
        savepoint = await completed(session.begin_nested())
        with pytest.raises(IntegrityError) as failed:
            await completed(execute(statement, params={'replacement': 'PUBLIC entity'},
                execution_options=OPTIONS))
        assert failed.value.orig.sqlstate == '23505'
        await completed(savepoint.rollback())
        assert outer.label == 'public outer edit'
        assert getattr(await completed(session.get(app.Customer, UUID(int=101))), attribute) == 'PUBLIC default'
    no_rows(await completed(execute(statement, params={'replacement': 'PUBLIC latest'},
        execution_options=OPTIONS)), 1)
    compiled = statement.compile()
    assert (str(compiled), compiled.params) == original_statement
    observed = [tuple(row) for row in (await completed(execute(selection(app, fixed)))).all()]
    await completed(session.commit() if commit else session.rollback())
    return observations, observed


@pytest.mark.parametrize('fixed,mode', [(False, 'sync'), (False, 'async'), (True, 'sqlmodel_async')])
def test_reusable_point_binds_native_results_state_recovery_and_current_exit(fixed, mode):
    with (single_application() if fixed else application(rows=3)) as app:
        tenant = TABLE_ID if fixed else TENANT

        def synchronous(factory=None):
            with observed_updates(app.runtime, factory is not None), \
                    (factory(tenant_id=tenant) if factory else Session(app.runtime)) as session:
                return asyncio.run(journey(app, session, fixed, session.execute, commit=factory is not None))

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                pytest.importorskip('sqlmodel', reason='optional SQLModel parameterized point UPDATE')
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                with observed_updates(engine.sync_engine, protected):
                    async with (factory(tenant_id=tenant) if protected else native(engine)) as session:
                        execute = session.exec if mode == 'sqlmodel_async' else session.execute
                        return await journey(app, session, fixed, execute, commit=protected)
            finally:
                await engine.dispose()

        expected = synchronous() if mode == 'sync' else asyncio.run(asynchronous(False))
        properties = {'record': app.table.c.id, 'value': app.table.c.name,
                      'public': app.table.c.label} if fixed else None
        with fresh_mapping(app, properties=properties):
            run(app); publish(app)
            if mode == 'sync':
                factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin))
                actual = synchronous(factory)
            else:
                actual = asyncio.run(asynchronous(True))
            assert actual == expected
            remove_current(app, keys)
            with app.owner.connect() as connection:
                latest = connection.exec_driver_sql(
                    f'SELECT id,name,label FROM "{app.schema}".customer ORDER BY id').all()
            assert [tuple(row) for row in latest] == expected[1]


@pytest.mark.parametrize('adapter_app', [{'bigint': True}], indirect=True)
def test_named_binds_reuse_signed_int64_records_and_multiple_protected_outputs(adapter_app):
    app = adapter_app
    identities = (-2**63, 2**63 - 1)

    def exercise(factory):
        with factory(tenant_id=ADAPTER_TENANT) as session:
            session.add_all(app.Customer(id=identity, tenant_id=ADAPTER_TENANT,
                name=f'public {index}', note='original note', secret='original secret', rank=index)
                for index, identity in enumerate(identities))
            session.flush()
            statement = update(app.Customer).where(app.Customer.id == bindparam('row_id', type_=BigInteger()),
                app.Customer.tenant_id == bindparam('scope_id', ADAPTER_TENANT, type_=Uuid())).values(
                    note=bindparam('replacement'), secret=bindparam('other_value')).returning(
                        app.Customer.id, app.Customer.note, app.Customer.secret)
            observed = []
            for identity, value in zip(identities, ('PUBLIC minimum', None)):
                result = session.execute(statement, {'row_id': identity,
                    'replacement': value, 'other_value': 'PUBLIC second field'}, execution_options=OPTIONS)
                assert tuple(result.keys()) == ('id', 'note', 'secret')
                row = result.one()
                assert type(row[0]) is int and row == (identity, value, 'PUBLIC second field')
                observed.append(tuple(row))
            session.rollback()
            return observed

    expected = exercise(adapter_factory(app, False))
    previous = app.mapping, app.Customer
    mapping = registry(metadata=app.mapping.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, app.Customer.__table__)
    app.mapping, app.Customer = mapping, Customer
    try:
        assert exercise(adapter_factory(app, True)) == expected
    finally:
        app.mapping, app.Customer = previous
        mapping.dispose()


@pytest.mark.parametrize('dtype,value,expected', CASES + [
    (BigInteger(), 2**63 - 1, 2**63 - 1),
    (Numeric(8, 2), Decimal('1.235'), Decimal('1.24')),
    (DateTime(), datetime(2040, 2, 29, 12, 34, 56, 123456),
     datetime(2040, 2, 29, 12, 34, 56, 123456)),
    (DateTime(timezone=True), datetime(2040, 2, 29, 12, 34, 56, 123456, tzinfo=timezone.utc),
     datetime(2040, 2, 29, 12, 34, 56, 123456, tzinfo=timezone.utc)),
    (TIMESTAMP(precision=6, timezone=False), datetime(2040, 2, 29, 12, 34, 56, 123456),
     datetime(2040, 2, 29, 12, 34, 56, 123456)),
    (TIMESTAMP(precision=6, timezone=True), datetime(2040, 2, 29, 12, 34, 56, 123456, tzinfo=timezone.utc),
     datetime(2040, 2, 29, 12, 34, 56, 123456, tzinfo=timezone.utc)),
])
def test_explicit_native_scalar_bind_roundtrips_match_assignment_and_null(dtype, value, expected):
    with application(rows=2, value_type=dtype, protected_values=(None, None), queries=[]) as app:
        def exercise(factory=None):
            statement = point(app).values(name=bindparam('replacement', type_=dtype)).returning(app.Customer.name)
            observed = []
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                for replacement in (value, None):
                    result = session.execute(statement, {'replacement': replacement}, execution_options=OPTIONS)
                    stored = result.scalar_one()
                    wanted = expected if replacement is not None else None
                    assert type(stored) is type(wanted) and stored == wanted
                    observed.append(stored.as_tuple() if type(stored) is Decimal else stored)
                session.rollback()
            return observed
        native = exercise()
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))
            assert exercise(factory) == native


class UpperText(TypeDecorator):
    impl, cache_ok = Text, True

    def bind_expression(self, value):
        return func.upper(value)


def test_unsupported_named_requests_refuse_before_keys_with_native_processor_control(monkeypatch):
    with application(rows=3) as app:
        def custom():
            return point(app).values(name=bindparam('replacement', type_=UpperText()))
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            with Session(app.runtime) as session:
                result = session.execute(custom().returning(app.Customer.name),
                    {'replacement': 'public processor input'}, execution_options=OPTIONS)
                assert result.scalar_one() == 'PUBLIC PROCESSOR INPUT'
                session.rollback()
            assert sent  # The raw observer sees a real native UPDATE.
        preparations = []
        def resolve(tenant):
            preparations.append(tenant)
            return keys(tenant)
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                deployment=(app.plan, app.pin))
            before = _snapshot(app)
            requests = [
                (point(app).values(name=bindparam('replacement')), {}),
                (assignments(app), {'scope_id': UUID(int=999)}),
                (point(app).values(name=bindparam('replacement', callable_=lambda: 'PUBLIC callback')), {}),
                (custom(), {'replacement': 'public processor input'}),
                (assignments(app), {'unmatched_parameter': 'PUBLIC extra'}),
                (assignments(app), {'row_id': str(UUID(int=101))}),
            ]
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                preparations.clear()
                for statement, parameters in requests:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement, parameters, execution_options=OPTIONS)
                    session.rollback()
                assert preparations == sent == []
                no_rows(session.execute(assignments(app), execution_options=OPTIONS), 1)
                assert preparations and sent
                session.rollback()
            assert _snapshot(app) == before


def test_narrower_integer_bind_cast_is_not_discarded(monkeypatch):
    with application(rows=2, value_type=BigInteger(), protected_values=(0, 1), queries=[]) as app:
        def narrowed():
            return point(app).values(name=bindparam('replacement', 32768, type_=SmallInteger()))
        with Session(app.runtime) as session:
            with pytest.raises(DBAPIError) as failed:
                session.execute(narrowed(), execution_options=OPTIONS)
            assert failed.value.orig.sqlstate == '22003'
            session.rollback()
        preparations = []
        def resolve(tenant):
            preparations.append(True)
            return keys(tenant)
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                preparations.clear()
                with pytest.raises(CryptoFailure):
                    session.execute(narrowed(), execution_options=OPTIONS)
                assert preparations == sent == []
                session.rollback()
                safe = point(app).values(name=bindparam('replacement', 32768, type_=BigInteger()))
                no_rows(session.execute(safe, execution_options=OPTIONS), 1)
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == 32768
                assert preparations and sent
                session.rollback()


def test_duplicate_named_defaults_keep_native_joint_binding_and_refuse_before_keys(monkeypatch):
    with application(rows=3) as app:
        def repeated_where():
            return update(app.Customer).where(
                app.Customer.id == bindparam('same', UUID(int=101), type_=Uuid()),
                app.Customer.tenant_id == bindparam('same', TENANT, type_=Uuid())).values(name='PUBLIC repeated where')
        def repeated_set():
            return point(app).values(name=bindparam('same', 'PUBLIC first', type_=Text()),
                                     label=bindparam('same', 'PUBLIC second', type_=Text()))
        native_before = stored_rows(app)
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            with Session(app.runtime) as session:
                # One native placeholder cannot simultaneously equal these distinct UUIDs.
                no_rows(session.execute(repeated_where(), execution_options=OPTIONS), 0)
                result = session.execute(repeated_set().returning(app.Customer.name, app.Customer.label),
                    execution_options=OPTIONS)
                value, label = result.one()
                assert value == label and value in ('PUBLIC first', 'PUBLIC second')
                session.rollback()
            assert len(sent) == 2
        assert stored_rows(app) == native_before
        preparations = []
        def resolve(tenant):
            preparations.append(tenant)
            return keys(tenant)
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                deployment=(app.plan, app.pin))
            before = _snapshot(app)
            requests = (repeated_where(), repeated_set())
            snapshots = [(str(compiled), deepcopy(compiled.params))
                         for compiled in (request.compile() for request in requests)]
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                preparations.clear()
                for request in requests:
                    with pytest.raises(CryptoFailure):
                        session.execute(request, execution_options=OPTIONS)
                    session.rollback()
                assert preparations == sent == []
                assert [(str(compiled), compiled.params)
                        for compiled in (request.compile() for request in requests)] == snapshots
                no_rows(session.execute(assignments(app), execution_options=OPTIONS), 1)
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == 'PUBLIC default'
                assert preparations and sent
                session.rollback()
            assert _snapshot(app) == before


def test_class_sql_hook_changed_during_provider_preparation_refuses_and_recovers(monkeypatch):
    with application(rows=3) as app:
        def uppercase(self, value):
            return func.upper(value)
        def statement():
            return point(app).values(name=bindparam('replacement', 'public class hook', type_=Text())).returning(
                app.Customer.name)
        native_before = stored_rows(app)
        with monkeypatch.context() as patch:
            patch.setattr(String, 'bind_expression', uppercase)
            # A fresh dialect observes the class hook without a warmed native type cache.
            engine = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
            try:
                with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                    with Session(engine) as session:
                        assert session.execute(statement(), execution_options=OPTIONS).scalar_one() == 'PUBLIC CLASS HOOK'
                        session.rollback()
                    assert sent
            finally:
                engine.dispose()
        assert stored_rows(app) == native_before
        with fresh_mapping(app):
            run(app); publish(app)
            provider = CallbackProvider()
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=provider.resolve,
                deployment=(app.plan, app.pin))
            request, before = statement(), _snapshot(app)
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                with monkeypatch.context() as patch:
                    provider.change = lambda: patch.setattr(String, 'bind_expression', uppercase)
                    provider.preparations.clear(); provider.armed = True
                    with pytest.raises(CryptoFailure):
                        session.execute(request, execution_options=OPTIONS)
                    assert provider.changed == [True] and 'sync' in provider.preparations and sent == []
                    session.rollback()
                provider.armed = False
                assert _snapshot(app) == before
                assert session.execute(request, execution_options=OPTIONS).scalar_one() == 'public class hook'
                assert sent
                session.rollback()
            assert _snapshot(app) == before


def test_naive_timestamp_refuses_custom_timezone_without_invoking_offset_callback(monkeypatch):
    marker, offsets = 'PUBLIC CUSTOM OFFSET CALLBACK', []
    class RaisingOffset(tzinfo):
        def utcoffset(self, value):
            offsets.append(True)
            raise ValueError(marker)
    value = datetime(2040, 2, 29, 12, 34, 56, 123456, tzinfo=RaisingOffset())
    with application(rows=2, value_type=DateTime(), protected_values=(None, None), queries=[]) as app:
        def statement():
            return point(app).values(name=bindparam('replacement', type_=DateTime()))
        with raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            with Session(app.runtime) as session:
                with pytest.raises((StatementError, ValueError)) as failed:
                    session.execute(statement(), {'replacement': value}, execution_options=OPTIONS)
                assert offsets and marker in str(failed.value)
                session.rollback()
            assert sent
        preparations = []
        def resolve(tenant):
            preparations.append(tenant)
            return keys(tenant)
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                deployment=(app.plan, app.pin))
            before, request = _snapshot(app), statement()
            with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                offsets.clear(); preparations.clear()
                with pytest.raises(CryptoFailure) as failed:
                    session.execute(request, {'replacement': value}, execution_options=OPTIONS)
                assert marker not in str(failed.value)
                assert offsets == sent == []
                assert preparations
                session.rollback()
                safe = value.replace(tzinfo=None)
                no_rows(session.execute(request, {'replacement': safe}, execution_options=OPTIONS), 1)
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == safe
                assert preparations and sent and offsets == []
                session.rollback()
            assert _snapshot(app) == before


def test_named_update_final_driver_mutation_refuses_and_same_request_retries(monkeypatch):
    with application(rows=3) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
            deployment=(app.plan, app.pin))
        statement, parameters = assignments(app), {'row_id': UUID(int=101), 'replacement': 'PUBLIC captured'}
        before = _snapshot(app)
        for fault in ('payload', 'identity', 'sql'):
            injected = []
            def mutate(connection, cursor, sql, values, context, many):
                if sql.lstrip().upper().startswith('UPDATE '):
                    injected.append(True)
                    if fault == 'payload':
                        target = next(key for key, value in values.items() if type(value) is psycopg.Binary)
                        values[target].obj = b'PUBLIC changed payload'
                    elif fault == 'identity':
                        target = next(key for key, value in values.items() if value == UUID(int=101))
                        values[target] = UUID(int=102)
                    else:
                        sql += ' /* PUBLIC changed request */'
                return sql, values
            event.listen(app.runtime, 'before_cursor_execute', mutate, retval=True)
            try:
                with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement, parameters, execution_options=OPTIONS)
                    assert injected == [True] and sent == []
                    session.rollback()
            finally:
                event.remove(app.runtime, 'before_cursor_execute', mutate)
            assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'UPDATE') as sent:
            no_rows(session.execute(statement, parameters, execution_options=OPTIONS), 1)
            assert sent
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == 'PUBLIC captured'
            session.rollback()
        assert parameters == {'row_id': UUID(int=101), 'replacement': 'PUBLIC captured'}


def test_jsonb_named_bind_own_null_mode_and_nested_mutation_during_await(monkeypatch):
    with application(rows=3, value_type=JSONB(none_as_null=True), queries=[],
                     protected_values=({}, None, [1.0])) as app:
        original = {'nested': [True, 1.0, None], 'text': '雪'}

        async def exercise(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            provider = CallbackProvider()
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=provider.resolve,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    observed = []
                    for none_as_null in (False, True):
                        statement = point(app).values(name=bindparam('document', type_=JSONB(none_as_null=none_as_null)))
                        result = await session.execute(statement.returning(app.Customer.name),
                            {'document': None}, execution_options=OPTIONS)
                        is_sql_null = await session.scalar(select(func.count()).select_from(app.Customer).where(
                            app.Customer.id == UUID(int=101), app.Customer.name.is_(None)))
                        assert is_sql_null == int(none_as_null)
                        observed.append((state(result.scalar_one()), is_sql_null))
                    await session.rollback()
                    value = deepcopy(original)
                    parameters = {'document': value, 'row_id': UUID(int=100)}
                    statement = point(app).values(name=bindparam('document', type_=JSONB())).returning(app.Customer.name)
                    if protected:
                        before = stored_rows(app)
                        provider.change = lambda: value['nested'].__setitem__(0, 1)
                        provider.preparations.clear(); provider.armed = True
                        with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as sent:
                            with pytest.raises(CryptoFailure):
                                await session.execute(statement, parameters, execution_options=OPTIONS)
                            assert provider.changed == [True] and 'async' in provider.preparations and sent == []
                            await session.rollback()
                            assert stored_rows(app) == before
                            provider.armed = False
                            value.clear(); value.update(deepcopy(original))
                            result = await session.execute(statement, parameters, execution_options=OPTIONS)
                            observed.append(state(result.scalar_one()))
                            assert sent
                    else:
                        result = await session.execute(statement, parameters, execution_options=OPTIONS)
                        observed.append(state(result.scalar_one()))
                    latest = [(identity, state(value)) for identity, value in
                        (await session.execute(select(app.Customer.id, app.Customer.name).order_by(app.Customer.id))).all()]
                    await session.commit() if protected else await session.rollback()
                    return observed, latest
            finally:
                await engine.dispose()

        expected = asyncio.run(exercise(False))
        with fresh_mapping(app):
            run(app); publish(app)
            assert asyncio.run(exercise(True)) == expected
            remove_current(app, keys)
        with app.owner.connect() as connection:
            row = connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
                (UUID(int=100),)).scalar_one()
            assert state(row) == expected[0][-1]
