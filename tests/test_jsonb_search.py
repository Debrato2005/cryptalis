"""Whole-document JSONB equality follows the native PostgreSQL oracle."""
import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal
import os
from threading import Barrier
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import JSON, and_, bindparam, func, insert, literal, not_, null, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_driver_event_boundary import raw_calls
from test_jsonb_boundaries import CallbackProvider, stored_rows
from test_jsonb_storage import mapping_for, state
from test_migration import TENANT, application, engine, keys, publish, run


OBJECT = {'nested': [True, 1.0], 'n': 1.2}
VALUES = (OBJECT, {'n': 1.20, 'nested': [True, 1]}, [1, {'n': 2.0}],
          1.0, True, JSON.NULL, None)
RAW = ('{"n":1.2000,"nested":[true,1.00]}', '0.0000', '-0.00',
       '"1"', '[1.00]', '{"n":1.20,"nested":[1,true]}', '"é"', '"e\\u0301"')


def seed_documents(connection, schema, role):
    for index, raw in enumerate(RAW):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) '
            'VALUES (%s,%s,%s::pg_catalog.jsonb,%s)',
            (UUID(int=800 + index), TENANT, raw, 'native raw JSONB'))
    connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) '
        'VALUES (%s,%s,NULL,%s)', (UUID(int=820), TENANT, 'SQL NULL control'))


@contextmanager
def attached_jsonb(app, none_as_null, resolver=keys):
    mapping, _, Model = mapping_for(app.schema, none_as_null)
    database = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        factory = attach(mapping, database, lock=app.plan.lock_bytes, keys=resolver,
                         deployment=(app.plan, app.pin))
        yield Model, factory
    finally:
        database.dispose(); mapping.dispose()


def queries(model):
    scope = model.tenant_id == TENANT
    base = lambda predicate: select(model.id, model.name).where(scope, predicate).order_by(model.id)
    yield 'all', select(model.id, model.name).where(scope).order_by(model.id), {}
    for number, pivot in enumerate((OBJECT, {'n': 1.2, 'nested': [1, True]}, [1, {'n': 2}],
                                    '1', 'é', 'e\u0301', 1, 0.0, True, JSON.NULL, None)):
        for none_as_null in (False, True):
            dtype = JSONB(none_as_null=none_as_null)
            typed = literal(pivot, dtype)
            predicates = {'equal': model.name == typed, 'not_equal': model.name != typed,
                'reversed': typed == model.name,
                'not_and': not_(and_(model.name == typed, model.label != 'label-101')),
                'or_null': or_(model.name == typed, model.name.is_(None))}
            for name, predicate in predicates.items():
                yield f'{number}/{none_as_null}/{name}', base(predicate), {}
    yield 'inferred_object', base(model.name == deepcopy(OBJECT)), {}
    yield 'inferred_array', base(model.name == [1, {'n': 2.0}]), {}
    for none_as_null in (False, True):
        dtype = JSONB(none_as_null=none_as_null)
        late = base(model.name == bindparam('needle', type_=dtype))
        for index, pivot in enumerate((OBJECT, None, JSON.NULL, 1, OBJECT)):
            yield f'late/{none_as_null}/{index}', late, {'needle': pivot}
        yield f'stored/{none_as_null}', late.params(needle=deepcopy(OBJECT)), {}
        expanded = base(model.name.in_(bindparam('needles', type_=dtype, expanding=True)))
        negative = base(model.name.not_in(bindparam('needles', type_=dtype, expanding=True)))
        for index, pivots in enumerate(([], [None], [JSON.NULL], [OBJECT, 1, None], [True, [1.0]])):
            yield f'in/{none_as_null}/{index}', expanded, {'needles': pivots}
            yield f'not_in/{none_as_null}/{index}', negative, {'needles': pivots}
    yield 'null', base(model.name.is_(None)), {}
    yield 'not_null', base(model.name.is_not(None)), {}
    yield 'count', select(func.count(model.name)).where(scope), {}
    yield 'distinct', select(model.name).where(scope).distinct(), {}
    yield 'distinct_count', select(func.count(model.name.distinct())).where(scope), {}
    yield 'filtered_distinct_count', select(func.count(model.name.distinct())).where(
        scope, model.name == deepcopy(OBJECT)), {}


def equivalence(value):
    """Native DISTINCT may return any numeric-scale representative of a document."""
    if type(value) in (int, float):
        return 'number', Decimal(str(value))
    if type(value) is dict:
        return 'object', tuple((key, equivalence(part)) for key, part in value.items())
    if type(value) is list:
        return 'array', tuple(equivalence(part) for part in value)
    return type(value).__name__, value


def observed_rows(name, rows):
    if name == 'distinct':
        # Preserve both SQL NULL and JSON null representatives despite their
        # identical default Python None result, and ignore unspecified row order.
        return Counter(tuple(equivalence(value) for value in row) for row in rows)
    return [tuple(state(value) for value in row) for row in rows]


def observe(session, model):
    return {f'{alias}/{name}': observed_rows(name, session.execute(statement, parameters))
        for alias, selected in (('mapped', model), ('alias', aliased(model)))
        for name, statement, parameters in queries(selected)}


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_whole_document_equality_types_nulls_aliases_counts_and_predicate_keys_match_native(none_as_null):
    with application(value_type=JSONB(none_as_null=none_as_null), unique=False, queries=['equality'],
                     protected_values=deepcopy(VALUES), setup=seed_documents) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer)
        run(app); publish(app)
        with attached_jsonb(app, none_as_null) as (Model, factory):
            with factory(tenant_id=TENANT) as session:
                assert observe(session, Model) == expected
                equal = Model.name == literal(deepcopy(OBJECT), JSONB())
                member = Model.name.in_(bindparam('needles', type_=JSONB(), expanding=True))
                labelled = equal.label('same_document')
                rows = session.execute(select(Model.id, labelled, member).where(
                    Model.tenant_id == TENANT).order_by(Model.id), {'needles': [OBJECT, JSON.NULL]}).all()
                assert rows and all(row._mapping[labelled] == row.same_document and row._mapping[member] == row[2] for row in rows)


def write_journey(factory, model):
    with factory() as session:
        before = observe(session, model)
        savepoint = session.begin_nested()
        created = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': {'current': [1.0, True]}}]).one()
        changed = session.execute(update(model).where(model.id == UUID(int=100), model.tenant_id == TENANT)
            .values(name={'current': [1, True]}).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        row = session.get(model, UUID(int=102)); row.name = {'current': [1.0, True]}
        session.flush(); session.refresh(row)
        matches = list(session.scalars(select(model.id).where(model.tenant_id == TENANT,
            model.name == {'current': [1.000, True]}).order_by(model.id)))
        result = state(created.created), state(changed.changed), state(row.name), matches
        savepoint.rollback(); session.expire_all()
        assert observe(session, model) == before
        session.rollback()
        return result


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_search_writes_returning_and_savepoints_match_native(none_as_null):
    with application(value_type=JSONB(none_as_null=none_as_null), unique=False, queries=['equality'],
                     protected_values=deepcopy(VALUES)) as app:
        expected = write_journey(lambda: Session(app.runtime), app.Customer)
        run(app); publish(app)
        with attached_jsonb(app, none_as_null) as (Model, factory):
            assert write_journey(lambda: factory(tenant_id=TENANT), Model) == expected


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_async_typed_document_queries_and_current_writes_match_native(none_as_null):
    async def journey(app, protected):
        mapping, _, Model = mapping_for(app.schema, none_as_null)
        database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
        try:
            factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
            async with factory(**({'tenant_id': TENANT} if protected else {})) as session:
                observed = {name: observed_rows(name,
                    (await session.execute(statement, parameters)).all())
                    for name, statement, parameters in queries(aliased(Model))}
                created = (await session.execute(insert(Model).returning(Model.name),
                    [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': {'async': [1.0, True]}}])).scalar_one()
                row = await session.get(Model, UUID(int=100)); row.name = {'async': [1, True]}
                await session.flush(); await session.refresh(row)
                matches = list((await session.scalars(select(Model.id).where(Model.tenant_id == TENANT,
                    Model.name == {'async': [1.0000, True]}).order_by(Model.id))).all())
                observed['writes'] = state(created), state(row.name), matches
                await session.rollback()
                return observed
        finally:
            await database.dispose(); mapping.dispose()
    with application(value_type=JSONB(none_as_null=none_as_null), unique=False, queries=['equality'],
                     protected_values=deepcopy(VALUES), setup=seed_documents) as app:
        expected = asyncio.run(journey(app, False))
        run(app); publish(app)
        assert asyncio.run(journey(app, True)) == expected


@pytest.mark.parametrize('none_as_null', [False, True])
def test_jsonb_unique_document_normalization_and_null_savepoints_match_native(none_as_null):
    first, duplicate = {'a': 1.20, 'b': [0, True]}, {'b': [-0.0, True], 'a': 1.2}
    def journey(factory, Model):
        with factory() as session:
            for route in ('flush', 'point_update'):
                savepoint = session.begin_nested()
                with pytest.raises(IntegrityError) as failure:
                    if route == 'flush':
                        session.add(Model(id=UUID(int=900), tenant_id=TENANT, name=deepcopy(duplicate)))
                        session.flush()
                    else:
                        session.execute(update(Model).where(Model.id == UUID(int=101), Model.tenant_id == TENANT)
                            .values(name=deepcopy(duplicate)), execution_options={'synchronize_session': False})
                assert failure.value.orig.sqlstate == '23505'
                savepoint.rollback()
            session.add_all((Model(id=UUID(int=901), tenant_id=TENANT, name=null()),
                             Model(id=UUID(int=902), tenant_id=TENANT, name=null())))
            session.flush()
            if none_as_null:
                session.add(Model(id=UUID(int=903), tenant_id=TENANT, name=JSON.NULL)); session.flush()
            savepoint = session.begin_nested()
            with pytest.raises(IntegrityError) as failure:
                session.add(Model(id=UUID(int=904), tenant_id=TENANT, name=JSON.NULL)); session.flush()
            assert failure.value.orig.sqlstate == '23505'; savepoint.rollback()
            found = list(session.scalars(select(Model.id).where(Model.tenant_id == TENANT,
                Model.name == deepcopy(duplicate)).order_by(Model.id)))
            session.rollback()
            return found
    with application(rows=2, value_type=JSONB(none_as_null=none_as_null), unique=True,
                     queries=['equality', 'unique'], protected_values=(first, None)) as app:
        expected = journey(lambda: Session(app.runtime), app.Customer)
        run(app); publish(app)
        with attached_jsonb(app, none_as_null) as (Model, factory):
            assert journey(lambda: factory(tenant_id=TENANT), Model) == expected


def test_jsonb_scoped_unique_race_matches_native_transaction_outcomes():
    other = UUID(int=777)
    def seed_other(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) '
            'VALUES (%s,%s,%s::jsonb,%s)', (UUID(int=800), other, '{"same":1.00}', 'other tenant'))
    def race(factory, Model):
        barrier = Barrier(2)
        def worker(index):
            with factory() as session:
                session.add(Model(id=UUID(int=950 + index), tenant_id=TENANT,
                                  name={'race': [1.0 if index else 1, {'x': 2 if index else 2.0}]}))
                barrier.wait(timeout=10)
                try:
                    session.commit(); return 'committed'
                except IntegrityError as failure:
                    code = failure.orig.sqlstate; session.rollback(); return code
        with ThreadPoolExecutor(max_workers=2) as workers:
            return sorted(workers.map(worker, range(2)))
    with application(rows=1, value_type=JSONB(), unique=True, queries=['equality', 'unique'],
                     protected_values=({'same': 1},), setup=seed_other) as app:
        expected = race(lambda: Session(app.runtime), app.Customer)
        assert expected == ['23505', 'committed']
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id IN (%s,%s)',
                                       (UUID(int=950), UUID(int=951)))
        run(app); publish(app)
        with attached_jsonb(app, False) as (Model, factory):
            assert race(lambda: factory(tenant_id=TENANT), Model) == expected
            for tenant, identity in ((TENANT, UUID(int=100)), (other, UUID(int=800))):
                with factory(tenant_id=tenant) as session:
                    assert list(session.scalars(select(Model.id).where(Model.tenant_id == tenant,
                        Model.name == {'same': 1.000}).order_by(Model.id))) == [identity]


def test_jsonb_bare_scalar_coercions_and_order_remain_refused_before_keys_or_dispatch(monkeypatch):
    with application(value_type=JSONB(), unique=False, queries=['equality'],
                     protected_values=deepcopy(VALUES)) as app:
        with Session(app.runtime) as session:
            for value in ('1', 1, True):
                savepoint = session.begin_nested()
                with pytest.raises(DBAPIError) as failure:
                    session.execute(select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                        app.Customer.name == value))
                assert failure.value.orig.sqlstate == '42883'; savepoint.rollback()
        run(app); publish(app)
        provider = CallbackProvider()
        with attached_jsonb(app, False, provider.resolve) as (Model, factory):
            with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                with factory(tenant_id=TENANT) as session:
                    for predicate in [*(Model.name == value for value in ('1', 1, True)),
                                      Model.name > literal({}, JSONB())]:
                        provider.preparations.clear()
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(select(Model.id).where(Model.tenant_id == TENANT, predicate))
                        assert provider.preparations == []
                    assert calls == []
                    assert session.scalar(select(Model.id).where(Model.tenant_id == TENANT,
                        Model.name == deepcopy(OBJECT)).order_by(Model.id)) == UUID(int=100)
                assert calls


def mutable_request(Model, route):
    value = deepcopy(OBJECT)
    base = select(Model.id).where(Model.tenant_id == TENANT).order_by(Model.id)
    parameters = None
    if route == 'embedded':
        statement = base.where(Model.name == value)
    elif route == 'statement_params':
        statement = base.where(Model.name == bindparam('needle', type_=JSONB())).params(needle=value)
    elif route == 'execute_params':
        statement = base.where(Model.name == bindparam('needle', type_=JSONB()))
        parameters = {'needle': value}
    else:
        statement = base.where(Model.name.in_(bindparam('needles', type_=JSONB(), expanding=True)))
        parameters = {'needles': [value]}
    def change():
        if route == 'execute_params':
            parameters['needle'] = {'replacement': True}
        else:
            value['nested'][0] = 1  # Same Python equality, different native JSON document.
    def restore():
        value.clear(); value.update(deepcopy(OBJECT))
        if route == 'execute_params': parameters['needle'] = value
    return statement, parameters, change, restore


@pytest.mark.parametrize('route', ['embedded', 'statement_params', 'execute_params', 'expanding'])
@pytest.mark.parametrize('asynchronous', [False, True])
def test_jsonb_search_pivots_cannot_change_during_provider_preparation(route, asynchronous, monkeypatch):
    with application(value_type=JSONB(), unique=False, queries=['equality'],
                     protected_values=deepcopy(VALUES)) as app:
        run(app); publish(app)
        before = stored_rows(app)
        if not asynchronous:
            provider = CallbackProvider()
            with attached_jsonb(app, False, provider.resolve) as (Model, factory):
                statement, parameters, provider.change, restore = mutable_request(Model, route)
                with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                    with factory(tenant_id=TENANT) as session:
                        provider.preparations.clear(); provider.armed = True
                        with pytest.raises(UnsupportedProtectedOperation): session.execute(statement, parameters)
                        assert provider.changed == [True] and provider.preparations and calls == []
                        assert stored_rows(app) == before
                        provider.armed = False; restore(); session.rollback()
                        assert list(session.scalars(statement, parameters)) == [UUID(int=100), UUID(int=101)]
                    assert calls
        else:
            async def journey():
                mapping, _, Model = mapping_for(app.schema, False)
                database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                provider = CallbackProvider()
                try:
                    factory = await attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                                           deployment=(app.plan, app.pin))
                    statement, parameters, provider.change, restore = mutable_request(Model, route)
                    with raw_calls(monkeypatch, app.schema, 'SELECT', asynchronous=True) as calls:
                        async with factory(tenant_id=TENANT) as session:
                            provider.preparations.clear(); provider.armed = True
                            with pytest.raises(UnsupportedProtectedOperation): await session.execute(statement, parameters)
                            assert provider.changed == [True] and 'async' in provider.preparations and calls == []
                            assert stored_rows(app) == before
                            provider.armed = False; restore(); await session.rollback()
                            assert list((await session.scalars(statement, parameters)).all()) == [UUID(int=100), UUID(int=101)]
                        assert calls
                finally:
                    await database.dispose(); mapping.dispose()
            asyncio.run(journey())
