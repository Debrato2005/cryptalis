"""Native PostgreSQL defines NUMERIC equality, SQL NULL and unique-key semantics."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import os
from threading import Barrier
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Integer, Numeric, and_, bindparam, cast, event, func, insert, literal, not_, or_, select, update
from sqlalchemy.dialects.postgresql import BIGINT, SMALLINT
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased

from cryptalis.crypto import AuthenticationFailed, InvalidValue
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_migration import application, keys, publish, run, TENANT
from test_driver_event_boundary import raw_calls


def decimals(*values):
    return tuple(Decimal(value) if value is not None else None for value in values)


CASES = [
    (Numeric(), decimals('1.2', '1.20', '-0.00', '0.000', '-2.50', None),
     decimals('1.200', '1.205', '-0.000', '-2.500'), Decimal('1.2000')),
    (Numeric(8, 2), decimals('1.205', '1.20', '-0.004', '0.00', '-2.505', None),
     decimals('1.205', '1.21', '1.200', '-0.000'), Decimal('1.205')),
    (Numeric(2, -3), decimals('14500', '15000', '-500', '0', '-14500', None),
     decimals('14500', '15000.00', '-500', '-0.000'), Decimal('14500')),
    (Numeric(3, 5), decimals('.000125', '.00013', '-.000004', '.00000', '-.001235', None),
     decimals('.000125', '.0001300', '-.000004', '-0.000'), Decimal('.000125')),
]


def frozen(value):
    return ('decimal', value.as_tuple()) if type(value) is Decimal else value


def cases(model, pivots):
    scope = model.tenant_id == TENANT
    base = lambda predicate: select(model.id, model.name).where(scope, predicate).order_by(model.id)
    yield 'all', select(model.id, model.name).where(scope).order_by(model.id), {}
    for number, pivot in enumerate((*pivots, 0, 1)):
        predicates = {
            'equal': model.name == pivot,
            'not_equal': model.name != pivot,
            'reversed': literal(pivot, Numeric()) == model.name,
            'in': model.name.in_([pivot, None]),
            'not_in': model.name.not_in([pivot]),
            'not_in_null': model.name.not_in([pivot, None]),
            'or_null': or_(model.name == pivot, model.name.is_(None)),
            'not_and': not_(and_(model.name == pivot, model.label != 'label-101')),
        }
        for name, predicate in predicates.items():
            yield f'{number}/{name}', base(predicate), {}
    for name, predicate in {
        'in_empty': model.name.in_([]), 'not_in_empty': model.name.not_in([]),
        'in_null': model.name.in_([None]), 'not_in_null': model.name.not_in([None]),
        'null': model.name.is_(None), 'not_null': model.name.is_not(None),
        'or': or_(model.name == pivots[0], model.name == pivots[1]),
        'and': and_(model.name.in_(pivots), model.label != 'label-100'),
    }.items():
        yield name, base(predicate), {}
    late = base(model.name == bindparam('needle', type_=Numeric()))
    for number, pivot in enumerate((pivots[0], pivots[1], None, pivots[0])):
        yield f'late/{number}', late, {'needle': pivot}
    expanded = base(model.name.in_(bindparam('needles', type_=Numeric(), expanding=True)))
    for number, values in enumerate(([], [None], [*pivots, None], [pivots[0]])):
        yield f'expanded/{number}', expanded, {'needles': values}
    yield 'predicate', select(model.id, (model.name == pivots[0]).label('matches'),
        model.name.in_([pivots[1], None]).label('member')).where(scope).order_by(model.id), {}
    yield 'count', select(func.count(model.name)).where(scope), {}
    yield 'distinct_count', select(func.count(model.name.distinct())).where(scope), {}
    yield 'filtered_count', select(func.count(model.name.distinct())).where(scope, model.name.in_(pivots)), {}


def observe(session, model, pivots):
    result = {}
    for alias, selected in (('mapped', model), ('alias', aliased(model))):
        for name, statement, parameters in cases(selected, pivots):
            result[f'{alias}/{name}'] = [tuple(frozen(value) for value in row)
                for row in session.execute(statement, parameters)]
    return result


@pytest.mark.parametrize('dtype,values,pivots,write', CASES)
def test_numeric_equality_in_null_aliases_and_distinct_match_native(dtype, values, pivots, write):
    with application(value_type=dtype, unique=False, queries=['equality'], protected_values=values) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer, pivots)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        seen = []
        def no_decimal_binds(connection, cursor, statement, parameters, context, executemany):
            for group in parameters if isinstance(parameters, list) else [parameters]:
                assert not any(type(value) is Decimal for value in
                    (group.values() if isinstance(group, dict) else group))
            seen.append(True)
        event.listen(app.runtime, 'before_cursor_execute', no_decimal_binds)
        try:
            with factory(tenant_id=TENANT) as session:
                assert observe(session, app.Customer, pivots) == expected
            assert seen
        finally:
            event.remove(app.runtime, 'before_cursor_execute', no_decimal_binds)


def writes(factory, model, value):
    with factory() as session:
        before = [tuple(frozen(part) for part in row) for row in session.execute(
            select(model.id, model.name).where(model.tenant_id == TENANT).order_by(model.id))]
        savepoint = session.begin_nested()
        created = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': value}]).one()
        changed = session.execute(update(model).where(model.id == UUID(int=100), model.tenant_id == TENANT)
            .values(name=value).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        matches = list(session.scalars(select(model.id).where(model.tenant_id == TENANT,
            model.name == changed.changed).order_by(model.id)))
        row = session.get(model, UUID(int=101))
        row.name = value
        session.flush()
        session.refresh(row)
        observed = frozen(created.created), frozen(changed.changed), matches, frozen(row.name)
        savepoint.rollback()
        session.expire_all()
        after = [tuple(frozen(part) for part in row) for row in session.execute(
            select(model.id, model.name).where(model.tenant_id == TENANT).order_by(model.id))]
        assert after == before
        session.rollback()
        return observed


@pytest.mark.parametrize('dtype,values,pivots,write', CASES)
def test_numeric_search_crud_returning_and_savepoint_match_native(dtype, values, pivots, write):
    with application(value_type=dtype, unique=False, queries=['equality'], protected_values=values) as app:
        expected = writes(lambda: Session(app.runtime), app.Customer, write)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert writes(lambda: factory(tenant_id=TENANT), app.Customer, write) == expected


@pytest.mark.parametrize('dtype,values,pivots,write', CASES)
def test_numeric_async_search_and_current_rounding_match_native(dtype, values, pivots, write):
    async def scenario(app, protected):
        database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
        try:
            factory = await attach(app.mapping, database, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
            async with factory(**({'tenant_id': TENANT} if protected else {})) as session:
                result = {}
                for name, statement, parameters in cases(aliased(app.Customer), pivots):
                    result[name] = [tuple(frozen(value) for value in row) for row in
                                   (await session.execute(statement, parameters)).all()]
                created = (await session.execute(insert(app.Customer).returning(app.Customer.name),
                    [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': write}])).scalar_one()
                result['created'] = frozen(created)
                result['new_matches'] = list((await session.scalars(select(app.Customer.id).where(
                    app.Customer.tenant_id == TENANT, app.Customer.name == created).order_by(app.Customer.id))).all())
                changed = (await session.execute(update(app.Customer).where(app.Customer.id == UUID(int=100),
                    app.Customer.tenant_id == TENANT).values(name=write).returning(app.Customer.name),
                    execution_options={'synchronize_session': False})).scalar_one()
                result['changed'] = frozen(changed)
                row = await session.get(app.Customer, UUID(int=101))
                row.name = write
                await session.flush()
                await session.refresh(row)
                result['flushed'] = frozen(row.name)
                await session.rollback()
                result['after_rollback'] = [tuple(frozen(value) for value in row) for row in
                    (await session.execute(select(app.Customer.id, app.Customer.name).where(
                        app.Customer.tenant_id == TENANT).order_by(app.Customer.id))).all()]
                assert result['after_rollback'] == result['all']
                return result
        finally:
            await database.dispose()
    with application(value_type=dtype, unique=False, queries=['equality'], protected_values=values) as app:
        expected = asyncio.run(scenario(app, False))
        run(app); publish(app)
        assert asyncio.run(scenario(app, True)) == expected


UNIQUE_CASES = [(Numeric(), Decimal('1.20'), Decimal('1.20000')),
    (Numeric(), Decimal('-0.00'), 0), (Numeric(8, 2), Decimal('1.235'), Decimal('1.24000')),
    (Numeric(2, -3), Decimal('14500'), Decimal('15000.00')),
    (Numeric(3, 5), Decimal('.000125'), Decimal('.0001300'))]


@pytest.mark.parametrize('dtype,first,duplicate', UNIQUE_CASES)
@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'point_update'])
def test_numeric_unique_scale_zero_rounding_and_savepoint_match_native(dtype, first, duplicate, route):
    with application(rows=2, value_type=dtype, unique=True, queries=['equality', 'unique'],
                     protected_values=(first, None)) as app:
        def scenario(factory):
            with factory() as session:
                savepoint = session.begin_nested()
                with pytest.raises(IntegrityError) as failure:
                    if route == 'flush':
                        session.add(app.Customer(id=UUID(int=900), tenant_id=TENANT, name=duplicate))
                        session.flush()
                    elif route == 'dictionary_insert':
                        session.execute(insert(app.Customer),
                            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': duplicate}])
                    else:
                        session.execute(update(app.Customer).where(app.Customer.id == UUID(int=101),
                            app.Customer.tenant_id == TENANT).values(name=duplicate),
                            execution_options={'synchronize_session': False})
                assert failure.value.orig.sqlstate == '23505'
                savepoint.rollback()
                match = session.scalar(select(app.Customer.name).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name == duplicate))
                assert session.get(app.Customer, UUID(int=101)).name is None
                # SQL NULL remains non-conflicting within the same tenant scope.
                session.add(app.Customer(id=UUID(int=901), tenant_id=TENANT, name=None))
                session.flush()
                session.rollback()
                return frozen(match)
        expected = scenario(lambda: Session(app.runtime))
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


def test_numeric_uniqueness_and_search_are_scoped_to_each_native_tenant():
    other = UUID(int=777)
    def seed_other(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
            (UUID(int=800), other, Decimal('1.2000'), 'other tenant'))
    with application(rows=1, value_type=Numeric(), unique=True, queries=['equality', 'unique'],
                     protected_values=(Decimal('1.20'),), setup=seed_other) as app:
        def scenario(factory):
            result = {}
            for tenant in (TENANT, other):
                with factory(tenant) as session:
                    result[tenant] = [tuple(frozen(value) for value in row) for row in session.execute(
                        select(app.Customer.id, app.Customer.name).where(app.Customer.tenant_id == tenant,
                            app.Customer.name == Decimal('1.2')).order_by(app.Customer.id))]
            return result
        expected = scenario(lambda tenant: Session(app.runtime))
        assert [row[0] for row in expected[TENANT]] == [UUID(int=100)]
        assert [row[0] for row in expected[other]] == [UUID(int=800)]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert scenario(lambda tenant: factory(tenant_id=tenant)) == expected


@pytest.mark.parametrize('value', [1.2, '1.20', True])
@pytest.mark.parametrize('shape', ['equality', 'in'])
def test_numeric_search_unadmitted_bind_coercions_refuse_before_driver(value, shape):
    with application(value_type=Numeric(), unique=False, queries=['equality'],
                     protected_values=decimals('1.2', None)) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        seen = []
        def driver(connection, cursor, statement, parameters, context, executemany):
            seen.append(True)
        event.listen(app.runtime, 'before_cursor_execute', driver)
        try:
            with factory(tenant_id=TENANT) as session:
                predicate = app.Customer.name == value if shape == 'equality' else app.Customer.name.in_([value])
                with pytest.raises((InvalidValue, UnsupportedProtectedOperation)):
                    session.execute(select(app.Customer.id).where(app.Customer.tenant_id == TENANT, predicate))
                session.rollback()
            assert seen == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', driver)


def test_numeric_order_refuses_until_separate_leakage_admission():
    with application(value_type=Numeric(), unique=False, queries=['equality'],
                     protected_values=decimals('1.2', None)) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            for statement in (select(app.Customer).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name > Decimal('1')), select(app.Customer).where(
                    app.Customer.tenant_id == TENANT).order_by(app.Customer.name)):
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement)
                session.rollback()


def mixed_in_cases(model):
    values = ([1, Decimal('1.6')], [Decimal('1.6'), 1],
              [None, 1, Decimal('1.6')], [1, None, Decimal('1.6')],
              [None, Decimal('-1.5'), 0], [Decimal('-1.5'), 0, None])
    for items in values:
        for predicate in (model.name.in_(items), model.name.not_in(items)):
            yield select(model.id).where(model.tenant_id == TENANT, predicate).order_by(model.id), {}


def typed_bind_cases(model, dtype):
    direct = select(model.id).where(model.tenant_id == TENANT,
        model.name == bindparam('needle', type_=dtype)).order_by(model.id)
    for value in (Decimal('1.6'), Decimal('-1.5'), Decimal('0.4'), 1, None):
        yield direct, {'needle': value}
    expanded = select(model.id).where(model.tenant_id == TENANT,
        model.name.in_(bindparam('needles', type_=dtype, expanding=True))).order_by(model.id)
    for values in ([1, Decimal('1.6')], [Decimal('1.6'), 1],
                   [None, Decimal('-1.5'), 0], [None], []):
        yield expanded, {'needles': values}


@pytest.mark.parametrize('dtype', [None, Integer(), SMALLINT(), BIGINT()],
                         ids=['inferred-mixed-in', 'integer', 'smallint', 'bigint'])
def test_numeric_mixed_and_deferred_binds_retain_original_native_cast_semantics(dtype):
    with application(rows=6, value_type=Numeric(), unique=False, queries=['equality'],
                     protected_values=decimals('1.00', '2.00', '-2.00', '1.600', '0.00', None)) as app:
        def observe_binds(session):
            queries = mixed_in_cases(app.Customer) if dtype is None else typed_bind_cases(app.Customer, dtype)
            return [list(session.scalars(statement, parameters)) for statement, parameters in queries]
        with Session(app.runtime) as session:
            expected = observe_binds(session)
        # The first inferred integer list rounds 1.6 to 2; Decimal-first retains 1.6.
        if dtype is None:
            assert expected[0] == [UUID(int=100), UUID(int=101)]
            assert expected[2] == [UUID(int=100), UUID(int=103)]
        else:
            assert expected[0] == [UUID(int=101)]
            assert expected[1] == [UUID(int=102)]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert observe_binds(session) == expected


@pytest.mark.parametrize('dtype,pivot,values', [
    (Numeric(8, 2), Decimal('1.235'), decimals('1.235', '1.24', None)),
    (Numeric(2, -3), Decimal('14500'), decimals('14500', '15000', None)),
    (Numeric(3, 5), Decimal('.000125'), decimals('.000125', '.00013', None)),
])
def test_numeric_precision_bind_metadata_does_not_round_but_explicit_cast_refuses(dtype, pivot, values, monkeypatch):
    with application(rows=3, value_type=Numeric(), unique=False, queries=['equality'],
                     protected_values=values) as app:
        def statement(explicit):
            bound = bindparam('needle', type_=dtype)
            return select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                app.Customer.name == (cast(bound, dtype) if explicit else bound)).order_by(app.Customer.id)
        with Session(app.runtime) as session:
            expected = list(session.scalars(statement(False), {'needle': pivot}))
            assert expected == [UUID(int=100)]
            assert list(session.scalars(statement(True), {'needle': pivot})) == [UUID(int=101)]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement(True), {'needle': pivot})
                session.rollback()
                assert calls == []
                assert list(session.scalars(statement(False), {'needle': pivot})) == expected
            assert calls


def test_numeric_distinct_returns_native_value_classes_and_authenticated_original_representatives():
    from test_migration import frames
    with application(rows=6, value_type=Numeric(), unique=False, queries=['equality'],
                     protected_values=decimals('1.200', '1.20000', '-0.00', '0.000', '-2.500', None)) as app:
        with Session(app.runtime) as session:
            original = list(session.scalars(select(app.Customer.name).where(app.Customer.tenant_id == TENANT)))
            expected = set(session.scalars(select(app.Customer.name).where(
                app.Customer.tenant_id == TENANT).distinct()))
            distinct_count = session.scalar(select(func.count(app.Customer.name.distinct())).where(
                app.Customer.tenant_id == TENANT))
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))

        def read():
            with factory(tenant_id=TENANT) as session:
                for model in (app.Customer, aliased(app.Customer)):
                    field = model.name.label('representative')
                    actual = list(session.scalars(select(field).where(model.tenant_id == TENANT).distinct()))
                    assert set(actual) == expected and len(actual) == len(expected)
                    for value in actual:
                        assert value is None or value.as_tuple() in {
                            source.as_tuple() for source in original if source is not None and source == value}
                    assert session.scalar(select(func.count(model.name.distinct())).where(
                        model.tenant_id == TENANT)) == distinct_count == 3
        read()
        retained = frames(app, True)
        with app.owner.begin() as connection:
            for identity, frame in retained.items():
                if frame is not None:
                    altered = frame[:-1] + bytes((frame[-1] ^ 1,))
                    connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                              (altered, identity))
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.scalars(select(app.Customer.name).where(app.Customer.tenant_id == TENANT).distinct()).all()
            session.rollback()
        with app.owner.begin() as connection:
            for identity, frame in retained.items():
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                          (frame, identity))
        read()


def test_numeric_native_unique_race_chooses_one_winner_across_equivalent_scales():
    with application(rows=1, value_type=Numeric(), unique=True, queries=['equality', 'unique'],
                     protected_values=(Decimal('9.99'),)) as app:
        def race(factory):
            ready = Barrier(2)
            def compete(rank):
                with factory() as session:
                    session.add(app.Customer(id=UUID(int=900 + rank), tenant_id=TENANT,
                        name=Decimal('1.20') if rank == 0 else Decimal('1.20000')))
                    ready.wait(timeout=10)
                    try:
                        session.commit()
                    except IntegrityError as error:
                        assert error.orig.sqlstate == '23505'
                        session.rollback()
                        return 'duplicate'
                    return 'committed'
            with ThreadPoolExecutor(2) as pool:
                outcomes = sorted(pool.map(compete, (0, 1)))
            with factory() as session:
                winners = session.scalars(select(app.Customer).where(app.Customer.tenant_id == TENANT,
                    app.Customer.name == Decimal('1.2'))).all()
                assert len(winners) == 1 and winners[0].id in (UUID(int=900), UUID(int=901))
                assert winners[0].name.as_tuple() in (Decimal('1.20').as_tuple(), Decimal('1.20000').as_tuple())
            return outcomes
        expected = race(lambda: Session(app.runtime))
        assert expected == ['committed', 'duplicate']
        with Session(app.runtime) as session:
            for identity in (UUID(int=900), UUID(int=901)):
                row = session.get(app.Customer, identity)
                if row is not None:
                    session.delete(row)
            session.commit()
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert race(lambda: factory(tenant_id=TENANT)) == expected
