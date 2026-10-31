"""PostgreSQL NUMERIC is the oracle for Decimal values and native typmods."""
from decimal import Decimal, DefaultContext, Inexact, Rounded, localcontext, ROUND_DOWN
from uuid import UUID
import asyncio
import os

import psycopg

import pytest
from sqlalchemy import Numeric, create_engine, event, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.dialects.postgresql import NUMERIC
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from test_migration import application, keys, publish, run, TENANT
from test_deprotection import native_rows


CASES = [(Numeric(), ('1.2300', '-0.00', '1E+20', '-.005', None)),
         (NUMERIC(8, 2), ('1.235', '-1.235', '1E+3', '999999.99', None)),
         (Numeric(3), ('1.5', '-1.5', '999', '0.00', None)),
         (Numeric(2, -3), ('14500', '-14500', '99000', '0', None)),
         (Numeric(3, 5), ('.000125', '-.000125', '.009994', '0', None)),
         (Numeric(1000, 1000), ('1E-1000', '-1E-1000', '.5', '0', None))]


def decimal_values(values):
    return tuple(Decimal(value) if value is not None else None for value in values)


def fingerprint(value):
    return value.as_tuple() if value is not None else None


def exercise(factory, model, value):
    with factory() as session:
        row = session.get(model, UUID(int=100))
        savepoint = session.begin_nested()
        row.name = value
        session.flush()
        session.refresh(row)
        result = [fingerprint(row.name)]
        returned = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': value}]).one()
        result.append(fingerprint(returned.created))
        changed = session.execute(update(model).where(model.id == row.id, model.tenant_id == TENANT)
            .values(name=value).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        result.append(fingerprint(changed.changed))
        savepoint.rollback()
        session.refresh(row)
        result.append(fingerprint(row.name))
        session.rollback()
        return result


@pytest.mark.parametrize('dtype,values', CASES)
def test_numeric_native_rounding_crud_returning_context_and_native_exit(dtype, values):
    from test_deprotection import proposal, reverse, consent, app_pin, d
    values = decimal_values(values)
    with application(value_type=dtype, queries=[], protected_values=values) as app:
        source = native_rows(app)
        expected = [exercise(lambda: Session(app.runtime), app.Customer, value) for value in values]
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        # Host decimal arithmetic settings must not alter database storage semantics.
        with localcontext() as context:
            context.prec, context.rounding = 2, ROUND_DOWN
            assert [exercise(lambda: sessions(tenant_id=TENANT), app.Customer, value)
                    for value in values] == expected
            with sessions(tenant_id=TENANT) as session:
                observed = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))}
                assert observed == source
                assert {key: fingerprint(value[1]) for key, value in observed.items()} == {
                    key: fingerprint(value[1]) for key, value in source.items()}
                current = session.get(app.Customer, UUID(int=100))
                current.name = values[1]
                session.commit()
                session.refresh(current)
                source[UUID(int=100)] = TENANT, current.name
        reverse_plan = proposal(app)
        reverse(app, reverse_plan)
        reverse(app, reverse_plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
        pure, _ = consent(reverse_plan, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(reverse_plan.target_id, reverse_plan.operation_id, reverse_plan.digest,
            'Native decimal current values verified.', 'Disposable fixture has no retained backups.', True)
        d.remove(reverse_plan, app.owner, pin=app_pin(reverse_plan, 'REMOVING'), approval=app.approval,
                 removal=removal, consent=pure)
        assert native_rows(app) == source
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT atttypmod::text FROM pg_catalog.pg_attribute '
                'WHERE attrelid=pg_catalog.to_regclass(%s) AND attname=%s',
                (f'"{app.schema}".customer', 'name')).scalar_one() == next(
                    column['typmod'] for column in app.plan.document['lock']['models'][0]['source_schema']['columns']
                    if column['name'] == 'name')


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('dtype', [Numeric(), Numeric(8, 2), Numeric(2, -3)])
def test_numeric_defaults_rotations_latest_edits_and_both_layouts(public_slots, dtype):
    from test_date_lifecycle import date_application, date_keys, rotate_all, remove_date
    default = Decimal('14500') if dtype.scale == -3 else Decimal('1.235')
    with date_application(public_slots=public_slots, value_type=dtype,
                          values=(default, None, default.copy_negate()), value_default=default) as app:
        before = native_rows(app)
        with Session(app.runtime) as session:
            row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
            session.add(row); session.flush(); session.refresh(row)
            native_default = fingerprint(row.name)
            session.rollback()
        run(app); publish(app); rotate_all(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                         deployment=(app.plan, app.pin))
        bound = []
        def observe(connection, cursor, statement, parameters, context, executemany):
            for values in parameters if isinstance(parameters, list) else [parameters]:
                assert not any(type(value) is Decimal for value in (values.values() if isinstance(values, dict) else values))
            bound.append(True)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
                session.add(row); session.flush(); session.refresh(row)
                assert fingerprint(row.name) == native_default
                session.commit()
                before[row.id] = TENANT, row.name
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert bound
        remove_date(app)
        assert native_rows(app) == before


def test_numeric_rounding_ignores_mutable_decimal_default_context(monkeypatch):
    with application(value_type=Numeric(8, 2), queries=[], protected_values=(Decimal('1.235'),)) as app:
        expected = exercise(lambda: Session(app.runtime), app.Customer, Decimal('-1.235'))
        monkeypatch.setattr(DefaultContext, 'prec', 2)
        monkeypatch.setattr(DefaultContext, 'Emax', 1)
        monkeypatch.setattr(DefaultContext, 'Emin', -1)
        monkeypatch.setitem(DefaultContext.traps, Inexact, True)
        monkeypatch.setitem(DefaultContext.traps, Rounded, True)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        assert exercise(lambda: factory(tenant_id=TENANT), app.Customer, Decimal('-1.235')) == expected


@pytest.mark.parametrize('dtype,value', [(Numeric(8, 2), Decimal('1E-20000')),
    (Numeric(8, 2), Decimal('-1E-20000')), (Numeric(8, 2), Decimal('0E-20000'))])
def test_numeric_exponents_outside_native_driver_domain_refuse(dtype, value):
    from cryptalis.crypto import InvalidValue
    from sqlalchemy.exc import DBAPIError
    with application(value_type=dtype, queries=[], protected_values=(Decimal('1.23'),)) as app:
        with Session(app.runtime) as session:
            session.get(app.Customer, UUID(int=100)).name = value
            with pytest.raises(DBAPIError):
                session.flush()
            session.rollback()
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=100)).name = value
            with pytest.raises(InvalidValue):
                session.flush()
            session.rollback()
            assert session.get(app.Customer, UUID(int=100)).name == Decimal('1.23')


@pytest.mark.parametrize('dtype', [Numeric(8, 2), Numeric()])
@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'point_update'])
def test_numeric_large_positive_zero_exponent_keeps_native_behavior(dtype, route):
    from cryptalis.crypto import CryptoFailure
    from sqlalchemy.exc import DBAPIError
    with application(value_type=dtype, queries=[], protected_values=(Decimal('1.23'),)) as app:
        def scenario(factory):
            with factory() as session:
                try:
                    if route == 'flush':
                        row = session.get(app.Customer, UUID(int=100))
                        row.name = Decimal('0E+200000'); session.flush(); session.refresh(row)
                        result = fingerprint(row.name)
                    elif route == 'dictionary_insert':
                        result = fingerprint(session.execute(insert(app.Customer).returning(app.Customer.name),
                            [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': Decimal('0E+200000')}]).scalar_one())
                    else:
                        result = fingerprint(session.execute(update(app.Customer).where(app.Customer.id == UUID(int=100),
                            app.Customer.tenant_id == TENANT).values(name=Decimal('0E+200000')).returning(app.Customer.name),
                            execution_options={'synchronize_session': False}).scalar_one())
                except (DBAPIError, CryptoFailure) as error:
                    result = ('error', getattr(error, 'sqlstate', None) if isinstance(error, CryptoFailure) else error.orig.sqlstate)
                session.rollback()
                return result
        expected = scenario(lambda: Session(app.runtime))
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


def test_numeric_full_native_digit_bounds_remain_exact_through_protection():
    from sqlalchemy import func
    values = (Decimal('-' + '9' * 131072 + '.' + '9' * 16383), Decimal('1E-16383'), None)
    with application(rows=3, value_type=Numeric(), queries=[], protected_values=values) as app:
        expected = {key: fingerprint(value) for key, (_, value) in native_rows(app).items()}
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert {row.id: fingerprint(row.name) for row in session.scalars(select(app.Customer))} == expected
            assert session.scalar(select(func.count(app.Customer.name))) == 2


def test_numeric_full_native_literal_default_retains_its_reader():
    value = Decimal('-' + '9' * 131072 + '.' + '9' * 16383)
    with application(rows=1, value_type=Numeric(), queries=[], value_default=value,
                     protected_values=(Decimal('1'),)) as app:
        def scenario(factory):
            with factory() as session:
                row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
                session.add(row); session.flush()
                before = fingerprint(row.name)
                session.refresh(row)
                after = fingerprint(row.name)
                session.rollback()
                return before, after
        expected = scenario(lambda: Session(app.runtime))
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


def test_numeric_small_default_preserves_scale_and_changed_scale_refuses():
    from cryptalis.sqlalchemy import PolicyMismatch
    with application(value_type=Numeric(), queries=[], value_default=Decimal('0.0000000100'),
                     protected_values=(Decimal('1'),)) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
            session.add(row); session.flush(); session.refresh(row)
            assert fingerprint(row.name) == fingerprint(Decimal('0.0000000100'))
            session.rollback()
        app.table.c.name.default.arg = Decimal('0.00000001')
        with pytest.raises(PolicyMismatch):
            with factory(tenant_id=TENANT) as session:
                session.get(app.Customer, UUID(int=100))


@pytest.mark.parametrize('default', [7, -7, 10**20, Decimal('1E+20'), Decimal('-0.00'), Decimal('0.0000000100')])
def test_numeric_literal_default_keeps_native_python_state_before_refresh(default):
    from sqlalchemy import inspect
    with application(value_type=Numeric(), queries=[], value_default=default, protected_values=(Decimal('1'),)) as app:
        def scenario(factory):
            with factory() as session:
                row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
                session.add(row); session.flush()
                before = type(row.name), fingerprint(row.name) if type(row.name) is Decimal else row.name
                expired = tuple(inspect(row).expired_attributes)
                session.refresh(row)
                after = fingerprint(row.name)
                session.rollback()
                return before, expired, after
        expected = scenario(lambda: Session(app.runtime))
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


def test_numeric_default_reader_is_independent_of_decimal_capitalization():
    with localcontext() as context:
        context.capitals = 0
        with application(value_type=Numeric(), queries=[], value_default=Decimal('1E+20'),
                         protected_values=(Decimal('1'),)) as app:
            context.capitals = 1
            run(app); publish(app)
            context.capitals = 0
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
                session.add(row); session.flush()
                assert fingerprint(row.name) == fingerprint(Decimal('1E+20'))
                session.refresh(row)
                assert fingerprint(row.name) == fingerprint(Decimal('100000000000000000000'))
                session.rollback()


def test_numeric_async_state_returned_values_and_rollback_match_native():
    async def observe(app, protected):
        database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
        try:
            factory = await attach(app.mapping, database, lock=app.plan.lock_bytes, keys=keys,
                                   deployment=(app.plan, app.pin)) if protected else None
            async with factory(tenant_id=TENANT) if protected else AsyncSession(database) as session:
                row = await session.get(app.Customer, UUID(int=100))
                await session.begin_nested()
                row.name = Decimal('-1.235')
                await session.flush(); await session.refresh(row)
                result = fingerprint(row.name)
                await session.rollback()
                return result
        finally:
            await database.dispose()
    with application(value_type=Numeric(8, 2), queries=[], protected_values=(Decimal('1.235'), None)) as app:
        expected = asyncio.run(observe(app, False))
        run(app); publish(app)
        assert asyncio.run(observe(app, True)) == expected


@pytest.mark.parametrize('literal', ['NaN', 'Infinity', '-Infinity'])
@pytest.mark.parametrize('apply', [False, True])
def test_nonfinite_numeric_source_refuses_before_schema_effects(literal, apply):
    from cryptalis import migration as m
    from test_date_storage import replan
    with application(value_type=Numeric(), queries=[], protected_values=(Decimal('1'),)) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s::numeric WHERE id=%s',
                                      (literal, UUID(int=100)))
        with pytest.raises(m.TransitionFailure) as failure:
            run(app, until='EXPANDED') if apply else replan(app)
        assert failure.value.code == 'numeric_source_domain'
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT count(*) FROM information_schema.columns '
                'WHERE table_schema=%s AND column_name LIKE %s', (app.schema, '_cryptalis_%')).scalar_one() == 0


@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'scoped_update'])
def test_numeric_precision_overflow_preserves_native_transaction_and_savepoint(route):
    from sqlalchemy.exc import DBAPIError
    from cryptalis.crypto import CryptoFailure
    def scenario(app, factory, protected):
        def write(session):
            if route == 'flush':
                session.get(app.Customer, UUID(int=100)).name = Decimal('999.995')
                session.flush()
            elif route == 'dictionary_insert':
                session.execute(insert(app.Customer), [{'id': UUID(int=900), 'tenant_id': TENANT, 'name': Decimal('999.995')}])
            else:
                session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                    [{'id': UUID(int=100), 'name': Decimal('999.995')}], execution_options={'synchronize_session': False})
        with factory() as session:
            driver = session.connection().connection.driver_connection
            with pytest.raises(CryptoFailure if protected else DBAPIError) as failure:
                write(session)
            assert (getattr(failure.value, 'sqlstate', None) if protected else failure.value.orig.sqlstate) == '22003'
            observed = session.is_active, driver.info.transaction_status.name
            session.rollback()
        with factory() as session:
            savepoint = session.begin_nested()
            with pytest.raises(CryptoFailure if protected else DBAPIError):
                write(session)
            savepoint.rollback()
            assert session.get(app.Customer, UUID(int=100)).name == Decimal('1.23')
        return observed
    with application(value_type=Numeric(5, 2), queries=[], protected_values=(Decimal('1.23'),)) as app:
        expected = scenario(app, lambda: Session(app.runtime), False)
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(app, lambda: sessions(tenant_id=TENANT), True) == expected


@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
@pytest.mark.parametrize('route', ['scoped_update', 'point_update', 'stale_flush'])
def test_numeric_prepared_zero_match_overflow_keeps_native_timing(mode, route):
    from cryptalis.crypto import CryptoFailure
    from sqlalchemy.exc import DBAPIError
    from sqlalchemy.orm.exc import StaleDataError
    with application(value_type=Numeric(5, 2), queries=[], protected_values=(Decimal('1.23'),)) as app:
        app.runtime.dispose()
        app.runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                options='-c plan_cache_mode=' + mode, prepare_threshold=0))
        def scenario(factory):
            with factory() as session:
                driver = session.connection().connection.driver_connection
                if route == 'stale_flush':
                    row = session.get(app.Customer, UUID(int=100))
                    with factory() as other:
                        other.delete(other.get(app.Customer, row.id)); other.commit()
                    row.name = Decimal('999.995')
                try:
                    statement = update(app.Customer).where(app.Customer.tenant_id == TENANT)
                    if route == 'stale_flush':
                        session.flush()
                    elif route == 'point_update':
                        session.execute(statement.where(app.Customer.id == UUID(int=999)).values(name=Decimal('999.995')),
                                        execution_options={'synchronize_session': False})
                    else:
                        session.execute(statement, [{'id': UUID(int=999), 'name': Decimal('999.995')}],
                                        execution_options={'synchronize_session': False})
                except (CryptoFailure, DBAPIError, StaleDataError) as error:
                    code = getattr(error, 'sqlstate', None) if isinstance(error, CryptoFailure) else getattr(getattr(error, 'orig', None), 'sqlstate', None)
                    result = code or type(error).__name__, session.is_active, driver.info.transaction_status.name
                else:
                    result = 'zero_rows', session.is_active, driver.info.transaction_status.name
                session.rollback()
                return result
        expected = scenario(lambda: Session(app.runtime))
        if route == 'stale_flush':
            with app.owner.begin() as connection:
                connection.execute(insert(app.table), {'id': UUID(int=100), 'tenant_id': TENANT,
                    'name': Decimal('1.23'), 'label': 'label-100'})
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


@pytest.mark.parametrize('route', ['entity_insert', 'dictionary_insert'])
@pytest.mark.parametrize('overflow_first', [False, True])
def test_numeric_insert_batch_preserves_native_constraint_error_order(route, overflow_first):
    from cryptalis.crypto import CryptoFailure
    from sqlalchemy.exc import DBAPIError
    with application(value_type=Numeric(5, 2), queries=[], protected_values=(Decimal('1.23'),)) as app:
        rows = [{'id': UUID(int=100), 'tenant_id': TENANT, 'name': Decimal('1')},
                {'id': UUID(int=999), 'tenant_id': TENANT, 'name': Decimal('999.995')}]
        if overflow_first:
            rows.reverse()
        def scenario(factory):
            with factory() as session:
                driver = session.connection().connection.driver_connection
                with pytest.raises((CryptoFailure, DBAPIError)) as failure:
                    if route == 'entity_insert':
                        session.add_all(app.Customer(**row) for row in rows); session.flush()
                    else:
                        session.execute(insert(app.Customer), rows)
                code = getattr(failure.value, 'sqlstate', None) if isinstance(failure.value, CryptoFailure) else failure.value.orig.sqlstate
                result = code, session.is_active, driver.info.transaction_status.name
                session.rollback()
                assert session.get(app.Customer, UUID(int=100)).name == Decimal('1.23')
                assert session.get(app.Customer, UUID(int=999)) is None
                return result
        expected = scenario(lambda: Session(app.runtime))
        assert expected[0] == ('22003' if overflow_first else '23505')
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        assert scenario(lambda: factory(tenant_id=TENANT)) == expected


def test_numeric_storage_refuses_search_and_unadmitted_values():
    from cryptalis.crypto import InvalidValue
    from cryptalis.sqlalchemy import UnsupportedProtectedOperation
    with application(value_type=Numeric(), queries=[], protected_values=(Decimal('1.2300'), None)) as app:
        nulls = [value for _, value in native_rows(app).values() if value is None]
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert session.scalars(select(app.Customer.name).where(app.Customer.name.is_(None))).all() == nulls
            for statement in (select(app.Customer).where(app.Customer.name == Decimal('1.23')),
                              select(app.Customer).order_by(app.Customer.name)):
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement)
            for value in ('1.23', 1.23, True, Decimal('NaN'), Decimal('Infinity')):
                session.get(app.Customer, UUID(int=100)).name = value
                with pytest.raises(InvalidValue):
                    session.flush()
                session.rollback()


@pytest.mark.parametrize('dtype', [Numeric(asdecimal=False), NUMERIC(asdecimal=False)])
def test_numeric_float_mappings_refuse(dtype):
    from cryptalis.manifest.compiler import PlanningRejected
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=dtype, queries=[]):
            pytest.fail('unadmitted numeric mapping accepted')
    assert 'unsupported_type' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('value', [Decimal('1.234'), Decimal('1.2300'), Decimal('1000000.00')])
def test_authenticated_numeric_incompatible_with_native_typmod_refuses(value):
    from cryptalis.crypto import FieldDescriptor, RepresentationMismatch, seal_value
    from test_deprotection import proposal, reverse
    with application(value_type=Numeric(8, 2), queries=[], protected_values=(Decimal('1.23'),)) as app:
        run(app); publish(app)
        field = app.plan.document['lock']['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        prepared = keys(TENANT).prepare()
        frame = seal_value(value, descriptor, TENANT, UUID(int=100), prepared)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                       (frame, UUID(int=100)))
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(RepresentationMismatch):
                session.get(app.Customer, UUID(int=100))
        with pytest.raises(app.m.TransitionFailure) as refusal:
            reverse(app, proposal(app))
        assert refusal.value.code == 'RepresentationMismatch'


@pytest.mark.parametrize('numeric', [False, True])
def test_previous_reader_accepts_timestamp_and_refuses_numeric_before_sql(tmp_path, numeric):
    import subprocess
    from datetime import datetime
    from sqlalchemy import DateTime
    reader = os.environ.get('CRYPTALIS_NUMERIC_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v10 reader interpreter')
    with application(value_type=Numeric() if numeric else DateTime(), queries=[],
                     protected_values=(Decimal('1.23'),) if numeric else (datetime(2000, 1, 1),)) as app:
        artifact = tmp_path / 'saved-plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis.migration import MigrationPlan, TransitionFailure
try:
    MigrationPlan(Path(sys.argv[1]).read_bytes()).document
except TransitionFailure as failure:
    assert sys.argv[2] == 'numeric' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'timestamp'
print('reader boundary passed')
''', str(artifact), 'numeric' if numeric else 'timestamp'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'previous-reader control failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'
