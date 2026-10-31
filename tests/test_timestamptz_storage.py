"""Aware timestamp values and session timezone results use native PostgreSQL oracles."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from uuid import UUID
from zoneinfo import ZoneInfo

import psycopg
import pytest
from sqlalchemy import DateTime, create_engine, event, insert, inspect, select, update
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis import migration as m
from cryptalis.crypto import InvalidValue
from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import attach
from test_date_storage import replan
from test_migration import application, keys, publish, run, TENANT


NEW_YORK = ZoneInfo('America/New_York')
VALUES = (datetime(1999, 12, 31, 23, 59, 59, 999999, timezone.utc),
          datetime(2000, 1, 1, tzinfo=timezone(timedelta(hours=5, minutes=30))),
          datetime(2026, 3, 8, 1, 59, 59, 999999, NEW_YORK),
          datetime(2026, 3, 8, 3, 0, tzinfo=NEW_YORK),
          datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK, fold=0),
          datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK, fold=1), None)
DEFAULT = datetime(2026, 11, 1, 12, 34, 56, 123456,
                   timezone(timedelta(hours=5, minutes=45)))
EDIT = datetime(2038, 1, 19, 3, 14, 7, 999999, timezone(timedelta(hours=-7)))
ZONES = ('UTC', 'Asia/Kolkata', 'America/New_York')


def fingerprint(value):
    if value is None:
        return None
    assert type(value) is datetime and value.utcoffset() is not None
    return value.isoformat(timespec='microseconds'), value.utcoffset(), value.fold


def runtime_engine(zone):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                                        options='-c timezone=' + zone))


@contextmanager
def runtime_timezone(app, zone):
    previous, database = app.runtime, runtime_engine(zone)
    app.runtime = database
    try:
        yield
    finally:
        database.dispose()
        app.runtime = previous


def native_values(app, zone):
    database = runtime_engine(zone)
    try:
        with database.connect() as connection:
            return {identity: fingerprint(value) for identity, value in connection.exec_driver_sql(
                f'SELECT id,name FROM "{app.schema}".customer')}
    finally:
        database.dispose()


def exercise(factory, model):
    with factory() as session:
        row = model(id=UUID(int=900), tenant_id=TENANT)
        session.add(row)
        session.flush()
        observed = [fingerprint(row.name), bool(inspect(row).expired_attributes)]
        session.refresh(row)
        observed.append(fingerprint(row.name))
        savepoint = session.begin_nested()
        created = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=901), 'tenant_id': TENANT, 'name': VALUES[5]}]).one()
        changed = session.execute(update(model).where(model.id == row.id, model.tenant_id == TENANT)
            .values(name=VALUES[4]).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        session.refresh(row)
        observed.extend((fingerprint(created.created), fingerprint(changed.changed), fingerprint(row.name)))
        row.name = EDIT
        session.flush()
        session.refresh(row)
        observed.append(fingerprint(row.name))
        savepoint.rollback()
        session.refresh(row)
        observed.append(fingerprint(row.name))
        session.rollback()
        return observed


@pytest.mark.parametrize('zone', ZONES)
@pytest.mark.parametrize('dtype,default', [(DateTime(timezone=True), None),
    (DateTime(timezone=True), DEFAULT), (TIMESTAMP(timezone=True, precision=6), DEFAULT)])
def test_timestamptz_native_session_timezone_crud_defaults_returning_and_exit(zone, dtype, default):
    from test_deprotection import app_pin, consent, d, proposal, reverse
    with application(value_type=dtype, queries=[], value_default=default, protected_values=VALUES) as app:
        source = native_values(app, zone)
        with runtime_timezone(app, zone):
            expected = exercise(lambda: Session(app.runtime, expire_on_commit=False), app.Customer)
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            observed_driver = []
            def no_plaintext(connection, cursor, statement, parameters, context, executemany):
                for group in parameters if isinstance(parameters, list) else [parameters]:
                    values = group.values() if isinstance(group, dict) else group
                    assert not any(isinstance(value, datetime) for value in values)
                observed_driver.append(True)
            event.listen(app.runtime, 'before_cursor_execute', no_plaintext)
            try:
                assert exercise(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer) == expected
                with factory(tenant_id=TENANT) as session:
                    assert {row.id: fingerprint(row.name) for row in session.scalars(select(app.Customer))} == source
                    session.get(app.Customer, UUID(int=100)).name = EDIT
                    session.commit()
                    session.refresh(session.get(app.Customer, UUID(int=100)))
                    source[UUID(int=100)] = fingerprint(session.get(app.Customer, UUID(int=100)).name)
                assert observed_driver
            finally:
                event.remove(app.runtime, 'before_cursor_execute', no_plaintext)
            backward = proposal(app)
            reverse(app, backward)
            assert native_values(app, zone) == source
            reverse(app, backward, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
            exposure, _ = consent(backward, 'PLAINTEXT_ACTIVATING')
            removal = d.RemovalApproval(backward.target_id, backward.operation_id, backward.digest,
                'Native timezone/offset/fold values match.', 'Disposable fixture has no retained backup.', True)
            d.remove(backward, app.owner, pin=app_pin(backward, 'REMOVING'), approval=app.approval,
                     removal=removal, consent=exposure)
            assert native_values(app, zone) == source


@pytest.mark.parametrize('zone', ZONES)
def test_timestamptz_async_native_offsets_folds_returning_and_rollback(zone):
    async def observe(app, protected):
        database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(
                os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], options='-c timezone=' + zone))
        try:
            factory = await attach(app.mapping, database, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(database, **options)
            async with factory(**({'tenant_id': TENANT} if protected else {}), expire_on_commit=False) as session:
                before = [(row.id, fingerprint(row.name)) for row in
                          (await session.scalars(select(app.Customer).order_by(app.Customer.id))).all()]
                row = app.Customer(id=UUID(int=900), tenant_id=TENANT)
                session.add(row)
                await session.flush()
                default_state = fingerprint(row.name), bool(inspect(row).expired_attributes)
                await session.refresh(row)
                returned = (await session.execute(insert(app.Customer).returning(app.Customer.name),
                    [{'id': UUID(int=901), 'tenant_id': TENANT, 'name': VALUES[5]}])).scalar_one()
                row.name = VALUES[4]
                await session.flush()
                await session.refresh(row)
                observed = before, default_state, fingerprint(returned), fingerprint(row.name)
                await session.rollback()
                return observed
        finally:
            await database.dispose()
    with application(value_type=DateTime(timezone=True), queries=[], value_default=DEFAULT,
                     protected_values=VALUES) as app:
        expected = asyncio.run(observe(app, False))
        run(app); publish(app)
        assert asyncio.run(observe(app, True)) == expected


@pytest.mark.parametrize('public_slots', [False, True])
def test_timestamptz_rotations_current_edits_and_both_native_layouts(public_slots):
    from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
    from test_public_slots import slots
    with date_application(public_slots=public_slots, value_type=TIMESTAMP(timezone=True, precision=6),
                          values=VALUES, value_default=DEFAULT) as app:
        original_slots = slots(app) if public_slots else None
        source = native_values(app, 'America/New_York')
        run(app); publish(app); rotate_all(app)
        with runtime_timezone(app, 'America/New_York'):
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                assert {row.id: fingerprint(row.name) for row in session.scalars(select(app.Customer))} == source
                row = session.get(app.Customer, UUID(int=100))
                row.name = EDIT
                session.commit()
                session.refresh(row)
                source[row.id] = fingerprint(row.name)
        remove_date(app)
        assert native_values(app, 'America/New_York') == source
        if public_slots:
            assert slots(app) == original_slots


@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'scoped_update'])
def test_timestamptz_naive_assignment_refuses_without_plaintext(route):
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(InvalidValue):
                if route == 'flush':
                    session.get(app.Customer, UUID(int=100)).name = datetime(2026, 11, 1)
                    session.flush()
                elif route == 'dictionary_insert':
                    session.execute(insert(app.Customer), [{'id': UUID(int=900), 'tenant_id': TENANT,
                        'name': datetime(2026, 11, 1)}])
                else:
                    session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                        [{'id': UUID(int=100), 'name': datetime(2026, 11, 1)}],
                        execution_options={'synchronize_session': False})
            session.rollback()
            assert session.get(app.Customer, UUID(int=100)).name == VALUES[0]


@pytest.mark.parametrize('at_apply', [False, True])
@pytest.mark.parametrize('literal', ['infinity', '-infinity', '10000-01-01 00:00:00+00', '0001-01-01 BC'])
def test_timestamptz_native_source_domain_refuses_before_schema_effects(at_apply, literal):
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s::timestamptz WHERE id=%s',
                                      (literal, UUID(int=100)))
        with pytest.raises(m.TransitionFailure) as failure:
            run(app, until='EXPANDED') if at_apply else replan(app)
        assert failure.value.code == 'timestamptz_source_domain'
        assert literal not in str(failure.value)
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT count(*) FROM information_schema.columns '
                'WHERE table_schema=%s AND column_name LIKE %s', (app.schema, '_cryptalis_%')).scalar_one() == 0


@pytest.mark.parametrize('value', [datetime.min.replace(tzinfo=timezone(timedelta(hours=1))),
                                 datetime.max.replace(tzinfo=timezone(timedelta(hours=-1)))])
def test_timestamptz_outside_utc_python_range_refuses_assignment(value):
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=100)).name = value
            with pytest.raises(InvalidValue):
                session.flush()
            session.rollback()
            assert session.get(app.Customer, UUID(int=100)).name == VALUES[0]


def test_timestamptz_precision_rounding_remains_explicitly_unadmitted():
    with pytest.raises(PlanningRejected) as failure:
        with application(rows=0, value_type=TIMESTAMP(timezone=True, precision=3), queries=[]):
            pytest.fail('unqualified timestamp precision admitted')
    assert 'unsupported_type' in {issue.code for issue in failure.value.issues}


@pytest.mark.parametrize('default', [VALUES[5],
    datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo.no_cache('America/New_York'), fold=1),
    datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=2), 'named offset'))])
def test_timestamptz_defaults_and_verification_preserve_zone_and_fold(default):
    from test_deprotection import proposal, reverse
    with application(value_type=DateTime(timezone=True), queries=[], value_default=default,
                     protected_values=VALUES) as app:
        previous = app.owner
        owner = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                                            options='-c timezone=America/New_York'))
        app.owner = owner
        try:
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                row = app.Customer(id=UUID(int=901), tenant_id=TENANT)
                session.add(row); session.flush()
                assert fingerprint(row.name) == fingerprint(default)
                assert row.name == default
                assert type(row.name.tzinfo) is type(default.tzinfo)
                assert getattr(row.name.tzinfo, 'key', None) == getattr(default.tzinfo, 'key', None)
                assert row.name.tzname() == default.tzname()
                session.rollback()
            backward = proposal(app)
            reverse(app, backward)
        finally:
            app.owner = previous
            owner.dispose()


def test_timestamptz_result_retains_execution_timezone_across_pools_and_delayed_consumption():
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        expected_ny = native_values(app, 'America/New_York')
        expected_india = native_values(app, 'Asia/Kolkata')
        run(app); publish(app)
        zone = ['America/New_York']
        database = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                                            options='-c timezone=' + zone[0]))
        try:
            factory = attach(app.mapping, database, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as first:
                pending = first.execute(select(app.Customer.id, app.Customer.name))
                zone[0] = 'Asia/Kolkata'
                database.dispose()
                with factory(tenant_id=TENANT) as second:
                    assert {row.id: fingerprint(row.name) for row in second.scalars(select(app.Customer))} == expected_india
                assert {identity: fingerprint(value) for identity, value in pending} == expected_ny
        finally:
            database.dispose()


def test_datetime_fold_replacement_at_driver_boundary_is_not_equal_to_original(monkeypatch):
    from sqlalchemy import Column
    from cryptalis.sqlalchemy import UnsafeDriverEvent
    from test_deprotection import app_pin
    from test_driver_event_boundary import raw_calls
    original, replacement = VALUES[4:6]
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        app.table.append_column(Column('observed_at', DateTime(timezone=True)))
        inspect(app.Customer).add_property('observed_at', app.table.c.observed_at)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN observed_at timestamptz')
            connection.execute(app.table.update().where(app.table.c.id == UUID(int=100)).values(observed_at=original))
        app.plan = replan(app)
        app.pin = app_pin(app.plan, 'PREPARED')
        statement = select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                                                app.Customer.observed_at == original)
        with Session(app.runtime) as session:
            assert list(session.scalars(statement)) == [UUID(int=100)]
            assert list(session.scalars(select(app.Customer.id).where(app.Customer.observed_at == replacement))) == []
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        def mutate(connection, cursor, statement, parameters, context, executemany):
            assert type(parameters) is dict
            for key, value in parameters.items():
                if value is original:
                    parameters[key] = replacement
            return statement, parameters
        event.listen(app.runtime, 'before_cursor_execute', mutate, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'SELECT') as calls:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(UnsafeDriverEvent):
                        session.execute(statement)
                    session.rollback()
                assert calls == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', mutate)
        with factory(tenant_id=TENANT) as session:
            assert list(session.scalars(statement)) == [UUID(int=100)]


@pytest.mark.parametrize('aware', [False, True])
def test_retained_v11_reader_accepts_numeric_and_refuses_aware_timestamp_before_sql(tmp_path, aware):
    import subprocess
    from decimal import Decimal
    from sqlalchemy import Numeric
    reader = os.environ.get('CRYPTALIS_TIMESTAMPTZ_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v11 reader interpreter')
    with application(value_type=DateTime(timezone=True) if aware else Numeric(), queries=[],
                     protected_values=(VALUES[0],) if aware else (Decimal('1.23'),)) as app:
        artifact = tmp_path / 'plan.json'
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
    assert sys.argv[2] == 'aware' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'numeric'
print('reader boundary passed')
''', str(artifact), 'aware' if aware else 'numeric'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'historical reader boundary failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'


@pytest.mark.parametrize('zone,value', [('America/New_York', datetime.min.replace(tzinfo=timezone.utc)),
                                      ('Asia/Kolkata', datetime.max.replace(tzinfo=timezone.utc))])
def test_timestamptz_display_calendar_overflow_refuses_instead_of_wrong_values(zone, value):
    from sqlalchemy.exc import DBAPIError
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=(VALUES[0],), rows=1) as app:
        with runtime_timezone(app, zone):
            with Session(app.runtime) as session:
                row = session.get(app.Customer, UUID(int=100))
                row.name = value
                session.flush()
                with pytest.raises(DBAPIError):
                    session.refresh(row)
                session.rollback()
        run(app); publish(app)
        with runtime_timezone(app, zone):
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                row = session.get(app.Customer, UUID(int=100))
                row.name = value
                session.flush()
                with pytest.raises(InvalidValue):
                    session.refresh(row)
                session.rollback()


def test_timestamptz_authenticated_plaintext_matches_native_binary_oracle():
    from test_migration import frames, independent_open
    with application(value_type=DateTime(timezone=True), queries=[], protected_values=VALUES) as app:
        with app.owner.connect() as connection:
            expected = dict(connection.exec_driver_sql(
                f'SELECT id,pg_catalog.timestamptz_send(name) FROM "{app.schema}".customer').all())
        descriptor = app.plan.document['lock']['models'][0]['fields'][0]['descriptor']
        run(app); publish(app)
        actual = {identity: independent_open(frame, descriptor, TENANT, identity, return_bytes=True)
                  for identity, frame in frames(app, True).items()}
        assert actual == expected
