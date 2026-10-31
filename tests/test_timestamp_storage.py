"""Timestamp behavior is compared with native PostgreSQL before protection."""
import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import DateTime, event, insert, inspect, select, update
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis import deprotection as d, migration as m
from cryptalis.crypto import InvalidValue
from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import attach
from test_date_storage import replan
from test_deprotection import app_pin, consent, native_rows, proposal, reverse
from test_migration import application, keys, publish, run, TENANT


VALUES = (datetime.min, datetime(1999, 12, 31, 23, 59, 59, 999999),
          datetime(2000, 1, 1), datetime(2000, 2, 29, 12, 34, 56, 123456),
          datetime.max, None)
DEFAULT = datetime(2026, 11, 1, 12, 34, 56, 123456)


def exercise(factory, model, default):
    with factory() as session:
        row = model(id=UUID(int=900), tenant_id=TENANT)
        session.add(row)
        session.flush()
        assert row.name == default and not inspect(row).expired_attributes
        session.refresh(row)
        savepoint = session.begin_nested()
        returned = session.execute(insert(model).returning(model.name.label('created')),
            [{'id': UUID(int=901), 'tenant_id': TENANT, 'name': VALUES[1]}]).one()
        changed = session.execute(update(model).where(model.id == row.id, model.tenant_id == TENANT)
            .values(name=VALUES[4]).returning(model.name.label('changed')),
            execution_options={'synchronize_session': False}).one()
        session.refresh(row)
        assert type(row.name) is datetime and row.name == VALUES[4]
        observed = returned.created, changed.changed, row.name
        savepoint.rollback()
        session.refresh(row)
        assert row.name == default
        session.rollback()
        return observed


@pytest.mark.parametrize('dtype,default', [(DateTime(), None), (DateTime(), DEFAULT),
                                         (TIMESTAMP(precision=6), DEFAULT)])
def test_timestamp_crud_defaults_returning_and_current_value_exit_match_native(dtype, default):
    with application(value_type=dtype, queries=[], value_default=default, protected_values=VALUES) as app:
        source = native_rows(app)
        expected = exercise(lambda: Session(app.runtime, expire_on_commit=False), app.Customer, default)
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        bound = []

        def inspect_binds(connection, cursor, statement, parameters, context, executemany):
            for group in parameters if isinstance(parameters, list) else [parameters]:
                values = group.values() if isinstance(group, dict) else group
                assert not any(isinstance(value, datetime) for value in values)
            bound.append(True)

        event.listen(app.runtime, 'before_cursor_execute', inspect_binds)
        try:
            assert exercise(lambda: factory(tenant_id=TENANT, expire_on_commit=False), app.Customer, default) == expected
            with factory(tenant_id=TENANT) as session:
                observed = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))}
                assert observed == source
                session.get(app.Customer, UUID(int=100)).name = DEFAULT
                session.commit()
            assert bound
        finally:
            event.remove(app.runtime, 'before_cursor_execute', inspect_binds)
        expected_rows = {**source, UUID(int=100): (TENANT, DEFAULT)}
        backward = proposal(app)
        reverse(app, backward)
        assert native_rows(app) == expected_rows
        exposure, pin = consent(backward, 'PLAINTEXT_ACTIVATING')
        d.apply(backward, app.owner, keys=keys, pin=pin, approval=app.approval,
                consent=exposure, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(backward.target_id, backward.operation_id, backward.digest,
                                    'native timestamp reads', 'public fixture backup obligation', True)
        assert d.remove(backward, app.owner, pin=replace(pin, phase='REMOVING'), approval=app.approval,
                        removal=removal, consent=exposure).phase == 'REMOVED'
        assert native_rows(app) == expected_rows


def test_timestamp_async_matches_native_and_rejects_aware_assignments():
    with application(value_type=DateTime(), queries=[], protected_values=VALUES) as app:
        async def observe(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(engine, **options)
                async with factory(**({'tenant_id': TENANT} if protected else {}), expire_on_commit=False) as session:
                    row = await session.get(app.Customer, UUID(int=100))
                    before = row.name
                    row.name = DEFAULT
                    await session.flush()
                    await session.refresh(row)
                    observed = before, row.name
                    if protected:
                        row.name = DEFAULT.replace(tzinfo=timezone.utc)
                        with pytest.raises(InvalidValue):
                            await session.flush()
                    await session.rollback()
                    return observed
            finally:
                await engine.dispose()
        expected = asyncio.run(observe(False))
        run(app); publish(app)
        assert asyncio.run(observe(True)) == expected


@pytest.mark.parametrize('at_apply', [False, True])
@pytest.mark.parametrize('literal', ['infinity', '-infinity', '10000-01-01', '0001-01-01 BC'])
def test_timestamp_outside_python_domain_refuses_before_effects(at_apply, literal):
    with application(value_type=DateTime(), queries=[], protected_values=VALUES) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s::timestamp WHERE id=%s',
                                      (literal, UUID(int=100)))
        with pytest.raises(m.TransitionFailure) as refused:
            run(app, until='EXPANDED') if at_apply else replan(app)
        assert refused.value.code == 'timestamp_source_domain'
        assert literal not in str(refused.value)
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT count(*) FROM information_schema.columns '
                'WHERE table_schema=%s AND column_name LIKE %s', (app.schema, '_cryptalis_%')).scalar_one() == 0


@pytest.mark.parametrize('dtype', [DateTime(timezone=True), TIMESTAMP(precision=3)])
def test_timestamp_unqualified_timezone_and_precision_refuse(dtype):
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=dtype, queries=[]):
            pytest.fail('unqualified timestamp mapping admitted')
    assert 'unsupported_type' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('dtype', [DateTime(), TIMESTAMP(precision=6)])
def test_timestamp_survives_all_rotations_and_current_value_removal(public_slots, dtype):
    from test_date_lifecycle import date_application, date_keys, remove_date, rotate_all
    with date_application(public_slots=public_slots, value_type=dtype, values=VALUES,
                          value_default=DEFAULT) as app:
        run(app); publish(app)
        rotate_all(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            observed = {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))}
            assert observed == app.source
            session.get(app.Customer, UUID(int=100)).name = datetime(2038, 1, 19, 3, 14, 7, 999999)
            session.commit()
        remove_date(app)
        expected = {**app.source, UUID(int=100): (TENANT, datetime(2038, 1, 19, 3, 14, 7, 999999))}
        assert native_rows(app) == expected


@pytest.mark.parametrize('timestamp', [False, True])
def test_previous_reader_accepts_date_and_refuses_timestamp_before_database(tmp_path, timestamp):
    import subprocess
    from sqlalchemy import Date
    reader = os.environ.get('CRYPTALIS_TIMESTAMP_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v9 reader interpreter')
    with application(value_type=DateTime() if timestamp else Date(), queries=[],
                     protected_values=VALUES if timestamp else (None,), rows=1) as app:
        artifact = tmp_path / 'plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-I', '-c', '''
from pathlib import Path
import sys
from cryptalis.migration import MigrationPlan, TransitionFailure
try:
    MigrationPlan(Path(sys.argv[1]).read_bytes()).document
except TransitionFailure as failure:
    assert sys.argv[2] == 'timestamp' and failure.code == 'invalid_plan'
else:
    assert sys.argv[2] == 'date'
print('reader boundary passed')
''', str(artifact), 'timestamp' if timestamp else 'date'], capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'previous-reader control failed; diagnostics withheld'
        assert child.stdout.strip() == 'reader boundary passed'
