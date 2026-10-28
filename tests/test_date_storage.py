"""Finite native Date values survive authenticated storage and native exit."""
import asyncio
import os
import subprocess
from datetime import date
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Date, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import TENANT, application, frames, keys, publish, run

from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import attach


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_date_protection_sync_async_current_edit_count_and_native_removal(public_slots, mode):
    values = (date.min, date(1970, 1, 1), date(2000, 2, 29), date.max, None)
    with application(rows=5, value_type=Date(), queries=[], protected_values=values) as app:
        if public_slots:
            from test_public_slots import select_layout, slots
            original_slots = slots(app)
            select_layout(app)
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v8'
        assert 'date-ordinal-u32/v1' in app.plan.document['lock']['required_readers']
        assert run(app, until='EXPANDED').phase == 'EXPANDED'
        assert run(app, until='BACKFILLED').phase == 'BACKFILLED'
        assert all(value is None or len(value) == 46 for value in frames(app).values())
        assert run(app).phase == 'PENDING'
        publish(app)
        if mode == 'sync':
            sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                              deployment=(app.plan, app.pin))
            with sessions(tenant_id=TENANT) as session:
                assert session.scalars(select(app.Customer.name).order_by(app.Customer.id)).all() == list(values)
                assert session.scalar(select(func.count(app.Customer.name))) == 4
                row = session.get(app.Customer, UUID(int=101))
                row.name = date(2025, 3, 1)
                session.commit()
        async def check():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                       deployment=(app.plan, app.pin))
                async with factory(tenant_id=TENANT) as session:
                    assert (await session.scalars(select(app.Customer.name).order_by(app.Customer.id))).all() == list(values)
                    assert await session.scalar(select(func.count(app.Customer.name))) == 4
                    row = await session.get(app.Customer, UUID(int=101))
                    assert row.name == date(1970, 1, 1) and type(row.name) is date
                    row.name = date(2025, 3, 1)
                    await session.commit()
            finally:
                await engine.dispose()
        if mode == 'async':
            asyncio.run(check())
        expected = dict(app.source)
        expected[UUID(int=101)] = TENANT, date(2025, 3, 1)
        plan = proposal(app)
        reverse(app, plan)
        reverse(app, plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
        approval, _ = consent(plan, 'PLAINTEXT_ACTIVATING')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
            'native date fixture', 'no retained copies in fixture', True)
        assert d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                        removal=removal, consent=approval).phase == 'REMOVED'
        with app.owner.connect() as connection:
            assert {row[0]: (row[1], row[2]) for row in connection.exec_driver_sql(
                f'SELECT id,tenant_id,name FROM "{app.schema}".customer')} == expected
        if public_slots:
            assert slots(app) == original_slots


@pytest.mark.parametrize('value', ['infinity', '-infinity', '10000-01-01', '0001-01-01 BC'])
def test_date_bounds_refuse_in_planning_before_generated_columns(value):
    from test_public_slots import select_layout
    with application(rows=0, value_type=Date(), queries=[]) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'INSERT INTO "{app.schema}".customer (id,tenant_id,name) '
                'VALUES (%s,%s,%s::date)', (UUID(int=100), TENANT, value))
        with pytest.raises(app.m.TransitionFailure) as refused:
            select_layout(app)
        assert refused.value.code == 'date_outside_python_range'
        with app.owner.connect() as connection:
            assert tuple(connection.exec_driver_sql(f'SELECT * FROM "{app.schema}".customer LIMIT 0').keys()) == (
                'id', 'tenant_id', 'name', 'label')


@pytest.mark.parametrize('case', ['search', 'default', 'custom_type'])
def test_date_unadmitted_intents_defaults_and_custom_mapping_refuse(case):
    class CustomDate(Date):
        pass
    with pytest.raises(PlanningRejected) as refused, application(
            rows=0, value_type=CustomDate() if case == 'custom_type' else Date(),
            queries=['equality'] if case == 'search' else [],
            value_default=date(2020, 1, 1) if case == 'default' else None):
        pytest.fail('unadmitted date configuration reached a plan')
    assert {'search': 'unsupported_query', 'default': 'protected_default',
            'custom_type': 'unsupported_type'}[case] in {issue.code for issue in refused.value.issues}


def test_previous_reader_refuses_date_plan_before_connecting(tmp_path):
    reader = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply a retained pre-date reader interpreter')
    with application(rows=0, value_type=Date(), queries=[]) as app:
        artifact = tmp_path / 'date-plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
import sys
from pathlib import Path
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('old reader must refuse before SQL')
Engine.connect = forbidden
from cryptalis import migration as m
try:
    m.MigrationPlan(Path(sys.argv[1]).read_bytes())
except m.TransitionFailure:
    print('date reader refused')
else:
    raise AssertionError('old reader admitted the date plan')
''', str(artifact)], check=False, capture_output=True, text=True, timeout=20)
        assert child.returncode == 0 and child.stdout.strip() == 'date reader refused', 'old reader refusal failed'
