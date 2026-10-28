"""Finite native Date values survive authenticated storage and native exit."""
import asyncio
import os
from datetime import date
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Date, func, select
from sqlalchemy.ext.asyncio import create_async_engine
from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import TENANT, application, frames, keys, publish, run

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
