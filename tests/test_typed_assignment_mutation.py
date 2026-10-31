"""Provider preparation cannot change captured native assignment semantics."""

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
import os
from uuid import UUID
from zoneinfo import ZoneInfo

import psycopg
import pytest
from sqlalchemy import DateTime, Numeric, select, update
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


NEW_YORK = ZoneInfo('America/New_York')
CASES = [
    pytest.param(Numeric(), Decimal('9.00'), Decimal('1.20'), Decimal('1.2'), id='decimal-scale'),
    pytest.param(DateTime(timezone=True), datetime(2020, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK, fold=0),
        datetime(2026, 11, 1, 1, 30, tzinfo=NEW_YORK, fold=1), id='datetime-fold'),
]


def stored_state(value):
    if type(value) is Decimal:
        return value.as_tuple()
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def request(app, route, value):
    clause = update(app.Customer).where(app.Customer.tenant_id == TENANT)
    if route != 'scoped_parameters':
        clause = clause.where(app.Customer.id == UUID(int=100))
    values = {'name': value, 'label': 'healthy typed assignment'}
    if route == 'point_values':
        return clause.values(**values), None
    if route == 'scoped_parameters':
        return clause, [dict(values, id=UUID(int=100))]
    return clause, values


@pytest.mark.parametrize('dtype,initial,original,replacement', CASES)
@pytest.mark.parametrize('route', ['point_values', 'point_parameters', 'scoped_parameters'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_provider_cannot_change_captured_fold_or_decimal_scale(
        dtype, initial, original, replacement, route, mode, monkeypatch):
    # Python equality hides both changes; the native stored representations differ.
    assert original == replacement
    assert stored_state(original) != stored_state(replacement)
    with application(rows=2, value_type=dtype, queries=[], protected_values=(initial,)) as app:
        run(app); publish(app)
        clause, parameters = request(app, route, original)
        armed, changed = [False], []

        def resolve(tenant):
            if armed[0] and not changed:
                if route == 'point_values':
                    target = next(node for node in visitors.iterate(clause)
                        if isinstance(node, BindParameter) and node.value is original)
                    target.value = replacement
                elif route == 'point_parameters':
                    parameters['name'] = replacement
                else:
                    parameters[0]['name'] = replacement
                changed.append(True)
            return keys(tenant)

        before = _snapshot(app)
        options = {'synchronize_session': False}

        def assert_rows(rows):
            assert {row.id: (stored_state(row.name), row.label) for row in rows} == {
                UUID(int=100): (stored_state(original), 'healthy typed assignment'),
                UUID(int=101): (stored_state(initial), 'label-101'),
            }

        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                keys=resolve, deployment=(app.plan, app.pin))
            with raw_calls(monkeypatch, app.schema, 'UPDATE') as calls:
                with factory(tenant_id=TENANT) as session:
                    armed[0] = True
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(clause, parameters, execution_options=options)
                    armed[0] = False
                    session.rollback()
                    assert changed == [True] and calls == []
                    assert _snapshot(app) == before
                    healthy, values = request(app, route, original)
                    session.execute(healthy, values, execution_options=options)
                    session.commit()
                    assert_rows(session.scalars(select(app.Customer)).all())
                assert calls  # The collector observes the successful native UPDATE.
        else:
            async def asynchronous():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                        keys=resolve, deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, 'UPDATE', asynchronous=True) as calls:
                        async with factory(tenant_id=TENANT) as session:
                            armed[0] = True
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(clause, parameters, execution_options=options)
                            armed[0] = False
                            await session.rollback()
                            assert changed == [True] and calls == []
                            assert _snapshot(app) == before
                            healthy, values = request(app, route, original)
                            await session.execute(healthy, values, execution_options=options)
                            await session.commit()
                            assert_rows((await session.scalars(select(app.Customer))).all())
                        assert calls
                finally:
                    await engine.dispose()
            asyncio.run(asynchronous())
