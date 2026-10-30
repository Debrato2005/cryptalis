"""Native DELETE RETURNING values, identity state and transaction behavior."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import delete, event, inspect
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TENANT


def statement(app, identity, kind='scalar'):
    columns = ((app.Customer,) if kind == 'entity' else (app.Customer.name,)
               if kind == 'scalar' else (app.Customer.id, app.Customer.name, app.Customer.label))
    return delete(app.Customer).where(app.Customer.id == identity,
        app.Customer.tenant_id == TENANT).returning(*columns)


def observe(result, kind):
    labels = tuple(result.keys())
    rows = result.all()
    values = [(row[0].id, row[0].name, row[0].label) if kind == 'entity' else tuple(row) for row in rows]
    return labels, values, [tuple(type(value) for value in row) for row in values]


@pytest.mark.parametrize('kind', ['scalar', 'tuple', 'entity'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_delete_returning_matches_native_nulls_missing_rows_identity_and_transactions(kind, mode):
    with application(rows=3) as app:
        options = {'synchronize_session': False}
        def sync(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                loaded = session.get(app.Customer, UUID(int=101))
                result = [observe(session.execute(statement(app, UUID(int=i), kind),
                    execution_options=options), kind) for i in (100, 101, 102, 999)]
                assert inspect(loaded).persistent and not inspect(loaded).deleted
                assert session.get(app.Customer, UUID(int=101)) is loaded
                session.rollback()
                assert session.get(app.Customer, UUID(int=101)).name == ''
                savepoint = session.begin_nested()
                assert session.execute(statement(app, UUID(int=100)), execution_options=options).scalar_one() is None
                savepoint.rollback()
                assert session.get(app.Customer, UUID(int=100)).name is None
                assert session.execute(statement(app, UUID(int=102)), execution_options=options).scalar_one() == '雪😀'
                session.commit() if factory else session.rollback()
                return result
        async def asynchronous(protected):
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if factory else AsyncSession(runtime)) as session:
                    loaded = await session.get(app.Customer, UUID(int=101))
                    result = [observe(await session.execute(statement(app, UUID(int=i), kind),
                        execution_options=options), kind) for i in (100, 101, 102, 999)]
                    assert inspect(loaded).persistent and not inspect(loaded).deleted
                    assert await session.get(app.Customer, UUID(int=101)) is loaded
                    await session.rollback()
                    assert (await session.get(app.Customer, UUID(int=101))).name == ''
                    savepoint = await session.begin_nested()
                    assert (await session.execute(statement(app, UUID(int=100)), execution_options=options)).scalar_one() is None
                    await savepoint.rollback()
                    assert (await session.get(app.Customer, UUID(int=100))).name is None
                    assert (await session.execute(statement(app, UUID(int=102)), execution_options=options)).scalar_one() == '雪😀'
                    await session.commit() if protected else await session.rollback()
                    return result
            finally:
                await runtime.dispose()
        expected = sync() if mode == 'sync' else asyncio.run(asynchronous(False))
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if mode == 'sync' else None
            sent = []
            def record(connection, cursor, sql, parameters, context, many):
                if sql.lstrip().upper().startswith('DELETE '):
                    assert 'RETURNING' in sql and not many
                    sent.append(True)
            event.listen(app.runtime, 'before_cursor_execute', record)
            try:
                if mode == 'sync':
                    observed = sync(factory)
                    assert len(sent) == 6
                else:
                    observed = asyncio.run(asynchronous(True))
                assert observed == expected
            finally:
                event.remove(app.runtime, 'before_cursor_execute', record)
            with app.owner.connect() as connection:
                assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == 2
