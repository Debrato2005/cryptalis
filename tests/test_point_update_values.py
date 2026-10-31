"""Native point UPDATE.values() must retain normal row counts and ORM state."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from test_migration import application, keys, publish, run, TABLE_ID, TENANT
from test_point_update_rows import query, selection
from test_scoped_delete import no_rows
from test_search_retained_readers import remove_current
from test_single_tenant_update import single_application, snapshot


@pytest.mark.parametrize('fixed', [False, True])
@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_embedded_point_counts_identity_savepoints_and_current_value_exit_match_native(fixed, mode):
    with (single_application() if fixed else application(rows=3)) as app:
        tenant = TABLE_ID if fixed else TENANT
        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            with (factory(tenant_id=tenant) if factory else native(app.runtime)) as session:
                execute = session.exec if mode == 'sqlmodel' else session.execute
                original = session.get(app.Customer, UUID(int=101))
                counts = []
                for identity in (101, 101, 999):
                    result = execute(query(app, fixed, UUID(int=identity)).values(**{'value' if fixed else 'name': 'updated'}),
                        execution_options={'synchronize_session': False})
                    counts.append(result.rowcount)
                    no_rows(result, 0 if identity == 999 else 1)
                assert counts == [1, 1, 0]
                assert session.get(app.Customer, UUID(int=101)) is original
                assert getattr(original, 'value' if fixed else 'name') == ''
                session.refresh(original)
                assert getattr(original, 'value' if fixed else 'name') == 'updated'
                savepoint = session.begin_nested()
                no_rows(execute(query(app, fixed, UUID(int=102)).values(**{'value' if fixed else 'name': None}),
                    execution_options={'synchronize_session': False}), 1)
                savepoint.rollback()
                assert getattr(session.get(app.Customer, UUID(int=102)), 'value' if fixed else 'name') == ('seed' if fixed else '雪😀')
                session.rollback()
                no_rows(execute(query(app, fixed, UUID(int=102)).values(**{'value' if fixed else 'name': 'latest no-return value'}),
                    execution_options={'synchronize_session': False}), 1)
                observed = [tuple(value) for value in execute(selection(app, fixed)).all()]
                session.commit() if factory else session.rollback()
                return observed

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=tenant) if protected else native(engine)) as session:
                    execute = session.exec if mode == 'sqlmodel_async' else session.execute
                    original = await session.get(app.Customer, UUID(int=101))
                    counts = []
                    for identity in (101, 101, 999):
                        result = await execute(query(app, fixed, UUID(int=identity)).values(**{'value' if fixed else 'name': 'updated'}),
                            execution_options={'synchronize_session': False})
                        counts.append(result.rowcount)
                        no_rows(result, 0 if identity == 999 else 1)
                    assert counts == [1, 1, 0]
                    assert await session.get(app.Customer, UUID(int=101)) is original
                    assert getattr(original, 'value' if fixed else 'name') == ''
                    await session.refresh(original)
                    assert getattr(original, 'value' if fixed else 'name') == 'updated'
                    savepoint = await session.begin_nested()
                    no_rows(await execute(query(app, fixed, UUID(int=102)).values(**{'value' if fixed else 'name': None}),
                        execution_options={'synchronize_session': False}), 1)
                    await savepoint.rollback()
                    assert getattr(await session.get(app.Customer, UUID(int=102)), 'value' if fixed else 'name') == ('seed' if fixed else '雪😀')
                    await session.rollback()
                    no_rows(await execute(query(app, fixed, UUID(int=102)).values(**{'value' if fixed else 'name': 'latest no-return value'}),
                        execution_options={'synchronize_session': False}), 1)
                    observed = [tuple(value) for value in (await execute(selection(app, fixed))).all()]
                    await session.commit() if protected else await session.rollback()
                    return observed
            finally:
                await engine.dispose()

        expected = asyncio.run(asynchronous(False)) if 'async' in mode else sync()
        # Fixed-scope mappings intentionally rename attributes; retain those
        # names with a fresh registry before protected attachment.
        from sqlalchemy.orm import registry
        previous = app.mapping, app.Customer
        mapping = registry(metadata=app.table.metadata)
        class Customer: pass
        mapping.map_imperatively(Customer, app.table, properties={
            'record': app.table.c.id, 'value': app.table.c.name, 'public': app.table.c.label} if fixed else {})
        app.mapping, app.Customer = mapping, Customer
        try:
            run(app); publish(app)
            if 'async' in mode:
                observed = asyncio.run(asynchronous(True))
            else:
                selected = attach
                if mode == 'sqlmodel':
                    from cryptalis.sqlmodel import attach as selected
                observed = sync(selected(mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)))
            assert observed == expected
            remove_current(app, keys)
            assert [tuple(value) for value in snapshot(app)] == expected
        finally:
            app.mapping, app.Customer = previous
            mapping.dispose()
