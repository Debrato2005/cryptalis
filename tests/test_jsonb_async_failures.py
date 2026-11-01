"""Async JSON preparation failures preserve native transaction recovery."""
import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from cryptalis.crypto import KeyUnavailable
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_driver_event_boundary import raw_calls
from test_jsonb_boundaries import CallbackProvider, stored_rows
from test_jsonb_storage import application, mapping_for, protect, state, wire
from test_migration import TENANT


@asynccontextmanager
async def mapped_sessions(app, provider=None):
    mapping, _, Model = mapping_for(app.schema, app.none_as_null)
    database = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    try:
        if provider is None:
            factory = lambda: AsyncSession(database)
        else:
            attached = await attach(mapping, database, lock=app.plan.lock_bytes, keys=provider.resolve,
                                    deployment=(app.plan, app.pin))
            factory = lambda: attached(tenant_id=TENANT)
        yield Model, factory
    finally:
        await database.dispose()
        mapping.dispose()


@pytest.mark.parametrize('fault', ['unavailable', 'cancelled'])
def test_jsonb_pending_async_root_exit_failure_rolls_back_and_session_retries(fault, monkeypatch):
    native_id, protected_id = UUID(int=970), UUID(int=971)
    document = {'committed after recovery': [True, None, 1.0]}
    with application() as app:
        original = wire(app)

        async def native():
            async with mapped_sessions(app) as (Model, factory):
                with raw_calls(monkeypatch, app.schema, 'INSERT', asynchronous=True) as calls:
                    async with factory() as session:
                        with pytest.raises(IntegrityError) as failure:
                            async with session.begin():
                                session.add_all((Model(id=native_id, tenant_id=TENANT, name=deepcopy(document)),
                                    Model(id=UUID(int=100), tenant_id=TENANT, name={'duplicate': True})))
                        assert failure.value.orig.sqlstate == '23505' and calls
                        assert not session.in_transaction() and session.is_active and not session.new
                        assert wire(app) == original
                        assert await session.get(Model, native_id) is None
                        await session.rollback()
                        async with session.begin():
                            session.add(Model(id=native_id, tenant_id=TENANT, name=deepcopy(document)))
                        expected = state(await session.scalar(select(Model.name).where(Model.id == native_id)))
                        await session.rollback()
                        assert not session.in_transaction()
                        return expected

        expected = asyncio.run(native())
        protect(app)
        before = stored_rows(app)

        async def protected():
            entered, body = asyncio.Event(), []

            class ExitProvider(CallbackProvider):
                async def unwrap_async(self, wrapper, context):
                    if self.armed:
                        self.preparations.append('exit preparation')
                        entered.set()
                        if fault == 'unavailable':
                            raise KeyUnavailable()
                        await asyncio.Future()
                    return await super().unwrap_async(wrapper, context)

            provider = ExitProvider()
            async with mapped_sessions(app, provider) as (Model, factory):
                with raw_calls(monkeypatch, app.schema, 'INSERT', asynchronous=True) as calls:
                    async with factory() as session:
                        pending = Model(id=protected_id, tenant_id=TENANT, name=deepcopy(document))

                        async def commit_pending():
                            async with session.begin():
                                session.add(pending)
                                body.append('only pending write')

                        provider.preparations.clear()
                        provider.armed = True
                        task = asyncio.create_task(commit_pending())
                        try:
                            await asyncio.wait_for(entered.wait(), timeout=10)
                            if fault == 'cancelled':
                                task.cancel()
                            with pytest.raises(KeyUnavailable if fault == 'unavailable' else asyncio.CancelledError):
                                await task
                        finally:
                            if not task.done():
                                task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                            provider.armed = False
                        assert body == ['only pending write'] and provider.preparations == ['exit preparation']
                        assert calls == [] and stored_rows(app) == before
                        assert not session.in_transaction() and session.is_active and not session.new
                        assert pending not in session
                        assert await session.get(Model, protected_id) is None
                        await session.rollback()
                        async with session.begin():
                            session.add(Model(id=protected_id, tenant_id=TENANT, name=deepcopy(document)))
                        assert not session.in_transaction()
                        assert state(await session.scalar(select(Model.name).where(Model.id == protected_id))) == expected
                        await session.rollback()
                        assert not session.in_transaction() and calls

        asyncio.run(protected())


def test_jsonb_async_bulk_insert_refuses_nested_provider_mutation_and_retries(monkeypatch):
    identity = UUID(int=972)
    original = {'nested': [True, 1.0], 'other': 'unchanged'}
    with application() as app:
        async def native():
            async with mapped_sessions(app) as (Model, factory):
                with raw_calls(monkeypatch, app.schema, 'INSERT', asynchronous=True) as calls:
                    async with factory() as session:
                        await session.execute(insert(Model),
                            [{'id': identity, 'tenant_id': TENANT, 'name': deepcopy(original)}])
                        expected = state(await session.scalar(select(Model.name).where(Model.id == identity)))
                        await session.rollback()
                        assert calls
                        return expected

        expected = asyncio.run(native())
        protect(app)
        before = stored_rows(app)

        async def protected():
            value = deepcopy(original)
            provider = CallbackProvider(lambda: value['nested'].__setitem__(0, 1))
            async with mapped_sessions(app, provider) as (Model, factory):
                with raw_calls(monkeypatch, app.schema, 'INSERT', asynchronous=True) as calls:
                    async with factory() as session:
                        parameters = [{'id': identity, 'tenant_id': TENANT, 'name': value}]
                        operation = session.execute(insert(Model), parameters)
                        provider.armed = True
                        with pytest.raises(UnsupportedProtectedOperation):
                            await operation
                        provider.armed = False
                        await session.rollback()
                        assert provider.changed == [True] and 'async' in provider.preparations
                        assert value == original and state(value) != state(original)
                        assert calls == [] and stored_rows(app) == before
                        await session.execute(insert(Model),
                            [{'id': identity, 'tenant_id': TENANT, 'name': deepcopy(original)}])
                        await session.commit()
                        assert state(await session.scalar(select(Model.name).where(Model.id == identity))) == expected
                        await session.rollback()
                        assert calls

        asyncio.run(protected())
