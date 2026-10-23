"""Native and attached async UUID identities retain PostgreSQL behavior."""
import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, event
from sqlalchemy.exc import DBAPIError, NoResultFound
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import registry

from cryptalis.sqlalchemy import attach
from test_migration import TENANT, application, keys, publish, run


async def exercise(app, protected):
    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        async_creator=lambda: psycopg.AsyncConnection.connect(
            os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False),
        Column('name', Text(collation='C')), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    statements = []
    def observe(connection, cursor, statement, parameters, context, many):
        statements.append(None)
    observations = []
    identity = UUID(int=100)
    absent = UUID('12345678-1234-4abc-8def-1234567890ab')
    raw = identity.hex
    forms = (str(identity), str(identity).upper(), '{' + str(identity) + '}',
             raw, '-'.join(raw[index:index + 4] for index in range(0, 32, 4)))
    try:
        if protected:
            factory = await attach(mapping, engine, lock=app.plan.lock_bytes,
                keys=keys, deployment=(app.plan, app.pin))
            sessions = lambda: factory(tenant_id=TENANT)
        else:
            sessions = async_sessionmaker(engine)
        event.listen(engine.sync_engine, 'before_cursor_execute', observe)
        for method in ('get', 'get_one'):
            for value in forms:
                async with sessions() as session:
                    lookup = getattr(session, method)
                    before = len(statements)
                    first = await lookup(Customer, value)
                    assert len(statements) - before == 1
                    assert type(first.id) is UUID and first.id == identity
                    assert first.tenant_id == TENANT and first.name == 'public first'
                    before = len(statements)
                    assert await lookup(Customer, value) is first
                    assert len(statements) - before == 1
                    before = len(statements)
                    assert await session.get(Customer, identity) is first
                    assert await session.get_one(Customer, identity) is first
                    assert len(statements) == before
                    observations.append((method, value, first.id, first.name))

        async with sessions() as session:
            for missing in (absent, str(absent), str(absent).upper()):
                assert await session.get(Customer, missing) is None
                with pytest.raises(NoResultFound):
                    await session.get_one(Customer, missing)
            assert (await session.get(Customer, UUID(int=101))).name == 'public second'
            observations.append(('missing', None, 'NoResultFound', 'public second'))

        for method in ('get', 'get_one'):
            async with sessions() as session:
                with pytest.raises(DBAPIError) as malformed:
                    await getattr(session, method)(Customer, 'not-a-uuid')
                assert malformed.value.orig.sqlstate == '22P02'
                assert session.is_active
                with pytest.raises(DBAPIError) as aborted:
                    await session.get(Customer, identity)
                assert aborted.value.orig.sqlstate == '25P02'
                await session.rollback()
                first = await session.get(Customer, identity)
                assert first.name == 'public first'
                observations.append((method, '22P02', '25P02', first.name))
        return observations
    finally:
        if event.contains(engine.sync_engine, 'before_cursor_execute', observe):
            event.remove(engine.sync_engine, 'before_cursor_execute', observe)
        await engine.dispose()
        mapping.dispose()


def test_async_uuid_identity_matches_native_cache_errors_and_rollback():
    with application(rows=2, queries=[],
                     protected_values=('public first', 'public second')) as app:
        native = asyncio.run(exercise(app, False))
        assert run(app).phase == 'PENDING'
        assert publish(app).phase == 'ACTIVE'
        assert asyncio.run(exercise(app, True)) == native
