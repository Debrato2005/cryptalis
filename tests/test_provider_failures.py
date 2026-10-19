"""Provider outage, revocation and lease drills against real PostgreSQL.

The local provider is synthetic. These cases prove that preparation failure
stops before database mutation, that a failed chunk or commit leaves no partial
state, and that a healthy retry resumes from the recorded checkpoint.
"""
import asyncio
import json
import os
import time
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry

import cryptalis.migration as m
from cryptalis.crypto import Keyring, KeyUnavailable
from cryptalis.sqlalchemy import attach

from test_migration import (FIELD_ID, PROVIDER, TABLE_ID, TENANT, PublicFixtureProvider,
                            application, frames, independent_open, keys, publish, run)


class InterruptingProvider(PublicFixtureProvider):
    """Returns the fixture roots until ``allow`` unwrap calls, then fails."""

    def __init__(self, allow):
        self.allow, self.calls = allow, 0

    def unwrap(self, wrapper, context):
        self.calls += 1
        if self.calls > self.allow:
            raise RuntimeError("PRIVATE_PROVIDER_DETAIL")
        return PublicFixtureProvider().unwrap(wrapper, context)

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


class ReplacedProvider(PublicFixtureProvider):
    """A restarted deployment no longer owns the wrappers it used to."""
    provider_id = uuid4()


class ShortMaterialProvider(PublicFixtureProvider):
    """Ambiguous provider reply: the root length is not 32 bytes."""

    def unwrap(self, wrapper, context):
        return b"short"


def resolve(provider):
    def ring(tenant):
        base = keys(tenant)
        return Keyring(base.policy, {PROVIDER: provider})
    return ring


def journal(app):
    with app.owner.connect() as c:
        return c.exec_driver_sql(
            f'SELECT state FROM {app.m._journal(c, app.plan)} WHERE operation_id=%s',
            (app.plan.operation_id,)).scalar_one()


def ciphertext_rows(app):
    with app.owner.connect() as c:
        return c.exec_driver_sql(
            f'SELECT count(*) FROM "{app.schema}".customer '
            f'WHERE "_cryptalis_{FIELD_ID.hex}" IS NOT NULL').scalar_one()


def test_chunk_outage_is_typed_rolls_back_the_failing_chunk_and_resumes():
    with application(rows=7) as app:
        assert run(app, until='EXPANDED').phase == 'EXPANDED'
        provider = InterruptingProvider(allow=2)
        with pytest.raises(m.TransitionFailure, match='KeyUnavailable') as failure:
            run(app, key_resolver=resolve(provider), chunk_size=2)
        assert 'PRIVATE_PROVIDER_DETAIL' not in str(failure.value)
        state = journal(app)
        assert state['phase'] == 'EXPANDED'
        assert state['models'][str(TABLE_ID)]['rows'] == 2
        assert state['models'][str(TABLE_ID)]['chunks'] == 1
        with app.owner.connect() as c:
            untouched = c.exec_driver_sql(
                f'SELECT count(*) FROM "{app.schema}".customer WHERE id > %s '
                f'AND "_cryptalis_{FIELD_ID.hex}" IS NULL AND name IS NOT NULL',
                (UUID(int=101),)).scalar_one()
        assert untouched == 5
        provider.allow = 10 ** 9
        assert run(app, key_resolver=resolve(provider), chunk_size=2).phase == 'PENDING'
        descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
        bodies = frames(app, True)
        observed = {identity: independent_open(bodies[identity], descriptor, tenant, identity)
                    for identity, (tenant, value) in app.source.items()}
        assert observed == {identity: value for identity, (tenant, value) in app.source.items()}


@pytest.mark.parametrize('provider', [ReplacedProvider(), ShortMaterialProvider()],
                         ids=['revoked-identity', 'short-material'])
def test_stale_or_invalid_provider_material_refuses_before_any_backfill_write(provider):
    with application(rows=5) as app:
        assert run(app, until='EXPANDED').phase == 'EXPANDED'
        with pytest.raises(m.TransitionFailure, match='KeyUnavailable'):
            run(app, key_resolver=resolve(provider), chunk_size=2)
        state = journal(app)
        assert state['phase'] == 'EXPANDED'
        assert state['models'][str(TABLE_ID)]['rows'] == 0
        assert ciphertext_rows(app) == 0
        assert run(app, key_resolver=keys, chunk_size=2).phase == 'PENDING'


def test_attached_commit_after_lease_expiry_fails_closed_and_recovers():
    with application(rows=3) as app:
        assert run(app).phase == 'PENDING'
        publish(app)
        provider = InterruptingProvider(allow=10 ** 9)
        ring = Keyring(keys(TENANT).policy, {PROVIDER: provider}, max_age=0.05)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                          keys=lambda tenant: ring, deployment=(app.plan, app.pin))
        first, second = uuid4(), uuid4()
        with sessions(tenant_id=TENANT) as s:
            s.add(app.Customer(id=first, tenant_id=TENANT, name='first', label='one'))
            s.commit()
        time.sleep(0.2)
        provider.allow = 0
        with pytest.raises(KeyUnavailable):
            with sessions(tenant_id=TENANT) as s:
                s.add(app.Customer(id=second, tenant_id=TENANT, name='second', label='two'))
                s.commit()
        with app.owner.connect() as c:
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer WHERE id=%s',
                                     (second,)).scalar_one() == 0
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer WHERE id=%s',
                                     (first,)).scalar_one() == 1
        provider.allow = 10 ** 9
        with sessions(tenant_id=TENANT) as s:
            s.add(app.Customer(id=second, tenant_id=TENANT, name='second', label='two'))
            s.commit()
            assert s.get(app.Customer, second).name == 'second'

        async def check():
            async_engine = create_async_engine(
                'postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            fresh = registry(metadata=MetaData(schema=app.schema))
            table = Table('customer', fresh.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                          Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                          Column('label', Text))
            class Customer: pass
            fresh.map_imperatively(Customer, table)
            try:
                factory = await attach(fresh, async_engine, lock=app.plan.lock_bytes,
                                       keys=lambda tenant: ring, deployment=(app.plan, app.pin))
                third = uuid4()
                async with factory(tenant_id=TENANT) as s:
                    s.add(Customer(id=third, tenant_id=TENANT, name='third', label='three'))
                    time.sleep(0.2)
                    provider.allow = 0
                    with pytest.raises(KeyUnavailable):
                        await s.commit()
                provider.allow = 10 ** 9
                with app.owner.connect() as c:
                    assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer WHERE id=%s',
                                             (third,)).scalar_one() == 0
                async with factory(tenant_id=TENANT) as s:
                    s.add(Customer(id=third, tenant_id=TENANT, name='third', label='three'))
                    await s.commit()
                async with factory(tenant_id=TENANT) as s:
                    assert await s.scalar(select(Customer.name).where(Customer.id == third)) == 'third'
            finally:
                await async_engine.dispose()
                fresh.dispose()
        asyncio.run(check())
