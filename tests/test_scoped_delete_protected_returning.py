"""Native deleted values pass through authenticated, request-bound CF1 carriers."""
import asyncio
from datetime import date
import importlib
import os
from types import MethodType
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import BigInteger, Boolean, Date, Integer, SmallInteger, String, Text, Uuid, delete
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.crypto import AuthenticationFailed, CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot
from test_sqlalchemy_adapter import app as adapter_app, db, factory as adapter_factory, TENANT as ADAPTER_TENANT


def statement(app, identity, kind):
    columns = (app.Customer.name,) if kind == 'scalar' else (app.Customer.id, app.Customer.name, app.Customer.label)
    return delete(app.Customer).where(app.Customer.tenant_id == TENANT,
        app.Customer.id == identity).returning(*columns)


def consume(result, app, kind):
    assert tuple(result.keys()) == (('name',) if kind == 'scalar' else ('id', 'name', 'label'))
    if kind == 'scalar':
        return result.scalars().all()
    rows = result.all()
    assert all(type(row) is Row and row._mapping[app.Customer.name] == row.name for row in rows)
    return [tuple(row) for row in rows]


@pytest.mark.parametrize('dtype,values', [
    (Text(), (None, '', '雪😀')), (String(4), (None, '', '雪😀')),
    (Boolean(), (None, False, True)), (Integer(), (None, -2**31, 2**31-1)),
    (SmallInteger(), (None, -2**15, 2**15-1)),
    (BigInteger(), (None, -2**63, 2**63-1)),
    (Date(), (None, date.min, date.max)),
    (Uuid(), (None, UUID(int=0), UUID(int=2**128-1))),
])
@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('kind', ['scalar', 'tuple'])
def test_protected_delete_values_types_keys_and_transactions_match_native(dtype, values, mode, kind):
    with application(rows=3, value_type=dtype, protected_values=values, queries=[]) as app:
        def check_types(observed):
            actual = [group[0] if kind == 'scalar' else group[0][1] for group in observed[:3]]
            assert [type(value) for value in actual] == [type(value) for value in values]
            assert actual == list(values)
            assert observed[3:] == [[], []]

        def sync_scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                observed = []
                for identity in (100, 101, 102, 102, 999):
                    query = statement(app, UUID(int=identity), kind)
                    original_types = tuple(item['type'] for item in query.returning_column_descriptions)
                    observed.append(consume(session.execute(query,
                        execution_options={'synchronize_session': False}), app, kind))
                    assert tuple(item['type'] for item in query.returning_column_descriptions) == original_types
                assert not session.identity_map
                session.rollback()
                if factory:
                    assert _snapshot(app) == before
                    assert consume(session.execute(statement(app, UUID(int=102), kind),
                        execution_options={'synchronize_session': False}), app, kind) == observed[2]
                    session.commit()
                    assert session.get(app.Customer, UUID(int=102)) is None
                    assert session.get(app.Customer, UUID(int=100)).name is None
                return observed

        async def async_scenario(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if factory else AsyncSession(engine)) as session:
                    observed = []
                    for identity in (100, 101, 102, 102, 999):
                        query = statement(app, UUID(int=identity), kind)
                        original_types = tuple(item['type'] for item in query.returning_column_descriptions)
                        observed.append(consume(await session.execute(query,
                            execution_options={'synchronize_session': False}), app, kind))
                        assert tuple(item['type'] for item in query.returning_column_descriptions) == original_types
                    assert not session.identity_map
                    await session.rollback()
                    if protected:
                        assert _snapshot(app) == before
                        assert consume(await session.execute(statement(app, UUID(int=102), kind),
                            execution_options={'synchronize_session': False}), app, kind) == observed[2]
                        await session.commit()
                        assert await session.get(app.Customer, UUID(int=102)) is None
                        assert (await session.get(app.Customer, UUID(int=100))).name is None
                    return observed
            finally:
                await engine.dispose()

        expected = sync_scenario() if mode == 'sync' else asyncio.run(async_scenario(False))
        check_types(expected)
        with fresh_mapping(app):
            run(app); publish(app)
            before = _snapshot(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin)) if mode == 'sync' else None
            observed = sync_scenario(factory) if mode == 'sync' else asyncio.run(async_scenario(True))
            check_types(observed)
            assert observed == expected


def test_corrupted_deleted_frame_refuses_and_rollback_restores_row():
    with application(rows=3) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
            deployment=(app.plan, app.pin))
        with app.owner.begin() as connection:
            body = connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
                (UUID(int=102),)).scalar_one()
            bad = body[:-1] + bytes([body[-1] ^ 1])
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                (bad, UUID(int=102)))
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.execute(statement(app, UUID(int=102), 'scalar'),
                    execution_options={'synchronize_session': False}).all()
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['other_row', 'missing_record', 'missing_tenant', 'wrong_tenant'])
@pytest.mark.parametrize('nullable', [False, True])
def test_deleted_result_requires_original_row_and_tenant_context(fault, nullable, monkeypatch):
    adapter = importlib.import_module('cryptalis.sqlalchemy')
    with application(rows=3) as app:
        run(app); publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
            deployment=(app.plan, app.pin))
        target = UUID(int=100 if nullable else 102)
        with app.owner.connect() as connection:
            other = connection.exec_driver_sql(
                f"SELECT encode(name, 'hex'), id, tenant_id FROM \"{app.schema}\".customer WHERE id=%s",
                (UUID(int=101),)).one()
        original = adapter._ReadText.process_result_value
        injected = []
        def substitute(processor, value, dialect):
            changed = list(value)
            if fault == 'other_row': changed = [other[0], str(other[1]), str(other[2])]
            elif fault == 'missing_record': changed = [None, None, None]
            elif fault == 'missing_tenant': changed[2] = None
            else: changed[2] = str(UUID(int=333))
            injected.append(True)
            return original(processor, changed, dialect)
        before = _snapshot(app)
        with monkeypatch.context() as patch:
            patch.setattr(adapter._ReadText, 'process_result_value', substitute)
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(AuthenticationFailed):
                    session.execute(statement(app, target, 'scalar'),
                        execution_options={'synchronize_session': False}).all()
                session.rollback()
        assert injected
        assert _snapshot(app) == before


@pytest.mark.parametrize('adapter_app', [{}, {'bigint': True}], indirect=True, ids=['uuid', 'int64'])
def test_each_deleted_field_authenticates_its_own_frame(adapter_app, monkeypatch):
    app = adapter_app
    factory = adapter_factory(app, True)
    identity = -(2**63) if isinstance(app.Customer.__table__.c.id.type, BigInteger) else UUID(int=9000)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        session.add(app.Customer(id=identity, tenant_id=ADAPTER_TENANT,
            name='public name', note='first field', secret='second field', rank=1))
        session.commit()
    query = delete(app.Customer).where(app.Customer.tenant_id == ADAPTER_TENANT,
        app.Customer.id == identity).returning(app.Customer.note, app.Customer.secret)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        assert tuple(session.execute(query, execution_options={'synchronize_session': False}).one()) == (
            'first field', 'second field')
        session.rollback()
    native_fetchall, injected = psycopg.Cursor.fetchall, []
    def swap_columns(cursor):
        rows = native_fetchall(cursor)
        if rows and not injected:
            protected = [i for i,value in enumerate(rows[0]) if type(value) is list and len(value)==3]
            if len(protected)==2:
                changed = list(rows[0])
                changed[protected[0]], changed[protected[1]] = changed[protected[1]], changed[protected[0]]
                rows[0] = tuple(changed)
                injected.append(True)
        return rows
    with monkeypatch.context() as patch:
        patch.setattr(psycopg.Cursor, 'fetchall', swap_columns)
        with factory(tenant_id=ADAPTER_TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.execute(query, execution_options={'synchronize_session': False}).all()
            session.rollback()
    assert injected == [True]
    with factory(tenant_id=ADAPTER_TENANT) as session:
        restored = session.get(app.Customer, identity)
        assert (restored.note, restored.secret) == ('first field', 'second field')


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_key_callback_cannot_replace_original_protected_annotation(mode, monkeypatch):
    with application(rows=3) as app:
        query = statement(app, UUID(int=102), 'scalar')
        armed, changed = [False], []
        def resolve(tenant):
            if armed[0] and not changed:
                monkeypatch.setattr(query._returning[0], 'type', app.table.c.name.type)
                changed.append(True)
            return keys(tenant)
        run(app); publish(app)
        before = _snapshot(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                armed[0] = True
                with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                    with pytest.raises(CryptoFailure):
                        session.execute(query, execution_options={'synchronize_session': False}).all()
                    assert not sent
                session.rollback()
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=resolve,
                        deployment=(app.plan, app.pin))
                    async with factory(tenant_id=TENANT) as session:
                        armed[0] = True
                        with raw_calls(monkeypatch, app.schema, 'DELETE', asynchronous=True) as sent:
                            with pytest.raises(CryptoFailure):
                                await session.execute(query, execution_options={'synchronize_session': False})
                            assert not sent
                        await session.rollback()
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert changed == [True]
        assert _snapshot(app) == before


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_projection_clone_cannot_replace_original_record_authority(mode, monkeypatch):
    with application(rows=3) as app:
        run(app); publish(app)
        query = statement(app, UUID(int=102), 'scalar')
        injected = []
        def substitute(_self):
            injected.append(True)
            return delete(app.Customer).where(app.Customer.tenant_id == TENANT,
                app.Customer.id == UUID(int=101))
        monkeypatch.setattr(query, '_generate', MethodType(substitute, query))
        before = _snapshot(app)
        if mode == 'sync':
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                    with pytest.raises(CryptoFailure):
                        session.execute(query, execution_options={'synchronize_session': False}).all()
                    assert not sent
                session.rollback()
        else:
            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                        deployment=(app.plan, app.pin))
                    async with factory(tenant_id=TENANT) as session:
                        with raw_calls(monkeypatch, app.schema, 'DELETE', asynchronous=True) as sent:
                            with pytest.raises(CryptoFailure):
                                await session.execute(query, execution_options={'synchronize_session': False})
                            assert not sent
                        await session.rollback()
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert injected == [True]
        assert _snapshot(app) == before
