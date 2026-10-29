"""Native public-column results from one tenant-and-record DELETE."""
import asyncio
import os
from types import MethodType
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String, delete, func, literal_column, select
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import native_application
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


def statement(app, identity=UUID(int=101), kind='tuple'):
    columns = (app.Customer.id,) if kind == 'scalar' else (app.Customer.id, app.Customer.label)
    return delete(app.Customer).where(
        app.Customer.tenant_id == TENANT, app.Customer.id == identity).returning(*columns)


def consume(result, app, kind):
    assert tuple(result.keys()) == (('id',) if kind == 'scalar' else ('id', 'label'))
    if kind == 'scalar':
        return result.scalars().all()
    rows = result.all()
    assert all(type(row) is Row and row._mapping[app.Customer.id] == row.id for row in rows)
    return [tuple(row) for row in rows]


@pytest.mark.parametrize('varchar', [False, True])
@pytest.mark.parametrize('kind', ['scalar', 'tuple'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_public_delete_results_match_native_keys_values_and_rollback(varchar, kind, mode):
    def foreign_row(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) VALUES(%s,%s,%s,%s)',
            (UUID(int=103), UUID(int=333), None, 'foreign'))
    with application(rows=3, value_type=String(4, collation='C') if varchar else None,
                     setup=foreign_row) as app:

        def sync_scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                observed = [consume(session.execute(statement(app, identity, kind),
                    execution_options={'synchronize_session': False}), app, kind)
                    for identity in (UUID(int=101), UUID(int=101), UUID(int=999), UUID(int=103))]
                assert not session.identity_map
                session.rollback()
                if factory:
                    assert _snapshot(app) == before
                    assert consume(session.execute(statement(app, kind=kind),
                        execution_options={'synchronize_session': False}), app, kind) == observed[0]
                    session.commit()
                    assert session.get(app.Customer, UUID(int=101)) is None
                    assert session.get(app.Customer, UUID(int=100)) is not None
                return observed

        async def async_scenario(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if factory else AsyncSession(engine)) as session:
                    observed = [consume(await session.execute(statement(app, identity, kind),
                        execution_options={'synchronize_session': False}), app, kind)
                        for identity in (UUID(int=101), UUID(int=101), UUID(int=999), UUID(int=103))]
                    assert not session.identity_map
                    await session.rollback()
                    if protected:
                        assert _snapshot(app) == before
                        assert consume(await session.execute(statement(app, kind=kind),
                            execution_options={'synchronize_session': False}), app, kind) == observed[0]
                        await session.commit()
                        assert await session.get(app.Customer, UUID(int=101)) is None
                        assert await session.get(app.Customer, UUID(int=100)) is not None
                    return observed
            finally:
                await engine.dispose()

        expected = sync_scenario() if mode == 'sync' else asyncio.run(async_scenario(False))
        assert len(expected[0]) == 1 and expected[1:] == [[], [], []]
        with fresh_mapping(app):
            run(app); publish(app)
            before = _snapshot(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                keys=keys, deployment=(app.plan, app.pin)) if mode == 'sync' else None
            actual = sync_scenario(factory) if mode == 'sync' else asyncio.run(async_scenario(True))
            assert actual == expected


@pytest.mark.parametrize('fault', ['protected', 'entity', 'label', 'expression', 'foreign', 'custom',
                                 'custom_type', 'native_type'])
def test_unadmitted_delete_projections_refuse_before_keys_or_driver(fault, monkeypatch):
    with native_application(False) as app:
        resolved = []
        def resolve(tenant):
            resolved.append(True)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        columns = {
            'protected': (app.Customer.name,), 'entity': (app.Customer,),
            'label': (app.Customer.id.label('renamed'),),
            'expression': (func.lower(app.Customer.label),),
            'foreign': (select(app.Customer.id).subquery().c.id,),
            'custom': (app.Customer.id,),
            'custom_type': (app.Customer.id,), 'native_type': (app.Customer.id,),
        }[fault]
        query = delete(app.Customer).where(app.Customer.tenant_id == TENANT,
            app.Customer.id == UUID(int=101)).returning(*columns)
        if fault == 'custom':
            target = query._returning[0]
            monkeypatch.setattr(target, '_compiler_dispatch', MethodType(lambda *a, **k: 'NULL', target))
        elif fault in ('custom_type', 'native_type'):
            class CustomResult(TypeDecorator):
                impl = String
                cache_ok = False
                def column_expression(self, column):
                    return literal_column("'custom-result'", String())
            monkeypatch.setattr(query._returning[0], 'type',
                CustomResult() if fault == 'custom_type' else String())
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            resolved.clear()
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with pytest.raises(CryptoFailure):
                    session.execute(query, execution_options={'synchronize_session': False})
                assert not resolved and not sent
            session.rollback()
        assert _snapshot(app) == before


@pytest.mark.parametrize('change', ['add', 'remove', 'reorder', 'type'])
def test_provider_cannot_change_original_returned_columns(change, monkeypatch):
    with native_application(False) as app:
        query = statement(app)
        armed = [False]
        def resolve(tenant):
            if armed[0]:
                columns = query._returning
                if change == 'type':
                    monkeypatch.setattr(columns[0], 'type', String())
                else:
                    query._returning = (columns + (app.Customer.tenant_id.__clause_element__(),)
                        if change == 'add' else () if change == 'remove' else tuple(reversed(columns)))
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            armed[0] = True
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with pytest.raises(CryptoFailure):
                    session.execute(query, execution_options={'synchronize_session': False})
                assert not sent
            session.rollback()
        assert _snapshot(app) == before
