"""Native tuple/entity INSERT results through actual protected migrations."""
import asyncio
from copy import deepcopy
from datetime import date
import os
from types import MethodType
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Boolean, Date, Integer, Text, Uuid, event, insert
from sqlalchemy.engine import Row
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from cryptalis.crypto import AuthenticationFailed, CryptoFailure
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TENANT
from test_sqlalchemy_adapter import app as adapter_app, db, factory as adapter_factory, TENANT as ADAPTER_TENANT


def statement(app, kind, ordered):
    model = app.Customer
    columns = (model,) if kind == 'entity' else (model.id, model.name, model.label)
    return insert(model).returning(*columns, sort_by_parameter_order=ordered)


def consume(session, app, result, kind):
    assert tuple(result.keys()) == (('Customer',) if kind == 'entity' else ('id', 'name', 'label'))
    rows = result.all()
    assert all(type(row) is Row for row in rows)
    if kind == 'entity':
        entities = [row[0] for row in rows]
        assert all(type(entity) is app.Customer for entity in entities)
        assert set(session.identity_map.values()) == set(entities)
        return [(entity.id, entity.name, entity.label) for entity in entities], entities
    assert not session.identity_map
    assert all(row._mapping[app.Customer.name] == row.name for row in rows)
    return [tuple(row) for row in rows], []


@pytest.mark.parametrize('dtype,values', [
    (Text(), ('雪😀', '', None)), (Boolean(), (True, False, None)),
    (Integer(), (-2**31, 2**31-1, None)),
    (Date(), (date.min, date.max, None)), (Uuid(), (UUID(int=0), UUID(int=2**128-1), None)),
])
@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('kind', ['tuple', 'entity'])
@pytest.mark.parametrize('ordered', [False, True])
def test_native_tuple_and_entity_returning_pages_identity_and_refresh(dtype, values, mode, kind, ordered):
    with application(rows=3, value_type=dtype, protected_values=values, queries=[]) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        rows = [dict(id=UUID(int=1000+i), tenant_id=TENANT, name=values[i % 3],
                     **({'label': 'public'} if i < 4 else {})) for i in range(6)]
        original = deepcopy(rows)

        def sync_scenario(factory=None):
            with (factory(tenant_id=TENANT) if factory else Session(app.runtime)) as session:
                result = session.execute(statement(app, kind, ordered), rows,
                    execution_options={'render_nulls': True})
                observed, entities = consume(session, app, result, kind)
                if entities:
                    first = entities[0]
                    assert session.get(app.Customer, first.id) is first
                    session.expire(first)
                    session.refresh(first)
                    assert (first.id, first.name, first.label) == observed[0]
                session.rollback()
                return observed

        async def async_scenario(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True, insertmanyvalues_page_size=2,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if factory else AsyncSession(engine)) as session:
                    result = await session.execute(statement(app, kind, ordered), rows,
                        execution_options={'render_nulls': True})
                    observed, entities = consume(session, app, result, kind)
                    if entities:
                        first = entities[0]
                        assert await session.get(app.Customer, first.id) is first
                        session.expire(first)
                        await session.refresh(first)
                        assert (first.id, first.name, first.label) == observed[0]
                    await session.rollback()
                    return observed
            finally:
                await engine.dispose()

        expected = sync_scenario() if mode == 'sync' else asyncio.run(async_scenario(False))
        with fresh_mapping(app):
            run(app); publish(app)
            if mode == 'sync':
                factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                                 deployment=(app.plan, app.pin))
                actual = sync_scenario(factory)
            else:
                actual = asyncio.run(async_scenario(True))
        assert rows == original and actual == expected
        if ordered:
            assert [row[0] for row in actual] == [row['id'] for row in rows]
        assert sorted(actual) == sorted((row['id'], row['name'], row.get('label')) for row in rows)


@pytest.mark.parametrize('kind', ['tuple', 'entity', 'labels'])
def test_multiple_protected_returning_outputs_authenticate_each_frame(adapter_app, kind, monkeypatch):
    app = adapter_app
    factory = adapter_factory(app, True)
    inputs = [dict(id=UUID(int=9000), tenant_id=ADAPTER_TENANT, name='public', rank=1,
                   note='first field', secret='second field')]
    columns = (app.Customer,) if kind == 'entity' else (app.Customer.note, app.Customer.secret)
    if kind == 'labels':
        columns = tuple(column.label(column.key) for column in columns)
    query = insert(app.Customer).returning(*columns)
    with factory(tenant_id=ADAPTER_TENANT) as session:
        result = session.execute(query, inputs)
        observed = result.scalar_one() if kind == 'entity' else result.one()
        assert (observed.note, observed.secret) == ('first field', 'second field')
        session.rollback()
    native_fetchall, injected = psycopg.Cursor.fetchall, []
    def swap_columns(cursor):
        rows = native_fetchall(cursor)
        if rows and not injected:
            protected = [i for i, value in enumerate(rows[0]) if type(value) is list and len(value) == 3]
            if len(protected) == 2:
                changed = list(rows[0])
                changed[protected[0]], changed[protected[1]] = changed[protected[1]], changed[protected[0]]
                rows[0] = tuple(changed)
                injected.append(True)
        return rows
    with monkeypatch.context() as patch:
        patch.setattr(psycopg.Cursor, 'fetchall', swap_columns)
        with factory(tenant_id=ADAPTER_TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.execute(query, inputs).all()
            session.rollback()
    assert injected == [True]


@pytest.mark.parametrize('fault', ['root', 'public_column', 'private_column'])
def test_custom_returning_dispatch_refuses_before_keys_and_sql(fault):
    with application() as app:
        run(app); publish(app)
        resolutions, sent = [], []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        query = statement(app, 'tuple', False)
        if fault == 'root':
            target = query
        else:
            target = query._returning[0 if fault == 'public_column' else 1]
        target._compiler_dispatch = MethodType(lambda self, compiler, **kw: '12345', target)
        def observe(*args):
            sent.append(True)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                with pytest.raises(CryptoFailure):
                    session.execute(query, [dict(id=UUID(int=9000), tenant_id=TENANT, name='new')])
                assert resolutions == sent == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)


def test_public_only_returning_preserves_native_scalar_ids():
    with application() as app:
        rows = [dict(id=UUID(int=i), tenant_id=TENANT, name=str(i)) for i in (9002, 9000, 9001)]
        query = lambda: insert(app.Customer).returning(app.Customer.id, sort_by_parameter_order=True)
        with Session(app.runtime) as session:
            expected = session.scalars(query(), rows).all()
            session.rollback()
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                assert session.scalars(query(), rows).all() == expected == [row['id'] for row in rows]
                assert not session.identity_map
