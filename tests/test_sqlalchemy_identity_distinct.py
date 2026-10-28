"""Selected primary keys let DISTINCT preserve native encrypted row semantics."""
import asyncio
import os
from datetime import date
from types import MethodType

import psycopg
import pytest
from sqlalchemy import Boolean, Date, Text, event, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased
from test_migration import TENANT, application, keys, publish, run
from test_sqlalchemy_search import _scope, search_application

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach


@pytest.mark.parametrize('dtype,values', [
    (Text(collation='C'), ('repeat', 'repeat', None, '', 'last')),
    (Boolean(), (True, True, None, False, False)),
    (Date(), (date.min, date.min, None, date(2000, 2, 29), date.max)),
])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_distinct_entities_tables_and_tuples_keep_native_public_pagination(dtype, values, mode):
    with application(rows=5, value_type=dtype, queries=[], protected_values=values) as app:
        model = app.Customer
        def statements():
            other = aliased(model)
            entity = select(model).where(model.tenant_id == TENANT).distinct().order_by(model.id).offset(1).limit(3)
            table = select(model.__table__).where(model.tenant_id == TENANT).distinct().order_by(model.id).limit(3)
            joined = select(model.id, model.name).join(other, model.tenant_id == other.tenant_id).where(
                model.tenant_id == TENANT).distinct().order_by(model.id).offset(1).limit(3)
            labeled = select(model.id.label('key'), model.name.label('value')).where(
                model.tenant_id == TENANT).distinct().order_by(model.id).limit(3)
            return ((entity, True), (table, False), (joined, False), (labeled, False))
        def materialize(result, statement, entities):
            if entities:
                return [tuple(getattr(row, key) for key in ('id', 'tenant_id', 'name', 'label'))
                        for row in result.scalars()]
            return [tuple(row._mapping[column] for column in statement.selected_columns) for row in result]
        def read(session):
            return tuple(materialize(session.execute(statement), statement, entities)
                         for statement, entities in statements())
        async def asynchronous(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with factory(tenant_id=TENANT) if protected else AsyncSession(engine) as session:
                    results = []
                    for statement, entities in statements():
                        results.append(materialize(await session.execute(statement), statement, entities))
                    return tuple(results)
            finally:
                await engine.dispose()
        if mode == 'async':
            expected = asyncio.run(asynchronous(False))
        else:
            with Session(app.runtime) as native:
                expected = read(native)
        run(app)
        publish(app)
        if mode == 'async':
            assert asyncio.run(asynchronous(True)) == expected
        else:
            sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                              deployment=(app.plan, app.pin))
            with sessions(tenant_id=TENANT) as session:
                assert read(session) == expected


def test_distinct_requires_each_source_record_identity_before_statement_keys():
    with search_application(attach_now=False) as app:
        model, other = app.Customer, aliased(app.Customer)
        changed = aliased(model)
        inspect(changed).selectable.c.id.name = 'rank'
        spoofed = aliased(model)
        spoofed_id = inspect(spoofed).selectable.c.id
        spoofed_id._compiler_dispatch = MethodType(lambda self, visitor, **kw: 'rank', spoofed_id)
        statements = (
            select(other.id, model.name).join(other, model.tenant_id == other.tenant_id).where(_scope(app)).distinct(),
            select(changed.id, changed.name).where(_scope(app, changed)).distinct(),
            select(spoofed.id, spoofed.name).where(_scope(app, spoofed)).distinct(),
        )
        called, observed = [], []
        def resolve(tenant):
            called.append(tenant)
            return app.keys(tenant)
        sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
        event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
        with sessions(tenant_id=app.tenant) as session:
            called.clear()
            for statement in statements:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement)
                assert called == [] and observed == []
