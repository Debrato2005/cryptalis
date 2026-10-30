"""Cached direct SELECT labels retain native keys and authenticated values."""
import asyncio
import os

import psycopg
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased
from sqlalchemy.sql.elements import Grouping

from cryptalis.sqlalchemy import attach
from test_bulk_insert_native import native_application
from test_migration import TENANT, keys, publish, run


@pytest.mark.parametrize('mode,varchar', [('sync', False), ('sync', True), ('async', False), ('async', True)])
@pytest.mark.parametrize('alias', [False, True])
@pytest.mark.parametrize('search', [False, True])
@pytest.mark.parametrize('wrapper', ['label', 'grouped_label', 'grouped_column'])
def test_cached_labels_preserve_original_lookup_and_values_across_search_rewrite(mode, varchar, alias, search, wrapper):
    with native_application(varchar) as app:
        model = aliased(app.Customer) if alias else app.Customer
        # Standalone parenthesized columns use the native Core result route;
        # native ORM loading cannot locate that unlabeled expression.
        columns = ((app.table.alias('core_source') if alias else app.table).c
                   if wrapper == 'grouped_column' else model)
        value = (Grouping(columns.name).label('protected value') if wrapper == 'grouped_label' else
                 Grouping(columns.name) if wrapper == 'grouped_column' else columns.name.label('protected value'))
        labels = (value, columns.id.label(None), columns.label.label('public value'))
        original = tuple(label.type for label in labels)
        query = select(*labels).where(columns.tenant_id == TENANT).order_by(columns.id)
        if search:
            query = query.where(columns.name.in_(['', '雪😀', None]))

        def consume(result):
            rows = result.all()
            return tuple(result.keys()), [tuple(row) for row in rows], [
                tuple(row[index] if isinstance(label, Grouping) else row._mapping[label]
                      for index, label in enumerate(labels)) for row in rows]

        async def async_observation(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    return consume(await session.execute(query))
            finally:
                await engine.dispose()

        if mode == 'sync':
            with Session(app.runtime) as session:
                expected = consume(session.execute(query))
            run(app)
            publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                actual = consume(session.execute(query))
        else:
            expected = asyncio.run(async_observation(False))
            run(app)
            publish(app)
            actual = asyncio.run(async_observation(True))
        assert actual == expected
        assert all(label.type is dtype for label, dtype in zip(labels, original))
