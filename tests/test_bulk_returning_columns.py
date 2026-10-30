"""Native row shape and authenticated values for multi-column INSERT RETURNING."""
import asyncio
from copy import deepcopy
import os

import psycopg
import pytest
from sqlalchemy import event, insert
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from cryptalis.crypto import CryptoFailure
from test_bulk_insert import protect
from test_bulk_insert_native import native_application
from test_bulk_returning import (assert_plaintext_collection, fresh_mapping,
                                 observe_inserts, returning_rows, stored_selection)
from test_migration import keys, publish, run, TENANT
from test_driver_event_boundary import raw_calls
from test_rewrap_plan import _snapshot
from test_sqlalchemy_adapter import (app as adapter_app, db, factory as adapter_factory,
                                     TABLE_ID as ADAPTER_TABLE_ID, TENANT as ADAPTER_TENANT)
from sqlalchemy.orm import registry


def returning(app, ordered, public_only):
    model = app.Customer
    columns = ((model.id, model.label, model.tenant_id) if public_only else
               (model.id, model.name, model.label, model.tenant_id, model.name))
    return insert(model).returning(*columns, sort_by_parameter_order=ordered)


def consume(result, session):
    names = tuple(result.keys())
    rows = result.all()
    assert len(session.identity_map) == 0
    return names, [tuple(row) for row in rows], [type(row) for row in rows]


@pytest.mark.parametrize('public_only', [False, True], ids=['mixed-columns', 'public-columns'])
@pytest.mark.parametrize('ordered', [False, True], ids=['native-order', 'input-order'])
@pytest.mark.parametrize('mode,varchar', [('sync', False), ('sync', True), ('async', False), ('async', True)])
def test_multiple_returning_columns_match_native_rows_and_stored_values(mode, varchar, ordered, public_only):
    with native_application(varchar) as app:
        inputs = returning_rows()
        original = deepcopy(inputs)
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)

        def sync_observation(factory=None):
            pages, sent = [], []
            observer = observe_inserts(app.runtime, pages, sent)
            try:
                with (Session(app.runtime) if factory is None else factory(tenant_id=TENANT)) as session:
                    observed = consume(session.execute(returning(app, ordered, public_only), inputs), session)
                    stored = [tuple(row) for row in session.execute(stored_selection(app))]
                    session.commit() if factory is not None else session.rollback()
            finally:
                event.remove(app.runtime, 'before_cursor_execute', observer)
            assert len(pages) >= 3 and all(pages)
            assert_plaintext_collection(sent, factory is not None)
            return observed, stored, pages

        async def async_observation(protected):
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                insertmanyvalues_page_size=2,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = (await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                                       deployment=(app.plan, app.pin))) if protected else None
                pages, sent = [], []
                observer = observe_inserts(engine.sync_engine, pages, sent)
                try:
                    async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                        observed = consume(await session.execute(returning(app, ordered, public_only), inputs), session)
                        stored = [tuple(row) for row in (await session.execute(stored_selection(app))).all()]
                        await session.commit() if protected else await session.rollback()
                finally:
                    event.remove(engine.sync_engine, 'before_cursor_execute', observer)
                assert len(pages) >= 3 and all(pages)
                assert_plaintext_collection(sent, protected)
                return observed, stored, pages
            finally:
                await engine.dispose()

        if mode == 'sync':
            expected = sync_observation()
            with fresh_mapping(app):
                actual = sync_observation(protect(app))
        else:
            expected = asyncio.run(async_observation(False))
            with fresh_mapping(app):
                run(app)
                publish(app)
                actual = asyncio.run(async_observation(True))
        assert actual == expected
        assert inputs == original
        assert expected[0][0] == (('id', 'label', 'tenant_id') if public_only else
                                  ('id', 'name', 'label', 'tenant_id', 'name'))
        if ordered:
            assert [row[0] for row in expected[0][1]] == [row['id'] for row in inputs]


@pytest.mark.parametrize('fault', ['reorder', 'add', 'remove'])
def test_late_column_projection_change_refuses_before_driver(fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        before, changed = _snapshot(app), []
        model = app.Customer
        columns = (model.name, model.id, model.label)
        replacement = {'reorder': (model.id, model.name, model.label),
                       'add': (*columns, model.tenant_id), 'remove': columns[:2]}[fault]

        def change(connection, current, multiparams, params, options):
            if current.is_insert:
                changed.append(True)
                current = insert(model).returning(*replacement)
            return current, multiparams, params

        event.listen(app.runtime, 'before_execute', change, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(insert(model).returning(*columns), returning_rows())
                    session.rollback()
                assert changed and sent == []
        finally:
            event.remove(app.runtime, 'before_execute', change)
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['literal', 'renamed'])
def test_public_column_mutation_cannot_return_protected_storage(fault, monkeypatch):
    with native_application(False) as app:
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        resolutions.clear()
        before = _snapshot(app)
        with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
            with monkeypatch.context() as patch:
                column = app.table.c.label
                patch.setattr(column, 'name', 'name::text' if fault == 'literal' else 'name')
                patch.setattr(column, 'is_literal', fault == 'literal')
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()  # Session construction admits its tenant policy.
                    with pytest.raises(CryptoFailure):
                        session.execute(insert(app.Customer).returning(column),
                            [{'id': returning_rows()[0]['id'], 'tenant_id': TENANT, 'name': 'secret'}])
                    session.rollback()
            assert sent == [] and resolutions == []
        assert _snapshot(app) == before


@pytest.mark.parametrize('adapter_app', [{'bigint': True, 'single_tenant': True}], indirect=True)
def test_multiple_protected_columns_keep_distinct_field_and_row_context(adapter_app):
    app = adapter_app
    identities = [-2**63, -1, 0, 2**63 - 1]
    rows = [dict(id=identity, tenant_id=ADAPTER_TENANT, name=f'public {index}', rank=index,
                 note=['雪😀', None, '', 'e\u0301'][index], secret=f'second field {index}')
            for index, identity in enumerate(identities)]

    def query():
        model = app.Customer
        return insert(model).returning(model.note, model.secret, model.id, model.note,
                                        sort_by_parameter_order=True)

    with adapter_factory(app, False)(tenant_id=ADAPTER_TABLE_ID) as session:
        expected = consume(session.execute(query(), rows, execution_options={'render_nulls': True}), session)
        session.rollback()
    old_mapping, old_model = app.mapping, app.Customer
    mapping = registry(metadata=old_mapping.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, old_model.__table__)
    app.mapping, app.Customer = mapping, Customer
    try:
        with adapter_factory(app, True)(tenant_id=ADAPTER_TABLE_ID) as session:
            actual = consume(session.execute(query(), rows, execution_options={'render_nulls': True}), session)
            assert actual == expected
            assert actual[1] == [(row['note'], row['secret'], row['id'], row['note']) for row in rows]
            session.commit()
    finally:
        app.mapping, app.Customer = old_mapping, old_model
        mapping.dispose()
