"""Native PostgreSQL oracle for one protected scalar from mapped bulk RETURNING."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import event, func, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased, load_only, registry

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_insert import protect
from test_bulk_insert_native import assert_aborted, native_application, row
from test_migration import keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


def returning_rows():
    # The first five rows share a parameter shape and exceed a two-row page.
    # All names fit VARCHAR(4) after native trailing-space truncation.
    return [
        row(1004, 'e\u0301😀界', label='unicode'),
        row(1001, 'abcd   ', label='truncated spaces'),
        row(1003, 'x ', label='significant space'),
        row(1000, 'next', label='ordinary'),
        row(1002, 'last', label='ordinary'),
        row(1006, None, label=None),
        {'id': UUID(int=1005), 'tenant_id': TENANT, 'label': 'omitted name'},
        row(1008, 'tail'),
        row(1007, None),
    ]


def statement(app, ordered, *, labelled=False):
    output = app.Customer.name.label('display_name') if labelled else app.Customer.name
    return insert(app.Customer).returning(output, sort_by_parameter_order=ordered)


@contextmanager
def fresh_mapping(app, *, properties=None):
    # Native RETURNING cached plaintext annotations. Attach a fresh mapping
    # through public APIs, before that mapping has statements or sessions.
    previous_mapping, previous_model = app.mapping, app.Customer
    mapping = registry(metadata=app.table.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, app.table, properties=properties)
    app.mapping, app.Customer = mapping, Customer
    try:
        yield
    finally:
        app.mapping, app.Customer = previous_mapping, previous_model
        mapping.dispose()


def stored_selection(app):
    return select(app.Customer.id, app.Customer.tenant_id, app.Customer.name,
                  app.Customer.label).where(app.Customer.id.in_(
                      [UUID(int=identity) for identity in range(1000, 1010)])).order_by(app.Customer.id)


def observe_inserts(engine, pages, parameters_seen):
    def observe(connection, cursor, sql, parameters, context, executemany):
        if sql.lstrip().upper().startswith('INSERT '):
            pages.append('RETURNING' in sql.upper())
            parameters_seen.append(repr(parameters))
    event.listen(engine, 'before_cursor_execute', observe)
    return observe


def assert_plaintext_collection(parameters_seen, protected):
    # Native execution proves this collector sees protected text. The same
    # collector must see only prepared binary parameters after attachment.
    exposed = 'e\u0301😀界' in repr(parameters_seen)
    assert exposed is not protected


def consume(result, session, consumption):
    # Keep keys and actual native Row/scalar types in the comparison. Do not
    # convert a row to a tuple before checking its type.
    result_keys = tuple(result.keys())
    assert result_keys == ('name',)
    assert len(session.identity_map) == 0
    values = result.all() if consumption == 'rows' else result.scalars().all()
    assert len(session.identity_map) == 0
    return {
        'keys': result_keys,
        'values': [value[0] for value in values] if consumption == 'rows' else values,
        'types': [(type(value), tuple(type(item) for item in value)) for value in values]
                 if consumption == 'rows' else [type(value) for value in values],
    }


def expected_values(rows, varchar):
    def stored_name(entry):
        value = entry.get('name')
        return 'abcd' if varchar and value == 'abcd   ' else value
    return [stored_name(entry) for entry in rows]


def sync_observation(app, rows, ordered, consumption, render_nulls, factory=None, commit=False):
    pages, parameters_seen = [], []
    listener = observe_inserts(app.runtime, pages, parameters_seen)
    try:
        with (Session(app.runtime) if factory is None else factory(tenant_id=TENANT)) as session:
            result = session.execute(statement(app, ordered), rows,
                                     execution_options={'render_nulls': render_nulls})
            observed = consume(result, session, consumption)
            observed['stored'] = [tuple(value) for value in session.execute(stored_selection(app)).all()]
            assert len(session.identity_map) == 0
            session.commit() if commit else session.rollback()
    finally:
        event.remove(app.runtime, 'before_cursor_execute', listener)
    # Native SQLAlchemy may choose individual statements for ordered results.
    # Learn its actual page route instead of assuming parameter/result order.
    assert len(pages) >= 3 and all(pages)
    assert_plaintext_collection(parameters_seen, factory is not None)
    observed['pages'] = pages
    return observed


async def async_observations(app, rows, ordered, render_nulls, protected):
    engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
        insertmanyvalues_page_size=2,
        async_creator=lambda: psycopg.AsyncConnection.connect(
            os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
    observations, listener = {}, None
    try:
        factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                               keys=keys, deployment=(app.plan, app.pin)) if protected else None
        for consumption in ('rows', 'scalars'):
            pages, parameters_seen = [], []
            listener = observe_inserts(engine.sync_engine, pages, parameters_seen)
            try:
                async with (factory(tenant_id=TENANT) if protected else AsyncSession(engine)) as session:
                    result = await session.execute(statement(app, ordered), rows,
                        execution_options={'render_nulls': render_nulls})
                    observed = consume(result, session, consumption)
                    observed['stored'] = [tuple(value) for value in
                                          (await session.execute(stored_selection(app))).all()]
                    assert len(session.identity_map) == 0
                    if protected and consumption == 'scalars':
                        await session.commit()
                    else:
                        await session.rollback()
            finally:
                event.remove(engine.sync_engine, 'before_cursor_execute', listener)
                listener = None
            assert len(pages) >= 3 and all(pages)
            assert_plaintext_collection(parameters_seen, protected)
            observed['pages'] = pages
            observations[consumption] = observed
    finally:
        if listener is not None:
            event.remove(engine.sync_engine, 'before_cursor_execute', listener)
        await engine.dispose()
    return observations


@pytest.mark.parametrize('mode,varchar,render_nulls', [
    ('sync', False, False), ('sync', True, True),
    ('async', False, True), ('async', True, False),
])
@pytest.mark.parametrize('ordered', [False, True], ids=['native-order', 'parameter-order'])
def test_bulk_returning_one_protected_column_matches_native_rows_and_scalars(
        mode, varchar, render_nulls, ordered, record_property):
    with native_application(varchar) as app:
        app.runtime.update_execution_options(insertmanyvalues_page_size=2)
        rows = returning_rows()
        original = deepcopy(rows)
        if mode == 'sync':
            native = {consumption: sync_observation(app, rows, ordered, consumption, render_nulls)
                      for consumption in ('rows', 'scalars')}
            assert rows == original
            with fresh_mapping(app):
                factory = protect(app)
                actual = {consumption: sync_observation(app, rows, ordered, consumption, render_nulls,
                                                       factory, commit=consumption == 'scalars')
                          for consumption in ('rows', 'scalars')}
        else:
            # Each fresh async engine uses the same native two-row page limit.
            async def scenario():
                native = await async_observations(app, rows, ordered, render_nulls, False)
                assert rows == original
                with fresh_mapping(app):
                    run(app)
                    publish(app)
                    actual = await async_observations(app, rows, ordered, render_nulls, True)
                return native, actual
            native, actual = asyncio.run(scenario())
        assert rows == original
        assert actual == native
        expected_stored = [(entry['id'], TENANT,
                            'abcd' if varchar and entry.get('name') == 'abcd   ' else entry.get('name'),
                            entry.get('label')) for entry in sorted(rows, key=lambda item: item['id'])]
        for consumption, observed in native.items():
            assert observed['stored'] == expected_stored
            if ordered:
                assert observed['values'] == expected_values(rows, varchar)
            assert len(observed['values']) == len(rows)
            record_property('native_returning_pages_' + consumption, json.dumps(observed['pages']))
            record_property('native_returning_order_' + consumption,
                            json.dumps(observed['values'], ensure_ascii=False))


@pytest.mark.parametrize('fault', ['foreign_column', 'aliased_entity', 'labeled_expression', 'expression', 'defaults', 'loader_options'])
def test_bulk_returning_unadmitted_results_refuse_before_keys_or_data_sql(fault):
    with native_application(False) as app:
        resolutions, data_sql = [], []

        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)

        factory = protect(app, resolver=resolve)
        resolutions.clear()
        base = insert(app.Customer)
        statements = {
            'foreign_column': base.returning(app.Customer.id, app.table.alias().c.name),
            'aliased_entity': base.returning(aliased(app.Customer)),
            'labeled_expression': base.returning(func.lower(app.Customer.name).label('renamed')),
            'expression': base.returning(func.lower(app.Customer.name)),
            'defaults': base.return_defaults(),
            'loader_options': base.returning(app.Customer.name).options(load_only(app.Customer.name)),
        }
        rows = [row(1000, 'new', label='public')]
        original, before = deepcopy(rows), _snapshot(app)

        def observe(*args):
            data_sql.append(True)

        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()  # Factory validates tenant policy once.
                with pytest.raises(CryptoFailure):
                    session.execute(statements[fault], rows)
                assert resolutions == data_sql == []
                assert len(session.identity_map) == 0
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert rows == original and _snapshot(app) == before


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_bulk_returning_duplicate_id_keeps_native_conflict_with_distinct_frames(varchar):
    with native_application(varchar) as app:
        # Different shapes issue separate statements. The two prepared frames
        # share an ID but differ in plaintext and fresh nonce; neither may be
        # lost through an ID-keyed result-proof map before native uniqueness.
        rows = [row(1000, 'good', label='first group'), row(1000, 'next')]
        original = deepcopy(rows)

        def attempt(session):
            with pytest.raises(IntegrityError) as failed:
                session.execute(statement(app, False), rows)
            assert failed.value.orig.sqlstate == '23505'
            assert len(session.identity_map) == 0
            assert_aborted(session)
            session.rollback()

        with Session(app.runtime) as session:
            attempt(session)
        assert rows == original
        with fresh_mapping(app):
            factory = protect(app)
            before = _snapshot(app)
            with factory(tenant_id=TENANT) as session:
                attempt(session)
            assert rows == original and _snapshot(app) == before
