"""Mapped dictionary inserts compared with the same native PostgreSQL app."""
import asyncio
from copy import deepcopy
import importlib
import os
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import bindparam, event, insert, literal, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError, ResourceClosedError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session

from cryptalis.crypto import CryptoFailure, Keyring, KeyUnavailable
from cryptalis.sqlalchemy import attach
from test_bulk_insert_native import assert_aborted, native_application, row
from test_migration import keys, publish, run, TENANT, PROVIDER, PublicFixtureProvider
from test_rewrap_plan import _snapshot


def selection(app):
    return select(app.Customer.id, app.Customer.tenant_id, app.Customer.name,
                  app.Customer.label).where(app.Customer.id.in_(
                      [UUID(int=value) for value in range(1000, 1010)])).order_by(app.Customer.id)


def protect(app, resolver=keys):
    run(app); publish(app)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                  keys=resolver, deployment=(app.plan, app.pin))


def collector(shapes, parameters):
    def collect(connection, cursor, statement, values, context, executemany):
        parameters.append(repr(values))
        if statement.lstrip().upper().startswith('INSERT '):
            shapes.append([sorted(group) for group in context.compiled_parameters])
    return collect


def native_success(app, rows, render_nulls):
    shapes, parameters = [], []
    collect = collector(shapes, parameters)
    event.listen(app.runtime, 'before_cursor_execute', collect)
    try:
        with Session(app.runtime) as session:
            result = session.execute(insert(app.Customer), rows,
                                     execution_options={'render_nulls': render_nulls})
            with pytest.raises(ResourceClosedError):
                result.all()
            expected = session.execute(selection(app)).all()
            assert len(session.identity_map) == 0
            session.rollback()
    finally:
        event.remove(app.runtime, 'before_cursor_execute', collect)
    return expected, shapes


def native_failure(app, rows):
    with Session(app.runtime) as session:
        with pytest.raises(DBAPIError) as failed:
            session.execute(insert(app.Customer), rows)
        code = failed.value.orig.sqlstate
        assert_aborted(session)
        session.rollback()
    return code


@pytest.mark.parametrize('mode,varchar,render_nulls', [
    ('sync', False, False), ('sync', True, True),
    ('async', False, True), ('async', True, False),
])
def test_bulk_values_grouping_and_result_match_native_without_plaintext_binds(mode, varchar, render_nulls):
    with native_application(varchar) as app:
        rows = [row(1000, 'e\u0301😀界', label='PUBLIC_BULK_VISIBLE_LABEL'),
                row(1001, None, label=None),
                {'id': UUID(int=1002), 'tenant_id': TENANT, 'label': 'omitted name'},
                row(1003, 'abcd   ', label='space overflow'), row(1004, 'x '),
                row(1005, 'new', label=None)]
        original = deepcopy(rows)
        expected, native_shapes = native_success(app, rows, render_nulls)
        shapes, parameters = [], []
        collect = collector(shapes, parameters)
        if mode == 'sync':
            factory = protect(app)
            event.listen(app.runtime, 'before_cursor_execute', collect)
            try:
                with factory(tenant_id=TENANT) as session:
                    result = session.execute(insert(app.Customer), rows,
                        execution_options={'render_nulls': render_nulls})
                    with pytest.raises(ResourceClosedError):
                        result.all()
                    assert len(session.identity_map) == 0
                    assert session.execute(selection(app)).all() == expected
                    session.commit()
                    assert session.scalar(select(app.Customer.id).where(
                        app.Customer.name == 'e\u0301😀界')) == UUID(int=1000)
                    assert session.scalars(select(app.Customer.id).where(
                        app.Customer.name.in_(['e\u0301😀界', 'new'])).order_by(app.Customer.id)).all() == [
                            UUID(int=1000), UUID(int=1005)]
            finally:
                event.remove(app.runtime, 'before_cursor_execute', collect)
        else:
            run(app); publish(app)

            async def scenario():
                engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                           keys=keys, deployment=(app.plan, app.pin))
                    event.listen(engine.sync_engine, 'before_cursor_execute', collect)
                    async with factory(tenant_id=TENANT) as session:
                        result = await session.execute(insert(app.Customer), rows,
                            execution_options={'render_nulls': render_nulls})
                        with pytest.raises(ResourceClosedError):
                            result.all()
                        assert len(session.identity_map) == 0
                        assert (await session.execute(selection(app))).all() == expected
                        await session.commit()
                        assert await session.scalar(select(app.Customer.id).where(
                            app.Customer.name == 'e\u0301😀界')) == UUID(int=1000)
                        assert (await session.scalars(select(app.Customer.id).where(
                            app.Customer.name.in_(['e\u0301😀界', 'new'])).order_by(app.Customer.id))).all() == [
                                UUID(int=1000), UUID(int=1005)]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        assert rows == original and shapes == native_shapes
        serialized = repr(parameters)
        assert 'PUBLIC_BULK_VISIBLE_LABEL' in serialized
        assert 'e\u0301😀界' not in serialized and 'abcd   ' not in serialized


@pytest.mark.parametrize('varchar', [False, True])
@pytest.mark.parametrize('fault', ['duplicate_id', 'unique_name'])
def test_same_group_bulk_conflict_matches_native_and_rolls_back(varchar, fault):
    with native_application(varchar) as app:
        rows = [row(1000, 'good', label='same shape'),
                row(1000 if fault == 'duplicate_id' else 1001,
                    'good' if fault == 'unique_name' else 'next', label='same shape')]
        original = deepcopy(rows)
        assert native_failure(app, rows) == '23505'
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(IntegrityError) as failed:
                session.execute(insert(app.Customer), rows)
            assert failed.value.orig.sqlstate == '23505'
            assert_aborted(session)
            session.rollback()
            assert session.execute(selection(app)).all() == []
        assert _snapshot(app) == before and rows == original


def test_bulk_varchar_overlength_matches_native_error_and_aborted_transaction():
    with native_application(True) as app:
        rows = [row(1000, 'good', label='prefix'), row(1001, 'abcde')]
        original = deepcopy(rows)
        assert native_failure(app, rows) == '22001'
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(CryptoFailure) as failed:
                session.execute(insert(app.Customer), rows)
            assert failed.value.code == 'VarcharLengthExceeded' and failed.value.sqlstate == '22001'
            assert 'abcde' not in str(failed.value)
            assert_aborted(session)
            session.rollback()
            assert session.execute(selection(app)).all() == []
            session.execute(insert(app.Customer), [row(1002, 'redo', label='recovered')])
            session.commit()
        assert rows == original
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=1002))) == 'redo'
        # The failed prefix did not survive rollback; only the later recovery did.
        assert [entry[0] for entry in _snapshot(app)[1] if entry[0].int >= 1000] == [UUID(int=1002)]
        assert before[0] == _snapshot(app)[0]


@pytest.mark.parametrize('varchar', [False, True])
def test_bulk_savepoint_recovery_matches_native_without_losing_outer_work(varchar):
    with native_application(varchar) as app:
        rows = [row(1001, 'dupe', label='inner prefix'), row(1002, 'dupe')]
        original = deepcopy(rows)

        def scenario(session, commit):
            session.execute(insert(app.Customer), [row(1000, 'keep', label='outer')])
            savepoint = session.begin_nested()
            with pytest.raises(IntegrityError) as failed:
                session.execute(insert(app.Customer), rows)
            assert failed.value.orig.sqlstate == '23505'
            assert_aborted(session)
            savepoint.rollback()
            assert session.execute(selection(app)).all() == [(UUID(int=1000), TENANT, 'keep', 'outer')]
            session.execute(insert(app.Customer), [row(1003, 'done', label='recovery')])
            observed = session.execute(selection(app)).all()
            session.commit() if commit else session.rollback()
            return observed

        with Session(app.runtime) as session:
            expected = scenario(session, False)
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            assert scenario(session, True) == expected
        with factory(tenant_id=TENANT) as session:
            assert session.execute(selection(app)).all() == expected
        assert rows == original


@pytest.mark.parametrize('first', ['duplicate', 'overlength'])
def test_bulk_first_native_failure_keeps_precedence_over_later_failure(first):
    with native_application(True) as app:
        duplicate = row(100, 'good', label='same shape')
        overlength = row(1000, 'abcde', label='same shape')
        rows = [duplicate, overlength] if first == 'duplicate' else [overlength, duplicate]
        original = deepcopy(rows)
        expected = native_failure(app, rows)
        assert expected == ('23505' if first == 'duplicate' else '22001')
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(IntegrityError if first == 'duplicate' else CryptoFailure) as failed:
                session.execute(insert(app.Customer), rows)
            actual = failed.value.orig.sqlstate if isinstance(failed.value, DBAPIError) else failed.value.sqlstate
            assert actual == expected
            assert_aborted(session)
            session.rollback()
        assert _snapshot(app) == before and rows == original


@pytest.mark.parametrize('fault', ['provider', 'expired'])
def test_bulk_unavailable_keys_reach_no_sql_and_leave_no_partial_prefix(fault, monkeypatch):
    with native_application(False) as app:
        run(app); publish(app)
        now = [100.0]
        key_module = importlib.import_module('cryptalis.crypto.keys')
        monkeypatch.setattr(key_module, 'time', SimpleNamespace(
            monotonic=lambda: now[0], monotonic_ns=lambda: int(now[0] * 1e9)))

        class UnavailableProvider:
            provider_id = PROVIDER
            def unwrap(self, *args):
                raise RuntimeError('PRIVATE_BULK_PROVIDER_FAILURE')

        class ExpiredKeys(Keyring):
            def prepare(self):
                material = super().prepare()
                now[0] += 2
                return material

        policy = keys(TENANT).policy
        bad = Keyring(policy, {PROVIDER: UnavailableProvider()}) if fault == 'provider' else ExpiredKeys(
            policy, {PROVIDER: PublicFixtureProvider()}, max_age=1)
        selected = [bad]
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
            keys=lambda tenant: selected[0], deployment=(app.plan, app.pin))
        rows = [row(1000, 'first private value'), row(1001, 'second private value')]
        original, before, observed = deepcopy(rows), _snapshot(app), []
        def collect(*args):
            observed.append(True)
        event.listen(app.runtime, 'before_cursor_execute', collect)
        try:
            with factory(tenant_id=TENANT) as session:
                with pytest.raises(KeyUnavailable) as failed:
                    session.execute(insert(app.Customer), rows)
                assert 'PRIVATE_BULK' not in str(failed.value)
                session.rollback()
            assert observed == []
        finally:
            event.remove(app.runtime, 'before_cursor_execute', collect)
        assert rows == original and _snapshot(app) == before
        selected[0] = keys(TENANT)
        with factory(tenant_id=TENANT) as session:
            session.execute(insert(app.Customer), rows)
            session.commit()
            assert len(session.execute(selection(app)).all()) == 2


def test_bulk_unadmitted_shapes_and_contexts_refuse_before_driver():
    with native_application(False) as app:
        factory = protect(app)
        good = row(1000, 'protected input', label='public label')
        calls = []
        def collect(*args):
            calls.append(True)
        event.listen(app.runtime, 'before_cursor_execute', collect)
        try:
            with factory(tenant_id=TENANT) as session:
                statements = [insert(app.Customer).returning(app.Customer.id.label('renamed')), insert(app.table),
                    insert(app.Customer).values(name='statement value'),
                    pg_insert(app.Customer).on_conflict_do_nothing(),
                    insert(app.Customer).from_select(['id', 'tenant_id', 'name', 'label'],
                        select(literal(UUID(int=1000)), literal(TENANT), literal('expression'), literal('label'))),
                    insert(app.Customer).values(name=bindparam('value', callable_=lambda: 'callable value'))]
                for statement in statements:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement, [dict(good)])
                    assert calls == []
                malformed = [dict(good, name=literal('row SQL expression')),
                    dict(good, id=str(good['id'])), dict(good, tenant_id=UUID(int=9999)),
                    {key: value for key, value in good.items() if key != 'id'}]
                for values in malformed:
                    with pytest.raises(CryptoFailure):
                        session.execute(insert(app.Customer), [values])
                    assert calls == []
                with pytest.raises(CryptoFailure):
                    session.execute(insert(app.Customer), [good], execution_options={'render_nulls': 1})
                assert calls == []
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', collect)
