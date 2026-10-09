"""Real PostgreSQL waiting locks and native reader results are the oracles."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
from threading import Event
import time
import json
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, Table, Text, Uuid, event

from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_migration import application, frames, keys, run, TENANT, TABLE_ID, FIELD_ID


@contextmanager
def second_schema(app):
    schema = app.schema + '_other'
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
        connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{app.role}"')
    try:
        yield schema
    finally:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')


def wait_for_pending_lock(connection, pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        pending = connection.execute('SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=%s AND mode=%s AND NOT granted)',
                                     (pid, 'AccessExclusiveLock')).fetchone()[0]
        if pending: return
        time.sleep(.005)
    raise AssertionError('native ACCESS EXCLUSIVE request did not enter the wait queue')


def test_native_pending_access_exclusive_request_queues_new_readers():
    with application() as app:
        table = f'"{app.schema}".customer'
        ready = Event(); pid = []
        def native_lock():
            with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as locker:
                pid.append(locker.info.backend_pid)
                locker.execute("SET LOCAL lock_timeout='5s'")
                ready.set()
                locker.execute(f'LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE')
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as existing:
            existing.execute(f'SELECT id FROM {table} LIMIT 1').fetchone()
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(native_lock)
                try:
                    assert ready.wait(3)
                    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], autocommit=True) as inspector:
                        wait_for_pending_lock(inspector, pid[0])
                    with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as new_reader:
                        new_reader.execute("SET LOCAL lock_timeout='100ms'")
                        with pytest.raises(psycopg.errors.LockNotAvailable):
                            new_reader.execute(f'SELECT id FROM {table} LIMIT 1').fetchone()
                finally:
                    existing.rollback()
                future.result(timeout=10)


def test_cutover_releases_queued_readers_promptly_and_preserves_retry_state():
    with application() as app:
        run(app, 'BACKFILLED')
        before = frames(app); table = f'"{app.schema}".customer'
        ready = Event(); pid = []
        def observe(connection, cursor, statement, parameters, context, many):
            if statement.startswith('SELECT "id","tenant_id","name","_cryptalis_') and not pid:
                pid.append(connection.connection.driver_connection.info.backend_pid); ready.set()
        event.listen(app.owner, 'before_cursor_execute', observe)
        try:
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as existing:
                existing.execute(f'SELECT id FROM {table} LIMIT 1').fetchone()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(app.m.apply, app.plan, app.owner, keys=keys,
                                         pin=app.pin, approval=app.approval)
                    try:
                        assert ready.wait(3)
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], autocommit=True) as inspector:
                            wait_for_pending_lock(inspector, pid[0])
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as reader:
                            # The old five-second DDL queue exceeds this native
                            # deadline. Bounded acquisition releases the queue.
                            reader.execute("SET LOCAL lock_timeout='750ms'")
                            observed = reader.execute(f'SELECT id,tenant_id,name FROM {table} ORDER BY id').fetchall()
                            assert observed == [(k, *v) for k, v in sorted(app.source.items())]
                        with pytest.raises(app.m.TransitionFailure) as failure:
                            future.result(timeout=3)
                        assert failure.value.code == 'table_lock_busy_retry'
                        assert failure.value.sqlstate == '55P03'
                        # Inspect while the original reader still holds its
                        # lock. No partial switch or completion may be visible.
                        assert existing.execute(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').fetchone() == ('BACKFILLED',)
                    finally:
                        existing.rollback()
        finally:
            event.remove(app.owner, 'before_cursor_execute', observe)
        assert frames(app) == before
        assert run(app).phase == 'PENDING'


def test_cutover_retries_after_reader_leaves_without_repeating_verification():
    with application() as app:
        run(app, 'BACKFILLED')
        timed_out = Event(); scanned = []; failures = []
        def failed(context):
            if getattr(context.original_exception, 'sqlstate', None) == '55P03':
                failures.append(True); timed_out.set()
        def observed(connection, cursor, statement, parameters, context, many):
            if statement.startswith('SELECT "id","tenant_id","name","_cryptalis_'):
                scanned.append(cursor.rowcount)
        event.listen(app.owner, 'handle_error', failed)
        event.listen(app.owner, 'after_cursor_execute', observed)
        try:
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as reader:
                reader.execute(f'SELECT id FROM "{app.schema}".customer LIMIT 1').fetchone()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(app.m.apply, app.plan, app.owner, keys=keys,
                                         pin=app.pin, approval=app.approval)
                    try:
                        assert timed_out.wait(7), 'native cutover lock did not time out'
                    finally:
                        reader.rollback()
                    assert future.result(timeout=10).phase == 'PENDING'
        finally:
            event.remove(app.owner, 'handle_error', failed)
            event.remove(app.owner, 'after_cursor_execute', observed)
        assert failures
        assert sum(scanned) == len(app.source)


def test_failed_partial_upgrade_releases_read_lock_but_retains_write_exclusion():
    with application() as app, second_schema(app) as schema:
        second_id, second_field = UUID(int=801), UUID(int=802)
        table = Table('zzz_customer', app.mapping.metadata,
                      Column('id', Uuid, primary_key=True, autoincrement=False),
                      Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), schema=schema)
        class OtherCustomer: pass
        app.mapping.map_imperatively(OtherCustomer, table)
        table.create(app.owner)
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'GRANT SELECT ON "{schema}".zzz_customer TO "{app.role}"')
            connection.execute(table.insert(), {'id': UUID(int=803), 'tenant_id': TENANT, 'name': 'other current value'})
        declaration = app.plan.document['lock']['declaration']
        declaration['models'].append({'model': 'OtherCustomer', 'table_id': str(second_id), 'tenancy': {'column': 'tenant_id'},
                                      'fields': [{'name': 'name', 'field_id': str(second_field), 'protect': True,
                                                  'queries': [], 'accept_leakage': []}]})
        app.plan = app.m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='native fixture'),
                                           Writer(second_id, 'app', 'sqlalchemy', evidence='native fixture'))),
            search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),), keys=keys,
            runtime_role=app.role, target_id=app.plan.target_id, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.pin = app.m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        run(app, 'BACKFILLED'); before = frames(app)
        ready = Event(); pid = []
        def observed(connection, cursor, statement, parameters, context, many):
            if statement.startswith('SELECT "id","tenant_id","name","_cryptalis_') and not pid:
                pid.append(connection.connection.driver_connection.info.backend_pid); ready.set()
        event.listen(app.owner, 'before_cursor_execute', observed)
        try:
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as blocker:
                blocker.execute(f'SELECT name FROM "{schema}".zzz_customer').fetchall()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(app.m.apply, app.plan, app.owner, keys=keys,
                                         pin=app.pin, approval=app.approval)
                    try:
                        assert ready.wait(3)
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], autocommit=True) as inspector:
                            wait_for_pending_lock(inspector, pid[0])
                        # First table was upgraded before the second table's
                        # reader prevented its upgrade. Native savepoint
                        # rollback must release that first ACCESS EXCLUSIVE.
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as reader:
                            reader.execute("SET LOCAL lock_timeout='750ms'")
                            result = reader.execute(f'SELECT id,tenant_id,name FROM "{app.schema}".customer ORDER BY id').fetchall()
                            assert result == [(k, *v) for k, v in sorted(app.source.items())]
                        # Its earlier EXCLUSIVE verification lock must survive
                        # the same rollback. Even owner writes cannot slip in.
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as writer:
                            writer.execute("SET LOCAL lock_timeout='20ms'")
                            with pytest.raises(psycopg.errors.LockNotAvailable):
                                writer.execute(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                               ('late unverified value', UUID(int=103)))
                        with pytest.raises(app.m.TransitionFailure, match='table_lock_busy_retry'):
                            future.result(timeout=3)
                        assert blocker.execute(f'SELECT name FROM "{schema}".zzz_customer').fetchall() == [('other current value',)]
                    finally:
                        blocker.rollback()
        finally:
            event.remove(app.owner, 'before_cursor_execute', observed)
        assert frames(app) == before
        assert run(app).phase == 'PENDING'
