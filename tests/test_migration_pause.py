"""Native SQL, independent frame decoding, and real lock conflicts are oracles."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import math
import os
from threading import Event
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine, event

from migration_commit_proxy import lost_commit_reply
from test_migration import application, frames, independent_open, keys, run


@contextmanager
def paused_verification(app):
    ready, resume = Event(), Event()
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
            pause_after_sql='SELECT "id","tenant_id","name","_cryptalis_',
            pause_events=(ready, resume)) as (url, _):
        engine = create_engine('postgresql+psycopg://', hide_parameters=True,
                               creator=lambda: psycopg.connect(url))
        try:
            yield engine, ready, resume
        finally:
            resume.set()
            engine.dispose()


def test_uninterrupted_switch_reads_each_payload_once():
    with application() as app:
        run(app, 'BACKFILLED')
        scans = []
        def observe(connection, cursor, statement, parameters, context, many):
            if statement.startswith('SELECT "id","tenant_id","name","_cryptalis_'):
                scans.append(cursor.rowcount)
        event.listen(app.owner, 'after_cursor_execute', observe)
        try:
            assert run(app).phase == 'PENDING'
        finally:
            event.remove(app.owner, 'after_cursor_execute', observe)
        # PostgreSQL's actual returned row counts distinguish one pass from two.
        assert sum(scans) == len(app.source)
        descriptor = app.plan.document['lock']['models'][0]['fields'][0]['descriptor']
        for identity, frame in frames(app, switched=True).items():
            tenant, value = app.source[identity]
            assert independent_open(frame, descriptor, tenant, identity) == value


@pytest.mark.parametrize('operation', ['switch', 'checkpoint', 'verify'])
def test_final_verification_permits_native_reads_but_blocks_all_writes(operation):
    with application() as app:
        run(app, 'BACKFILLED')
        with paused_verification(app) as (engine, ready, resume):
            with ThreadPoolExecutor(max_workers=1) as pool:
                if operation == 'verify':
                    future = pool.submit(app.m.verify, app.plan, engine, keys=keys,
                                         pin=app.pin, approval=app.approval)
                else:
                    future = pool.submit(app.m.apply, app.plan, engine, keys=keys,
                        pin=app.pin, approval=app.approval,
                        until='VERIFIED' if operation == 'checkpoint' else 'PENDING')
                try:
                    assert ready.wait(10), 'verification did not reach its row scan'
                    table = f'"{app.schema}".customer'
                    for variable in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
                        with psycopg.connect(os.environ[variable]) as reader:
                            reader.execute("SET LOCAL lock_timeout='250ms'")
                            observed = reader.execute(f'SELECT id, tenant_id, name FROM {table} ORDER BY id').fetchall()
                            assert observed == [(k, *v) for k, v in sorted(app.source.items())]
                    commands = [(f'UPDATE {table} SET label=%s WHERE id=%s', ('late', UUID(int=103))),
                        (f'DELETE FROM {table} WHERE id=%s', (UUID(int=103),)),
                        (f'INSERT INTO {table}(id,tenant_id) VALUES (%s,%s)', (UUID(int=999), app.source[UUID(int=103)][0])),
                        (f'TRUNCATE {table}', ()),
                        (f'SELECT id FROM {table} FOR UPDATE', ())]
                    for command, values in commands:
                        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as writer:
                            writer.execute("SET LOCAL lock_timeout='100ms'")
                            with pytest.raises(psycopg.errors.LockNotAvailable):
                                writer.execute(command, values)
                finally:
                    resume.set()
                result = future.result(timeout=20)
                if operation != 'verify':
                    assert result.phase == ('VERIFIED' if operation == 'checkpoint' else 'PENDING')


def test_reader_delaying_ddl_preserves_source_and_backfilled_marker():
    with application() as app:
        run(app, 'BACKFILLED')
        before = frames(app)
        with paused_verification(app) as (engine, ready, resume):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(app.m.apply, app.plan, engine, keys=keys,
                                     pin=app.pin, approval=app.approval)
                try:
                    assert ready.wait(10), 'verification did not reach its row scan'
                    with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as reader:
                        reader.execute("SET LOCAL lock_timeout='250ms'")
                        reader.execute(f'SELECT name FROM "{app.schema}".customer').fetchall()
                        resume.set()
                        # Keep ACCESS SHARE until ALTER TABLE's real lock timeout.
                        with pytest.raises(app.m.TransitionFailure) as failure:
                            future.result(timeout=20)
                        assert failure.value.sqlstate == '55P03'
                finally:
                    resume.set()
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').scalar_one() == 'BACKFILLED'
            observed = connection.exec_driver_sql(f'SELECT id, tenant_id, name FROM "{app.schema}".customer ORDER BY id').all()
            assert observed == [(k, *v) for k, v in sorted(app.source.items())]
        assert frames(app) == before
        assert run(app).phase == 'PENDING'


def test_saved_verification_cannot_accept_changed_valid_frames():
    from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
    with application() as app:
        run(app, 'VERIFIED')
        field = app.plan.document['lock']['models'][0]['fields'][0]
        identity = UUID(int=103)
        tenant, value = app.source[identity]
        frame = seal_text(value, FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest']),
                          tenant, identity, keys(tenant).prepare())
        assert independent_open(frame, field['descriptor'], tenant, identity) == value
        assert frame != frames(app)[identity]
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{field["payload_column"]}"=%s WHERE id=%s',
                                       (frame, identity))
        with pytest.raises(app.m.TransitionFailure, match='verification_changed_before_switch'):
            run(app)
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s', (identity,)).scalar_one() == value


def test_printed_plan_estimates_one_final_pass_from_native_count(capsys):
    with application(rows=1001) as app:
        with app.owner.connect() as connection:
            count = connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one()
        assert app.plan.document['estimates']['writer_pause_seconds_estimate'] == math.ceil(count / 1000 + count / 1000)
        print(app.plan)
        report = capsys.readouterr().out
        assert 'Estimated writer pause: 3 s' in report
        assert '1001 rows' in report
        assert 'backfill 1000 rows/s; verify 1000 rows/s' in report
        assert 'checkpoint' in report and 'publication' in report
        assert 'cryptalis.transition/v1' not in report
