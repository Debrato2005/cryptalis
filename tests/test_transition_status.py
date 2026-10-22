"""Read-only operational status against durable PostgreSQL transition state."""
from dataclasses import replace
import json

import pytest
from sqlalchemy import event
from sqlalchemy.exc import DBAPIError

from test_migration import application, publish, run


@pytest.mark.parametrize('phase', ['PREPARED', 'EXPANDED', 'BACKFILLED', 'VERIFIED',
                                    'PENDING', 'ACTIVE', 'ABORTED'])
def test_status_observes_durable_progress_without_effects(phase):
    with application() as app:
        if phase == 'ACTIVE':
            run(app)
            publish(app)
        elif phase == 'ABORTED':
            run(app, 'EXPANDED')
            app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
        elif phase != 'PREPARED':
            run(app, phase)
        statements = []

        def collect(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        event.listen(app.owner, 'before_cursor_execute', collect)
        try:
            observed = app.m.status(app.plan, app.owner, pin=app.pin)
        finally:
            event.remove(app.owner, 'before_cursor_execute', collect)
        assert observed.operation_id == app.plan.operation_id
        assert observed.phase == phase
        assert observed.external_phase == app.pin.phase
        assert observed.runtime_metadata_matches is (phase == 'ACTIVE')
        assert observed.verification == 'NOT_PERFORMED'
        assert observed.committed_rows == (7 if phase in ('BACKFILLED', 'VERIFIED', 'PENDING', 'ACTIVE') else 0)
        assert observed.committed_chunks == (4 if observed.committed_rows else 0)
        assert observed.remedy
        assert all(statement.lstrip().split()[0].upper() in ('SELECT', 'SET') for statement in statements)
        assert not any('pg_try_advisory_lock' in statement or 'LOCK TABLE' in statement for statement in statements)
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SHOW transaction_read_only').scalar_one() == 'off'


def test_status_transaction_refuses_accidental_writes():
    with application() as app:
        attempted = False

        def attempt_write(connection, cursor, statement, parameters, context, executemany):
            nonlocal attempted
            if attempted or not statement.lstrip().upper().startswith('SELECT'):
                return
            attempted = True
            try:
                with connection.begin_nested():
                    connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=\'unsafe status write\'')
            except DBAPIError as error:
                assert error.orig.sqlstate == '25006'
            else:
                pytest.fail('status did not enforce a read-only transaction')

        event.listen(app.owner, 'before_cursor_execute', attempt_write)
        try:
            assert app.m.status(app.plan, app.owner, pin=app.pin).phase == 'PREPARED'
        finally:
            event.remove(app.owner, 'before_cursor_execute', attempt_write)
        assert attempted


def test_status_needs_no_executor_lock_or_maintenance_approval():
    with application() as app:
        run(app, 'EXPANDED')
        with app.m._executor(app.plan, app.owner, app.pin, app.approval):
            assert app.m.status(app.plan, app.owner, pin=app.pin).phase == 'EXPANDED'


def test_status_keeps_one_snapshot_while_an_executor_commits_progress():
    with application() as app:
        run(app, 'EXPANDED')
        advanced = False

        def advance_after_snapshot(connection, cursor, statement, parameters, context, executemany):
            nonlocal advanced
            if advanced or not statement.startswith('SELECT current_database()'):
                return
            advanced = True
            assert run(app, 'BACKFILLED').phase == 'BACKFILLED'

        event.listen(app.owner, 'after_cursor_execute', advance_after_snapshot)
        try:
            observed = app.m.status(app.plan, app.owner, pin=app.pin)
        finally:
            event.remove(app.owner, 'after_cursor_execute', advance_after_snapshot)
        assert advanced
        assert observed.phase == 'EXPANDED' and observed.committed_rows == 0
        latest = app.m.status(app.plan, app.owner, pin=app.pin)
        assert latest.phase == 'BACKFILLED' and latest.committed_rows == 7


def test_status_refuses_wrong_target_pin_and_changed_writer_fence():
    with application() as app:
        document = app.plan.document
        document['target'][0] = 'different_database'
        other = app.m.MigrationPlan(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())
        with pytest.raises(app.m.TransitionFailure, match='wrong_database_target'):
            app.m.status(other, app.owner, pin=replace(app.pin, plan_digest=other.digest))
        with pytest.raises(app.m.TransitionFailure, match='external_policy_mismatch'):
            app.m.status(app.plan, app.owner, pin=replace(app.pin, plan_digest='0' * 64))
        run(app, 'EXPANDED')
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER ALL')
        with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
            app.m.status(app.plan, app.owner, pin=app.pin)
