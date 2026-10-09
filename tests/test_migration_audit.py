"""Audit regressions: native PostgreSQL state and explicit local failure injection.

Connection decorators forward real SQLAlchemy/PostgreSQL operations. Injected
Python cleanup errors do not stand in for PostgreSQL semantics.
"""
from dataclasses import replace
import hashlib
import json

import psycopg
import pytest
from sqlalchemy.exc import OperationalError
from sqlalchemy import event

from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview, InspectionUnavailable
from test_migration import application, keys, run, TABLE_ID, FIELD_ID


SECRET = 'AUDIT_DIAGNOSTIC_PRIVATE_MARKER'


def invoke(app, operation, engine=None, approval=None):
    options = {'pin': app.pin, 'approval': approval}
    if operation != 'abort': options['keys'] = keys
    if operation == 'apply': options['until'] = 'EXPANDED'
    return getattr(app.m, operation)(app.plan, engine or app.owner, **options)


@pytest.mark.parametrize('operation', ['apply', 'verify', 'abort'])
@pytest.mark.parametrize('approval', [None, 'not an approval', 'empty', 'too short', 'nan', 'bool'])
def test_every_maintenance_entry_rejects_invalid_approval_before_connect(monkeypatch, operation, approval):
    with application() as app:
        if approval == 'empty': approval = replace(app.approval, writer_exclusion=' ')
        if approval == 'too short': approval = replace(app.approval, approved_pause_seconds=0)
        if approval == 'nan': approval = replace(app.approval, approved_pause_seconds=float('nan'))
        if approval == 'bool': approval = replace(app.approval, approved_pause_seconds=True)
        connects = []
        original = app.owner.connect
        def observed_connect(*args, **kwargs):
            connects.append(True)
            return original(*args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(app.owner, 'connect', observed_connect)
            with pytest.raises(app.m.TransitionFailure) as caught:
                invoke(app, operation, approval=approval)
        assert caught.value.code in {'maintenance_approval_required', 'writer_exclusion_or_pause_not_approved'}
        assert not connects, 'invalid maintenance authority reached connection acquisition'
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (f'{app.schema}._cryptalis_journal',)).scalar_one() is None


@pytest.mark.parametrize('operation', ['apply', 'verify', 'abort', 'check_deployment'])
def test_initial_connection_error_is_safe_and_keeps_operation(monkeypatch, operation):
    with application() as app:
        def fail_connect(*args, **kwargs):
            raise OperationalError(SECRET, {}, psycopg.OperationalError(SECRET))
        with monkeypatch.context() as patch:
            patch.setattr(app.owner, 'connect', fail_connect)
            with pytest.raises(app.m.TransitionFailure) as caught:
                if operation == 'check_deployment': app.m.check_deployment(app.plan, app.owner, pin=app.pin)
                else: invoke(app, operation, approval=app.approval)
        assert caught.value.code == 'database_effect_requires_inspection'
        assert caught.value.operation_id == app.plan.operation_id
        assert SECRET not in str(caught.value)
        assert caught.value.__cause__ is None


@pytest.mark.parametrize('connection_number', [1, 2])
def test_read_only_plan_connection_error_is_sanitized(monkeypatch, connection_number):
    with application() as app:
        calls = []
        original = app.owner.connect
        def fail_selected_connect(*args, **kwargs):
            calls.append(True)
            if len(calls) == connection_number:
                raise OperationalError(SECRET, {}, psycopg.OperationalError(SECRET))
            return original(*args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(app.owner, 'connect', fail_selected_connect)
            with pytest.raises((app.m.TransitionFailure, InspectionUnavailable)) as caught:
                app.m.plan(json.dumps(app.plan.document['lock']['declaration']).encode(), app.mapping, app.owner,
                    writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='owned synthetic application'),)),
                    search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded names'),), keys=keys,
                    runtime_role=app.role, target_id=app.plan.target_id,
                    backfill_rows_per_second=1000, verify_rows_per_second=1000,
                    temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        assert SECRET not in str(caught.value)
        assert caught.value.__cause__ is None


def test_read_only_policy_and_attachment_checks_need_no_maintenance_approval():
    with application() as app:  # The read-only plan also takes no approval.
        run(app)
        app.pin = replace(app.pin, phase='ACTIVATING')
        run(app, until='ACTIVE')
        app.pin = replace(app.pin, phase='ACTIVE')
        observed = []
        def observe(connection, cursor, statement, parameters, context, many):
            observed.append(statement)
        event.listen(app.owner, 'before_cursor_execute', observe)
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            app.m.check_deployment(app.plan, app.owner, pin=app.pin)
            with app.runtime.connect() as connection:
                app.m.check_attachment(connection, app.plan.lock_bytes, (app.plan, app.pin))
        finally:
            event.remove(app.owner, 'before_cursor_execute', observe)
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert observed
        assert all(statement.lstrip().upper().startswith('SELECT') for statement in observed)


@pytest.mark.parametrize('primary', [False, True])
@pytest.mark.parametrize('stages', [('rollback',), ('invalidate',), ('close',), ('rollback', 'invalidate', 'close')])
def test_cleanup_failures_are_safe_and_do_not_replace_primary(monkeypatch, primary, stages):
    with application() as app:
        original_connect = app.owner.connect
        called = []
        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            for stage in ('rollback', 'invalidate', 'close'):
                original = getattr(connection, stage)
                def cleanup(*args, _stage=stage, _original=original, **kwargs):
                    called.append(_stage)
                    _original(*args, **kwargs)
                    if _stage in stages: raise RuntimeError(SECRET)
                monkeypatch.setattr(connection, stage, cleanup)
            return connection
        def injected_primary(*args, **kwargs):
            raise app.m.TransitionFailure('injected_primary', app.plan.operation_id)
        with monkeypatch.context() as patch:
            patch.setattr(app.owner, 'connect', connect)
            if primary: patch.setattr(app.m, '_expand', injected_primary)
            with pytest.raises(app.m.TransitionFailure) as caught:
                invoke(app, 'apply', approval=app.approval)
        assert caught.value.code == ('injected_primary' if primary else 'connection_cleanup_requires_inspection')
        assert caught.value.operation_id == app.plan.operation_id
        assert tuple(error[0] for error in caught.value.cleanup_errors) == stages
        assert all(stage in called for stage in ('rollback', 'invalidate', 'close'))
        assert SECRET not in str(caught.value)
        # A different real session must acquire the same advisory lock after
        # cleanup, even if an injected Python cleanup method reported failure.
        names = [[model['schema'], model['table']] for model in app.plan.document['lock']['models']]
        lock = int.from_bytes(hashlib.sha256(json.dumps(names, sort_keys=True, separators=(',', ':')).encode()).digest()[:8], 'big', signed=True)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT pg_catalog.pg_try_advisory_lock(%s)', (lock,)).scalar_one()
            assert c.exec_driver_sql('SELECT pg_catalog.pg_advisory_unlock(%s)', (lock,)).scalar_one()


def test_failed_invalidation_still_physically_closes_advisory_lock_session(monkeypatch):
    with application() as app:
        original_connect = app.owner.connect
        connection = original_connect()
        driver = connection.connection.driver_connection
        def failed_invalidation(*args, **kwargs): raise RuntimeError(SECRET)
        with monkeypatch.context() as patch:
            patch.setattr(connection, 'invalidate', failed_invalidation)
            patch.setattr(app.owner, 'connect', lambda: connection)
            with pytest.raises(app.m.TransitionFailure) as caught:
                invoke(app, 'apply', approval=app.approval)
        assert caught.value.code == 'connection_cleanup_requires_inspection'
        assert driver.closed
        assert SECRET not in str(caught.value)


@pytest.mark.parametrize('phase, before, after', [
    ('_expand', None, None),
    ('_backfill_chunk', 'EXPANDED', 'EXPANDED'),
    ('_verify', 'BACKFILLED', 'BACKFILLED'),
    ('_switch', 'VERIFIED', 'VERIFIED'),
    ('_activate', 'PENDING', 'PENDING'),
    ('abort', 'EXPANDED', 'EXPANDED'),
])
def test_real_database_error_at_each_phase_keeps_durable_progress(monkeypatch, phase, before, after):
    with application() as app:
        if before: run(app, until=before)
        if phase == '_activate': app.pin = replace(app.pin, phase='ACTIVATING')
        target = '_save' if phase == 'abort' else phase
        original = getattr(app.m, target)
        def fail_after_effect(connection, *args, **kwargs):
            result = original(connection, *args, **kwargs)
            connection.exec_driver_sql('SELECT 1 / 0')  # Real PG 22012, transaction abort.
            return result
        with monkeypatch.context() as patch:
            patch.setattr(app.m, target, fail_after_effect)
            with pytest.raises(app.m.TransitionFailure) as caught:
                if phase == 'abort': invoke(app, 'abort', approval=app.approval)
                else: run(app, until='ACTIVE' if phase == '_activate' else 'PENDING')
        assert caught.value.code == 'database_effect_requires_inspection'
        assert caught.value.sqlstate == '22012'
        assert caught.value.operation_id == app.plan.operation_id
        with app.owner.connect() as connection:
            exists = connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (f'{app.schema}._cryptalis_journal',)).scalar_one()
            if after is None:
                assert exists is None
            else:
                state = connection.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
                assert state['phase'] == after
                if phase == '_backfill_chunk': assert sum(model['rows'] for model in state['models'].values()) == 0
                column_type = connection.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=\'customer\' AND column_name=\'name\'', (app.schema,)).scalar_one()
                assert column_type == ('bytea' if after == 'PENDING' else 'text')
        # Inspected retry succeeds using the original plan and independent
        # PostgreSQL transaction, without changing the operation identity.
        if phase == 'abort': assert invoke(app, 'abort', approval=app.approval).phase == 'ABORTED'
        else: assert run(app, until='ACTIVE' if phase == '_activate' else 'PENDING').operation_id == app.plan.operation_id

