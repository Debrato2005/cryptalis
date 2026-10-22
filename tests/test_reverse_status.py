"""Native read-only observation of decrypt-back progress and terminal removal."""
from contextlib import contextmanager
from dataclasses import replace
import json
from uuid import uuid4

import pytest
from sqlalchemy import event
from sqlalchemy.exc import DBAPIError

import cryptalis.deprotection as d
from test_deprotection import app_pin, consent, proposal, reverse
from test_migration import application, keys, publish, run


@contextmanager
def reversing():
    with application() as app:
        run(app)
        publish(app)
        yield app, proposal(app)


def reach(app, plan, phase):
    if phase == 'PREPARED':
        return app_pin(plan, 'PREPARED')
    if phase == 'ABORTED':
        reverse(app, plan, 'EXPANDED')
        d.abort(plan, app.owner, pin=app_pin(plan, 'PREPARED'), approval=app.approval,
                consent=consent(plan)[0])
        return app_pin(plan, 'PREPARED')
    if phase in ('PLAINTEXT_ACTIVE', 'REMOVED'):
        reverse(app, plan)
        active = consent(plan, 'PLAINTEXT_ACTIVATING')[0]
        d.apply(plan, app.owner, keys=keys, pin=app_pin(plan, 'PLAINTEXT_ACTIVATING'),
                approval=app.approval, consent=active, until='PLAINTEXT_ACTIVE')
        if phase == 'REMOVED':
            removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                'public fixture native workload', 'public fixture without retained backup', True)
            d.remove(plan, app.owner, pin=app_pin(plan, 'REMOVING'), approval=app.approval,
                     removal=removal, consent=active)
        return app_pin(plan, phase)
    reverse(app, plan, phase)
    return app_pin(plan, 'PREPARED')


@pytest.mark.parametrize('phase', [*d.PHASES, 'ABORTED', 'REMOVED'])
def test_reverse_status_reports_committed_native_phases_without_effects(phase):
    with reversing() as (app, plan):
        pin = reach(app, plan, phase)
        statements = []
        def observe(c, cursor, statement, parameters, context, many):
            statements.append(statement)
        event.listen(app.owner, 'before_cursor_execute', observe)
        try:
            result = d.status(plan, app.owner, pin=pin)
        finally:
            event.remove(app.owner, 'before_cursor_execute', observe)
        assert result.operation_id == plan.operation_id
        assert result.phase == phase and result.external_phase == pin.phase
        assert result.runtime_metadata_matches is (phase in ('PLAINTEXT_ACTIVE', 'REMOVED'))
        assert result.verification == 'NOT_PERFORMED' and result.remedy
        expected = None if phase == 'REMOVED' else 7 if phase in (
            'BACKFILLED', 'VERIFIED', 'PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE') else 0
        assert result.committed_rows == expected
        assert result.committed_chunks == (None if expected is None else 4 if expected else 0)
        assert all(s.lstrip().split()[0].upper() in ('SELECT', 'SET') for s in statements)
        assert not any('advisory_lock' in s or 'LOCK TABLE' in s for s in statements)


def test_reverse_status_has_no_executor_key_or_consent_dependency_and_rejects_writes():
    with reversing() as (app, plan):
        reverse(app, plan, 'EXPANDED')
        attempted = False
        def write(c, cursor, statement, parameters, context, many):
            nonlocal attempted
            if attempted or not statement.lstrip().upper().startswith('SELECT'):
                return
            attempted = True
            with pytest.raises(DBAPIError) as error:
                with c.begin_nested():
                    c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=\'status must refuse\'')
            assert error.value.orig.sqlstate == '25006'
        with d._executor(plan, app.owner, app_pin(plan, 'PREPARED'), app.approval, consent(plan)[0]):
            event.listen(app.owner, 'before_cursor_execute', write)
            try:
                assert d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED')).phase == 'EXPANDED'
            finally:
                event.remove(app.owner, 'before_cursor_execute', write)
        assert attempted


def test_reverse_status_snapshot_does_not_mix_concurrent_commits():
    with reversing() as (app, plan):
        reverse(app, plan, 'EXPANDED')
        advanced = False
        def advance(c, cursor, statement, parameters, context, many):
            nonlocal advanced
            if advanced or not statement.startswith('SELECT current_database()'):
                return
            advanced = True
            reverse(app, plan, 'BACKFILLED')
        event.listen(app.owner, 'after_cursor_execute', advance)
        try:
            result = d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
        finally:
            event.remove(app.owner, 'after_cursor_execute', advance)
        assert advanced and result.phase == 'EXPANDED' and result.committed_rows == 0
        latest = d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
        assert latest.phase == 'BACKFILLED' and latest.committed_rows == 7


@pytest.mark.parametrize('phase', ['PREPARED', 'EXPANDED', 'PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE', 'REMOVED'])
def test_reverse_status_refuses_catalog_drift(phase):
    with reversing() as (app, plan):
        pin = reach(app, plan, phase)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN late_drift integer')
        with pytest.raises(app.m.TransitionFailure):
            d.status(plan, app.owner, pin=pin)


@pytest.mark.parametrize('damage', ['pin', 'source_pin', 'missing_journal', 'fake_removed'])
def test_reverse_status_rejects_unproved_identity_and_terminal_state(damage):
    with reversing() as (app, plan):
        pin = app_pin(plan, 'PREPARED')
        if damage == 'pin':
            pin = replace(pin, operation_id=uuid4())
        elif damage == 'source_pin':
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET plan_digest=%s WHERE operation_id=%s',
                                  ('0' * 64, app.plan.operation_id))
        else:
            with app.owner.begin() as c:
                c.exec_driver_sql(f'DROP TABLE "{app.schema}"._cryptalis_journal')
            if damage == 'fake_removed':
                pin = app_pin(plan, 'REMOVED')
        with pytest.raises(app.m.TransitionFailure):
            d.status(plan, app.owner, pin=pin)


@pytest.mark.parametrize('value', [-1, True, 'PRIVATE_STATUS_COUNTER', None, 1.5])
def test_reverse_status_refuses_malformed_journal_progress(value):
    with reversing() as (app, plan):
        reverse(app, plan, 'EXPANDED')
        with app.owner.begin() as c:
            state = c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal WHERE operation_id=%s',
                                     (plan.operation_id,)).scalar_one()
            next(iter(state['models'].values()))['rows'] = value
            c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb WHERE operation_id=%s',
                              (json.dumps(state), plan.operation_id))
        with pytest.raises(app.m.TransitionFailure) as error:
            d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
        assert 'PRIVATE_STATUS_COUNTER' not in str(error.value)


@pytest.mark.parametrize('phase', ['PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE', 'REMOVED'])
def test_reverse_status_refuses_captured_metadata_drift(phase):
    with reversing() as (app, plan):
        pin = reach(app, plan, phase)
        with app.owner.begin() as c:
            c.exec_driver_sql(f"COMMENT ON COLUMN \"{app.schema}\".customer.name IS 'late metadata drift'")
        with pytest.raises(app.m.TransitionFailure):
            d.status(plan, app.owner, pin=pin)


def test_reverse_pending_status_refuses_disabled_guard():
    with reversing() as (app, plan):
        pin = reach(app, plan, 'PLAINTEXT_PENDING')
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER ALL')
        with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
            d.status(plan, app.owner, pin=pin)


def test_reverse_status_refuses_wrong_database_target():
    with reversing() as (app, plan):
        doc = plan.document
        doc['target'][0] = doc['source_plan']['target'][0] = 'different_status_database'
        doc['source_pin']['plan_digest'] = app.m.MigrationPlan(app.m._canonical(doc['source_plan'])).digest
        other = d.DeprotectionPlan(app.m._canonical(doc))
        with pytest.raises(app.m.TransitionFailure, match='wrong_database_target'):
            d.status(other, app.owner, pin=app_pin(other, 'PREPARED'))


@pytest.mark.parametrize('point', ['connect', 'close'])
def test_reverse_status_preserves_safe_connection_and_cleanup_failures(monkeypatch, point):
    import psycopg
    from sqlalchemy.exc import OperationalError
    with reversing() as (app, plan):
        original = app.owner.connect
        def connect(*args, **kwargs):
            if point == 'connect':
                raise OperationalError('PRIVATE_REVERSE_FAILURE', {}, psycopg.OperationalError('PRIVATE_REVERSE_FAILURE'))
            connection = original(*args, **kwargs)
            close = connection.close
            def fail_close():
                close()
                raise RuntimeError('PRIVATE_REVERSE_FAILURE')
            monkeypatch.setattr(connection, 'close', fail_close)
            return connection
        with monkeypatch.context() as patch:
            patch.setattr(app.owner, 'connect', connect)
            with pytest.raises(app.m.TransitionFailure) as failure:
                d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
        assert failure.value.operation_id == plan.operation_id
        assert failure.value.code == ('database_effect_requires_inspection' if point == 'connect'
                                      else 'connection_cleanup_requires_inspection')
        assert 'PRIVATE_REVERSE_FAILURE' not in str(failure.value)


def test_plaintext_status_cannot_accept_schema_drift_from_a_forged_journal():
    with reversing() as (app, plan):
        pin = reach(app, plan, 'PLAINTEXT_ACTIVE')
        model = plan.document['lock']['models'][0]
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN forged_native_column integer')
            state = c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal WHERE operation_id=%s',
                                     (plan.operation_id,)).scalar_one()
            state['models'][model['table_id']]['plaintext_schema'] = app.m._facts(c, model)
            c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb WHERE operation_id=%s',
                              (json.dumps(state), plan.operation_id))
        with pytest.raises(app.m.TransitionFailure):
            d.status(plan, app.owner, pin=pin)
