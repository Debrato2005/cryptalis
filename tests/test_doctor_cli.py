"""Native Doctor observations keep unobserved boundaries explicitly unknown."""
from dataclasses import replace
import json
import os
import subprocess
import sys

import psycopg
import pytest
from sqlalchemy import event
from sqlalchemy.engine import Connection, Engine

from cryptalis import cli, migration as m
from cryptalis.crypto import Keyring
from test_cli import _run_cli
from test_deprotection import proposal as reverse_plan
from test_migration import application, publish, run
from test_rewrap_plan import _snapshot
from test_runtime_boundary import privilege_change
from test_status_cli import arguments, inputs


UNKNOWN_CHECKS = {'provider_keys', 'frame_authentication', 'query_routes',
                  'writer_exclusion', 'host_authority', 'recovery_capacity'}


def doctor_inputs(app, directory):
    paths = inputs(app, directory)
    paths['database'].write_text(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
    return paths


def doctor_arguments(paths):
    return ('doctor', *arguments(paths)[1:])


def checks(document, runtime_status):
    observed = document['checks']
    assert set(observed) == UNKNOWN_CHECKS | {'runtime_deployment'}
    assert observed['runtime_deployment']['status'] == runtime_status
    assert all(observed[name]['status'] == 'UNKNOWN' for name in UNKNOWN_CHECKS)
    if runtime_status == 'PASS':
        assert observed['runtime_deployment']['code'] == 'RuntimeDeployment.Matches'


def diagnostic(result, exit_code, runtime_status, code=None):
    assert result.returncode == exit_code, result.stderr
    assert result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['operation'] == 'deployment.doctor'
    if code is not None:
        assert error['code'] == code
    checks(error, runtime_status)
    assert 'Traceback' not in result.stderr and 'PRIVATE_DOCTOR' not in result.stderr
    for variable in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
        assert os.environ[variable] not in result.stderr
    return error


def test_doctor_observes_active_runtime_without_claiming_full_health(tmp_path):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        before = _snapshot(app)
        result = _run_cli(*doctor_arguments(paths))
        assert result.returncode == 0, result.stderr
        assert result.stderr == ''
        observed = json.loads(result.stdout)
        assert observed['scope'] == 'active_runtime_deployment'
        assert observed['status'] == 'UNKNOWN'
        assert observed['operation_id'] == str(app.plan.operation_id)
        assert observed['effects'] == 'NONE'
        assert observed['authority'] == 'HOST_SUPPLIED_PIN'
        assert observed['verification'] == 'NOT_PERFORMED'
        checks(observed, 'PASS')
        assert _snapshot(app) == before
        assert os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'] not in result.stdout


def test_diagnose_uses_one_read_only_snapshot_without_provider_work(monkeypatch):
    with application() as app:
        run(app); publish(app)
        before, statements, calls, settings = _snapshot(app), [], [], []

        def forbidden(*args, **kwargs):
            calls.append(True)
            raise AssertionError('Doctor must not prepare provider keys')

        def collect(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)

        def inspect_transaction(connection, cursor, statement, parameters, context, executemany):
            if statement.upper().startswith('SET TRANSACTION ISOLATION LEVEL'):
                settings.append(connection.exec_driver_sql(
                    "SELECT current_setting('transaction_read_only'), "
                    "current_setting('transaction_isolation')").one())

        monkeypatch.setattr(Keyring, 'prepare', forbidden)
        monkeypatch.setattr(Keyring, '_provider', forbidden)
        event.listen(Engine, 'before_cursor_execute', collect)
        event.listen(Engine, 'after_cursor_execute', inspect_transaction)
        try:
            assert m.diagnose_deployment(app.plan, app.runtime, pin=app.pin) is None
        finally:
            event.remove(Engine, 'before_cursor_execute', collect)
            event.remove(Engine, 'after_cursor_execute', inspect_transaction)
        assert settings == [('on', 'repeatable read')]
        assert calls == [] and statements
        assert statements[0].upper() == 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY'
        assert all(statement.lstrip().split()[0].upper() in ('SELECT', 'SET') for statement in statements)
        assert not any('LOCK TABLE' in statement.upper() or 'pg_try_advisory_lock' in statement
                       for statement in statements)
        assert _snapshot(app) == before


def test_doctor_refuses_owner_credentials_as_observed_runtime_mismatch(tmp_path):
    with application() as app:
        run(app); publish(app)
        paths = inputs(app, tmp_path)
        before = _snapshot(app)
        diagnostic(_run_cli(*doctor_arguments(paths)), 3, 'FAIL',
                   'attachment_requires_planned_runtime_role')
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['schema_create', 'journal_column_update'])
def test_doctor_and_active_status_refuse_unsafe_runtime_grants(tmp_path, fault):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        grant, revoke = privilege_change(app, fault)
        try:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(grant)
            before = _snapshot(app)
            with pytest.raises(m.TransitionFailure) as refused:
                m.status(app.plan, app.runtime, pin=app.pin)
            assert refused.value.code == 'unsafe_runtime_role'
            diagnostic(_run_cli(*doctor_arguments(paths)), 3, 'FAIL', 'unsafe_runtime_role')
            assert _snapshot(app) == before
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(revoke)
        assert m.status(app.plan, app.runtime, pin=app.pin).runtime_metadata_matches
        restored = _run_cli(*doctor_arguments(paths))
        assert restored.returncode == 0 and restored.stderr == ''
        checks(json.loads(restored.stdout), 'PASS')


@pytest.mark.parametrize('fault', ['schema_create', 'journal_column_update'])
def test_pending_status_refuses_unsafe_grants_and_recovers_same_artifacts(fault):
    with application() as app:
        run(app)
        pin = replace(app.pin, phase='PENDING')
        grant, revoke = privilege_change(app, fault)
        before = _snapshot(app)
        try:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(grant)
            with pytest.raises(m.TransitionFailure) as refused:
                m.status(app.plan, app.runtime, pin=pin)
            assert refused.value.code == 'unsafe_runtime_role'
            assert _snapshot(app) == before
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(revoke)
        recovered = m.status(app.plan, app.runtime, pin=pin)
        assert recovered.phase == recovered.external_phase == 'PENDING'
        assert recovered.runtime_metadata_matches is False
        assert recovered.verification == 'NOT_PERFORMED'
        assert _snapshot(app) == before


@pytest.mark.parametrize('primary_unsafe', [False, True])
def test_doctor_reports_real_close_failure_without_losing_primary_error(
        tmp_path, monkeypatch, capsys, primary_unsafe):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        grant, revoke = privilege_change(app, 'schema_create')
        original_close, closed = Connection.close, []

        def fail_after_close(connection):
            original_close(connection)
            assert connection.closed
            closed.append(True)
            raise OSError('PRIVATE_DOCTOR_CLOSE_FAILURE')

        try:
            if primary_unsafe:
                with app.owner.begin() as connection:
                    connection.exec_driver_sql(grant)
            before = _snapshot(app)
            with monkeypatch.context() as patch:
                patch.setattr(Connection, 'close', fail_after_close)
                exit_code = cli.main(list(doctor_arguments(paths)))
            captured = capsys.readouterr()
            result = subprocess.CompletedProcess(doctor_arguments(paths), exit_code,
                                                 captured.out, captured.err)
            error = diagnostic(result, 4, 'UNKNOWN', 'unsafe_runtime_role' if primary_unsafe
                               else 'connection_cleanup_requires_inspection')
            assert error['cleanup_errors'] == [{'stage': 'close', 'cause': 'OSError', 'sqlstate': None}]
            assert closed == [True]
            assert _snapshot(app) == before
        finally:
            if primary_unsafe:
                with app.owner.begin() as connection:
                    connection.exec_driver_sql(revoke)


def test_doctor_reports_connection_failure_as_unknown_without_private_details(tmp_path):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        private = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        private['password'] = 'PRIVATE_DOCTOR_WRONG_PASSWORD'
        paths['database'].write_text(psycopg.conninfo.make_conninfo(**private))
        before = _snapshot(app)
        result = _run_cli(*doctor_arguments(paths))
        diagnostic(result, 4, 'UNKNOWN')
        assert not any(private.get(name) and private[name] in result.stderr
                       for name in ('host', 'user', 'password'))
        assert _snapshot(app) == before


def test_missing_doctor_arguments_keep_all_observations_unknown():
    result = _run_cli('doctor', '--json')
    assert result.returncode == 2 and result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['operation'] in ('cli', 'deployment.doctor')
    checks(error, 'UNKNOWN')
    assert 'Traceback' not in result.stderr


@pytest.mark.parametrize('fault', ['malformed_plan', 'wrong_pin', 'PREPARED', 'PENDING'])
def test_doctor_refuses_invalid_or_unpublished_authority_before_connection(tmp_path, fault):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        if fault == 'malformed_plan':
            paths['plan'].write_text('{"private":"PRIVATE_DOCTOR_INPUT"}')
        else:
            pin = json.loads(paths['pin'].read_text())
            if fault == 'wrong_pin':
                pin['plan_digest'] = '0' * 64
            else:
                pin['phase'] = fault
            paths['pin'].write_text(json.dumps(pin))
        # A connection attempt would produce exit 4, not the required input refusal.
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_DOCTOR_INPUT')
        before = _snapshot(app)
        diagnostic(_run_cli(*doctor_arguments(paths)), 2, 'UNKNOWN',
                   'InvalidInput' if fault == 'malformed_plan' else 'external_policy_mismatch')
        assert _snapshot(app) == before


def test_doctor_rejects_valid_reverse_artifact_before_connection(tmp_path):
    with application() as app:
        run(app); publish(app)
        reverse = reverse_plan(app)
        paths = doctor_inputs(app, tmp_path)
        paths['plan'].write_bytes(reverse.artifact)
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_DOCTOR_INPUT')
        before = _snapshot(app)
        diagnostic(_run_cli(*doctor_arguments(paths)), 2, 'UNKNOWN', 'InvalidInput')
        assert _snapshot(app) == before


def test_doctor_output_failure_is_explicit_without_database_changes(tmp_path):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        before = _snapshot(app)
        with open('/dev/full', 'w') as unavailable:
            result = subprocess.run([sys.executable, '-m', 'cryptalis', *doctor_arguments(paths)],
                stdout=unavailable, stderr=subprocess.PIPE, text=True, timeout=15)
        assert result.returncode == 4
        error = json.loads(result.stderr)['error']
        assert (error['family'], error['code']) == ('CLI', 'OutputUnavailable')
        checks(error, 'UNKNOWN')
        assert os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'] not in result.stderr
        assert _snapshot(app) == before
