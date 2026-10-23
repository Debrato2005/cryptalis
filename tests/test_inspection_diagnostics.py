"""Inspection refusals retain safe context and give bounded remedies."""
import json
import os

import psycopg
import pytest

from test_cli import _run_cli
from test_doctor_cli import checks, doctor_inputs
from test_migration import application, publish, run
from test_rewrap_plan import _snapshot
from test_runtime_boundary import privilege_change
from test_status_cli import arguments


def inspect(paths, command, machine):
    argv = (command, *arguments(paths)[1:])
    return _run_cli(*(argv if machine else argv[:-1]))


def private_details_absent(output):
    assert 'PRIVATE_INSPECTION' not in output and 'Traceback' not in output
    for variable in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
        assert os.environ[variable] not in output
        private = psycopg.conninfo.conninfo_to_dict(os.environ[variable])
        assert all(not private.get(name) or private[name] not in output
                   for name in ('host', 'user', 'password'))


@pytest.mark.parametrize('command,fault', [
    ('doctor', 'owner'), ('doctor', 'unsafe'), ('status', 'unsafe'),
    ('doctor', 'pin'), ('status', 'pin'),
])
def test_known_inspection_refusals_retain_operation_and_safe_remedy(tmp_path, command, fault):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        grant, revoke = privilege_change(app, 'journal_column_update')
        if fault == 'owner':
            paths['database'].write_text(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        elif fault == 'pin':
            pin = json.loads(paths['pin'].read_text())
            pin['plan_digest'] = '0' * 64
            paths['pin'].write_text(json.dumps(pin))
            # A pin refusal must precede a connection attempt.
            paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_INSPECTION_INPUT')
        else:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(grant)
        try:
            before = _snapshot(app)
            expected_code, reason, remedy = {
                'owner': ('attachment_requires_planned_runtime_role',
                          'This inspection requires the runtime role declared in the plan.',
                          'Use a private connection file for the declared runtime role.'),
                'unsafe': ('unsafe_runtime_role',
                           'The declared runtime role is missing or has unsafe privileges.',
                           'Restore the declared runtime role. Remove unsafe administrative or inherited rights, database/schema CREATE, table TRIGGER/TRUNCATE, and journal mutation rights; keep required application CRUD.'),
                'pin': ('external_policy_mismatch',
                        'The supplied pin does not authorize this plan and phase.',
                        'Obtain the current pin from the host authority and check its plan identity, digest, and permitted phase.'),
            }[fault]
            for machine in (True, False):
                result = inspect(paths, command, machine)
                assert result.returncode == (2 if fault == 'pin' else 3)
                assert result.stdout == ''
                private_details_absent(result.stderr)
                if machine:
                    error = json.loads(result.stderr)['error']
                    assert error['code'] == expected_code
                    assert error['operation_id'] == str(app.plan.operation_id)
                    assert error['reason'] == reason and error['remedy'] == remedy
                    assert error['stage'] == 'database_inspection'
                    if command == 'doctor':
                        checks(error, 'UNKNOWN' if fault == 'pin' else 'FAIL')
                else:
                    assert f'Transition.{expected_code}: {reason}' in result.stderr
                    assert f'operation_id={app.plan.operation_id}' in result.stderr
                    assert f'remedy={remedy}' in result.stderr
                assert _snapshot(app) == before
        finally:
            if fault == 'unsafe':
                with app.owner.begin() as connection:
                    connection.exec_driver_sql(revoke)


@pytest.mark.parametrize('command', ['doctor', 'status'])
def test_connection_failure_keeps_generic_reason_and_operation_without_private_details(tmp_path, command):
    with application() as app:
        run(app); publish(app)
        paths = doctor_inputs(app, tmp_path)
        connection = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        connection['password'] = 'PRIVATE_INSPECTION_WRONG_PASSWORD'
        paths['database'].write_text(psycopg.conninfo.make_conninfo(**connection))
        before = _snapshot(app)
        for machine in (True, False):
            result = inspect(paths, command, machine)
            assert result.returncode == 4 and result.stdout == ''
            private_details_absent(result.stderr)
            if machine:
                error = json.loads(result.stderr)['error']
                assert error['code'] == 'database_effect_requires_inspection'
                assert error['operation_id'] == str(app.plan.operation_id)
                assert error['reason'] == 'Inspection failed. Check this operation and the current external policy.'
                assert 'remedy' not in error
                if command == 'doctor':
                    checks(error, 'UNKNOWN')
            else:
                assert f'operation_id={app.plan.operation_id}' in result.stderr
                assert 'remedy=' not in result.stderr
            assert _snapshot(app) == before
