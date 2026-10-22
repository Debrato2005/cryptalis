"""Transition status CLI: real PostgreSQL observation and private diagnostics."""
from dataclasses import asdict
from hashlib import sha256
import json
import os
import subprocess
import sys

import psycopg
import pytest

from test_cli import _run_cli
from test_migration import application, publish, run


def inputs(app, directory):
    paths = {name: directory / (name + '.json') for name in ('plan', 'pin', 'database')}
    paths['plan'].write_bytes(app.plan.artifact)
    paths['pin'].write_text(json.dumps(asdict(app.pin), default=str))
    paths['database'].write_text(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
    paths['database'].chmod(0o600)
    return paths


def arguments(paths):
    return ('status', str(paths['plan']), '--pin', str(paths['pin']),
            '--database-url-file', str(paths['database']), '--json')


@pytest.mark.parametrize('phase,exit_code', [('PREPARED', 3), ('PENDING', 3),
                                           ('ACTIVE', 0), ('ABORTED', 3)])
def test_cli_observes_status_without_admitting_incomplete_operations(tmp_path, phase, exit_code):
    with application() as app:
        if phase == 'ACTIVE':
            run(app)
            publish(app)
        elif phase == 'ABORTED':
            run(app, 'EXPANDED')
            app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
        elif phase == 'PENDING':
            run(app)
        paths = inputs(app, tmp_path)
        result = _run_cli(*arguments(paths))
        assert result.returncode == exit_code, result.stderr
        assert result.stderr == ''
        observed = json.loads(result.stdout)
        assert observed['scope'] == 'protection_transition'
        assert observed['operation_id'] == str(app.plan.operation_id)
        assert observed['phase'] == phase
        assert observed['external_phase'] == app.pin.phase
        assert observed['runtime_metadata_matches'] is (phase == 'ACTIVE')
        assert observed['verification'] == 'NOT_PERFORMED'
        assert observed['authority'] == 'HOST_SUPPLIED_PIN'
        assert observed['effects'] == 'NONE'
        assert observed['committed_rows'] == (7 if phase in ('PENDING', 'ACTIVE') else 0)
        assert os.environ['CRYPTALIS_TEST_DATABASE_URL'] not in result.stdout


@pytest.mark.parametrize('bad_input', ['plan', 'pin', 'database', 'missing_plan', 'oversized_database'])
def test_cli_rejects_private_malformed_inputs_without_echo(tmp_path, bad_input):
    with application() as app:
        paths = inputs(app, tmp_path)
        if bad_input == 'missing_plan':
            paths['plan'] = tmp_path / 'PRIVATE_MISSING_STATUS_INPUT'
        elif bad_input == 'oversized_database':
            paths['database'].write_bytes(b'PRIVATE_STATUS_INPUT' * 4096)
        elif bad_input == 'database':
            paths['database'].write_bytes(b'\xffPRIVATE_STATUS_INPUT')
        else:
            paths[bad_input].write_text('{"private": "PRIVATE_STATUS_INPUT"}')
        result = _run_cli(*arguments(paths))
        assert result.returncode == 2
        assert result.stdout == ''
        error = json.loads(result.stderr)['error']
        assert error['operation'] == 'transition.status'
        assert 'PRIVATE_' not in result.stderr
        assert os.environ['CRYPTALIS_TEST_DATABASE_URL'] not in result.stderr


def test_cli_suppresses_real_connection_failure_details(tmp_path):
    with application() as app:
        paths = inputs(app, tmp_path)
        private = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        private['password'] = 'PRIVATE_STATUS_WRONG_PASSWORD'
        paths['database'].write_text(psycopg.conninfo.make_conninfo(**private))
        result = _run_cli(*arguments(paths))
        assert result.returncode == 4
        assert result.stdout == ''
        error = json.loads(result.stderr)['error']
        assert error['operation'] == 'transition.status'
        needles = [os.environ['CRYPTALIS_TEST_DATABASE_URL']]
        needles += [private.get(name, '') for name in ('host', 'user', 'password')]
        assert not any(needle and needle in result.stderr for needle in needles)


@pytest.mark.parametrize('damage', ['missing_target', 'missing_operation_id', 'bad_uuid',
                                   'null_target', 'short_target', 'object_lock', 'unknown_member'])
def test_cli_rejects_malformed_transition_shape_before_connection(tmp_path, damage):
    with application() as app:
        paths = inputs(app, tmp_path)
        document = app.plan.document
        if damage.startswith('missing_'):
            document.pop(damage.removeprefix('missing_'))
        elif damage == 'bad_uuid':
            document['operation_id'] = 'PRIVATE_STATUS_INPUT'
        elif damage == 'null_target':
            document['target'] = None
        elif damage == 'short_target':
            document['target'] = ['PRIVATE_STATUS_INPUT']
        elif damage == 'object_lock':
            document['lock'] = []
        else:
            document['PRIVATE_STATUS_INPUT'] = True
        paths['plan'].write_text(json.dumps(document, sort_keys=True, separators=(',', ':')))
        pin = json.loads(paths['pin'].read_text())
        pin['plan_digest'] = sha256(paths['plan'].read_bytes()).hexdigest()
        paths['pin'].write_text(json.dumps(pin))
        # A connection attempt would instead produce exit 4. Invalid plans need no server.
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_STATUS_INPUT')
        result = _run_cli(*arguments(paths))
        assert result.returncode == 2, result.stderr
        assert result.stdout == ''
        error = json.loads(result.stderr)['error']
        assert (error['family'], error['code']) == ('Transition', 'InvalidInput')
        assert 'PRIVATE_STATUS_INPUT' not in result.stderr
        assert 'Traceback' not in result.stderr


def test_cli_text_status_and_output_failure_are_explicit(tmp_path):
    with application() as app:
        paths = inputs(app, tmp_path)
        result = _run_cli(*arguments(paths)[:-1])
        assert result.returncode == 3 and result.stderr == ''
        assert 'phase: PREPARED\n' in result.stdout
        assert 'verification: NOT_PERFORMED\n' in result.stdout
        with open('/dev/full', 'w') as unavailable:
            failed = subprocess.run([sys.executable, '-m', 'cryptalis', *arguments(paths)],
                                    stdout=unavailable, stderr=subprocess.PIPE, text=True, timeout=10)
        assert failed.returncode == 4
        error = json.loads(failed.stderr)['error']
        assert (error['family'], error['code']) == ('CLI', 'OutputUnavailable')
        assert 'PRIVATE_' not in failed.stderr
