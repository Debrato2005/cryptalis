"""Operators can inspect profile changes without custody or mutation authority."""
from dataclasses import asdict, replace
import json
import os

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

from cryptalis import cli
from cryptalis.crypto import Keyring
from test_application_modification import configured_change, propose, prepare
from test_cli import _run_cli
from test_migration import application, keys, publish, run
from test_modification_storage import storage_change
from test_payload_rotation_execution import operation_pin
from test_rotation_status_cli import preparation_inputs, snapshot, failure
from test_status_cli import arguments


@pytest.mark.parametrize('search', [True, False])
@pytest.mark.parametrize('phase', ['PREPARED', 'EXPANDED', 'BACKFILLED', 'ABORTED'])
def test_status_reports_profile_progress_without_claiming_verification(tmp_path, search, phase):
    with application(unique=False, queries=[] if search else ['equality']) as app:
        run(app); publish(app)
        configured = configured_change(app) if search else storage_change(app)
        proposal = propose(configured, app)
        if phase != 'PREPARED':
            prepare(configured, app, proposal, max_chunks=None if phase == 'BACKFILLED' else 1)
        if phase == 'ABORTED':
            configured.abort_modification(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
                keys=keys, approval=app.approval)
        paths = preparation_inputs(app, proposal, tmp_path)
        paths['database'].write_text(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        before = snapshot(app, proposal)
        public = configured.status(app.owner, deployment=(proposal, operation_pin(proposal)))
        result = _run_cli(*arguments(paths))
        assert result.returncode == 3 and result.stderr == '', result.stderr
        observed = json.loads(result.stdout)
        assert observed['scope'] == 'profile_rotation_preparation'
        assert observed['source_operation_id'] == str(app.plan.operation_id)
        assert observed['operation_id'] == str(proposal.operation_id)
        assert observed['phase'] == public.phase == phase
        assert observed['committed_rows'] == public.committed_rows
        assert observed['committed_chunks'] == public.committed_chunks
        assert observed['verification'] == 'NOT_PERFORMED'
        assert observed['effects'] == 'NONE' and observed['runtime_metadata_matches'] is False
        assert snapshot(app, proposal) == before
        assert os.environ['CRYPTALIS_TEST_DATABASE_URL'] not in result.stdout


def test_profile_status_is_read_only_and_key_free(tmp_path, monkeypatch, capsys):
    with application(unique=False) as app:
        run(app); publish(app)
        configured = storage_change(app)
        proposal = propose(configured, app)
        prepare(configured, app, proposal, max_chunks=1)
        paths = preparation_inputs(app, proposal, tmp_path)
        before, statements, calls = snapshot(app, proposal), [], []
        def forbidden(*args, **kwargs):
            calls.append(True)
            pytest.fail('recorded status attempted provider work')
        def collect(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement)
        monkeypatch.setattr(Keyring, 'prepare', forbidden)
        monkeypatch.setattr(Keyring, '_provider', forbidden)
        event.listen(Engine, 'before_cursor_execute', collect)
        try:
            assert cli.main(list(arguments(paths))) == 3
        finally:
            event.remove(Engine, 'before_cursor_execute', collect)
        captured = capsys.readouterr()
        assert captured.err == '' and json.loads(captured.out)['phase'] == 'EXPANDED'
        assert not calls and statements
        assert all(statement.lstrip().split()[0].upper() in ('SELECT', 'SET') for statement in statements)
        assert not any('LOCK TABLE' in statement.upper() or 'pg_try_advisory_lock' in statement for statement in statements)
        assert snapshot(app, proposal) == before


def test_profile_status_wrong_pin_and_doctor_refuse_before_connection(tmp_path):
    with application(unique=False) as app:
        run(app); publish(app)
        proposal = propose(storage_change(app), app)
        paths = preparation_inputs(app, proposal, tmp_path,
            replace(operation_pin(proposal), plan_digest='0' * 64))
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_ROTATION_INPUT')
        before = snapshot(app, proposal)
        failure(_run_cli(*arguments(paths)), 2, 'profile_operation_pin_mismatch')
        paths['pin'].write_text(json.dumps(asdict(operation_pin(proposal)), default=str))
        failure(_run_cli(*arguments(paths), '--restore-binding', str(tmp_path / 'PRIVATE_UNUSED')), 2, 'InvalidInput')
        result = _run_cli('doctor', *arguments(paths)[1:])
        assert result.returncode == 2 and result.stdout == ''
        assert json.loads(result.stderr)['error']['code'] == 'InvalidInput'
        assert snapshot(app, proposal) == before
