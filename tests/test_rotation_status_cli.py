"""Native preparation status observes progress without deployment authority."""
from dataclasses import asdict, replace
from hashlib import sha256
import json
import os

import psycopg
import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine

from cryptalis import cli, migration as m, rotation as r
from cryptalis.crypto import Keyring
from search_rotation_worker import target_keys as search_keys
from test_cli import _run_cli
from test_migration import application, keys, publish, run
from test_payload_rotation_execution import operation_pin, staged_frames
from test_payload_rotation_plan import plan as payload_plan, target_factory
from test_rewrap_plan import _snapshot
from test_runtime_boundary import privilege_change
from test_search_rotation_lifecycle import plan as search_plan
from test_status_cli import arguments, inputs


def prepare(app, purpose):
    run(app); publish(app)
    target = target_factory()[0] if purpose == 'payload' else search_keys
    planner = payload_plan if purpose == 'payload' else search_plan
    return planner(app, target), target


def reach(app, proposal, target, phase):
    if phase == 'PREPARED':
        return
    getattr(r, 'apply_' + proposal.purpose + '_rotation')(
        proposal, app.owner, keys=keys, target_keys=target,
        pin=operation_pin(proposal), approval=app.approval,
        max_chunks=1 if phase in ('EXPANDED', 'ABORTED') else None)
    if phase == 'ABORTED':
        getattr(r, 'abort_' + proposal.purpose + '_rotation')(
            proposal, app.owner, keys=keys, source_pin=app.pin, approval=app.approval)


def preparation_inputs(app, proposal, directory, pin=None):
    paths = inputs(app, directory)
    paths['plan'].write_bytes(proposal.artifact)
    paths['pin'].write_text(json.dumps(asdict(pin or operation_pin(proposal)), default=str))
    return paths


def snapshot(app, proposal):
    original = _snapshot(app)
    columns = {column['name'] for column in original[2]['columns']}
    shadow = proposal.source.document['lock']['models'][0]['fields'][0]['payload_column'] + '_rotation'
    return original, staged_frames(app, proposal) if shadow in columns else None


def failure(result, exit_code, code):
    assert result.returncode == exit_code, result.stderr
    assert result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['operation'] == 'transition.status'
    assert error['code'] == code
    assert 'PRIVATE_ROTATION' not in result.stderr and 'Traceback' not in result.stderr
    for variable in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
        assert os.environ[variable] not in result.stderr


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('phase', ['PREPARED', 'EXPANDED', 'BACKFILLED', 'ABORTED'])
def test_cli_observes_recorded_preparation_without_active_admission(tmp_path, purpose, phase):
    with application() as app:
        proposal, target = prepare(app, purpose)
        reach(app, proposal, target, phase)
        pin = operation_pin(proposal)
        paths = preparation_inputs(app, proposal, tmp_path, pin)
        paths['database'].write_text(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        before = snapshot(app, proposal)
        public = getattr(r, 'status_' + purpose + '_rotation')(proposal, app.owner, pin=pin)
        result = _run_cli(*arguments(paths))
        assert result.returncode == 3, result.stderr
        assert result.stderr == ''
        observed = json.loads(result.stdout)
        assert observed['scope'] == purpose + '_rotation_preparation'
        assert observed['source_operation_id'] == str(app.plan.operation_id)
        assert observed['operation_id'] == str(proposal.operation_id)
        assert observed['phase'] == public.phase == phase
        assert observed['external_phase'] == public.external_phase == 'PREPARED'
        assert observed['committed_rows'] == public.committed_rows == {
            'PREPARED': 0, 'EXPANDED': 3, 'BACKFILLED': 7, 'ABORTED': 3}[phase]
        assert observed['committed_chunks'] == public.committed_chunks
        assert observed['runtime_metadata_matches'] is public.runtime_metadata_matches is False
        assert observed['verification'] == public.verification == 'NOT_PERFORMED'
        assert observed['authority'] == 'HOST_SUPPLIED_PIN' and observed['effects'] == 'NONE'
        assert snapshot(app, proposal) == before
        assert os.environ['CRYPTALIS_TEST_DATABASE_URL'] not in result.stdout


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_cli_preparation_status_uses_read_only_sql_without_key_work(tmp_path, purpose, monkeypatch, capsys):
    with application() as app:
        proposal, target = prepare(app, purpose)
        reach(app, proposal, target, 'EXPANDED')
        paths = preparation_inputs(app, proposal, tmp_path)
        before, statements, calls = snapshot(app, proposal), [], []

        def forbidden(*args, **kwargs):
            calls.append(True)
            raise AssertionError('Recorded status must not prepare keys')

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
        assert calls == [] and statements
        assert all(statement.lstrip().split()[0].upper() in ('SELECT', 'SET') for statement in statements)
        assert not any('LOCK TABLE' in statement.upper() or 'pg_try_advisory_lock' in statement
                       for statement in statements)
        assert snapshot(app, proposal) == before


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('fault', ['schema_create', 'journal_column_update'])
def test_staged_status_refuses_unsafe_runtime_grants_without_effects(tmp_path, purpose, fault):
    with application() as app:
        proposal, target = prepare(app, purpose)
        reach(app, proposal, target, 'EXPANDED')
        paths = preparation_inputs(app, proposal, tmp_path)
        grant, revoke = privilege_change(app, fault)
        try:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(grant)
            before = snapshot(app, proposal)
            with pytest.raises(m.TransitionFailure) as refused:
                getattr(r, 'status_' + purpose + '_rotation')(
                    proposal, app.owner, pin=operation_pin(proposal))
            assert refused.value.code == 'unsafe_runtime_role'
            failure(_run_cli(*arguments(paths)), 3, 'unsafe_runtime_role')
            assert snapshot(app, proposal) == before
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(revoke)
        assert getattr(r, 'status_' + purpose + '_rotation')(
            proposal, app.owner, pin=operation_pin(proposal)).phase == 'EXPANDED'


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_preparation_identity_and_scope_refuse_before_connection(tmp_path, purpose):
    with application() as app:
        proposal, _ = prepare(app, purpose)
        paths = preparation_inputs(app, proposal, tmp_path,
            replace(operation_pin(proposal), plan_digest='0' * 64))
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_ROTATION_INPUT')
        before = snapshot(app, proposal)
        failure(_run_cli(*arguments(paths)), 2, purpose + '_operation_pin_mismatch')

        paths['pin'].write_text(json.dumps(asdict(operation_pin(proposal)), default=str))
        # This file must never be read: rotation of an adopted target is outside P's scope.
        absent_binding = tmp_path / 'PRIVATE_ROTATION_UNREAD_BINDING'
        failure(_run_cli(*arguments(paths), '--restore-binding', str(absent_binding)), 2, 'InvalidInput')
        doctor = _run_cli('doctor', *arguments(paths)[1:])
        assert doctor.returncode == 2 and doctor.stdout == ''
        error = json.loads(doctor.stderr)['error']
        assert (error['operation'], error['code']) == ('deployment.doctor', 'InvalidInput')

        malformed = proposal.document
        malformed['models'] = []
        raw = json.dumps(malformed, sort_keys=True, separators=(',', ':')).encode()
        paths['plan'].write_bytes(raw)
        pin = asdict(operation_pin(proposal))
        pin['plan_digest'] = sha256(raw).hexdigest()
        paths['pin'].write_text(json.dumps(pin, default=str))
        failure(_run_cli(*arguments(paths)), 2, 'InvalidInput')
        assert snapshot(app, proposal) == before


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_forward_preparation_pin_requires_a_recorded_operation(tmp_path, purpose):
    with application() as app:
        proposal, _ = prepare(app, purpose)
        paths = preparation_inputs(app, proposal, tmp_path, operation_pin(proposal, 'EXPANDED'))
        before = snapshot(app, proposal)
        failure(_run_cli(*arguments(paths)), 3, 'missing_' + purpose + '_operation')
        assert snapshot(app, proposal) == before


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_preparation_connection_failure_suppresses_private_details(tmp_path, purpose):
    with application() as app:
        proposal, _ = prepare(app, purpose)
        paths = preparation_inputs(app, proposal, tmp_path)
        private = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        private['password'] = 'PRIVATE_ROTATION_WRONG_PASSWORD'
        paths['database'].write_text(psycopg.conninfo.make_conninfo(**private))
        before = snapshot(app, proposal)
        result = _run_cli(*arguments(paths))
        failure(result, 4, 'database_effect_requires_inspection')
        assert not any(private.get(name) and private[name] in result.stderr
                       for name in ('host', 'user', 'password'))
        assert snapshot(app, proposal) == before
