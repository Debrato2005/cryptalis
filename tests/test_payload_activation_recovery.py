"""Native recovery across sealed payload cutover and publication boundaries."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys

import psycopg
import pytest
from sqlalchemy import create_engine, event

from cryptalis import migration as m, rotation as r
from migration_commit_proxy import lost_commit_reply
from payload_rotation_worker import target_keys
from test_deprotection import app_pin
from test_migration import application, frames, keys, publish, run
from test_payload_rotation_cutover import activate, seal, switch
from test_payload_rotation_execution import operation_pin, plan, snapshot, stage, staged_frames
from test_payload_rotation_recovery import assert_paused
from test_rewrap_abort import index_identity
from test_rewrap_plan import _snapshot


def test_lost_cutover_commit_reply_preserves_exact_sealed_target_for_retry():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        sealed = {identity: values[0] for identity, values in staged_frames(app, proposal).items()}
        index_before = index_identity(app)
        # Admission commits first. The whole public copy, shadow retirement,
        # writer-fence exchange and reciprocal journal chain commit second.
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure):
                    r.switch_payload_rotation(proposal, activation, proxied, keys=keys,
                        target_keys=target_keys, pin=app_pin(activation, 'PREPARED'), approval=app.approval)
                assert dropped.wait(5), 'proxy did not discard the committed cutover reply'
            finally:
                proxied.dispose()
        assert frames(app, True) == sealed and index_identity(app) == index_before
        committed = _snapshot(app)
        assert m.status(activation, app.owner, pin=app_pin(activation, 'PREPARED')).phase == 'PENDING'
        assert _snapshot(app) == committed
        assert_paused(app)
        def unavailable_source(tenant):
            raise AssertionError('A committed cutover retry must use target custody only.')
        assert switch(app, proposal, activation, keys=unavailable_source).phase == 'PENDING'
        assert _snapshot(app) == committed
        activate(app, activation)
        assert frames(app, True) == sealed and index_identity(app) == index_before


def test_sigkill_after_committed_cutover_publishes_same_disk_artifacts_in_fresh_process(tmp_path):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        prepared = stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        sealed = {identity: values[0] for identity, values in staged_frames(app, proposal).items()}
        index_before = index_identity(app)
        proposal_path, activation_path, pin_path, approval_path = (
            tmp_path / name for name in ('preparation.json', 'activation.json', 'pin.json', 'approval.json'))
        proposal_path.write_bytes(proposal.artifact)
        activation_path.write_bytes(activation.artifact)
        pin_path.write_text(json.dumps(asdict(app_pin(activation, 'PREPARED')), default=str))
        approval_path.write_text(json.dumps(asdict(app.approval)))
        command = [sys.executable, str(Path(__file__).with_name('payload_activation_worker.py')),
                   str(proposal_path), str(activation_path), str(pin_path), str(approval_path)]
        child = subprocess.Popen(command + ['switch', 'pause'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), 'payload activation worker did not report committed cutover'
            report = json.loads(child.stdout.readline())
            assert report == {'phase': 'PENDING', 'rows': prepared.committed_rows,
                              'chunks': prepared.committed_chunks,
                              'operation_id': str(activation.operation_id), 'digest': activation.digest}
            assert frames(app, True) == sealed and index_identity(app) == index_before
            assert_paused(app)
            child.kill()
            child.communicate(timeout=20)
            assert child.returncode == -signal.SIGKILL
            committed = _snapshot(app)
            inspected = subprocess.run(command + ['status', 'exit'], capture_output=True,
                                        text=True, timeout=30)
            assert inspected.returncode == 0
            assert json.loads(inspected.stdout) == report
            assert _snapshot(app) == committed
            pin_path.write_text(json.dumps(asdict(app_pin(activation, 'ACTIVATING')), default=str))
            restarted = subprocess.run(command + ['publish', 'exit'], capture_output=True,
                                        text=True, timeout=30)
            assert restarted.returncode == 0
            assert json.loads(restarted.stdout) == {**report, 'phase': 'ACTIVE'}
            assert frames(app, True) == sealed and index_identity(app) == index_before
            assert proposal_path.read_bytes() == proposal.artifact
            assert activation_path.read_bytes() == activation.artifact
            assert m.check_deployment(activation, app.owner, pin=app_pin(activation, 'ACTIVE')) is None
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=20)


@pytest.mark.parametrize('boundary', ['public_copy', 'guard_drop'])
def test_failure_after_native_cutover_effect_rolls_back_source_and_backfilled_preparation(boundary):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        original, index_before = frames(app, True), index_identity(app)
        staged = {identity: values[0] for identity, values in staged_frames(app, proposal).items()}
        committed = snapshot(app, proposal)
        field = proposal.source.document['lock']['models'][0]['fields'][0]
        shadow = field['payload_column'] + '_rotation'
        trigger = '_cryptalis_' + proposal.operation_id.hex + '_pause'
        reached = []

        def fail_after_effect(connection, cursor, statement, parameters, context, executemany):
            copied = boundary == 'public_copy' and statement.startswith('UPDATE ') and shadow in statement
            retired = boundary == 'guard_drop' and statement.startswith('DROP TRIGGER ') and trigger in statement
            if copied or retired:
                reached.append(boundary)
                raise RuntimeError('public injected failure after native payload cutover effect')

        event.listen(app.owner, 'after_cursor_execute', fail_after_effect)
        try:
            with pytest.raises(m.TransitionFailure):
                switch(app, proposal, activation)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_effect)
        assert reached == [boundary]
        assert snapshot(app, proposal) == committed
        assert frames(app, True) == original and index_identity(app) == index_before
        observed = r.status_payload_rotation(proposal, app.owner, pin=operation_pin(proposal))
        assert observed.phase == 'BACKFILLED'
        assert_paused(app)
        assert switch(app, proposal, activation).phase == 'PENDING'
        assert frames(app, True) == staged and index_identity(app) == index_before
        activate(app, activation)
        assert frames(app, True) == staged


def test_lost_publication_commit_reply_retries_actual_activating_pin_without_rewriting_values():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        stage(app, proposal, target_keys)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        sealed, index_before = frames(app, True), index_identity(app)
        pin = app_pin(activation, 'ACTIVATING')
        # Admission, initial journal inspection, then actual activation COMMIT.
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=3) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure):
                    m.apply(activation, proxied, keys=target_keys, pin=pin,
                            approval=app.approval, until='ACTIVE')
                assert dropped.wait(5), 'proxy did not discard the committed publication reply'
            finally:
                proxied.dispose()
        assert m.status(activation, app.owner, pin=pin).phase == 'ACTIVE'
        committed = _snapshot(app)
        assert m.apply(activation, app.owner, keys=target_keys, pin=pin,
                       approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        assert _snapshot(app) == committed
        assert frames(app, True) == sealed and index_identity(app) == index_before
        assert m.check_deployment(activation, app.owner, pin=app_pin(activation, 'ACTIVE')) is None
