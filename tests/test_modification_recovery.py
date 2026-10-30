"""Real process termination and lost PostgreSQL commit replies during modification."""
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
from sqlalchemy import create_engine

from cryptalis.migration import TransitionFailure
from migration_commit_proxy import lost_commit_reply
from test_application_modification import configured_change, propose, prepare, seal
from test_deprotection import app_pin
from test_migration import application, frames, keys, publish, run
from test_payload_rotation_execution import operation_pin, snapshot, staged_frames
from test_payload_rotation_recovery import assert_paused


def test_sigkill_after_committed_chunk_resumes_in_fresh_process(tmp_path):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        proposal = propose(configured, app)
        original = frames(app, True)
        artifact, pin, approval = (tmp_path / name for name in ('proposal.json', 'pin.json', 'approval.json'))
        artifact.write_bytes(proposal.artifact)
        pin.write_text(json.dumps(asdict(operation_pin(proposal)), default=str))
        approval.write_text(json.dumps(asdict(app.approval)))
        command = [sys.executable, str(Path(__file__).with_name('payload_rotation_worker.py')),
                   str(artifact), str(pin), str(approval)]
        child = subprocess.Popen(command + ['chunk', 'pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=30), 'worker did not report progress'
            observed = json.loads(child.stdout.readline())
            assert (observed['phase'], observed['rows'], observed['chunks']) == ('EXPANDED', 2, 1)
            prefix = staged_frames(app, proposal)
            assert_paused(app)
            child.kill(); child.communicate(timeout=20)
            assert child.returncode == -signal.SIGKILL
            retained = snapshot(app, proposal)
            inspected = subprocess.run(command + ['status', 'exit'], capture_output=True, text=True, timeout=30)
            assert inspected.returncode == 0 and json.loads(inspected.stdout) == observed
            assert snapshot(app, proposal) == retained
            resumed = subprocess.run(command + ['resume', 'exit'], capture_output=True, text=True, timeout=30)
            assert resumed.returncode == 0 and json.loads(resumed.stdout)['phase'] == 'BACKFILLED'
            complete = staged_frames(app, proposal)
            assert all(complete[identity] == value for identity, value in prefix.items() if value[0] is not None)
            assert frames(app, True) == original and artifact.read_bytes() == proposal.artifact
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=20)


@pytest.mark.parametrize('operation', ['chunk', 'switch'])
def test_lost_commit_reply_is_inspected_before_resume(operation):
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        proposal = propose(configured, app)
        if operation == 'chunk':
            prepare(configured, app, proposal, until='EXPANDED')
        else:
            prepare(configured, app, proposal)
            successor = seal(configured, app, proposal)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=3 if operation == 'chunk' else 2) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True, creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(TransitionFailure):
                    if operation == 'chunk':
                        configured.prepare_modification(proxied, deployment=(proposal, operation_pin(proposal)), keys=keys, approval=app.approval)
                    else:
                        configured.switch_modification(proxied, proposal=proposal,
                            deployment=(successor, app_pin(successor, 'PREPARED')), keys=keys, approval=app.approval)
                assert dropped.wait(5)
            finally: proxied.dispose()
        if operation == 'chunk':
            observed = configured.status(app.owner, deployment=(proposal, operation_pin(proposal)))
            assert (observed.phase, observed.committed_rows, observed.committed_chunks) == ('EXPANDED', 2, 1)
            prefix = staged_frames(app, proposal)
            assert prepare(configured, app, proposal).phase == 'BACKFILLED'
            complete = staged_frames(app, proposal)
            assert all(complete[identity] == value for identity, value in prefix.items() if value[0] is not None)
        else:
            observed = configured.status(app.owner, deployment=(successor, app_pin(successor, 'PREPARED')))
            assert observed.phase == 'PENDING' and observed.verification == 'NOT_PERFORMED'
            current = frames(app, True)
            assert configured.switch_modification(app.owner, proposal=proposal,
                deployment=(successor, app_pin(successor, 'PENDING')), keys=keys, approval=app.approval).phase == 'PENDING'
            assert frames(app, True) == current
