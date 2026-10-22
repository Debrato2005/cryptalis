"""Native process-crash, lost-reply and transaction rollback controls."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, rotation as r
from migration_commit_proxy import lost_commit_reply
from payload_rotation_worker import target_keys
from test_migration import application, frames, keys, publish, run
from test_payload_rotation_execution import (
    index_identity, operation_pin, plan, snapshot, stage, staged_frames,
)
from test_rewrap_plan import _snapshot


def assert_paused(app):
    with app.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as caught:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s', ('paused',))
        assert caught.value.orig.sqlstate == '55000'


def assert_preserved_prefix(before, after):
    for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
        assert after[identity] == before[identity]
    assert before[UUID(int=101)][0] is not None
    assert before[UUID(int=102)][0] is not None


def test_sigkill_after_committed_chunk_resumes_same_artifact_in_fresh_process(tmp_path):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        original, index_before = frames(app, True), index_identity(app)
        artifact, pin_file, approval_file = (
            tmp_path / name for name in ('payload.json', 'pin.json', 'approval.json'))
        artifact.write_bytes(proposal.artifact)
        pin_file.write_text(json.dumps(asdict(operation_pin(proposal)), default=str))
        approval_file.write_text(json.dumps(asdict(app.approval)))
        command = [sys.executable, str(Path(__file__).with_name('payload_rotation_worker.py')),
                   str(artifact), str(pin_file), str(approval_file)]
        child = subprocess.Popen(command + ['chunk', 'pause'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), 'payload worker did not report committed progress'
            report = json.loads(child.stdout.readline())
            assert report == {'phase': 'EXPANDED', 'rows': 3, 'chunks': 1,
                              'operation_id': str(proposal.operation_id), 'digest': proposal.digest}
            prefix = staged_frames(app, proposal)
            assert frames(app, True) == original and index_identity(app) == index_before
            assert_paused(app)
            child.kill()
            child.communicate(timeout=20)
            assert child.returncode == -signal.SIGKILL
            committed = snapshot(app, proposal)
            inspected = subprocess.run(command + ['status', 'exit'], capture_output=True,
                                        text=True, timeout=30)
            assert inspected.returncode == 0
            assert json.loads(inspected.stdout) == report
            assert snapshot(app, proposal) == committed
            resumed = subprocess.run(command + ['resume', 'exit'], capture_output=True,
                                      text=True, timeout=30)
            assert resumed.returncode == 0
            assert json.loads(resumed.stdout) == {
                'phase': 'BACKFILLED', 'rows': len(original), 'chunks': 3,
                'operation_id': str(proposal.operation_id), 'digest': proposal.digest}
            assert_preserved_prefix(prefix, staged_frames(app, proposal))
            assert frames(app, True) == original and index_identity(app) == index_before
            assert artifact.read_bytes() == proposal.artifact
            assert_paused(app)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=20)


def test_lost_chunk_commit_reply_is_inspected_without_resealing_prefix():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        original, index_before = frames(app, True), index_identity(app)
        assert stage(app, proposal, target_keys, until='EXPANDED').phase == 'EXPANDED'
        # Executor admission commits first, inspection second, and the first
        # complete encrypted chunk third. The proxy drops a terminal reply.
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=3) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure):
                    r.apply_payload_rotation(proposal, proxied, keys=keys, target_keys=target_keys,
                                             pin=operation_pin(proposal), approval=app.approval)
                assert dropped.wait(5), 'proxy did not discard the committed chunk reply'
            finally:
                proxied.dispose()
        committed = snapshot(app, proposal)
        observed = r.status_payload_rotation(proposal, app.owner, pin=operation_pin(proposal))
        assert (observed.phase, observed.committed_rows, observed.committed_chunks) == ('EXPANDED', 3, 1)
        assert snapshot(app, proposal) == committed
        prefix = staged_frames(app, proposal)
        assert_paused(app)
        assert stage(app, proposal, target_keys).phase == 'BACKFILLED'
        assert_preserved_prefix(prefix, staged_frames(app, proposal))
        assert frames(app, True) == original and index_identity(app) == index_before


def test_lost_abort_commit_reply_is_inspected_before_idempotent_cancellation():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        original, index_before = frames(app, True), index_identity(app)
        source_schema = _snapshot(app)[2]
        stage(app, proposal, target_keys, max_chunks=1)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
            proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                    creator=lambda: psycopg.connect(url))
            try:
                with pytest.raises(m.TransitionFailure):
                    r.abort_payload_rotation(proposal, proxied, keys=keys,
                                             source_pin=app.pin, approval=app.approval)
                assert dropped.wait(5), 'proxy did not discard the committed abort reply'
            finally:
                proxied.dispose()
        observed = r.status_payload_rotation(proposal, app.owner, pin=operation_pin(proposal))
        assert observed.phase == 'ABORTED'
        committed = _snapshot(app)
        assert r.abort_payload_rotation(proposal, app.owner, keys=keys,
                                         source_pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert _snapshot(app) == committed
        assert committed[2] == source_schema
        assert frames(app, True) == original and index_identity(app) == index_before
        assert m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches
        with app.runtime.begin() as connection:
            result = connection.exec_driver_sql(
                f'UPDATE "{app.schema}".customer SET label=%s WHERE id=%s',
                ('writers resume after inspected abort', UUID(int=101)))
            assert result.rowcount == 1


def test_failure_after_real_shadow_update_rolls_back_new_chunk_and_marker():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        original, index_before = frames(app, True), index_identity(app)
        stage(app, proposal, target_keys, max_chunks=1)
        committed = snapshot(app, proposal)
        prefix = staged_frames(app, proposal)
        shadow = app.plan.document['lock']['models'][0]['fields'][0]['payload_column'] + '_rotation'
        updates = []

        def fail_after_update(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('UPDATE ') and shadow in statement:
                updates.append(cursor.rowcount)
                raise RuntimeError('public injected failure after native shadow UPDATE')

        event.listen(app.owner, 'after_cursor_execute', fail_after_update)
        try:
            with pytest.raises(m.TransitionFailure):
                stage(app, proposal, target_keys)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_update)
        assert updates == [3]
        assert snapshot(app, proposal) == committed
        assert frames(app, True) == original and index_identity(app) == index_before
        assert_paused(app)
        assert stage(app, proposal, target_keys).phase == 'BACKFILLED'
        assert_preserved_prefix(prefix, staged_frames(app, proposal))


def test_failure_after_real_guard_drop_rolls_back_abort_and_retains_fence():
    with application() as app:
        run(app); publish(app)
        proposal = plan(app, target_keys)
        original, index_before = frames(app, True), index_identity(app)
        stage(app, proposal, target_keys, max_chunks=1)
        committed = snapshot(app, proposal)
        trigger = '_cryptalis_' + proposal.operation_id.hex + '_pause'
        dropped = []

        def fail_after_drop(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('DROP TRIGGER ') and trigger in statement:
                dropped.append(True)
                raise RuntimeError('public injected failure after native guard DROP')

        event.listen(app.owner, 'after_cursor_execute', fail_after_drop)
        try:
            with pytest.raises(m.TransitionFailure):
                r.abort_payload_rotation(proposal, app.owner, keys=keys,
                                         source_pin=app.pin, approval=app.approval)
        finally:
            event.remove(app.owner, 'after_cursor_execute', fail_after_drop)
        assert dropped == [True]
        assert snapshot(app, proposal) == committed
        assert frames(app, True) == original and index_identity(app) == index_before
        assert_paused(app)
        assert r.abort_payload_rotation(proposal, app.owner, keys=keys,
                                         source_pin=app.pin, approval=app.approval).phase == 'ABORTED'
        assert m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches
