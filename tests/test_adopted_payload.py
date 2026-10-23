"""Payload rotation continues an explicitly adopted v5 deployment."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, rotation
from cryptalis.crypto import CryptoFailure, FieldDescriptor, open_text, seal_text
from payload_rotation_worker import PublicPayloadProvider
from migration_commit_proxy import lost_commit_reply
from smolink_fresh_cluster import rotated_keys
import test_adopted_rewrap as recovery
import test_payload_rotation_execution as execution
import test_smolink_fresh_cluster as smolink_recovery

# Reuse the real fresh-target fixture without re-exporting its collected tests.
adopted = recovery.adopted


def preparation_pin(proposal):
    return m.DeploymentPin(proposal.source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')


def test_adopted_payload_current_values_resume_publish_and_native_exit(adopted, tmp_path):
    app = adopted
    source = recovery.publish_rewrap(app, recovery.proposal(app), recovery.fresh.keys, recovery.target_keys)
    assert source.document['format'] == 'cryptalis.transition/v5'
    before, index = recovery.frame_bytes(app), recovery.index_identity(app)
    stable = recovery.snapshot(app)
    source_artifact = source.artifact
    source_pin = recovery.pin(source, 'ACTIVE')
    proposal = rotation.plan_payload_rotation(source, app.owner, source_pin=source_pin,
        keys=recovery.target_keys, target_keys=rotated_keys, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
        max_batch_rows=3, max_batch_bytes=64 * 1024 * 1024)
    assert recovery.snapshot(app) == stable and source.artifact == source_artifact
    assert proposal.source.artifact == source_artifact
    assert rotation.PayloadRotationPlan(proposal.artifact).artifact == proposal.artifact
    first = rotation.apply_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE, max_chunks=1)
    assert (first.phase, first.committed_rows, first.committed_chunks) == ('EXPANDED', 3, 1)
    view = SimpleNamespace(owner=app.owner, schema=recovery.fresh.SCHEMA)
    prefix = execution.staged_frames(view, proposal)
    assert recovery.frame_bytes(app) == before and recovery.index_identity(app) == index
    assert rotation.apply_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE).phase == 'BACKFILLED'
    complete = execution.staged_frames(view, proposal)
    for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
        assert complete[identity] == prefix[identity]
    assert recovery.frame_bytes(app) == before and recovery.index_identity(app) == index
    field = source.document['lock']['models'][0]['fields'][0]
    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
    material = rotated_keys(recovery.fresh.TENANT).prepare()
    for identity, (frame,) in complete.items():
        assert open_text(frame, descriptor, recovery.fresh.TENANT, identity, material) == recovery.fresh.MANIFEST['expected'][str(identity)][1]
        if frame is not None:
            assert int.from_bytes(frame[6:10], 'big') == 2
            assert frame[10:46] == before[identity][10:46]
            assert frame != before[identity]
    staged = recovery.snapshot(app)
    activation = rotation.seal_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE,
        copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    assert activation.document['format'] == 'cryptalis.transition/v6'
    assert activation.document['restore_lineage'] == source.document['restore_lineage']
    assert activation.document['estimates']['copy_rows_per_second'] == 1000.5
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    malformed_and_old_reader_refuse(proposal, activation, tmp_path)
    repeated = rotation.seal_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE,
        copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    assert repeated.artifact == activation.artifact and recovery.snapshot(app) == staged
    assert rotation.switch_payload_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    pending = recovery.snapshot(app)
    assert rotation.switch_payload_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=recovery.pin(activation, 'PENDING'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert recovery.snapshot(app) == pending
    assert recovery.frame_bytes(app) == {identity: values[0] for identity, values in complete.items()}
    assert recovery.index_identity(app) == index
    assert m.apply(activation, app.owner, keys=rotated_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    recovery.current_edit(app, activation, rotated_keys, 'latest adopted payload value')
    current_frames = recovery.frame_bytes(app)
    rewrap = rotation.plan_rewrap(activation, app.owner, source_pin=recovery.pin(activation, 'ACTIVE'),
        keys=rotated_keys, target_keys=smolink_recovery.adopted_keys, verify_rows_per_second=1000)
    assert rewrap.source.artifact == activation.artifact  # Includes the fractional v6 cost.
    assert rotation.RewrapPlan(rewrap.artifact).artifact == rewrap.artifact
    current = recovery.publish_rewrap(app, rewrap, rotated_keys, smolink_recovery.adopted_keys)
    assert current.document['format'] == 'cryptalis.transition/v5'
    assert current.document['restore_lineage'] == activation.document['restore_lineage']
    assert recovery.frame_bytes(app) == current_frames and recovery.index_identity(app) == index
    recovery.current_edit(app, current, smolink_recovery.adopted_keys, 'latest after payload rewrap')
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest after payload rewrap']
    recovery.decrypt_remove_and_restart(app, current, smolink_recovery.adopted_keys, expected)


def active_source(app, aborted_rewrap=False):
    if aborted_rewrap:
        canceled = recovery.proposal(app)
        assert recovery.pending(app, canceled).phase == 'PENDING'
        assert rotation.abort_rewrap(canceled, app.owner, keys=recovery.fresh.keys,
            pin=app.source_pin, approval=recovery.MAINTENANCE).phase == 'ABORTED'
    return recovery.publish_rewrap(app, recovery.proposal(app), recovery.fresh.keys, recovery.target_keys)


def plan_payload(app, source):
    return rotation.plan_payload_rotation(source, app.owner, source_pin=recovery.pin(source, 'ACTIVE'),
        keys=recovery.target_keys, target_keys=rotated_keys, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
        max_batch_rows=3, max_batch_bytes=64 * 1024 * 1024)


def stage(app, proposal, **options):
    return rotation.apply_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE, **options)


def seal(app, proposal, **options):
    arguments = dict(keys=recovery.target_keys, target_keys=rotated_keys, pin=preparation_pin(proposal),
                     approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    arguments.update(options)
    return rotation.seal_payload_rotation(proposal, app.owner, **arguments)


def shadows(app, proposal):
    return execution.staged_frames(SimpleNamespace(owner=app.owner, schema=recovery.fresh.SCHEMA), proposal)


def staged_snapshot(app, proposal):
    return recovery.snapshot(app), shadows(app, proposal)


def assert_fenced(app):
    with app.runtime.connect() as connection:
        with pytest.raises(DBAPIError) as refused:
            connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET label=%s', ('still fenced',))
        assert refused.value.orig.sqlstate == '55000'


def switch_and_publish(app, proposal, activation):
    assert rotation.switch_payload_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
        target_keys=rotated_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=rotated_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'


def test_partial_cancel_needs_only_source_then_latest_edit_and_new_rotation(adopted, monkeypatch):
    app = adopted
    source = active_source(app, aborted_rewrap=True)
    proposal = plan_payload(app, source)
    original, index = recovery.frame_bytes(app), recovery.index_identity(app)
    assert stage(app, proposal, max_chunks=1).phase == 'EXPANDED'
    assert_fenced(app)
    with monkeypatch.context() as patch:
        patch.setattr(PublicPayloadProvider, 'unwrap', lambda *args: pytest.fail('cancellation required target custody'))
        assert rotation.abort_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
            source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.frame_bytes(app) == original and recovery.index_identity(app) == index
    assert m.check_deployment(source, app.owner, pin=recovery.pin(source, 'ACTIVE')) is None
    recovery.current_edit(app, source, recovery.target_keys, 'latest after canceled payload')
    current = recovery.snapshot(app)
    assert rotation.abort_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
        source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.snapshot(app) == current
    next_proposal = plan_payload(app, source)
    assert stage(app, next_proposal).phase == 'BACKFILLED'
    activation = seal(app, next_proposal)
    switch_and_publish(app, next_proposal, activation)
    assert activation.document['restore_lineage'] == source.document['restore_lineage']
    recovery.current_edit(app, activation, rotated_keys, 'healthy after canceled payload')


@pytest.mark.parametrize('fault', ['pin', 'source_policy', 'custody', 'approved_check', 'guard', 'retained_generation', 'sealed_target'])
def test_adopted_staging_refusals_preserve_fence_and_recover(adopted, fault, monkeypatch):
    app = adopted
    source = active_source(app)
    proposal = plan_payload(app, source)
    original, index = recovery.frame_bytes(app), recovery.index_identity(app)
    assert stage(app, proposal).phase == 'BACKFILLED'
    activation = seal(app, proposal)
    field = source.document['lock']['models'][0]['fields'][0]
    column, constraint = field['payload_column'] + '_rotation', field['payload_column'] + '_frame'
    guard = '_cryptalis_' + proposal.operation_id.hex + '_pause'
    previous = shadows(app, proposal)[UUID(int=101)][0]
    definition = None
    if fault in ('approved_check', 'guard', 'retained_generation', 'sealed_target'):
        with app.owner.begin() as connection:
            if fault == 'approved_check':
                definition = connection.exec_driver_sql('SELECT pg_catalog.pg_get_constraintdef(oid) '
                    'FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                    (f'"{recovery.fresh.SCHEMA}".customer', constraint)).scalar_one()
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" CHECK (octet_length(name)>=0)')
            elif fault == 'guard':
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DISABLE TRIGGER "{guard}"')
            else:
                if fault == 'retained_generation':
                    replacement = original[UUID(int=101)]  # Authentic generation1; target retains its reader.
                else:
                    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
                    replacement = seal_text(recovery.fresh.MANIFEST['expected'][str(UUID(int=101))][1], descriptor,
                        recovery.fresh.TENANT, UUID(int=101), rotated_keys(recovery.fresh.TENANT).prepare())
                    assert replacement != previous and replacement[10:46] == previous[10:46]
                connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{column}"=%s WHERE id=%s',
                                          (replacement, UUID(int=101)))
    changed = staged_snapshot(app, proposal)
    with monkeypatch.context() as patch:
        if fault == 'custody':
            patch.setattr(PublicPayloadProvider, 'unwrap', lambda *args: (_ for _ in ()).throw(RuntimeError('private target outage')))
        with pytest.raises((m.TransitionFailure, CryptoFailure)):
            if fault == 'sealed_target':
                rotation.switch_payload_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
                    target_keys=rotated_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
            else:
                seal(app, proposal, pin=replace(preparation_pin(proposal), plan_digest='0' * 64)
                     if fault == 'pin' else preparation_pin(proposal),
                     keys=recovery.fresh.keys if fault == 'source_policy' else recovery.target_keys)
    assert staged_snapshot(app, proposal) == changed
    assert recovery.frame_bytes(app) == original and recovery.index_identity(app) == index
    with app.owner.begin() as connection:
        if fault == 'approved_check':
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" {definition}')
        elif fault == 'guard':
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ENABLE TRIGGER "{guard}"')
        elif fault in ('retained_generation', 'sealed_target'):
            connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{column}"=%s WHERE id=%s',
                                      (previous, UUID(int=101)))
    if fault == 'guard':
        # Ordinary ENABLE does not restore the recorded ALWAYS trigger mode.
        partial = staged_snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure, match='writer_fence_changed'):
            seal(app, proposal)
        assert staged_snapshot(app, proposal) == partial
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ENABLE ALWAYS TRIGGER "{guard}"')
    assert_fenced(app)
    assert seal(app, proposal).artifact == activation.artifact
    switch_and_publish(app, proposal, activation)
    recovery.current_edit(app, activation, rotated_keys, 'recovered adopted payload')


_PAYLOAD_WORKER = r'''
from dataclasses import asdict
import json, pathlib, signal, sys
from uuid import UUID
sys.path.insert(0, sys.argv[1])
from cryptalis import migration as m, rotation
from test_migration import engine
from rewrap_worker import target_keys as keys
from smolink_fresh_cluster import rotated_keys as target_keys
try:
    proposal = rotation.PayloadRotationPlan(pathlib.Path(sys.argv[2]).read_bytes())
    raw = json.loads(pathlib.Path(sys.argv[3]).read_text())
    raw.update(target_id=UUID(raw['target_id']), operation_id=UUID(raw['operation_id']))
    pin = m.DeploymentPin(**raw)
    approval = m.MaintenanceApproval(**json.loads(pathlib.Path(sys.argv[4]).read_text()))
    action, pause = sys.argv[5:7]
    connection_engine = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        if action == 'status':
            progress = rotation.status_payload_rotation(proposal, connection_engine, pin=pin)
        else:
            progress = rotation.apply_payload_rotation(proposal, connection_engine, keys=keys,
                target_keys=target_keys, pin=pin, approval=approval,
                max_chunks=1 if action == 'chunk' else None)
    finally:
        connection_engine.dispose()
    print(json.dumps({'phase': progress.phase, 'rows': progress.committed_rows,
        'chunks': progress.committed_chunks, 'operation_id': str(progress.operation_id),
        'digest': proposal.digest}), flush=True)
    if pause == 'pause': signal.pause()
except Exception as failure:
    print(json.dumps({'type': type(failure).__name__,
        'code': failure.code if isinstance(failure, m.TransitionFailure) else None}), flush=True)
    raise SystemExit(2)
'''


def test_adopted_committed_chunk_sigkill_fresh_status_and_resume(adopted, tmp_path):
    app = adopted
    source = active_source(app)
    proposal = plan_payload(app, source)
    original, index = recovery.frame_bytes(app), recovery.index_identity(app)
    paths = [tmp_path / name for name in ('payload.json', 'pin.json', 'approval.json')]
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_text(json.dumps(asdict(preparation_pin(proposal)), default=str))
    paths[2].write_text(json.dumps(asdict(recovery.MAINTENANCE)))
    command = [sys.executable, '-B', '-c', _PAYLOAD_WORKER, str(Path(__file__).parent), *map(str, paths)]
    child = subprocess.Popen(command + ['chunk', 'pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=30), 'payload worker did not report committed chunk'
        first = json.loads(child.stdout.readline())
        assert first == {'phase': 'EXPANDED', 'rows': 3, 'chunks': 1,
                         'operation_id': str(proposal.operation_id), 'digest': proposal.digest}
        prefix = shadows(app, proposal)
        child.kill()
        child.communicate(timeout=20)
        assert child.returncode == -signal.SIGKILL
        committed = staged_snapshot(app, proposal)
        inspected = subprocess.run(command + ['status', 'exit'], capture_output=True, text=True, timeout=45)
        assert inspected.returncode == 0, 'fresh payload status failed; diagnostics suppressed'
        assert json.loads(inspected.stdout) == first
        assert staged_snapshot(app, proposal) == committed
        resumed = subprocess.run(command + ['resume', 'exit'], capture_output=True, text=True, timeout=45)
        assert resumed.returncode == 0, 'fresh payload resume failed; diagnostics suppressed'
        observed = json.loads(resumed.stdout)
        assert observed['phase'] == 'BACKFILLED' and observed['rows'] == len(original)
        assert observed['operation_id'] == str(proposal.operation_id) and observed['digest'] == proposal.digest
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
            assert shadows(app, proposal)[identity] == prefix[identity]
        assert paths[0].read_bytes() == proposal.artifact
        assert recovery.frame_bytes(app) == original and recovery.index_identity(app) == index
        assert_fenced(app)
        activation = seal(app, proposal)
        switch_and_publish(app, proposal, activation)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


@pytest.mark.parametrize('action', ['chunk', 'abort'])
def test_adopted_real_lost_commit_reply_preserves_current_operation(adopted, action):
    app = adopted
    source = active_source(app)
    proposal = plan_payload(app, source)
    original, index = recovery.frame_bytes(app), recovery.index_identity(app)
    if action == 'chunk': assert stage(app, proposal, until='EXPANDED').committed_rows == 0
    else: assert stage(app, proposal, max_chunks=1).committed_rows == 3
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=3 if action == 'chunk' else 2) as (url, dropped):
        proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                                creator=lambda: psycopg.connect(url, connect_timeout=5))
        try:
            with pytest.raises(m.TransitionFailure):
                if action == 'chunk':
                    rotation.apply_payload_rotation(proposal, proxied, keys=recovery.target_keys,
                        target_keys=rotated_keys, pin=preparation_pin(proposal), approval=recovery.MAINTENANCE)
                else:
                    rotation.abort_payload_rotation(proposal, proxied, keys=recovery.target_keys,
                        source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE)
            assert dropped.wait(5), 'proxy did not discard the committed reply'
        finally:
            proxied.dispose()
    observed = rotation.status_payload_rotation(proposal, app.owner, pin=preparation_pin(proposal))
    assert observed.phase == ('EXPANDED' if action == 'chunk' else 'ABORTED')
    if action == 'chunk':
        assert observed.committed_rows == 3 and observed.committed_chunks == 1
        prefix = shadows(app, proposal)
        assert_fenced(app)
        assert stage(app, proposal).phase == 'BACKFILLED'
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
            assert shadows(app, proposal)[identity] == prefix[identity]
        activation = seal(app, proposal)
        switch_and_publish(app, proposal, activation)
    else:
        committed = recovery.snapshot(app)
        assert rotation.abort_payload_rotation(proposal, app.owner, keys=recovery.target_keys,
            source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
        assert recovery.snapshot(app) == committed
        assert m.check_deployment(source, app.owner, pin=recovery.pin(source, 'ACTIVE')) is None
        assert recovery.frame_bytes(app) == original
    assert recovery.index_identity(app) == index


def malformed_and_old_reader_refuse(proposal, activation, directory):
    for fault in ('missing', 'empty', 'duplicate', 'target', 'probe', 'downgrade'):
        document = activation.document
        if fault == 'missing': document.pop('restore_lineage')
        elif fault == 'empty': document['restore_lineage'] = []
        elif fault == 'duplicate': document['restore_lineage'] *= 2
        elif fault == 'target': document['target'][3] += 1
        elif fault == 'probe': document['restore_lineage'][0]['restatements'][0].pop('probe')
        else: document['format'] = 'cryptalis.transition/v3'
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(document))
    paths = directory / 'current-payload.json', directory / 'current-activation.json'
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_bytes(activation.artifact)
    interpreter = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    assert interpreter, 'set CRYPTALIS_PREVIOUS_READER_PYTHON to the retained installed previous reader'
    script = r'''
import json, pathlib, sys
import cryptalis, psycopg
from cryptalis import migration as m, rotation
assert pathlib.Path(cryptalis.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
calls = []
def forbidden(*args, **kwargs):
    calls.append(True)
    raise AssertionError('old artifact reader attempted a database connection')
psycopg.connect = forbidden
for constructor, path in ((rotation.PayloadRotationPlan, sys.argv[2]), (m.MigrationPlan, sys.argv[3])):
    try:
        constructor(pathlib.Path(path).read_bytes())
    except m.TransitionFailure:
        pass
    else:
        raise AssertionError('previous reader accepted unsupported adopted artifact')
assert calls == []
print(json.dumps({'payload': 'REFUSED', 'activation': 'REFUSED', 'database_calls': 0, 'installed_previous_reader': True}))
'''
    environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
    child = subprocess.run([interpreter, '-I', '-c', script, str(Path(interpreter).parent.parent), *map(str, paths)],
                           env=environment, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, 'previous installed reader control failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'payload': 'REFUSED', 'activation': 'REFUSED',
                                        'database_calls': 0, 'installed_previous_reader': True}
