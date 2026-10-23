"""Adopted search reindex preserves storage bytes and native query semantics."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys

from threading import Barrier
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError

from cryptalis import migration as m, rotation
from cryptalis.crypto import CryptoFailure, FieldDescriptor, Keyring, seal_text
from cryptalis.crypto import cf1
from migration_commit_proxy import lost_commit_reply
from search_rotation_worker import PublicSearchProvider
from cryptalis.crypto.keys import WrappedRoot
from payload_rotation_worker import PublicPayloadProvider, target_context, TARGET_WRAPPER
from search_rotation_worker import target_keys as new_search_keys
from test_rewrap_plan import _target
import test_adopted_rewrap as recovery
import test_adopted_payload as payload
import test_payload_rotation_execution as execution

adopted = recovery.adopted


def search_keys(tenant):
    return new_search_keys(tenant, source=recovery.target_keys)


@contextmanager
def sessions(app, active, keys):
    mapping, Customer = recovery.fresh.customer_mapping()
    runtime = recovery.fresh.engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        factory = recovery.attach(mapping, runtime, lock=active.lock_bytes, keys=keys,
                                  deployment=(active, recovery.pin(active, 'ACTIVE')))
        yield Customer, factory
    finally:
        runtime.dispose()
        mapping.dispose()



def index_identity(app):
    model = app.source.document['lock']['models'][0]
    name = next(field for field in model['fields'] if field['column'] == 'name')['payload_column'] + '_eq'
    with app.owner.connect() as connection:
        return tuple(connection.exec_driver_sql('SELECT oid::text,relfilenode::text FROM pg_catalog.pg_class '
            'WHERE oid=pg_catalog.to_regclass(%s)', (f'"{recovery.fresh.SCHEMA}"."{name}"',)).one())


def labels(app):
    with app.owner.connect() as connection:
        return {identity: bytes(frame) if frame is not None else None for identity, frame in
                connection.exec_driver_sql(f'SELECT id,label FROM "{recovery.fresh.SCHEMA}".customer')}


def query_controls(app, active):
    with sessions(app, active, search_keys) as (Customer, factory):
        tenant = recovery.fresh.TENANT
        with factory(tenant_id=tenant) as session:
            assert session.scalar(select(Customer.id).where(Customer.name == 'edited while protected')) == UUID(int=101)
            assert set(session.scalars(select(Customer.id).where(Customer.name.in_(['雪😀', 'é', None])))) == {UUID(int=102), UUID(int=104)}
            assert list(session.scalars(select(Customer.id).where(Customer.name.in_([])))) == []
            assert list(session.scalars(select(Customer.id).where(Customer.name.is_(None)))) == [UUID(int=100)]
            session.add(Customer(id=UUID(int=29001), tenant_id=tenant, name='é', label='public duplicate'))
            with pytest.raises(IntegrityError) as duplicate: session.commit()
            assert duplicate.value.orig.sqlstate == '23505' and not session.is_active
            session.rollback()
            assert session.scalar(select(Customer.name).where(Customer.id == UUID(int=104))) == 'é'
        ready = Barrier(2, timeout=10)
        def contender(number):
            with factory(tenant_id=tenant) as session:
                identity = UUID(int=29010 + number)
                session.add(Customer(id=identity, tenant_id=tenant, name='public concurrent search value', label='race'))
                ready.wait()  # No transaction is checked out yet.
                try:
                    session.commit()
                    return identity, 'committed'
                except IntegrityError as failure:
                    assert failure.orig.sqlstate == '23505'
                    session.rollback()
                    return identity, 'duplicate'
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(contender, index) for index in range(2)]
            outcomes = [future.result(timeout=30) for future in futures]
        assert sorted(outcome for _, outcome in outcomes) == ['committed', 'duplicate']
        with factory(tenant_id=tenant) as session:
            winner = session.scalars(select(Customer).where(Customer.name == 'public concurrent search value')).one()
            assert (winner.id, 'committed') in outcomes
            session.delete(winner)
            session.commit()


@pytest.mark.parametrize('rewrap_first', [False, True])
def test_adopted_search_reindexes_then_rewraps_and_rotates_payload_before_native_exit(adopted, tmp_path, rewrap_first):
    app = adopted
    assert recovery.fresh.MANIFEST['adopted_search'] is True
    source = payload.active_source(app)
    original, storage, index = recovery.frame_bytes(app), labels(app), index_identity(app)
    before = recovery.snapshot(app)
    proposal = rotation.plan_search_rotation(source, app.owner, source_pin=recovery.pin(source, 'ACTIVE'),
        keys=recovery.target_keys, target_keys=search_keys, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    assert recovery.snapshot(app) == before
    preparation = payload.preparation_pin(proposal)
    assert rotation.apply_search_rotation(proposal, app.owner, keys=recovery.target_keys, target_keys=search_keys,
        pin=preparation, approval=recovery.MAINTENANCE, max_chunks=1).committed_rows == 3
    view = type('View', (), {'owner': app.owner, 'schema': recovery.fresh.SCHEMA})()
    prefix = execution.staged_frames(view, proposal)
    assert rotation.apply_search_rotation(proposal, app.owner, keys=recovery.target_keys, target_keys=search_keys,
        pin=preparation, approval=recovery.MAINTENANCE).phase == 'BACKFILLED'
    staged = execution.staged_frames(view, proposal)
    for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
        assert staged[identity] == prefix[identity]
    positions = {field['column']: index for index, field in enumerate(proposal.source.document['lock']['models'][0]['fields'])}
    for identity, values in staged.items():
        name, label = values[positions['name']], values[positions['label']]
        assert label == storage[identity]
        if name is not None:
            assert name[:10] == original[identity][:10] and int.from_bytes(name[10:14], 'big') == 2
            assert name[14:46] != original[identity][14:46] and name[46:58] != original[identity][46:58]
    activation = rotation.seal_search_rotation(proposal, app.owner, keys=recovery.target_keys, target_keys=search_keys,
        pin=preparation, approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    assert activation.document['format'] == 'cryptalis.transition/v7'
    assert activation.document['restore_lineage'] == source.document['restore_lineage']
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    malformed_and_previous_reader_refuse(proposal, activation, tmp_path)
    assert rotation.seal_search_rotation(proposal, app.owner, keys=recovery.target_keys, target_keys=search_keys,
        pin=preparation, approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5,
        copy_wal_bytes_per_row=2048).artifact == activation.artifact
    assert rotation.switch_search_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
        target_keys=search_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    def forbidden(tenant): pytest.fail('pending retry used old source custody')
    assert rotation.switch_search_rotation(proposal, activation, app.owner, keys=forbidden,
        target_keys=search_keys, pin=recovery.pin(activation, 'PENDING'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=search_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    assert labels(app) == storage and index_identity(app) == index
    query_controls(app, activation)
    current, target = activation, search_keys
    if rewrap_first:
        target, _ = _target(search_keys)
        rewrap = rotation.plan_rewrap(activation, app.owner, source_pin=recovery.pin(activation, 'ACTIVE'),
                                     keys=search_keys, target_keys=target, verify_rows_per_second=1000)
        assert rewrap.source.artifact == activation.artifact
        current = recovery.publish_rewrap(app, rewrap, search_keys, target)
        assert current.document['format'] == 'cryptalis.transition/v5'
    def next_payload(tenant):
        old = target(tenant) if callable(target) else target
        provider = PublicPayloadProvider()
        wrapper = WrappedRoot(provider.provider_id, target_context(tenant), TARGET_WRAPPER)
        return Keyring(replace(old.policy, wrappers=old.policy.wrappers + (wrapper,), payload_generation=2),
                       {**old._providers, provider.provider_id: provider})
    prepared = rotation.plan_payload_rotation(current, app.owner, source_pin=recovery.pin(current, 'ACTIVE'),
        keys=target, target_keys=next_payload, backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    # Both direct fractional-v7 and rewrapped-v5 source decoders execute.
    assert rotation.PayloadRotationPlan(prepared.artifact).artifact == prepared.artifact
    assert rotation.apply_payload_rotation(prepared, app.owner, keys=target, target_keys=next_payload,
        pin=payload.preparation_pin(prepared), approval=recovery.MAINTENANCE).phase == 'BACKFILLED'
    latest = rotation.seal_payload_rotation(prepared, app.owner, keys=target, target_keys=next_payload,
        pin=payload.preparation_pin(prepared), approval=recovery.MAINTENANCE,
        copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    assert latest.document['format'] == 'cryptalis.transition/v6'
    assert m.MigrationPlan(latest.artifact).artifact == latest.artifact
    assert latest.document['restore_lineage'] == activation.document['restore_lineage']
    assert rotation.switch_payload_rotation(prepared, latest, app.owner, keys=target, target_keys=next_payload,
        pin=recovery.pin(latest, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(latest, app.owner, keys=next_payload, pin=recovery.pin(latest, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    recovery.current_edit(app, latest, next_payload, 'latest adopted search value')
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest adopted search value']
    recovery.decrypt_remove_and_restart(app, latest, next_payload, expected)
    with app.owner.connect() as connection:
        assert {str(identity): value for identity, value in connection.exec_driver_sql(
            f'SELECT id,label FROM "{recovery.fresh.SCHEMA}".customer')} == recovery.fresh.MANIFEST['storage_expected']


def plan_search(app, source):
    return rotation.plan_search_rotation(source, app.owner, source_pin=recovery.pin(source, 'ACTIVE'),
        keys=recovery.target_keys, target_keys=search_keys, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)


def stage(app, proposal, **options):
    return rotation.apply_search_rotation(proposal, app.owner, keys=recovery.target_keys,
        target_keys=search_keys, pin=payload.preparation_pin(proposal), approval=recovery.MAINTENANCE, **options)


def seal(app, proposal, **options):
    arguments = dict(keys=recovery.target_keys, target_keys=search_keys, pin=payload.preparation_pin(proposal),
        approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    arguments.update(options)
    return rotation.seal_search_rotation(proposal, app.owner, **arguments)


def switch_publish(app, proposal, activation):
    assert rotation.switch_search_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
        target_keys=search_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=search_keys, pin=recovery.pin(activation, 'ACTIVATING'),
        approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'


def test_partial_cancel_source_only_terminal_retry_after_edit_and_new_search(adopted, monkeypatch):
    app = adopted
    source = payload.active_source(app, aborted_rewrap=True)
    proposal = plan_search(app, source)
    original, storage, index = recovery.frame_bytes(app), labels(app), index_identity(app)
    assert stage(app, proposal, max_chunks=1).committed_rows == 3
    payload.assert_fenced(app)
    with monkeypatch.context() as patch:
        patch.setattr(PublicSearchProvider, 'unwrap', lambda *args: pytest.fail('abort requested target custody'))
        assert rotation.abort_search_rotation(proposal, app.owner, keys=recovery.target_keys,
            source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.frame_bytes(app) == original and labels(app) == storage and index_identity(app) == index
    assert m.check_deployment(source, app.owner, pin=recovery.pin(source, 'ACTIVE')) is None
    recovery.current_edit(app, source, recovery.target_keys, 'latest after canceled search')
    edited = recovery.snapshot(app)
    assert rotation.abort_search_rotation(proposal, app.owner, keys=recovery.target_keys,
        source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.snapshot(app) == edited
    healthy = plan_search(app, source)
    assert stage(app, healthy).phase == 'BACKFILLED'
    activation = seal(app, healthy)
    switch_publish(app, healthy, activation)
    recovery.current_edit(app, activation, search_keys, 'healthy after canceled search')


@pytest.mark.parametrize('fault', ['pin', 'source_policy', 'retained_generation', 'guard', 'sealed_target'])
def test_adopted_search_refusals_preserve_source_shadows_fence_and_recover(adopted, fault):
    app = adopted
    source = payload.active_source(app)
    proposal = plan_search(app, source)
    original, storage, index = recovery.frame_bytes(app), labels(app), index_identity(app)
    assert stage(app, proposal).phase == 'BACKFILLED'
    activation = seal(app, proposal)
    fields = source.document['lock']['models'][0]['fields']
    position = next(i for i, field in enumerate(fields) if field['column'] == 'name')
    field = fields[position]
    shadow = field['payload_column'] + '_rotation'
    previous = payload.shadows(app, proposal)[UUID(int=101)][position]
    guard = '_cryptalis_' + proposal.operation_id.hex + '_pause'
    with app.owner.begin() as connection:
        if fault == 'guard':
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DISABLE TRIGGER "{guard}"')
        elif fault in ('retained_generation', 'sealed_target'):
            replacement = original[UUID(int=101)]
            if fault == 'sealed_target':
                descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
                replacement = seal_text('edited while protected', descriptor, recovery.fresh.TENANT, UUID(int=101),
                                        search_keys(recovery.fresh.TENANT).prepare())
                assert replacement != previous and replacement[10:46] == previous[10:46]
            connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{shadow}"=%s WHERE id=%s',
                                      (replacement, UUID(int=101)))
    changed = payload.staged_snapshot(app, proposal)
    with pytest.raises((m.TransitionFailure, CryptoFailure)):
        if fault == 'sealed_target':
            rotation.switch_search_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
                target_keys=search_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
        else:
            seal(app, proposal, pin=replace(payload.preparation_pin(proposal), plan_digest='0' * 64)
                 if fault == 'pin' else payload.preparation_pin(proposal),
                 keys=recovery.fresh.keys if fault == 'source_policy' else recovery.target_keys)
    assert payload.staged_snapshot(app, proposal) == changed
    assert recovery.frame_bytes(app) == original and labels(app) == storage and index_identity(app) == index
    with app.owner.begin() as connection:
        if fault == 'guard':
            connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ENABLE ALWAYS TRIGGER "{guard}"')
        elif fault in ('retained_generation', 'sealed_target'):
            connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{shadow}"=%s WHERE id=%s',
                                      (previous, UUID(int=101)))
    payload.assert_fenced(app)
    assert seal(app, proposal).artifact == activation.artifact
    switch_publish(app, proposal, activation)
    recovery.current_edit(app, activation, search_keys, 'recovered adopted search')


def test_injected_search_collision_native_unique_copy_rolls_back_then_source_abort(adopted, monkeypatch):
    app = adopted
    source = payload.active_source(app)
    original, storage, index = recovery.frame_bytes(app), labels(app), index_identity(app)
    actual = cf1._term
    def collide(encoded, field, material):
        if material.context.purpose == 'search' and material.context.generation == 2:
            return b'c' * 32
        return actual(encoded, field, material)
    with monkeypatch.context() as patch:
        patch.setattr(cf1, '_term', collide)
        proposal = plan_search(app, source)
        assert stage(app, proposal).phase == 'BACKFILLED'
        activation = seal(app, proposal)
        before = payload.staged_snapshot(app, proposal)
        with pytest.raises(m.TransitionFailure) as refused:
            rotation.switch_search_rotation(proposal, activation, app.owner, keys=recovery.target_keys,
                target_keys=search_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
        assert refused.value.sqlstate == '23505'
        assert payload.staged_snapshot(app, proposal) == before
        assert recovery.frame_bytes(app) == original and labels(app) == storage and index_identity(app) == index
        payload.assert_fenced(app)
    assert rotation.abort_search_rotation(proposal, app.owner, keys=recovery.target_keys,
        source_pin=recovery.pin(source, 'ACTIVE'), approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert m.check_deployment(source, app.owner, pin=recovery.pin(source, 'ACTIVE')) is None


# Reuse the committed-chunk protocol with the adopted source/target fixture resolvers.
_SEARCH_WORKER = payload._PAYLOAD_WORKER.replace('PayloadRotationPlan', 'SearchRotationPlan').replace(
    'payload_rotation', 'search_rotation').replace(
    'from smolink_fresh_cluster import rotated_keys as target_keys',
    'from test_adopted_search import search_keys as target_keys')


def test_committed_search_chunk_sigkill_fresh_status_resume_preserves_prefix(adopted, tmp_path):
    app = adopted
    source = payload.active_source(app)
    proposal = plan_search(app, source)
    original, storage, index = recovery.frame_bytes(app), labels(app), index_identity(app)
    paths = [tmp_path / name for name in ('search.json', 'pin.json', 'approval.json')]
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_text(json.dumps(asdict(payload.preparation_pin(proposal)), default=str))
    paths[2].write_text(json.dumps(asdict(recovery.MAINTENANCE)))
    command = [sys.executable, '-B', '-c', _SEARCH_WORKER, str(Path(__file__).parent), *map(str, paths)]
    child = subprocess.Popen(command + ['chunk', 'pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=30), 'search worker did not report committed chunk'
        first = json.loads(child.stdout.readline())
        assert first == {'phase': 'EXPANDED', 'rows': 3, 'chunks': 1,
                         'operation_id': str(proposal.operation_id), 'digest': proposal.digest}
        prefix = payload.shadows(app, proposal)
        child.kill()
        child.communicate(timeout=20)
        assert child.returncode == -signal.SIGKILL
        committed = payload.staged_snapshot(app, proposal)
        inspected = subprocess.run(command + ['status', 'exit'], capture_output=True, text=True, timeout=45)
        assert inspected.returncode == 0, 'fresh search status failed; diagnostics suppressed'
        assert json.loads(inspected.stdout) == first
        assert payload.staged_snapshot(app, proposal) == committed
        resumed = subprocess.run(command + ['resume', 'exit'], capture_output=True, text=True, timeout=45)
        assert resumed.returncode == 0, 'fresh search resume failed; diagnostics suppressed'
        report = json.loads(resumed.stdout)
        assert report['phase'] == 'BACKFILLED' and report['rows'] == len(original)
        assert report['operation_id'] == str(proposal.operation_id) and report['digest'] == proposal.digest
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
            assert payload.shadows(app, proposal)[identity] == prefix[identity]
        assert recovery.frame_bytes(app) == original and labels(app) == storage and index_identity(app) == index
        assert paths[0].read_bytes() == proposal.artifact
        switch_publish(app, proposal, seal(app, proposal))
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


def test_real_lost_search_cutover_commit_reply_target_only_retry(adopted):
    app = adopted
    source = payload.active_source(app)
    proposal = plan_search(app, source)
    storage, index = labels(app), index_identity(app)
    assert stage(app, proposal).phase == 'BACKFILLED'
    activation = seal(app, proposal)
    fields = proposal.source.document['lock']['models'][0]['fields']
    position = next(i for i, field in enumerate(fields) if field['column'] == 'name')
    sealed = {identity: values[position] for identity, values in payload.shadows(app, proposal).items()}
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
        proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                               creator=lambda: psycopg.connect(url, connect_timeout=5))
        try:
            with pytest.raises(m.TransitionFailure):
                rotation.switch_search_rotation(proposal, activation, proxied, keys=recovery.target_keys,
                    target_keys=search_keys, pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
            assert dropped.wait(5), 'proxy did not discard the committed cutover reply'
        finally:
            proxied.dispose()
    assert m.status(activation, app.owner, pin=recovery.pin(activation, 'PENDING')).phase == 'PENDING'
    committed = recovery.snapshot(app)
    def forbidden(tenant): pytest.fail('committed cutover retry requested old source custody')
    assert rotation.switch_search_rotation(proposal, activation, app.owner, keys=forbidden,
        target_keys=search_keys, pin=recovery.pin(activation, 'PENDING'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert recovery.snapshot(app) == committed
    assert recovery.frame_bytes(app) == sealed and labels(app) == storage and index_identity(app) == index
    assert m.apply(activation, app.owner, keys=search_keys, pin=recovery.pin(activation, 'ACTIVATING'),
        approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'


def malformed_and_previous_reader_refuse(proposal, activation, directory):
    for fault in ('missing', 'empty', 'duplicate', 'target', 'probe', 'downgrade'):
        document = activation.document
        if fault == 'missing': document.pop('restore_lineage')
        elif fault == 'empty': document['restore_lineage'] = []
        elif fault == 'duplicate': document['restore_lineage'] *= 2
        elif fault == 'target': document['target'][3] += 1
        elif fault == 'probe': document['restore_lineage'][0]['restatements'][0].pop('probe')
        else: document['format'] = 'cryptalis.transition/v4'
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(document))
    assert rotation.SearchRotationPlan(proposal.artifact).artifact == proposal.artifact
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    paths = directory / 'search.json', directory / 'activation.json'
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_bytes(activation.artifact)
    interpreter = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    assert interpreter, 'set CRYPTALIS_PREVIOUS_READER_PYTHON to the retained previous payload wheel'
    script = r'''
import json, pathlib, sys
import cryptalis, psycopg
from cryptalis import migration as m, rotation
assert pathlib.Path(cryptalis.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
calls = []
def forbidden(*args, **kwargs):
    calls.append(True)
    raise AssertionError('previous reader attempted a database connection')
psycopg.connect = forbidden
for constructor, path in ((rotation.SearchRotationPlan, sys.argv[2]), (m.MigrationPlan, sys.argv[3])):
    try:
        constructor(pathlib.Path(path).read_bytes())
    except m.TransitionFailure:
        pass
    else:
        raise AssertionError('previous reader accepted adopted search artifact')
assert calls == []
print(json.dumps({'search': 'REFUSED', 'activation': 'REFUSED', 'database_calls': 0, 'installed_previous_reader': True}))
'''
    environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
    child = subprocess.run([interpreter, '-I', '-c', script, str(Path(interpreter).parent.parent), *map(str, paths)],
        env=environment, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, 'previous installed reader failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'search': 'REFUSED', 'activation': 'REFUSED',
        'database_calls': 0, 'installed_previous_reader': True}
