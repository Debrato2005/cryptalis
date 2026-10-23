"""Generation rotation uses explicit adoption authority without prior rewrap."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from types import SimpleNamespace

import psycopg
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine

from cryptalis import cli, restore
from cryptalis.crypto import CryptoFailure, Keyring, seal_text
from payload_rotation_worker import PublicPayloadProvider
from search_rotation_worker import PublicSearchProvider
from migration_commit_proxy import lost_commit_reply
from test_cli import _run_cli
from test_status_cli import arguments
from test_fresh_cluster_export import dump, environment as dump_environment
import test_adopted_payload as paused
from uuid import UUID

import pytest

from cryptalis import migration as m, rotation
from cryptalis.crypto import FieldDescriptor, open_text
from payload_rotation_worker import target_keys as payload_keys
from search_rotation_worker import target_keys as search_keys
import test_adopted_rewrap as recovery
import test_adopted_search as mixed
import test_payload_rotation_execution as execution

adopted = recovery.adopted


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_adopted_generation_current_values_to_native_exit(adopted, purpose, tmp_path):
    app = adopted
    source, source_pin, binding = app.source, app.source_pin, app.binding
    target = payload_keys if purpose == 'payload' else search_keys
    planner = getattr(rotation, 'plan_' + purpose + '_rotation')
    constructor = getattr(rotation, purpose.capitalize() + 'RotationPlan')
    apply = getattr(rotation, 'apply_' + purpose + '_rotation')
    seal = getattr(rotation, 'seal_' + purpose + '_rotation')
    switch = getattr(rotation, 'switch_' + purpose + '_rotation')
    before = recovery.snapshot(app)
    original, storage, index = recovery.frame_bytes(app), mixed.labels(app), mixed.index_identity(app)
    source_bytes, binding_bytes = source.artifact, binding.artifact
    proposal = planner(source, app.owner, source_pin=source_pin, restore=binding,
        keys=recovery.fresh.keys, target_keys=target, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
        max_batch_rows=3)
    assert recovery.snapshot(app) == before
    assert source.artifact == source_bytes and binding.artifact == binding_bytes
    assert proposal.source.artifact == source_bytes
    assert proposal.document['format'] == 'cryptalis.' + purpose + '-rotation/v2'
    assert proposal.document['restore'] == binding.document
    assert proposal.restore_binding.artifact == binding_bytes
    assert constructor(proposal.artifact).artifact == proposal.artifact
    prep = m.DeploymentPin(source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    options = dict(keys=recovery.fresh.keys, target_keys=target, pin=prep, approval=recovery.MAINTENANCE)
    first = apply(proposal, app.owner, max_chunks=1, **options)
    assert (first.phase, first.committed_rows, first.committed_chunks) == ('EXPANDED', 3, 1)
    view = SimpleNamespace(owner=app.owner, schema=recovery.fresh.SCHEMA)
    prefix = execution.staged_frames(view, proposal)
    assert recovery.frame_bytes(app) == original and mixed.labels(app) == storage
    assert mixed.index_identity(app) == index
    assert apply(constructor(proposal.artifact), app.owner, **options).phase == 'BACKFILLED'
    complete = execution.staged_frames(view, proposal)
    for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
        assert complete[identity] == prefix[identity]
    fields = source.document['lock']['models'][0]['fields']
    material = target(recovery.fresh.TENANT).prepare()
    for identity, frames in complete.items():
        for field, frame in zip(fields, frames, strict=True):
            column = field['column']
            old = original[identity] if column == 'name' else storage[identity]
            expected = (recovery.fresh.MANIFEST['expected'][str(identity)][1] if column == 'name'
                        else recovery.fresh.MANIFEST['storage_expected'][str(identity)])
            descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
            assert open_text(frame, descriptor, recovery.fresh.TENANT, identity, material) == expected
            if frame is None:
                assert old is None
            elif purpose == 'payload':
                assert int.from_bytes(frame[6:10], 'big') == 2 and frame != old
                if column == 'name':
                    assert frame[10:46] == old[10:46]
            elif column == 'label':
                assert frame == old
            else:
                assert frame[:10] == old[:10] and int.from_bytes(frame[10:14], 'big') == 2
                assert frame[14:46] != old[14:46] and frame[46:58] != old[46:58]
    staged = recovery.snapshot(app), complete
    activation = seal(proposal, app.owner, copy_rows_per_second=1000.5,
                      copy_wal_bytes_per_row=2048, **options)
    assert activation.document['format'] == ('cryptalis.transition/v6' if purpose == 'payload'
                                             else 'cryptalis.transition/v7')
    assert activation.document['target'] == binding.document['target']
    assert activation.document['restore_lineage'] == [binding.document]
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    previous_reader(proposal, activation, tmp_path)
    assert seal(proposal, app.owner, copy_rows_per_second=1000.5,
                copy_wal_bytes_per_row=2048, **options).artifact == activation.artifact
    assert (recovery.snapshot(app), execution.staged_frames(view, proposal)) == staged
    assert switch(proposal, activation, app.owner, keys=recovery.fresh.keys, target_keys=target,
        pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    committed = recovery.snapshot(app)
    def forbidden(tenant):
        pytest.fail('committed direct switch retry requested original source custody')
    assert switch(proposal, activation, app.owner, keys=forbidden, target_keys=target,
        pin=recovery.pin(activation, 'PENDING'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert recovery.snapshot(app) == committed and mixed.index_identity(app) == index
    positions = {field['column']: i for i, field in enumerate(fields)}
    assert recovery.frame_bytes(app) == {identity: values[positions['name']] for identity, values in complete.items()}
    assert mixed.labels(app) == {identity: values[positions['label']] for identity, values in complete.items()}
    assert m.apply(activation, app.owner, keys=target, pin=recovery.pin(activation, 'ACTIVATING'),
        approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    with pytest.raises(m.TransitionFailure):
        m.check_deployment(source, app.owner, pin=source_pin, restore=binding)
    latest = 'latest after direct adopted ' + purpose
    recovery.current_edit(app, activation, target, latest)
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), latest]
    recovery.decrypt_remove_and_restart(app, activation, target, expected)
    with app.owner.connect() as connection:
        assert {str(identity): value for identity, value in connection.exec_driver_sql(
            f'SELECT id,label FROM "{recovery.fresh.SCHEMA}".customer')} == recovery.fresh.MANIFEST['storage_expected']


def target_keys(purpose):
    return payload_keys if purpose == 'payload' else search_keys


def prepare(app, purpose, **overrides):
    options = dict(source_pin=app.source_pin, restore=app.binding, keys=recovery.fresh.keys,
        target_keys=target_keys(purpose), backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    options.update(overrides)
    return getattr(rotation, 'plan_' + purpose + '_rotation')(app.source, app.owner, **options)


def prep_pin(proposal):
    return m.DeploymentPin(proposal.source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')


def stage(app, proposal, **options):
    return getattr(rotation, 'apply_' + proposal.purpose + '_rotation')(proposal, app.owner,
        keys=recovery.fresh.keys, target_keys=target_keys(proposal.purpose),
        pin=prep_pin(proposal), approval=recovery.MAINTENANCE, **options)


def seal(app, proposal):
    return getattr(rotation, 'seal_' + proposal.purpose + '_rotation')(proposal, app.owner,
        keys=recovery.fresh.keys, target_keys=target_keys(proposal.purpose), pin=prep_pin(proposal),
        approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)


def publish(app, proposal, activation):
    assert getattr(rotation, 'switch_' + proposal.purpose + '_rotation')(proposal, activation, app.owner,
        keys=recovery.fresh.keys, target_keys=target_keys(proposal.purpose),
        pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=target_keys(proposal.purpose),
        pin=recovery.pin(activation, 'ACTIVATING'), approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'


def staged(app, proposal):
    return recovery.snapshot(app), paused.shadows(app, proposal)


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('started', [False, True])
def test_direct_source_only_cancel_edit_terminal_retry_and_healthy_successor(adopted, purpose, started, monkeypatch):
    app = adopted
    proposal = prepare(app, purpose)
    original, storage, index = recovery.frame_bytes(app), mixed.labels(app), mixed.index_identity(app)
    if started:
        assert stage(app, proposal, max_chunks=1).committed_rows == 3
        paused.assert_fenced(app)
    abort = getattr(rotation, 'abort_' + purpose + '_rotation')
    provider = PublicPayloadProvider if purpose == 'payload' else PublicSearchProvider
    with monkeypatch.context() as patch:
        patch.setattr(provider, 'unwrap', lambda *args: pytest.fail('abort requested target custody'))
        assert abort(proposal, app.owner, keys=recovery.fresh.keys, source_pin=app.source_pin,
                     approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.frame_bytes(app) == original and mixed.labels(app) == storage and mixed.index_identity(app) == index
    assert m.check_deployment(app.source, app.owner, pin=app.source_pin, restore=app.binding) is None
    recovery.current_edit(app, app.source, recovery.fresh.keys, 'edited after direct cancellation', app.binding)
    edited = recovery.snapshot(app)
    with monkeypatch.context() as patch:
        patch.setattr(provider, 'unwrap', lambda *args: pytest.fail('terminal abort requested target custody'))
        assert abort(proposal, app.owner, keys=recovery.fresh.keys, source_pin=app.source_pin,
                     approval=recovery.MAINTENANCE).phase == 'ABORTED'
    assert recovery.snapshot(app) == edited
    healthy = prepare(app, purpose)
    assert stage(app, healthy).phase == 'BACKFILLED'
    activation = seal(app, healthy)
    publish(app, healthy, activation)
    recovery.current_edit(app, activation, target_keys(purpose), 'healthy after direct cancellation')


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_pure_authority_and_v2_parser_refusals_before_connection_or_keys(adopted, purpose):
    app = adopted
    proposal = prepare(app, purpose)
    constructor = getattr(rotation, purpose.capitalize() + 'RotationPlan')
    before = recovery.snapshot(app)
    calls = []
    class Closed:
        def connect(self):
            calls.append('connection')
            pytest.fail('invalid authority reached connection')
    def forbidden(tenant):
        calls.append('provider')
        pytest.fail('invalid authority reached keys')
    planner = getattr(rotation, 'plan_' + purpose + '_rotation')
    for fault in ('source', 'custody', 'probe', 'owner', 'pin'):
        document = app.binding.document
        source_pin = app.source_pin
        if fault == 'source': document['source']['plan_digest'] = '0' * 64
        elif fault == 'custody': document['custody'][str(recovery.fresh.TENANT)] = '0' * 64
        elif fault == 'probe':
            assert document['restatements']
            document['restatements'][0].pop('probe')
        elif fault == 'owner': document['target'][-1] = 'unplanned_owner'
        else: source_pin = replace(source_pin, plan_digest='0' * 64)
        binding = restore.RestoreBinding(m._canonical(document))
        with pytest.raises(m.TransitionFailure):
            planner(app.source, Closed(), source_pin=source_pin, restore=binding, keys=forbidden,
                target_keys=forbidden, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
    for fault in ('missing', 'null', 'v1', 'extra', 'journal', 'probe'):
        document = proposal.document
        if fault == 'missing': document.pop('restore')
        elif fault == 'null': document['restore'] = None
        elif fault == 'v1': document['format'] = constructor.format
        elif fault == 'extra': document['unexpected'] = True
        elif fault == 'journal': document['journal_state_digest'] = '0' * 64
        else: document['restore']['restatements'][0].pop('probe')
        with pytest.raises(m.TransitionFailure): constructor(m._canonical(document))
    assert calls == [] and recovery.snapshot(app) == before
    assert constructor(proposal.artifact).artifact == proposal.artifact


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_live_schema_guard_generation_and_seal_refusals_recover(adopted, purpose):
    app = adopted
    proposal = prepare(app, purpose)
    assert stage(app, proposal).phase == 'BACKFILLED'
    activation = seal(app, proposal)
    fields = app.source.document['lock']['models'][0]['fields']
    position = next(i for i, field in enumerate(fields) if field['column'] == 'name')
    field = fields[position]
    shadow, constraint = field['payload_column'] + '_rotation', field['payload_column'] + '_frame'
    guard = '_cryptalis_' + proposal.operation_id.hex + '_pause'
    original, storage, index = recovery.frame_bytes(app), mixed.labels(app), mixed.index_identity(app)
    previous = paused.shadows(app, proposal)[UUID(int=101)][position]
    for fault in ('check', 'guard', 'retained_generation', 'sealed_frame'):
        definition = None
        with app.owner.begin() as connection:
            if fault == 'check':
                definition = connection.exec_driver_sql('SELECT pg_catalog.pg_get_constraintdef(oid) '
                    'FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                    (f'"{recovery.fresh.SCHEMA}".customer', constraint)).scalar_one()
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" CHECK (octet_length(name)>=0)')
            elif fault == 'guard':
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DISABLE TRIGGER "{guard}"')
            else:
                replacement = original[UUID(int=101)]
                if fault == 'sealed_frame':
                    descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
                    replacement = seal_text('edited while protected', descriptor, recovery.fresh.TENANT, UUID(int=101),
                                            target_keys(purpose)(recovery.fresh.TENANT).prepare())
                    assert replacement != previous
                connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{shadow}"=%s WHERE id=%s',
                                          (replacement, UUID(int=101)))
        changed = staged(app, proposal)
        if fault in ('check', 'guard'):
            calls = []
            def forbidden(tenant):
                calls.append(tenant)
                pytest.fail('changed staged schema reached provider preparation')
            with pytest.raises(m.TransitionFailure):
                getattr(rotation, 'apply_' + purpose + '_rotation')(proposal, app.owner,
                    keys=forbidden, target_keys=forbidden, pin=prep_pin(proposal), approval=recovery.MAINTENANCE)
            assert calls == [] and staged(app, proposal) == changed
        with pytest.raises((m.TransitionFailure, CryptoFailure)):
            if fault == 'sealed_frame':
                getattr(rotation, 'switch_' + purpose + '_rotation')(proposal, activation, app.owner,
                    keys=recovery.fresh.keys, target_keys=target_keys(purpose),
                    pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
            else:
                seal(app, proposal)
        assert staged(app, proposal) == changed
        assert recovery.frame_bytes(app) == original and mixed.labels(app) == storage and mixed.index_identity(app) == index
        with app.owner.begin() as connection:
            if fault == 'check':
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" {definition}')
            elif fault == 'guard':
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ENABLE ALWAYS TRIGGER "{guard}"')
            else:
                connection.exec_driver_sql(f'UPDATE "{recovery.fresh.SCHEMA}".customer SET "{shadow}"=%s WHERE id=%s',
                                          (previous, UUID(int=101)))
        paused.assert_fenced(app)
        assert seal(app, proposal).artifact == activation.artifact
    publish(app, proposal, activation)


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_v2_cli_status_is_keyless_and_rejects_external_binding(adopted, purpose, tmp_path, monkeypatch, capsys):
    app = adopted
    proposal = prepare(app, purpose)
    paths = {name: tmp_path / (name + '.json') for name in ('plan', 'pin', 'database')}
    paths['plan'].write_bytes(proposal.artifact)
    paths['pin'].write_text(json.dumps(asdict(prep_pin(proposal)), default=str))
    paths['database'].write_text(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
    paths['database'].chmod(0o600)
    def forbidden(*args, **kwargs): pytest.fail('status requested provider keys')
    statements = []
    def collect(connection, cursor, statement, parameters, context, many): statements.append(statement)
    for phase in ('PREPARED', 'EXPANDED', 'BACKFILLED', 'ABORTED'):
        if phase == 'EXPANDED': stage(app, proposal, max_chunks=1)
        elif phase == 'BACKFILLED': stage(app, proposal)
        elif phase == 'ABORTED':
            getattr(rotation, 'abort_' + purpose + '_rotation')(proposal, app.owner,
                keys=recovery.fresh.keys, source_pin=app.source_pin, approval=recovery.MAINTENANCE)
        before = recovery.snapshot(app)
        with monkeypatch.context() as patch:
            patch.setattr(Keyring, 'prepare', forbidden)
            patch.setattr(Keyring, '_provider', forbidden)
            event.listen(Engine, 'before_cursor_execute', collect)
            try:
                assert cli.main(list(arguments(paths))) == 3
            finally:
                event.remove(Engine, 'before_cursor_execute', collect)
        captured = capsys.readouterr()
        assert captured.err == ''
        observed = json.loads(captured.out)
        assert observed['phase'] == phase and observed['scope'] == purpose + '_rotation_preparation'
        assert observed['source_operation_id'] == str(app.source.operation_id)
        assert observed['effects'] == 'NONE' and observed['authority'] == 'HOST_SUPPLIED_PIN'
        assert observed['verification'] == 'NOT_PERFORMED' and observed['runtime_metadata_matches'] is False
        assert observed['committed_rows'] == {'PREPARED': 0, 'EXPANDED': 3, 'BACKFILLED': len(recovery.frame_bytes(app)), 'ABORTED': len(recovery.frame_bytes(app))}[phase]
        assert recovery.snapshot(app) == before
    assert statements and all(statement.lstrip().split()[0].upper() in ('SELECT', 'SET') for statement in statements)
    result = _run_cli(*arguments(paths), '--restore-binding', str(tmp_path / 'must-not-be-read'))
    assert result.returncode == 2 and result.stdout == ''
    assert json.loads(result.stderr)['error']['code'] == 'InvalidInput'


# The existing public worker protocol uses original fixture custody on this route.
_DIRECT_WORKER = paused._PAYLOAD_WORKER.replace('from rewrap_worker import target_keys as keys',
    'from test_migration import keys').replace('from smolink_fresh_cluster import rotated_keys as target_keys',
    'from payload_rotation_worker import target_keys')


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_committed_chunk_sigkill_independent_status_resume(adopted, purpose, tmp_path):
    app = adopted
    proposal = prepare(app, purpose)
    worker = _DIRECT_WORKER
    if purpose == 'search':
        worker = worker.replace('PayloadRotationPlan', 'SearchRotationPlan').replace('payload_rotation', 'search_rotation')
    paths = [tmp_path / name for name in ('proposal.json', 'pin.json', 'approval.json')]
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_text(json.dumps(asdict(prep_pin(proposal)), default=str))
    paths[2].write_text(json.dumps(asdict(recovery.MAINTENANCE)))
    command = [sys.executable, '-B', '-c', worker, str(Path(__file__).parent), *map(str, paths)]
    child = subprocess.Popen(command + ['chunk', 'pause'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=30), 'direct worker did not report committed chunk'
        first = json.loads(child.stdout.readline())
        assert first == {'phase': 'EXPANDED', 'rows': 3, 'chunks': 1,
                         'operation_id': str(proposal.operation_id), 'digest': proposal.digest}
        prefix = paused.shadows(app, proposal)
        child.kill()
        child.communicate(timeout=20)
        assert child.returncode == -signal.SIGKILL
        committed = staged(app, proposal)
        status = subprocess.run(command + ['status', 'exit'], capture_output=True, text=True, timeout=45)
        assert status.returncode == 0, 'independent direct status failed; diagnostics suppressed'
        assert json.loads(status.stdout) == first and staged(app, proposal) == committed
        resumed = subprocess.run(command + ['resume', 'exit'], capture_output=True, text=True, timeout=45)
        assert resumed.returncode == 0, 'independent direct resume failed; diagnostics suppressed'
        report = json.loads(resumed.stdout)
        assert report['phase'] == 'BACKFILLED' and report['rows'] == len(recovery.frame_bytes(app))
        assert report['operation_id'] == str(proposal.operation_id) and report['digest'] == proposal.digest
        for identity in (UUID(int=100), UUID(int=101), UUID(int=102)):
            assert paused.shadows(app, proposal)[identity] == prefix[identity]
        assert paths[0].read_bytes() == proposal.artifact
        publish(app, proposal, seal(app, proposal))
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=20)


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_real_lost_cutover_commit_reply_target_only_recovery(adopted, purpose):
    app = adopted
    proposal = prepare(app, purpose)
    assert stage(app, proposal).phase == 'BACKFILLED'
    activation = seal(app, proposal)
    index = mixed.index_identity(app)
    with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'], commit_number=2) as (url, dropped):
        proxied = create_engine('postgresql+psycopg://', hide_parameters=True,
                               creator=lambda: psycopg.connect(url, connect_timeout=5))
        try:
            with pytest.raises(m.TransitionFailure):
                getattr(rotation, 'switch_' + purpose + '_rotation')(proposal, activation, proxied,
                    keys=recovery.fresh.keys, target_keys=target_keys(purpose),
                    pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE)
            assert dropped.wait(5), 'proxy did not discard the committed cutover reply'
        finally:
            proxied.dispose()
    assert m.status(activation, app.owner, pin=recovery.pin(activation, 'PENDING')).phase == 'PENDING'
    committed = recovery.snapshot(app)
    def forbidden(tenant): pytest.fail('committed cutover recovery requested old source custody')
    assert getattr(rotation, 'switch_' + purpose + '_rotation')(proposal, activation, app.owner,
        keys=forbidden, target_keys=target_keys(purpose), pin=recovery.pin(activation, 'PENDING'),
        approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert recovery.snapshot(app) == committed and mixed.index_identity(app) == index
    assert m.apply(activation, app.owner, keys=target_keys(purpose), pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'


def previous_reader(proposal, activation, directory):
    interpreter = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    assert interpreter, 'set CRYPTALIS_PREVIOUS_READER_PYTHON to unchanged installed previous 2df wheel'
    paths = directory / 'direct.json', directory / 'activation.json'
    paths[0].write_bytes(proposal.artifact)
    paths[1].write_bytes(activation.artifact)
    script = r'''
import json, pathlib, sys
import cryptalis, psycopg
from cryptalis import migration as m, rotation
assert pathlib.Path(cryptalis.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
calls = []
def forbidden(*args, **kwargs):
    calls.append(True)
    raise AssertionError('previous reader attempted database work')
psycopg.connect = forbidden
constructor = rotation.PayloadRotationPlan if sys.argv[2] == 'payload' else rotation.SearchRotationPlan
try:
    constructor(pathlib.Path(sys.argv[3]).read_bytes())
except m.TransitionFailure:
    pass
else:
    raise AssertionError('previous reader accepted v2 preparation')
raw = pathlib.Path(sys.argv[4]).read_bytes()
assert m.MigrationPlan(raw).artifact == raw
assert calls == []
print(json.dumps({'v2_preparation': 'REFUSED', 'existing_activation_format': 'ACCEPTED', 'database_calls': 0}))
'''
    env = {name: value for name, value in os.environ.items() if name != 'PYTHONPATH'}
    child = subprocess.run([interpreter, '-I', '-B', '-c', script, str(Path(interpreter).parent.parent),
        proposal.purpose, *map(str, paths)], env=env, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, 'previous installed reader control failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'v2_preparation': 'REFUSED', 'existing_activation_format': 'ACCEPTED', 'database_calls': 0}


def test_direct_second_real_adoption_extends_lineage_and_rotates_other_generation(adopted):
    app = adopted
    proposal = prepare(app, 'payload')
    assert stage(app, proposal).phase == 'BACKFILLED'
    first = seal(app, proposal)
    publish(app, proposal, first)
    recovery.current_edit(app, first, payload_keys, 'latest before second direct adoption')
    backup = recovery.fresh.WORKDIR / ('direct-v6-' + first.operation_id.hex + '.sql')
    dump(backup, recovery.fresh.SCHEMA, dump_environment('CRYPTALIS_TEST_DATABASE_URL'))
    original_copy = recovery.snapshot(app)
    owner = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**recovery.fresh.environment(
            'CRYPTALIS_TEST_DATABASE_URL', recovery.fresh.PLAIN_DATABASE)))
    runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**recovery.fresh.environment(
            'CRYPTALIS_TEST_RUNTIME_DATABASE_URL', recovery.fresh.PLAIN_DATABASE)))
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{recovery.fresh.SCHEMA}" CASCADE')
        recovery.fresh.restore(backup, 'CRYPTALIS_TEST_DATABASE_URL', recovery.fresh.PLAIN_DATABASE)
        binding = restore.plan(first, owner, pin=recovery.pin(first, 'ACTIVE'), keys=payload_keys,
            approval=restore.RestoreApproval('qualification host', 'authorize second protected fixture copy',
                'original app sessions stopped; both disposable copies remain quarantined', True))
        assert binding.target != binding.source_target
        assert binding.document['restatements'] == []  # Inherited CHECK admissions remain necessary.
        def combined_keys(tenant):
            return search_keys(tenant, source=payload_keys)
        second = rotation.plan_search_rotation(first, owner, source_pin=recovery.pin(first, 'ACTIVE'),
            restore=binding, keys=payload_keys, target_keys=combined_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
        options = dict(keys=payload_keys, target_keys=combined_keys, pin=prep_pin(second), approval=recovery.MAINTENANCE)
        assert rotation.apply_search_rotation(second, owner, **options).phase == 'BACKFILLED'
        activation = rotation.seal_search_rotation(second, owner, copy_rows_per_second=1000.5,
                                                   copy_wal_bytes_per_row=2048, **options)
        assert activation.document['restore_lineage'] == [app.binding.document, binding.document]
        assert activation.document['target'] == binding.target
        assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
        assert rotation.switch_search_rotation(second, activation, owner, keys=payload_keys, target_keys=combined_keys,
            pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
        assert m.apply(activation, owner, keys=combined_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                       approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
        restored = SimpleNamespace(owner=owner, runtime=runtime, source=first)
        recovery.current_edit(restored, activation, combined_keys, 'latest after second direct adoption')
        expected = dict(recovery.fresh.MANIFEST['expected'])
        expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest after second direct adoption']
        recovery.decrypt_remove_and_restart(restored, activation, combined_keys, expected)
        assert recovery.snapshot(app) == original_copy
    finally:
        runtime.dispose()
        owner.dispose()


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_apply_checks_restored_schema_and_staged_guard_before_resolvers(adopted, purpose):
    app = adopted
    proposal = prepare(app, purpose)
    field = next(field for field in app.source.document['lock']['models'][0]['fields'] if field['column'] == 'name')
    constraint = field['payload_column'] + '_frame'
    guard = '_cryptalis_' + proposal.operation_id.hex + '_pause'
    calls = []
    def forbidden(tenant):
        calls.append('forbidden')
        pytest.fail('changed restored schema reached key resolver')
    def source_keys(tenant):
        calls.append('source')
        return recovery.fresh.keys(tenant)
    def target(tenant):
        calls.append('target')
        return target_keys(purpose)(tenant)
    apply = getattr(rotation, 'apply_' + purpose + '_rotation')
    for phase in ('first_apply', 'staged_resume'):
        with app.owner.begin() as connection:
            if phase == 'first_apply':
                definition = connection.exec_driver_sql('SELECT pg_catalog.pg_get_constraintdef(oid) '
                    'FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                    (f'"{recovery.fresh.SCHEMA}".customer', constraint)).scalar_one()
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" CHECK (octet_length(name)>=0)')
            else:
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DISABLE TRIGGER "{guard}"')
        before = recovery.snapshot(app) if phase == 'first_apply' else staged(app, proposal)
        with pytest.raises(m.TransitionFailure):
            apply(proposal, app.owner, keys=forbidden, target_keys=forbidden,
                  pin=prep_pin(proposal), approval=recovery.MAINTENANCE)
        assert 'forbidden' not in calls
        assert (recovery.snapshot(app) if phase == 'first_apply' else staged(app, proposal)) == before
        with app.owner.begin() as connection:
            if phase == 'first_apply':
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer DROP CONSTRAINT "{constraint}"')
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ADD CONSTRAINT "{constraint}" {definition}')
            else:
                connection.exec_driver_sql(f'ALTER TABLE "{recovery.fresh.SCHEMA}".customer ENABLE ALWAYS TRIGGER "{guard}"')
        calls.clear()
        result = apply(proposal, app.owner, keys=source_keys, target_keys=target, pin=prep_pin(proposal),
            approval=recovery.MAINTENANCE, until='EXPANDED' if phase == 'first_apply' else 'BACKFILLED')
        assert result.phase == ('EXPANDED' if phase == 'first_apply' else 'BACKFILLED')
        assert 'source' in calls and 'target' in calls
    publish(app, proposal, seal(app, proposal))
