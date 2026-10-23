"""Public fixture artifacts joining the pinned Smolink app to fresh recovery."""
import base64
from dataclasses import asdict, replace
import json
from pathlib import Path
import selectors
import subprocess
import sys

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring
from cryptalis.crypto.keys import WrappedRoot
from test_fresh_cluster_export import dump, environment
from test_migration import keys
from rewrap_worker import PublicRewrapProvider, target_keys as rewrap_keys
from payload_rotation_worker import PublicPayloadProvider, target_context, TARGET_WRAPPER


def rotated_keys(tenant):
    """Keep the public rewrapped readers and add the existing public payload root."""
    old = rewrap_keys(tenant)
    rewrap, payload = PublicRewrapProvider(), PublicPayloadProvider()
    wrapper = WrappedRoot(payload.provider_id, target_context(tenant), TARGET_WRAPPER)
    return Keyring(replace(old.policy, wrappers=old.policy.wrappers + (wrapper,), payload_generation=2),
                   {rewrap.provider_id: rewrap, payload.provider_id: payload})


def catalog(owner):
    with owner.connect() as c:
        return {'columns': [list(row) for row in c.exec_driver_sql(
            "SELECT column_name,data_type,character_maximum_length,is_nullable,column_default "
            "FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='urls' "
            "ORDER BY column_name")],
            'constraints': [list(row) for row in c.exec_driver_sql(
                "SELECT conname,pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint "
                "WHERE conrelid='urls'::regclass ORDER BY conname")],
            'indexes': [list(row) for row in c.exec_driver_sql(
                "SELECT indexname,indexdef FROM pg_catalog.pg_indexes "
                "WHERE schemaname=current_schema() AND tablename='urls' ORDER BY indexname")]}


def export_plain(owner, schema, directory):
    dump(directory / 'plain.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
    with (directory / 'smolink-native-catalog.json').open('x') as stream:
        json.dump(catalog(owner), stream)


def interrupt_and_resume(proposal, owner, pin, approval, directory):
    path = directory / 'source-plan.json'
    path.write_bytes(proposal.artifact)
    worker = subprocess.Popen([sys.executable, str(Path(__file__).with_name('migration_worker.py')),
                               str(path), 'BACKFILLED', 'PREPARED', 'pause'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(worker.stdout, selectors.EVENT_READ)
            assert ready.select(60), 'migration child did not reach the committed checkpoint'
        assert worker.stdout.readline().strip() == 'BACKFILLED'
        worker.kill()
        assert worker.wait(timeout=10) < 0
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=10)
        worker.stdout.close()
    progress = m.status(proposal, owner, pin=pin)
    assert progress.phase == 'BACKFILLED' and progress.committed_rows > 0
    assert m.apply(proposal, owner, keys=keys, pin=pin, approval=approval).phase == 'PENDING'


def rotate(source, owner, pin, approval, directory):
    proposal = r.plan_rewrap(source, owner, source_pin=pin, keys=keys,
                              target_keys=rewrap_keys, verify_rows_per_second=1000)
    activation = proposal.activation_plan
    pin = m.DeploymentPin(activation.target_id, activation.operation_id, activation.digest, 'PREPARED')
    assert r.apply_rewrap(proposal, owner, keys=keys, target_keys=rewrap_keys,
                          pin=pin, approval=approval).phase == 'PENDING'
    assert m.apply(activation, owner, keys=rewrap_keys, pin=replace(pin, phase='ACTIVATING'),
                   approval=approval, until='ACTIVE').phase == 'ACTIVE'
    source, pin = activation, replace(pin, phase='ACTIVE')
    preparation = r.plan_payload_rotation(source, owner, source_pin=pin, keys=rewrap_keys,
        target_keys=rotated_keys, backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
    prep_pin = m.DeploymentPin(source.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
    assert r.apply_payload_rotation(preparation, owner, keys=rewrap_keys, target_keys=rotated_keys,
                                     pin=prep_pin, approval=approval).phase == 'BACKFILLED'
    activation = r.seal_payload_rotation(preparation, owner, keys=rewrap_keys, target_keys=rotated_keys,
        pin=prep_pin, approval=approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=3000)
    pin = m.DeploymentPin(activation.target_id, activation.operation_id, activation.digest, 'PREPARED')
    assert r.switch_payload_rotation(preparation, activation, owner, keys=rewrap_keys,
                                    target_keys=rotated_keys, pin=pin, approval=approval).phase == 'PENDING'
    assert m.apply(activation, owner, keys=rotated_keys, pin=replace(pin, phase='ACTIVATING'),
                   approval=approval, until='ACTIVE').phase == 'ACTIVE'
    for name, value in [('rewrap-plan', proposal), ('payload-plan', preparation), ('activation-plan', activation)]:
        (directory / (name + '.json')).write_bytes(value.artifact)
    return activation, replace(pin, phase='ACTIVE'), rotated_keys


def export_protected(owner, schema, proposal, pin, current, baseline, hashes, directory):
    import psycopg
    from test_smolink_application import REVISION
    values = psycopg.conninfo.conninfo_to_dict(__import__('os').environ['CRYPTALIS_TEST_DATABASE_URL'])
    with owner.connect() as c:
        role = c.exec_driver_sql('SELECT current_user').scalar_one()
        frames = c.exec_driver_sql('SELECT id,destination FROM urls ORDER BY id').all()
    assert frames and all(bytes(frame).startswith(b'CF1\0') for _, frame in frames)
    assert all(int.from_bytes(bytes(frame)[6:10], 'big') == 2 for _, frame in frames)
    dump(directory / 'protected.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
    manifest = {'application_profile': 'smolink', 'application_revision': REVISION,
        'application_source_sha256': hashes, 'schema': schema, 'database': values['dbname'],
        'owner_role': role, 'runtime_role': proposal.document['runtime_role'],
        'plan': base64.b64encode(proposal.artifact).decode(), 'pin': asdict(pin),
        'current': current, 'baseline': baseline,
        'expected': {str(item['id']): item['destination'] for item in (baseline, current)},
        'native_catalog': json.loads((directory / 'smolink-native-catalog.json').read_text()),
        'interruption': 'SIGKILL after child committed BACKFILLED; same source plan resumed',
        'rotations': ['rewrap', 'payload_rotation'], 'key_fixture': 'public deterministic fixture only',
        'gates': 'all seven UNKNOWN'}
    with (directory / 'restore-manifest.json').open('x') as stream:
        json.dump(manifest, stream, indent=2, default=str)
        stream.write('\n')
