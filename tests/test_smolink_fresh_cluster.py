"""The pinned original Smolink app resumes from a protected fresh-cluster dump."""
import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cryptalis import migration as m, deprotection as d, restore as recovery
from cryptalis.sqlalchemy import attach
from test_smolink_application import (snapshot, settings, redis_server, native_engine, TABLE)
from smolink_workload import workflow, restart_without_cryptalis
from smolink_fresh_cluster import catalog, rotated_keys
from test_cli import _run_cli
from test_doctor_cli import checks, doctor_arguments, doctor_inputs

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run the --smolink fresh-cluster profile', allow_module_level=True)


def restore_dump(directory):
    values = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
    env = dict(os.environ, PGHOST=values.get('host', ''), PGPORT=values.get('port', '5432'),
               PGUSER=values['user'], PGPASSWORD=values['password'], PGDATABASE=values['dbname'])
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(directory / 'protected.sql')],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'protected Smolink restore failed; diagnostics withheld'


def test_original_smolink_restores_current_values_and_removes_cryptalis(tmp_path, monkeypatch):
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'smolink'
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    values = manifest['pin']
    pin = m.DeploymentPin(UUID(values['target_id']), UUID(values['operation_id']), values['plan_digest'], values['phase'])
    assert source.document['format'] == 'cryptalis.transition/v3' and source.document['kind'] == 'payload_rotation'
    assert len(source.document['predecessors']) >= 3 and pin.phase == 'ACTIVE'
    backend, hashes = snapshot(os.environ['CRYPTALIS_SMOLINK_CHECKOUT'], tmp_path)
    assert hashes == manifest['application_source_sha256'] and len(hashes) == 38
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    restore_dump(directory)
    schema = manifest['schema']
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = None
    maintenance = m.MaintenanceApproval('source export finished and schema dropped; fresh copy excluded writers', 3600)
    try:
        with redis_server(tmp_path) as redis_url:
            settings(monkeypatch, redis_url)
            from app.main import app as api
            from app.core.redis import get_redis_client
            from app.db.base import Base
            from app.models.url import Url
            with owner.connect() as c:
                frames = c.exec_driver_sql('SELECT id,destination FROM urls ORDER BY id').all()
            assert {str(identity) for identity, _ in frames} == set(manifest['expected'])
            assert all(bytes(body).startswith(b'CF1\0') for _, body in frames)
            with pytest.raises(m.TransitionFailure):
                m.check_deployment(source, owner, pin=pin)
            binding = recovery.plan(source, owner, pin=pin, keys=rotated_keys,
                approval=recovery.RestoreApproval('qualification host', 'restore current Smolink protected copy',
                                                   'source schema dropped after retained export; fresh copy quarantined', True))
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                    options='-csearch_path=' + schema))
            doctor = doctor_inputs(SimpleNamespace(plan=source, pin=pin), tmp_path)
            # The existing helper supplies the same runtime role on this fresh target.
            binding_path = tmp_path / 'restore-binding.json'
            binding_path.write_bytes(binding.artifact)
            observed = _run_cli(*doctor_arguments(doctor), '--restore-binding', str(binding_path))
            assert observed.returncode == 0 and observed.stderr == ''
            checks(json.loads(observed.stdout), 'PASS')

            async def current_workload():
                try:
                    sessions = await attach(Base.registry, runtime, lock=source.lock_bytes, keys=rotated_keys,
                                            deployment=(source, pin, binding))
                    factory = lambda: sessions(tenant_id=TABLE, expire_on_commit=False)
                    async with factory() as session:
                        for identity, value in manifest['expected'].items():
                            assert (await session.get(Url, int(identity))).destination == value
                    current = await workflow(api, factory, 'restored-live', retained=manifest['current'])
                    # This is a new committed value after restoration and adoption.
                    async with factory() as session:
                        row = await session.get(Url, manifest['current']['id'])
                        row.destination = 'https://example.invalid/latest-after-fresh-restore'
                        await session.commit()
                        await session.refresh(row)
                        assert row.destination.endswith('/latest-after-fresh-restore')
                    await get_redis_client().flushdb()
                    return current
                finally:
                    await get_redis_client().aclose()
                    await runtime.dispose()
            current = asyncio.run(current_workload())
            reverse = d.plan(source, owner, source_pin=pin, keys=rotated_keys, restore=binding,
                plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
            reverse_pin = m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, 'PREPARED')
            consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                          'public fixture retained backup and latest restored application values')
            assert d.apply(reverse, owner, keys=rotated_keys, pin=reverse_pin, approval=maintenance,
                           consent=consent).phase == 'PLAINTEXT_PENDING'
            assert d.apply(reverse, owner, keys=rotated_keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
                approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
            removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                'original Smolink URL router restart with Cryptalis denied', 'public retained backup fixture', True)
            assert d.remove(reverse, owner, pin=replace(reverse_pin, phase='REMOVING'), approval=maintenance,
                            removal=removal, consent=consent).phase == 'REMOVED'
            assert d.check_removed(reverse, owner, pin=replace(reverse_pin, phase='REMOVED')) is None
            with owner.connect() as c:
                assert c.exec_driver_sql('SELECT destination FROM urls WHERE id=%s',
                    (manifest['current']['id'],)).scalar_one() == 'https://example.invalid/latest-after-fresh-restore'
                assert c.exec_driver_sql('SELECT destination FROM urls WHERE id=%s',
                    (current['id'],)).scalar_one() == current['destination']
            assert catalog(owner) == manifest['native_catalog']
            restart_without_cryptalis(backend, schema, current)
            assert hashes == {str(p.relative_to(backend)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted(backend.rglob('*.py'))}
            receipt = {'application_revision': manifest['application_revision'], 'application_source_sha256': hashes,
                'model_changes': [], 'query_changes': [], 'interruption': manifest['interruption'],
                'rotations': manifest['rotations'], 'source_plan_digest': source.digest,
                'restore_adoption_id': binding.document['adoption_id'], 'doctor_runtime_deployment': 'PASS',
                'journey': 'native baseline; interrupted protect/resume; rewrap; payload rotation; original protected CRUD; '
                           'fresh-cluster restore/adoption; original CRUD and latest edit; decryptback/remove; Cryptalis-denied original restart',
                'native_schema_constraints_indexes': 'matches pre-protection catalog',
                'profile': 'Url.destination storage-only; public short_code and protected ID lookups; real Redis',
                'key_custody': 'public deterministic fixture; external custody not qualified', 'gates': 'all seven UNKNOWN'}
            with (directory / 'smolink-journey-receipt.json').open('x') as stream:
                json.dump(receipt, stream, indent=2)
                stream.write('\n')
    finally:
        if runtime is not None:
            asyncio.run(runtime.dispose())
        owner.dispose()
        import sys
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
