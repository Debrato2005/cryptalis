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
from uuid import UUID, uuid5

import psycopg
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cryptalis import migration as m, deprotection as d, restore as recovery, rotation
from cryptalis.crypto import KeyContext, Keyring
from cryptalis.crypto.keys import KeyUnavailable, WrappedRoot
from rewrap_worker import PublicRewrapProvider
from payload_rotation_worker import PublicPayloadProvider
from cryptalis.sqlalchemy import attach
from test_smolink_application import (snapshot, settings, redis_server, native_engine, TABLE)
from smolink_workload import workflow, restart_without_cryptalis
from smolink_fresh_cluster import catalog, rotated_keys
from test_cli import _run_cli
from test_doctor_cli import checks, doctor_arguments, doctor_inputs

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run the --smolink fresh-cluster profile', allow_module_level=True)



ADOPTED_PROVIDER = UUID(int=19501)
ADOPTED_WRAPPER = b'PUBLIC SMOLINK ADOPTED REWRAP WRAPPER'
ADOPTED_PAYLOAD_PROVIDER = UUID(int=19502)
ADOPTED_PAYLOAD_WRAPPER = b'PUBLIC SMOLINK ADOPTED PAYLOAD3 WRAPPER'


class PublicAdoptedProvider:
    """Public custody fixture for every retained Smolink source context."""
    provider_id = ADOPTED_PROVIDER

    def unwrap(self, wrapper, context):
        if (not isinstance(wrapper, WrappedRoot) or wrapper.provider_id != self.provider_id
                or wrapper.context != context or wrapper.sealed != ADOPTED_WRAPPER):
            raise KeyUnavailable()
        source = rotated_keys(context.tenant_id)
        originals = [item for item in source.policy.wrappers if item.context == context]
        if len(originals) != 1:
            raise KeyUnavailable()
        providers = (PublicRewrapProvider(), PublicPayloadProvider())
        provider = next((item for item in providers if item.provider_id == originals[0].provider_id), None)
        if provider is None:
            raise KeyUnavailable()
        return provider.unwrap(originals[0], context)

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def adopted_keys(tenant):
    source = rotated_keys(tenant)
    provider = PublicAdoptedProvider()
    wrappers = tuple(WrappedRoot(provider.provider_id, item.context, ADOPTED_WRAPPER)
                     for item in source.policy.wrappers)
    return Keyring(replace(source.policy, wrappers=wrappers), {provider.provider_id: provider})


def adopted_payload_context(tenant):
    return KeyContext(rotated_keys(tenant).policy.domain_id, tenant, 'payload',
                      uuid5(ADOPTED_PAYLOAD_PROVIDER, f'payload3:{tenant}'), 3)


class PublicAdoptedPayloadProvider:
    """Independent public generation-three root; retained roots use adopted custody."""
    provider_id = ADOPTED_PAYLOAD_PROVIDER

    def unwrap(self, wrapper, context):
        if (not isinstance(context, KeyContext) or not isinstance(wrapper, WrappedRoot)
                or context != adopted_payload_context(context.tenant_id)
                or wrapper.provider_id != self.provider_id or wrapper.context != context
                or wrapper.sealed != ADOPTED_PAYLOAD_WRAPPER):
            raise KeyUnavailable()
        return hashlib.sha256(b'PUBLIC SMOLINK ADOPTED PAYLOAD3 ROOT' + context.tenant_id.bytes
                              + context.generation.to_bytes(4, 'big')).digest()

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def adopted_payload_keys(tenant):
    source = adopted_keys(tenant)
    provider = PublicAdoptedPayloadProvider()
    wrapper = WrappedRoot(provider.provider_id, adopted_payload_context(tenant), ADOPTED_PAYLOAD_WRAPPER)
    return Keyring(replace(source.policy, wrappers=source.policy.wrappers + (wrapper,), payload_generation=3),
                   {ADOPTED_PROVIDER: PublicAdoptedProvider(), provider.provider_id: provider})


def protected_storage(owner):
    with owner.connect() as connection:
        frames = {identity: bytes(frame) for identity, frame in
                  connection.exec_driver_sql('SELECT id,destination FROM urls ORDER BY id')}
        indexes = {name: (identity, node) for name, identity, node in connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
            "JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid WHERE i.indrelid='urls'::regclass")}
    assert frames and indexes
    return frames, indexes


def operation_pin(plan, phase):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


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

            original_source, original_pin = source, pin
            before = protected_storage(owner)
            original_policy, target_policy = rotated_keys(TABLE).policy, adopted_keys(TABLE).policy
            assert original_policy.payload_generation == target_policy.payload_generation == 2
            assert original_policy.search_generation == target_policy.search_generation
            assert {item.context for item in original_policy.wrappers} == {
                item.context for item in target_policy.wrappers}
            assert len(original_policy.wrappers) == 3  # Retained payload1/search1 plus selected payload2.
            canceled = rotation.plan_rewrap(source, owner, source_pin=pin, keys=rotated_keys,
                target_keys=adopted_keys, verify_rows_per_second=1000, restore=binding)
            assert rotation.apply_rewrap(canceled, owner, keys=rotated_keys, target_keys=adopted_keys,
                pin=operation_pin(canceled.activation_plan, 'PREPARED'), approval=maintenance).phase == 'PENDING'
            assert protected_storage(owner) == before
            with monkeypatch.context() as patch:
                patch.setattr(PublicAdoptedProvider, 'unwrap',
                    lambda *args: pytest.fail('adopted cancellation required target custody'))
                assert rotation.abort_rewrap(canceled, owner, keys=rotated_keys, pin=pin,
                                             approval=maintenance).phase == 'ABORTED'
            assert protected_storage(owner) == before
            assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
            with pytest.raises(m.TransitionFailure):
                m.apply(canceled.activation_plan, owner, keys=adopted_keys,
                    pin=operation_pin(canceled.activation_plan, 'ACTIVATING'), approval=maintenance, until='ACTIVE')
            adopted_rewrap = rotation.plan_rewrap(source, owner, source_pin=pin, keys=rotated_keys,
                target_keys=adopted_keys, verify_rows_per_second=1000, restore=binding)
            successor = adopted_rewrap.activation_plan
            assert successor.document['format'] == 'cryptalis.transition/v5'
            assert successor.document['restore_lineage'] == [binding.document]
            assert rotation.apply_rewrap(adopted_rewrap, owner, keys=rotated_keys, target_keys=adopted_keys,
                pin=operation_pin(successor, 'PREPARED'), approval=maintenance).phase == 'PENDING'
            assert protected_storage(owner) == before
            with pytest.raises(m.TransitionFailure):
                m.check_deployment(original_source, owner, pin=original_pin, restore=binding)
            assert m.apply(successor, owner, keys=adopted_keys, pin=operation_pin(successor, 'ACTIVATING'),
                           approval=maintenance, until='ACTIVE').phase == 'ACTIVE'
            assert protected_storage(owner) == before
            source, pin = successor, operation_pin(successor, 'ACTIVE')
            assert m.check_deployment(source, owner, pin=pin) is None

            payload_policy = adopted_payload_keys(TABLE).policy
            assert target_policy.payload_generation == 2 and len(target_policy.wrappers) == 3
            assert payload_policy.payload_generation == 3 and len(payload_policy.wrappers) == 4
            assert payload_policy.wrappers[:-1] == target_policy.wrappers
            assert payload_policy.wrappers[-1].context not in {item.context for item in target_policy.wrappers}
            assert payload_policy.search_generation == target_policy.search_generation
            adopted_payload = rotation.plan_payload_rotation(source, owner, source_pin=pin, keys=adopted_keys,
                target_keys=adopted_payload_keys, backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
            prep_pin = m.DeploymentPin(source.target_id, adopted_payload.operation_id, adopted_payload.digest, 'PREPARED')
            assert rotation.apply_payload_rotation(adopted_payload, owner, keys=adopted_keys,
                target_keys=adopted_payload_keys, pin=prep_pin, approval=maintenance).phase == 'BACKFILLED'
            assert protected_storage(owner) == before
            payload_activation = rotation.seal_payload_rotation(adopted_payload, owner, keys=adopted_keys,
                target_keys=adopted_payload_keys, pin=prep_pin, approval=maintenance,
                copy_rows_per_second=1000, copy_wal_bytes_per_row=3000)
            assert payload_activation.document['format'] == 'cryptalis.transition/v6'
            assert payload_activation.document['kind'] == 'payload_rotation'
            assert payload_activation.document['restore_lineage'] == successor.document['restore_lineage']
            assert rotation.switch_payload_rotation(adopted_payload, payload_activation, owner, keys=adopted_keys,
                target_keys=adopted_payload_keys, pin=operation_pin(payload_activation, 'PREPARED'),
                approval=maintenance).phase == 'PENDING'
            payload_frames, payload_indexes = protected_storage(owner)
            assert payload_indexes == before[1] and payload_frames.keys() == before[0].keys()
            assert all(int.from_bytes(body[6:10], 'big') == 3 and body[14:] != before[0][identity][14:]
                       and body[10:14] == before[0][identity][10:14] for identity, body in payload_frames.items())
            assert m.apply(payload_activation, owner, keys=adopted_payload_keys,
                pin=operation_pin(payload_activation, 'ACTIVATING'), approval=maintenance,
                until='ACTIVE').phase == 'ACTIVE'
            assert protected_storage(owner) == (payload_frames, payload_indexes)
            source, pin = payload_activation, operation_pin(payload_activation, 'ACTIVE')
            assert m.check_deployment(source, owner, pin=pin) is None

            async def current_workload():
                try:
                    sessions = await attach(Base.registry, runtime, lock=source.lock_bytes, keys=adopted_payload_keys,
                                            deployment=(source, pin))
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
            reverse = d.plan(source, owner, source_pin=pin, keys=adopted_payload_keys,
                plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
            reverse_pin = m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, 'PREPARED')
            consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                          'public fixture retained backup and latest restored application values')
            assert d.apply(reverse, owner, keys=adopted_payload_keys, pin=reverse_pin, approval=maintenance,
                           consent=consent).phase == 'PLAINTEXT_PENDING'
            assert d.apply(reverse, owner, keys=adopted_payload_keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
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
                'rotations': manifest['rotations'] + ['adopted_rewrap_cancel', 'adopted_rewrap', 'adopted_payload_rotation'],
                'source_plan_digest': original_source.digest, 'active_plan_digest': source.digest,
                'adopted_rewrap': {'plan_digest': adopted_rewrap.digest,
                    'canceled_plan_digest': canceled.digest, 'frame_and_index_identity_preserved': True,
                    'retained_contexts': len(target_policy.wrappers), 'payload_generation': target_policy.payload_generation},
                'adopted_payload': {'plan_digest': adopted_payload.digest,
                    'activation_plan_digest': payload_activation.digest, 'source_plan_digest': successor.digest,
                    'retained_contexts': len(payload_policy.wrappers), 'source_payload_generation': 2,
                    'payload_generation': payload_policy.payload_generation, 'search_generation': payload_policy.search_generation,
                    'frame_payload_bytes_changed': True, 'index_identity_preserved': True,
                    'restore_lineage_preserved': True},
                'restore_adoption_id': binding.document['adoption_id'], 'doctor_runtime_deployment': 'PASS',
                'journey': 'native baseline; interrupted protect/resume; rewrap; payload rotation; original protected CRUD; '
                           'fresh-cluster restore/adoption; root-rewrap cancellation; new root rewrap/v5 publication; '
                           'adopted payload generation 2 to 3/v6 publication; '
                           'original async CRUD and latest edit; decryptback/remove; Cryptalis-denied original restart',
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
