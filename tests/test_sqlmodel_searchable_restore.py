"""Original searchable SQLModel CRUD continues after genuine fresh adoption."""
import base64
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import pytest

pytest.importorskip('sqlmodel', reason='optional pinned SQLModel searchable application')

from cryptalis import deprotection as d, migration as m, restore, rotation
from cryptalis.sqlmodel import attach
from rewrap_worker import target_keys as adopted_keys
from search_rotation_worker import target_keys as new_search_keys
from profile_sqlmodel_public_slots_application import restart as slot_restart
import test_sqlmodel_searchable_export as exported
from test_fresh_cluster_export import environment
from test_migration import keys

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run the --sqlmodel-searchable fresh-cluster profile', allow_module_level=True)


def search_keys(tenant):
    return new_search_keys(tenant, source=adopted_keys)


def restart(backend, schema, retained):
    script = r'''
import importlib.abc, json, os, pathlib, runpy, sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
sys.path[:0] = json.loads(os.environ['SQLMODEL_CHILD_PATHS'])
try:
    import cryptalis
except ImportError:
    pass
else:
    raise AssertionError('Cryptalis import guard did not refuse')
import psycopg
from sqlalchemy import create_engine
from sqlmodel import Session
namespace = runpy.run_path(os.environ['SQLMODEL_WORKLOAD_HELPER'])
engine = create_engine('postgresql+psycopg://', hide_parameters=True,
    creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
        options='-csearch_path=' + os.environ['SQLMODEL_SCHEMA'], connect_timeout=5))
try:
    namespace['workflow'](lambda: Session(engine, expire_on_commit=False),
        os.environ['SQLMODEL_CHILD_PHASE'], json.loads(os.environ['SQLMODEL_CURRENT']))
finally:
    engine.dispose()
for name, module in tuple(sys.modules.items()):
    if name == 'app' or name.startswith('app.'):
        origin = getattr(module, '__file__', None)
        if origin:
            assert pathlib.Path(origin).resolve().is_relative_to(pathlib.Path(os.environ['SQLMODEL_BACKEND']).resolve())
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print(json.dumps({'native_crud': 'passed', 'cryptalis_imported': False, 'original_app_origin': True}))
'''
    child = subprocess.run([sys.executable, '-I', '-B', '-c', script], capture_output=True, text=True,
        timeout=60, env=dict(os.environ, SQLMODEL_CHILD_PATHS=json.dumps(sys.path), SQLMODEL_SCHEMA=schema,
            SQLMODEL_BACKEND=str(backend), SQLMODEL_CURRENT=json.dumps(retained), SQLMODEL_CHILD_PHASE=uuid4().hex,
            SQLMODEL_WORKLOAD_HELPER=str(Path(__file__).with_name('sqlmodel_template_workload.py').resolve())))
    assert child.returncode == 0, 'package-free original SQLModel CRUD failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_crud': 'passed', 'cryptalis_imported': False, 'original_app_origin': True}


def test_original_searchable_app_fresh_adoption_search_rotation_and_latest_native_exit(tmp_path, monkeypatch):
    http = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_FRESH') == '1'
    slot_profile = os.environ.get('CRYPTALIS_SQLMODEL_PUBLIC_SLOTS') == '1'
    direct = (slot_profile and not http) or os.environ.get('CRYPTALIS_SQLMODEL_DIRECT_SEARCH') == '1'
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == ('sqlmodel-http' if http else 'sqlmodel-public-slots' if slot_profile else 'sqlmodel-searchable')
    assert manifest.get('sqlmodel_public_slots', False) is slot_profile
    backend, hashes, workflow = exported.app_copy(tmp_path, monkeypatch)
    assert hashes == manifest['application_source_sha256'] and len(hashes) == (26 if http else 6)
    workload_helper = Path(__file__).with_name('sqlmodel_template_workload.py').resolve()
    boolean_controls = runpy.run_path(str(workload_helper))['boolean_controls'] if slot_profile and not http else None
    from app.models import User
    from app import crud
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    raw = manifest['pin']
    source_pin = m.DeploymentPin(UUID(raw['target_id']), UUID(raw['operation_id']), raw['plan_digest'], raw['phase'])
    assert source_pin == exported.pin(source, 'ACTIVE')
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(directory / 'protected.sql')],
        env=environment('CRYPTALIS_TEST_DATABASE_URL'), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'protected SQLModel restore failed; diagnostics suppressed'
    schema = manifest['schema']
    owner = exported.original.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = exported.original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = User._sa_registry
    approval = m.MaintenanceApproval('source schema dropped; fresh restored copy quarantined and writers stopped', 3600)
    try:
        before = exported.storage(owner, boolean_storage=slot_profile)
        assert set(before[0]) == set(manifest['expected'])
        target_slots = exported.public_slots(owner, manifest['source_public_slots']) if slot_profile else None
        if slot_profile:
            assert target_slots.keys() == manifest['source_public_slots'].keys()
            for table, values in target_slots.items():
                assert list(values['order']) == manifest['source_public_slots'][table]['order']
            assert source.document['lock']['schema'] == 'cryptalis.lock/v6'
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=source_pin)
        if http:
            identity = UUID(manifest['current']['id'])
            frame = before[0][str(identity)][0]
            with owner.begin() as connection:
                connection.exec_driver_sql('UPDATE "user" SET email=%s WHERE id=%s',
                    (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
            try:
                with pytest.raises(m.TransitionFailure):
                    restore.plan(source, owner, pin=source_pin, keys=keys,
                        approval=restore.RestoreApproval('qualification host', 'refuse corrupted HTTP backup',
                            'source schema dropped; this copy is quarantined', True))
            finally:
                with owner.begin() as connection:
                    connection.exec_driver_sql('UPDATE "user" SET email=%s WHERE id=%s', (frame, identity))
        binding = restore.plan(source, owner, pin=source_pin, keys=keys,
            approval=restore.RestoreApproval('qualification host', 'recover pinned original searchable SQLModel app',
                'source schema dropped after export; this fresh restored copy is quarantined', True))
        assert m.diagnose_deployment(source, runtime, pin=source_pin, restore=binding) is None
        if slot_profile:
            assert binding.document['format'] == 'cryptalis.restore/v3'
            source_columns = dict(manifest['source_public_slots']['user']['columns'])
            target_columns = dict(target_slots['user']['columns'])
            model = source.document['lock']['models'][0]
            assert binding.document['columns'] == [{'model': model['table_id'], 'column': name,
                'source_attnum': number, 'target_attnum': target_columns[name]} for name, number in source_columns.items()]
            assert binding.document['sequences'] == []
        rewrap = None
        planner_options = {}
        current_source, current_pin, source_keys, target = source, source_pin, keys, new_search_keys
        if direct:
            planner_options['restore'] = binding
        else:
            rewrap = rotation.plan_rewrap(source, owner, source_pin=source_pin, keys=keys,
                target_keys=adopted_keys, verify_rows_per_second=1000, restore=binding)
            adopted = rewrap.activation_plan
            assert adopted.document['format'] == 'cryptalis.transition/v5'
            assert rotation.apply_rewrap(rewrap, owner, keys=keys, target_keys=adopted_keys,
                pin=exported.pin(adopted, 'PREPARED'), approval=approval).phase == 'PENDING'
            assert exported.storage(owner, boolean_storage=slot_profile) == before
            assert m.apply(adopted, owner, keys=adopted_keys, pin=exported.pin(adopted, 'ACTIVATING'),
                approval=approval, until='ACTIVE').phase == 'ACTIVE'
            with pytest.raises(m.TransitionFailure):
                m.check_deployment(source, owner, pin=source_pin, restore=binding)
            current_source, current_pin = adopted, exported.pin(adopted, 'ACTIVE')
            source_keys, target = adopted_keys, search_keys
        payload = None
        if http:
            from payload_rotation_worker import rotated_keys
            payload = rotation.plan_payload_rotation(current_source, owner, source_pin=current_pin,
                keys=source_keys, target_keys=rotated_keys, backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000,
                max_batch_rows=1)
            prepared = m.DeploymentPin(current_source.target_id, payload.operation_id, payload.digest, 'PREPARED')
            assert rotation.apply_payload_rotation(payload, owner, keys=source_keys, target_keys=rotated_keys,
                pin=prepared, approval=approval, max_chunks=1).committed_rows == 1
            assert rotation.apply_payload_rotation(payload, owner, keys=source_keys, target_keys=rotated_keys,
                pin=prepared, approval=approval).phase == 'BACKFILLED'
            assert exported.storage(owner, boolean_storage=True) == before
            successor = rotation.seal_payload_rotation(payload, owner, keys=source_keys, target_keys=rotated_keys,
                pin=prepared, approval=approval, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=3000)
            assert rotation.switch_payload_rotation(payload, successor, owner, keys=source_keys,
                target_keys=rotated_keys, pin=exported.pin(successor, 'PREPARED'), approval=approval).phase == 'PENDING'
            assert m.apply(successor, owner, keys=rotated_keys, pin=exported.pin(successor, 'ACTIVATING'),
                approval=approval, until='ACTIVE').phase == 'ACTIVE'
            after_payload = exported.storage(owner, boolean_storage=True)
            assert after_payload[1] == before[1]
            for identity, values in after_payload[0].items():
                for old, frame in zip(before[0][identity], values):
                    assert (old is None and frame is None) or (frame != old
                        and int.from_bytes(frame[6:10], 'big') == 2 and frame[10:14] == old[10:14])
            before = after_payload
            current_source, current_pin, source_keys = successor, exported.pin(successor, 'ACTIVE'), rotated_keys
            target = lambda tenant: new_search_keys(tenant, source=rotated_keys)
        proposal = rotation.plan_search_rotation(current_source, owner, source_pin=current_pin,
            keys=source_keys, target_keys=target, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000, max_batch_rows=1, **planner_options)
        if direct:
            assert proposal.document['format'] == 'cryptalis.search-rotation/v2'
            assert proposal.source.artifact == source.artifact and proposal.document['restore'] == binding.document
        prep = m.DeploymentPin(current_source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
        assert rotation.apply_search_rotation(proposal, owner, keys=source_keys, target_keys=target,
            pin=prep, approval=approval, max_chunks=1).committed_rows == 1
        assert rotation.apply_search_rotation(proposal, owner, keys=source_keys, target_keys=target,
            pin=prep, approval=approval).phase == 'BACKFILLED'
        assert exported.storage(owner, boolean_storage=slot_profile) == before
        activation = rotation.seal_search_rotation(proposal, owner, keys=source_keys, target_keys=target,
            pin=prep, approval=approval, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=3000)
        assert activation.document['format'] == 'cryptalis.transition/v7'
        assert activation.document['restore_lineage'] == [binding.document]
        assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
        assert rotation.switch_search_rotation(proposal, activation, owner, keys=source_keys, target_keys=target,
            pin=exported.pin(activation, 'PREPARED'), approval=approval).phase == 'PENDING'
        after = exported.storage(owner, boolean_storage=slot_profile)
        assert after[1] == before[1]
        for identity, values in after[0].items():
            email, name = values[:2]
            old_email, old_name = before[0][identity][:2]
            assert values[2:] == before[0][identity][2:]
            assert name == old_name
            assert email[:10] == old_email[:10] and int.from_bytes(email[10:14], 'big') == 2
            assert email[14:46] != old_email[14:46] and email[46:58] != old_email[46:58]
        assert m.apply(activation, owner, keys=target, pin=exported.pin(activation, 'ACTIVATING'),
            approval=approval, until='ACTIVE').phase == 'ACTIVE'
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=source_pin, restore=binding)
        assert m.diagnose_deployment(activation, runtime, pin=exported.pin(activation, 'ACTIVE')) is None
        if slot_profile:
            assert exported.public_slots(owner, manifest['source_public_slots']) == target_slots
            assert activation.document['lock']['schema'] == 'cryptalis.lock/v6'
        factory = attach(mapping, runtime, lock=activation.lock_bytes, keys=target,
                         deployment=(activation, exported.pin(activation, 'ACTIVE')))
        attached = lambda: factory(tenant_id=exported.original.TABLE, expire_on_commit=False)
        with attached() as session:
            for expected in manifest['expected'].values():
                row = crud.get_user_by_email(session=session, email=expected['email'])
                assert str(row.id) == expected['id'] and row.full_name == expected['full_name']
                if slot_profile:
                    assert row.is_active is expected['is_active']
        current = workflow(attached, uuid4().hex, manifest['current'])
        if boolean_controls:
            current = boolean_controls(attached, current, uuid4().hex)
        if slot_profile:
            assert exported.public_slots(owner, manifest['source_public_slots']) == target_slots
        current, controls = exported.search_controls(attached, current)
        assert controls == manifest['search_controls']
        runtime.dispose()
        reverse = d.plan(activation, owner, source_pin=exported.pin(activation, 'ACTIVE'), keys=target,
            plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'], backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                     'public fixture retained backup and latest original app values')
        assert d.apply(reverse, owner, keys=target, pin=exported.pin(reverse, 'PREPARED'),
            approval=approval, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=target, pin=exported.pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'original SQLModel CRUD restart with Cryptalis imports denied', 'public retained backup fixture only', True)
        assert d.remove(reverse, owner, pin=exported.pin(reverse, 'REMOVING'), approval=approval,
            removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=exported.pin(reverse, 'REMOVED')) is None
        assert exported.catalog(owner) == manifest['native_catalog']
        if slot_profile:
            assert exported.public_slots(owner) == target_slots
        with owner.connect() as connection:
            columns = 'email,full_name,is_active' if slot_profile else 'email,full_name'
            latest = connection.exec_driver_sql('SELECT ' + columns + ' FROM "user" WHERE id=%s',
                                                (UUID(current['id']),)).one()
        assert tuple(latest) == ((current['email'], current['full_name'], current['is_active']) if http else
                                (current['email'], current['full_name'], False) if slot_profile
                                 else (current['email'], current['full_name']))
        child = None
        if http:
            from sqlmodel_http_package_free import run
            child = run(backend.parent, schema, current)
            assert exported.public_slots(owner) == target_slots
        elif slot_profile:
            slot_restart(backend, schema, current, workload_helper)
            assert exported.public_slots(owner) == target_slots
        else:
            restart(backend, schema, current)
        exported.unchanged(backend, hashes)
        receipt_name = 'sqlmodel-http-journey-receipt.json' if http else 'sqlmodel-public-slots-journey-receipt.json' if slot_profile else 'sqlmodel-searchable-journey-receipt.json'
        with (directory / receipt_name).open('x') as stream:
            json.dump({'application_revision': manifest['application_revision'], 'application_source_sha256': hashes,
                'model_changes': [], 'query_changes': [], 'source_plan_digest': source.digest,
                'restore_adoption_id': binding.document['adoption_id'], 'rewrap_plan_digest': rewrap.digest if rewrap is not None else None,
                'direct_restore_binding': direct,
                **({'layout': 'preserve-public-slots/v1', 'restore_format': binding.document['format'],
                    'source_public_slots': manifest['source_public_slots'], 'restored_target_public_slots': target_slots,
                    'restored_target_public_slots_preserved': True, 'boolean_latest_false': True} if slot_profile else {}),
                **({'payload_plan_digest': payload.digest, 'payload_generation': 2,
                    'native_http_controls': manifest['baseline']['controls'],
                    'protected_http_controls': manifest['current']['controls'],
                    'restored_http_controls': current['controls'], 'pre_adoption_doctor': manifest['pre_adoption_doctor'],
                    'local_smtp': [manifest['baseline']['local_smtp'], manifest['current']['local_smtp'], current['local_smtp']],
                    'removed_original_http': child, 'tampered_backup': 'refused before adoption',
                    'boundary': 'Pinned original TestClient HTTP/JWT and loopback SMTP; no browser, live KMS, external mail or deployment qualification'} if http else {}),
                'search_plan_digest': proposal.digest, 'activation_plan_digest': activation.digest,
                'search_controls': controls, 'storage_frame_bytes_preserved': True, 'index_identity_preserved': True,
                'native_catalog_restored': True, 'latest_value_decryptback': True, 'cryptalis_denied_restart': True,
                'tenancy': manifest['tenancy'], 'key_custody': manifest['key_custody'],
                'production_email_domain_admission': 'UNKNOWN', 'gates': 'all seven UNKNOWN'}, stream, indent=2)
    finally:
        runtime.dispose()
        owner.dispose()
        mapping.dispose()
        exported.clear_app()
