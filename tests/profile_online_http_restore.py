"""Restore the pinned online HTTP application on a genuinely fresh cluster.

The source cluster is exported and decommissioned by the outer qualification
harness. This profile restores its protected backup, adopts it with explicit
quarantine evidence, runs the unchanged application through three successor
formats, then decrypts current values and exits to native access.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import pytest

pytest.importorskip('sqlmodel', reason='optional pinned SQLModel HTTP restore profile')
pytest.importorskip('fastapi', reason='optional original FastAPI HTTP restore profile')

import psycopg
from sqlmodel import Session
from sqlalchemy.exc import DBAPIError

from cryptalis import deprotection as d
from cryptalis import migration as m
from cryptalis import restore, rotation
from cryptalis.manifest.compiler import _canonical
from cryptalis.sqlmodel import attach
from payload_rotation_worker import rotated_keys
from profile_online_http_application import SOURCE, _mapped_rows, _native_rows, _online_pin
from profile_sqlmodel_public_slots_application import public_slots
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from rewrap_worker import target_keys as rewrapped_keys
from search_rotation_worker import target_keys as new_search_keys
from sqlmodel_http_workload import workflow as http_workflow
from sqlmodel_http_mail_workload import workflow as mail_workflow
from test_migration import keys
from test_sqlmodel_application import native_engine, settings


def _jsonable(value):
    return json.loads(json.dumps(value, default=str))


def _conninfo(variable):
    parsed = psycopg.conninfo.conninfo_to_dict(os.environ[variable])
    return {'host': parsed.get('host', ''), 'port': parsed.get('port', '5432'),
            'user': parsed['user'], 'password': parsed['password'], 'dbname': parsed['dbname']}


def _restore_dump(path):
    values = _conninfo('CRYPTALIS_TEST_DATABASE_URL')
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(path)],
        env=dict(os.environ, PGHOST=values['host'], PGPORT=values['port'], PGUSER=values['user'],
                 PGPASSWORD=values['password'], PGDATABASE=values['dbname']),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    assert result.returncode == 0, 'protected SQL restore failed; diagnostics withheld'


def _search_keys(tenant):
    return new_search_keys(tenant, source=rotated_keys)


def _rotation_pin(plan, phase):
    target_id = plan.target_id if hasattr(plan, 'target_id') else plan.source.target_id
    return m.DeploymentPin(target_id, plan.operation_id, plan.digest, phase)


def _catalog_json(owner):
    return {name: [list(row) for row in rows] for name, rows in native_catalog(owner).items()}


def test_online_http_backup_restores_rotates_and_exits_on_fresh_cluster(tmp_path, monkeypatch):
    snapshot_root = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    backup_root = os.environ.get('CRYPTALIS_ONLINE_HTTP_BACKUP_DIR')
    required = ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL',
                'CRYPTALIS_TEST_SOURCE_URL')
    if not snapshot_root or not backup_root or any(not os.environ.get(name) for name in required):
        pytest.skip('set the pinned SQLModel snapshot, backup directory and all three fresh-cluster URLs')
    assert sys.version_info >= (3, 13), 'pinned original HTTP snapshot requires Python 3.13'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)

    backup = Path(backup_root)
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    source = m.MigrationPlan(_canonical(manifest['source_plan']))
    source_pin = _online_pin(source, 'ACTIVE')
    assert manifest['application_revision'] == SOURCE['revision']

    copied = tmp_path / 'original'
    hashes = {}
    for relative, expected in SOURCE['files'].items():
        raw = (Path(snapshot_root) / relative).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    assert len(hashes) == 26 and hashes == manifest['application_source_sha256']

    monkeypatch.syspath_prepend(str(copied / 'backend'))
    isolated_cwd = tmp_path / 'empty' / 'cwd'
    isolated_cwd.mkdir(parents=True)
    monkeypatch.chdir(isolated_cwd)
    settings(monkeypatch)
    for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
            EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name, value)

    schema = source.document['lock']['models'][0]['schema']
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = original_engine = None
    try:
        from app.models import SQLModel, User
        from app.main import app as api
        from app.core.db import engine as original_engine
        mapping = User._sa_registry
        source_columns = _jsonable(manifest['source_public_slots'])
        source_catalog = manifest['native_catalog']
        _restore_dump(backup / 'protected.sql')

        with owner.connect() as connection:
            owner_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with runtime.connect() as connection:
            target_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with psycopg.connect(**_conninfo('CRYPTALIS_TEST_SOURCE_URL')) as connection:
            source_role = connection.execute('SELECT current_user').fetchone()[0]
        contract = source.document['access_contract']
        assert (owner_role, source_role, target_role) == (
            contract['owner'], contract['source_role'], contract['target_role'])
        assert len({owner_role, source_role, target_role}) == 3

        target_slots = public_slots(owner, manifest['source_public_slots'])
        assert target_slots.keys() == manifest['source_public_slots'].keys()
        for table, original in manifest['source_public_slots'].items():
            observed = target_slots[table]
            assert _jsonable(observed['columns']) == _jsonable(original['columns'])
            assert _jsonable(observed['order']) == _jsonable(original['order'])
        # OIDs identify this restored cluster and become the local baseline.
        target_slots = _jsonable(target_slots)
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=source_pin)
        approval = restore.RestoreApproval('local online HTTP recovery host',
            'adopt the protected backup after source-cluster decommission',
            'the source cluster is stopped and decommissioned; this restored cluster remains quarantined', True)
        binding = restore.plan(source, owner, pin=source_pin, keys=keys, approval=approval)
        assert m.diagnose_deployment(source, runtime, pin=source_pin, restore=binding) is None

        maintenance = m.MaintenanceApproval(
            'The source cluster is decommissioned and application writers are stopped during adoption.', 3600)
        rewrap = rotation.plan_rewrap(source, owner, source_pin=source_pin, keys=keys,
            target_keys=rewrapped_keys, verify_rows_per_second=1000, restore=binding)
        adopted = rewrap.activation_plan
        assert adopted.document['format'] == 'cryptalis.transition/v12'
        assert rotation.apply_rewrap(rewrap, owner, keys=keys, target_keys=rewrapped_keys,
            pin=_rotation_pin(adopted, 'PREPARED'), approval=maintenance).phase == 'PENDING'
        assert m.apply(adopted, owner, keys=rewrapped_keys, pin=_rotation_pin(adopted, 'ACTIVATING'),
            approval=maintenance, until='ACTIVE').phase == 'ACTIVE'
        adopted_pin = _rotation_pin(adopted, 'ACTIVE')
        assert m.diagnose_deployment(adopted, runtime, pin=adopted_pin) is None

        payload = rotation.plan_payload_rotation(adopted, owner, source_pin=adopted_pin,
            keys=rewrapped_keys, target_keys=rotated_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000,
            max_batch_rows=1)
        payload_pin = _rotation_pin(payload, 'PREPARED')
        assert rotation.apply_payload_rotation(payload, owner, keys=rewrapped_keys,
            target_keys=rotated_keys, pin=payload_pin, approval=maintenance,
            max_chunks=1).committed_rows == 1
        assert rotation.apply_payload_rotation(payload, owner, keys=rewrapped_keys,
            target_keys=rotated_keys, pin=payload_pin, approval=maintenance).phase == 'BACKFILLED'
        payload_successor = rotation.seal_payload_rotation(payload, owner, keys=rewrapped_keys,
            target_keys=rotated_keys, pin=payload_pin, approval=maintenance,
            copy_rows_per_second=1000.5, copy_wal_bytes_per_row=3000)
        assert payload_successor.document['format'] == 'cryptalis.transition/v13'
        assert rotation.switch_payload_rotation(payload, payload_successor, owner, keys=rewrapped_keys,
            target_keys=rotated_keys, pin=_rotation_pin(payload_successor, 'PREPARED'),
            approval=maintenance).phase == 'PENDING'
        assert m.apply(payload_successor, owner, keys=rotated_keys,
            pin=_rotation_pin(payload_successor, 'ACTIVATING'), approval=maintenance,
            until='ACTIVE').phase == 'ACTIVE'
        payload_pin = _rotation_pin(payload_successor, 'ACTIVE')

        search = rotation.plan_search_rotation(payload_successor, owner, source_pin=payload_pin,
            keys=rotated_keys, target_keys=_search_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000,
            max_batch_rows=1)
        search_pin = _rotation_pin(search, 'PREPARED')
        assert rotation.apply_search_rotation(search, owner, keys=rotated_keys,
            target_keys=_search_keys, pin=search_pin, approval=maintenance,
            max_chunks=1).committed_rows == 1
        assert rotation.apply_search_rotation(search, owner, keys=rotated_keys,
            target_keys=_search_keys, pin=search_pin, approval=maintenance).phase == 'BACKFILLED'
        activation = rotation.seal_search_rotation(search, owner, keys=rotated_keys,
            target_keys=_search_keys, pin=search_pin, approval=maintenance,
            copy_rows_per_second=1000.5, copy_wal_bytes_per_row=3000)
        assert activation.document['format'] == 'cryptalis.transition/v14'
        assert activation.document['restore_lineage'] == [binding.document]
        assert rotation.switch_search_rotation(search, activation, owner, keys=rotated_keys,
            target_keys=_search_keys, pin=_rotation_pin(activation, 'PREPARED'),
            approval=maintenance).phase == 'PENDING'
        assert m.apply(activation, owner, keys=_search_keys,
            pin=_rotation_pin(activation, 'ACTIVATING'), approval=maintenance,
            until='ACTIVE').phase == 'ACTIVE'
        active_pin = _rotation_pin(activation, 'ACTIVE')
        assert m.diagnose_deployment(activation, runtime, pin=active_pin) is None

        sessions = attach(mapping, runtime, lock=activation.lock_bytes, keys=_search_keys,
            deployment=(activation, active_pin))
        factory = lambda: sessions(tenant_id=UUID(source.document['lock']['models'][0]['table_id']),
                                   expire_on_commit=False)
        assert _jsonable(_mapped_rows(factory, mapping)) == manifest['expected_rows']
        retained = manifest['retained']
        current = http_workflow(api, factory, retained=retained)
        assert current['is_active'] is True
        current, search_controls_result = search_controls(factory, current)
        assert search_controls_result['unique_sqlstate'] == '23505'
        assert search_controls_result['latest_email_edit'] is True
        mail = mail_workflow(api, factory, current, monkeypatch)
        assert mail['smtp_messages'] == 4
        latest_rows = _mapped_rows(factory, mapping)

        reverse = d.plan(activation, owner, source_pin=active_pin, keys=_search_keys,
            plaintext_runtime_role=source_role, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'Public fixture values only; the quarantined protected backup is retained.')
        assert d.apply(reverse, owner, keys=_search_keys, pin=_rotation_pin(reverse, 'PREPARED'),
            approval=maintenance, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=_search_keys,
            pin=_rotation_pin(reverse, 'PLAINTEXT_ACTIVATING'), approval=maintenance,
            consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        target_probe = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        try:
            with target_probe.connect() as connection, pytest.raises(DBAPIError) as revoked:
                connection.exec_driver_sql(f'SELECT id FROM "{schema}"."user"').all()
            assert getattr(revoked.value.orig, 'sqlstate', None) == '42501'
        finally:
            target_probe.dispose()
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'The unchanged original HTTP/JWT application runs under the source role after decrypt-back.',
            'No historical plaintext or protected backup is claimed erased.', True)
        assert d.remove(reverse, owner, pin=_rotation_pin(reverse, 'REMOVING'),
            approval=maintenance, removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=_rotation_pin(reverse, 'REMOVED')) is None

        assert _catalog_json(owner) == source_catalog
        assert _jsonable(public_slots(owner, target_slots)) == target_slots
        assert _jsonable(_native_rows(owner, mapping)) == _jsonable(latest_rows)

        with monkeypatch.context() as source_url:
            source_url.setenv('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', os.environ['CRYPTALIS_TEST_SOURCE_URL'])
            from sqlmodel_http_package_free import run as package_free_http
            package_free = package_free_http(copied, schema, current)
        assert package_free['native_http'] == 'passed'
        assert hashes == {relative: hashlib.sha256((copied / relative).read_bytes()).hexdigest()
                          for relative in hashes}

        receipt_path = os.environ.get('CRYPTALIS_ONLINE_HTTP_REPORT')
        if receipt_path:
            with Path(receipt_path).open('x', encoding='utf-8') as stream:
                json.dump({'source_plan_digest': source.digest,
                    'restore_adoption_id': binding.document['adoption_id'],
                    'rewrap_plan_digest': rewrap.digest,
                    'payload_rotation_plan_digest': payload.digest,
                    'search_rotation_plan_digest': search.digest,
                    'activation_plan_digest': activation.digest,
                    'application_revision': SOURCE['revision'], 'application_source_sha256': hashes,
                    'restored_initial_all_table_rows_match': True,
                    'latest_all_table_rows_match_after_decryptback': True,
                    'native_catalog_restored': True, 'restored_target_public_slots_preserved': True,
                    'retained_http_authentication': 'PASS', 'restored_http_controls': current['controls'],
                    'restored_search_controls': search_controls_result, 'restored_local_smtp': mail,
                    'package_free_native_exit': package_free,
                    'cluster_boundary': 'new PostgreSQL cluster with newly provisioned credentials; source cluster decommissioned before restore',
                    'key_custody': 'public deterministic fixture providers only; no live KMS',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        runtime.dispose()
        if original_engine is not None:
            original_engine.dispose()
        owner.dispose()
        if mapping is not None:
            mapping.dispose()
            mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
