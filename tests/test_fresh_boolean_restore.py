"""Fresh PostgreSQL Boolean adoption authenticates values before latest-value removal."""
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Boolean, Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry

from cryptalis import deprotection as d, migration as m, restore as recovery
from cryptalis.sqlalchemy import attach
from payload_rotation_worker import target_keys
from test_deprotection import app_pin
from test_migration import engine, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --boolean', allow_module_level=True)


def restore_dump(path, database=None):
    from test_fresh_cluster_export import environment
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(path)],
        env=environment('CRYPTALIS_TEST_DATABASE_URL', database),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'Boolean dump restore failed; diagnostics withheld'


def test_boolean_fresh_cluster_authentication_adoption_and_package_free_latest_false():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'boolean-storage'
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        native = connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall()
    assert {str(key): value for key, value in native} == manifest['source']
    assert all(value is None or type(value) is bool for _, value in native)
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    values = manifest['pin']
    pin = m.DeploymentPin(UUID(values['target_id']), UUID(values['operation_id']), values['plan_digest'], values['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Boolean), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    approval = m.MaintenanceApproval('source export finished and schema dropped; fresh target excludes writers', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt typed Boolean restored copy',
                                     'source schema dropped after export; target quarantined', True)
    try:
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            identity, frame = connection.exec_driver_sql(
                f'SELECT id,name FROM "{schema}".customer WHERE name IS NOT NULL ORDER BY id LIMIT 1').one()
            frame = bytes(frame)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with pytest.raises(m.TransitionFailure):
            recovery.plan(source, owner, pin=pin, keys=target_keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, identity))
        binding = recovery.plan(source, owner, pin=pin, keys=target_keys, approval=intent)
        sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=target_keys,
                          deployment=(source, pin, binding))
        with sessions(tenant_id=TENANT) as session:
            observed = {str(row.id): row.name for row in session.scalars(select(Customer))}
            assert observed == manifest['expected']
            assert all(type(value) is bool or value is None for value in observed.values())
            row = session.get(Customer, UUID(int=999))
            row.name = False
            session.commit()
            session.refresh(row)
            assert row.name is False
        expected = dict(manifest['expected'])
        expected[str(UUID(int=999))] = False
        reverse = d.plan(source, owner, source_pin=pin, keys=target_keys, restore=binding,
            plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        reverse_pin = app_pin(reverse, 'PREPARED')
        pure = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                  'public Boolean fixtures and retained protected dump')
        assert d.apply(reverse, owner, keys=target_keys, pin=reverse_pin,
            approval=approval, consent=pure).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=target_keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
            approval=approval, consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'fresh process with Cryptalis imports denied', 'public fixture backup', True)
        assert d.remove(reverse, owner, pin=app_pin(reverse, 'REMOVING'), approval=approval,
                        removal=removal, consent=pure).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=app_pin(reverse, 'REMOVED')) is None
        child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
import psycopg
from psycopg import sql
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    values = connection.execute(sql.SQL('SELECT id,name FROM {}.customer').format(
        sql.Identifier(os.environ['BOOLEAN_RESTORE_SCHEMA']))).fetchall()
assert {str(key): value for key, value in values} == json.loads(os.environ['BOOLEAN_RESTORE_EXPECTED'])
assert all(value is None or type(value) is bool for _, value in values)
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native Boolean package-free restart passed')
'''], env=dict(os.environ, BOOLEAN_RESTORE_SCHEMA=schema, BOOLEAN_RESTORE_EXPECTED=json.dumps(expected)),
            cwd=directory, capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'native Boolean restart failed; diagnostics withheld'
        assert child.stdout.strip() == 'native Boolean package-free restart passed'
        (directory / 'boolean-journey-receipt.json').write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'profile': 'Boolean storage, payload rotation, fresh PostgreSQL16 adoption, latest False removal',
            'tampered_frame': 'refused before adoption', 'package_free_restart': 'passed',
            'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
