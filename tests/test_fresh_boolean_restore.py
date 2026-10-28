"""Fresh PostgreSQL Boolean adoption authenticates values before latest-value removal."""
import base64
from dataclasses import replace
from datetime import date
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import psycopg
from psycopg import sql
import pytest
from sqlalchemy import BigInteger, Integer, SmallInteger, Boolean, Column, Date, MetaData, Table, Text, Uuid, select
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
    bits = int(os.environ.get('CRYPTALIS_FRESH_INTEGER_BITS', '0'))
    dates = os.environ.get('CRYPTALIS_FRESH_DATE') == '1'
    uuids = os.environ.get('CRYPTALIS_FRESH_UUID') == '1'
    dtype = Uuid if uuids else Date if dates else {0: Boolean, 16: SmallInteger, 32: Integer, 64: BigInteger}[bits]
    native_python = UUID if uuids else date if dates else int if bits else bool
    profile = 'native-uuid-storage' if uuids else 'native-date-storage' if dates else 'integer-' + str(bits) if bits else 'boolean-storage'
    latest = UUID(int=2026) if uuids else date(2026, 10, 28) if dates else -(1 << (bits - 1)) + 29 if bits else False
    if dates or uuids:
        for name in ('source', 'expected'):
            manifest[name] = {key: (UUID(value) if uuids else date.fromisoformat(value)) if value is not None else None
                              for key, value in manifest[name].items()}
    default = int(manifest['application_default']) if manifest.get('application_default') is not None else None
    reader_keys = target_keys
    if manifest.get('root_rewrapped'):
        from payload_rotation_worker import rotated_keys
        reader_keys = rotated_keys
    assert manifest.get('root_rewrapped', False) is (default is not None or dates or uuids)
    assert manifest['application_profile'] == profile and manifest.get('integer_bits', 0) == bits
    column_name = manifest.get('column', 'name')
    assert column_name == os.environ.get('CRYPTALIS_FRESH_COLUMN_NAME', 'name')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    assert source.document['lock']['models'][0]['fields'][0]['column'] == column_name
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        native = connection.execute(sql.SQL('SELECT id,{} FROM {}.customer').format(
            sql.Identifier(column_name), sql.Identifier(schema))).fetchall()
    assert {str(key): value for key, value in native} == manifest['source']
    assert all(value is None or type(value) is native_python for _, value in native)
    restore_dump(directory / 'protected.sql')
    values = manifest['pin']
    pin = m.DeploymentPin(UUID(values['target_id']), UUID(values['operation_id']), values['plan_digest'], values['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column(column_name, dtype(), default=default), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table, properties={'name': table.c[column_name]})
    column = owner.dialect.identifier_preparer.quote_identifier(column_name)
    approval = m.MaintenanceApproval('source export finished and schema dropped; fresh target excludes writers', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt typed Boolean restored copy',
                                     'source schema dropped after export; target quarantined', True)
    try:
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            identity, frame = connection.exec_driver_sql(
                f'SELECT id,{column} FROM "{schema}".customer WHERE {column} IS NOT NULL ORDER BY id LIMIT 1').one()
            frame = bytes(frame)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET {column}=%s WHERE id=%s',
                (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with pytest.raises(m.TransitionFailure):
            recovery.plan(source, owner, pin=pin, keys=reader_keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET {column}=%s WHERE id=%s', (frame, identity))
        binding = recovery.plan(source, owner, pin=pin, keys=reader_keys, approval=intent)
        if column_name != 'name':
            frame_name = source.document['lock']['models'][0]['fields'][0]['payload_column'] + '_frame'
            assert any(item['name'] == frame_name for item in binding.document['restatements'])
        sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=reader_keys,
                          deployment=(source, pin, binding))
        with sessions(tenant_id=TENANT) as session:
            observed = {str(row.id): row.name for row in session.scalars(select(Customer))}
            assert observed == manifest['expected']
            assert all(type(value) is native_python or value is None for value in observed.values())
            row = session.get(Customer, UUID(int=999))
            row.name = latest
            session.commit()
            session.refresh(row)
            assert row.name == latest and type(row.name) is native_python
        expected = dict(manifest['expected'])
        expected[str(UUID(int=999))] = latest
        reverse = d.plan(source, owner, source_pin=pin, keys=reader_keys, restore=binding,
            plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        reverse_pin = app_pin(reverse, 'PREPARED')
        pure = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                  'public Boolean fixtures and retained protected dump')
        assert d.apply(reverse, owner, keys=reader_keys, pin=reverse_pin,
            approval=approval, consent=pure).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=reader_keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
            approval=approval, consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'fresh process with Cryptalis imports denied', 'public fixture backup', True)
        assert d.remove(reverse, owner, pin=app_pin(reverse, 'REMOVING'), approval=approval,
                        removal=removal, consent=pure).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=app_pin(reverse, 'REMOVED')) is None
        if manifest.get('public_slots'):
            with owner.connect() as connection:
                restored_slots = connection.exec_driver_sql('SELECT attname,attnum FROM pg_catalog.pg_attribute '
                    'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped ORDER BY attnum',
                    (f'"{schema}".customer',)).all()
            assert [list(row) for row in restored_slots] == manifest['source_public_slots']

        child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from datetime import date
from uuid import UUID
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
import psycopg
from psycopg import sql
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    values = connection.execute(sql.SQL('SELECT id,{} FROM {}.customer').format(
        sql.Identifier(os.environ['SCALAR_RESTORE_COLUMN']), sql.Identifier(os.environ['BOOLEAN_RESTORE_SCHEMA']))).fetchall()
dates = os.environ['SCALAR_RESTORE_DATE'] == '1'
uuids = os.environ['SCALAR_RESTORE_UUID'] == '1'
expected = json.loads(os.environ['BOOLEAN_RESTORE_EXPECTED'])
if dates or uuids:
    expected = {key: (UUID(value) if uuids else date.fromisoformat(value)) if value is not None else None for key, value in expected.items()}
assert {str(key): value for key, value in values} == expected
assert all(value is None or type(value) is (UUID if uuids else date if dates else int if int(os.environ['SCALAR_RESTORE_BITS']) else bool) for _, value in values)
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    actual_type = connection.execute('SELECT a.atttypid::regtype::text FROM pg_catalog.pg_attribute a '
        'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
        ('\"' + os.environ['BOOLEAN_RESTORE_SCHEMA'] + '\".customer', os.environ['SCALAR_RESTORE_COLUMN'])).fetchone()[0]
assert actual_type == ('uuid' if uuids else 'date' if dates else {0:'boolean',16:'smallint',32:'integer',64:'bigint'}[int(os.environ['SCALAR_RESTORE_BITS'])])
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native Boolean package-free restart passed')
'''], env=dict(os.environ, BOOLEAN_RESTORE_SCHEMA=schema,
            BOOLEAN_RESTORE_EXPECTED=json.dumps(expected, default=lambda value: str(value) if type(value) is UUID else date.isoformat(value)),
            SCALAR_RESTORE_BITS=str(bits), SCALAR_RESTORE_COLUMN=column_name, SCALAR_RESTORE_DATE='1' if dates else '0', SCALAR_RESTORE_UUID='1' if uuids else '0'),
            cwd=directory, capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'native Boolean restart failed; diagnostics withheld'
        assert child.stdout.strip() == 'native Boolean package-free restart passed'
        (directory / (profile + '-journey-receipt.json')).write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'column': column_name, 'public_slots': manifest.get('public_slots', False),
            'frame_restatements': [{'name': item['name'], 'definition': item['definition']}
                                   for item in binding.document['restatements']],
            'profile': profile + ' storage, payload rotation, fresh PostgreSQL16 adoption, latest-value removal',
            'tampered_frame': 'refused before adoption', 'package_free_restart': 'passed',
            'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
