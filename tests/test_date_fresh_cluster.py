"""Genuine fresh-cluster native scalar adoption precedes current-data exit."""
import base64
from datetime import date, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, Date, DateTime, MetaData, Numeric, Table, Text, Uuid, select
from sqlalchemy.orm import registry

from cryptalis import migration as m, restore as recovery
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_application, date_keys, native_restart, remove_date, rotate_all
from test_migration import engine, frames, publish, run, TENANT

TIMESTAMP_PROFILE = os.environ.get('CRYPTALIS_FRESH_TIMESTAMP') == '1'
NUMERIC_PROFILE = os.environ.get('CRYPTALIS_FRESH_NUMERIC') == '1'
NATIVE_TYPE = Decimal if NUMERIC_PROFILE else datetime if TIMESTAMP_PROFILE else date
MAPPED_TYPE = Numeric(8, 2) if NUMERIC_PROFILE else DateTime() if TIMESTAMP_PROFILE else Date()
PROFILE = 'numeric-storage' if NUMERIC_PROFILE else 'timestamp-storage' if TIMESTAMP_PROFILE else 'date-storage'
DEFAULT = Decimal('1.23') if NUMERIC_PROFILE else NATIVE_TYPE.min
UPDATED = Decimal('999999.99') if NUMERIC_PROFILE else NATIVE_TYPE.max
RESTORED_EDIT = Decimal('-98765.43') if NUMERIC_PROFILE else NATIVE_TYPE(2026, 10, 27)

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --date', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump


def wire(values):
    return {str(key): (format(value, 'f') if NUMERIC_PROFILE else value.isoformat())
            if value is not None else None for key, value in values.items()}


def numeric_restart(schema, expected, directory):
    child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from decimal import Decimal
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from psycopg import sql
schema = os.environ['NUMERIC_SCHEMA']
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    rows = connection.execute(sql.SQL('SELECT id,name FROM {}.customer').format(sql.Identifier(schema))).fetchall()
    assert all(value is None or type(value) is Decimal for _, value in rows)
    assert {str(key): format(value, 'f') if value is not None else None for key, value in rows} == json.loads(os.environ['NUMERIC_EXPECTED'])
    dtype, typmod = connection.execute('SELECT a.atttypid::regtype::text,a.atttypmod FROM pg_catalog.pg_attribute a '
        'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
        ('"' + schema + '".customer', 'name')).fetchone()
    assert dtype == 'numeric' and typmod == ((8 << 16) | 2) + 4
    observed = connection.execute(sql.SQL('UPDATE {}.customer SET name=%s WHERE id=%s RETURNING name').format(
        sql.Identifier(schema)), (Decimal('1.235'), next(iter(json.loads(os.environ['NUMERIC_EXPECTED']))))).fetchone()[0]
    assert observed.as_tuple() == Decimal('1.24').as_tuple()
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native NUMERIC package-free restart passed')
'''], env=dict(os.environ, NUMERIC_SCHEMA=schema, NUMERIC_EXPECTED=json.dumps(wire(expected))),
        cwd=directory, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native NUMERIC restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native NUMERIC package-free restart passed'


def test_export_date_backup_after_rotations():
    workdir = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
    from test_date_storage import VALUES as DATE_VALUES
    from test_timestamp_storage import VALUES as TIMESTAMP_VALUES
    values = ((Decimal('1.23'), Decimal('-0.01'), Decimal('999999.99'), Decimal('0.00'),
               None, Decimal('-999999.99')) if NUMERIC_PROFILE else
              TIMESTAMP_VALUES if TIMESTAMP_PROFILE else DATE_VALUES)
    with date_application(public_slots=public_slots, value_type=MAPPED_TYPE,
                          values=values, value_default=DEFAULT) as app:
        source_slots = None
        if public_slots:
            from test_public_slots import slots
            source_slots = [list(row) for row in slots(app)[1]]
        source = {identity: value for identity, (_, value) in app.source.items()}
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        rotate_all(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = UPDATED
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT))
            session.commit()
        expected = dict(source)
        expected[UUID(int=101)] = UPDATED
        expected[UUID(int=999)] = DEFAULT
        del expected[UUID(int=106)]
        if not NUMERIC_PROFILE:
            assert all(value is None or len(value) == (50 if TIMESTAMP_PROFILE else 46) for value in frames(app, True).values())
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': PROFILE, 'application_default': wire({'default': DEFAULT})['default'],
            'public_slots': public_slots, 'source_public_slots': source_slots,
            'database': owner['dbname'], 'owner_role': owner['user'], 'runtime_role': runtime['user'],
            'schema': app.schema, 'source': wire(source), 'expected': wire(expected),
            'plan': base64.b64encode(app.plan.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def test_restore_date_authentication_explicit_adoption_latest_exit():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == PROFILE
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        assert wire(dict(connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall())) == manifest['source']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    raw = manifest['pin']
    pin = m.DeploymentPin(UUID(raw['target_id']), UUID(raw['operation_id']), raw['plan_digest'], raw['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', MAPPED_TYPE, default=DEFAULT), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    approval = m.MaintenanceApproval('source schema removed; isolated fresh target excludes all writers', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt native scalar protected backup',
                                     'source schema dropped and target quarantined', True)
    try:
        with pytest.raises(m.TransitionFailure): m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            identity, frame = connection.exec_driver_sql(
                f'SELECT id,name FROM "{schema}".customer WHERE name IS NOT NULL ORDER BY id LIMIT 1').one()
            frame = bytes(frame)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                                      (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with pytest.raises(m.TransitionFailure):
            recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, identity))
        binding = recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=date_keys, deployment=(source, pin, binding))
        with sessions(tenant_id=TENANT) as session:
            actual = {row.id: row.name for row in session.scalars(select(Customer))}
            assert wire(actual) == manifest['expected']
            assert all(value is None or type(value) is NATIVE_TYPE for value in actual.values())
            session.get(Customer, UUID(int=999)).name = RESTORED_EDIT
            session.commit()
        actual[UUID(int=999)] = RESTORED_EDIT
        app = SimpleNamespace(owner=owner, plan=source, pin=pin, approval=approval)
        remove_date(app, restore=binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
        if manifest['public_slots']:
            with owner.connect() as connection:
                slots = connection.exec_driver_sql('SELECT attname,attnum FROM pg_catalog.pg_attribute '
                    'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped ORDER BY attnum',
                    (f'"{schema}".customer',)).all()
            assert [list(row) for row in slots] == manifest['source_public_slots']
        if NUMERIC_PROFILE:
            numeric_restart(schema, actual, directory)
        else:
            native_restart(schema, actual, directory=directory, timestamp=TIMESTAMP_PROFILE)
        (directory / (PROFILE.removesuffix('-storage') + '-journey-receipt.json')).write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'profile': PROFILE + ', three rotations, fresh PostgreSQL16 adoption, latest-value removal',
            'tampered_frame': 'refused before adoption', 'package_free_restart': 'passed',
            'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
