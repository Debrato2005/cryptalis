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
from zoneinfo import ZoneInfo

import psycopg
import pytest
from sqlalchemy import Column, Date, DateTime, MetaData, Numeric, Table, Text, Uuid, select
from sqlalchemy.orm import Session, registry

from cryptalis import migration as m, restore as recovery
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_application, date_keys, native_restart, remove_date, rotate_all
from test_migration import engine, frames, publish, run, TENANT

TIMESTAMP_PROFILE = os.environ.get('CRYPTALIS_FRESH_TIMESTAMP') == '1'
TIMESTAMPTZ_PROFILE = os.environ.get('CRYPTALIS_FRESH_TIMESTAMPTZ') == '1'
NUMERIC_EQUALITY_PROFILE = os.environ.get('CRYPTALIS_FRESH_NUMERIC_EQUALITY') == '1'
NUMERIC_PROFILE = os.environ.get('CRYPTALIS_FRESH_NUMERIC') == '1' or NUMERIC_EQUALITY_PROFILE
NATIVE_TYPE = Decimal if NUMERIC_PROFILE else datetime if TIMESTAMP_PROFILE or TIMESTAMPTZ_PROFILE else date
MAPPED_TYPE = (Numeric(8, 2) if NUMERIC_PROFILE else DateTime(timezone=True) if TIMESTAMPTZ_PROFILE else
               DateTime() if TIMESTAMP_PROFILE else Date())
PROFILE = ('numeric-equality' if NUMERIC_EQUALITY_PROFILE else
           'timestamptz-storage' if TIMESTAMPTZ_PROFILE else 'numeric-storage' if NUMERIC_PROFILE else
           'timestamp-storage' if TIMESTAMP_PROFILE else 'date-storage')
if TIMESTAMPTZ_PROFILE:
    from test_timestamptz_storage import DEFAULT, EDIT as UPDATED, VALUES as AWARE_VALUES, runtime_engine
    RESTORED_EDIT = datetime(2026, 11, 1, 1, 45, tzinfo=ZoneInfo('America/New_York'), fold=1)
else:
    DEFAULT = Decimal('1.23') if NUMERIC_PROFILE else NATIVE_TYPE.min
    UPDATED = Decimal('999999.99') if NUMERIC_PROFILE else NATIVE_TYPE.max
    RESTORED_EDIT = Decimal('-98765.43') if NUMERIC_PROFILE else NATIVE_TYPE(2026, 10, 27)

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --date', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump


def wire(values):
    if TIMESTAMPTZ_PROFILE:
        return {str(key): {'iso': value.isoformat(timespec='microseconds'), 'fold': value.fold}
                if value is not None else None for key, value in values.items()}
    return {str(key): (format(value, 'f') if NUMERIC_PROFILE else value.isoformat())
            if value is not None else None for key, value in values.items()}


def numeric_queries(session, model):
    from test_numeric_search import observe
    pivots = tuple(Decimal(value) for value in ('1.2300', '1.235', '-0.000', '999999.990'))
    return json.loads(json.dumps(observe(session, model, pivots), default=str))


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


def timestamptz_restart(schema, expected, directory):
    child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from datetime import datetime
from uuid import UUID
from zoneinfo import ZoneInfo
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from psycopg import sql
schema = os.environ['TIMESTAMPTZ_SCHEMA']
expected = json.loads(os.environ['TIMESTAMPTZ_EXPECTED'])
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                     options='-c timezone=America/New_York') as connection:
    rows = connection.execute(sql.SQL('SELECT id,name FROM {}.customer').format(sql.Identifier(schema))).fetchall()
    assert all(value is None or type(value) is datetime and value.utcoffset() is not None for _, value in rows)
    assert {str(key): {'iso': value.isoformat(timespec='microseconds'), 'fold': value.fold}
            if value is not None else None for key, value in rows} == expected
    dtype, typmod = connection.execute('SELECT a.atttypid::regtype::text,a.atttypmod FROM pg_catalog.pg_attribute a '
        'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
        ('"' + schema + '".customer', 'name')).fetchone()
    assert dtype == 'timestamp with time zone' and typmod == -1
    value = datetime(2026, 11, 1, 1, 30, tzinfo=ZoneInfo('America/New_York'), fold=1)
    observed = connection.execute(sql.SQL('UPDATE {}.customer SET name=%s WHERE id=%s RETURNING name').format(
        sql.Identifier(schema)), (value, UUID(next(iter(expected))))).fetchone()[0]
    assert observed.isoformat(timespec='microseconds') == value.isoformat(timespec='microseconds')
    assert observed.fold == 1
    assert connection.execute('SELECT pg_catalog.nextval(%s::pg_catalog.regclass)',
        ('"' + schema + '".preserved_seq',)).fetchone()[0] == 129
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native TIMESTAMPTZ package-free restart passed')
'''], env=dict(os.environ, TIMESTAMPTZ_SCHEMA=schema, TIMESTAMPTZ_EXPECTED=json.dumps(wire(expected))),
        cwd=directory, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native TIMESTAMPTZ restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native TIMESTAMPTZ package-free restart passed'


def test_export_date_backup_after_rotations():
    workdir = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
    from test_date_storage import VALUES as DATE_VALUES
    from test_timestamp_storage import VALUES as TIMESTAMP_VALUES
    values = (AWARE_VALUES if TIMESTAMPTZ_PROFILE else
              (Decimal('1.23'), Decimal('-0.01'), Decimal('999999.99'), Decimal('0.00'),
               None, Decimal('-999999.99')) if NUMERIC_PROFILE else
              TIMESTAMP_VALUES if TIMESTAMP_PROFILE else DATE_VALUES)
    with date_application(public_slots=public_slots, value_type=MAPPED_TYPE,
                          values=values, value_default=DEFAULT, owned_sequences=TIMESTAMPTZ_PROFILE,
                          value_queries=('equality',) if NUMERIC_EQUALITY_PROFILE else ()) as app:
        sequence = None
        if TIMESTAMPTZ_PROFILE:
            from test_owned_sequences import facts, next_value
            sequence = list(facts(app))
            assert next_value(app) == 101
        source_slots = None
        if public_slots:
            from test_public_slots import slots
            source_slots = [list(row) for row in slots(app)[1]]
        source = {identity: value for identity, (_, value) in app.source.items()}
        if TIMESTAMPTZ_PROFILE:
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
                                 options='-c timezone=America/New_York') as connection:
                source = dict(connection.execute(f'SELECT id,name FROM "{app.schema}".customer').fetchall())
        native_queries = final_queries = None
        if NUMERIC_EQUALITY_PROFILE:
            with Session(app.runtime) as session:
                native_queries = numeric_queries(session, app.Customer)
                savepoint = session.begin_nested()
                session.get(app.Customer, UUID(int=101)).name = UPDATED
                session.delete(session.get(app.Customer, UUID(int=106)))
                session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT))
                session.flush()
                final_queries = numeric_queries(session, app.Customer)
                savepoint.rollback()
                session.rollback()
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        rotate_all(app)
        if TIMESTAMPTZ_PROFILE:
            assert list(facts(app)) == sequence
            assert next_value(app) == 108
        runtime = runtime_engine('America/New_York') if TIMESTAMPTZ_PROFILE else app.runtime
        try:
            sessions = attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=date_keys,
                              deployment=(app.plan, app.pin))
            with sessions(tenant_id=TENANT) as session:
                assert wire({row.id: row.name for row in session.scalars(select(app.Customer))}) == wire(source)
                if NUMERIC_EQUALITY_PROFILE:
                    assert numeric_queries(session, app.Customer) == native_queries
                session.get(app.Customer, UUID(int=101)).name = UPDATED
                session.delete(session.get(app.Customer, UUID(int=106)))
                session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT))
                session.commit()
                if NUMERIC_EQUALITY_PROFILE:
                    assert numeric_queries(session, app.Customer) == final_queries
        finally:
            if TIMESTAMPTZ_PROFILE:
                runtime.dispose()
        expected = dict(source)
        expected[UUID(int=101)] = UPDATED
        expected[UUID(int=999)] = DEFAULT
        if TIMESTAMPTZ_PROFILE:
            for identity in (UUID(int=101), UUID(int=999)):
                expected[identity] = expected[identity].astimezone(ZoneInfo('America/New_York'))
        del expected[UUID(int=106)]
        if not NUMERIC_PROFILE:
            assert all(value is None or len(value) == (50 if TIMESTAMP_PROFILE or TIMESTAMPTZ_PROFILE else 46) for value in frames(app, True).values())
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': PROFILE, 'application_default': DEFAULT.isoformat() if TIMESTAMPTZ_PROFILE else wire({'default': DEFAULT})['default'],
            'public_slots': public_slots, 'source_public_slots': source_slots,
            'database': owner['dbname'], 'owner_role': owner['user'], 'runtime_role': runtime['user'],
            'schema': app.schema, 'source': wire(source), 'expected': wire(expected),
            'plan': base64.b64encode(app.plan.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
        if TIMESTAMPTZ_PROFILE:
            manifest['aware_sequence_facts'] = sequence
            manifest['aware_sequence_next'] = 115
        if NUMERIC_EQUALITY_PROFILE:
            manifest['numeric_query_results'] = final_queries
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def test_restore_date_authentication_explicit_adoption_latest_exit():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == PROFILE
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'],
                         **({'options': '-c timezone=America/New_York'} if TIMESTAMPTZ_PROFILE else {})) as connection:
        assert wire(dict(connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall())) == manifest['source']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    raw = manifest['pin']
    pin = m.DeploymentPin(UUID(raw['target_id']), UUID(raw['operation_id']), raw['plan_digest'], raw['phase'])
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    runtime = runtime_engine('America/New_York') if TIMESTAMPTZ_PROFILE else engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
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
        observed_sequence = None
        if TIMESTAMPTZ_PROFILE:
            from test_owned_sequences import sequence_facts, next_value
            with owner.connect() as connection:
                observed_sequence = list(sequence_facts(connection, schema))
            original_sequence = manifest['aware_sequence_facts']
            assert observed_sequence[0] != original_sequence[0] and observed_sequence[1:] == original_sequence[1:]
            with owner.begin() as connection:
                connection.exec_driver_sql(f'ALTER SEQUENCE "{schema}".preserved_seq INCREMENT BY 1')
            with pytest.raises(m.TransitionFailure) as failure:
                recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
            assert failure.value.code == 'restored_sequence_mismatch'
            with owner.begin() as connection:
                connection.exec_driver_sql(f'ALTER SEQUENCE "{schema}".preserved_seq INCREMENT BY 7')
                assert list(sequence_facts(connection, schema)) == observed_sequence
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
        if TIMESTAMPTZ_PROFILE:
            assert binding.document['sequences'] == [{
                'model': source.document['lock']['models'][0]['table_id'],
                'schema': schema, 'name': 'preserved_seq', 'column': 'name',
                'source_oid': original_sequence[0], 'target_oid': observed_sequence[0]}]
            assert next_value(SimpleNamespace(schema=schema)) == manifest['aware_sequence_next'] == 115
        sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=date_keys, deployment=(source, pin, binding))
        with sessions(tenant_id=TENANT) as session:
            actual = {row.id: row.name for row in session.scalars(select(Customer))}
            assert wire(actual) == manifest['expected']
            assert all(value is None or type(value) is NATIVE_TYPE for value in actual.values())
            if NUMERIC_EQUALITY_PROFILE:
                assert numeric_queries(session, Customer) == manifest['numeric_query_results']
            row = session.get(Customer, UUID(int=999))
            row.name = RESTORED_EDIT
            session.commit()
            session.refresh(row)
            actual[UUID(int=999)] = row.name
            if NUMERIC_EQUALITY_PROFILE:
                assert session.scalar(select(Customer.id).where(Customer.tenant_id == TENANT,
                    Customer.name == Decimal('-98765.4300'))) == UUID(int=999)
        app = SimpleNamespace(owner=owner, plan=source, pin=pin, approval=approval)
        remove_date(app, restore=binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
        if TIMESTAMPTZ_PROFILE:
            with owner.connect() as connection:
                assert list(sequence_facts(connection, schema)) == observed_sequence
            assert next_value(SimpleNamespace(schema=schema)) == 122
        if manifest['public_slots']:
            with owner.connect() as connection:
                slots = connection.exec_driver_sql('SELECT attname,attnum FROM pg_catalog.pg_attribute '
                    'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped ORDER BY attnum',
                    (f'"{schema}".customer',)).all()
            assert [list(row) for row in slots] == manifest['source_public_slots']
        if TIMESTAMPTZ_PROFILE:
            timestamptz_restart(schema, actual, directory)
        elif NUMERIC_PROFILE:
            numeric_restart(schema, actual, directory)
        else:
            native_restart(schema, actual, directory=directory, timestamp=TIMESTAMP_PROFILE)
        (directory / (PROFILE.removesuffix('-storage') + '-journey-receipt.json')).write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'profile': PROFILE + ', three rotations, fresh PostgreSQL16 adoption, latest-value removal',
            'tampered_frame': 'refused before adoption', 'package_free_restart': 'passed',
            **({'sequence_metadata_drift': 'restored_sequence_mismatch',
                'sequence_counter': [101, 108, 115, 122, 129]} if TIMESTAMPTZ_PROFILE else {}),
            'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
