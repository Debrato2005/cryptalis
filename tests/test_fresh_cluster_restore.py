"""Fresh-cluster recovery evidence for a restored protected schema.

This module runs against a newly initialized PostgreSQL 16 cluster with a
temporary HOME credential pair. It proves native readability of a plaintext
pre-protection backup, frame-level recovery of a protected backup with the
retained key policy and reader path, and loud refusal of the restored journal
as current authority.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import uuid

import psycopg
import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid
from sqlalchemy.orm import registry

import cryptalis.migration as m
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_migration import engine, independent_open, keys, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py', allow_module_level=True)

WORKDIR = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
MANIFEST = json.loads((WORKDIR / 'restore-manifest.json').read_text())
SCHEMA = MANIFEST['schema']
PLAIN_DATABASE = os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']


def environment(variable, database=None):
    parsed = psycopg.conninfo.conninfo_to_dict(os.environ[variable])
    return {'host': parsed.get('host', ''), 'port': parsed.get('port', '5432'),
            'user': parsed['user'], 'password': parsed['password'],
            'dbname': database or parsed['dbname']}


def restore(path, variable, database=None):
    values = environment(variable, database)
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(path)],
                            env=dict(os.environ, PGHOST=values['host'], PGPORT=values['port'],
                                     PGUSER=values['user'], PGPASSWORD=values['password'],
                                     PGDATABASE=values['dbname']),
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'psql restore failed (diagnostics withheld)'


def rows(variable, statement, database=None):
    with psycopg.connect(**environment(variable, database)) as c:
        return c.execute(statement).fetchall()


def test_plaintext_backup_restores_natively():
    restore(WORKDIR / 'plain.sql', 'CRYPTALIS_TEST_DATABASE_URL', PLAIN_DATABASE)
    observed = {str(identity): [str(tenant), value] for identity, tenant, value in rows(
        'CRYPTALIS_TEST_DATABASE_URL', f'SELECT id, tenant_id, name FROM "{SCHEMA}".customer ORDER BY id',
        PLAIN_DATABASE)}
    assert observed == MANIFEST['source']


def test_protected_backup_recovers_values_with_retained_keys():
    restore(WORKDIR / 'protected.sql', 'CRYPTALIS_TEST_DATABASE_URL')
    with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
        assert c.execute(
            'SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s '
            'AND column_name=%s', (SCHEMA, 'customer', MANIFEST['column'])).fetchone()[0] == 'bytea'
        assert c.execute('SELECT pg_catalog.to_regclass(%s)',
                         (f'{MANIFEST["journal_schema"]}.{m.JOURNAL}',)).fetchone()[0] is not None
        restored = c.execute(
            f'SELECT id, tenant_id, "{MANIFEST["column"]}" FROM "{SCHEMA}".customer ORDER BY id').fetchall()
    with psycopg.connect(**environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')) as c:
        assert c.execute(f'SELECT count(*) FROM "{SCHEMA}".customer').fetchone()[0] == len(MANIFEST['expected'])
        assert c.execute(f'SELECT count(*) FROM "{SCHEMA}".customer '
                         "WHERE name = pg_catalog.convert_to('edited while protected','UTF8')").fetchone()[0] == 0
    descriptor = FieldDescriptor.from_compiled(MANIFEST['descriptor'], MANIFEST['descriptor_digest'])
    material = keys(TENANT).prepare()
    recovered = {str(identity): [str(tenant), open_text(None if frame is None else bytes(frame), descriptor,
                                                        tenant, identity, material)]
                 for identity, tenant, frame in restored}
    assert recovered == MANIFEST['expected']
    assert MANIFEST['deleted_id'] not in recovered and MANIFEST['added_id'] in recovered
    independent = {str(identity): [str(tenant), independent_open(None if frame is None else bytes(frame),
                                                                 MANIFEST['descriptor'], tenant, identity)]
                   for identity, tenant, frame in restored}
    assert independent == MANIFEST['expected']


def test_restored_journal_cannot_override_current_authority():
    import cryptalis.deprotection as d
    source = m.MigrationPlan(base64.b64decode(MANIFEST['plan']))
    pin = m.DeploymentPin(uuid.UUID(MANIFEST['pin']['target_id']), uuid.UUID(MANIFEST['pin']['operation_id']),
                          MANIFEST['pin']['plan_digest'], MANIFEST['pin']['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=SCHEMA))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    try:
        with pytest.raises(m.TransitionFailure, match='deployment_not_current'):
            m.check_deployment(source, owner, pin=pin)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin))
        with pytest.raises(m.TransitionFailure, match='deployment_not_current'):
            d.plan(source, owner, source_pin=pin, keys=keys, plaintext_runtime_role='postgres',
                   backfill_rows_per_second=1000, verify_rows_per_second=1000,
                   temporary_bytes_per_row=700, wal_bytes_per_row=700)
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()
