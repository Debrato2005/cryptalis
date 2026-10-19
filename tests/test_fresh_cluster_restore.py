"""Fresh-cluster recovery evidence for a restored protected schema.

This module runs against a newly initialized PostgreSQL 16 cluster with a
temporary HOME credential pair. It proves native readability of a plaintext
pre-protection backup, frame-level recovery of a protected backup with the
retained key policy and reader path, loud refusal of the restored journal as
current authority, and the full adopted lifecycle: explicit fenced restore
approval, a verified ``cryptalis.restore/v1`` binding, attached reads and
exact search, protected modifications, decrypt-back, and approved removal.
"""
import base64
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import subprocess
import uuid

import psycopg
import pytest
from sqlalchemy import Column, Index, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry

import cryptalis.migration as m
import cryptalis.restore as r
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.manifest.compiler import _canonical
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_migration import engine, independent_open, keys, TENANT

d = importlib.import_module('cryptalis.deprotection')

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


def artifacts():
    source = m.MigrationPlan(base64.b64decode(MANIFEST['plan']))
    pin = m.DeploymentPin(uuid.UUID(MANIFEST['pin']['target_id']), uuid.UUID(MANIFEST['pin']['operation_id']),
                          MANIFEST['pin']['plan_digest'], MANIFEST['pin']['phase'])
    return source, pin


def customer_mapping():
    mapping = registry(metadata=MetaData(schema=SCHEMA))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    Index('native_name', table.c.tenant_id, table.c.name, unique=True)
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    return mapping, Customer


def approval():
    return r.RestoreApproval('qualification host', 'authorize the restored protected copy',
                                   'source cluster fenced and quarantined during restore test', True)


def flip_name_byte(identity):
    column = f'"{MANIFEST["column"]}"'
    statement = (f'UPDATE "{SCHEMA}".customer SET {column}=pg_catalog.set_byte({column},'
                 f'octet_length({column})-1,pg_catalog.get_byte({column},octet_length({column})-1) # 1) '
                 'WHERE id=%s')
    with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
        c.execute(statement, (identity,))
        c.commit()


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


def test_restore_adoption_requires_explicit_fenced_approval():
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            r.plan(source, owner, pin=pin, keys=keys, approval=None)
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            r.plan(source, owner, pin=pin, keys=keys, approval=replace(approval(), source_fenced=False))
        with pytest.raises(m.TransitionFailure, match='source_pin_must_be_active'):
            r.plan(source, owner, pin=replace(pin, phase='PENDING'), keys=keys, approval=approval())
        with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
            r.plan(source, owner, pin=replace(pin, plan_digest='0' * 64), keys=keys, approval=approval())
    finally:
        owner.dispose()


def test_restored_target_refuses_corrupt_frames_and_tampered_bindings():
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    identity = uuid.UUID(int=101)
    flip_name_byte(identity)
    try:
        with pytest.raises(m.TransitionFailure, match='restored_frame_verification_failed'):
            r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    finally:
        flip_name_byte(identity)
    try:
        binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        assert binding.source_plan_digest == source.digest
        assert binding.source_target == source.document['target']
        assert binding.target[:-1] != source.document['target'][:-1]
        assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
        document = binding.document
        bad_state = r.RestoreBinding(_canonical({**document, 'journal_state_digest': '0' * 64}))
        with pytest.raises(m.TransitionFailure, match='restored_state_changed'):
            m.check_deployment(source, owner, pin=pin, restore=bad_state)
        document = binding.document
        document['target'] = [document['target'][0], '0'] + document['target'][2:]
        bad_target = r.RestoreBinding(_canonical(document))
        with pytest.raises(m.TransitionFailure, match='restore_target_mismatch'):
            m.check_deployment(source, owner, pin=pin, restore=bad_target)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, bad_state))
        with pytest.raises(m.TransitionFailure, match='restore_binding_mismatch'):
            m.check_deployment(source, owner, pin=pin,
                               restore=r.RestoreBinding(_canonical({
                                   **binding.document, 'source': {**binding.document['source'],
                                                                  'plan_digest': '0' * 64}})))
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()


def test_restored_target_refuses_post_adoption_drift():
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    table = f'"{SCHEMA}".customer'
    field_id = source.document['lock']['models'][0]['fields'][0]['field_id']
    frame = '_cryptalis_' + uuid.UUID(field_id).hex + '_frame'
    definition = binding.document['restatements'][0]['definition']
    weakened = definition.replace('>= 74', '>= 73')
    assert weakened != definition
    with owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {weakened}')
    try:
        with pytest.raises(m.TransitionFailure, match='restored_schema_changed'):
            m.check_deployment(source, owner, pin=pin, restore=binding)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {definition}')
    with owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} CHECK (true)')
    try:
        with pytest.raises(m.TransitionFailure, match='restored_schema_mismatch'):
            m.check_deployment(source, owner, pin=pin, restore=binding)
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {definition}')
    journal = f'"{MANIFEST["journal_schema"]}"."_cryptalis_journal"'
    with owner.begin() as c:
        c.exec_driver_sql(f"""UPDATE {journal} SET state = state || '{{"drift": true}}'::jsonb""")
    try:
        with pytest.raises(m.TransitionFailure, match='restored_state_changed'):
            m.check_deployment(source, owner, pin=pin, restore=binding)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f"UPDATE {journal} SET state = state - 'drift'")
    try:
        assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()


def test_restored_cluster_completes_adopted_lifecycle():
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
    with runtime.connect() as c:
        assert m.check_attachment(c, source.lock_bytes, (source, pin, binding)) is None
    sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    with sessions(tenant_id=TENANT) as session:
        observed = {str(row.id): [str(row.tenant_id), row.name] for row in session.scalars(select(Customer))}
        found = [row.id for row in session.scalars(
            select(Customer).where(Customer.name == 'edited while protected'))]
    assert observed == MANIFEST['expected']
    assert found == [uuid.UUID(int=101)]
    with sessions(tenant_id=TENANT) as session:
        session.get(Customer, uuid.UUID(int=101)).name = 'edited on restored copy'
        session.commit()
        session.add(Customer(id=uuid.UUID(int=1000), tenant_id=TENANT,
                             name='added on restored copy', label='restored'))
        session.commit()
        session.delete(session.get(Customer, uuid.UUID(int=999)))
        session.commit()
    runtime.dispose()
    proposal = d.plan(source, owner, source_pin=pin, keys=keys,
                      plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
                      backfill_rows_per_second=1000, verify_rows_per_second=1000,
                      temporary_bytes_per_row=700, wal_bytes_per_row=700, restore=binding)
    assert proposal.document['restore']['adoption_id'] == binding.document['adoption_id']
    reverse_pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    consent = d.PlaintextApproval(proposal.target_id, proposal.operation_id, proposal.digest, True,
                                  'fresh-cluster retained backup recovery')
    maintenance = m.MaintenanceApproval('fresh-cluster qualification stopped and excluded writers', 3600)
    try:
        assert d.apply(proposal, owner, keys=keys, pin=reverse_pin, approval=maintenance,
                       consent=consent, chunk_size=2).phase == 'PLAINTEXT_PENDING'
        assert d.apply(proposal, owner, keys=keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
                       approval=maintenance, consent=consent, chunk_size=2,
                       until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
                                    'fresh-cluster package-free psycopg workload',
                                    'fresh-cluster retained backup recovery', True)
        assert d.remove(proposal, owner, pin=replace(reverse_pin, phase='REMOVING'),
                        approval=maintenance, removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(proposal, owner, pin=replace(reverse_pin, phase='REMOVED')) is None
        expected = dict(MANIFEST['expected'])
        expected[str(uuid.UUID(int=101))] = [str(TENANT), 'edited on restored copy']
        expected[str(uuid.UUID(int=1000))] = [str(TENANT), 'added on restored copy']
        del expected[str(uuid.UUID(int=999))]
        with psycopg.connect(**environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')) as c:
            observed = {str(identity): [str(tenant), value] for identity, tenant, value in c.execute(
                f'SELECT id, tenant_id, name FROM "{SCHEMA}".customer')}
            kind = c.execute('SELECT data_type FROM information_schema.columns WHERE table_schema=%s '
                             'AND table_name=%s AND column_name=%s', (SCHEMA, 'customer', 'name')).fetchone()[0]
        assert observed == expected
        assert kind == 'text'
        with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
            assert c.execute('SELECT pg_catalog.to_regclass(%s)',
                             (f'{MANIFEST["journal_schema"]}.{m.JOURNAL}',)).fetchone()[0] is None
    finally:
        owner.dispose()
        mapping.dispose()
