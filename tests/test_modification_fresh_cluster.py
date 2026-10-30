"""Real backup/adoption and package-free exit after active search modification."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry

from cryptalis import deprotection as d, migration as m, restore as recovery
from test_application_modification import configured_change, propose, activate_change
from test_deprotection import app_pin, consent
from test_migration import application, engine, keys, publish, run, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --modification', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump


def wire(values):
    return {str(identity): value for identity, value in values.items()}


def test_export_modified_backup():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        expected = {identity: value for identity, (_, value) in app.source.items()}
        source = wire(expected)
        dump(directory / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        activate_change(configured, app, propose(configured, app))
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = 'latest before modified backup'
            session.commit()
        expected[UUID(int=101)] = 'latest before modified backup'
        dump(directory / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = dict(application_profile='active-search-modification', schema=app.schema,
            database=owner['dbname'], owner_role=owner['user'], runtime_role=runtime['user'],
            source=source, expected=wire(expected), plan=base64.b64encode(app.plan.artifact).decode(),
            pin=dict(target_id=str(app.pin.target_id), operation_id=str(app.pin.operation_id),
                     plan_digest=app.pin.plan_digest, phase=app.pin.phase))
    (directory / 'restore-manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')


def test_restore_modified_backup_authenticate_and_remove_current_values():
    from cryptalis.application import ApplicationConfig
    from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'active-search-modification'
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        assert wire(dict(connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall())) == manifest['source']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    pin = app_pin(source, 'ACTIVE')
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    lock = source.document['lock']
    configured = ApplicationConfig(json.dumps(lock['declaration']).encode(), mapping,
        WriterInventory(True, tuple(Writer(UUID(x['table_id']), x['name'], x['route'], x['excluded'], x['evidence'])
            for x in lock['writer_inventory']['writers'])),
        tuple(SearchReview(UUID(x['field_id']), x['small_domain'], x['evidence']) for x in lock['search_reviews']))
    maintenance = m.MaintenanceApproval('source schema removed; isolated target excludes all writers', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt modified protected backup',
        'source schema dropped and fresh target quarantined', True)
    try:
        with pytest.raises(m.TransitionFailure): m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            frame = bytes(connection.exec_driver_sql(f'SELECT name FROM "{schema}".customer WHERE id=%s', (UUID(int=101),)).scalar_one())
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                (frame[:-1] + bytes([frame[-1] ^ 1]), UUID(int=101)))
        with pytest.raises(m.TransitionFailure): recovery.plan(source, owner, pin=pin, keys=keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, UUID(int=101)))
        binding = recovery.plan(source, owner, pin=pin, keys=keys, approval=intent)
        factory = configured.attach(runtime, deployment=(source, pin, binding), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert wire({row.id: row.name for row in session.scalars(select(Customer))}) == manifest['expected']
            assert session.scalar(select(Customer.id).where(Customer.name == 'latest before modified backup')) == UUID(int=101)
            session.get(Customer, UUID(int=101)).name = 'latest after restored modification'
            session.commit()
        reverse = configured.plan_deprotection(owner, deployment=(source, pin, binding), keys=keys,
            plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        approval, reverse_pin = consent(reverse)
        configured.decrypt_back(owner, deployment=(reverse, reverse_pin), keys=keys,
            approval=maintenance, consent=approval)
        configured.decrypt_back(owner, deployment=(reverse, app_pin(reverse, 'PLAINTEXT_ACTIVATING')),
            keys=keys, approval=maintenance, consent=approval, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'native current-value verification', 'retained synthetic backup and public fixture roots', True)
        configured.remove(owner, deployment=(reverse, app_pin(reverse, 'REMOVING')),
            approval=maintenance, consent=approval, removal=removal)
        expected = dict(manifest['expected']); expected[str(UUID(int=101))] = 'latest after restored modification'
        child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from psycopg import sql
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    rows = connection.execute(sql.SQL('SELECT id,name FROM {}.customer').format(sql.Identifier(os.environ['MOD_SCHEMA']))).fetchall()
    assert {str(k): v for k, v in rows} == json.loads(os.environ['MOD_EXPECTED'])
    assert all(v is None or type(v) is str for _, v in rows)
    connection.execute(sql.SQL('UPDATE {}.customer SET name=%s WHERE id=%s').format(sql.Identifier(os.environ['MOD_SCHEMA'])), ('native edit', rows[0][0]))
assert not any(n == 'cryptalis' or n.startswith('cryptalis.') for n in sys.modules)
print('native package-free exit passed')
'''], env=dict(os.environ, MOD_SCHEMA=schema, MOD_EXPECTED=json.dumps(expected)), cwd=directory,
            capture_output=True, text=True, timeout=30)
        assert child.returncode == 0, 'package-free exit failed; diagnostics withheld'
        assert child.stdout.strip() == 'native package-free exit passed'
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
