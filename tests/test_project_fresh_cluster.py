"""Project recovery on a genuinely restored cluster. Run with fresh_cluster_qualification.py --project."""
import json
import os
from pathlib import Path
import subprocess
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, Index, Integer, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import Project
from cryptalis.crypto import DevelopmentKeyProvider
from cryptalis.migration import TransitionFailure
from cryptalis.sqlalchemy import PolicyMismatch
from test_fresh_cluster_export import dump, environment as dump_environment
from test_migration import engine

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --project', allow_module_level=True)

WORKDIR = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
STATE = WORKDIR / 'project-state'
SCHEMA = 'cryptalis_project_fresh'
TENANT = UUID(int=9100)
STOPPED = 'Fixture writers are stopped; the attached application is the only writer.'
MANIFEST = json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(UUID(int=9101)),
    'models': [{'model': 'Customer', 'table_id': str(UUID(int=9102)), 'tenancy': {'column': 'tenant_id'},
        'fields': [{'name': 'name', 'field_id': str(UUID(int=9103)), 'protect': True,
                    'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']},
                   {'name': 'amount', 'field_id': str(UUID(int=9105)), 'protect': True,
                    'queries': ['equality', 'order'], 'accept_leakage': ['equality', 'order']}]}]}).encode()


class PublicKeyProvider(DevelopmentKeyProvider):
    """PUBLIC TEST KEY that survives between processes, as a real provider's custody does."""

    def __init__(self):
        super().__init__()
        self.provider_id, self._key = UUID(int=9104), b'PUBLIC FRESH CLUSTER TEST KEY 32'


def process():
    mapping = registry(metadata=MetaData(schema=SCHEMA))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')), Column('amount', Integer))
    Index('native_name', table.c.tenant_id, table.c.name, unique=True)
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    project = Project(MANIFEST, mapping, provider=PublicKeyProvider(), state_dir=STATE)
    return project, Customer, mapping


def test_export_project_source():
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    parsed = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
    runtime_role = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])['user']
    project, Customer, mapping = process()
    rows = {str(UUID(int=number)): f'customer-{number}' for number in range(9200, 9207)}
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
            connection.exec_driver_sql(f'CREATE SCHEMA "{SCHEMA}"')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{SCHEMA}" TO "{runtime_role}"')
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{SCHEMA}".customer TO "{runtime_role}"')
        with sessionmaker(owner)() as session:
            session.add_all(Customer(id=UUID(key), tenant_id=TENANT, name=name, amount=UUID(key).int - 9203)
                            for key, name in rows.items())
            session.commit()
        project.protect(owner, runtime_role=runtime_role, writers_stopped=STOPPED, search_reviewed='Fixture names are not enumerable.')
        sessions = project.attach(runtime)
        edited = str(UUID(int=9201))
        with sessions(tenant_id=TENANT) as session:
            session.get(Customer, UUID(edited)).name = rows[edited] = 'edited while protected'
            session.commit()
        dump(WORKDIR / 'protected.sql', SCHEMA, dump_environment('CRYPTALIS_TEST_DATABASE_URL'))
        (WORKDIR / 'restore-manifest.json').write_text(json.dumps({
            'database': parsed['dbname'], 'owner_role': parsed['user'], 'runtime_role': runtime_role,
            'schema': SCHEMA, 'rows': rows, 'rewrapped': False, 'payload_rotated': False, 'search_rotated': False}))
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{SCHEMA}" CASCADE')
        owner.dispose()
        mapping.dispose()


def test_recover_project_on_fresh_cluster():
    values = dump_environment('CRYPTALIS_TEST_DATABASE_URL')
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(WORKDIR / 'protected.sql')],
                            env=values, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'psql restore failed (diagnostics withheld)'
    expected = json.loads((WORKDIR / 'restore-manifest.json').read_text())['rows']
    owner, runtime_engines = engine('CRYPTALIS_TEST_DATABASE_URL'), []
    def runtime():
        runtime_engines.append(engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL'))
        return runtime_engines[-1]
    def read(project, Customer):
        with project.attach(runtime())(tenant_id=TENANT) as session:
            return {str(row.id): row.name for row in session.scalars(select(Customer))}
    try:
        # A restored copy must not authorize itself.
        project, Customer, _ = process()
        with pytest.raises((PolicyMismatch, TransitionFailure)):
            project.attach(runtime())
        approval = dict(host='qualification host', quarantine='Isolated fresh cluster.')
        with pytest.raises(TransitionFailure, match='restore_approval_required'):
            process()[0].recover(owner, source_fenced=False, **approval)
        process()[0].recover(owner, source_fenced=True, **approval)

        project, Customer, _ = process()
        assert read(project, Customer) == expected
        project, Customer, _ = process()
        with project.attach(runtime())(tenant_id=TENANT) as session:
            found = session.scalars(select(Customer.id).where(Customer.name == 'edited while protected')).all()
            assert found == [UUID(int=9201)]
            # Range and sort keep working on the restored frames: amounts run from -3 to 3.
            assert session.scalars(select(Customer.amount).where(Customer.tenant_id == TENANT, Customer.amount >= 1)
                                   .order_by(Customer.amount.desc())).all() == [3, 2, 1]
            session.get(Customer, UUID(int=9202)).name = expected[str(UUID(int=9202))] = 'edited after recovery'
            session.commit()

        process()[0].rotate(owner, 'payload', writers_stopped=STOPPED)
        project, Customer, _ = process()
        assert read(project, Customer) == expected

        inputs = dict(writers_stopped=STOPPED)
        assert process()[0].decrypt(owner, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'], accept_plaintext=True,
            retained_backups='The retained state and provider can still read earlier backups.', **inputs).phase == 'PLAINTEXT_ACTIVE'
        removed = process()[0].remove(owner, application_verified='Latest values compared below.', old_workers_stopped=True, **inputs)
        assert removed.phase == 'REMOVED'
    finally:
        for created in runtime_engines:
            created.dispose()
        owner.dispose()
    # The native table now holds the latest committed values in plaintext.
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        with owner.connect() as connection:
            assert {str(row[0]): row[1] for row in connection.exec_driver_sql(
                f'SELECT id, name FROM "{SCHEMA}".customer')} == expected
            assert [row[0] for row in connection.exec_driver_sql(
                f'SELECT amount FROM "{SCHEMA}".customer ORDER BY amount')] == list(range(-3, 4))
    finally:
        owner.dispose()
