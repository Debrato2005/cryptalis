"""Export the pinned searchable SQLModel app through public protection APIs."""
import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
from uuid import UUID, uuid4

import psycopg
import pytest
pytest.importorskip('sqlmodel', reason='optional pinned SQLModel searchable application')
from sqlmodel import Session

from cryptalis import migration as m
from cryptalis.doctor import preflight
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlmodel import attach
from test_migration import DOMAIN, keys
import test_sqlmodel_application as original
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from test_fresh_cluster_export import dump, environment

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run the --sqlmodel-searchable fresh-cluster profile', allow_module_level=True)


def pin(plan, phase):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def catalog(owner):
    result = {key: [list(row) for row in rows] for key, rows in native_catalog(owner).items()}
    with owner.connect() as connection:
        result['schema_columns'] = [list(row) for row in connection.exec_driver_sql(
            "SELECT table_name,column_name,data_type,character_maximum_length,is_nullable,column_default "
            "FROM information_schema.columns WHERE table_schema=current_schema() ORDER BY table_name,column_name")]
        result['schema_constraints'] = [list(row) for row in connection.exec_driver_sql(
            "SELECT t.relname,c.conname,pg_catalog.pg_get_constraintdef(c.oid) FROM pg_catalog.pg_constraint c "
            "JOIN pg_catalog.pg_class t ON t.oid=c.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace "
            "WHERE n.nspname=current_schema() ORDER BY t.relname,c.conname")]
        result['schema_indexes'] = [list(row) for row in connection.exec_driver_sql(
            "SELECT tablename,indexname,indexdef FROM pg_catalog.pg_indexes "
            "WHERE schemaname=current_schema() ORDER BY tablename,indexname")]
    return result


def app_copy(tmp_path, monkeypatch):
    source = os.environ.get('CRYPTALIS_SQLMODEL_APP_SOURCE')
    assert source, 'set CRYPTALIS_SQLMODEL_APP_SOURCE to the pinned six-file snapshot'
    assert sys.version_info >= (3, 13), 'original template qualification uses Python 3.13'
    assert original.sqlmodel.__version__ == '0.0.48', 'original template qualification uses SQLModel 0.0.48'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    backend, hashes = original.snapshot(Path(source), tmp_path / 'snapshot')
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    original.settings(monkeypatch)
    namespace = runpy.run_path(str(Path(__file__).with_name('sqlmodel_template_workload.py')))
    return backend, hashes, namespace['workflow']


def unchanged(backend, hashes):
    root = backend.parent
    assert hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in original.SOURCES}


def clear_app():
    for name in tuple(sys.modules):
        if name == 'app' or name.startswith('app.'):
            del sys.modules[name]


def storage(owner):
    with owner.connect() as connection:
        rows = {str(identity): (bytes(email), bytes(name) if name is not None else None)
            for identity, email, name in connection.exec_driver_sql('SELECT id,email,full_name FROM "user" ORDER BY id')}
        indexes = [tuple(row) for row in connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid '
            'WHERE i.indrelid=\'"user"\'::regclass ORDER BY c.relname')]
    assert rows and all(email.startswith(b'CF1\0') and (name is None or name.startswith(b'CF1\0'))
                        for email, name in rows.values())
    return rows, indexes


def test_export_pinned_searchable_sqlmodel_current_values(tmp_path, monkeypatch):
    backend, hashes, workflow = app_copy(tmp_path, monkeypatch)
    from app.models import SQLModel, User
    schema = 'sqlmodel_search_fresh_' + uuid4().hex
    owner = original.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = User._sa_registry
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        SQLModel.metadata.create_all(owner)
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            q = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {q(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {q(role)}')
        native = lambda: Session(runtime, expire_on_commit=False)
        baseline = workflow(native, uuid4().hex)
        baseline, native_search = search_controls(native, baseline)
        native_schema = catalog(owner)
        dump(directory / 'plain.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        email = UUID(int=1903)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(original.TABLE), 'tenancy': {'single_tenant': True},
                'fields': [
                    {'name': 'full_name', 'field_id': str(original.FIELD), 'protect': True, 'queries': [], 'accept_leakage': []},
                    {'name': 'email', 'field_id': str(email), 'protect': True,
                     'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']}]}]}
        reviews = (SearchReview(email, False,
            'Public qualification fixtures only: independent opaque UUID128 email local parts at example.com. '
            'Equality/frequency/query and uniqueness leakage accepted only for these disposable identities. '
            'Arbitrary production email domain admission remains UNKNOWN.'),)
        inventory = WriterInventory(True, (Writer(original.TABLE, 'app', 'sqlalchemy',
            evidence='pinned unchanged official SQLModel CRUD; disposable single-tenant profile'),))
        report = preflight(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert report['status'] == 'UNKNOWN' and report['checks']['manifest_schema'] == 'PASS'
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews,
            keys=keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        maintenance = m.MaintenanceApproval('original app stopped; all inventoried fixture writers excluded', 3600)
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'PREPARED'), approval=maintenance).phase == 'PENDING'
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'ACTIVATING'),
            approval=maintenance, until='ACTIVE').phase == 'ACTIVE'
        factory = attach(mapping, runtime, lock=proposal.lock_bytes, keys=keys,
                         deployment=(proposal, pin(proposal, 'ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        current = workflow(attached, uuid4().hex, baseline)
        current, protected_search = search_controls(attached, current)
        assert protected_search == native_search
        rows, _ = storage(owner)
        assert set(rows) == {baseline['id'], current['id']}
        dump(directory / 'protected.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        values = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        with owner.connect() as connection:
            owner_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        manifest = {'application_profile': 'sqlmodel-searchable', 'schema': schema, 'database': values['dbname'],
            'owner_role': owner_role, 'runtime_role': role, 'application_revision': original.REVISION,
            'application_source_sha256': hashes, 'native_catalog': native_schema,
            'plan': base64.b64encode(proposal.artifact).decode(), 'pin': asdict(pin(proposal, 'ACTIVE')),
            'baseline': baseline, 'current': current, 'search_controls': protected_search,
            'expected': {row['id']: row for row in (baseline, current)},
            'tenancy': 'one explicitly declared single-tenant table; original global email uniqueness',
            'key_custody': 'public deterministic fixture only', 'production_email_domain_admission': 'UNKNOWN',
            'gates': 'all seven UNKNOWN'}
        with (directory / 'restore-manifest.json').open('x') as stream:
            json.dump(manifest, stream, indent=2, default=str)
        unchanged(backend, hashes)
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()
        clear_app()
