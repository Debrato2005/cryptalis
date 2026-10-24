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
from profile_sqlmodel_public_slots_application import public_slots, field_frames
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
    http = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_FRESH') == '1'
    source = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE' if http else 'CRYPTALIS_SQLMODEL_APP_SOURCE')
    assert source, 'Set the application source variable for the selected pinned snapshot.'
    assert sys.version_info >= (3, 13), 'original template qualification uses Python 3.13'
    assert original.sqlmodel.__version__ == '0.0.48', 'original template qualification uses SQLModel 0.0.48'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    if http:
        from test_sqlmodel_http_application import SOURCE
        hashes = {}
        for name, expected in SOURCE['files'].items():
            raw = (Path(source) / name).read_bytes()
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
            destination = tmp_path / 'snapshot' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        backend = tmp_path / 'snapshot' / 'backend'
    else:
        backend, hashes = original.snapshot(Path(source), tmp_path / 'snapshot')
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    original.settings(monkeypatch)
    if http:
        for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
                EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
            monkeypatch.setenv(name, value)
        from app.main import app
        from sqlmodel_http_workload import workflow as http_workflow
        from sqlmodel_http_mail_workload import workflow as mail_workflow
        def workflow(factory, phase, retained=None):
            current = http_workflow(app, factory, retained=retained)
            return dict(current, local_smtp=mail_workflow(app, factory, current, monkeypatch))
        return backend, hashes, workflow
    namespace = runpy.run_path(str(Path(__file__).with_name('sqlmodel_template_workload.py')))
    return backend, hashes, namespace['workflow']


def unchanged(backend, hashes):
    root = backend.parent
    assert hashes == {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in hashes}


def clear_app():
    database = sys.modules.get('app.core.db')
    if database is not None:
        database.engine.dispose()
    for name in tuple(sys.modules):
        if name == 'app' or name.startswith('app.'):
            del sys.modules[name]


def storage(owner, *, boolean_storage=False):
    with owner.connect() as connection:
        columns = 'id,email,full_name,is_active' if boolean_storage else 'id,email,full_name'
        rows = {str(row[0]): tuple(bytes(value) if value is not None else None for value in row[1:])
            for row in connection.exec_driver_sql('SELECT ' + columns + ' FROM "user" ORDER BY id')}
        indexes = [tuple(row) for row in connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text,c.relfilenode::text FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_index i ON i.indexrelid=c.oid '
            'WHERE i.indrelid=\'"user"\'::regclass ORDER BY c.relname')]
    assert rows and all(values[0].startswith(b'CF1\0')
        and all(value is None or value.startswith(b'CF1\0') for value in values[1:]) for values in rows.values())
    return rows, indexes


def test_export_pinned_searchable_sqlmodel_current_values(tmp_path, monkeypatch):
    http = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_FRESH') == '1'
    slot_profile = os.environ.get('CRYPTALIS_SQLMODEL_PUBLIC_SLOTS') == '1'
    backend, hashes, workflow = app_copy(tmp_path, monkeypatch)
    boolean_controls = runpy.run_path(str(Path(__file__).with_name('sqlmodel_template_workload.py')))['boolean_controls'] if slot_profile and not http else None
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
        if boolean_controls:
            baseline = boolean_controls(native, baseline, uuid4().hex)
        baseline, native_search = search_controls(native, baseline)
        native_schema = catalog(owner)
        source_slots = public_slots(owner) if slot_profile else None
        dump(directory / 'plain.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        email = UUID(int=1903)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(original.TABLE), 'tenancy': {'single_tenant': True},
                'fields': [
                    {'name': 'full_name', 'field_id': str(original.FIELD), 'protect': True, 'queries': [], 'accept_leakage': []},
                    {'name': 'email', 'field_id': str(email), 'protect': True,
                     'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']}]}]}
        if slot_profile:
            declaration['models'][0]['fields'].append({'name': 'is_active', 'field_id': str(UUID(int=1904)),
                'protect': True, 'queries': [], 'accept_leakage': []})
        reviews = (SearchReview(email, False,
            'Public qualification fixtures only: independent opaque UUID128 email local parts at example.com. '
            'Equality/frequency/query and uniqueness leakage accepted only for these disposable identities. '
            'Arbitrary production email domain admission remains UNKNOWN.'),)
        inventory = WriterInventory(True, (Writer(original.TABLE, 'app', 'sqlalchemy',
            evidence='pinned unchanged official SQLModel CRUD; disposable single-tenant profile'),))
        report = preflight(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert report['status'] == 'UNKNOWN' and report['checks']['manifest_schema'] == 'PASS'
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner,
            **({'layout': 'preserve-public-slots/v1'} if slot_profile else {}), writers=inventory, search_reviews=reviews,
            keys=keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        maintenance = m.MaintenanceApproval('original app stopped; all inventoried fixture writers excluded', 3600)
        if slot_profile:
            assert proposal.document['lock']['schema'] == 'cryptalis.lock/v6'
            assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'PREPARED'),
                approval=maintenance, until='VERIFIED').phase == 'VERIFIED'
            staged = field_frames(owner, proposal.document['lock']['models'][0], staged=True)
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'PREPARED'), approval=maintenance).phase == 'PENDING'
        if slot_profile:
            assert field_frames(owner, proposal.document['lock']['models'][0], staged=False) == staged
            assert public_slots(owner, source_slots) == source_slots
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'ACTIVATING'),
            approval=maintenance, until='ACTIVE').phase == 'ACTIVE'
        factory = attach(mapping, runtime, lock=proposal.lock_bytes, keys=keys,
                         deployment=(proposal, pin(proposal, 'ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        current = workflow(attached, uuid4().hex, baseline)
        if boolean_controls:
            current = boolean_controls(attached, current, uuid4().hex)
        if slot_profile:
            assert public_slots(owner, source_slots) == source_slots
        current, protected_search = search_controls(attached, current)
        assert protected_search == native_search
        rows, _ = storage(owner, boolean_storage=slot_profile)
        if http:
            with attached() as session:
                from sqlmodel import select
                expected = {str(row.id): {'id': str(row.id), 'email': row.email,
                    'full_name': row.full_name, 'is_active': row.is_active}
                    for row in session.exec(select(User)).all()}
            assert set(rows) == set(expected)
        else:
            assert set(rows) == {baseline['id'], current['id']}
            expected = {row['id']: row for row in (baseline, current)}
        dump(directory / 'protected.sql', schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        values = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        with owner.connect() as connection:
            owner_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        manifest = {'application_profile': 'sqlmodel-http' if http else 'sqlmodel-public-slots' if slot_profile else 'sqlmodel-searchable',
            'schema': schema, 'database': values['dbname'],
            'owner_role': owner_role, 'runtime_role': role, 'application_revision': original.REVISION,
            'application_source_sha256': hashes, 'native_catalog': native_schema,
            'plan': base64.b64encode(proposal.artifact).decode(), 'pin': asdict(pin(proposal, 'ACTIVE')),
            'baseline': baseline, 'current': current, 'search_controls': protected_search,
            'expected': expected,
            'pre_adoption_doctor': report,
            'tenancy': 'one explicitly declared single-tenant table; original global email uniqueness',
            'key_custody': 'public deterministic fixture only', 'production_email_domain_admission': 'UNKNOWN',
            'gates': 'all seven UNKNOWN'}
        if slot_profile:
            manifest.update(sqlmodel_public_slots=True, source_public_slots=source_slots,
                protected_fields=['User.email', 'User.full_name', 'User.is_active'])
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
