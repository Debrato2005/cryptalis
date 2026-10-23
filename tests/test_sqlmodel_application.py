"""Opt-in pinned official SQLModel template CRUD and package-free lifecycle."""

import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

sqlmodel = pytest.importorskip('sqlmodel', reason='optional SQLModel application profile')
pytestmark = pytest.mark.skipif(sqlmodel.__version__ != '0.0.48', reason='exact SQLModel 0.0.48 profile')

import psycopg
from sqlalchemy import create_engine, event
from sqlmodel import Session

import cryptalis.deprotection as d
import cryptalis.migration as m
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys


REVISION = 'd40de23896d27d15c17a7bf9649123fd167a0aa8'
TABLE, FIELD = UUID(int=1901), UUID(int=1902)
SOURCES = {
    'LICENSE': 'f11987b50cfa15ae4f99d4c559137458c87d7a69',
    'backend/pyproject.toml': '3c876f11e0c79763713ca24424098e94bdea58d0',
    'backend/app/models.py': 'b5132e0e2c61b9f11a3fd6598adb0fe978f2fa0b',
    'backend/app/crud.py': 'a8ceba64442f852707964418256022ea2aaf00b7',
    'backend/app/core/security.py': '1e49ebc1fef8e856cce20b506481c9a2a82e8631',
    'backend/app/core/config.py': '650b9f791072476007183a5ce1b9665e5682f278',
}


def snapshot(source, directory):
    hashes = {}
    for relative, expected in SOURCES.items():
        body = (source / relative).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest() == expected
        target = directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        hashes[relative] = hashlib.sha256(body).hexdigest()
    assert b'MIT License' in (directory / 'LICENSE').read_bytes()
    return directory / 'backend', hashes


def native_engine(variable, schema):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(os.environ[variable], options='-csearch_path=' + schema))


def settings(monkeypatch):
    for name, value in dict(PROJECT_NAME='Cryptalis disposable template profile',
        POSTGRES_SERVER='unused.invalid', POSTGRES_USER='unused', POSTGRES_PASSWORD='PUBLIC unused',
        FIRST_SUPERUSER='owner@example.com', FIRST_SUPERUSER_PASSWORD='PUBLIC unused password',
        SECRET_KEY='PUBLIC disposable configuration key 2026').items():
        monkeypatch.setenv(name, value)


def test_unchanged_template_user_crud_protects_and_restarts_without_cryptalis(tmp_path, monkeypatch):
    run_application(tmp_path, monkeypatch)


def run_application(tmp_path, monkeypatch, *, searchable_email=False):
    source = os.environ.get('CRYPTALIS_SQLMODEL_APP_SOURCE')
    if not source:
        pytest.skip('set CRYPTALIS_SQLMODEL_APP_SOURCE to the pinned official source snapshot')
    assert sys.version_info >= (3, 13), 'qualification profile uses Python 3.13'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    backend, hashes = snapshot(Path(source), tmp_path / 'snapshot')
    monkeypatch.syspath_prepend(str(backend))
    empty = tmp_path / 'empty' / 'cwd'
    empty.mkdir(parents=True)
    monkeypatch.chdir(empty)
    settings(monkeypatch)
    schema = 'sqlmodel_template_' + uuid4().hex
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = None
    try:
        from app.models import SQLModel, User
        from cryptalis.sqlmodel import attach
        mapping = User._sa_registry
        spec = importlib.util.spec_from_file_location('sqlmodel_template_workload',
            Path(__file__).with_name('sqlmodel_template_workload.py'))
        workload = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(workload)
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
        baseline = workload.workflow(native, uuid4().hex if searchable_email else 'native')
        if searchable_email:
            from profile_sqlmodel_searchable_application import search_controls, native_catalog
            baseline, native_search = search_controls(native, baseline)
            source_catalog = native_catalog(owner)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(TABLE), 'tenancy': {'single_tenant': True},
                        'fields': [{'name': 'full_name', 'field_id': str(FIELD), 'protect': True,
                                    'queries': [], 'accept_leakage': []}]}]}
        reviews = ()
        if searchable_email:
            email_field = UUID(int=1903)
            declaration['models'][0]['fields'].append({'name': 'email', 'field_id': str(email_field),
                'protect': True, 'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']})
            reviews = (SearchReview(email_field, False,
                'Qualification fixture only: independent opaque UUID128 local parts under example.com; '
                'equality/frequency/query and uniqueness leakage accepted for public disposable identities. '
                'This is not a review of arbitrary production email domains.'),)
        from cryptalis.doctor import preflight
        inventory = WriterInventory(True, (Writer(TABLE, 'app', 'sqlalchemy',
            evidence='pinned unchanged official template CRUD; isolated profile'),))
        report = preflight(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert report['scope'] == 'pre_adoption' and report['effects'] == 'NONE'
        assert report['status'] == 'UNKNOWN' and report['checks']['manifest_schema'] == 'PASS', report['issues']
        assert report['checks']['provider_keys'] == 'UNKNOWN'
        assert report['checks']['query_routes'] == 'UNKNOWN'
        invalid = json.loads(json.dumps(declaration))
        invalid['models'][0]['tenancy'] = {'column': 'missing_tenant_column'}
        refused = preflight(json.dumps(invalid).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert refused['status'] == 'FAIL' and refused['issues']
        assert all(issue['code'] and issue['location'] and issue['remedy'] for issue in refused['issues'])
        assert refused['checks']['provider_keys'] == 'UNKNOWN'
        from sqlalchemy.exc import OperationalError
        def unavailable():
            raise OperationalError('PRIVATE_DOCTOR_STATEMENT', {},
                                   psycopg.OperationalError('PRIVATE_DOCTOR_CONNECTION'))
        with monkeypatch.context() as outage:
            outage.setattr(owner, 'connect', unavailable)
            unavailable_report = preflight(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert unavailable_report['status'] == 'UNKNOWN'
        assert unavailable_report['checks']['manifest_schema'] == 'UNKNOWN'
        assert unavailable_report['issues'][0]['code'] == 'inspection_unavailable'
        assert 'PRIVATE_DOCTOR' not in json.dumps(unavailable_report)
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner,
            writers=inventory, search_reviews=reviews,
            keys=keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        if searchable_email:
            from test_default_collation import serialized_refusals
            serialized_refusals(proposal)
        approval = m.MaintenanceApproval('disposable app stopped; inventoried writers excluded', 3600)
        def pin(phase):
            return m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, phase)
        assert m.apply(proposal, owner, keys=keys, pin=pin('PREPARED'), approval=approval).phase == 'PENDING'
        assert m.apply(proposal, owner, keys=keys, pin=pin('ACTIVATING'), approval=approval, until='ACTIVE').phase == 'ACTIVE'
        active = pin('ACTIVE')
        attached = attach(mapping, runtime, lock=proposal.lock_bytes, keys=keys, deployment=(proposal, active))
        observed = []
        def capture(connection, cursor, statement, values, context, many):
            observed.append(repr(values))
        event.listen(runtime, 'before_cursor_execute', capture)
        try:
            current = workload.workflow(lambda: attached(tenant_id=TABLE, expire_on_commit=False),
                uuid4().hex if searchable_email else 'protected', baseline)
            if searchable_email:
                current, protected_search = search_controls(
                    lambda: attached(tenant_id=TABLE, expire_on_commit=False), current)
                assert native_search == protected_search
                from cryptalis.sqlalchemy import PolicyMismatch
                with pytest.raises(PolicyMismatch):
                    with attached(tenant_id=uuid4()) as wrong_scope:
                        wrong_scope.get(User, UUID(current['id']))
        finally:
            event.remove(runtime, 'before_cursor_execute', capture)
        assert 'private-name-' not in ''.join(observed)
        if searchable_email:
            assert '@example.com' not in ''.join(observed)
        with owner.connect() as connection:
            values = connection.exec_driver_sql('SELECT full_name FROM "user"').scalars().all()
            assert len(values) == 2 and all(bytes(value).startswith(b'CF1\0') for value in values)
        if searchable_email:
            with owner.connect() as connection:
                email_frames = connection.exec_driver_sql('SELECT email FROM "user"').scalars().all()
                assert len(email_frames) == 2 and all(bytes(value).startswith(b'CF1\0') for value in email_frames)
        reverse = d.plan(proposal, owner, source_pin=active, keys=keys,
            plaintext_runtime_role=least_privilege_role(SimpleNamespace(owner=owner, role=role)),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'public disposable test values; no historical protected backup')
        def reverse_pin(phase):
            return m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, phase)
        assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PREPARED'), approval=approval,
                       consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PLAINTEXT_ACTIVATING'), approval=approval,
                       consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'fresh unchanged template CRUD with Cryptalis imports denied', 'public disposable values', True)
        assert d.remove(reverse, owner, pin=reverse_pin('REMOVING'), approval=approval,
                        removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=reverse_pin('REMOVED')) is None
        with owner.connect() as connection:
            assert connection.exec_driver_sql("SELECT character_maximum_length FROM information_schema.columns "
                "WHERE table_schema=%s AND table_name='user' AND column_name='full_name'", (schema,)).scalar_one() == 255
        if searchable_email:
            assert native_catalog(owner) == source_catalog
        child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, runpy, sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
sys.path[:0] = json.loads(os.environ['SQLMODEL_CHILD_PATHS'])
import psycopg
from sqlalchemy import create_engine
from sqlmodel import Session
namespace = runpy.run_path(os.environ['SQLMODEL_WORKLOAD_HELPER'])
engine = create_engine('postgresql+psycopg://', hide_parameters=True,
    creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
        options='-csearch_path=' + os.environ['SQLMODEL_SCHEMA']))
try:
    namespace['workflow'](lambda: Session(engine, expire_on_commit=False), os.environ['SQLMODEL_CHILD_PHASE'],
                          json.loads(os.environ['SQLMODEL_CURRENT']))
finally:
    engine.dispose()
assert not any(n == 'cryptalis' or n.startswith('cryptalis.') for n in sys.modules)
print(json.dumps({'native_crud': 'passed', 'cryptalis_imported': False}))
'''], env=dict(os.environ, SQLMODEL_CHILD_PATHS=json.dumps(sys.path), SQLMODEL_SCHEMA=schema,
            SQLMODEL_CURRENT=json.dumps(current),
            SQLMODEL_CHILD_PHASE=uuid4().hex if searchable_email else 'package-free', SQLMODEL_WORKLOAD_HELPER=str(
                Path(__file__).with_name('sqlmodel_template_workload.py').resolve())),
            cwd=empty, capture_output=True, text=True, timeout=60)
        assert child.returncode == 0, 'package-free template CRUD failed; diagnostics suppressed'
        assert json.loads(child.stdout) == {'native_crud': 'passed', 'cryptalis_imported': False}
        assert hashes == {relative: hashlib.sha256((tmp_path / 'snapshot' / relative).read_bytes()).hexdigest()
                          for relative in SOURCES}
        evidence = os.environ.get('CRYPTALIS_SQLMODEL_APP_RECEIPT')
        if evidence:
            with Path(evidence).open('x') as stream:
                json.dump({'application_revision': REVISION, 'application_release': '0.10.0',
                    'application_source_sha256': hashes, 'model_changes': [], 'query_changes': [],
                    'protected_fields': ['User.full_name', 'User.email'] if searchable_email else ['User.full_name'],
                    'profile': 'fixture-only email equality/IN/unique; explicit single tenant' if searchable_email else 'storage-only; explicit single tenant',
                    'crud': 'unchanged native/protected/package-free create/get/update/delete; real password hashing',
                    'application_boundary': 'CRUD modules only; HTTP endpoints/startup/authentication not qualified',
                    'runtime': {name: importlib.metadata.version(name) for name in (
                        'sqlmodel', 'pydantic', 'SQLAlchemy', 'greenlet', 'psycopg', 'cryptography')},
                    'python': sys.version.split()[0], 'psycopg_impl': psycopg.pq.__impl__,
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        if mapping is not None:
            mapping.dispose()
            mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
