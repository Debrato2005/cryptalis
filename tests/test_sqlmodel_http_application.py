"""Unchanged pinned FastAPI authentication over encrypted SQLModel user fields."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

pytest.importorskip('sqlmodel', reason='optional SQLModel HTTP application profile')
pytest.importorskip('fastapi', reason='optional original FastAPI HTTP application profile')

from sqlmodel import Session

from cryptalis import deprotection as d
from cryptalis import migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlmodel import attach
from test_migration import DOMAIN, keys
from test_deprotection import least_privilege_role
from test_sqlmodel_application import native_engine, settings, TABLE, FIELD

SOURCE = json.loads((Path(__file__).parent / 'fixtures/sqlmodel_http_source.json').read_text())


from sqlmodel_http_workload import workflow as http_workflow
from sqlmodel_http_mail_workload import workflow as mail_workflow


def test_original_http_jwt_identity_and_encrypted_user_fields(tmp_path, monkeypatch):
    location = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    if not location:
        pytest.skip('set CRYPTALIS_SQLMODEL_HTTP_SOURCE to the pinned complete HTTP snapshot')
    assert sys.version_info >= (3, 13)
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    source, copied = Path(location), tmp_path / 'original'
    hashes = {}
    for rel, expected in SOURCE['files'].items():
        raw = (source / rel).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        target = copied / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        hashes[rel] = hashlib.sha256(raw).hexdigest()
    monkeypatch.syspath_prepend(str(copied / 'backend'))
    monkeypatch.chdir(tmp_path)
    settings(monkeypatch)
    for name,value in dict(ENVIRONMENT='local',SMTP_HOST='',SMTP_USER='',SMTP_PASSWORD='',
                           EMAILS_FROM_EMAIL='',SENTRY_DSN='',FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name,value)
    schema = 'sqlmodel_http_' + uuid4().hex
    owner, runtime = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema), native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = original_engine = None
    try:
        from app.models import SQLModel, User
        from app.main import app as api
        from app.core.db import engine as original_engine
        mapping = User._sa_registry
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        SQLModel.metadata.create_all(owner)
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {quote(role)}')
        native = http_workflow(api, lambda: Session(runtime))
        assert native['is_active'] is True
        native_mail = mail_workflow(api, lambda: Session(runtime), native, monkeypatch)
        assert native_mail['smtp_messages'] == 4
        from uuid import UUID
        email_field, active_field = UUID(int=1903), UUID(int=1904)
        declaration = {'schema':'cryptalis.protection/v1', 'profile':'cf1','domain_id':str(DOMAIN),
            'models':[{'model':'User','table_id':str(TABLE),'tenancy':{'single_tenant':True},'fields':[
                {'name':'full_name','field_id':str(FIELD),'protect':True,'queries':[],'accept_leakage':[]},
                {'name':'email','field_id':str(email_field),'protect':True,
                 'queries':['equality','unique'],'accept_leakage':['equality','unique']},
                {'name':'is_active','field_id':str(active_field),'protect':True,'queries':[],'accept_leakage':[]}]}]}
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner,
            writers=WriterInventory(True,(Writer(TABLE,'original HTTP app','sqlalchemy',
                evidence='pinned original request session dependency and unchanged routes'),)),
            search_reviews=(SearchReview(email_field,False,
                'Fixture-only opaque UUID128 addresses; equality/frequency/query/uniqueness leakage accepted for disposable public identities'),),
            keys=keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        approval = m.MaintenanceApproval('local original HTTP client stopped; owner writers excluded',3600)
        def pin(phase): return m.DeploymentPin(proposal.target_id,proposal.operation_id,proposal.digest,phase)
        assert m.apply(proposal,owner,keys=keys,pin=pin('PREPARED'),approval=approval).phase == 'PENDING'
        assert m.apply(proposal,owner,keys=keys,pin=pin('ACTIVATING'),approval=approval,until='ACTIVE').phase == 'ACTIVE'
        sessions = attach(mapping,runtime,lock=proposal.lock_bytes,keys=keys,deployment=(proposal,pin('ACTIVE')))
        protected = http_workflow(api,lambda: sessions(tenant_id=TABLE),retained=native)
        assert protected['is_active'] is True
        protected_mail = mail_workflow(api,lambda: sessions(tenant_id=TABLE),protected,monkeypatch)
        assert protected_mail == native_mail
        with owner.connect() as connection:
            frames = connection.exec_driver_sql('SELECT email,full_name,is_active FROM "user"').all()
            assert frames and all(bytes(email).startswith(b'CF1\0')
                and (name is None or bytes(name).startswith(b'CF1\0'))
                and len(bytes(active)) == 43 for email,name,active in frames)
        active = pin('ACTIVE')
        reverse = d.plan(proposal,owner,source_pin=active,keys=keys,
            plaintext_runtime_role=least_privilege_role(SimpleNamespace(owner=owner,role=role)),
            backfill_rows_per_second=1000,verify_rows_per_second=1000,
            temporary_bytes_per_row=3000,wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id,reverse.operation_id,reverse.digest,True,
            'public disposable HTTP fixtures; no historical protected backup')
        def reverse_pin(phase):
            return m.DeploymentPin(reverse.target_id,reverse.operation_id,reverse.digest,phase)
        assert d.apply(reverse,owner,keys=keys,pin=reverse_pin('PREPARED'),approval=approval,
                       consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse,owner,keys=keys,pin=reverse_pin('PLAINTEXT_ACTIVATING'),approval=approval,
                       consent=consent,until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id,reverse.operation_id,reverse.digest,
            'unchanged original HTTP app in a fresh process with Cryptalis imports denied',
            'public disposable values',True)
        assert d.remove(reverse,owner,pin=reverse_pin('REMOVING'),approval=approval,
                        removal=removal,consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse,owner,pin=reverse_pin('REMOVED')) is None
        from sqlmodel_http_package_free import run as package_free
        child = package_free(copied,schema,protected)
        assert hashes == {rel:hashlib.sha256((copied/rel).read_bytes()).hexdigest() for rel in hashes}
        evidence = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_RECEIPT')
        if evidence:
            with Path(evidence).open('x') as stream:
                json.dump({'application_revision':SOURCE['revision'],'application_source_sha256':hashes,
                    'model_changes':[],'query_changes':[],'route_changes':[],
                    'protected_fields':['User.email','User.full_name','User.is_active'],
                    'profile':'fixture-only opaque UUID128 email equality/unique; explicit single tenant',
                    'native_http_controls':native['controls'],'protected_http_controls':protected['controls'],
                    'native_local_smtp':native_mail,'protected_local_smtp':protected_mail,
                    'removed_original_http':child,
                    'runtime':{name:importlib.metadata.version(name) for name in (
                        'fastapi','starlette','httpx','emails','sqlmodel','pydantic','SQLAlchemy',
                        'greenlet','psycopg','cryptography')},
                    'python':sys.version.split()[0],
                    'boundary':'local TestClient ASGI routes and real localhost SMTP; no browser, deployment or external mail qualification',
                    'gates':'all seven UNKNOWN'},stream,indent=2)
                stream.write('\n')
    finally:
        runtime.dispose()
        if original_engine is not None: original_engine.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        if mapping is not None:
            mapping.dispose(); mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
