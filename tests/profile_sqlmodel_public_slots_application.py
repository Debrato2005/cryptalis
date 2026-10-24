"""Opt-in original SQLModel multi-field public-slot lifecycle.

Email search review covers only opaque public fixture identities. Production
email domains, external custody, and the seven release gates remain UNKNOWN.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlmodel import Session

from cryptalis import deprotection as d, migration as m
from cryptalis.doctor import preflight
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlmodel import attach
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys
import test_sqlmodel_application as original


LAYOUT = 'preserve-public-slots/v1'


def public_slots(owner, original=None):
    """Observe native table identities and each original visible column slot."""
    with owner.connect() as connection:
        tables = connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace '
            "WHERE n.nspname=current_schema() AND c.relkind='r' ORDER BY c.relname").all()
        observed = {}
        for name, oid in tables:
            if original is not None and name not in original:
                continue
            columns = connection.exec_driver_sql(
                'SELECT attname,attnum FROM pg_catalog.pg_attribute '
                'WHERE attrelid=%s::oid AND attnum>0 AND NOT attisdropped ORDER BY attnum', (oid,)).all()
            names = None if original is None else {column for column, _ in original[name]['columns']}
            columns = tuple((column, slot) for column, slot in columns if names is None or column in names)
            quoted = connection.dialect.identifier_preparer.quote(name)
            order = tuple(connection.exec_driver_sql('SELECT * FROM ' + quoted + ' LIMIT 0').keys())
            if names is not None:
                order = tuple(column for column in order if column in names)
            observed[name] = {'oid': oid, 'columns': columns, 'order': order}
    return observed



def field_frames(owner, model, *, staged):
    fields = sorted(model['fields'], key=lambda field: field['column'])
    with owner.connect() as connection:
        quote = connection.dialect.identifier_preparer.quote
        columns = [quote(field['payload_column'] if staged else field['column']) for field in fields]
        rows = connection.exec_driver_sql('SELECT id,' + ','.join(columns) + ' FROM "user" ORDER BY id')
        return {str(row[0]): tuple(None if value is None else bytes(value) for value in row[1:]) for row in rows}

def restart(backend, schema, retained, helper):
    script = r'''
import importlib.abc,json,os,pathlib,runpy,sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0,DenyCryptalis())
sys.path[:0]=json.loads(os.environ['SQLMODEL_CHILD_PATHS'])
try:import cryptalis
except ImportError:pass
else:raise AssertionError('Cryptalis import guard did not refuse')
import psycopg
from sqlalchemy import create_engine
from sqlmodel import Session
namespace=runpy.run_path(os.environ['SQLMODEL_WORKLOAD_HELPER'])
engine=create_engine('postgresql+psycopg://',hide_parameters=True,
    creator=lambda:psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'],
        options='-csearch_path='+os.environ['SQLMODEL_SCHEMA'],connect_timeout=5))
try:
    factory=lambda:Session(engine,expire_on_commit=False)
    current=namespace['workflow'](factory,os.environ['SQLMODEL_CHILD_PHASE'],json.loads(os.environ['SQLMODEL_CURRENT']))
    namespace['boolean_controls'](factory,current,os.environ['SQLMODEL_CHILD_PHASE'])
finally:engine.dispose()
for name,module in tuple(sys.modules.items()):
    if name=='app' or name.startswith('app.'):
        origin=getattr(module,'__file__',None)
        if origin:assert pathlib.Path(origin).resolve().is_relative_to(pathlib.Path(os.environ['SQLMODEL_BACKEND']).resolve())
assert not any(name=='cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print(json.dumps({'native_crud':'passed','cryptalis_imported':False,'original_app_origin':True}))
'''
    child = subprocess.run([sys.executable, '-I', '-B', '-c', script], capture_output=True, text=True,
        timeout=60, env=dict(os.environ, SQLMODEL_CHILD_PATHS=json.dumps(sys.path), SQLMODEL_SCHEMA=schema,
            SQLMODEL_BACKEND=str(backend), SQLMODEL_CURRENT=json.dumps(retained), SQLMODEL_CHILD_PHASE=uuid4().hex,
            SQLMODEL_WORKLOAD_HELPER=str(helper)))
    assert child.returncode == 0, 'package-free original SQLModel CRUD failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_crud': 'passed', 'cryptalis_imported': False, 'original_app_origin': True}


def test_original_three_field_app_preserves_public_slots_and_latest_native_exit(tmp_path, monkeypatch):
    source = os.environ.get('CRYPTALIS_SQLMODEL_APP_SOURCE')
    if not source:
        pytest.skip('set CRYPTALIS_SQLMODEL_APP_SOURCE to the pinned original six-file snapshot')
    assert sys.version_info >= (3, 13) and original.sqlmodel.__version__ == '0.0.48'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    backend, hashes = original.snapshot(Path(source), tmp_path / 'snapshot')
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    original.settings(monkeypatch)
    helper = Path(original.__file__).with_name('sqlmodel_template_workload.py').resolve()
    workload = runpy.run_path(str(helper))
    from app.models import SQLModel, User
    schema = 'sqlmodel_public_slots_' + uuid4().hex
    owner = original.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = User._sa_registry
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        SQLModel.metadata.create_all(owner)
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            quoted = connection.dialect.identifier_preparer.quote(role)
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quoted}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {quoted}')
        native = lambda: Session(runtime, expire_on_commit=False)
        phase = uuid4().hex
        retained = workload['workflow'](native, phase)
        retained = workload['boolean_controls'](native, retained, phase)
        retained, native_search = search_controls(native, retained)
        original_slots, original_catalog = public_slots(owner), native_catalog(owner)
        assert {'user', 'item'} <= original_slots.keys()
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(original.TABLE), 'tenancy': {'single_tenant': True},
                'fields': [
                    {'name': 'full_name', 'field_id': str(original.FIELD), 'protect': True, 'queries': [], 'accept_leakage': []},
                    {'name': 'email', 'field_id': str(UUID(int=1903)), 'protect': True,
                     'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']},
                    {'name': 'is_active', 'field_id': str(UUID(int=1904)), 'protect': True, 'queries': [], 'accept_leakage': []}]}]}
        inventory = WriterInventory(True, (Writer(original.TABLE, 'app', 'sqlalchemy',
            evidence='pinned unchanged original SQLModel CRUD; disposable single-tenant fixture'),))
        reviews = (SearchReview(UUID(int=1903), False,
            'Public fixtures only: independent opaque UUID128 local parts at example.com; equality, '
            'frequency, query and uniqueness leakage accepted for these disposable identities. '
            'Arbitrary production email domains remain UNKNOWN.'),)
        report = preflight(json.dumps(declaration).encode(), mapping, owner, writers=inventory, search_reviews=reviews)
        assert report['status'] == 'UNKNOWN' and report['checks']['manifest_schema'] == 'PASS'
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner, layout=LAYOUT,
            writers=inventory, search_reviews=reviews, keys=keys, runtime_role=role, target_id=uuid4(),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        assert proposal.document['lock']['schema'] == 'cryptalis.lock/v6'
        assert proposal.document['lock']['layout'] == LAYOUT
        approval = m.MaintenanceApproval('original fixture app stopped; all inventoried writers excluded', 3600)
        def pin(plan, phase): return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'PREPARED'),
            approval=approval, until='VERIFIED').phase == 'VERIFIED'
        model = proposal.document['lock']['models'][0]
        staged = field_frames(owner, model, staged=True)
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'PREPARED'), approval=approval).phase == 'PENDING'
        assert field_frames(owner, model, staged=False) == staged
        assert public_slots(owner, original_slots) == original_slots
        assert m.apply(proposal, owner, keys=keys, pin=pin(proposal, 'ACTIVATING'),
            approval=approval, until='ACTIVE').phase == 'ACTIVE'
        factory = attach(mapping, runtime, lock=proposal.lock_bytes, keys=keys,
                         deployment=(proposal, pin(proposal, 'ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        phase = uuid4().hex
        current = workload['workflow'](attached, phase, retained)
        current = workload['boolean_controls'](attached, current, phase)
        current, observed_search = search_controls(attached, current)
        assert observed_search == native_search
        assert public_slots(owner, original_slots) == original_slots
        with owner.connect() as connection:
            rows = connection.exec_driver_sql('SELECT email,full_name,is_active FROM "user"').all()
        assert len(rows) == 2 and all(all(bytes(value).startswith(b'CF1\0') for value in row) for row in rows)
        reverse = d.plan(proposal, owner, source_pin=pin(proposal, 'ACTIVE'), keys=keys,
            plaintext_runtime_role=least_privilege_role(SimpleNamespace(owner=owner, role=role)),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                     'public disposable original app values')
        assert d.apply(reverse, owner, keys=keys, pin=pin(reverse, 'PREPARED'),
            approval=approval, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert public_slots(owner, original_slots) == original_slots
        assert d.apply(reverse, owner, keys=keys, pin=pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'original package-free CRUD with Cryptalis imports denied', 'public disposable fixture backups', True)
        assert d.remove(reverse, owner, pin=pin(reverse, 'REMOVING'), approval=approval,
            removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=pin(reverse, 'REMOVED')) is None
        assert public_slots(owner) == original_slots and native_catalog(owner) == original_catalog
        with owner.connect() as connection:
            latest = connection.exec_driver_sql('SELECT email,full_name,is_active FROM "user" WHERE id=%s',
                                                (UUID(current['id']),)).one()
        assert tuple(latest) == (current['email'], current['full_name'], False)
        restart(backend, schema, current, helper)
        assert public_slots(owner) == original_slots
        assert hashes == {name: hashlib.sha256((backend.parent / name).read_bytes()).hexdigest() for name in original.SOURCES}
        receipt = os.environ.get('CRYPTALIS_SQLMODEL_PUBLIC_SLOTS_RECEIPT')
        if receipt:
            with Path(receipt).open('x') as stream:
                json.dump({'application_revision': original.REVISION, 'application_source_sha256': hashes,
                    'model_changes': [], 'query_changes': [], 'layout': LAYOUT,
                    'protected_fields': ['User.email', 'User.full_name', 'User.is_active'],
                    'original_table_oids_public_attnums_and_order_preserved': True,
                    'search_controls': observed_search, 'latest_value_decryptback': True,
                    'cryptalis_denied_restart': True, 'key_custody': 'public deterministic fixtures',
                    'production_email_domain_admission': 'UNKNOWN', 'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()
        mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
