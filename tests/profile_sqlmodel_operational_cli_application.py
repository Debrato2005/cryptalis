"""Opt-in original app lifecycle through host-configured operational commands.

Fixture host code supplies public keys and independent pin/maintenance approval.
This does not qualify production email review, custody, or host authentication.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
import cryptalis
from cryptalis import deprotection as d, migration as m
from cryptalis.sqlmodel import attach
from profile_sqlmodel_public_slots_application import public_slots, field_frames, restart
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys
import test_sqlmodel_application as original


ROOT = Path(__file__).resolve().parents[1]
LAUNCH = r'''
import json,pathlib,sys
expected=pathlib.Path(sys.argv[1]).resolve()
source_origin=sys.argv[2]
if source_origin:sys.path.insert(0,source_origin)
import cryptalis
assert pathlib.Path(cryptalis.__file__).resolve()==expected
sys.path[:0]=json.loads(sys.argv[3])
from cryptalis.cli import main
try:code=main(sys.argv[4:])
finally:
    for name,module in tuple(sys.modules.items()):
        if name=='cryptalis' or name.startswith('cryptalis.'):
            assert expected.parent in pathlib.Path(module.__file__).resolve().parents
raise SystemExit(code)
'''
HOST = r'''
from pathlib import Path
import json,os,signal
import psycopg
from sqlalchemy import create_engine,event
from app.models import User
from cryptalis.cli_host import PlanningContext,ApplyContext
from cryptalis.manifest.compiler import Writer,WriterInventory,SearchReview
from cryptalis.migration import DeploymentPin,MaintenanceApproval
from test_migration import keys
from uuid import UUID

def configuration():return json.loads(Path(os.environ['OPERATIONAL_HOST_CONFIGURATION']).read_text())
def owned(c):
    return create_engine('postgresql+psycopg://',echo=False,hide_parameters=True,
        creator=lambda:psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
            options='-csearch_path='+c['schema'],connect_timeout=5))
def planning():
    c=configuration()
    return PlanningContext(engine=owned(c),mapping=User._sa_registry,
        writers=WriterInventory(True,(Writer(UUID(int=1901),'app','sqlalchemy',evidence='unchanged pinned original CRUD; public disposable fixtures'),)),
        search_reviews=(SearchReview(UUID(int=1903),False,'Opaque UUID128 fixture email local parts only; equality/frequency/query/uniqueness leakage accepted for public fixtures; production domain UNKNOWN.'),),
        keys=keys,runtime_role=c['runtime_role'],target_id=UUID(c['target_id']),
        backfill_rows_per_second=1000,verify_rows_per_second=1000,temporary_bytes_per_row=3000,wal_bytes_per_row=6000)
def applying():
    c=configuration()
    raw=json.loads(Path(c['pin_path']).read_text())
    approval=json.loads(Path(c['approval_path']).read_text())
    engine=owned(c)
    if c.get('pause_after_dispose'):
        def pause(ignored):
            Path(c['checkpoint']).write_text('disposed after committed API progress')
            signal.pause()
        event.listen(engine,'engine_disposed',pause)
    return ApplyContext(engine=engine,keys=keys,
        pin=DeploymentPin(UUID(raw['target_id']),UUID(raw['operation_id']),raw['plan_digest'],raw['phase']),
        approval=MaintenanceApproval(**approval))
'''


def test_original_three_field_app_cli_plan_kill_resume_publish_and_native_exit(tmp_path, monkeypatch):
    source = os.environ.get('CRYPTALIS_SQLMODEL_APP_SOURCE')
    if not source:
        pytest.skip('set CRYPTALIS_SQLMODEL_APP_SOURCE to the pinned six-file original source')
    assert sys.version_info >= (3, 13) and original.sqlmodel.__version__ == '0.0.48'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    backend, hashes = original.snapshot(Path(source), tmp_path / 'snapshot')
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)
    original.settings(monkeypatch)
    helper = Path(original.__file__).with_name('sqlmodel_template_workload.py').resolve()
    workload = runpy.run_path(str(helper))
    from app.models import SQLModel, User
    schema = 'sqlmodel_cli_' + uuid4().hex
    owner = original.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = User._sa_registry
    process = None
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
        native = lambda: original.Session(runtime, expire_on_commit=False)
        retained = workload['workflow'](native, uuid4().hex)
        retained = workload['boolean_controls'](native, retained, uuid4().hex)
        retained, native_search = search_controls(native, retained)
        native_slots, catalog = public_slots(owner), native_catalog(owner)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(original.TABLE), 'tenancy': {'single_tenant': True},
                'fields': [
                    {'name': 'full_name', 'field_id': str(original.FIELD), 'protect': True, 'queries': [], 'accept_leakage': []},
                    {'name': 'email', 'field_id': str(UUID(int=1903)), 'protect': True,
                     'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']},
                    {'name': 'is_active', 'field_id': str(UUID(int=1904)), 'protect': True, 'queries': [], 'accept_leakage': []}]}]}
        manifest, plan_path = tmp_path / 'manifest.json', tmp_path / 'cli-plan.json'
        manifest.write_text(json.dumps(declaration))
        pin_path, approval_path = tmp_path / 'host-pin.json', tmp_path / 'host-approval.json'
        approval = m.MaintenanceApproval('original fixture app stopped; all inventoried writers excluded', 3600)
        approval_path.write_text(json.dumps(asdict(approval)))
        configuration_path = tmp_path / 'host-configuration.json'
        configuration = {'schema': schema, 'runtime_role': role, 'target_id': str(uuid4()),
            'pin_path': str(pin_path), 'approval_path': str(approval_path), 'checkpoint': str(tmp_path / 'committed-checkpoint')}
        configuration_path.write_text(json.dumps(configuration))
        module = 'original_cli_host_' + uuid4().hex
        (tmp_path / (module + '.py')).write_text(HOST)
        expected_origin = Path(cryptalis.__file__).resolve()
        source_origin = str(expected_origin.parent.parent) if expected_origin.parent.parent == ROOT / 'src' else ''
        paths = json.dumps([str(tmp_path), str(backend), str(ROOT / 'tests')])
        environment = dict(os.environ, OPERATIONAL_HOST_CONFIGURATION=str(configuration_path))
        def command(*arguments):
            return [sys.executable, '-I', '-B', '-c', LAUNCH, str(expected_origin), source_origin, paths, *arguments]
        def execute(*arguments):
            result = subprocess.run(command(*arguments), env=environment, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, 'operational CLI child failed; diagnostics suppressed'
            assert result.stderr == ''
            assert all(os.environ[name] not in result.stdout for name in ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'))
            return json.loads(result.stdout)
        planned = execute('plan', str(manifest), '--host-context', module + ':planning', '--out', str(plan_path),
                          '--layout', 'preserve-public-slots/v1', '--json')
        plan = m.MigrationPlan(plan_path.read_bytes())
        assert planned['phase'] == 'PREPARED' and planned['operation_id'] == str(plan.operation_id)
        assert planned['authority'] == 'HOST_SUPPLIED_CONTEXT' and plan.document['lock']['schema'] == 'cryptalis.lock/v6'
        assert public_slots(owner) == native_slots
        def pin(phase): return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)
        pin_path.write_text(json.dumps(asdict(pin('PREPARED')), default=str))
        configuration['pause_after_dispose'] = True
        configuration_path.write_text(json.dumps(configuration))
        process = subprocess.Popen(command('apply', str(plan_path), '--host-context', module + ':applying',
            '--until', 'BACKFILLED', '--chunk-size', '1', '--json'), env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 25
        while not Path(configuration['checkpoint']).exists():
            assert process.poll() is None, 'checkpoint CLI child exited early; diagnostics suppressed'
            assert time.monotonic() < deadline, 'CLI committed checkpoint was not observed'
            time.sleep(0.05)
        observed = m.status(plan, owner, pin=pin('PREPARED'))
        assert observed.phase == 'BACKFILLED' and observed.committed_rows == 1
        model = plan.document['lock']['models'][0]
        prefix = field_frames(owner, model, staged=True)
        process.kill()
        process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        configuration['pause_after_dispose'] = False
        configuration_path.write_text(json.dumps(configuration))
        resumed = execute('apply', str(plan_path), '--host-context', module + ':applying',
            '--resume', str(plan.operation_id), '--until', 'VERIFIED', '--chunk-size', '1', '--json')
        assert resumed['phase'] == 'VERIFIED' and field_frames(owner, model, staged=True) == prefix
        assert execute('apply', str(plan_path), '--host-context', module + ':applying', '--until', 'PENDING', '--json')['phase'] == 'PENDING'
        assert field_frames(owner, model, staged=False) == prefix
        pin_path.write_text(json.dumps(asdict(pin('ACTIVATING')), default=str))
        assert execute('apply', str(plan_path), '--host-context', module + ':applying', '--until', 'ACTIVE', '--json')['phase'] == 'ACTIVE'
        assert public_slots(owner, native_slots) == native_slots
        factory = attach(mapping, runtime, lock=plan.lock_bytes, keys=keys, deployment=(plan, pin('ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        current = workload['workflow'](attached, uuid4().hex, retained)
        current = workload['boolean_controls'](attached, current, uuid4().hex)
        current, controls = search_controls(attached, current)
        assert controls == native_search and public_slots(owner, native_slots) == native_slots
        reverse = d.plan(plan, owner, source_pin=pin('ACTIVE'), keys=keys,
            plaintext_runtime_role=least_privilege_role(SimpleNamespace(owner=owner, role=role)),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                     'public disposable original app values')
        def reverse_pin(phase): return m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, phase)
        assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PREPARED'), approval=approval,
            consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PLAINTEXT_ACTIVATING'), approval=approval,
            consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'unchanged package-free original CRUD', 'public disposable fixture backups', True)
        assert d.remove(reverse, owner, pin=reverse_pin('REMOVING'), approval=approval,
                        removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=reverse_pin('REMOVED')) is None
        assert public_slots(owner) == native_slots and native_catalog(owner) == catalog
        with owner.connect() as connection:
            latest = connection.exec_driver_sql('SELECT email,full_name,is_active FROM "user" WHERE id=%s',
                                                (UUID(current['id']),)).one()
        assert tuple(latest) == (current['email'], current['full_name'], False)
        restart(backend, schema, current, helper)
        assert hashes == {name: hashlib.sha256((backend.parent / name).read_bytes()).hexdigest() for name in original.SOURCES}
        receipt = os.environ.get('CRYPTALIS_SQLMODEL_OPERATIONAL_CLI_RECEIPT')
        if receipt:
            with Path(receipt).open('x') as stream:
                json.dump({'application_revision': original.REVISION, 'application_source_sha256': hashes,
                    'model_changes': [], 'query_changes': [], 'layout': 'preserve-public-slots/v1',
                    'protected_fields': ['User.email', 'User.full_name', 'User.is_active'],
                    'source_plan_digest': plan.digest, 'cli_plan_apply_resume_publication': True,
                    'sigkill_after_committed_backfilled': True, 'independent_resume_preserved_frames': True,
                    'host_pin_authority': 'fixture-only; PREPARED then explicitly supplied ACTIVATING',
                    'search_controls': controls, 'native_public_slots_preserved': True,
                    'latest_value_decryptback': True, 'cryptalis_denied_restart': True,
                    'boundary': 'Original CRUD only; no HTTP, production email domain, custody or host authentication qualification',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        mapping.dispose()
        mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
