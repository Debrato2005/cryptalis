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
from cryptalis import deprotection as d, migration as m, rotation as r
from cryptalis.sqlmodel import attach
from profile_sqlmodel_public_slots_application import public_slots, field_frames, restart
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys
from rewrap_worker import target_keys
from payload_rotation_worker import rotated_keys
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
from cryptalis.cli_host import (PlanningContext,ApplyContext,ReversePlanningContext,ReverseApplyContext,RemovalContext,
    RewrapPlanningContext,RewrapApplyContext,RewrapActivationContext,RewrapAbortContext,
    PayloadPlanningContext,PayloadApplyContext,PayloadStatusContext,PayloadSealingContext,
    PayloadSwitchContext,PayloadActivationContext,PayloadAbortContext)
from cryptalis.manifest.compiler import Writer,WriterInventory,SearchReview
from cryptalis.migration import DeploymentPin,MaintenanceApproval
from cryptalis.deprotection import PlaintextApproval,RemovalApproval
from test_migration import keys
from rewrap_worker import target_keys
from payload_rotation_worker import rotated_keys
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
    pause_after_dispose(engine,c)
    return ApplyContext(engine=engine,keys=keys,
        pin=DeploymentPin(UUID(raw['target_id']),UUID(raw['operation_id']),raw['plan_digest'],raw['phase']),
        approval=MaintenanceApproval(**approval))
def pause_after_dispose(engine,c):
    if c.get('pause_after_dispose'):
        def pause(ignored):
            Path(c['checkpoint']).write_text('disposed after committed API progress')
            signal.pause()
        event.listen(engine,'engine_disposed',pause)
def deployment(c):
    raw=json.loads(Path(c['pin_path']).read_text())
    return DeploymentPin(UUID(raw['target_id']),UUID(raw['operation_id']),raw['plan_digest'],raw['phase'])
def current_keys(c):return rotated_keys if c.get('current_payload_custody') else target_keys if c.get('current_target_custody') else keys
def reverse_planning():
    c=configuration()
    return ReversePlanningContext(engine=owned(c),keys=current_keys(c),source_pin=deployment(c),
        plaintext_runtime_role=c['plaintext_runtime_role'],backfill_rows_per_second=1000,
        verify_rows_per_second=1000,temporary_bytes_per_row=3000,wal_bytes_per_row=6000,restore=None)
def plaintext_consent(c):
    raw=json.loads(Path(c['consent_path']).read_text())
    raw['target_id']=UUID(raw['target_id']);raw['operation_id']=UUID(raw['operation_id'])
    return PlaintextApproval(**raw)
def reversing():
    c=configuration()
    engine=owned(c)
    pause_after_dispose(engine,c)
    return ReverseApplyContext(engine=engine,keys=current_keys(c),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())),consent=plaintext_consent(c))
def removing():
    c=configuration()
    raw=json.loads(Path(c['removal_path']).read_text())
    raw['target_id']=UUID(raw['target_id']);raw['operation_id']=UUID(raw['operation_id'])
    return RemovalContext(engine=owned(c),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())),
        consent=plaintext_consent(c),removal=RemovalApproval(**raw))
def rewrap_source(c,tenant):
    if c.get('rewrap_source_unavailable'):raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    return keys(tenant)
def rewrap_target(c,tenant):
    if c.get('rewrap_target_unavailable'):raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    return target_keys(tenant)
def rewrap_planning():
    c=configuration()
    return RewrapPlanningContext(engine=owned(c),source_keys=lambda t:rewrap_source(c,t),
        target_keys=lambda t:rewrap_target(c,t),source_pin=deployment(c),verify_rows_per_second=1000,restore=None)
def rewrap_applying():
    c=configuration()
    engine=owned(c)
    pause_after_dispose(engine,c)
    return RewrapApplyContext(engine=engine,source_keys=lambda t:rewrap_source(c,t),
        target_keys=lambda t:rewrap_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def rewrap_activating():
    c=configuration()
    return RewrapActivationContext(engine=owned(c),target_keys=lambda t:rewrap_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def rewrap_aborting():
    c=configuration()
    return RewrapAbortContext(engine=owned(c),source_keys=lambda t:rewrap_source(c,t),source_pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def payload_source(c,tenant):
    if c.get('payload_source_unavailable'):raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    return target_keys(tenant)
def payload_target(c,tenant):
    if c.get('payload_target_unavailable'):raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
    return rotated_keys(tenant)
def payload_planning():
    c=configuration()
    return PayloadPlanningContext(engine=owned(c),source_keys=lambda t:payload_source(c,t),
        target_keys=lambda t:payload_target(c,t),source_pin=deployment(c),restore=None,
        backfill_rows_per_second=1000,verify_rows_per_second=1000,temporary_bytes_per_row=3000,wal_bytes_per_row=6000)
def payload_applying():
    c=configuration()
    return PayloadApplyContext(engine=owned(c),source_keys=lambda t:payload_source(c,t),
        target_keys=lambda t:payload_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def payload_status():
    c=configuration()
    return PayloadStatusContext(engine=owned(c),pin=deployment(c))
def payload_sealing():
    c=configuration()
    return PayloadSealingContext(engine=owned(c),source_keys=lambda t:payload_source(c,t),
        target_keys=lambda t:payload_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())),
        copy_rows_per_second=0.5,copy_wal_bytes_per_row=3000)
def payload_switching():
    c=configuration();engine=owned(c);pause_after_dispose(engine,c)
    return PayloadSwitchContext(engine=engine,source_keys=lambda t:payload_source(c,t),
        target_keys=lambda t:payload_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def payload_activating():
    c=configuration()
    return PayloadActivationContext(engine=owned(c),target_keys=lambda t:payload_target(c,t),pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
def payload_aborting():
    c=configuration()
    return PayloadAbortContext(engine=owned(c),source_keys=lambda t:payload_source(c,t),source_pin=deployment(c),
        approval=MaintenanceApproval(**json.loads(Path(c['approval_path']).read_text())))
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
        protection_plan_digest = plan.digest
        source_plan, source_path, source_active_pin = plan, plan_path, pin('ACTIVE')
        def rewrap_command(action, path, factory, *extra):
            return ('keys', 'rotate', 'rewrap', action, str(path), '--host-context', module + ':' + factory, *extra, '--json')
        def indices():
            with owner.connect() as connection:
                return connection.exec_driver_sql('SELECT c.relname,c.oid::text,c.relfilenode::text '
                    'FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid '
                    'WHERE i.indrelid=\'"user"\'::regclass ORDER BY c.relname').all()
        original_indexes = indices()
        pin_path.write_text(json.dumps(asdict(source_active_pin), default=str))
        configuration_path.write_text(json.dumps(configuration))
        cancelled_path, cancelled_activation = tmp_path / 'cancelled-rewrap.json', tmp_path / 'cancelled-successor.json'
        execute(*rewrap_command('plan', source_path, 'rewrap_planning', '--out', str(cancelled_path)))
        cancelled = r.RewrapPlan(cancelled_path.read_bytes())
        pin_path.write_text(json.dumps(asdict(m.DeploymentPin(cancelled.activation_plan.target_id,
            cancelled.operation_id, cancelled.activation_plan.digest, 'PREPARED')), default=str))
        configuration['rewrap_target_unavailable'] = True
        configuration_path.write_text(json.dumps(configuration))
        unavailable = subprocess.run(command(*rewrap_command('apply', cancelled_path, 'rewrap_applying',
            '--out', str(cancelled_activation))), env=environment, capture_output=True, text=True, timeout=30)
        assert unavailable.returncode == 4 and unavailable.stdout == ''
        assert 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER' not in unavailable.stderr
        refused = json.loads(unavailable.stderr)['error']
        assert refused['effects'] == 'INSPECT_JOURNAL' and 'known_result' not in refused
        assert refused['artifact_result']['artifact_directory_durable'] is True
        assert m.status(source_plan, owner, pin=source_active_pin).runtime_metadata_matches
        configuration['rewrap_target_unavailable'] = False
        configuration_path.write_text(json.dumps(configuration))
        original_frames = field_frames(owner, source_plan.document['lock']['models'][0], staged=False)
        assert execute(*rewrap_command('apply', cancelled_path, 'rewrap_applying', '--out', str(cancelled_activation),
            '--resume', str(cancelled.operation_id)))['phase'] == 'PENDING'
        configuration['rewrap_target_unavailable'] = True
        configuration_path.write_text(json.dumps(configuration))
        pin_path.write_text(json.dumps(asdict(source_active_pin), default=str))
        assert execute(*rewrap_command('abort', cancelled_path, 'rewrap_aborting'))['phase'] == 'ABORTED'
        assert field_frames(owner, source_plan.document['lock']['models'][0], staged=False) == original_frames
        assert indices() == original_indexes
        from app import crud
        from app.models import UserUpdate
        with attached() as session:
            row = crud.get_user_by_email(session=session, email=current['email'])
            latest_name = 'private-name-after-rewrap-cancellation-' + uuid4().hex
            crud.update_user(session=session, db_user=row, user_in=UserUpdate(full_name=latest_name))
        current = dict(current, full_name=latest_name)
        edited_frames = field_frames(owner, source_plan.document['lock']['models'][0], staged=False)
        assert execute(*rewrap_command('abort', cancelled_path, 'rewrap_aborting'))['phase'] == 'ABORTED'
        assert field_frames(owner, source_plan.document['lock']['models'][0], staged=False) == edited_frames
        configuration['rewrap_target_unavailable'] = False
        configuration_path.write_text(json.dumps(configuration))
        rewrap_path, activation_path = tmp_path / 'current-rewrap.json', tmp_path / 'current-successor.json'
        execute(*rewrap_command('plan', source_path, 'rewrap_planning', '--out', str(rewrap_path)))
        rewrap = r.RewrapPlan(rewrap_path.read_bytes())
        activation_plan = rewrap.activation_plan
        pin_path.write_text(json.dumps(asdict(m.DeploymentPin(activation_plan.target_id,
            activation_plan.operation_id, activation_plan.digest, 'PREPARED')), default=str))
        Path(configuration['checkpoint']).unlink()
        configuration['pause_after_dispose'] = True
        configuration_path.write_text(json.dumps(configuration))
        process = subprocess.Popen(command(*rewrap_command('apply', rewrap_path, 'rewrap_applying',
            '--out', str(activation_path))), env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 25
        while not Path(configuration['checkpoint']).exists():
            assert process.poll() is None, 'rewrap checkpoint child exited early; diagnostics suppressed'
            assert time.monotonic() < deadline, 'rewrap committed checkpoint was not observed'
            time.sleep(0.05)
        assert m.status(activation_plan, owner, pin=m.DeploymentPin(activation_plan.target_id,
            activation_plan.operation_id, activation_plan.digest, 'PREPARED')).phase == 'PENDING'
        assert field_frames(owner, source_plan.document['lock']['models'][0], staged=False) == edited_frames
        process.kill()
        process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        configuration['pause_after_dispose'] = False
        configuration_path.write_text(json.dumps(configuration))
        resumed = execute(*rewrap_command('apply', rewrap_path, 'rewrap_applying', '--out', str(activation_path),
            '--resume', str(rewrap.operation_id)))
        assert resumed['phase'] == 'PENDING' and resumed['artifact_result']['artifact_reused'] is True
        configuration.update(rewrap_source_unavailable=True, current_target_custody=True)
        configuration_path.write_text(json.dumps(configuration))
        pin_path.write_text(json.dumps(asdict(m.DeploymentPin(activation_plan.target_id,
            activation_plan.operation_id, activation_plan.digest, 'ACTIVATING')), default=str))
        assert execute(*rewrap_command('activate', activation_path, 'rewrap_activating'))['phase'] == 'ACTIVE'
        assert field_frames(owner, source_plan.document['lock']['models'][0], staged=False) == edited_frames
        assert indices() == original_indexes and public_slots(owner, native_slots) == native_slots
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source_plan, owner, pin=source_active_pin)
        plan, plan_path = activation_plan, activation_path
        runtime.dispose()
        mapping.dispose()
        mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
        workload = runpy.run_path(str(helper))
        from app.models import User as RewrappedUser, UserUpdate as RewrappedUpdate
        from app import crud as rewrapped_crud
        mapping = RewrappedUser._sa_registry
        runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        factory = attach(mapping, runtime, lock=plan.lock_bytes, keys=target_keys, deployment=(plan, pin('ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        with attached() as session:
            row = rewrapped_crud.get_user_by_email(session=session, email=current['email'])
            latest_name = 'private-name-under-target-custody-' + uuid4().hex
            rewrapped_crud.update_user(session=session, db_user=row, user_in=RewrappedUpdate(full_name=latest_name))
        current = dict(current, full_name=latest_name)
        current = workload['boolean_controls'](attached, current, uuid4().hex)
        current, after_rewrap_controls = search_controls(attached, current)
        assert after_rewrap_controls == controls
        # Payload generation changes retain the exact current rewrapped readers.
        payload_source_plan, payload_source_path, payload_source_pin = plan, plan_path, pin('ACTIVE')
        def payload_command(action, path, factory, *extra):
            return ('keys', 'rotate', 'payload', action, str(path), '--host-context', module + ':' + factory, *extra, '--json')
        pin_path.write_text(json.dumps(asdict(payload_source_pin), default=str))
        cancelled_payload_path = tmp_path / 'cancelled-payload.json'
        execute(*payload_command('plan', plan_path, 'payload_planning', '--out', str(cancelled_payload_path)))
        cancelled_payload = r.PayloadRotationPlan(cancelled_payload_path.read_bytes())
        def preparation_pin(proposal):
            return m.DeploymentPin(proposal.source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
        pin_path.write_text(json.dumps(asdict(preparation_pin(cancelled_payload)), default=str))
        assert execute(*payload_command('apply', cancelled_payload_path, 'payload_applying', '--max-chunks', '1'))['phase'] == 'EXPANDED'
        configuration['payload_target_unavailable'] = True
        configuration_path.write_text(json.dumps(configuration))
        pin_path.write_text(json.dumps(asdict(payload_source_pin), default=str))
        assert execute(*payload_command('abort', cancelled_payload_path, 'payload_aborting'))['phase'] == 'ABORTED'
        configuration['payload_target_unavailable'] = False
        configuration_path.write_text(json.dumps(configuration))
        payload_path, payload_activation_path = tmp_path / 'payload.json', tmp_path / 'payload-activation.json'
        execute(*payload_command('plan', plan_path, 'payload_planning', '--out', str(payload_path)))
        payload = r.PayloadRotationPlan(payload_path.read_bytes())
        pin_path.write_text(json.dumps(asdict(preparation_pin(payload)), default=str))
        payload_before = field_frames(owner, plan.document['lock']['models'][0], staged=False)
        assert execute(*payload_command('apply', payload_path, 'payload_applying', '--max-chunks', '1'))['phase'] == 'EXPANDED'
        assert execute(*payload_command('apply', payload_path, 'payload_applying', '--resume', str(payload.operation_id)))['phase'] == 'BACKFILLED'
        assert execute(*payload_command('status', payload_path, 'payload_status'))['verification'] == 'NOT_PERFORMED'
        sealed = execute(*payload_command('seal', payload_path, 'payload_sealing', '--out', str(payload_activation_path)))
        assert 'phase' not in sealed and 'known_result' not in sealed
        payload_activation = m.MigrationPlan(payload_activation_path.read_bytes())
        repeated_seal = tmp_path / 'payload-identical-reseal.json'
        execute(*payload_command('seal', payload_path, 'payload_sealing', '--out', str(repeated_seal)))
        assert repeated_seal.read_bytes() == payload_activation_path.read_bytes()
        def payload_staged():
            model = payload.source.document['lock']['models'][0]
            with owner.connect() as connection:
                quote = connection.dialect.identifier_preparer.quote
                columns = [quote(field['payload_column'] + '_rotation') for field in sorted(model['fields'], key=lambda field: field['column'])]
                return {str(row[0]): tuple(None if value is None else bytes(value) for value in row[1:])
                    for row in connection.exec_driver_sql('SELECT id,' + ','.join(columns) + ' FROM "user" ORDER BY id')}
        sealed_frames = payload_staged()
        fields = sorted(payload.source.document['lock']['models'][0]['fields'], key=lambda field: field['column'])
        for identity, values in sealed_frames.items():
            for field, previous, frame in zip(fields, payload_before[identity], values):
                if frame is not None:
                    assert int.from_bytes(frame[6:10], 'big') == 2 and frame != previous
                    assert frame[10:14] == previous[10:14]
                    if field['descriptor']['representation'] == 'cf1-packed-equality/v1':
                        assert frame[14:46] == previous[14:46]
                else:
                    assert previous is None
        pin_path.write_text(json.dumps(asdict(m.DeploymentPin(payload_activation.target_id,
            payload_activation.operation_id, payload_activation.digest, 'PREPARED')), default=str))
        Path(configuration['checkpoint']).unlink()
        configuration['pause_after_dispose'] = True
        configuration_path.write_text(json.dumps(configuration))
        process = subprocess.Popen(command(*payload_command('switch', payload_path, 'payload_switching',
            '--activation', str(payload_activation_path))), env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 25
        while not Path(configuration['checkpoint']).exists():
            assert process.poll() is None, 'payload switch child exited early; diagnostics suppressed'
            assert time.monotonic() < deadline, 'payload committed checkpoint was not observed'
            time.sleep(0.05)
        assert m.status(payload_activation, owner, pin=m.DeploymentPin(payload_activation.target_id,
            payload_activation.operation_id, payload_activation.digest, 'PREPARED')).phase == 'PENDING'
        assert field_frames(owner, payload_activation.document['lock']['models'][0], staged=False) == sealed_frames
        process.kill();process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        configuration.update(pause_after_dispose=False, payload_source_unavailable=True)
        configuration_path.write_text(json.dumps(configuration))
        assert execute(*payload_command('switch', payload_path, 'payload_switching', '--activation', str(payload_activation_path),
            '--resume', str(payload_activation.operation_id)))['phase'] == 'PENDING'
        pin_path.write_text(json.dumps(asdict(m.DeploymentPin(payload_activation.target_id,
            payload_activation.operation_id, payload_activation.digest, 'ACTIVATING')), default=str))
        assert execute(*payload_command('activate', payload_activation_path, 'payload_activating'))['phase'] == 'ACTIVE'
        configuration['current_payload_custody'] = True
        configuration_path.write_text(json.dumps(configuration))
        assert indices() == original_indexes and public_slots(owner, native_slots) == native_slots
        assert sealed_frames != payload_before
        with pytest.raises(m.TransitionFailure):m.check_deployment(payload_source_plan, owner, pin=payload_source_pin)
        plan, plan_path = payload_activation, payload_activation_path
        runtime.dispose();mapping.dispose();mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):del sys.modules[name]
        workload = runpy.run_path(str(helper))
        from app.models import User as PayloadUser
        mapping = PayloadUser._sa_registry
        runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        factory = attach(mapping, runtime, lock=plan.lock_bytes, keys=rotated_keys, deployment=(plan, pin('ACTIVE')))
        attached = lambda: factory(tenant_id=original.TABLE, expire_on_commit=False)
        current = workload['workflow'](attached, uuid4().hex, current)
        current = workload['boolean_controls'](attached, current, uuid4().hex)
        current, payload_controls = search_controls(attached, current)
        assert payload_controls == controls
        # The trusted host supplies ACTIVE source authority before reverse planning.
        pin_path.write_text(json.dumps(asdict(pin('ACTIVE')), default=str))
        configuration['plaintext_runtime_role'] = least_privilege_role(SimpleNamespace(owner=owner, role=role))
        configuration_path.write_text(json.dumps(configuration))
        reverse_path = tmp_path / 'cli-reverse.json'
        reversed_plan = execute('plan', '--reverse', str(plan_path), '--host-context', module + ':reverse_planning',
                                '--out', str(reverse_path), '--json')
        reverse = d.DeprotectionPlan(reverse_path.read_bytes())
        assert reversed_plan['phase'] == 'PREPARED' and reversed_plan['source_operation_id'] == str(plan.operation_id)
        with owner.connect() as connection:
            reverse_source_ids = {str(row[0]) for row in connection.exec_driver_sql('SELECT id FROM "user"')}
        assert len(reverse_source_ids) == 3
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                     'public disposable original app values')
        consent_path, removal_path = tmp_path / 'host-consent.json', tmp_path / 'host-removal.json'
        consent_path.write_text(json.dumps(asdict(consent), default=str))
        configuration.update(consent_path=str(consent_path), removal_path=str(removal_path))
        def reverse_pin(phase): return m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, phase)
        pin_path.write_text(json.dumps(asdict(reverse_pin('PREPARED')), default=str))
        # The old protection marker cannot satisfy this second checkpoint wait.
        Path(configuration['checkpoint']).unlink()
        configuration['pause_after_dispose'] = True
        configuration_path.write_text(json.dumps(configuration))
        process = subprocess.Popen(command('rollback', str(reverse_path), '--host-context', module + ':reversing',
            '--until', 'BACKFILLED', '--chunk-size', '1', '--json'), env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 25
        while not Path(configuration['checkpoint']).exists():
            assert process.poll() is None, 'reverse checkpoint child exited early; diagnostics suppressed'
            assert time.monotonic() < deadline, 'reverse committed checkpoint was not observed'
            time.sleep(0.05)
        observed = d.status(reverse, owner, pin=reverse_pin('PREPARED'))
        assert observed.phase == 'BACKFILLED' and observed.committed_rows == len(reverse_source_ids)
        def plaintext_staging():
            fields = sorted(reverse.document['lock']['models'][0]['fields'], key=lambda field: field['column'])
            with owner.connect() as connection:
                quote = connection.dialect.identifier_preparer.quote
                columns = [quote('_cryptalis_' + UUID(field['field_id']).hex + '_plain') for field in fields]
                return {str(row[0]): tuple(row[1:]) for row in connection.exec_driver_sql(
                    'SELECT id,' + ','.join(columns) + ' FROM "user" ORDER BY id')}
        plaintext_prefix = plaintext_staging()
        assert set(plaintext_prefix) == reverse_source_ids
        process.kill()
        process.communicate(timeout=10)
        assert process.returncode == -signal.SIGKILL
        configuration['pause_after_dispose'] = False
        configuration_path.write_text(json.dumps(configuration))
        resumed = execute('rollback', str(reverse_path), '--host-context', module + ':reversing',
            '--resume', str(reverse.operation_id), '--until', 'VERIFIED', '--chunk-size', '1', '--json')
        assert resumed['phase'] == 'VERIFIED' and plaintext_staging() == plaintext_prefix
        assert execute('rollback', str(reverse_path), '--host-context', module + ':reversing', '--json')['phase'] == 'PLAINTEXT_PENDING'
        pin_path.write_text(json.dumps(asdict(reverse_pin('PLAINTEXT_ACTIVATING')), default=str))
        assert execute('apply', str(reverse_path), '--host-context', module + ':reversing',
                       '--until', 'PLAINTEXT_ACTIVE', '--json')['phase'] == 'PLAINTEXT_ACTIVE'
        # Reload the original mapping before native traffic; the attached mapping stays guarded.
        mapping.dispose()
        mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
        native_workload = runpy.run_path(str(helper))
        from app.models import User as NativeUser
        mapping = NativeUser._sa_registry
        native_runtime = original.native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        try:
            native = lambda: original.Session(native_runtime, expire_on_commit=False)
            current = native_workload['workflow'](native, uuid4().hex, current)
            current = native_workload['boolean_controls'](native, current, uuid4().hex)
            current, native_after_publication = search_controls(native, current)
            assert native_after_publication == controls
        finally:
            native_runtime.dispose()
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'unchanged package-free original CRUD', 'public disposable fixture backups', True)
        removal_path.write_text(json.dumps(asdict(removal), default=str))
        pin_path.write_text(json.dumps(asdict(reverse_pin('REMOVING')), default=str))
        assert execute('remove', str(reverse_path), '--host-context', module + ':removing', '--json')['phase'] == 'REMOVED'
        pin_path.write_text(json.dumps(asdict(reverse_pin('REMOVED')), default=str))
        assert execute('remove', str(reverse_path), '--host-context', module + ':removing', '--json')['phase'] == 'REMOVED'
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
                    'source_plan_digest': protection_plan_digest, 'cli_plan_apply_resume_publication': True,
                    'cli_root_rewrap_plan_apply_activate_abort': True, 'cancelled_rewrap_digest': cancelled.digest,
                    'rewrap_proposal_digest': rewrap.digest, 'rewrap_activation_digest': activation_plan.digest,
                    'rewrap_target_outage_retained_source': True, 'source_only_rewrap_abort_after_target_outage': True,
                    'terminal_rewrap_abort_preserved_later_edit': True, 'sigkill_after_rewrap_pending': True,
                    'independent_rewrap_resume_preserved_frames': True, 'rewrap_target_only_activation': True,
                    'rewrap_frame_and_index_identity_preserved': True,
                    'cli_payload_plan_stage_seal_switch_activate_abort_status': True,
                    'payload_proposal_digest': payload.digest, 'payload_activation_digest': payload_activation.digest,
                    'payload_generation': 2, 'payload_source_only_abort': True, 'payload_keyless_status': True,
                    'payload_authenticated_identical_reseal': True, 'sigkill_after_payload_pending': True,
                    'independent_payload_resume_preserved_frames': True, 'payload_target_only_publication': True,
                    'payload_search_boolean_latest_values': True,
                    'sigkill_after_committed_backfilled': True, 'independent_resume_preserved_frames': True,
                    'cli_reverse_plan_apply_resume_remove': True, 'reverse_plan_digest': reverse.digest,
                    'sigkill_after_reverse_backfilled': True, 'independent_reverse_resume_preserved_plaintext': True,
                    'native_latest_edits_after_plaintext_publication': True, 'keyless_idempotent_cli_removal': True,
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
