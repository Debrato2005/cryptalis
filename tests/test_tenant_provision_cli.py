"""Maintenance CLI retains exact tenant artifacts and independent host authority."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType
from uuid import UUID, uuid4

from sqlalchemy import event, select

from cryptalis import cli, migration as m, tenancy
from cryptalis.sqlalchemy import attach
from test_migration import engine, keys
from test_online_protection import app
from test_online_tenants import tenant_app, _pin, _transition_approval
from test_operational_cli import invoke
from test_tenant_provisioning import active, snapshot, NEW_TENANT


def host(app, source, monkeypatch, action, **updates):
    configuration = dict(tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT),
        source_pin=_pin(source, 'ACTIVE'), pin=None, keys=keys, expected_artifact=None)
    configuration.update(updates)
    observed = dict(factory=0, dispose=0, connect=0, keys=0)
    module = ModuleType('tenant_cli_' + uuid4().hex)
    def factory():
        from cryptalis.cli_host import (TenantPlanningContext, TenantApplyContext,
            TenantActivationContext, TenantAbortContext)
        observed['factory'] += 1
        if configuration.get('factory_failure'):
            raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        if configuration['expected_artifact'] is not None:
            path, expected = configuration['expected_artifact']
            assert Path(path).read_bytes() == expected
            assert stat.S_IMODE(Path(path).stat().st_mode) == 0o600
        owned = engine('CRYPTALIS_TEST_DATABASE_URL')
        event.listen(owned, 'engine_disposed', lambda *args: observed.__setitem__('dispose', observed['dispose'] + 1))
        event.listen(owned, 'connect', lambda *args: observed.__setitem__('connect', observed['connect'] + 1))
        def resolve(tenant):
            observed['keys'] += 1
            return configuration['keys'](tenant)
        if action == 'plan':
            return TenantPlanningContext(engine=owned, source_keys=resolve,
                source_pin=configuration['source_pin'], tenant_id=configuration['tenant_id'],
                key_policy=configuration['key_policy'], verify_rows_per_second=1000, restore=None)
        if action == 'abort':
            return TenantAbortContext(engine=owned, source_keys=resolve,
                source_pin=configuration['source_pin'], approval=_transition_approval(app))
        context = TenantApplyContext if action == 'apply' else TenantActivationContext
        return context(engine=owned, keys=resolve, pin=configuration['pin'], approval=_transition_approval(app))
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, observed


def command(action, path, reference, *extra):
    return ('tenants', 'provision', action, str(path), '--host-context', reference, *extra, '--json')


def successful(capsys, *arguments):
    code, output, error = invoke(capsys, *arguments)
    assert code == 0 and error == '', (code, error)
    return json.loads(output)


def test_cli_saved_tenant_policy_resume_independent_publication_and_first_item(tenant_app, tmp_path, monkeypatch, capsys):
    app = tenant_app
    source = active(app)
    original = snapshot(app, source)
    source_path, proposal_path, successor_path = (tmp_path / name for name in ('source.json', 'proposal.json', 'successor.json'))
    source_path.write_bytes(source.artifact)
    planning, _, planned = host(app, source, monkeypatch, 'plan')
    summary = successful(capsys, *command('plan', source_path, planning, '--out', str(proposal_path)))
    proposal = tenancy.TenantProvisionPlan(proposal_path.read_bytes())
    successor = proposal.activation_plan
    assert summary['scope'] == 'tenant_provision_plan' and summary['proposal_digest'] == proposal.digest
    assert summary['artifact_directory_durable'] is True and stat.S_IMODE(proposal_path.stat().st_mode) == 0o600
    assert snapshot(app, source) == original and planned['factory'] == planned['dispose'] == 1
    applying, _, applied = host(app, source, monkeypatch, 'apply', pin=_pin(successor, 'PREPARED'),
        expected_artifact=(successor_path, successor.artifact))
    summary = successful(capsys, *command('apply', proposal_path, applying, '--out', str(successor_path)))
    assert summary['phase'] == 'PENDING' and summary['artifact_result']['artifact_directory_durable'] is True
    assert summary['scope'] == 'tenant_provision_transition'
    denied = invoke(capsys, *command('apply', proposal_path, applying, '--out', str(successor_path)))
    assert denied[0] == 2 and denied[1] == '' and applied['factory'] == 1
    summary = successful(capsys, *command('apply', proposal_path, applying, '--out', str(successor_path), '--resume', str(proposal.operation_id)))
    assert summary['phase'] == 'PENDING' and summary['artifact_result']['artifact_reused'] is True
    activating, authority, activated = host(app, source, monkeypatch, 'activate', pin=_pin(successor, 'PREPARED'))
    denied = invoke(capsys, *command('activate', successor_path, activating))
    assert denied[0] == 2 and denied[1] == '' and activated['keys'] == 0
    authority['pin'] = _pin(successor, 'ACTIVATING')
    summary = successful(capsys, *command('activate', successor_path, activating))
    assert summary['phase'] == 'ACTIVE' and summary['authority'] == 'HOST_SUPPLIED_PIN'
    assert snapshot(app, source) == original
    pin_path, database_path = tmp_path / 'active-pin.json', tmp_path / 'runtime-url'
    pin_path.write_text(json.dumps(asdict(_pin(successor, 'ACTIVE')), default=str))
    database_path.write_text(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
    database_path.chmod(0o600)
    observation = ('--pin', str(pin_path), '--database-url-file', str(database_path), '--json')
    status = successful(capsys, 'status', str(successor_path), *observation)
    doctor = successful(capsys, 'doctor', str(successor_path), *observation)
    assert status['phase'] == 'ACTIVE' and status['effects'] == 'NONE'
    assert doctor['checks']['runtime_deployment']['status'] == 'PASS'
    assert doctor['status'] == 'UNKNOWN' and doctor['verification'] == 'NOT_PERFORMED'
    sessions = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
        deployment=(successor, _pin(successor, 'ACTIVE')))
    with sessions(tenant_id=NEW_TENANT) as session:
        session.add(app.TenantCustomer(id=UUID(int=39901), tenant_id=NEW_TENANT, name='cli approved tenant'))
        session.commit()
        assert session.scalar(select(app.TenantCustomer.name).where(app.TenantCustomer.name == 'cli approved tenant')) == 'cli approved tenant'
    assert applied['factory'] == applied['dispose'] == 2
    assert activated['factory'] == activated['dispose'] == 2


def test_cli_cancel_source_only_and_host_scope_refusal_before_keys(tenant_app, tmp_path, monkeypatch, capsys):
    app = tenant_app
    source = active(app)
    before = snapshot(app, source)
    source_path, proposal_path, successor_path = (tmp_path / name for name in ('source.json', 'proposal.json', 'successor.json'))
    source_path.write_bytes(source.artifact)
    planning, configuration, observed = host(app, source, monkeypatch, 'plan', tenant_id=str(NEW_TENANT))
    rejected = invoke(capsys, *command('plan', source_path, planning, '--out', str(proposal_path)))
    assert rejected[0] == 2 and rejected[1] == '' and not proposal_path.exists()
    assert observed['keys'] == observed['connect'] == 0 and observed['dispose'] == 1
    configuration['tenant_id'] = NEW_TENANT
    successful(capsys, *command('plan', source_path, planning, '--out', str(proposal_path)))
    proposal = tenancy.TenantProvisionPlan(proposal_path.read_bytes())
    applying, configuration, applied = host(app, source, monkeypatch, 'apply',
        pin=_pin(proposal.activation_plan, 'PREPARED'), factory_failure=True)
    rejected = invoke(capsys, *command('apply', proposal_path, applying, '--out', str(successor_path)))
    diagnostic = json.loads(rejected[2])['error']
    assert rejected[0] == 4 and rejected[1] == '' and 'known_result' not in diagnostic
    assert diagnostic['effects'] == 'NONE' and diagnostic['artifact_result']['artifact_directory_durable'] is True
    assert successor_path.read_bytes() == proposal.activation_plan.artifact and snapshot(app, source) == before
    configuration['factory_failure'] = False
    successful(capsys, *command('apply', proposal_path, applying, '--out', str(successor_path), '--resume', str(proposal.operation_id)))
    cancelling, _, cancelled = host(app, source, monkeypatch, 'abort')
    for _ in range(2):
        summary = successful(capsys, *command('abort', proposal_path, cancelling))
        assert summary['phase'] == 'ABORTED'
    m.check_deployment(source, app.target, pin=_pin(source, 'ACTIVE'))
    assert snapshot(app, source) == before and successor_path.read_bytes() == proposal.activation_plan.artifact
    assert observed['factory'] == observed['dispose'] == 2
    assert applied['factory'] == 2 and applied['dispose'] == 1
    assert cancelled['factory'] == cancelled['dispose'] == 2
