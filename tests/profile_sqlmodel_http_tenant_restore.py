"""Fresh-cluster recovery of the original authenticated owner-scoped HTTP app.

The outer online qualification harness stops the source cluster before creating
this cluster. Public fixture keys are reconstructible; no live custody claim.
The original application and the shared complete lifecycle remain unchanged.
"""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType
from uuid import UUID, uuid4

import pytest

pytest.importorskip('sqlmodel', reason='optional original tenant HTTP recovery')
pytest.importorskip('fastapi', reason='optional original tenant HTTP recovery')

from cryptalis import cli, cli_host, migration as m, restore, tenancy
from sqlalchemy import event
from sqlmodel import Session
from profile_sqlmodel_http_tenant_application import SOURCE, complete_lifecycle, pin
from profile_online_http_restore import _restore_dump
from test_migration import keys
from test_sqlmodel_application import native_engine, settings


def _cli_publication(monkeypatch, *, source, source_keys, tenant_id, key_policy, keys,
        approval, artifact_directory, schema):
    """Fixture host publishes its own retained pins; the CLI never creates authority."""
    def retain(name, raw):
        path = artifact_directory / name
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(artifact_directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path

    def publish_host_pin(plan, phase):
        # This is an explicit local host publication, independent of the journal
        # and CLI. Each version is retained rather than inferred from DB state.
        return retain('host-' + phase.lower() + '.json',
            json.dumps(asdict(pin(plan, phase)), default=str, sort_keys=True).encode())

    source_path = retain('source.json', source.artifact)
    host_pin = publish_host_pin(source, 'ACTIVE')
    source_pin = host_pin
    action = 'plan'
    successor = None
    proposal_path, successor_path = artifact_directory / 'proposal.json', artifact_directory / 'activation.json'
    observed = dict(factory=0, dispose=0, keys=0)
    module = ModuleType('restored_tenant_cli_host_' + uuid4().hex)

    def read_pin(path):
        document = json.loads(path.read_bytes())
        assert set(document) == {'target_id', 'operation_id', 'plan_digest', 'phase'}
        return m.DeploymentPin(UUID(document['target_id']), UUID(document['operation_id']),
            document['plan_digest'], document['phase'])

    def factory():
        observed['factory'] += 1
        if action == 'apply':
            assert successor_path.read_bytes() == successor.artifact
        owned = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
        event.listen(owned, 'engine_disposed', lambda *_:
            observed.__setitem__('dispose', observed['dispose'] + 1))
        def resolve(tenant):
            observed['keys'] += 1
            return (source_keys if action == 'plan' else keys)(tenant)
        if action == 'plan':
            return cli_host.TenantPlanningContext(owned, resolve, read_pin(source_pin),
                tenant_id, key_policy, 1000, None)
        context = cli_host.TenantApplyContext if action == 'apply' else cli_host.TenantActivationContext
        return context(owned, resolve, read_pin(host_pin), approval)

    monkeypatch.setitem(sys.modules, module.__name__, module)
    module.factory = factory
    reference = module.__name__ + ':factory'
    def invoke(path, *, out=None, expected=0):
        arguments = ['tenants', 'provision', action, str(path), '--host-context', reference, '--json']
        if out is not None:
            arguments.extend(('--out', str(out)))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(arguments)
        assert code == expected, (code, stderr.getvalue())
        assert not (stderr.getvalue() if expected == 0 else stdout.getvalue())
        return json.loads(stdout.getvalue() if expected == 0 else stderr.getvalue())

    planned = invoke(source_path, out=proposal_path)
    proposal = tenancy.TenantProvisionPlan(proposal_path.read_bytes())
    successor = proposal.activation_plan
    assert successor.document['format'] == 'cryptalis.transition/v16'
    assert planned['artifact_directory_durable'] is True and planned['proposal_digest'] == proposal.digest
    host_pin = publish_host_pin(successor, 'PREPARED')
    action = 'apply'
    pending = invoke(proposal_path, out=successor_path)
    assert pending['phase'] == 'PENDING' and pending['artifact_result']['artifact_directory_durable'] is True
    action = 'activate'
    malformed_path = retain('malformed.json', b'{"format":"cryptalis.transition/v16"}')
    before = dict(observed)
    malformed = invoke(malformed_path, expected=2)['error']
    assert malformed['code'] == 'InvalidInput' and observed == before
    premature = invoke(successor_path, expected=2)['error']
    assert premature['code'] == 'tenant_provision_executor_required' and observed['keys'] == before['keys']
    host_pin = publish_host_pin(successor, 'ACTIVATING')
    active = invoke(successor_path)
    assert active['phase'] == 'ACTIVE' and active['authority'] == 'HOST_SUPPLIED_PIN'
    # Publication after the successful transition is another explicit host
    # operation. Retain it without modifying the saved source ACTIVE authority.
    active_path = retain('host-successor-active.json',
        json.dumps(asdict(pin(successor, 'ACTIVE')), default=str, sort_keys=True).encode())
    assert read_pin(source_pin) == pin(source, 'ACTIVE')
    assert read_pin(active_path) == pin(successor, 'ACTIVE')
    assert observed['factory'] == observed['dispose'] == 4
    return successor, dict(method='CLI', format=successor.document['format'],
        phases=[planned['phase'], pending['phase'], active['phase']],
        malformed_before_host=True, premature_publication_before_keys=True,
        proposal_digest=proposal.digest, activation_digest=successor.digest,
        retained_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in artifact_directory.iterdir()}, owned_engines=observed['dispose'],
        pin_authority='explicit local fixture host; independently retained ACTIVE/PREPARED/ACTIVATING/ACTIVE versions')


def test_original_tenant_http_fresh_restore_adopt_rotate_and_package_free_exit(tmp_path, monkeypatch):
    snapshot = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    backup = os.environ.get('CRYPTALIS_TENANT_HTTP_BACKUP_DIR')
    if not snapshot or not backup:
        pytest.skip('requires the pinned original snapshot and --tenant-http-fresh backup directory')
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    manifest = json.loads((Path(backup) / 'manifest.json').read_text())
    source_plan = m.MigrationPlan(m._canonical(manifest['source_plan']))
    assert manifest['application_revision'] == SOURCE['revision']
    copied, hashes = tmp_path / 'original', {}
    for relative, expected in SOURCE['files'].items():
        raw = (Path(snapshot) / relative).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    assert hashes == manifest['application_source_sha256']
    monkeypatch.syspath_prepend(str(copied / 'backend'))
    monkeypatch.chdir(tmp_path)
    settings(monkeypatch)
    for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
            EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name, value)
    schema = manifest['schema']
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    source = native_engine('CRYPTALIS_TEST_SOURCE_URL', schema)
    public = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = original_engine = None
    restored = False
    def reload_application():
        nonlocal mapping, original_engine
        original_engine.dispose()
        mapping.dispose()
        mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
        from app.main import app
        from app.models import User, Item
        from app.core.db import engine
        mapping, original_engine = User._sa_registry, engine
        return app, User, Item
    try:
        from app.models import User
        from app.core.db import engine as original_engine
        mapping = User._sa_registry
        _restore_dump(Path(backup) / 'protected.sql')
        restored = True
        contract = source_plan.document['access_contract']
        for engine, role in ((owner, 'owner'), (source, 'source_role'), (public, 'target_role')):
            with engine.connect() as connection:
                assert connection.exec_driver_sql('SELECT current_user').scalar_one() == contract[role]
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source_plan, owner, pin=pin(source_plan, 'ACTIVE'))
        approval = restore.RestoreApproval('local original tenant HTTP recovery host',
            'adopt the protected backup after source cluster shutdown',
            'source cluster stopped and decommissioned; restored target quarantined before publication', True)
        binding = restore.plan(source_plan, owner, pin=pin(source_plan, 'ACTIVE'), keys=keys, approval=approval)
        assert m.diagnose_deployment(source_plan, public, pin=pin(source_plan, 'ACTIVE'), restore=binding) is None
        completed = complete_lifecycle(owner=owner, source=source, public=public, schema=schema,
            plan=source_plan, cohort=manifest['cohort'], reload_application=reload_application,
            copied=copied, monkeypatch=monkeypatch, binding=binding, expected_items=manifest['expected_items'],
            publish_policy=lambda **inputs: _cli_publication(monkeypatch, **inputs))
        assert completed.get('provisioning_method') == 'CLI'
        assert completed['publication']['phases'] == ['PREPARED', 'PENDING', 'ACTIVE']
        assert completed['restore_lineage'] == [binding.document]
        assert completed['rotated']['controls'][:len(manifest['original_native_controls'])] == manifest['original_native_controls']
        assert hashes == {relative: hashlib.sha256((copied / relative).read_bytes()).hexdigest() for relative in hashes}
        receipt = os.environ.get('CRYPTALIS_TENANT_HTTP_REPORT')
        if receipt:
            with Path(receipt).open('x') as stream:
                json.dump({'application_revision': SOURCE['revision'], 'application_source_sha256': hashes,
                    'original_source_edits': [], 'ordinary_unadopted_startup_refused': True,
                    'explicit_restore_binding': True, 'backup_item_count': len(manifest['expected_items']),
                    'latest_item_count': completed['latest_item_count'],
                    'restored_http_controls': completed['rotated']['controls'],
                    'provisioning_controls': completed['provisioning_controls'],
                    'provisioning_format': completed['provisioning_format'],
                    'provisioning_cli': completed['publication'],
                    'package_free': completed['package_free'],
                    'boundary': 'Distinct local PostgreSQL16 clusters with successful source shutdown first. '
                        'Original HTTP/JWT and explicit tenant/admin/cascade host adapters. '
                        'Explicit maintenance owner-policy addition, global writer pause, O(N) verification and '
                        'public reconstructible fixture custody only. Scalable online signup provisioning, '
                        'production fencing, independent custody/review and measured pause budgets remain UNKNOWN.',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        source.dispose()
        public.dispose()
        if original_engine is not None:
            original_engine.dispose()
        if restored:
            with owner.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        if mapping is not None:
            mapping.dispose()
            mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
