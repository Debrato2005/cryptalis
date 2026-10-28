"""Fresh-cluster recovery of the original authenticated owner-scoped HTTP app.

The outer online qualification harness stops the source cluster before creating
this cluster. Public fixture keys are reconstructible; no live custody claim.
The original application and the shared complete lifecycle remain unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

pytest.importorskip('sqlmodel', reason='optional original tenant HTTP recovery')
pytest.importorskip('fastapi', reason='optional original tenant HTTP recovery')

from cryptalis import migration as m, restore
from sqlmodel import Session
from profile_sqlmodel_http_tenant_application import SOURCE, complete_lifecycle, pin
from profile_online_http_restore import _restore_dump
from test_migration import keys
from test_sqlmodel_application import native_engine, settings


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
            copied=copied, monkeypatch=monkeypatch, binding=binding, expected_items=manifest['expected_items'])
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
