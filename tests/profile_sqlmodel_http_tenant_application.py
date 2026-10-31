"""Opt-in unchanged original HTTP app with explicit authenticated tenant host glue."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import pytest

pytest.importorskip('sqlmodel', reason='optional SQLModel tenant HTTP profile')
pytest.importorskip('fastapi', reason='optional original HTTP tenant profile')

from sqlmodel import Session, select
from cryptalis import deprotection as d, migration as m, online
from cryptalis import tenancy
from cryptalis.crypto.keys import KeyUnavailable
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlmodel import attach
from test_migration import DOMAIN, keys
from test_sqlmodel_application import native_engine, settings
from test_online_tenants import _rotate_all_scopes
from test_online_recovery import pg_bin, pg_environment
from sqlmodel_http_tenant_workload import native_requests, seed, workflow

SOURCE = json.loads((Path(__file__).parent / 'fixtures/sqlmodel_http_source.json').read_text())
TABLE, TITLE, DESCRIPTION = (UUID(int=value) for value in (39101, 39102, 39103))


def pin(plan, phase):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def item_rows(scoped, public):
    from app.models import Item
    with Session(public) as session:
        owners = session.exec(select(Item.id, Item.owner_id).order_by(Item.id)).all()
    result = {}
    for identity, tenant in owners:
        with scoped(tenant_id=tenant) as session:
            row = session.get(Item, identity)
            result[str(identity)] = (str(tenant), row.title, row.description)
    return result


def provision_account(*, owner, public, target, api, scoped, plan, current_keys, admin,
        reload_application, schema, artifact_directory, publish_policy=None):
    """Original authentication -> explicit host approval -> published empty policy -> HTTP write."""
    from fastapi.testclient import TestClient
    from sqlmodel_http_tenant_host import TenantHost
    from sqlmodel_http_tenant_workload import PASSWORD
    from app.api.deps import get_current_user, get_current_active_superuser
    old_plan = plan
    host = TenantHost(api, lambda: Session(public), scoped,
        approved_tenants=tuple(UUID(value) for value in plan.document['key_policies']),
        deployment=(plan, pin(plan, 'ACTIVE')))
    with host, TestClient(api) as client:
        email = uuid4().hex + '@example.com'
        registered = client.post('/api/v1/users/signup', json={'email': email, 'password': PASSWORD})
        assert registered.status_code == 200
        login = client.post('/api/v1/login/access-token', data={'username': email, 'password': PASSWORD})
        admin_login = client.post('/api/v1/login/access-token', data={
            'username': admin['email'], 'password': PASSWORD})
        assert login.status_code == admin_login.status_code == 200
        token, admin_token = login.json()['access_token'], admin_login.json()['access_token']
        headers = {'Authorization': 'Bearer ' + token}
        assert client.get('/api/v1/users/me', headers=headers).json()['id'] == registered.json()['id']
        count = len(host.scopes)
        refused = client.post('/api/v1/items/', headers=headers, json={'title': 'PUBLIC before approval'})
        assert refused.status_code == 409 and len(host.scopes) == count
    # This is a trusted host operation, not a new unauthenticated application
    # route. The original current-account and administrator rules authorize the
    # exact typed identity; no body/JWT tenant claim or database frame chooses it.
    with Session(public) as session:
        account = get_current_user(session, token)
        administrator = get_current_user(session, admin_token)
        get_current_active_superuser(administrator)
        tenant = account.id
        assert type(tenant) is UUID and str(tenant) == registered.json()['id']
    new_policy = keys(tenant)
    allowed = {UUID(value) for value in plan.document['key_policies']} | {tenant}
    def augmented(approved):
        if type(approved) is not UUID or approved not in allowed:
            raise KeyUnavailable()
        return new_policy if approved == tenant else current_keys(approved)
    with owner.connect() as connection:
        before = connection.exec_driver_sql('SELECT id,owner_id,title,description FROM item ORDER BY id').all()
    artifact_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    maintenance = m.MaintenanceApproval('Original HTTP writers stopped and drained for explicit host-approved tenant maintenance.', 3600)
    if publish_policy is None:
        proposal = tenancy.plan(plan, owner, source_pin=pin(plan, 'ACTIVE'), keys=current_keys,
            tenant_id=tenant, key_policy=new_policy, verify_rows_per_second=1000)
        (artifact_directory / 'proposal.json').write_bytes(proposal.artifact)
        successor_path = artifact_directory / 'activation.json'
        successor_path.write_bytes(proposal.activation_plan.artifact)
        successor = m.MigrationPlan(successor_path.read_bytes())
        publication = {'method': 'PYTHON_API'}
    else:
        successor, publication = publish_policy(source=plan, source_keys=current_keys, tenant_id=tenant,
            key_policy=new_policy, keys=augmented, approval=maintenance,
            artifact_directory=artifact_directory, schema=schema)
    assert successor.lock_bytes == plan.lock_bytes
    assert successor.document['access_contract'] == plan.document['access_contract']
    assert successor.document['key_policies'] == {**plan.document['key_policies'], str(tenant): m._policy(new_policy)}
    if publish_policy is None:
        assert tenancy.apply(proposal, owner, keys=augmented, pin=pin(successor, 'PREPARED'),
            approval=maintenance).phase == 'PENDING'
        assert m.apply(successor, owner, keys=augmented, pin=pin(successor, 'ACTIVATING'),
            approval=maintenance, until='ACTIVE').phase == 'ACTIVE'
    with owner.connect() as connection:
        assert connection.exec_driver_sql('SELECT id,owner_id,title,description FROM item ORDER BY id').all() == before
    # A retained old host/factory with valid old keys must refuse new requests
    # under its stale pin, even though old tenants' payload keys did not change.
    count = len(host.scopes)
    with host, TestClient(api, raise_server_exceptions=False) as client:
        stale = client.get('/api/v1/items/', headers={'Authorization': 'Bearer ' + admin_token})
        assert stale.status_code == 500 and len(host.scopes) == count
    with pytest.raises(m.TransitionFailure):
        m.check_deployment(old_plan, public, pin=pin(old_plan, 'ACTIVE'))
    target.dispose()
    api, User, Item = reload_application()
    target = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    scoped = attach(User._sa_registry, target, lock=successor.lock_bytes, keys=augmented,
        deployment=(successor, pin(successor, 'ACTIVE')))
    host = TenantHost(api, lambda: Session(public), scoped, approved_tenants=tuple(allowed),
        deployment=(successor, pin(successor, 'ACTIVE')))
    with host, TestClient(api) as client:
        written = client.post('/api/v1/items/', headers=headers, json={
            'title': 'PUBLIC newly provisioned Item ' + uuid4().hex, 'description': 'PUBLIC dynamic 雪😀'})
        assert written.status_code == 200 and written.json()['owner_id'] == str(tenant)
        latest = client.put('/api/v1/items/' + written.json()['id'], headers=headers,
            json={'title': 'PUBLIC latest provisioned Item ' + uuid4().hex, 'description': None})
        assert latest.status_code == 200
        observed = client.get('/api/v1/items/' + written.json()['id'], headers=headers)
        assert observed.status_code == 200 and observed.json() == latest.json()
    return dict(plan=successor, keys=augmented, api=api, target=target, scoped=scoped,
        tenant_id=str(tenant), item=latest.json(), publication=publication, controls=[
            'original post-migration signup/JWT then unapproved Item409 before key lookup',
            'original active administrator and account authorize exact typed new policy',
            'unchanged old policy digests/frame bytes/schema/lock/access contract through maintenance publication',
            'retained stale host pin refuses before scoped factory after publication',
            'first protected Item and latest NULL/Unicode edit/read succeed after actual successor activation'])


def complete_lifecycle(*, owner, source, public, schema, plan, cohort,
        reload_application, copied, monkeypatch, binding=None, expected_items=None, publish_policy=None):
    """One shared original-app rotation/current-value exit journey for both clusters."""
    from sqlmodel_http_tenant_host import TenantHost
    successor, current_keys = _rotate_all_scopes(owner, plan, keys, plan.document['access_contract'], binding)
    api, User, Item = reload_application()
    target = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    try:
        scoped = attach(User._sa_registry, target, lock=successor.lock_bytes, keys=current_keys,
            deployment=(successor, pin(successor, 'ACTIVE')))
        if expected_items is not None:
            assert json.loads(json.dumps(item_rows(scoped, public))) == expected_items
        tenants = tuple(UUID(value) for value in successor.document['key_policies'])
        host = TenantHost(api, lambda: Session(public), scoped, approved_tenants=tenants,
            deployment=(successor, pin(successor, 'ACTIVE')))
        with host:
            rotated = workflow(api, cohort, lambda: Session(public), host=host)
        provisioned = provision_account(owner=owner, public=public, target=target, api=api, scoped=scoped,
            plan=successor, current_keys=current_keys, admin=cohort['admin'], reload_application=reload_application,
            schema=schema, artifact_directory=Path(copied).parent / 'late-tenant-provision', publish_policy=publish_policy)
        successor, current_keys, api, target, scoped = (provisioned[name] for name in ('plan', 'keys', 'api', 'target', 'scoped'))
        from app.models import User, Item
        latest_rows = item_rows(scoped, public)
        with owner.connect() as connection:
            users_before = connection.exec_driver_sql('SELECT * FROM "user" ORDER BY id').all()
            frames = connection.exec_driver_sql('SELECT title,description FROM item').all()
            assert frames and all(bytes(title).startswith(b'CF1\0') and
                (description is None or bytes(description).startswith(b'CF1\0')) for title, description in frames)
        with source.connect() as connection:
            source_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        maintenance = m.MaintenanceApproval('Original HTTP writers stopped during maintenance; old source fenced.', 3600)
        reverse = d.plan(successor, owner, source_pin=pin(successor, 'ACTIVE'), keys=current_keys,
            plaintext_runtime_role=source_role, backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'Disposable public tenant HTTP fixtures; retained protected backup is not claimed erased.')
        assert d.apply(reverse, owner, keys=current_keys, pin=pin(reverse, 'PREPARED'),
            approval=maintenance, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=current_keys, pin=pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=maintenance, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'Original account/Item HTTP routes run after current-data reversal.',
            'Public fixture custody; historical protected backup remains recoverable.', True)
        assert d.remove(reverse, owner, pin=pin(reverse, 'REMOVING'), approval=maintenance,
            removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=pin(reverse, 'REMOVED')) is None
        api, User, Item = reload_application()
        with Session(source) as session:
            assert {str(row.id): (str(row.owner_id), row.title, row.description)
                for row in session.exec(select(Item)).all()} == latest_rows
            from sqlmodel_http_tenant_workload import PASSWORD
            retained_accounts = {str(row.id): {'email': row.email, 'password': PASSWORD}
                for row in session.exec(select(User).where(User.id.in_(
                    [UUID(values[0]) for values in latest_rows.values()]))).all()}
        retained_items = {'rows': latest_rows, 'accounts': retained_accounts}
        with owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT * FROM "user" ORDER BY id').all() == users_before
        from sqlmodel_http_workload import workflow as original_workflow
        source_factory = lambda: Session(source)
        with native_requests(api, source_factory):
            retained = original_workflow(api, source_factory)
        from sqlmodel_http_package_free import run as package_free
        with monkeypatch.context() as child_environment:
            child_environment.setenv('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', os.environ['CRYPTALIS_TEST_SOURCE_URL'])
            child = package_free(copied, schema, retained, retained_items=retained_items)
        return {'rotated': rotated, 'package_free': child, 'latest_item_count': len(latest_rows),
            'restore_lineage': successor.document.get('restore_lineage', []),
            'provisioning_controls': provisioned['controls'], 'provisioning_format': successor.document['format'],
            'provisioning_method': provisioned['publication']['method'], 'publication': provisioned['publication']}
    finally:
        target.dispose()


def test_original_http_authenticated_owners_admin_cascades_rotations_and_native_exit(tmp_path, monkeypatch):
    location = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    if not location:
        pytest.skip('set CRYPTALIS_SQLMODEL_HTTP_SOURCE to the pinned complete original snapshot')
    assert sys.version_info >= (3, 12)
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)
    copied, hashes = tmp_path / 'original', {}
    for relative, expected in SOURCE['files'].items():
        raw = (Path(location) / relative).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    monkeypatch.syspath_prepend(str(copied / 'backend'))
    monkeypatch.chdir(tmp_path)
    settings(monkeypatch)
    for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
            EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name, value)
    schema = 'sqlmodel_tenant_http_' + uuid4().hex
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    source = native_engine('CRYPTALIS_TEST_SOURCE_URL', schema)
    target = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    public = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    mapping = original_engine = host = None
    created = False
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
    def pin(plan, phase):
        return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)
    try:
        from app.models import SQLModel, User, Item
        from app.main import app as api
        from app.core.db import engine as original_engine
        mapping = User._sa_registry
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        created = True
        SQLModel.metadata.create_all(owner)
        roles = {}
        for name, engine in (('source', source), ('target', target)):
            with engine.connect() as connection:
                roles[name] = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            for name, role in roles.items():
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
                connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON "{schema}"."user" TO {quote(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON "{schema}"."item" TO {quote(roles["source"])}')
        source_factory = lambda: Session(source)
        phases = ('native', 'protected', 'rotated', 'restored') if os.environ.get('CRYPTALIS_TENANT_HTTP_BACKUP_DIR') else (
            'native', 'protected', 'rotated')
        cohorts = {phase: seed(source_factory) for phase in phases}
        native = None
        with native_requests(api, source_factory):
            native = workflow(api, cohorts['native'], source_factory)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'Item', 'table_id': str(TABLE), 'tenancy': {'column': 'owner_id'}, 'fields': [
                {'name': 'title', 'field_id': str(TITLE), 'protect': True,
                 'queries': ['equality'], 'accept_leakage': ['equality']},
                {'name': 'description', 'field_id': str(DESCRIPTION), 'protect': True,
                 'queries': [], 'accept_leakage': []}]}]}
        tenants = tuple(UUID(account['id']) for cohort in cohorts.values() for account in cohort.values())
        inventory = WriterInventory(True, (Writer(TABLE, 'original HTTP with tenant host adapters', 'sqlalchemy',
            evidence='original JWT/account authorization; public owner metadata; scoped ORM CRUD and cascade translation'),))
        preparation = online.plan(json.dumps(declaration).encode(), mapping, owner,
            source_role=roles['source'], runtime_role=roles['target'], writers=inventory,
            search_reviews=(SearchReview(TITLE, False,
                'Disposable public titles include opaque UUID128 suffixes; explicit fixture equality leakage acceptance.'),),
            native_tenants=tenants, keys=keys, target_id=uuid4(), max_rows=2, max_bytes=8192,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        approval = online.OnlineApproval('Only source-role original application writers; owner writers excluded.', True, 3600)
        online.apply(preparation, owner, keys=keys, pin=pin(preparation, 'PREPARED'), approval=approval, max_chunks=1)
        # Original source-role HTTP writes remain live after a real backfill
        # batch. Update a staged row and create the first Item in an approved
        # empty account scope before catch-up and publication.
        from fastapi.testclient import TestClient
        from sqlmodel_http_tenant_workload import PASSWORD
        captured = []
        with native_requests(api, source_factory), TestClient(api) as client:
            for cohort, path, method in ((cohorts['native'], '/api/v1/items/' + native['latest']['id'], 'put'),
                    (cohorts['protected'], '/api/v1/items/', 'post')):
                login = client.post('/api/v1/login/access-token', data={
                    'username': cohort['alice']['email'], 'password': PASSWORD})
                assert login.status_code == 200
                written = getattr(client, method)(path,
                    headers={'Authorization': 'Bearer ' + login.json()['access_token']},
                    json={'title': 'PUBLIC during tenant capture ' + uuid4().hex, 'description': None})
                assert written.status_code == 200
                captured.append((cohort['alice'], written.json()))
        online.apply(preparation, owner, keys=keys, pin=pin(preparation, 'PREPARED'), approval=approval,
            fence=True, max_chunks=100)
        successor = online.seal(preparation, owner, keys=keys, pin=pin(preparation, 'PREPARED'), approval=approval)
        successor = online.switch(preparation, owner, successor=successor, keys=keys,
            pin=pin(preparation, 'PREPARED'), approval=approval)
        maintenance = m.MaintenanceApproval('Original HTTP writers stopped during publication and maintenance.', 3600)
        m.apply(successor, owner, keys=keys, pin=pin(successor, 'ACTIVATING'), approval=maintenance, until='ACTIVE')
        from sqlmodel_http_tenant_host import TenantHost
        scoped = attach(mapping, target, lock=successor.lock_bytes, keys=keys,
            deployment=(successor, pin(successor, 'ACTIVE')))
        host = TenantHost(api, lambda: Session(public), scoped, approved_tenants=tenants,
            deployment=(successor, pin(successor, 'ACTIVE')))
        with host:
            with TestClient(api) as client:
                for account, expected in captured:
                    login = client.post('/api/v1/login/access-token', data={
                        'username': account['email'], 'password': PASSWORD})
                    assert login.status_code == 200
                    observed = client.get('/api/v1/items/' + expected['id'],
                        headers={'Authorization': 'Bearer ' + login.json()['access_token']})
                    assert observed.status_code == 200 and observed.json() == expected
            protected = workflow(api, cohorts['protected'], lambda: Session(public), host=host)
            with TestClient(api, raise_server_exceptions=False) as client:
                token = client.post('/api/v1/login/access-token', data={
                    'username': cohorts['protected']['alice']['email'], 'password': PASSWORD})
                assert token.status_code == 200
                headers = {'Authorization': 'Bearer ' + token.json()['access_token']}
                identity = UUID(protected['latest']['id'])
                tenant = UUID(cohorts['protected']['alice']['id'])
                other = UUID(cohorts['protected']['bob']['id'])
                before = host.payload_requests
                def owner_changed(record, _tenant):
                    host.after_owner_probe = None
                    with owner.begin() as connection:
                        connection.exec_driver_sql('UPDATE item SET owner_id=%s WHERE id=%s', (other, record))
                host.after_owner_probe = owner_changed
                try:
                    raced = client.get('/api/v1/items/' + str(identity), headers=headers)
                    assert raced.status_code == 409
                    assert host.payload_requests == before
                finally:
                    host.after_owner_probe = None
                    with owner.begin() as connection:
                        connection.exec_driver_sql('UPDATE item SET owner_id=%s WHERE id=%s', (tenant, identity))
                with owner.connect() as connection:
                    original_frame = bytes(connection.exec_driver_sql('SELECT title FROM item WHERE id=%s', (identity,)).scalar_one())
                try:
                    damaged = original_frame[:-1] + bytes([original_frame[-1] ^ 1])
                    with owner.begin() as connection:
                        connection.exec_driver_sql('UPDATE item SET title=%s WHERE id=%s', (damaged, identity))
                    refused = client.get('/api/v1/items/' + str(identity), headers=headers)
                    assert refused.status_code == 500
                    assert protected['latest']['title'] not in refused.text
                finally:
                    with owner.begin() as connection:
                        connection.exec_driver_sql('UPDATE item SET title=%s WHERE id=%s', (original_frame, identity))
                restored = client.get('/api/v1/items/' + str(identity), headers=headers)
                assert restored.status_code == 200 and restored.json() == protected['latest']
        assert native['controls'] == protected['controls'][:len(native['controls'])]
        initial_provision = provision_account(owner=owner, public=public, target=target, api=api,
            scoped=scoped, plan=successor, current_keys=keys, admin=cohorts['protected']['admin'],
            reload_application=reload_application, schema=schema, artifact_directory=tmp_path / 'initial-tenant-provision')
        successor, api, target, scoped = (initial_provision[name] for name in ('plan', 'api', 'target', 'scoped'))
        from app.models import User, Item
        backup = os.environ.get('CRYPTALIS_TENANT_HTTP_BACKUP_DIR')
        if backup:
            directory = Path(backup)
            with (directory / 'protected.sql').open('xb') as output:
                os.chmod(output.name, 0o600)
                dumped = subprocess.run([pg_bin('pg_dump'), '--schema=' + schema],
                    env=pg_environment(os.environ['CRYPTALIS_TEST_DATABASE_URL']),
                    stdout=output, stderr=subprocess.PIPE)
            assert dumped.returncode == 0, 'Tenant application protected dump failed; diagnostics withheld'
            with (directory / 'manifest.json').open('x') as output:
                json.dump({'schema': schema, 'source_plan': successor.document,
                    'application_revision': SOURCE['revision'], 'application_source_sha256': hashes,
                    'cohort': cohorts['restored'], 'expected_items': item_rows(scoped, public),
                    'original_native_controls': native['controls']}, output, indent=2)
            os.chmod(directory / 'manifest.json', 0o600)
        target.dispose()
        completed = complete_lifecycle(owner=owner, source=source, public=public, schema=schema,
            plan=successor, cohort=cohorts['rotated'], reload_application=reload_application,
            copied=copied, monkeypatch=monkeypatch)
        rotated, child = completed['rotated'], completed['package_free']
        assert rotated['controls'] == protected['controls']
        assert hashes == {relative: hashlib.sha256((copied / relative).read_bytes()).hexdigest() for relative in hashes}
        receipt = os.environ.get('CRYPTALIS_TENANT_HTTP_REPORT')
        if receipt:
            with Path(receipt).open('x') as stream:
                json.dump({'application_revision': SOURCE['revision'], 'application_source_sha256': hashes,
                    'original_source_edits': [], 'protected_fields': ['Item.title', 'Item.description'],
                    'host_adaptations': ['original JWT/account authentication before scope selection',
                        'public owner preauthorization and scoped locked race recheck',
                        'administrator exact public metadata pagination and owner-scoped payload loads',
                        'administrator owner-only bulk delete translated to transactional scoped ORM cascade'],
                    'native_controls': native['controls'], 'protected_controls': protected['controls'],
                    'online_http_controls': ['post-backfill original Item update and first Item in an empty approved account scope',
                        'exact captured HTTP values after protected publication'],
                    'fault_controls': ['owner race refuses 409 before protected Item load',
                        'damaged authenticated title refuses HTTP500 without plaintext; restored frame reads correctly'],
                    'initial_provisioning_controls': initial_provision['controls'],
                    'later_provisioning_controls': completed['provisioning_controls'],
                    'rotated_controls': rotated['controls'], 'package_free': child,
                    'boundary': 'Local original ASGI routes; preapproved existing owner policies; public fixture custody. '
                        'Explicit maintenance tenant provisioning uses a global pause and O(N) frame scans. '
                        'Scalable online signup provisioning, production fencing, '
                        'external custody, pause budgets and independent review remain UNKNOWN.',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        for engine in (target, public, source):
            engine.dispose()
        if original_engine is not None:
            original_engine.dispose()
        if created:
            with owner.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        if mapping is not None:
            mapping.dispose()
            mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
