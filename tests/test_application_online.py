"""One manifest through native capture, tenant publication and current-value exit."""
from dataclasses import replace
import json
from uuid import UUID, uuid4

import pytest
from sqlalchemy import MetaData, Table, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import deprotection as d, migration as m
from cryptalis.application import ApplicationConfig, ConfigurationInvalid
from cryptalis.crypto import KeyUnavailable
from cryptalis.manifest.compiler import SearchReview
from cryptalis.sqlalchemy import PolicyMismatch
from test_migration import keys, TENANT
from test_online_protection import app, _pin, _payloads, _source_rows, _engine
from test_online_tenants import tenant_app, NIL_TENANT, OTHER_TENANT, _transition_approval
from test_tenant_provisioning import NEW_TENANT, snapshot


def configuration(app, proposal):
    lock = proposal.document['lock']
    return ApplicationConfig(json.dumps(lock['declaration']).encode(), app.mapping, app.inventory,
        tuple(SearchReview(UUID(r['field_id']), r['small_domain'], r['evidence']) for r in lock['search_reviews']))


def plan_online(configured, app, resolver=keys):
    return configured.plan_online(app.owner, keys=resolver,
        source_role=app.source_role, runtime_role=app.target_role, target_id=uuid4(),
        native_tenants=(NIL_TENANT, TENANT, OTHER_TENANT), max_rows=1, max_bytes=4096,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=2000, wal_bytes_per_row=4000)


def activate(configured, app, successor, resolver=keys):
    assert configured.apply(app.owner, deployment=(successor, _pin(successor, 'ACTIVATING')),
        keys=resolver, approval=_transition_approval(app), until='ACTIVE').phase == 'ACTIVE'
    return successor, _pin(successor, 'ACTIVE')


def capture(configured, app, resolver=keys):
    proposal = plan_online(configured, app, resolver)
    deployment = proposal, _pin(proposal, 'PREPARED')
    assert configured.status(app.owner, deployment=deployment).phase == 'PREPARED'
    first = configured.capture_online(app.owner, deployment=deployment,
        keys=resolver, approval=app.approval, max_chunks=1)
    assert first.phase == 'CAPTURING' and first.committed_chunks == 1
    saved = _payloads(app, proposal)
    def unavailable(tenant): raise KeyUnavailable()
    with pytest.raises(m.TransitionFailure):
        configured.capture_online(app.owner, deployment=deployment,
            keys=unavailable, approval=app.approval, max_chunks=1)
    assert _payloads(app, proposal) == saved
    assert configured.status(app.owner, deployment=deployment).committed_chunks == 1
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=20)).body = 'edited during native capture'
        session.add(app.TenantCustomer(id=UUID(int=1003), tenant_id=TENANT, name=None))
        session.commit()
    assert configured.capture_online(app.owner, deployment=deployment,
        keys=resolver, approval=app.approval, max_chunks=100, fence=True).phase == 'FENCED'
    with app.source.connect() as connection, pytest.raises(DBAPIError) as refused:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET body=body')
    assert refused.value.orig.sqlstate in ('42501', '55000')
    configured.capture_online(app.owner, deployment=deployment,
        keys=resolver, approval=app.approval, max_chunks=100)
    successor = configured.seal_online(app.owner, deployment=deployment, keys=resolver, approval=app.approval)
    assert configured.switch_online(app.owner, deployment=deployment, successor=successor,
        keys=resolver, approval=app.approval).artifact == successor.artifact
    assert configured.status(app.owner, deployment=(successor, _pin(successor, 'PREPARED'))).phase == 'PENDING'
    return activate(configured, app, successor, resolver)


def exercise_online(app, resolver=keys):
    configured = configuration(app, app.tenant_plan)
    source = capture(configured, app, resolver)
    before = snapshot(app, source[0])
    def addition():
        return configured.plan_tenant(app.owner, deployment=source, keys=resolver,
            tenant_id=NEW_TENANT, key_policy=resolver(NEW_TENANT), verify_rows_per_second=1000)
    proposal = addition()
    successor = proposal.activation_plan
    pending = successor, _pin(successor, 'PREPARED')
    configured.provision_tenant(app.owner, proposal=proposal, deployment=pending,
        keys=resolver, approval=_transition_approval(app))
    def source_only(tenant):
        if tenant == NEW_TENANT: pytest.fail('cancel accessed unpublished tenant custody')
        return resolver(tenant)
    assert configured.abort_tenant(app.owner, proposal=proposal, deployment=source,
        keys=source_only, approval=_transition_approval(app)).phase == 'ABORTED'
    assert snapshot(app, source[0]) == before
    proposal = addition()
    successor = proposal.activation_plan
    pending = successor, _pin(successor, 'PREPARED')
    for _ in range(2):
        assert configured.provision_tenant(app.owner, proposal=proposal, deployment=pending,
            keys=resolver, approval=_transition_approval(app)).phase == 'PENDING'
    # PENDING has intentional writer fences; bytes remain unchanged until the
    # matching publication removes those guards and restores the native schema.
    assert snapshot(app, source[0])[0] == before[0]
    active = activate(configured, app, successor, resolver)
    assert snapshot(app, successor) == before
    runtime = _engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        with pytest.raises(PolicyMismatch):
            configured.attach(runtime, deployment=source, keys=resolver)
        sessions = configured.attach(runtime, deployment=active, keys=resolver)
        with sessions(tenant_id=NEW_TENANT) as session:
            session.add(app.TenantCustomer(id=UUID(int=1020), tenant_id=NEW_TENANT, name='same-name'))
            session.commit()
            assert session.scalars(select(app.TenantCustomer.id).where(
                app.TenantCustomer.name.in_(['same-name']))).all() == [UUID(int=1020)]
            session.get(app.TenantCustomer, UUID(int=1020)).name = 'latest after onboarding'
            session.commit()
            session.add(app.TenantCustomer(id=UUID(int=1021), tenant_id=NEW_TENANT, name='latest after onboarding'))
            with pytest.raises(IntegrityError) as duplicate: session.commit()
            assert duplicate.value.orig.sqlstate == '23505'
            session.rollback()
        with sessions(tenant_id=TENANT) as session:
            assert session.scalars(select(app.TenantCustomer.id).where(
                app.TenantCustomer.name == 'same-name')).all() == [UUID(int=1001)]
            assert session.scalar(select(app.TenantCustomer.name).where(app.TenantCustomer.id == UUID(int=1003))) is None
    finally:
        runtime.dispose()
    reverse = configured.plan_deprotection(app.owner, deployment=active, keys=resolver,
        plaintext_runtime_role=app.source_role, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        True, 'Public synthetic values; retained test keys remain available.')
    assert configured.decrypt_back(app.owner, deployment=(reverse, _pin(reverse, 'PREPARED')),
        keys=resolver, approval=_transition_approval(app), consent=consent).phase == 'PLAINTEXT_PENDING'
    configured.decrypt_back(app.owner, deployment=(reverse, _pin(reverse, 'PLAINTEXT_ACTIVATING')),
        keys=resolver, approval=_transition_approval(app), consent=consent, until='PLAINTEXT_ACTIVE')
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'Native source-role current-value verification', 'Synthetic fixture; custody retained', True)
    assert configured.remove(app.owner, deployment=(reverse, _pin(reverse, 'REMOVING')),
        approval=_transition_approval(app), consent=consent, removal=removal).phase == 'REMOVED'
    # Like restarted application workers, use ordinary fresh mappings after
    # removing protection; do not rely on previously cached native statements.
    native = registry(metadata=MetaData(schema=app.schema))
    class Customer: pass
    class TenantCustomer: pass
    try:
        native.map_imperatively(Customer, Table('customer', native.metadata, autoload_with=app.source))
        native.map_imperatively(TenantCustomer, Table('tenant_customer', native.metadata, autoload_with=app.source))
        with sessionmaker(app.source)() as session:
            assert session.get(Customer, UUID(int=20)).body == 'edited during native capture'
            assert {r.id: (r.tenant_id, r.name) for r in session.scalars(select(TenantCustomer))} == {
                UUID(int=1001): (TENANT, 'same-name'), UUID(int=1002): (OTHER_TENANT, 'same-name'),
                UUID(int=1003): (TENANT, None), UUID(int=1020): (NEW_TENANT, 'latest after onboarding')}
    finally:
        native.dispose()


def test_shared_online_capture_tenant_publication_and_current_value_removal(tenant_app):
    exercise_online(tenant_app)


@pytest.mark.parametrize('fence', [False, True])
def test_shared_online_abort_preserves_native_edits_without_keys(app, fence):
    configured = configuration(app, app.plan)
    deployment = app.plan, app.pin
    configured.capture_online(app.owner, deployment=deployment, keys=keys, approval=app.approval)
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=10)).body = 'current native edit'
        session.commit()
    configured.capture_online(app.owner, deployment=deployment, keys=keys,
        approval=app.approval, max_chunks=0, fence=fence)
    for _ in range(2):
        assert configured.abort_online(app.owner, deployment=deployment, approval=app.approval).phase == 'ABORTED'
    assert configured.status(app.owner, deployment=deployment).phase == 'ABORTED'
    assert _source_rows(app)[UUID(int=10)][0] == 'current native edit'


@pytest.mark.parametrize('fault', ['manifest', 'inventory', 'review'])
def test_online_and_tenant_routes_reject_intent_drift_before_database_or_keys(tenant_app, fault):
    app = tenant_app
    configured = configuration(app, app.tenant_plan)
    source = capture(configured, app)
    proposal = configured.plan_tenant(app.owner, deployment=source, keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    if fault == 'manifest':
        manifest = json.loads(configured.manifest); manifest['domain_id'] = str(uuid4())
        configured = replace(configured, manifest=json.dumps(manifest).encode())
    elif fault == 'inventory': configured = replace(configured, writers=replace(configured.writers, complete=False))
    else: configured = replace(configured, search_reviews=())
    def forbidden(*args): pytest.fail('intent drift accessed custody')
    online = app.tenant_plan, app.tenant_pin
    pending = proposal.activation_plan, _pin(proposal.activation_plan, 'PREPARED')
    operations = [
        lambda: configured.status(object(), deployment=online),
        lambda: configured.capture_online(object(), deployment=online, keys=forbidden, approval=app.approval),
        lambda: configured.seal_online(object(), deployment=online, keys=forbidden, approval=app.approval),
        lambda: configured.switch_online(object(), deployment=online, successor=source[0], keys=forbidden, approval=app.approval),
        lambda: configured.abort_online(object(), deployment=online, approval=app.approval),
        lambda: configured.plan_tenant(object(), deployment=source, keys=forbidden, tenant_id=NEW_TENANT, key_policy=None, verify_rows_per_second=1000),
        lambda: configured.provision_tenant(object(), proposal=proposal, deployment=pending, keys=forbidden, approval=app.approval),
        lambda: configured.abort_tenant(object(), proposal=proposal, deployment=source, keys=forbidden, approval=app.approval)]
    for operation in operations:
        with pytest.raises(ConfigurationInvalid) as error: operation()
        assert error.value.code == ('Application.ManifestMismatch' if fault == 'manifest' else 'Application.HostEvidenceMismatch')


def test_shared_online_query_admission_precedes_custody(tenant_app):
    app = tenant_app
    configured = replace(configuration(app, app.tenant_plan),
        queries=(select(app.TenantCustomer.name).order_by(app.TenantCustomer.name),))
    def forbidden(*args): pytest.fail('unsupported protected query accessed custody')
    with pytest.raises(m.TransitionFailure, match='query_samples_incompatible'):
        plan_online(configured, app, forbidden)


def test_online_pin_and_approval_refuse_before_effects(app):
    configured = configuration(app, app.plan)
    def forbidden(*args): pytest.fail('invalid authority accessed custody')
    with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
        configured.capture_online(object(), deployment=(app.plan, replace(app.pin, plan_digest='f'*64)),
            keys=forbidden, approval=app.approval)
    with pytest.raises(m.TransitionFailure, match='online_capture_approval_required'):
        configured.capture_online(object(), deployment=(app.plan, app.pin), keys=forbidden, approval=None)


def test_tenant_wrong_successor_pin_and_missing_approval_refuse_before_effects(tenant_app):
    app = tenant_app
    configured = configuration(app, app.tenant_plan)
    source = capture(configured, app)
    proposal = configured.plan_tenant(app.owner, deployment=source, keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    successor = proposal.activation_plan
    pending = successor, _pin(successor, 'PREPARED')
    def forbidden(*args): pytest.fail('invalid tenant authority accessed custody')
    with pytest.raises(ConfigurationInvalid, match='Application.InvalidDeployment'):
        configured.provision_tenant(object(), proposal=proposal, deployment=source,
            keys=forbidden, approval=_transition_approval(app))
    with pytest.raises(ConfigurationInvalid, match='Application.InvalidDeployment'):
        configured.abort_tenant(object(), proposal=proposal, deployment=pending,
            keys=forbidden, approval=_transition_approval(app))
    with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
        configured.provision_tenant(object(), proposal=proposal,
            deployment=(successor, replace(pending[1], plan_digest='f'*64)),
            keys=forbidden, approval=_transition_approval(app))
    with pytest.raises(m.TransitionFailure, match='maintenance_approval_required'):
        configured.provision_tenant(object(), proposal=proposal, deployment=pending, keys=forbidden, approval=None)
