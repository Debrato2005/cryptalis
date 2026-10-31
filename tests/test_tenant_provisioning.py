"""Real PostgreSQL authority and lifecycle for additive tenant policy publication."""
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import pytest
from sqlalchemy import select

from cryptalis import migration as m, online
from cryptalis.sqlalchemy import PolicyMismatch, attach
from sqlalchemy.exc import DBAPIError
from test_migration import keys, TENANT
from test_online_protection import app
from test_online_tenants import tenant_app, _pin, _transition_approval


NEW_TENANT = UUID(int=39199)


class ClaimedTenant(UUID):
    def __str__(self):
        return str(TENANT)


def active(app):
    proposal = app.tenant_plan
    online.apply(proposal, app.owner, keys=keys, pin=_pin(proposal, 'PREPARED'),
        approval=app.approval, max_chunks=100)
    online.apply(proposal, app.owner, keys=keys, pin=_pin(proposal, 'PREPARED'),
        approval=app.approval, max_chunks=100, fence=True)
    successor = online.seal(proposal, app.owner, keys=keys,
        pin=_pin(proposal, 'PREPARED'), approval=app.approval)
    successor = online.switch(proposal, app.owner, successor=successor, keys=keys,
        pin=_pin(proposal, 'PREPARED'), approval=app.approval)
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
        approval=_transition_approval(app), until='ACTIVE')
    return successor


def snapshot(app, source):
    with app.owner.connect() as connection:
        rows = {model['table_id']: connection.exec_driver_sql(
            f'SELECT * FROM {m._table(connection, model)} ORDER BY id').all()
            for model in source.document['lock']['models']}
        facts = {model['table_id']: m._facts(connection, model)
            for model in source.document['lock']['models']}
    return rows, facts


def test_empty_tenant_requires_exact_successor_publication_before_first_protected_write(tenant_app):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    before = snapshot(app, source)
    proposal = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    successor = proposal.activation_plan
    assert successor.document['format'] == 'cryptalis.transition/v15'
    assert successor.lock_bytes == source.lock_bytes
    assert successor.document['access_contract'] == source.document['access_contract']
    assert successor.document['key_policies'] == {
        **source.document['key_policies'], str(NEW_TENANT): m._policy(keys(NEW_TENANT))}
    assert snapshot(app, source) == before
    assert tenancy.apply(proposal, app.owner, keys=keys, pin=_pin(successor, 'PREPARED'),
        approval=_transition_approval(app)).phase == 'PENDING'
    with pytest.raises(m.TransitionFailure):
        m.check_deployment(source, app.target, pin=_pin(source, 'ACTIVE'))
    with pytest.raises(m.TransitionFailure):
        m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'PREPARED'),
            approval=_transition_approval(app), until='ACTIVE')
    assert tenancy.apply(proposal, app.owner, keys=keys, pin=_pin(successor, 'PENDING'),
        approval=_transition_approval(app)).phase == 'PENDING'
    assert m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
        approval=_transition_approval(app), until='ACTIVE').phase == 'ACTIVE'
    assert snapshot(app, successor) == before
    sessions = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=keys,
        deployment=(successor, _pin(successor, 'ACTIVE')))
    with sessions(tenant_id=NEW_TENANT) as session:
        session.add(app.TenantCustomer(id=UUID(int=39901), tenant_id=NEW_TENANT, name='new protected tenant'))
        session.commit()
        assert session.scalar(select(app.TenantCustomer.name).where(
            app.TenantCustomer.id == UUID(int=39901))) == 'new protected tenant'


@pytest.mark.parametrize('tenant', [NEW_TENANT, ClaimedTenant(int=NEW_TENANT.int)])
def test_unknown_pinned_tenant_refuses_before_key_resolver(tenant_app, tenant):
    app = tenant_app
    source = active(app)
    calls = []
    def resolve(tenant):
        calls.append(tenant)
        return keys(tenant)
    sessions = attach(app.mapping, app.target, lock=source.lock_bytes, keys=resolve,
        deployment=(source, _pin(source, 'ACTIVE')))
    with pytest.raises(PolicyMismatch):
        sessions(tenant_id=tenant)
    assert calls == []


def test_pending_policy_addition_cancels_under_source_authority_and_retry_preserves_data(tenant_app):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    before = snapshot(app, source)
    proposal = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    successor = proposal.activation_plan
    tenancy.apply(proposal, app.owner, keys=keys, pin=_pin(successor, 'PREPARED'), approval=_transition_approval(app))
    with app.target.connect() as connection, pytest.raises(DBAPIError) as denied:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".tenant_customer SET name=name')
    assert denied.value.orig.sqlstate == '55000'
    for _ in range(2):
        assert tenancy.abort(proposal, app.owner, keys=keys, pin=_pin(source, 'ACTIVE'),
            approval=_transition_approval(app)).phase == 'ABORTED'
    m.check_deployment(source, app.target, pin=_pin(source, 'ACTIVE'))
    assert snapshot(app, source) == before
    with pytest.raises(m.TransitionFailure):
        tenancy.apply(proposal, app.owner, keys=keys, pin=_pin(successor, 'PREPARED'), approval=_transition_approval(app))


@pytest.mark.parametrize('tenant', [TENANT, UUID(int=501), 'not-a-uuid'])
def test_existing_fixed_and_untyped_tenants_refuse_without_provider_access(tenant_app, tenant):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    calls = []
    def denied(tenant):
        calls.append(tenant)
        raise AssertionError('Host key resolver must not be called')
    before = snapshot(app, source)
    with pytest.raises(m.TransitionFailure):
        tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=denied,
            tenant_id=tenant, key_policy=None, verify_rows_per_second=1000)
    assert calls == [] and snapshot(app, source) == before


def test_row_appearing_after_plan_refuses_before_added_policy_lookup_and_does_not_publish(tenant_app):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    proposal = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'INSERT INTO "{app.schema}".tenant_customer (id,tenant_id,name) '
            f'SELECT %s,%s,name FROM "{app.schema}".tenant_customer LIMIT 1', (UUID(int=39999), NEW_TENANT))
    calls = []
    def resolver(tenant):
        calls.append(tenant)
        return keys(tenant)
    with pytest.raises(m.TransitionFailure) as refused:
        tenancy.apply(proposal, app.owner, keys=resolver, pin=_pin(proposal.activation_plan, 'PREPARED'),
            approval=_transition_approval(app))
    assert refused.value.code == 'tenant_scope_not_empty' and calls == []
    m.check_deployment(source, app.target, pin=_pin(source, 'ACTIVE'))
    with app.owner.connect() as connection:
        assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}"._cryptalis_journal '
            'WHERE operation_id=%s', (proposal.operation_id,)).scalar_one() == 0


def test_changed_source_and_competing_proposals_require_replanning(tenant_app):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    first = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    second = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=UUID(int=39200), key_policy=keys(UUID(int=39200)), verify_rows_per_second=1000)
    successor = first.activation_plan
    tenancy.apply(first, app.owner, keys=keys, pin=_pin(successor, 'PREPARED'), approval=_transition_approval(app))
    m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
        approval=_transition_approval(app), until='ACTIVE')
    calls = []
    def resolver(tenant):
        calls.append(tenant)
        return keys(tenant)
    with pytest.raises(m.TransitionFailure):
        tenancy.apply(second, app.owner, keys=resolver, pin=_pin(second.activation_plan, 'PREPARED'),
            approval=_transition_approval(app))
    assert calls == []


@pytest.mark.parametrize('fault', ['policy', 'predecessor', 'extra'])
def test_tenant_activation_artifact_refuses_mutated_authority(tenant_app, fault):
    from cryptalis import tenancy
    app = tenant_app
    source = active(app)
    proposal = tenancy.plan(source, app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    document = proposal.activation_plan.document
    if fault == 'policy':
        document['key_policies'][str(TENANT)] = '0' * 64
    elif fault == 'predecessor':
        document['predecessors'] = []
    else:
        document['unexpected'] = True
    with pytest.raises(m.TransitionFailure, match='invalid_plan'):
        m.MigrationPlan(m._canonical(document))


def test_physical_previous_reader_refuses_new_tenant_authority_before_execution(tenant_app, tmp_path):
    reader = os.environ.get('CRYPTALIS_TENANT_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('set CRYPTALIS_TENANT_PREVIOUS_READER_PYTHON to an installed pre-provisioning reader')
    from cryptalis import tenancy
    source = active(tenant_app)
    proposal = tenancy.plan(source, tenant_app.owner, source_pin=_pin(source, 'ACTIVE'), keys=keys,
        tenant_id=NEW_TENANT, key_policy=keys(NEW_TENANT), verify_rows_per_second=1000)
    path = tmp_path / 'new-transition.json'
    path.write_bytes(proposal.activation_plan.artifact)
    child = subprocess.run([reader, '-I', '-c',
        'import pathlib,sys; from cryptalis.migration import MigrationPlan,TransitionFailure; '
        'raw=pathlib.Path(sys.argv[1]).read_bytes(); '
        '\ntry: MigrationPlan(raw)\nexcept TransitionFailure: print("refused")\nelse: raise AssertionError("old reader accepted new authority")',
        str(path)], capture_output=True, text=True, timeout=30)
    assert child.returncode == 0 and child.stdout.strip() == 'refused'
