"""Pinned tenant admission must precede the host key-authority callback."""
from uuid import UUID

import pytest
from sqlalchemy import select

from cryptalis import migration as m, online
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_migration import TENANT, keys
from test_online_protection import app
from test_online_tenants import tenant_app, _pin, _transition_approval


UNKNOWN = UUID(int=39199)


class ClaimedTenant(UUID):
    def __str__(self):
        return str(TENANT)


@pytest.mark.parametrize('tenant', [UNKNOWN, ClaimedTenant(int=UNKNOWN.int)])
def test_pinned_unknown_or_custom_tenant_refuses_before_host_key_lookup(tenant_app, tenant):
    app, proposal = tenant_app, tenant_app.tenant_plan
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
    resolutions = []

    def resolve(scope):
        resolutions.append(scope)
        return keys(scope)

    sessions = attach(app.mapping, app.target, lock=successor.lock_bytes, keys=resolve,
                      deployment=(successor, _pin(successor, 'ACTIVE')))
    with pytest.raises(PolicyMismatch):
        sessions(tenant_id=tenant)
    assert resolutions == []
    with sessions(tenant_id=TENANT) as session:
        assert session.scalar(select(app.TenantCustomer.name).where(
            app.TenantCustomer.id == UUID(int=1001))) == 'same-name'
    assert resolutions and all(type(scope) is UUID and scope == TENANT for scope in resolutions)
