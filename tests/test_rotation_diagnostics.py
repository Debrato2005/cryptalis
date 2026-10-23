"""Rotation input and missing-publication failures preserve native state."""
from uuid import UUID

import pytest

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring
from test_deprotection import app_pin
from test_migration import application, publish, run
from test_payload_rotation_execution import snapshot
import test_payload_rotation_cutover as payload
import test_search_rotation_lifecycle as search


@pytest.mark.parametrize('planner', [r.plan_payload_rotation, r.plan_search_rotation],
                         ids=['payload', 'search'])
@pytest.mark.parametrize('source', [None, object()], ids=['none', 'object'])
def test_invalid_rotation_source_is_typed_before_connection_or_keys(planner, source):
    calls = []

    class ForbiddenEngine:
        def connect(self):
            calls.append('connect')
            raise AssertionError('Invalid source reached the database')

    def forbidden(*args, **kwargs):
        calls.append('keys')
        raise AssertionError('Invalid source reached key work')

    pin = m.DeploymentPin(UUID(int=1), UUID(int=2), '0' * 64, 'ACTIVE')
    with pytest.raises(m.TransitionFailure) as refused:
        planner(source, ForbiddenEngine(), source_pin=pin, keys=forbidden,
                target_keys=forbidden, backfill_rows_per_second=1000,
                verify_rows_per_second=1000, temporary_bytes_per_row=1024,
                wal_bytes_per_row=2048)
    assert refused.value.code == 'external_policy_mismatch'
    assert calls == []


@pytest.mark.parametrize('workflow,code', [
    (payload, 'missing_payload_activation'),
    (search, 'missing_search_activation'),
], ids=['payload', 'search'])
def test_pending_pin_cannot_claim_uncommitted_rotation_activation(monkeypatch, workflow, code):
    with application() as app:
        run(app)
        publish(app)
        proposal = workflow.plan(app, workflow.target_keys)
        assert workflow.stage(app, proposal, workflow.target_keys).phase == 'BACKFILLED'
        activation = workflow.seal(app, proposal)
        before = snapshot(app, proposal)
        calls = []

        def forbidden(*args, **kwargs):
            calls.append('keys')
            raise AssertionError('Missing activation reached key work')

        monkeypatch.setattr(Keyring, 'prepare', forbidden)
        switch = r.switch_payload_rotation if workflow is payload else r.switch_search_rotation
        with pytest.raises(m.TransitionFailure) as refused:
            switch(proposal, activation, app.owner, keys=forbidden, target_keys=forbidden,
                   pin=app_pin(activation, 'PENDING'), approval=app.approval)
        assert refused.value.code == code
        assert refused.value.operation_id == activation.operation_id
        assert calls == []
        assert snapshot(app, proposal) == before
