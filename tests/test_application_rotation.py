"""Shared manifest intent across three rotations, recovery and native exit."""
from dataclasses import replace
import json
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError

from cryptalis.application import ConfigurationInvalid
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring, create_root
from cryptalis.crypto._rewrap import prepare_rewrap
from cryptalis.migration import TransitionFailure
from test_application_config import config
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows
from test_migration import application, frames, keys, publish, run, TENANT
from test_payload_rotation_execution import operation_pin, staged_frames
from test_rewrap_abort import index_identity


def generation_keys(source, provider, purpose):
    old = source(TENANT) if callable(source) else source
    context = KeyContext(old.policy.domain_id, TENANT, purpose, uuid4(), 2)
    wrapper = create_root(provider, context)
    policy = replace(old.policy, wrappers=old.policy.wrappers + (wrapper,),
                     **{purpose + '_generation': 2})
    return Keyring(policy, {**old._providers, provider.provider_id: provider})


def plan_generation(configured, app, purpose, source, target):
    return configured.plan_rotation(app.owner, purpose=purpose, deployment=(app.plan, app.pin),
        keys=source, target_keys=target, backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
        max_batch_rows=3)


def activate(configured, app, successor, target):
    assert configured.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
        keys=target, approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
    app.plan, app.pin = successor, app_pin(successor, 'ACTIVE')


def exercise_rotations(app, configured, source=keys, provider=None):
    """Run with either public development custody or the separate actual service."""
    provider = provider or DevelopmentKeyProvider()
    source_ring = source(TENANT) if callable(source) else source
    target = Keyring(prepare_rewrap(source_ring, provider), {provider.provider_id: provider})
    proposal = configured.plan_rewrap(app.owner, deployment=(app.plan, app.pin), keys=source,
        target_keys=target, verify_rows_per_second=1000)
    original, index = frames(app, True), index_identity(app)
    successor = proposal.activation_plan
    pending = (successor, app_pin(successor, 'PREPARED'))
    assert configured.rewrap(app.owner, proposal=proposal, deployment=pending,
        keys=source, target_keys=target, approval=app.approval).phase == 'PENDING'
    assert configured.rewrap(app.owner, proposal=proposal, deployment=pending,
        keys=source, target_keys=target, approval=app.approval).phase == 'PENDING'
    assert configured.status(app.owner, deployment=pending).phase == 'PENDING'
    assert frames(app, True) == original and index_identity(app) == index
    activate(configured, app, successor, target)
    source = target
    for purpose in ('payload', 'search'):
        target = generation_keys(source, provider, purpose)
        proposal = plan_generation(configured, app, purpose, source, target)
        deployment = proposal, operation_pin(proposal)
        original = frames(app, True)
        first = configured.prepare_rotation(app.owner, deployment=deployment, keys=source,
            target_keys=target, approval=app.approval, max_chunks=1)
        assert (first.phase, first.committed_rows, first.committed_chunks) == ('EXPANDED', 3, 1)
        saved = staged_frames(app, proposal)
        observed = configured.status(app.owner, deployment=deployment)
        assert observed.phase == 'EXPANDED' and observed.verification == 'NOT_PERFORMED'
        assert configured.prepare_rotation(app.owner, deployment=deployment, keys=source,
            target_keys=target, approval=app.approval).phase == 'BACKFILLED'
        staged = staged_frames(app, proposal)
        assert all(staged[identity] == value for identity, value in saved.items() if value[0] is not None)
        assert frames(app, True) == original
        successor = configured.seal_rotation(app.owner, deployment=deployment, keys=source,
            target_keys=target, approval=app.approval,
            copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        pending = successor, app_pin(successor, 'PREPARED')
        assert configured.switch_rotation(app.owner, proposal=proposal, deployment=pending,
            keys=source, target_keys=target, approval=app.approval).phase == 'PENDING'
        def forbidden(*args): pytest.fail('committed cutover needed former source custody')
        assert configured.switch_rotation(app.owner, proposal=proposal, deployment=pending,
            keys=forbidden, target_keys=target, approval=app.approval).phase == 'PENDING'
        current = frames(app, True)
        assert index_identity(app) == index
        for identity, value in current.items():
            assert value == staged[identity][0]
            if value is None: continue
            assert value != original[identity]
            if purpose == 'payload':
                assert int.from_bytes(value[6:10], 'big') == 2
                assert value[10:46] == original[identity][10:46]
            else:
                assert value[6:10] == original[identity][6:10]
                assert int.from_bytes(value[10:14], 'big') == 2
                assert value[14:46] != original[identity][14:46]
        activate(configured, app, successor, target)
        source = target
    sessions = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=source)
    with sessions(tenant_id=TENANT) as session:
        assert {r.id: (r.tenant_id, r.name) for r in session.scalars(select(app.Customer))} == app.source
        session.get(app.Customer, UUID(int=101)).name = 'latest after three rotations'
        session.commit()
        assert session.scalar(select(app.Customer.id).where(
            app.Customer.name == 'latest after three rotations')) == UUID(int=101)
        assert session.scalars(select(app.Customer.id).where(
            app.Customer.name.in_(['latest after three rotations']))).all() == [UUID(int=101)]
        session.add(app.Customer(id=UUID(int=4000), tenant_id=TENANT, name='latest after three rotations'))
        with pytest.raises(IntegrityError) as duplicate: session.commit()
        assert duplicate.value.orig.sqlstate == '23505'
        session.rollback()
    reverse = configured.plan_deprotection(app.owner, deployment=(app.plan, app.pin), keys=source,
        plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
        verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
    exposure, pin = consent(reverse)
    assert configured.decrypt_back(app.owner, deployment=(reverse, pin), keys=source,
        approval=app.approval, consent=exposure).phase == 'PLAINTEXT_PENDING'
    pin = replace(pin, phase='PLAINTEXT_ACTIVATING')
    assert configured.decrypt_back(app.owner, deployment=(reverse, pin), keys=source,
        approval=app.approval, consent=exposure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'native latest-value comparison', 'fixture provider and all wrappers retained', True)
    assert configured.remove(app.owner, deployment=(reverse, replace(pin, phase='REMOVING')),
        approval=app.approval, consent=exposure, removal=removal).phase == 'REMOVED'
    expected = dict(app.source)
    expected[UUID(int=101)] = TENANT, 'latest after three rotations'
    assert native_rows(app) == expected


def test_one_configuration_preserves_three_rotation_semantics_and_current_value_removal():
    with application() as app:
        configured = config(app)
        run(app); publish(app)
        exercise_rotations(app, configured)


@pytest.mark.parametrize('purpose', ['rewrap', 'payload', 'search'])
def test_cancel_pending_rotation_with_source_custody_only(purpose):
    with application() as app:
        configured = config(app)
        run(app); publish(app)
        provider = DevelopmentKeyProvider()
        before = frames(app, True)
        if purpose == 'rewrap':
            target = Keyring(prepare_rewrap(keys(TENANT), provider), {provider.provider_id: provider})
            proposal = configured.plan_rewrap(app.owner, deployment=(app.plan, app.pin), keys=keys,
                target_keys=target, verify_rows_per_second=1000)
            successor = proposal.activation_plan
            configured.rewrap(app.owner, proposal=proposal, deployment=(successor, app_pin(successor, 'PREPARED')),
                keys=keys, target_keys=target, approval=app.approval)
            operation = configured.abort_rewrap
        else:
            target = generation_keys(keys, provider, purpose)
            proposal = plan_generation(configured, app, purpose, keys, target)
            configured.prepare_rotation(app.owner, deployment=(proposal, operation_pin(proposal)),
                keys=keys, target_keys=target, approval=app.approval, max_chunks=1)
            operation = configured.abort_rotation
        provider.unwrap = lambda *args: pytest.fail('cancellation tried unavailable target custody')
        for _ in range(2):
            assert operation(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
                keys=keys, approval=app.approval).phase == 'ABORTED'
        assert frames(app, True) == before
        assert configured.status(app.owner, deployment=(app.plan, app.pin)).phase == 'ACTIVE'


@pytest.mark.parametrize('fault', ['manifest', 'inventory'])
def test_rotation_configuration_drift_refuses_all_routes_before_database_or_keys(fault):
    with application() as app:
        configured = config(app)
        run(app); publish(app)
        provider = DevelopmentKeyProvider()
        target = Keyring(prepare_rewrap(keys(TENANT), provider), {provider.provider_id: provider})
        rewrap = configured.plan_rewrap(app.owner, deployment=(app.plan, app.pin), keys=keys,
            target_keys=target, verify_rows_per_second=1000)
        proposals = [plan_generation(configured, app, purpose, keys, generation_keys(keys, provider, purpose))
                     for purpose in ('payload', 'search')]
        if fault == 'manifest':
            manifest = json.loads(configured.manifest); manifest['domain_id'] = str(uuid4())
            configured = replace(configured, manifest=json.dumps(manifest).encode())
        else:
            from cryptalis.manifest.compiler import WriterInventory
            configured = replace(configured, writers=WriterInventory(False, ()))
        def forbidden(*args, **kwargs): pytest.fail('configuration drift reached database or keys')
        source = app.plan, app.pin
        successor = rewrap.activation_plan
        calls = [
            lambda: configured.plan_rewrap(app.owner, deployment=source, keys=forbidden,
                target_keys=forbidden, verify_rows_per_second=1000),
            lambda: configured.rewrap(app.owner, proposal=rewrap, deployment=(successor, app_pin(successor, 'PREPARED')),
                keys=forbidden, target_keys=forbidden, approval=app.approval),
            lambda: configured.abort_rewrap(app.owner, proposal=rewrap, deployment=source,
                keys=forbidden, approval=app.approval)]
        for proposal in proposals:
            deployment = proposal, operation_pin(proposal)
            calls.extend([
                lambda p=proposal: plan_generation(configured, app, p.purpose, forbidden, forbidden),
                lambda d=deployment: configured.prepare_rotation(app.owner, deployment=d, keys=forbidden,
                    target_keys=forbidden, approval=app.approval),
                lambda d=deployment: configured.status(app.owner, deployment=d),
                lambda d=deployment: configured.seal_rotation(app.owner, deployment=d, keys=forbidden,
                    target_keys=forbidden, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=700),
                lambda p=proposal: configured.switch_rotation(app.owner, proposal=p, deployment=source,
                    keys=forbidden, target_keys=forbidden, approval=app.approval),
                lambda p=proposal: configured.abort_rotation(app.owner, proposal=p, deployment=source,
                    keys=forbidden, approval=app.approval)])
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            for call in calls:
                with pytest.raises(ConfigurationInvalid) as error: call()
                assert error.value.code == ('Application.ManifestMismatch' if fault == 'manifest'
                                           else 'Application.HostEvidenceMismatch')
        finally: event.remove(app.owner, 'engine_connect', forbidden)


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_rotation_missing_authority_and_wrong_successor_refuse_before_effects(purpose):
    with application() as app:
        configured = config(app)
        run(app); publish(app)
        target = generation_keys(keys, DevelopmentKeyProvider(), purpose)
        proposal = plan_generation(configured, app, purpose, keys, target)
        def forbidden(*args, **kwargs): pytest.fail('invalid authority reached database or keys')
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(TransitionFailure, match=purpose + '_operation_pin_mismatch'):
                configured.prepare_rotation(app.owner, deployment=(proposal, app.pin), keys=forbidden,
                    target_keys=forbidden, approval=app.approval)
            with pytest.raises(TransitionFailure, match='maintenance_approval_required'):
                configured.prepare_rotation(app.owner, deployment=(proposal, operation_pin(proposal)),
                    keys=forbidden, target_keys=forbidden, approval=None)
            with pytest.raises(TransitionFailure, match='activation_binding_mismatch'):
                configured.switch_rotation(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
                    keys=forbidden, target_keys=forbidden, approval=app.approval)
            with pytest.raises(ConfigurationInvalid, match='InvalidRotationPurpose'):
                plan_generation(configured, app, 'automatic', forbidden, forbidden)
        finally: event.remove(app.owner, 'engine_connect', forbidden)


def test_rewrap_rejects_wrong_artifact_pin_and_missing_maintenance_before_effects():
    with application() as app:
        configured = config(app)
        run(app); publish(app)
        provider = DevelopmentKeyProvider()
        target = Keyring(prepare_rewrap(keys(TENANT), provider), {provider.provider_id: provider})
        proposal = configured.plan_rewrap(app.owner, deployment=(app.plan, app.pin), keys=keys,
            target_keys=target, verify_rows_per_second=1000)
        successor = proposal.activation_plan
        pending = successor, app_pin(successor, 'PREPARED')
        def forbidden(*args, **kwargs): pytest.fail('invalid authority reached database or keys')
        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(ConfigurationInvalid, match='InvalidDeployment'):
                configured.rewrap(app.owner, proposal=proposal, deployment=(app.plan, app.pin),
                    keys=forbidden, target_keys=forbidden, approval=app.approval)
            with pytest.raises(ConfigurationInvalid, match='InvalidDeployment'):
                configured.abort_rewrap(app.owner, proposal=proposal, deployment=pending,
                    keys=forbidden, approval=app.approval)
            with pytest.raises(TransitionFailure, match='rewrap_prepublication_pin_required'):
                configured.rewrap(app.owner, proposal=proposal, deployment=(successor, app.pin),
                    keys=forbidden, target_keys=forbidden, approval=app.approval)
            with pytest.raises(TransitionFailure, match='maintenance_approval_required'):
                configured.rewrap(app.owner, proposal=proposal, deployment=pending,
                    keys=forbidden, target_keys=forbidden, approval=None)
        finally: event.remove(app.owner, 'engine_connect', forbidden)
