"""Manifest changes preserve encrypted current data through staged verification."""
import json
from uuid import UUID

import pytest
from sqlalchemy import String, select
from sqlalchemy.orm import Session

from test_application_config import config
from test_deprotection import app_pin, native_rows
from test_migration import application, frames, keys, publish, run, TENANT
from test_payload_rotation_execution import operation_pin, staged_frames
from test_search_retained_readers import remove_current


def configured_change(app):
    declaration = app.plan.document['lock']['declaration']
    declaration['models'][0]['fields'][0].update(queries=['equality'], accept_leakage=['equality'])
    return config(app, manifest=json.dumps(declaration).encode(), queries=())


def propose(configured, app, **options):
    args = dict(backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=2)
    args.update(options)
    return configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=keys, **args)


def prepare(configured, app, proposal, **options):
    return configured.prepare_modification(app.owner, deployment=(proposal, operation_pin(proposal)),
        keys=keys, approval=app.approval, **options)


def seal(configured, app, proposal):
    return configured.seal_modification(app.owner, deployment=(proposal, operation_pin(proposal)),
        keys=keys, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)


def activate_change(configured, app, proposal):
    prepare(configured, app, proposal)
    successor = seal(configured, app, proposal)
    configured.switch_modification(app.owner, proposal=proposal,
        deployment=(successor, app_pin(successor, 'PREPARED')), keys=keys, approval=app.approval)
    configured.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
        keys=keys, approval=app.approval, until='ACTIVE')
    app.plan, app.pin = successor, app_pin(successor, 'ACTIVE')
    return successor


@pytest.mark.parametrize('varchar', [False, True])
def test_enable_exact_search_on_active_storage_field_resume_and_current_value_removal(varchar):
    with application(unique=False, queries=[], value_type=String(64, collation='C') if varchar else None) as app:
        with Session(app.runtime) as session:
            expected = session.scalars(select(app.Customer.id).where(
                app.Customer.name.in_(['雪😀', 'é'])).order_by(app.Customer.id)).all()
        configured = configured_change(app)
        run(app); publish(app)
        original = frames(app, True)
        proposal = configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=keys,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=2)
        deployment = proposal, operation_pin(proposal)
        first = configured.prepare_modification(app.owner, deployment=deployment, keys=keys,
            approval=app.approval, max_chunks=1)
        assert (first.phase, first.committed_rows, first.committed_chunks) == ('EXPANDED', 2, 1)
        saved = staged_frames(app, proposal)
        assert frames(app, True) == original
        observed = configured.status(app.owner, deployment=deployment)
        assert observed.phase == 'EXPANDED' and observed.verification == 'NOT_PERFORMED'
        assert configured.prepare_modification(app.owner, deployment=deployment, keys=keys,
            approval=app.approval).phase == 'BACKFILLED'
        staged = staged_frames(app, proposal)
        assert all(staged[identity] == value for identity, value in saved.items() if value[0] is not None)
        successor = configured.seal_modification(app.owner, deployment=deployment, keys=keys,
            approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert successor.lock_bytes != app.plan.lock_bytes
        assert successor.document['key_policies'] == app.plan.document['key_policies']
        pending = successor, app_pin(successor, 'PREPARED')
        assert configured.switch_modification(app.owner, proposal=proposal, deployment=pending,
            keys=keys, approval=app.approval).phase == 'PENDING'
        assert configured.switch_modification(app.owner, proposal=proposal, deployment=pending,
            keys=keys, approval=app.approval).phase == 'PENDING'
        assert configured.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
            keys=keys, approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = successor, app_pin(successor, 'ACTIVE')
        current = frames(app, True)
        assert current[UUID(int=100)] is None
        assert all(body is None or body != original[identity] for identity, body in current.items())
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=keys)
        with factory(tenant_id=TENANT) as session:
            assert session.scalars(select(app.Customer.id).where(
                app.Customer.name.in_(['雪😀', 'é'])).order_by(app.Customer.id)).all() == expected
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)
            session.get(app.Customer, UUID(int=101)).name = 'latest after capability change'
            session.commit()
            assert session.scalar(select(app.Customer.id).where(
                app.Customer.name == 'latest after capability change')) == UUID(int=101)
        remove_current(app, keys)
        recovered = dict(app.source)
        recovered[UUID(int=101)] = TENANT, 'latest after capability change'
        assert native_rows(app) == recovered


@pytest.mark.parametrize('purpose', ['payload', 'search', 'rewrap'])
def test_generation_rotation_after_profile_change_retains_current_value_removal(purpose):
    from test_application_rotation import activate, generation_keys, plan_generation
    from cryptalis.crypto import DevelopmentKeyProvider
    with application(unique=False, queries=[]) as app:
        configured = configured_change(app)
        run(app); publish(app)
        activate_change(configured, app, propose(configured, app))
        if purpose == 'rewrap':
            from cryptalis.crypto import Keyring
            from cryptalis.crypto._rewrap import prepare_rewrap
            provider = DevelopmentKeyProvider()
            target = Keyring(prepare_rewrap(keys(TENANT), provider), {provider.provider_id: provider})
            proposal = configured.plan_rewrap(app.owner, deployment=(app.plan, app.pin), keys=keys,
                target_keys=target, verify_rows_per_second=1000)
            successor = proposal.activation_plan
            configured.rewrap(app.owner, proposal=proposal, deployment=(successor, app_pin(successor, 'PREPARED')),
                keys=keys, target_keys=target, approval=app.approval)
        else:
            target = generation_keys(keys, DevelopmentKeyProvider(), purpose)
            proposal = plan_generation(configured, app, purpose, keys, target)
            deployment = proposal, operation_pin(proposal)
            configured.prepare_rotation(app.owner, deployment=deployment, keys=keys, target_keys=target,
                                        approval=app.approval)
            successor = configured.seal_rotation(app.owner, deployment=deployment, keys=keys, target_keys=target,
                approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
            configured.switch_rotation(app.owner, proposal=proposal, deployment=(successor, app_pin(successor, 'PREPARED')),
                                        keys=keys, target_keys=target, approval=app.approval)
        activate(configured, app, successor, target)
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=target)
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)
            session.get(app.Customer, UUID(int=101)).name = 'after later rotation'
            session.commit()
        remove_current(app, lambda tenant: target)
        expected = dict(app.source); expected[UUID(int=101)] = TENANT, 'after later rotation'
        assert native_rows(app) == expected
