"""Public restore adoption lease controls on the approved fresh cluster."""
from contextlib import contextmanager
from dataclasses import replace
import os
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import event

if 'CRYPTALIS_FRESH_PLAIN_DATABASE' not in os.environ:
    pytest.skip('run through the fresh-cluster restore lease profile', allow_module_level=True)

from cryptalis import migration as m, restore as r
from test_fresh_cluster_restore import (
    MANIFEST, SCHEMA, WORKDIR, approval, artifacts, restore as restore_dump,
)
from test_migration import engine, keys, TENANT
from test_migration_lease_boundary import warm_resolver


@pytest.fixture(scope='module')
def restored_app():
    if any(MANIFEST.get(name) for name in ('rewrapped', 'payload_rotated', 'search_rotated')):
        pytest.fail('Restore lease controls require the original protected TEXT/VARCHAR fixture.')
    restore_dump(WORKDIR / 'protected.sql', 'CRYPTALIS_TEST_DATABASE_URL')
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        yield SimpleNamespace(plan=source, pin=pin, owner=owner, schema=SCHEMA)
    finally:
        owner.dispose()


def snapshot(app):
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT * FROM "{app.schema}".customer ORDER BY id').all()
        journal = connection.exec_driver_sql(
            f'SELECT operation_id, plan_digest, state FROM "{app.plan.document["journal_schema"]}".'
            '"_cryptalis_journal" ORDER BY operation_id').all()
        schema = m._facts(connection, app.plan.document['lock']['models'][0])
    return rows, journal, schema


def adopt(app, resolver):
    return r.plan(app.plan, app.owner, pin=app.pin, keys=resolver, approval=approval())


@contextmanager
def probes(app, clock=None):
    observed = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('UPDATE ') and app.schema in statement and 'customer' in statement:
            if clock is not None:
                assert clock.expiries == 1 and clock.remaining == 0
            observed.append(True)

    event.listen(app.owner, 'before_cursor_execute', observe)
    try:
        yield observed
    finally:
        event.remove(app.owner, 'before_cursor_execute', observe)


def test_fresh_restore_retries_post_aead_expiry_before_probes_and_issues_binding(restored_app, monkeypatch):
    app = restored_app
    before = snapshot(app)
    with monkeypatch.context() as patch:
        resolve, clock, provider = warm_resolver(patch)
        with probes(app, clock) as observed:
            binding = adopt(app, resolve)
        assert clock.expiries == 1 and len(provider.calls) == 4
        assert binding.document['custody'] == {str(TENANT): app.plan.document['key_policies'][str(TENANT)]}
        assert binding.source_plan_digest == app.plan.digest
        assert binding.target[:-1] != app.plan.document['target'][:-1]
        assert bool(observed) == bool(binding.document['restatements'])
        assert all(item['probe'] == 'rejected-malformed-frames' for item in binding.document['restatements'])
        assert m.check_deployment(app.plan, app.owner, pin=app.pin, restore=binding) is None
    assert snapshot(app) == before


@pytest.mark.parametrize('fault', ['provider', 'repeated_expiry', 'policy'])
def test_fresh_restore_refresh_refusal_precedes_probes_and_has_no_effects(restored_app, fault, monkeypatch):
    app = restored_app
    before = snapshot(app)
    with monkeypatch.context() as patch:
        resolve, clock, provider = warm_resolver(
            patch, expiries=2 if fault == 'repeated_expiry' else 1, fault=fault)
        with probes(app) as observed:
            with pytest.raises(m.TransitionFailure) as failed:
                adopt(app, resolve)
        assert failed.value.code == ('key_policy_changed' if fault == 'policy' else 'KeyUnavailable')
        assert 'PRIVATE_LEASE_PROVIDER_DETAIL' not in str(failed.value)
        assert clock.expiries == (2 if fault == 'repeated_expiry' else 1)
        assert len(provider.calls) == {'provider': 3, 'repeated_expiry': 4, 'policy': 2}[fault]
        assert observed == [] and snapshot(app) == before
        clock.remaining = 0
        assert adopt(app, keys).source_plan_digest == app.plan.digest
    assert snapshot(app) == before


def test_fresh_restore_initial_provider_outage_does_not_probe_or_retry(restored_app, monkeypatch):
    app = restored_app
    before = snapshot(app)
    with monkeypatch.context() as patch:
        resolve, clock, provider = warm_resolver(patch, fault='provider')
        clock.now += 2
        clock.expiries, clock.remaining = 1, 0
        with probes(app) as observed:
            with pytest.raises(m.TransitionFailure) as failed:
                adopt(app, resolve)
        assert failed.value.code == 'KeyUnavailable'
        assert len(provider.calls) == 3 and observed == []
    assert snapshot(app) == before


@pytest.mark.parametrize('fault', ['authentication', 'generation'])
def test_fresh_restore_corruption_keeps_original_code_without_retry_or_probes(restored_app, fault, monkeypatch):
    app = restored_app
    with app.owner.connect() as connection:
        original = bytes(connection.exec_driver_sql(
            f'SELECT name FROM "{app.schema}".customer WHERE id=%s', (UUID(int=101),)).scalar_one())
    damaged = bytearray(original)
    if fault == 'authentication':
        damaged[-1] ^= 1
    else:
        damaged[6:10] = (2).to_bytes(4, 'big')
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                   (bytes(damaged), UUID(int=101)))
    try:
        before = snapshot(app)
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(patch)
            with probes(app) as observed:
                with pytest.raises(m.TransitionFailure) as failed:
                    adopt(app, resolve)
            assert failed.value.code == ('generation_mismatch' if fault == 'generation'
                                         else 'restored_frame_verification_failed')
            assert clock.expiries == 0 and len(provider.calls) == 2 and observed == []
        assert snapshot(app) == before
    finally:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                       (original, UUID(int=101)))
    assert adopt(app, keys).source_plan_digest == app.plan.digest


@pytest.mark.parametrize('fault', ['approval', 'pin', 'runtime_role'])
def test_fresh_restore_authority_refusal_precedes_keys_and_probes(restored_app, fault):
    app = restored_app
    before, resolutions = snapshot(app), []

    def forbidden(tenant):
        resolutions.append(tenant)
        raise AssertionError('Authority must be admitted before provider work.')

    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        with probes(app) as observed:
            with pytest.raises(m.TransitionFailure) as failed:
                r.plan(app.plan, runtime if fault == 'runtime_role' else app.owner,
                       pin=replace(app.pin, phase='PENDING') if fault == 'pin' else app.pin,
                       keys=forbidden, approval=None if fault == 'approval' else approval())
        assert failed.value.code == {'approval': 'restore_approval_required', 'pin': 'source_pin_must_be_active',
                                     'runtime_role': 'maintenance_requires_planned_owner'}[fault]
        assert resolutions == observed == [] and snapshot(app) == before
    finally:
        runtime.dispose()
