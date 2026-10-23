"""Real PostgreSQL restored-frame scan lease boundaries; no adoption authority."""
from contextlib import contextmanager
from uuid import UUID

import pytest
from sqlalchemy import event

from cryptalis import migration as m, restore
from test_migration import application, frames, keys, publish, run, TENANT
from test_migration_lease_boundary import snapshot, warm_resolver


@contextmanager
def active_application():
    with application(rows=5) as app:
        run(app)
        publish(app)
        yield app


def scan(app, resolver):
    with m._connection(app.owner, app.plan.operation_id) as connection:
        return restore._scan(connection, app.plan, resolver)


@contextmanager
def writes(app):
    observed = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith(('UPDATE ', 'INSERT ', 'DELETE ', 'ALTER ', 'CREATE ', 'DROP ')):
            observed.append(statement.split()[0])

    event.listen(app.owner, 'before_cursor_execute', observe)
    try:
        yield observed
    finally:
        event.remove(app.owner, 'before_cursor_execute', observe)


def test_restore_scan_recovers_exact_post_aead_expiry_without_effects(monkeypatch):
    with active_application() as app:
        before = snapshot(app)
        original = frames(app, True)
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(patch)
            with writes(app) as observed:
                custody = scan(app, resolve)
            assert custody == {str(TENANT): app.plan.document['key_policies'][str(TENANT)]}
            assert clock.expiries == 1 and len(provider.calls) == 4
            assert observed == []
        assert snapshot(app) == before and frames(app, True) == original


@pytest.mark.parametrize('fault', ['provider', 'repeated_expiry', 'policy'])
def test_restore_scan_failed_refresh_keeps_exact_state_and_can_retry_explicitly(fault, monkeypatch):
    with active_application() as app:
        before = snapshot(app)
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(
                patch, expiries=2 if fault == 'repeated_expiry' else 1, fault=fault)
            with writes(app) as observed:
                with pytest.raises(m.TransitionFailure) as failed:
                    scan(app, resolve)
            assert failed.value.code == ('key_policy_changed' if fault == 'policy' else 'KeyUnavailable')
            assert 'PRIVATE_LEASE_PROVIDER_DETAIL' not in str(failed.value)
            assert clock.expiries == (2 if fault == 'repeated_expiry' else 1)
            assert len(provider.calls) == {'provider': 3, 'repeated_expiry': 4, 'policy': 2}[fault]
            assert observed == [] and snapshot(app) == before
            clock.remaining = 0
            assert scan(app, keys) == {str(TENANT): app.plan.document['key_policies'][str(TENANT)]}
        assert snapshot(app) == before


def test_restore_scan_initial_provider_failure_is_not_retried(monkeypatch):
    with active_application() as app:
        before = snapshot(app)
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(patch, fault='provider')
            clock.now += 2
            clock.expiries = 1  # Expire warm roots before preparation; provider now refuses.
            clock.remaining = 0
            with writes(app) as observed:
                with pytest.raises(m.TransitionFailure) as failed:
                    scan(app, resolve)
            assert failed.value.code == 'KeyUnavailable'
            assert len(provider.calls) == 3 and observed == []
        assert snapshot(app) == before


@pytest.mark.parametrize('fault', ['authentication', 'generation'])
def test_restore_scan_real_corruption_preserves_original_code_without_refresh(fault, monkeypatch):
    with active_application() as app:
        original = frames(app, True)[UUID(int=101)]
        changed = bytearray(original)
        if fault == 'authentication':
            changed[-1] ^= 1
        else:
            changed[6:10] = (2).to_bytes(4, 'big')
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                       (bytes(changed), UUID(int=101)))
        try:
            before = snapshot(app)
            with monkeypatch.context() as patch:
                resolve, clock, provider = warm_resolver(patch)
                with writes(app) as observed:
                    with pytest.raises(m.TransitionFailure) as failed:
                        scan(app, resolve)
                assert failed.value.code == ('generation_mismatch' if fault == 'generation'
                                             else 'restored_frame_verification_failed')
                assert clock.expiries == 0 and len(provider.calls) == 2 and observed == []
            assert snapshot(app) == before
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                           (original, UUID(int=101)))
        assert scan(app, keys) == {str(TENANT): app.plan.document['key_policies'][str(TENANT)]}
