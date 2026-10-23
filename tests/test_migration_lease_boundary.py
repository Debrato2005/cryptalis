"""Real PostgreSQL row-crypto lease boundaries, with an isolated key clock."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import importlib
import json
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest
from sqlalchemy import event

from cryptalis import migration as m
from cryptalis.crypto import Keyring, KeyUnavailable
from test_deprotection import proposal, reverse
from test_migration import (application, frames, independent_open, keys, publish, run,
                            FIELD_ID, PROVIDER, TABLE_ID, TENANT, PublicFixtureProvider)


class CryptoClock:
    def __init__(self, expiries):
        self.now, self.remaining, self.expiries = 100.0, expiries, 0

    def monotonic(self):
        resolve = sys._getframe(1)
        crypto = resolve.f_back
        if (self.remaining and resolve.f_code.co_name == '_resolve' and crypto is not None
                and crypto.f_code.co_name in ('seal_text', 'open_text')
                and crypto.f_locals.get('record') == UUID(int=101)
                and resolve.f_locals.get('purpose') == 'payload'
                and ('sealed' in crypto.f_locals if crypto.f_code.co_name == 'seal_text'
                     else 'encoded' in crypto.f_locals)):
            # The real AEAD call completed; only its final lease check sees expiry.
            self.now += 2
            self.remaining -= 1
            self.expiries += 1
        return self.now


class ObservedProvider(PublicFixtureProvider):
    def __init__(self, clock, outage=False):
        self.clock, self.outage, self.calls = clock, outage, []

    def unwrap(self, wrapper, context):
        self.calls.append(context)
        if self.outage and self.clock.expiries:
            raise KeyUnavailable() from OSError('PRIVATE_LEASE_PROVIDER_DETAIL')
        return super().unwrap(wrapper, context)


def warm_resolver(monkeypatch, *, expiries=1, fault=None):
    clock = CryptoClock(expiries)
    module = importlib.import_module('cryptalis.crypto.keys')
    monkeypatch.setattr(module, 'time', SimpleNamespace(
        monotonic=clock.monotonic, monotonic_ns=time.monotonic_ns))
    provider = ObservedProvider(clock, outage=fault == 'provider')
    ring = Keyring(keys(TENANT).policy, {PROVIDER: provider}, max_age=1)
    ring.prepare()
    assert len(provider.calls) == 2
    clock.now = 100.9  # prepare() must reuse these genuinely warm, nearly expired roots.
    wrappers = tuple(replace(wrapper, context=replace(wrapper.context, root_id=UUID(int=9999)))
                     if index == 0 else wrapper for index, wrapper in enumerate(ring.policy.wrappers))
    changed = Keyring(replace(ring.policy, wrappers=wrappers), {PROVIDER: provider})

    def resolve(tenant):
        assert tenant == TENANT
        return changed if fault == 'policy' and clock.expiries else ring

    return resolve, clock, provider


def state(app, plan):
    with app.owner.connect() as connection:
        return connection.exec_driver_sql(
            f'SELECT state FROM "{app.schema}"."_cryptalis_journal" WHERE operation_id=%s',
            (plan.operation_id,)).scalar_one()


def snapshot(app):
    with app.owner.connect() as connection:
        rows = connection.exec_driver_sql(f'SELECT * FROM "{app.schema}".customer ORDER BY id').all()
        journal = connection.exec_driver_sql(
            f'SELECT operation_id, plan_digest, state FROM "{app.schema}"."_cryptalis_journal" '
            'ORDER BY operation_id').all()
    return rows, journal


@contextmanager
def customer_updates(app):
    updates = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('UPDATE ') and app.schema in statement and 'customer' in statement:
            updates.append(True)

    event.listen(app.owner, 'after_cursor_execute', observe)
    try:
        yield updates
    finally:
        event.remove(app.owner, 'after_cursor_execute', observe)


def stage(app, direction, phase):
    if direction == 'protect':
        run(app, until=phase, chunk_size=5)
        return app.plan, lambda until, resolver: run(app, until=until, chunk_size=5, key_resolver=resolver)
    run(app)
    publish(app)
    plan = proposal(app)
    reverse(app, plan, until=phase, chunk_size=5)
    return plan, lambda until, resolver: reverse(app, plan, until=until, chunk_size=5, key_resolver=resolver)


def expected_digest(app, bodies):
    digest = hashlib.sha256()
    for record, (tenant, _) in sorted(app.source.items()):
        digest.update(json.dumps([str(record), str(tenant)], sort_keys=True,
                                 separators=(',', ':')).encode())
        frame = bodies[record]
        digest.update(b'\x00' if frame is None else b'\x01' + len(frame).to_bytes(4, 'big') + frame)
    return {str(TABLE_ID): digest.hexdigest()}


@pytest.mark.parametrize('direction', ['protect', 'deprotect'])
@pytest.mark.parametrize('phase', ['backfill', 'verify'])
def test_warm_row_lease_expiry_reprepares_once_before_progress_or_digest(direction, phase, monkeypatch):
    with application(rows=5) as app:
        plan, invoke = stage(app, direction, 'EXPANDED' if phase == 'backfill' else 'BACKFILLED')
        original_frames = frames(app, switched=direction == 'deprotect')
        target = 'BACKFILLED' if phase == 'backfill' else 'VERIFIED'
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(patch)
            with customer_updates(app) as updates:
                result = invoke(target, resolve)
            assert result.phase == target and result.committed_rows == 5
            assert clock.expiries == 1 and len(provider.calls) == 4
            assert len(updates) == (1 if phase == 'backfill' else 0)
            current = state(app, plan)
            assert current['models'][str(TABLE_ID)]['rows'] == 5
            assert current['models'][str(TABLE_ID)]['chunks'] == 1
            bodies = frames(app, switched=direction == 'deprotect')
            if direction == 'protect':
                descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
                assert {record: independent_open(body, descriptor, TENANT, record)
                        for record, body in bodies.items()} == {
                            record: value for record, (_, value) in app.source.items()}
            else:
                assert bodies == original_frames
                with app.owner.connect() as connection:
                    plaintext = dict(connection.exec_driver_sql(
                        f'SELECT id, "_cryptalis_{FIELD_ID.hex}_plain" FROM "{app.schema}".customer').all())
                assert plaintext == {record: value for record, (_, value) in app.source.items()}
            if phase == 'verify':
                assert current['verification'] == expected_digest(app, bodies)
                # A second full verification at switch must match the saved digest.
                clock.remaining = 0
                terminal = 'PENDING' if direction == 'protect' else 'PLAINTEXT_PENDING'
                assert invoke(terminal, resolve).phase == terminal


@pytest.mark.parametrize('direction', ['protect', 'deprotect'])
@pytest.mark.parametrize('phase', ['backfill', 'verify'])
@pytest.mark.parametrize('fault', ['provider', 'repeated_expiry', 'policy'])
def test_row_refresh_failure_keeps_rows_and_checkpoint_unchanged(direction, phase, fault, monkeypatch):
    with application(rows=5) as app:
        initial = 'EXPANDED' if phase == 'backfill' else 'BACKFILLED'
        target = 'BACKFILLED' if phase == 'backfill' else 'VERIFIED'
        plan, invoke = stage(app, direction, initial)
        before = snapshot(app)
        with monkeypatch.context() as patch:
            resolve, clock, provider = warm_resolver(
                patch, expiries=2 if fault == 'repeated_expiry' else 1, fault=fault)
            with customer_updates(app) as updates:
                with pytest.raises(m.TransitionFailure) as failed:
                    invoke(target, resolve)
            assert failed.value.code == ('key_policy_changed' if fault == 'policy' else 'KeyUnavailable')
            assert 'PRIVATE_LEASE_PROVIDER_DETAIL' not in str(failed.value)
            assert clock.expiries == (2 if fault == 'repeated_expiry' else 1)
            assert len(provider.calls) == {'provider': 3, 'repeated_expiry': 4, 'policy': 2}[fault]
            assert updates == [] and snapshot(app) == before
            current = state(app, plan)
            assert current['phase'] == initial
            assert current['models'][str(TABLE_ID)]['rows'] == (0 if phase == 'backfill' else 5)
            assert current['models'][str(TABLE_ID)]['chunks'] == (0 if phase == 'backfill' else 1)
            clock.remaining = 0
            assert invoke(target, keys).phase == target
