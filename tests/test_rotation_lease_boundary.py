"""Actual post-AEAD expiry during encrypted rotation staging and sealing."""
from dataclasses import replace
import importlib
import sys
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring, KeyUnavailable
from payload_rotation_worker import target_keys as payload_keys
from search_rotation_worker import target_keys as search_keys
from test_migration import application, frames, keys, publish, run, TENANT
from test_payload_rotation_execution import operation_pin, snapshot
from test_payload_rotation_plan import plan as payload_plan
from test_search_rotation_lifecycle import plan as search_plan


class RotationClock:
    def __init__(self, purpose, phase, expiries):
        self.purpose, self.phase = purpose, phase
        self.now, self.remaining, self.expiries = 100.0, expiries, 0

    def monotonic(self):
        resolve = sys._getframe(1)
        crypto = resolve.f_back
        boundary = '_chunk' if self.phase == 'backfill' else '_verify_prefix'
        source_first = self.remaining == 2
        operation = 'open_text' if source_first or self.phase == 'verify' else 'seal_text'
        completed = 'encoded' if operation == 'open_text' else 'sealed'
        caller = crypto
        while caller is not None and caller.f_code.co_name != boundary:
            caller = caller.f_back
        if (self.remaining and resolve.f_code.co_name == '_resolve' and crypto is not None
                and caller is not None and crypto.f_locals.get('record') == UUID(int=101)
                and resolve.f_locals.get('purpose') == 'payload'
                and getattr(resolve.f_locals['self'].policy, self.purpose + '_generation') == (1 if source_first else 2)
                and crypto.f_code.co_name == operation and completed in crypto.f_locals):
            # Real AEAD completed. Its final lease check alone observes expiry.
            self.now += 2
            self.remaining -= 1
            self.expiries += 1
        return self.now


class Provider:
    def __init__(self, delegate, role, clock, fault, calls):
        self.delegate, self.provider_id = delegate, delegate.provider_id
        self.role, self.clock, self.fault, self.calls = role, clock, fault, calls

    def unwrap(self, wrapper, context):
        self.calls.append((self.role, context))
        if self.role == 'target' and self.fault == 'provider' and self.clock.expiries:
            raise KeyUnavailable() from OSError('PRIVATE_ROTATION_LEASE_PROVIDER_DETAIL')
        return self.delegate.unwrap(wrapper, context)


def warm_pair(monkeypatch, purpose, phase, fault=None):
    clock = RotationClock(purpose, phase, 2 if fault == 'repeated_expiry' else 1)
    module = importlib.import_module('cryptalis.crypto.keys')
    monkeypatch.setattr(module, 'time', SimpleNamespace(
        monotonic=clock.monotonic, monotonic_ns=time.monotonic_ns))
    calls, resolvers = [], []
    target = payload_keys if purpose == 'payload' else search_keys
    for role, original in (('source', keys(TENANT)), ('target', target(TENANT))):
        providers = {identity: Provider(provider, role, clock, fault, calls)
                     for identity, provider in original._providers.items()}
        ring = Keyring(original.policy, providers, max_age=1)
        ring.prepare()
        wrappers = tuple(replace(wrapper, context=replace(wrapper.context, root_id=UUID(int=9999)))
                         if index == 0 else wrapper for index, wrapper in enumerate(ring.policy.wrappers))
        changed = Keyring(replace(ring.policy, wrappers=wrappers), providers, max_age=1)

        def resolve(tenant, role=role, ring=ring, changed=changed):
            assert tenant == TENANT
            return changed if fault == role + '_policy' and clock.expiries else ring

        resolvers.append(resolve)
    assert len(calls) == 5
    clock.now = 100.9
    return *resolvers, clock, calls


def preparation(app, purpose, phase):
    target = payload_keys if purpose == 'payload' else search_keys
    proposal = (payload_plan if purpose == 'payload' else search_plan)(app, target)
    getattr(r, 'apply_' + purpose + '_rotation')(
        proposal, app.owner, keys=keys, target_keys=target,
        pin=operation_pin(proposal), approval=app.approval,
        until='EXPANDED' if phase == 'backfill' else 'BACKFILLED')
    return proposal, target


def invoke(app, proposal, phase, source, target):
    if phase == 'backfill':
        return getattr(r, 'apply_' + proposal.purpose + '_rotation')(
            proposal, app.owner, keys=source, target_keys=target,
            pin=operation_pin(proposal), approval=app.approval, max_chunks=1)
    return getattr(r, 'seal_' + proposal.purpose + '_rotation')(
        proposal, app.owner, keys=source, target_keys=target,
        pin=operation_pin(proposal), approval=app.approval,
        copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)


def complete(app, proposal, target):
    assert getattr(r, 'apply_' + proposal.purpose + '_rotation')(
        proposal, app.owner, keys=keys, target_keys=target,
        pin=operation_pin(proposal), approval=app.approval).phase == 'BACKFILLED'
    return invoke(app, proposal, 'verify', keys, target)


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('phase', ['backfill', 'verify'])
def test_rotation_reprepares_exact_pair_once_after_real_aead_expiry(purpose, phase, monkeypatch):
    with application(rows=5) as app:
        run(app); publish(app)
        proposal, target = preparation(app, purpose, phase)
        original, before = frames(app, True), snapshot(app, proposal)
        with monkeypatch.context() as patch:
            source, refreshed, clock, calls = warm_pair(patch, purpose, phase)
            result = invoke(app, proposal, phase, source, refreshed)
            assert clock.expiries == 1 and len(calls) == 10
        assert frames(app, True) == original
        if phase == 'backfill':
            assert result.committed_rows == 3 and result.committed_chunks == 1
        else:
            assert snapshot(app, proposal) == before
        sealed = complete(app, proposal, target)
        if phase == 'verify':
            assert result.artifact == sealed.artifact
        assert sealed.document['kind'] == purpose + '_rotation'


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('phase', ['backfill', 'verify'])
@pytest.mark.parametrize('fault', ['provider', 'source_policy', 'target_policy', 'repeated_expiry'])
def test_rotation_refresh_refusal_preserves_source_shadow_and_journal(purpose, phase, fault, monkeypatch):
    with application(rows=5) as app:
        run(app); publish(app)
        proposal, target = preparation(app, purpose, phase)
        before = snapshot(app, proposal)
        with monkeypatch.context() as patch:
            source, refreshed, clock, calls = warm_pair(patch, purpose, phase, fault)
            with pytest.raises(m.TransitionFailure) as refused:
                invoke(app, proposal, phase, source, refreshed)
            assert refused.value.code == {
                'provider': 'KeyUnavailable', 'repeated_expiry': 'KeyUnavailable',
                'source_policy': 'key_policy_changed',
                'target_policy': purpose + '_rotation_policy_changed',
            }[fault]
            assert 'PRIVATE_ROTATION' not in str(refused.value)
            assert clock.expiries == (2 if fault == 'repeated_expiry' else 1)
            assert len(calls) == {'provider': 8, 'source_policy': 5,
                                  'target_policy': 5, 'repeated_expiry': 10}[fault]
        assert snapshot(app, proposal) == before
        assert complete(app, proposal, target).document['kind'] == purpose + '_rotation'
