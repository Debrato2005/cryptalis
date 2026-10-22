"""Native controls for read-only rewrap admission."""
from dataclasses import replace
import traceback
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event

from cryptalis import migration as m
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring
from cryptalis.crypto.keys import WrappedRoot
from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
from cryptalis.crypto._rewrap import prepare_rewrap
from cryptalis.rotation import RewrapPlan, plan_rewrap
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_migration import (application, frames, keys, publish, run,
                            PublicFixtureProvider, PROVIDER, TENANT, DOMAIN, TABLE_ID)


def _target(source_keys=keys):
    provider = DevelopmentKeyProvider()
    policy = prepare_rewrap(source_keys(TENANT), provider)
    return Keyring(policy, {provider.provider_id: provider}), provider


def _plan(app, target, verify_rows_per_second=1000, **kwargs):
    return plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=keys,
                       target_keys=target, verify_rows_per_second=verify_rows_per_second, **kwargs)


def _snapshot(app):
    with app.owner.connect() as c:
        state = c.exec_driver_sql(
            f'SELECT operation_id, plan_digest, state FROM "{app.schema}"."_cryptalis_journal" '
            'ORDER BY operation_id').all()
        rows = c.exec_driver_sql(
            f'SELECT id, tenant_id, name, label FROM "{app.schema}".customer ORDER BY id').all()
        schema = m._facts(c, app.plan.document['lock']['models'][0])
    return state, rows, schema


@pytest.mark.parametrize('rate', [1000, 1e100])
def test_native_rewrap_plan_authenticates_both_policies_without_publication(rate):
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        before = _snapshot(app)
        proposal = _plan(app, target, verify_rows_per_second=rate)
        assert _snapshot(app) == before
        d = proposal.document
        assert proposal.operation_id != app.plan.operation_id
        assert d['source_plan'] == app.plan.document
        assert d['required_readers'] == app.plan.document['lock']['required_readers']
        assert d['models'][str(TABLE_ID)]['rows'] == len(app.source)
        assert d['journal_state_digest'] == m._hash(before[0][0][2])
        assert d['key_policies'][str(TENANT)]['source'] == m._policy(keys(TENANT))
        assert d['key_policies'][str(TENANT)]['target'] == m._policy(target)
        assert RewrapPlan(proposal.artifact).artifact == proposal.artifact
        assert 'Inactive rewrap plan' in str(proposal)
        assert repr(proposal) == str(proposal)
        assert all(not forbidden in proposal.artifact for forbidden in (b'PUBLIC TEST WRAPPER', b'root_bytes'))
        # Rewrap admission does not make target custody current authority.
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                          keys=target, deployment=(app.plan, app.pin))
        with pytest.raises(PolicyMismatch):
            with sessions(tenant_id=TENANT) as session:
                session.get(app.Customer, UUID(int=101))
        assert _snapshot(app) == before


def test_original_application_remains_current_after_read_only_admission():
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        first = _plan(app, target)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                          keys=keys, deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            row = session.get(app.Customer, UUID(int=101))
            row.name = 'an ordinary edit after rewrap planning'
            session.commit()
        second = _plan(app, target)
        a, b = first.document['models'][str(TABLE_ID)], second.document['models'][str(TABLE_ID)]
        assert a['membership'] == b['membership'] and a['schema'] == b['schema']
        assert a['frames'] != b['frames']
        with sessions(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=101)).name == 'an ordinary edit after rewrap planning'


def _historical(tenant):
    source = keys(tenant)
    c = KeyContext(DOMAIN, tenant, 'payload', UUID(int=9081), 3)
    old = WrappedRoot(PROVIDER, c, b'PUBLIC RETAINED WRAPPER')
    return Keyring(replace(source.policy, wrappers=source.policy.wrappers+(old,)),
                   {PROVIDER: PublicFixtureProvider()})


@pytest.mark.parametrize('missing', [False, True])
def test_retained_reader_root_cannot_disappear_when_no_current_frame_uses_it(missing):
    with application() as app:
        document = app.plan.document
        document['key_policies'][str(TENANT)] = m._policy(_historical(TENANT))
        app.plan = m.MigrationPlan(m._canonical(document))
        app.pin = replace(app.pin, plan_digest=app.plan.digest)
        run(app, key_resolver=_historical)
        publish(app)
        target, provider = _target(_historical)
        if missing:
            policy = replace(target.policy, wrappers=tuple(
                w for w in target.policy.wrappers if w.context.generation != 3))
            target = Keyring(policy, {provider.provider_id: provider})
        before = _snapshot(app)
        if missing:
            with pytest.raises(m.TransitionFailure) as caught:
                plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=_historical,
                            target_keys=target, verify_rows_per_second=1000)
            assert caught.value.code == 'KeyUnavailable'
        else:
            proposal = plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=_historical,
                                   target_keys=target, verify_rows_per_second=1000)
            assert len(proposal.document['key_policies'][str(TENANT)]['contexts']) == 3
        assert _snapshot(app) == before


@pytest.mark.parametrize('missing', [False, True])
def test_deleted_tenant_still_has_required_key_custody(missing):
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        with app.owner.begin() as c:
            c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer')
        before = _snapshot(app)
        if missing:
            with pytest.raises(m.TransitionFailure) as caught:
                _plan(app, lambda tenant: None)
            assert caught.value.code == 'missing_target_key_policy'
        else:
            proposal = _plan(app, target)
            assert proposal.document['models'][str(TABLE_ID)]['rows'] == 0
            assert set(proposal.document['key_policies']) == {str(TENANT)}
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['root', 'generation', 'context', 'outage', 'unchanged'])
def test_wrong_or_unavailable_target_never_mutates_native_source(fault):
    with application() as app:
        run(app)
        publish(app)
        target, provider = _target()
        if fault == 'unchanged':
            target = keys(TENANT)
        elif fault == 'outage':
            class Unavailable:
                provider_id = provider.provider_id
                def unwrap(self, *args):
                    raise RuntimeError('PRIVATE_REWRAP_PROVIDER_DETAIL')
            target = Keyring(target.policy, {provider.provider_id: Unavailable()})
        else:
            wrappers = list(target.policy.wrappers)
            index = next(i for i, w in enumerate(wrappers) if w.context.purpose == 'payload')
            context = wrappers[index].context
            root = provider.unwrap(wrappers[index], context)
            if fault == 'root':
                root = b'x' * 32
            elif fault == 'generation':
                context = replace(context, generation=2)
            elif fault == 'context':
                context = replace(context, root_id=uuid4())
            wrappers[index] = provider.wrap(root, context)
            policy = replace(target.policy, wrappers=tuple(wrappers),
                             payload_generation=2 if fault == 'generation' else 1)
            target = Keyring(policy, {provider.provider_id: provider})
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:
            _plan(app, target)
        assert caught.value.code == ('rewrap_policy_unchanged' if fault == 'unchanged' else 'KeyUnavailable')
        assert 'PRIVATE_REWRAP_PROVIDER_DETAIL' not in ''.join(traceback.format_exception(caught.value))
        assert _snapshot(app) == before


@pytest.mark.parametrize('fault', ['pin', 'journal', 'schema', 'frame'])
def test_stale_or_corrupt_native_source_refuses_a_rewrap_plan(fault):
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        if fault == 'pin':
            app.pin = replace(app.pin, target_id=uuid4())
        else:
            with app.owner.begin() as c:
                if fault == 'journal':
                    c.exec_driver_sql(f'UPDATE "{app.schema}"."_cryptalis_journal" SET plan_digest=%s', ('0'*64,))
                elif fault == 'schema':
                    c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN unexpected text')
                else:
                    frame = bytearray(frames(app, True)[UUID(int=101)])
                    frame[-1] ^= 1
                    c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                      (bytes(frame), UUID(int=101)))
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure):
            _plan(app, target)
        assert _snapshot(app) == before


def test_current_null_row_with_unrecorded_tenant_refuses_admission():
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        with app.owner.begin() as c:
            c.exec_driver_sql(
                f'INSERT INTO "{app.schema}".customer (id, tenant_id, name, label) VALUES (%s,%s,NULL,%s)',
                (UUID(int=999), UUID(int=7001), 'unrecorded tenant'))
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:
            _plan(app, target)
        assert caught.value.code == 'key_policy_changed'
        assert _snapshot(app) == before


def test_wrong_native_database_target_refuses_before_key_resolution():
    with application() as app:
        run(app)
        publish(app)
        document = app.plan.document
        document['target'][1] = '0'
        app.plan = m.MigrationPlan(m._canonical(document))
        app.pin = replace(app.pin, plan_digest=app.plan.digest)
        # Match journal continuity so native target comparison is the refusal.
        with app.owner.begin() as c:
            c.exec_driver_sql(
                f'UPDATE "{app.schema}"."_cryptalis_journal" SET plan_digest=%s', (app.plan.digest,))
        before = _snapshot(app)
        def forbidden(tenant):
            pytest.fail('wrong database target reached key resolution')
        with pytest.raises(m.TransitionFailure) as caught:
            plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=forbidden,
                        target_keys=forbidden, verify_rows_per_second=1000)
        assert caught.value.code == 'deployment_not_current'
        assert _snapshot(app) == before


def test_source_provider_outage_hides_private_error_and_keeps_native_source():
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        class Unavailable(PublicFixtureProvider):
            def unwrap(self, *args):
                raise RuntimeError('PRIVATE_SOURCE_REWRAP_DETAIL')
        source = Keyring(keys(TENANT).policy, {PROVIDER: Unavailable()})
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:
            plan_rewrap(app.plan, app.owner, source_pin=app.pin, keys=source,
                        target_keys=target, verify_rows_per_second=1000)
        assert caught.value.code == 'KeyUnavailable'
        assert 'PRIVATE_SOURCE_REWRAP_DETAIL' not in ''.join(traceback.format_exception(caught.value))
        assert _snapshot(app) == before


def test_planner_observes_read_only_snapshot_during_a_committed_frame_edit():
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        before = _plan(app, target)
        field = app.plan.document['lock']['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        new_frame = seal_text('committed during rewrap planning', descriptor, TENANT,
                              UUID(int=101), keys(TENANT).prepare())
        settings = []
        def observe(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith('SET TRANSACTION ISOLATION LEVEL'):
                with cursor.connection.cursor() as probe:
                    probe.execute('SHOW transaction_read_only')
                    read_only = probe.fetchone()[0]
                    probe.execute('SHOW transaction_isolation')
                    settings.append((read_only, probe.fetchone()[0]))
        def concurrent_target(tenant):
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                  (new_frame, UUID(int=101)))
            return target
        event.listen(app.owner, 'after_cursor_execute', observe)
        try:
            during = _plan(app, concurrent_target)
        finally:
            event.remove(app.owner, 'after_cursor_execute', observe)
        after = _plan(app, target)
        assert settings == [('on', 'repeatable read')]
        first = before.document['models'][str(TABLE_ID)]
        consistent = during.document['models'][str(TABLE_ID)]
        changed = after.document['models'][str(TABLE_ID)]
        assert first == consistent
        assert changed['membership'] == first['membership']
        assert changed['frames'] != first['frames']


@pytest.mark.parametrize('fault', [
    'missing_payload_context', 'missing_context_field', 'bool_model_rows',
    'bool_total_rows', 'negative_cost', 'out_of_range_cost', 'unrepresentable_cost'])
def test_malformed_rewrap_protocol_artifact_has_a_typed_safe_failure(fault):
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        proposal = _plan(app, target)
        document = proposal.document
        policy = document['key_policies'][str(TENANT)]
        if fault == 'missing_payload_context':
            policy['contexts'] = [c for c in policy['contexts'] if c['purpose'] != 'payload']
        elif fault == 'missing_context_field':
            policy['contexts'][0].pop('root_id')
        elif fault == 'bool_model_rows':
            document['models'][str(TABLE_ID)]['rows'] = True
        elif fault == 'bool_total_rows':
            document['estimates']['rows'] = True
        elif fault == 'negative_cost':
            document['estimates']['verify_seconds_estimate'] = -1
        elif fault == 'out_of_range_cost':
            document['estimates']['verify_seconds_estimate'] = 2**53
        else:
            document['estimates']['verify_rows_per_second'] = 1e-320
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:
            RewrapPlan(m._canonical(document))
        assert caught.value.code == 'invalid_rewrap_plan'
        assert _snapshot(app) == before


@pytest.mark.parametrize('rate', [True, 0, -1, float('nan'), float('inf'), 10**1000])
def test_invalid_host_rate_refuses_before_database_connection(rate):
    with application() as app:
        run(app)
        publish(app)
        class Closed:
            def connect(self):
                pytest.fail('invalid rate opened a connection')
        with pytest.raises(m.TransitionFailure) as caught:
            plan_rewrap(app.plan, Closed(), source_pin=app.pin, keys=keys,
                        target_keys=None, verify_rows_per_second=rate)
        assert caught.value.code == 'missing_measured_rates'


def test_expiry_during_connection_cleanup_refuses_the_completed_proposal(monkeypatch):
    import time
    from types import SimpleNamespace
    from cryptalis.crypto import keys as crypto_keys
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        before = _snapshot(app)
        clock = [time.monotonic()]
        monkeypatch.setattr(crypto_keys, 'time', SimpleNamespace(
            monotonic=lambda: clock[0], monotonic_ns=time.monotonic_ns))

        class Connection:
            def __init__(self, native): self.native = native
            def __getattr__(self, name): return getattr(self.native, name)
            def close(self):
                self.native.close()
                clock[0] += 301

        class Engine:
            def connect(self): return Connection(app.owner.connect())

        with pytest.raises(m.TransitionFailure) as caught:
            plan_rewrap(app.plan, Engine(), source_pin=app.pin, keys=keys,
                        target_keys=target, verify_rows_per_second=1000)
        assert caught.value.code == 'KeyUnavailable'
        assert _snapshot(app) == before


def test_operation_identity_failure_is_safe_and_leaves_native_state_unchanged(monkeypatch):
    from cryptalis import rotation
    with application() as app:
        run(app)
        publish(app)
        target, _ = _target()
        before = _snapshot(app)

        def unavailable():
            raise OSError('PRIVATE_REWRAP_RANDOM_DETAIL')

        monkeypatch.setattr(rotation, 'uuid4', unavailable)
        with pytest.raises(m.TransitionFailure) as caught:
            _plan(app, target)
        assert caught.value.code == 'operation_failed_requires_inspection'
        assert 'PRIVATE_REWRAP_RANDOM_DETAIL' not in ''.join(traceback.format_exception(caught.value))
        assert _snapshot(app) == before
