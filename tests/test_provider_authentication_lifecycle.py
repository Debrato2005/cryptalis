"""Authentication failures keep native uncertainty separate from database effects."""
import json
from uuid import UUID

import pytest
from sqlalchemy import event, select

from cryptalis import migration as m
from cryptalis.crypto import ProviderAuthenticationUnavailable
from test_migration import application, keys, publish, run, TENANT
from test_operational_cli import host, inputs, invoke, PRIVATE
from test_owned_sequences import _snapshot
from test_application_online import app, tenant_app, configuration, plan_online


def unavailable(tenant):
    raise ProviderAuthenticationUnavailable() from RuntimeError(PRIVATE)


def authentication_error(result, *, effects):
    code, output, error = result
    assert code == 4 and output == ''
    item = json.loads(error)['error']
    assert item['code'] == 'ProviderAuthenticationUnavailable'
    assert item['retryable'] is False
    assert item['effects'] == effects and item['effects_scope'] == 'database'
    assert item['provider_effects'] == 'UNKNOWN'
    assert 'native token issuance' in item['remedy']
    assert 'token may already have been issued' in item['remedy']
    return item


@pytest.mark.parametrize('purpose,side', [('protection', 'source'), ('protection', 'late'),
    ('rewrap', 'source'), ('rewrap', 'target'), ('payload', 'source'), ('payload', 'target'),
    ('search', 'source'), ('search', 'target')])
def test_read_only_cli_authentication_failure_is_operational_without_published_artifact(
        tmp_path, monkeypatch, capsys, purpose, side):
    with application() as app:
        if purpose != 'protection':
            run(app); publish(app)
        path, manifest = inputs(app, tmp_path)
        output = tmp_path / 'unpublished.json'
        if purpose == 'protection':
            calls = []
            def resolve(tenant):
                calls.append(tenant)
                if side == 'late' and len(calls) == 1: return keys(tenant)
                return unavailable(tenant)
            reference, _, observed = host(app, monkeypatch, planning=True, resolver=resolve)
            arguments = ('plan', str(manifest))
        else:
            if purpose == 'rewrap':
                from test_rewrap_operational_cli import host as rotation_host
            elif purpose == 'payload':
                from test_payload_operational_cli import host as rotation_host
            else:
                from test_search_operational_cli import host as rotation_host
            reference, _, observed = rotation_host(app, monkeypatch, None, kind='plan',
                                                   **{side + '_keys': unavailable})
            arguments = ('keys', 'rotate', purpose, 'plan', str(path))
        before = _snapshot(app)
        authentication_error(invoke(capsys, *arguments, '--host-context', reference,
            '--out', str(output), '--json'), effects='NONE')
        assert _snapshot(app) == before and not output.exists()
        assert observed['factory'] == observed['dispose'] == 1
        assert observed['keys' if purpose == 'protection' else side] == (2 if side == 'late' else 1)


@pytest.mark.parametrize('cleanup_failure', [False, True])
def test_execution_preserves_journal_and_native_uncertainty_through_cleanup_and_resume(
        tmp_path, monkeypatch, capsys, cleanup_failure):
    with application() as app:
        run(app, until='EXPANDED')
        path, _ = inputs(app, tmp_path)
        before = _snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:
            run(app, until='BACKFILLED', key_resolver=unavailable)
        failure = caught.value
        assert failure.code == 'ProviderAuthenticationUnavailable'
        assert failure.effects == 'INSPECT_JOURNAL'
        assert failure.provider_effects == 'UNKNOWN' and failure.retryable is False
        assert 'native token issuance' in str(failure) and PRIVATE not in str(failure)
        assert _snapshot(app) == before
        reference, configuration, observed = host(app, monkeypatch, resolver=unavailable,
                                                 dispose_failure=cleanup_failure)
        result = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        if cleanup_failure:
            code, output, error = result
            item = json.loads(error)['error']
            assert code == 4 and output == '' and item['code'] == 'CleanupUnavailable'
            related = item['related_error']
            authentication_error((4, '', json.dumps({'error': related})), effects='INSPECT_JOURNAL')
        else:
            authentication_error(result, effects='INSPECT_JOURNAL')
        assert observed['keys'] == observed['dispose'] == 1 and _snapshot(app) == before
        progress = m.status(app.plan, app.owner, pin=app.pin)
        assert progress.phase == 'EXPANDED' and progress.committed_rows == 0
        configuration.update(resolver=keys, dispose_failure=False)
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        assert code == 0 and error == '' and json.loads(output)['phase'] == 'PENDING'


def test_online_approved_tenant_resolver_retains_authentication_identity(tenant_app):
    configured = configuration(tenant_app, tenant_app.tenant_plan)
    with pytest.raises(m.TransitionFailure) as caught:
        plan_online(configured, tenant_app, unavailable)
    assert caught.value.code == 'ProviderAuthenticationUnavailable'
    assert caught.value.provider_effects == 'UNKNOWN' and caught.value.retryable is False
    assert PRIVATE not in str(caught.value)


def test_runtime_resolver_preserves_authentication_failure_before_sql_and_recovers():
    from cryptalis.sqlalchemy import attach
    with application() as app:
        run(app); publish(app)
        bad, statements = [False], []
        def resolve(tenant):
            return unavailable(tenant) if bad[0] else keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=resolve, deployment=(app.plan, app.pin))
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: statements.append(True))
        bad[0] = True
        with pytest.raises(ProviderAuthenticationUnavailable) as caught:
            factory(tenant_id=TENANT)
        assert caught.value.effects == 'UNKNOWN' and caught.value.retryable is False
        assert caught.value.__suppress_context__ and PRIVATE not in str(caught.value)
        assert statements == []
        bad[0] = False
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.name).where(
                app.Customer.id == UUID(int=101), app.Customer.tenant_id == TENANT)) == app.source[UUID(int=101)][1]


@pytest.mark.parametrize('purpose', ['payload', 'search'])
@pytest.mark.parametrize('phase', ['backfill', 'verify'])
def test_rotation_expiry_refresh_keeps_authentication_failure_and_atomic_state(purpose, phase, monkeypatch):
    from test_rotation_lease_boundary import preparation, warm_pair, invoke as rotate, snapshot, complete
    with application(rows=5) as app:
        run(app); publish(app)
        proposal, target = preparation(app, purpose, phase)
        before = snapshot(app, proposal)
        with monkeypatch.context() as patch:
            source, refreshed, clock, _ = warm_pair(patch, purpose, phase)
            def refresh(tenant):
                return unavailable(tenant) if clock.expiries else refreshed(tenant)
            with pytest.raises(m.TransitionFailure) as caught:
                rotate(app, proposal, phase, source, refresh)
            assert clock.expiries == 1
            assert caught.value.code == 'ProviderAuthenticationUnavailable'
            assert caught.value.provider_effects == 'UNKNOWN' and caught.value.retryable is False
            assert PRIVATE not in str(caught.value)
        assert snapshot(app, proposal) == before
        assert complete(app, proposal, target).document['kind'] == purpose + '_rotation'
