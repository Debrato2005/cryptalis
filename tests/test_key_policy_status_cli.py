"""Status binds public key metadata without preparing or contacting providers."""
from dataclasses import replace
import hashlib
import io
import json
import sys
from types import ModuleType, SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest

from cryptalis import cli, migration as m, rotation as r
from cryptalis.crypto import KeyContext, KeyPolicy, Keyring, WrappedRoot
from test_migration import application, run, publish, keys, TENANT
from test_operational_cli import invoke
from test_owned_sequences import _snapshot
from test_status_cli import inputs, arguments


def test_status_reports_pinned_public_policy_metadata_without_key_work(tmp_path, monkeypatch, capsys):
    with application() as app:
        run(app); publish(app)
        policy = keys(TENANT).policy
        module = ModuleType('key_policy_status_' + uuid4().hex)
        def factory():
            from cryptalis.cli_host import KeyPolicyStatusContext
            return KeyPolicyStatusContext(app.plan.operation_id, app.plan.digest, (policy,))
        module.factory = factory
        monkeypatch.setitem(sys.modules, module.__name__, module)
        before = _snapshot(app)
        def forbidden(*args, **kwargs):
            raise AssertionError('public policy metadata must not prepare keys')
        with monkeypatch.context() as no_keys:
            no_keys.setattr(Keyring, 'prepare', forbidden)
            code, text, error = invoke(capsys, *arguments(inputs(app, tmp_path)),
                '--key-policy-context', module.__name__ + ':factory')
        assert code == 0 and error == '', (code, error)
        summary = json.loads(text)
        metadata = summary['pinned_key_policy_metadata']
        assert metadata['status'] == 'DIGEST_MATCH' and metadata['authority'] == 'HOST_SUPPLIED_METADATA'
        assert metadata['verification'] == 'NOT_PERFORMED'
        assert all(metadata[name] == 'UNKNOWN' for name in (
            'provider_availability', 'material_correctness', 'inventory_completeness', 'recovery_capacity'))
        record = metadata['policies'][0]
        assert record['tenant_id'] == str(TENANT) and record['policy_digest'] == app.plan.document['key_policies'][str(TENANT)]
        assert record['payload_generation'] == policy.payload_generation and record['search_generation'] == policy.search_generation
        assert [item['wrapper_sha256'] for item in record['wrappers']] == [hashlib.sha256(item.sealed).hexdigest() for item in policy.wrappers]
        assert 'sealed' not in text and _snapshot(app) == before


def host(app, monkeypatch, *, policies=None, **overrides):
    from cryptalis.cli_host import KeyPolicyStatusContext
    context = KeyPolicyStatusContext(app.plan.operation_id, app.plan.digest,
        (keys(TENANT).policy,) if policies is None else policies)
    configuration = {'context': replace(context, **overrides)}
    calls = []
    module = ModuleType('policy_metadata_host_' + uuid4().hex)
    def factory():
        calls.append(True)
        print('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        if configuration.get('unavailable'):
            raise RuntimeError('PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        return configuration['context']
    module.factory = factory
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module.__name__ + ':factory', configuration, calls


def no_keys(*args, **kwargs):
    pytest.fail('metadata inspection prepared keys or contacted a provider')


def no_connect(*args, **kwargs):
    pytest.fail('invalid metadata reached command-managed database access')


def test_public_policy_digest_retains_exact_order_and_canonical_document():
    # This independent literal keeps the existing artifact digest representation.
    policy = keys(TENANT).policy
    expected = {'domain': str(policy.domain_id), 'tenant': str(policy.tenant_id),
        'payload': policy.payload_generation, 'search': policy.search_generation,
        'wrappers': [{'provider': str(item.provider_id), 'context': {
            'domain': str(item.context.domain_id), 'tenant': str(item.context.tenant_id),
            'purpose': item.context.purpose, 'root': str(item.context.root_id), 'generation': item.context.generation},
            'wrapper': hashlib.sha256(item.sealed).hexdigest()} for item in policy.wrappers]}
    canonical = json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    assert m._policy_document(policy) == expected and m._canonical(m._policy_document(policy)) == canonical
    assert m._policy(keys(TENANT)) == hashlib.sha256(canonical).hexdigest()
    reversed_policy = replace(policy, wrappers=tuple(reversed(policy.wrappers)))
    assert m._policy_document(reversed_policy)['wrappers'] == list(reversed(expected['wrappers']))
    assert m._hash(m._policy_document(reversed_policy)) != hashlib.sha256(canonical).hexdigest()


@pytest.mark.parametrize('fault', ['operation', 'artifact_digest', 'context_type', 'list', 'missing', 'duplicate',
    'extra_tenant', 'wrong_domain', 'wrapper', 'selection', 'policy_type', 'forged_policy',
    'forged_wrapper', 'forged_context', 'extra_policy_field', 'too_many', 'too_many_wrappers', 'aggregate_bytes'])
def test_invalid_public_metadata_refuses_before_database_and_key_work(tmp_path, monkeypatch, capsys, fault):
    with application() as app:
        reference, configuration, calls = host(app, monkeypatch)
        context = configuration['context']
        policy = context.policies[0]
        if fault == 'operation': context = replace(context, operation_id=uuid4())
        elif fault == 'artifact_digest': context = replace(context, plan_digest='0' * 64)
        elif fault == 'context_type': context = {'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER': True}
        elif fault == 'list': context = replace(context, policies=list(context.policies))
        elif fault == 'missing': context = replace(context, policies=())
        elif fault == 'duplicate': context = replace(context, policies=(policy, policy))
        elif fault == 'extra_tenant': context = replace(context, policies=(policy, keys(uuid4()).policy))
        elif fault == 'wrong_domain':
            domain = uuid4()
            changed = replace(policy, domain_id=domain, wrappers=tuple(replace(item,
                context=replace(item.context, domain_id=domain)) for item in policy.wrappers))
            context = replace(context, policies=(changed,))
        elif fault == 'wrapper':
            changed = replace(policy, wrappers=(replace(policy.wrappers[0], sealed=b'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER'),) + policy.wrappers[1:])
            context = replace(context, policies=(changed,))
        elif fault == 'selection': context = replace(context, policies=(replace(policy, search_generation=None),))
        elif fault == 'policy_type': context = replace(context, policies=(keys(TENANT),))
        elif fault == 'forged_policy': object.__setattr__(policy, 'payload_generation', True)
        elif fault == 'forged_wrapper': object.__setattr__(policy.wrappers[0], 'provider_id', UUID(int=0))
        elif fault == 'forged_context': object.__setattr__(policy.wrappers[0].context, 'generation', True)
        elif fault == 'extra_policy_field': object.__setattr__(policy, 'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER', True)
        elif fault == 'too_many': context = replace(context, policies=(policy,) * 65)
        elif fault == 'too_many_wrappers': object.__setattr__(policy, 'wrappers', policy.wrappers * 17)
        elif fault == 'aggregate_bytes':
            # Valid bounded native values exceed only the aggregate metadata budget.
            policies = []
            for _ in range(9):
                tenant = uuid4()
                wrappers = tuple(WrappedRoot(uuid4(), KeyContext(policy.domain_id, tenant, 'payload', uuid4(), generation),
                                             b'x' * 65536) for generation in range(1, 33))
                policies.append(KeyPolicy(policy.domain_id, tenant, wrappers, 32))
            context = replace(context, policies=tuple(policies))
        configuration['context'] = context
        paths, before = inputs(app, tmp_path), _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            forbidden.setattr(Keyring, 'prepare', no_keys)
            code, text, error = invoke(capsys, *arguments(paths), '--key-policy-context', reference)
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == '' and diagnostic['code'] == 'KeyPolicyMetadataInvalid'
        assert diagnostic['effects'] == 'NONE' and diagnostic['host_configuration_effects'] == 'UNKNOWN'
        assert 'known_result' not in diagnostic and calls == [True] and _snapshot(app) == before


@pytest.mark.parametrize('damage', ['plan', 'pin', 'preparation'])
def test_inputs_and_preparation_refusal_precede_either_metadata_factory(tmp_path, monkeypatch, capsys, damage):
    from test_payload_rotation_plan import plan as payload_plan
    from payload_rotation_worker import target_keys
    with application() as app:
        if damage == 'preparation':
            run(app); publish(app)
            app.plan = payload_plan(app, target_keys)
            app.pin = m.DeploymentPin(app.plan.source.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        reference, _, calls = host(app, monkeypatch)
        paths = inputs(app, tmp_path)
        if damage == 'plan': paths['plan'].write_bytes(b'PRIVATE_OPERATIONAL_HOST_OR_PROVIDER')
        elif damage == 'pin':
            doc = json.loads(paths['pin'].read_text()); doc['plan_digest'] = '0' * 64
            paths['pin'].write_text(json.dumps(doc))
        snapshot = SimpleNamespace(**{**vars(app), 'plan': app.plan.source if damage == 'preparation' else app.plan})
        before = _snapshot(snapshot)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            code, text, error = invoke(capsys, *arguments(paths), '--key-policy-context', reference,
                '--host-context', reference)
        diagnostic = json.loads(error)['error']
        assert code == 2 and text == ''
        assert diagnostic['code'] == ('KeyPolicyMetadataUnsupported' if damage == 'preparation' else 'InvalidInput')
        assert calls == [] and _snapshot(snapshot) == before


def test_host_failure_remains_safe_and_operational_without_database_access(tmp_path, monkeypatch, capsys):
    with application() as app:
        reference, configuration, calls = host(app, monkeypatch)
        configuration['unavailable'] = True
        paths, before = inputs(app, tmp_path), _snapshot(app)
        with monkeypatch.context() as forbidden:
            forbidden.setattr(psycopg, 'connect', no_connect)
            code, text, error = invoke(capsys, *arguments(paths), '--key-policy-context', reference)
        diagnostic = json.loads(error)['error']
        assert code == 4 and text == '' and diagnostic['code'] == 'HostContextUnavailable'
        assert diagnostic['effects'] == 'NONE' and calls == [True] and _snapshot(app) == before


def test_current_generation_policy_and_retained_backup_metadata_survive_native_removal(tmp_path, monkeypatch, capsys):
    from rewrap_worker import target_keys as rewrapped_keys
    from payload_rotation_worker import rotated_keys, PublicPayloadProvider
    from rewrap_worker import PublicRewrapProvider
    from search_rotation_worker import target_keys as search_keys, PublicSearchProvider
    from test_retained_obligations_cli import host as retained_host
    from cryptalis.cli_host import RetainedBackupObligation
    from test_deprotection import app_pin, d, least_privilege_role, native_rows
    from cryptalis.sqlalchemy import attach
    def current_keys(tenant): return search_keys(tenant, source=rotated_keys)
    with application() as app:
        run(app); publish(app)
        source = app.plan
        proposal = r.plan_rewrap(source, app.owner, source_pin=app.pin, keys=keys,
            target_keys=rewrapped_keys, verify_rows_per_second=1000)
        activation = proposal.activation_plan
        assert r.apply_rewrap(proposal, app.owner, keys=keys, target_keys=rewrapped_keys,
            pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=rewrapped_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        for purpose, old, new in (('payload', rewrapped_keys, rotated_keys), ('search', rotated_keys, current_keys)):
            preparation = getattr(r, 'plan_' + purpose + '_rotation')(activation, app.owner,
                source_pin=app_pin(activation, 'ACTIVE'), keys=old, target_keys=new,
                backfill_rows_per_second=1000, verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
            prep_pin = m.DeploymentPin(activation.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
            assert getattr(r, 'apply_' + purpose + '_rotation')(preparation, app.owner, keys=old, target_keys=new,
                pin=prep_pin, approval=app.approval).phase == 'BACKFILLED'
            activation = getattr(r, 'seal_' + purpose + '_rotation')(preparation, app.owner, keys=old, target_keys=new,
                pin=prep_pin, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
            assert getattr(r, 'switch_' + purpose + '_rotation')(preparation, activation, app.owner, keys=old, target_keys=new,
                pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
            assert m.apply(activation, app.owner, keys=new, pin=app_pin(activation, 'ACTIVATING'),
                approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        policy = current_keys(TENANT).policy
        reference, policy_configuration, _ = host(app, monkeypatch, policies=(policy,))
        backup = RetainedBackupObligation(uuid4(), source.artifact, 'a' * 64, 'b' * 64, None)
        retained_reference, retained_configuration, _ = retained_host(app, monkeypatch, records=(backup,))
        paths = inputs(app, tmp_path)
        def inspect():
            with monkeypatch.context() as forbidden:
                forbidden.setattr(Keyring, 'prepare', no_keys)
                for provider in (PublicRewrapProvider, PublicPayloadProvider, PublicSearchProvider):
                    forbidden.setattr(provider, 'unwrap', no_keys)
                result = invoke(capsys, *arguments(paths), '--key-policy-context', reference, '--host-context', retained_reference)
            assert result[0] == 0 and result[2] == ''
            return json.loads(result[1])
        before = _snapshot(app)
        summary = inspect()
        metadata = summary['pinned_key_policy_metadata']
        assert metadata['policies'][0]['payload_generation'] == metadata['policies'][0]['search_generation'] == 2
        assert sorted((item['context']['purpose'], item['context']['generation']) for item in metadata['policies'][0]['wrappers']) == [
            ('payload', 1), ('payload', 2), ('search', 1), ('search', 2)]
        assert summary['retained_obligations']['records'][0]['required_policy_digests'] == source.document['key_policies']
        assert _snapshot(app) == before
        factory = attach(app.mapping, app.runtime, lock=activation.lock_bytes, keys=current_keys, deployment=(activation, app.pin))
        with factory(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = 'latest value after public key metadata inspection'
            session.commit()
        expected = dict(app.source); expected[UUID(int=101)] = TENANT, 'latest value after public key metadata inspection'
        reverse = d.plan(activation, app.owner, source_pin=app.pin, keys=current_keys,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'fixture-only retained obligations remain UNKNOWN')
        assert d.apply(reverse, app.owner, keys=current_keys, pin=app_pin(reverse, 'PREPARED'),
            approval=app.approval, consent=consent).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, app.owner, keys=current_keys, pin=app_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=app.approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'native fixture latest-value workload', 'public backup references; no qualified custody', True)
        assert d.remove(reverse, app.owner, pin=app_pin(reverse, 'REMOVING'), approval=app.approval,
            consent=consent, removal=removal).phase == 'REMOVED'
        app.plan, app.pin = reverse, app_pin(reverse, 'REMOVED')
        assert native_rows(app) == expected
        paths['plan'].write_bytes(reverse.artifact)
        from dataclasses import asdict
        paths['pin'].write_text(json.dumps(asdict(app.pin), default=str))
        for configuration in (policy_configuration, retained_configuration):
            configuration['context'] = replace(configuration['context'], operation_id=reverse.operation_id, plan_digest=reverse.digest)
        summary = inspect()
        assert summary['phase'] == 'REMOVED' and summary['pinned_key_policy_metadata'] == metadata
        assert summary['retained_obligations']['records'][0]['source_plan_digest'] == source.digest
        before = _snapshot(app)
        with io.TextIOWrapper(io.FileIO('/dev/full', 'w'), write_through=True) as output, monkeypatch.context() as stream:
            stream.setattr(sys, 'stdout', output)
            code = cli.main(list(arguments(paths) + ('--key-policy-context', reference)))
        diagnostic = json.loads(capsys.readouterr().err)['error']
        assert code == 4 and diagnostic['code'] == 'OutputUnavailable' and 'known_result' not in diagnostic
        assert diagnostic['pinned_key_policy_metadata'] == metadata and _snapshot(app) == before
