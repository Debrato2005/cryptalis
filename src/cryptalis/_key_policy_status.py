"""Public policy metadata bound to a saved artifact, without provider access."""
from uuid import UUID

from cryptalis import migration as m
from cryptalis.cli_host import KeyPolicyStatusContext
from cryptalis.crypto.keys import KeyContext, KeyPolicy, WrappedRoot
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES
from cryptalis._retained_obligations import _digest


def _failure(code, *, operational=False):
    from cryptalis.cli import _CommandFailure
    failure = _CommandFailure('Supply public key policies bound to this exact status artifact.',
        family='Transition', code=code, operation='transition.status', stage='key_policy_metadata',
        cause=code, exit_code=4 if operational else 2)
    failure.error.update(effects='NONE', host_configuration_effects='UNKNOWN',
        remedy='Check the saved policy digests and complete tenant policy set. Digest agreement does not prove custody, material correctness or safe retirement.')
    return failure


def report(plan, specification):
    """Describe validated public identities; no provider or material is inspected."""
    from cryptalis._cli_operations import _load_host, _quiet
    from cryptalis.cli import _CommandFailure
    try:
        context = _load_host(specification, 'transition.status')
    except _CommandFailure as failure:
        raise _failure(failure.error['code'], operational=failure.exit_code == 4) from None
    try:
        with _quiet():
            if (type(context) is not KeyPolicyStatusContext
                    or set(vars(context)) != {'operation_id', 'plan_digest', 'policies'}
                    or type(context.operation_id) is not UUID or context.operation_id.int == 0
                    or not _digest(context.plan_digest)
                    or (context.operation_id, context.plan_digest) != (plan.operation_id, plan.digest)
                    or type(context.policies) is not tuple or len(context.policies) > 64):
                raise ValueError
            document = plan.document
            expected = document['key_policies']
            domain = document['lock']['domain_id']
            total, policies, tenants = 0, [], set()
            for supplied in context.policies:
                if (type(supplied) is not KeyPolicy
                        or set(vars(supplied)) != {'domain_id', 'tenant_id', 'wrappers', 'payload_generation', 'search_generation'}
                        or type(supplied.domain_id) is not UUID or type(supplied.tenant_id) is not UUID
                        or type(supplied.wrappers) is not tuple or not 1 <= len(supplied.wrappers) <= 32):
                    raise ValueError
                wrappers = []
                for item in supplied.wrappers:
                    if (type(item) is not WrappedRoot or set(vars(item)) != {'provider_id', 'context', 'sealed'}
                            or type(item.provider_id) is not UUID or type(item.sealed) is not bytes
                            or not 1 <= len(item.sealed) <= 65536 or type(item.context) is not KeyContext):
                        raise ValueError
                    total += len(item.sealed)
                    if total > MAX_DOCUMENT_BYTES:
                        raise ValueError
                    c = item.context
                    if (set(vars(c)) != {'domain_id', 'tenant_id', 'purpose', 'root_id', 'generation'}
                            or any(type(value) is not UUID for value in (c.domain_id, c.tenant_id, c.root_id))
                            or type(c.purpose) is not str):
                        raise ValueError
                    native_context = KeyContext(c.domain_id, c.tenant_id, c.purpose, c.root_id, c.generation)
                    wrappers.append(WrappedRoot(item.provider_id, native_context, item.sealed))
                policy = KeyPolicy(supplied.domain_id, supplied.tenant_id, tuple(wrappers),
                                   supplied.payload_generation, supplied.search_generation)
                tenant = str(policy.tenant_id)
                identity = m._policy_document(policy)
                digest = m._hash(identity)
                if str(policy.domain_id) != domain or tenant in tenants or expected.get(tenant) != digest:
                    raise ValueError
                tenants.add(tenant)
                policies.append(dict(domain_id=str(policy.domain_id), tenant_id=tenant, policy_digest=digest,
                    payload_generation=policy.payload_generation, search_generation=policy.search_generation,
                    wrappers=[dict(provider_id=item['provider'], context=dict(item['context']), wrapper_sha256=item['wrapper'])
                              for item in identity['wrappers']]))
            if tenants != set(expected):
                raise ValueError
    except Exception:
        raise _failure('KeyPolicyMetadataInvalid') from None
    return dict(scope='pinned_public_key_policy_metadata', status='DIGEST_MATCH', authority='HOST_SUPPLIED_METADATA',
        verification='NOT_PERFORMED', provider_availability='UNKNOWN', material_correctness='UNKNOWN',
        inventory_completeness='UNKNOWN', recovery_capacity='UNKNOWN', policies=policies)
