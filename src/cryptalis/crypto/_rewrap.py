"""Internal candidate preparation, not active-policy publication or rotation.

No SQL, journal, deployment pin or persistent custody changes occur here.
Provider wrap/unwrap calls can have provider-side effects. Python does not
promise root zeroization or cancellation of a blocking provider call.
"""
from hmac import compare_digest
from uuid import UUID

from .keys import KeyPolicy, Keyring, KeyUnavailable, WrappedRoot


def prepare_rewrap(source: Keyring, target) -> KeyPolicy:
    """Verify exact roots under target custody; return an inactive candidate.

    Every admitted root, including historical readers, retains its context.
    The existing active-artifact guards still reject this candidate until a
    separately verified publication operation makes it current.
    """
    try:
        if not isinstance(source, Keyring):
            raise KeyUnavailable()
        identity = target.provider_id
        if type(identity) is not UUID or identity.int == 0:
            raise KeyUnavailable()
        prepared = source.prepare()
        policy = prepared.policy
        replacements = []
        for wrapper in policy.wrappers:
            context = wrapper.context
            material = prepared._resolve(context.domain_id, context.tenant_id,
                                         context.purpose, context.generation)
            if material.context != context:
                raise KeyUnavailable()
            replacement = target.wrap(material.root, context)
            if (not isinstance(replacement, WrappedRoot)
                    or replacement.provider_id != identity
                    or replacement.context != context):
                raise KeyUnavailable()
            recovered = target.unwrap(replacement, context)
            if (type(recovered) is not bytes or len(recovered) != 32
                    or not compare_digest(material.root, recovered)):
                raise KeyUnavailable()
            prepared._resolve(context.domain_id, context.tenant_id,
                              context.purpose, context.generation)
            if target.provider_id != identity:
                raise KeyUnavailable()
            replacements.append(replacement)
        # A later provider call must not outlive any earlier source lease.
        for wrapper in policy.wrappers:
            context = wrapper.context
            prepared._resolve(context.domain_id, context.tenant_id,
                              context.purpose, context.generation)
        return KeyPolicy(policy.domain_id, policy.tenant_id, tuple(replacements),
                         policy.payload_generation, policy.search_generation)
    except Exception:
        raise KeyUnavailable() from None
