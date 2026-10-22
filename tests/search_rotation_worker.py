"""Stable public search-rotation fixtures for independent test processes.

No production custody or serialized key material is provided. Lifecycle worker
commands belong to the later maintenance integration.
"""
from dataclasses import replace
import hashlib
from uuid import UUID, uuid5

from cryptalis.crypto import KeyContext, Keyring
from cryptalis.crypto.keys import KeyUnavailable, WrappedRoot
from test_migration import DOMAIN, keys


TARGET_PROVIDER = UUID(int=9521)
TARGET_WRAPPER = b'PUBLIC SEARCH WORKER WRAPPER'


def target_context(tenant, generation=2):
    return KeyContext(DOMAIN, tenant, 'search',
                      uuid5(DOMAIN, f'search-worker:{tenant}:{generation}'), generation)


class PublicSearchProvider:
    """Synthetic custody for independent public search generations."""

    provider_id = TARGET_PROVIDER

    def unwrap(self, wrapper, context):
        if (not isinstance(context, KeyContext) or not isinstance(wrapper, WrappedRoot)
                or context.generation < 2
                or context != target_context(context.tenant_id, context.generation)
                or wrapper.provider_id != self.provider_id
                or wrapper.context != context or wrapper.sealed != TARGET_WRAPPER):
            raise KeyUnavailable()
        return hashlib.sha256(b'PUBLIC SEARCH WORKER ROOT' + context.tenant_id.bytes
                              + context.generation.to_bytes(4, 'big')).digest()

    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def target_keys(tenant, *, generation=None, source=keys):
    """Keep exact readers/providers and select one new public search root."""
    old = source(tenant) if callable(source) else source
    if (not isinstance(old, Keyring) or old.policy.domain_id != DOMAIN
            or old.policy.tenant_id != tenant or old.policy.search_generation is None):
        raise KeyUnavailable()
    if generation is None:
        generation = max(wrapper.context.generation for wrapper in old.policy.wrappers
                         if wrapper.context.purpose == 'search') + 1
    provider = PublicSearchProvider()
    wrapper = WrappedRoot(provider.provider_id, target_context(tenant, generation), TARGET_WRAPPER)
    policy = replace(old.policy, wrappers=old.policy.wrappers + (wrapper,), search_generation=generation)
    # Test-only provider reuse preserves earlier payload/search fixture custody.
    return Keyring(policy, {**old._providers, provider.provider_id: provider})
