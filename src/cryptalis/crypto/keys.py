"""Explicit root custody and bounded process-local preparation.

The local provider is for synthetic development data only. Python immutable
bytes cannot provide a verified zeroization guarantee.
"""

import asyncio
import os
import threading
import time
from itertools import count
from dataclasses import dataclass, field
from hmac import compare_digest
from types import MappingProxyType
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

_operation_numbers = count()


class CryptoFailure(ValueError):
    """Safe diagnostics: no supplied values or underlying exception text."""

    stage = "crypto"
    remedy = "Check the pinned descriptor, expected row context, and admitted key policy."
    retryable = False
    effects = "none"

    def __init__(self):
        self.code = type(self).__name__
        # Diagnostic identifiers need no randomness; RNG failure must remain typed.
        self.operation_id = f"{os.getpid():x}-{time.monotonic_ns():x}-{next(_operation_numbers):x}"
        super().__init__(f"{self.code} during {self.stage}. {self.remedy} Operation {self.operation_id}.")


class InvalidContext(CryptoFailure):
    stage = "context validation"


class InvalidText(CryptoFailure):
    stage = "text encoding"
    remedy = "Supply strict UTF-8 text without NUL, at most 16 MiB encoded, or SQL NULL."


class InvalidFrame(CryptoFailure):
    stage = "frame validation"
    remedy = "Restore the complete CF1 frame from a trusted source; do not retry altered data."


class AuthenticationFailed(CryptoFailure):
    stage = "authentication"
    remedy = "Check expected context and exact admitted roots; investigate possible data alteration."


class RepresentationMismatch(CryptoFailure):
    stage = "representation validation"


class CryptoBackendUnavailable(CryptoFailure):
    stage = "cryptographic backend"
    remedy = "Check OS randomness and the installed cryptography backend. Do not switch algorithms."
    retryable = True


class KeyUnavailable(CryptoFailure):
    stage = "key preparation or use"
    remedy = "Check the exact provider, wrapped roots and generation policy; prepare fresh keys in this process."
    retryable = True


def tuple_bytes(*parts: bytes) -> bytes:
    """CF1 length-prefixed tuple, with no implicit conversion."""
    if len(parts) > 0xFFFFFFFF or any(type(p) is not bytes or len(p) > 0xFFFFFFFF for p in parts):
        raise InvalidContext()
    return len(parts).to_bytes(4, "big") + b"".join(len(p).to_bytes(4, "big") + p for p in parts)


def _identity(value):
    if not isinstance(value, UUID) or value.int == 0:
        raise InvalidContext()


def _native_uuid(value):
    # Nil UUIDs are valid PostgreSQL application values, not deployment IDs.
    if not isinstance(value, UUID):
        raise InvalidContext()


def _generation(value):
    if type(value) is not int or not 1 <= value <= 0xFFFFFFFF:
        raise InvalidContext()


@dataclass(frozen=True)
class KeyContext:
    domain_id: UUID
    tenant_id: UUID
    purpose: str
    root_id: UUID
    generation: int

    def __post_init__(self):
        for identity in (self.domain_id, self.root_id):
            _identity(identity)
        _native_uuid(self.tenant_id)
        _generation(self.generation)
        if self.purpose not in ("payload", "search"):
            raise InvalidContext()

    def _aad(self, provider_id):
        _identity(provider_id)
        return tuple_bytes(b"CF1/development-wrap/v1", provider_id.bytes, self.domain_id.bytes,
                           self.tenant_id.bytes, self.purpose.encode("ascii"), self.root_id.bytes,
                           self.generation.to_bytes(4, "big"))


@dataclass(frozen=True)
class WrappedRoot:
    provider_id: UUID
    context: KeyContext
    sealed: bytes = field(repr=False)

    def __post_init__(self):
        _identity(self.provider_id)
        if not isinstance(self.context, KeyContext) or type(self.sealed) is not bytes or not 1 <= len(self.sealed) <= 65536:
            raise InvalidContext()


class KeyProvider(Protocol):
    """Provider authority comes from deployment policy, never a frame header."""

    provider_id: UUID

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot: ...
    def unwrap(self, wrapper: WrappedRoot, context: KeyContext) -> bytes: ...
    async def unwrap_async(self, wrapper: WrappedRoot, context: KeyContext) -> bytes: ...
    def rewrap(self, wrapper: WrappedRoot, new_provider: "KeyProvider", context: KeyContext) -> WrappedRoot: ...


def create_root(provider: KeyProvider, context: KeyContext) -> WrappedRoot:
    """Generate an independent OS-random root, retaining only its wrapper."""
    if not isinstance(context, KeyContext):
        raise InvalidContext()
    try:
        result = provider.wrap(os.urandom(32), context)
        if not isinstance(result, WrappedRoot) or result.context != context or result.provider_id != provider.provider_id:
            raise KeyUnavailable()
        return result
    except Exception:
        raise KeyUnavailable() from None


class DevelopmentKeyProvider:
    """An ephemeral local KEK. Restart loses custody; no production mode exists."""

    def __init__(self):
        self._pid = os.getpid()
        try:
            self.provider_id = uuid4()
            self._key = os.urandom(32)
        except Exception:
            raise KeyUnavailable() from None

    def _check(self):
        if self._pid != os.getpid():
            self._key = None
            raise KeyUnavailable()

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot:
        self._check()
        if type(root) is not bytes or len(root) != 32 or not isinstance(context, KeyContext):
            raise InvalidContext()
        try:
            nonce = os.urandom(12)
            sealed = AESGCMSIV(self._key).encrypt(nonce, root, context._aad(self.provider_id))
            return WrappedRoot(self.provider_id, context, nonce + sealed)
        except Exception:
            raise KeyUnavailable() from None

    def unwrap(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        if (not isinstance(wrapper, WrappedRoot) or wrapper.provider_id != self.provider_id or
                wrapper.context != context or len(wrapper.sealed) != 60):
            raise KeyUnavailable()
        try:
            return AESGCMSIV(self._key).decrypt(wrapper.sealed[:12], wrapper.sealed[12:], context._aad(self.provider_id))
        except Exception:
            raise KeyUnavailable() from None

    async def unwrap_async(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        return self.unwrap(wrapper, context)

    def rewrap(self, wrapper: WrappedRoot, new_provider: KeyProvider, context: KeyContext) -> WrappedRoot:
        root = self.unwrap(wrapper, context)
        try:
            result = new_provider.wrap(root, context)
            if not isinstance(result, WrappedRoot) or result.context != context or result.provider_id != new_provider.provider_id:
                raise KeyUnavailable()
            return result
        except Exception:
            raise KeyUnavailable() from None


@dataclass(frozen=True)
class KeyPolicy:
    """Trusted finite admission set for exactly one domain and tenant."""

    domain_id: UUID
    tenant_id: UUID
    wrappers: tuple[WrappedRoot, ...]
    payload_generation: int
    search_generation: int | None = None

    def __post_init__(self):
        _identity(self.domain_id)
        _native_uuid(self.tenant_id)
        _generation(self.payload_generation)
        if self.search_generation is not None:
            _generation(self.search_generation)
        if type(self.wrappers) is not tuple or not 1 <= len(self.wrappers) <= 32:
            raise InvalidContext()
        identities, roots = set(), set()
        for wrapper in self.wrappers:
            if not isinstance(wrapper, WrappedRoot):
                raise InvalidContext()
            c = wrapper.context
            identity = (c.purpose, c.generation)
            if (c.domain_id, c.tenant_id) != (self.domain_id, self.tenant_id) or identity in identities or c.root_id in roots:
                raise InvalidContext()
            identities.add(identity)
            roots.add(c.root_id)
        if ("payload", self.payload_generation) not in identities:
            raise InvalidContext()
        if self.search_generation is not None and ("search", self.search_generation) not in identities:
            raise InvalidContext()


@dataclass(frozen=True)
class _Material:
    context: KeyContext
    root: bytes = field(repr=False)
    expires: float


@dataclass(frozen=True)
class PreparedKeys:
    """An operation's admitted keys. Expiry is checked on every actual use."""

    policy: KeyPolicy
    _materials: object = field(repr=False)
    _pid: int = field(repr=False)

    def _resolve(self, domain, tenant, purpose, generation):
        if self._pid != os.getpid() or (domain, tenant) != (self.policy.domain_id, self.policy.tenant_id):
            raise KeyUnavailable()
        material = self._materials.get((purpose, generation))
        if material is None or time.monotonic() >= material.expires:
            raise KeyUnavailable()
        return material


class Keyring:
    """One immutable policy and one bounded cache; no remote work at frame read."""

    def __init__(self, policy: KeyPolicy, providers: dict[UUID, KeyProvider], *, max_age: float = 60):
        if (not isinstance(policy, KeyPolicy) or type(max_age) not in (float, int) or not 0 < max_age <= 300):
            raise InvalidContext()
        self._policy = policy
        self._providers = dict(providers)
        self._max_age = max_age
        self._cache = {}
        self._pid = os.getpid()
        self._lock = threading.Lock()

    @property
    def policy(self):
        return self._policy

    def _check(self):
        # Check before taking a lock: a fork can inherit a locked mutex.
        if self._pid != os.getpid():
            self._cache.clear()
            raise KeyUnavailable()

    def _snapshot(self):
        self._check()
        started = time.monotonic()
        with self._lock:
            cached = {w: m for w, m in self._cache.items()
                      if w in self.policy.wrappers and m.expires > started}
            self._cache = dict(cached)
        return started, cached

    def _provider(self, wrapper):
        provider = self._providers.get(wrapper.provider_id)
        if provider is None or provider.provider_id != wrapper.provider_id:
            raise KeyUnavailable()
        return provider

    def _material(self, wrapper, root, started):
        if type(root) is not bytes or len(root) != 32:
            raise KeyUnavailable()
        return _Material(wrapper.context, root, started + self._max_age)

    def _publish(self, staged):
        self._check()
        materials = tuple(staged.values())
        now = time.monotonic()
        if any(m.expires <= now for m in materials):
            raise KeyUnavailable()
        # Distinct root identities/generations must carry independent material.
        for i, a in enumerate(materials):
            for b in materials[i + 1:]:
                if compare_digest(a.root, b.root):
                    raise KeyUnavailable()
        with self._lock:
            for wrapper, material in staged.items():
                existing = self._cache.get(wrapper)
                if existing is None or existing.expires <= now:
                    self._cache[wrapper] = material
                else:
                    staged[wrapper] = existing
        by_generation = {(m.context.purpose, m.context.generation): m for m in staged.values()}
        return PreparedKeys(self.policy, MappingProxyType(by_generation), self._pid)

    def prepare(self) -> PreparedKeys:
        started, staged = self._snapshot()
        try:
            for wrapper in self.policy.wrappers:
                if wrapper not in staged:
                    root = self._provider(wrapper).unwrap(wrapper, wrapper.context)
                    staged[wrapper] = self._material(wrapper, root, started)
            return self._publish(staged)
        except Exception:
            raise KeyUnavailable() from None

    async def prepare_async(self) -> PreparedKeys:
        started, staged = self._snapshot()
        try:
            for wrapper in self.policy.wrappers:
                if wrapper not in staged:
                    root = await self._provider(wrapper).unwrap_async(wrapper, wrapper.context)
                    staged[wrapper] = self._material(wrapper, root, started)
                if asyncio.current_task().cancelling():
                    raise asyncio.CancelledError()
            return self._publish(staged)
        except Exception:
            raise KeyUnavailable() from None
