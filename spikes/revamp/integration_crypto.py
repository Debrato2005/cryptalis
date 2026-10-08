"""Bounded CF1 text composition for the local integrated fixture. Unreviewed."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import hmac
import os
import struct
import time
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Failure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def t(*parts):
    if any(type(part) is not bytes for part in parts):
        raise Failure("BYTE_ENCODING_REQUIRED")
    return struct.pack(">I", len(parts)) + b"".join(struct.pack(">I", len(part)) + part for part in parts)


def u32(value):
    if type(value) is not int or not 0 < value < 2 ** 32:
        raise Failure("INVALID_GENERATION")
    return struct.pack(">I", value)


def integer(value, width):
    if type(value) is not int or width not in (4, 8) or not -(2 ** (width * 8 - 1)) <= value < 2 ** (width * 8 - 1):
        raise Failure("ORIGINAL_INTEGER_ID_REQUIRED")
    return t(b"int32" if width == 4 else b"int64", value.to_bytes(width, "big", signed=True))


def tenant_id(value, width):
    integer(value, width)
    # Injective public mapping for the admitted original signed integer type.
    return (b"i032" if width == 4 else b"i064") + value.to_bytes(12, "big", signed=True)


@dataclass(frozen=True)
class Field:
    domain: bytes
    identity: bytes
    search_domain: bytes
    record_width: int
    tenant_width: int
    max_bytes: int = 16 * 1024 * 1024

    def descriptor(self):
        return t(b"CF1/descriptor", b"utf8-text", struct.pack(">I", self.max_bytes),
                 b"SQL_NULL", b"pg:deterministic-text:exact", self.identity,
                 b"int32" if self.record_width == 4 else b"int64",
                 b"int32" if self.tenant_width == 4 else b"int64")


class LocalKeyring:
    """Memory-only development authority/cache. No mature-provider custody claim."""
    development_only = True

    def __init__(self, max_age=60):
        self._kek = os.urandom(32)
        self._wrapped = {}
        self._cache = {}
        self._scope = ContextVar("cryptalis_local_scope_" + uuid.uuid4().hex, default=None)
        self.max_age = max_age
        self.available = True
        self.payload_generation = 1
        self.search_generation = 1
        self.admitted_payload = {1}
        self.admitted_search = {1}
        self.unwraps = 0

    @contextmanager
    def scope(self, tenants):
        token = self._scope.set(frozenset(tenants))
        try:
            yield
        finally:
            self._scope.reset(token)

    def authorize(self, tenant):
        scope = self._scope.get()
        if scope is not None and tenant not in scope:
            raise Failure("TENANT_SCOPE_DENIED")

    def tenants(self):
        scope = self._scope.get()
        tenants = {key[0] for key in self._wrapped}
        return sorted(tenants if scope is None else tenants & scope)

    def _context(self, key, root_id):
        tenant, purpose, generation = key
        return t(b"LOCAL-DEVELOPMENT-WRAP", tenant.to_bytes(16, "big", signed=True), purpose, u32(generation), root_id)

    def prepare(self, tenant, purpose, generation, *, create=False):
        self.authorize(tenant)
        admitted = self.admitted_payload if purpose == b"payload" else self.admitted_search
        if purpose not in (b"payload", b"search") or generation not in admitted:
            raise Failure("EXACT_GENERATION_NOT_ADMITTED")
        key = (tenant, purpose, generation)
        if key not in self._wrapped:
            if not create or not self.available or self._kek is None:
                raise Failure("EXACT_ROOT_UNAVAILABLE")
            root = os.urandom(32)
            root_id = uuid.uuid4().bytes
            nonce = os.urandom(12)
            wrapper = nonce + AESGCMSIV(self._kek).encrypt(nonce, root, self._context(key, root_id))
            self._wrapped[key] = (root_id, wrapper)
        root_id, wrapper = self._wrapped[key]
        cached = self._cache.get(key)
        if cached is not None and time.monotonic() < cached[1]:
            return root_id, cached[0]
        if not self.available or self._kek is None:
            raise Failure("KEY_UNAVAILABLE_COLD_OR_EXPIRED")
        try:
            root = AESGCMSIV(self._kek).decrypt(wrapper[:12], wrapper[12:], self._context(key, root_id))
        except InvalidTag:
            raise Failure("LOCAL_WRAPPER_AUTHENTICATION_FAILED") from None
        self.unwraps += 1
        self._cache[key] = (root, time.monotonic() + self.max_age)
        return root_id, root

    def rewrap_local(self):
        if not self.available or self._kek is None:
            raise Failure("LOCAL_WRAPPING_AUTHORITY_UNAVAILABLE")
        new_kek = os.urandom(32)
        replacements = {}
        for key, (root_id, wrapper) in self._wrapped.items():
            try:
                root = AESGCMSIV(self._kek).decrypt(wrapper[:12], wrapper[12:], self._context(key, root_id))
            except InvalidTag:
                raise Failure("LOCAL_WRAPPER_AUTHENTICATION_FAILED") from None
            nonce = os.urandom(12)
            replacements[key] = (root_id, nonce + AESGCMSIV(new_kek).encrypt(nonce, root, self._context(key, root_id)))
        self._wrapped = replacements
        self._kek = new_kek
        self._cache.clear()

    def clear_cache(self):
        self._cache.clear()


def derived(field, provider, tenant, purpose, generation, info, *, create=False):
    root_id, root = provider.prepare(tenant, purpose, generation, create=create)
    salt = hashlib.sha256(t(b"CF1/root", field.domain, tenant_id(tenant, field.tenant_width), root_id, u32(generation))).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(root)


def encoded(field, value):
    if type(value) is not str or "\x00" in value:
        raise Failure("ORIGINAL_POSTGRESQL_TEXT_REQUIRED")
    try:
        result = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise Failure("INVALID_UTF8_TEXT") from None
    if len(result) > field.max_bytes:
        raise Failure("VALUE_OUTSIDE_DECLARED_RESOURCE_BOUND")
    return result


def term(field, provider, tenant, value, generation=None, *, create=False):
    if value is None:
        return None
    generation = provider.search_generation if generation is None else generation
    key = derived(field, provider, tenant, b"search", generation,
                  t(b"CF1/search-key", field.search_domain, b"utf8-text", b"exact", b"equality"), create=create)
    return hmac.digest(key, t(b"equality", encoded(field, value)), "sha256")


def payload_key(field, provider, tenant, record, generation, *, create=False):
    return derived(field, provider, tenant, b"payload", generation,
                   t(b"CF1/payload-key", field.identity, integer(record, field.record_width)), create=create)


def aad(field, tenant, record, header):
    return t(b"CF1/payload", field.domain, tenant_id(tenant, field.tenant_width), field.identity,
             integer(record, field.record_width), hashlib.sha256(field.descriptor()).digest(), header)


def seal(field, provider, tenant, record, value):
    if value is None:
        return None
    data = encoded(field, value)
    packed = term(field, provider, tenant, value, create=True)
    header = b"CF1\x00\x01\x01" + u32(provider.payload_generation) + u32(provider.search_generation) + packed
    nonce = os.urandom(12)
    key = payload_key(field, provider, tenant, record, provider.payload_generation, create=True)
    return header + nonce + AESGCMSIV(key).encrypt(nonce, data, aad(field, tenant, record, header))


def reveal(field, provider, tenant, record, frame):
    if frame is None:
        return None
    if not isinstance(frame, bytes) or not 74 <= len(frame) <= 74 + field.max_bytes or frame[:6] != b"CF1\x00\x01\x01":
        raise Failure("CF1_FRAME_REJECTED")
    payload_generation, search_generation = struct.unpack(">II", frame[6:14])
    key = payload_key(field, provider, tenant, record, payload_generation)
    try:
        value = AESGCMSIV(key).decrypt(frame[46:58], frame[58:], aad(field, tenant, record, frame[:46])).decode("utf-8", errors="strict")
    except (InvalidTag, UnicodeError):
        raise Failure("AUTHENTICATION_FAILED") from None
    encoded(field, value)
    expected = term(field, provider, tenant, value, search_generation)
    if not hmac.compare_digest(frame[14:46], expected):
        raise Failure("REPRESENTATION_MISMATCH")
    return value
