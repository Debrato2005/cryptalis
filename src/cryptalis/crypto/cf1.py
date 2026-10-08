"""Bounded CF1 text frames with expected context and pre-admitted roots.

No provider call, algorithm fallback, normalization or plaintext fallback is
allowed here. SQL NULL presence and same-context replay are outside AEAD.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from hmac import compare_digest
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .keys import (
    AuthenticationFailed, CryptoBackendUnavailable, InvalidContext, InvalidFrame, InvalidText,
    KeyUnavailable, PreparedKeys, RepresentationMismatch, _identity, _native_uuid, tuple_bytes,
)

MAX_TEXT_BYTES = 16 * 1024 * 1024
_MAGIC = b"CF1\x00\x01"
_DESCRIPTOR_MEMBERS = frozenset(("schema", "domain_id", "table_id", "field_id", "text_codec",
                               "normalizer", "null_policy", "record_codec", "tenant_codec", "representation"))


@dataclass(frozen=True)
class FieldDescriptor:
    domain_id: UUID
    table_id: UUID
    field_id: UUID
    record_codec: str
    tenant_codec: str
    representation: str
    digest: bytes

    def __post_init__(self):
        for identity in (self.domain_id, self.table_id, self.field_id):
            _identity(identity)
        if (self.record_codec not in ("uuid16/v1", "int64-be/v1") or
                self.tenant_codec not in ("uuid16/v1", "single-tenant-uuid/v1") or
                self.representation not in ("cf1-storage/v1", "cf1-packed-equality/v1") or
                type(self.digest) is not bytes or len(self.digest) != 32):
            raise InvalidContext()

    @classmethod
    def from_compiled(cls, document: dict, digest: str) -> "FieldDescriptor":
        """Consume one trusted compiler descriptor; a hash is not authenticity."""
        try:
            if type(document) is not dict or set(document) != _DESCRIPTOR_MEMBERS:
                raise InvalidContext()
            if any(type(v) is not str or len(v) > 128 for v in document.values()):
                raise InvalidContext()
            if (document["schema"], document["text_codec"], document["normalizer"], document["null_policy"]) != (
                    "cryptalis.context/v1", "utf8-exact/v1", "identity/v1", "sql-null/v1"):
                raise InvalidContext()
            canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf8")
            actual = hashlib.sha256(canonical).digest()
            if type(digest) is not str or digest != actual.hex():
                raise InvalidContext()
            ids = tuple(UUID(document[name]) for name in ("domain_id", "table_id", "field_id"))
            if any(str(identity) != document[name] for identity, name in zip(ids, ("domain_id", "table_id", "field_id"))):
                raise InvalidContext()
            return cls(*ids, document["record_codec"], document["tenant_codec"], document["representation"], actual)
        except Exception:
            raise InvalidContext() from None

    @property
    def equality(self):
        return self.representation == "cf1-packed-equality/v1"

    def _record(self, tenant, record):
        _native_uuid(tenant)
        if self.tenant_codec == "single-tenant-uuid/v1" and tenant != self.table_id:
            raise InvalidContext()
        if self.record_codec == "uuid16/v1":
            _native_uuid(record)
            return record.bytes
        if type(record) is not int or not -(2**63) <= record < 2**63:
            raise InvalidContext()
        return tuple_bytes(b"int64", record.to_bytes(8, "big", signed=True))


def _encode(value):
    if type(value) is not str or len(value) > MAX_TEXT_BYTES or "\x00" in value:
        raise InvalidText()
    try:
        encoded = value.encode("utf8", errors="strict")
    except UnicodeError:
        raise InvalidText() from None
    if len(encoded) > MAX_TEXT_BYTES:
        raise InvalidText()
    return encoded


def _derive(material, info):
    c = material.context
    salt = hashlib.sha256(tuple_bytes(b"CF1/root", c.domain_id.bytes, c.tenant_id.bytes,
                                     c.root_id.bytes, c.generation.to_bytes(4, "big"))).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(material.root)


def _term(encoded, field, material):
    key = _derive(material, tuple_bytes(b"CF1/search-key", field.field_id.bytes,
                                       b"utf8-exact/v1", b"identity/v1", b"equality"))
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(tuple_bytes(b"equality", encoded))
    return mac.finalize()


def _context(field, tenant, record, keys):
    if not isinstance(field, FieldDescriptor) or not isinstance(keys, PreparedKeys):
        raise InvalidContext()
    typed = field._record(tenant, record)
    if (field.domain_id, tenant) != (keys.policy.domain_id, keys.policy.tenant_id):
        raise KeyUnavailable()
    return typed


def _aad(field, tenant, record, header):
    return tuple_bytes(b"CF1/payload", field.domain_id.bytes, tenant.bytes, field.field_id.bytes,
                       record, field.digest, header)


def seal_text(value: str | None, field: FieldDescriptor, tenant: UUID,
              record: UUID | int, keys: PreparedKeys) -> bytes | None:
    """Seal exact text using active policy generations and a fresh OS nonce."""
    typed = _context(field, tenant, record, keys)
    payload_generation = keys.policy.payload_generation
    payload = keys._resolve(field.domain_id, tenant, "payload", payload_generation)
    if value is None:
        return None
    encoded = _encode(value)
    search_generation = 0
    term = b""
    if field.equality:
        search_generation = keys.policy.search_generation
        search = keys._resolve(field.domain_id, tenant, "search", search_generation)
        term = _term(encoded, field, search)
    header = (_MAGIC + bytes([int(field.equality)]) + payload_generation.to_bytes(4, "big") +
              search_generation.to_bytes(4, "big") + term)
    key = _derive(payload, tuple_bytes(b"CF1/payload-key", field.field_id.bytes, typed))
    try:
        nonce = os.urandom(12)
        sealed = AESGCMSIV(key).encrypt(nonce, encoded, _aad(field, tenant, typed, header))
    except Exception:
        raise CryptoBackendUnavailable() from None
    # Check again after crypto work: no output using expired or forked material.
    keys._resolve(field.domain_id, tenant, "payload", payload_generation)
    if field.equality:
        keys._resolve(field.domain_id, tenant, "search", search_generation)
    return header + nonce + sealed


def open_text(frame: bytes | None, field: FieldDescriptor, tenant: UUID,
              record: UUID | int, keys: PreparedKeys) -> str | None:
    """Authenticate before decode or release. Header IDs cannot select custody."""
    typed = _context(field, tenant, record, keys)
    if frame is None:
        keys._resolve(field.domain_id, tenant, "payload", keys.policy.payload_generation)
        return None
    header_size = 46 if field.equality else 14
    overhead = header_size + 28
    if type(frame) is not bytes or not overhead <= len(frame) <= MAX_TEXT_BYTES + overhead:
        raise InvalidFrame()
    if frame[:5] != _MAGIC or frame[5] not in (0, 1):
        raise InvalidFrame()
    if frame[5] != int(field.equality):
        raise RepresentationMismatch()
    payload_generation = int.from_bytes(frame[6:10], "big")
    search_generation = int.from_bytes(frame[10:14], "big")
    if payload_generation == 0 or bool(search_generation) != field.equality:
        raise InvalidFrame()
    payload = keys._resolve(field.domain_id, tenant, "payload", payload_generation)
    search = keys._resolve(field.domain_id, tenant, "search", search_generation) if field.equality else None
    header = frame[:header_size]
    key = _derive(payload, tuple_bytes(b"CF1/payload-key", field.field_id.bytes, typed))
    try:
        encoded = AESGCMSIV(key).decrypt(frame[header_size:header_size + 12],
                                        frame[header_size + 12:], _aad(field, tenant, typed, header))
    except InvalidTag:
        raise AuthenticationFailed() from None
    except Exception:
        raise CryptoBackendUnavailable() from None
    if search is not None and not compare_digest(header[14:46], _term(encoded, field, search)):
        raise RepresentationMismatch()
    try:
        value = encoded.decode("utf8", errors="strict")
    except UnicodeError:
        raise InvalidText() from None
    if "\x00" in value:
        raise InvalidText()
    keys._resolve(field.domain_id, tenant, "payload", payload_generation)
    if field.equality:
        keys._resolve(field.domain_id, tenant, "search", search_generation)
    return value
