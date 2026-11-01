"""Bounded CF1 typed values with expected context and pre-admitted roots.

No provider call, algorithm fallback, normalization or plaintext fallback is
allowed here. SQL NULL presence and same-context replay are outside AEAD.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from hmac import compare_digest, digest as hmac_digest
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .keys import (
    AuthenticationFailed, CryptoBackendUnavailable, InvalidContext, InvalidFrame, InvalidText, InvalidValue,
    KeyUnavailable, PreparedKeys, RepresentationMismatch, _identity, _native_uuid, tuple_bytes,
)
from .._search_layout import prefix_block_size

MAX_TEXT_BYTES = 16 * 1024 * 1024
_MAGIC = b"CF1\x00\x01"
_INTEGER_WIDTHS = {"pg-int2-be/v1": 2, "pg-int4-be/v1": 4, "pg-int8-be/v1": 8}
_DATE_CODEC = "pg-date-days-be/v1"
_DATE_EPOCH = date(2000, 1, 1)
_TIMESTAMP_CODEC = 'pg-timestamp-us-be/v1'
_TIMESTAMP_EPOCH = datetime(2000, 1, 1)
_TIMESTAMPTZ_CODEC = 'pg-timestamptz-us-be/v1'
_NUMERIC_CODEC = 'pg-numeric-decimal/v1'
_JSONB_CODEC = 'pg-jsonb-text/v1'
_JSONB_NULL_POLICIES = {False: 'jsonb-none-as-json-null/v1', True: 'jsonb-none-as-sql-null/v1'}
_ORDER_REPRESENTATION = "cf1-packed-order/v1"
_PREFIX_REPRESENTATION = 'cf1-packed-prefix/v1'
_ORDER_CODECS = (*_INTEGER_WIDTHS, _DATE_CODEC, _TIMESTAMP_CODEC, _TIMESTAMPTZ_CODEC)
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
    value_codec: str = "utf8-exact/v1"
    prefix_lengths: tuple[int, int] | None = None
    json_none_as_null: bool | None = None

    def __post_init__(self):
        for identity in (self.domain_id, self.table_id, self.field_id):
            _identity(identity)
        if (self.record_codec not in ("uuid16/v1", "int64-be/v1") or
                self.tenant_codec not in ("uuid16/v1", "single-tenant-uuid/v1") or
                self.representation not in ("cf1-storage/v1", "cf1-packed-equality/v1", _ORDER_REPRESENTATION, _PREFIX_REPRESENTATION) or
                self.value_codec not in ("utf8-exact/v1", "boolean-u8/v1", _DATE_CODEC, _TIMESTAMP_CODEC, _TIMESTAMPTZ_CODEC, _NUMERIC_CODEC, _JSONB_CODEC, "date-ordinal-u32/v1", "uuid-bytes16/v1", *_INTEGER_WIDTHS) or
                self.value_codec == _JSONB_CODEC and (type(self.json_none_as_null) is not bool or
                    self.representation != 'cf1-storage/v1') or
                self.value_codec != _JSONB_CODEC and self.json_none_as_null is not None or
                self.representation == "cf1-packed-equality/v1" and self.value_codec not in ("utf8-exact/v1", _NUMERIC_CODEC) or
                self.representation == _ORDER_REPRESENTATION and self.value_codec not in _ORDER_CODECS or
                self.prefixed and (self.value_codec != 'utf8-exact/v1' or
                    type(self.prefix_lengths) is not tuple or len(self.prefix_lengths) != 2 or
                    any(type(bound) is not int for bound in self.prefix_lengths) or
                    not 1 <= self.prefix_lengths[0] <= self.prefix_lengths[1] <= 256) or
                not self.prefixed and self.prefix_lengths is not None or
                type(self.digest) is not bytes or len(self.digest) != 32):
            raise InvalidContext()

    @classmethod
    def from_compiled(cls, document: dict, digest: str) -> "FieldDescriptor":
        """Consume one trusted compiler descriptor; a hash is not authenticity."""
        try:
            if type(document) is not dict:
                raise InvalidContext()
            typed = document.get("schema") == "cryptalis.context/v2"
            prefix = document.get('schema') == 'cryptalis.context/v3'
            members = (_DESCRIPTOR_MEMBERS - {"text_codec"}) | {"value_codec"} if typed else _DESCRIPTOR_MEMBERS
            if prefix:
                members = members | {'prefix_lengths'}
            if set(document) != members:
                raise InvalidContext()
            if any(type(v) is not str or len(v) > 128 for k, v in document.items() if k != 'prefix_lengths'):
                raise InvalidContext()
            bounds = None
            if prefix:
                raw = document['prefix_lengths']
                if type(raw) is not dict or set(raw) != {'min', 'max'}:
                    raise InvalidContext()
                bounds = raw['min'], raw['max']
                if document['representation'] != _PREFIX_REPRESENTATION:
                    raise InvalidContext()
            elif document['representation'] == _PREFIX_REPRESENTATION:
                raise InvalidContext()
            codec = document["value_codec" if typed else "text_codec"]
            allowed_codecs = ("boolean-u8/v1", _DATE_CODEC, _TIMESTAMP_CODEC, _TIMESTAMPTZ_CODEC, _NUMERIC_CODEC, _JSONB_CODEC, "date-ordinal-u32/v1", "uuid-bytes16/v1", *_INTEGER_WIDTHS) if typed else ("utf8-exact/v1",)
            normalizer = ('pg-numeric-equality/v1' if codec == _NUMERIC_CODEC and
                          document['representation'] == 'cf1-packed-equality/v1' else 'identity/v1')
            json_none_as_null = None
            null_policy = 'sql-null/v1'
            if codec == _JSONB_CODEC:
                if document['null_policy'] not in _JSONB_NULL_POLICIES.values():
                    raise InvalidContext()
                json_none_as_null = document['null_policy'] == _JSONB_NULL_POLICIES[True]
                null_policy = _JSONB_NULL_POLICIES[json_none_as_null]
            if ((document["schema"], document["normalizer"], document["null_policy"]) != (
                    "cryptalis.context/v3" if prefix else "cryptalis.context/v2" if typed else "cryptalis.context/v1", normalizer, null_policy)
                    or codec not in allowed_codecs):
                raise InvalidContext()
            canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf8")
            actual = hashlib.sha256(canonical).digest()
            if type(digest) is not str or digest != actual.hex():
                raise InvalidContext()
            ids = tuple(UUID(document[name]) for name in ("domain_id", "table_id", "field_id"))
            if any(str(identity) != document[name] for identity, name in zip(ids, ("domain_id", "table_id", "field_id"))):
                raise InvalidContext()
            return cls(*ids, document["record_codec"], document["tenant_codec"], document["representation"], actual, codec, bounds, json_none_as_null)
        except Exception:
            raise InvalidContext() from None

    @property
    def equality(self):
        """Whether frames carry a search term; order terms also answer equality."""
        return self.representation != "cf1-storage/v1"

    @property
    def ordered(self):
        return self.representation == _ORDER_REPRESENTATION

    @property
    def prefixed(self):
        return self.representation == _PREFIX_REPRESENTATION

    @property
    def header_size(self):
        return (46 if self.equality else 14) + (prefix_block_size(self.prefix_lengths) if self.prefixed else 0)

    @property
    def overhead(self):
        return self.header_size + 28

    @property
    def flags(self):
        return 5 if self.prefixed else int(self.equality)

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


def _encode_value(value, field):
    if field.value_codec == _JSONB_CODEC:
        from .._jsonb import JsonbValue
        if type(value) is not JsonbValue or type(value.data) is not bytes or not 1 <= len(value.data) <= MAX_TEXT_BYTES:
            raise InvalidValue()
        return JsonbValue(value.data).data
    if field.value_codec == _NUMERIC_CODEC:
        from .._numeric import numeric_value
        return format(numeric_value(value), 'f').encode('ascii')
    if field.value_codec in (_TIMESTAMP_CODEC, _TIMESTAMPTZ_CODEC):
        if field.value_codec == _TIMESTAMPTZ_CODEC:
            from .._timestamp import aware_value
            value = aware_value(value).replace(tzinfo=None)
        elif type(value) is not datetime or value.tzinfo is not None:
            raise InvalidValue()
        delta = value - _TIMESTAMP_EPOCH
        microseconds = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        return microseconds.to_bytes(8, 'big', signed=True)
    if field.value_codec == "boolean-u8/v1":
        if type(value) is not bool:
            raise InvalidValue()
        return b"\x01" if value else b"\x00"
    if field.value_codec == 'uuid-bytes16/v1':
        if type(value) is not UUID:
            raise InvalidValue()
        return value.bytes
    if field.value_codec == 'date-ordinal-u32/v1':
        if type(value) is not date:
            raise InvalidValue()
        return value.toordinal().to_bytes(4, 'big')
    if field.value_codec == _DATE_CODEC:
        if type(value) is not date:
            raise InvalidValue()
        return (value - _DATE_EPOCH).days.to_bytes(4, 'big', signed=True)
    if field.value_codec in _INTEGER_WIDTHS:
        width = _INTEGER_WIDTHS[field.value_codec]
        bound = 1 << (8 * width - 1)
        if type(value) is not int or not -bound <= value < bound:
            raise InvalidValue()
        return value.to_bytes(width, 'big', signed=True)
    return _encode(value)


def _derive(material, info):
    c = material.context
    salt = hashlib.sha256(tuple_bytes(b"CF1/root", c.domain_id.bytes, c.tenant_id.bytes,
                                     c.root_id.bytes, c.generation.to_bytes(4, "big"))).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(material.root)


def _order_term(encoded, field, material):
    """CLWW order encoding (Chenette et al., FSE 2016) that compares as plain bytes.

    Each output byte is a keyed offset for the digits so far plus the next digit.
    Two values share every byte up to their first differing digit, where the smaller
    digit gives the smaller byte. No modular wrap occurs, so bytea order equals value
    order. A fixed 32 bytes keeps the frame layout and index of an equality term.
    int8 uses 2-bit digits to fit; narrower types use single bits.
    """
    key = _derive(material, tuple_bytes(b"CF1/search-key", field.field_id.bytes, field.value_codec.encode("ascii"),
                                        b"identity/v1", b"order"))
    width = 8 * len(encoded)
    # Flipping the sign bit makes two's complement compare as unsigned.
    number = int.from_bytes(encoded, "big") ^ (1 << (width - 1))
    bits = 2 if width == 64 else 1
    digits = width // bits
    prefix = bytearray()
    term = bytearray()
    for position in range(digits):
        digit = (number >> (bits * (digits - 1 - position))) & ((1 << bits) - 1)
        offset = int.from_bytes(hmac_digest(key, tuple_bytes(b"order", bytes(prefix)), "sha256")[:8], "big")
        term.append(offset % (257 - (1 << bits)) + digit)
        prefix.append(digit)
    return bytes(term).ljust(32, b"\x00")


def _term(encoded, field, material):
    if field.ordered:
        return _order_term(encoded, field, material)
    codec, normalizer = b'utf8-exact/v1', b'identity/v1'
    if field.value_codec == _NUMERIC_CODEC:
        from .._numeric import numeric_search_bytes
        if not 1 <= len(encoded) <= 147457:
            raise InvalidValue()
        try:
            encoded = numeric_search_bytes(Decimal(encoded.decode('ascii')))
        except (UnicodeError, ValueError, InvalidOperation):
            raise InvalidValue() from None
        codec, normalizer = _NUMERIC_CODEC.encode('ascii'), b'pg-numeric-equality/v1'
    key = _derive(material, tuple_bytes(b"CF1/search-key", field.field_id.bytes,
                                       codec, normalizer, b"equality"))
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(tuple_bytes(b"equality", encoded))
    return mac.finalize()


def _search_material(field, tenant, keys):
    if not isinstance(field, FieldDescriptor) or not field.equality or not isinstance(keys, PreparedKeys):
        raise InvalidContext()
    if field.prefixed:
        from .._search_layout import require_prefix_qualification
        require_prefix_qualification()
    _native_uuid(tenant)
    if (field.domain_id, tenant) != (keys.policy.domain_id, keys.policy.tenant_id):
        raise KeyUnavailable()
    if field.tenant_codec == "single-tenant-uuid/v1" and tenant != field.table_id:
        raise InvalidContext()
    generation = keys.policy.search_generation
    material = keys._resolve(field.domain_id, tenant, "search", generation)
    return generation, material


def equality_term(value: str | None, field: FieldDescriptor, tenant: UUID,
                  keys: PreparedKeys) -> bytes | None:
    """Prepare a query term with the same frozen composition as a CF1 header."""
    generation, material = _search_material(field, tenant, keys)
    result = None if value is None else _term(_encode_value(value, field), field, material)
    keys._resolve(field.domain_id, tenant, "search", generation)
    return result


def _prefix_key(field, material):
    return _derive(material, tuple_bytes(b'CF1/search-key', field.field_id.bytes,
        b'utf8-exact/v1', b'utf8-prefix/v1', b'prefix'))


def _prefix_mac(encoded, key):
    return hmac_digest(key, tuple_bytes(b'prefix', encoded), 'sha256').hex()


def _prefix_block(encoded, field, material):
    try:
        value = encoded.decode('utf8', errors='strict')
    except UnicodeError:
        raise InvalidText() from None
    lower, upper = field.prefix_lengths
    key = _prefix_key(field, material)
    terms = [_term(encoded, field, material).hex()]
    terms.extend(_prefix_mac(value[:length].encode('utf8'), key)
                 for length in range(lower, min(len(value), upper) + 1))
    terms.extend(['~' * 64] * (upper - lower + 2 - len(terms)))
    return ','.join(sorted(terms)).encode('ascii')


def prefix_query_terms(value, kind, field, tenant, keys):
    """Exact, prefix and universal LIKE terms; NULL remains SQL NULL."""
    if not isinstance(field, FieldDescriptor) or not field.prefixed:
        raise InvalidContext()
    generation, material = _search_material(field, tenant, keys)
    if value is None:
        result = None
    else:
        encoded = _encode(value)
        if kind == 'exact':
            result = [_term(encoded, field, material).hex()]
        elif kind == 'all' and value == '':
            result = []
        elif kind == 'prefix' and field.prefix_lengths[0] <= len(value) <= field.prefix_lengths[1]:
            result = [_prefix_mac(encoded, _prefix_key(field, material))]
        else:
            raise InvalidValue()
    keys._resolve(field.domain_id, tenant, 'search', generation)
    return result


def _context(field, tenant, record, keys):
    if not isinstance(field, FieldDescriptor) or not isinstance(keys, PreparedKeys):
        raise InvalidContext()
    if field.prefixed:
        from .._search_layout import require_prefix_qualification
        require_prefix_qualification()
    typed = field._record(tenant, record)
    if (field.domain_id, tenant) != (keys.policy.domain_id, keys.policy.tenant_id):
        raise KeyUnavailable()
    return typed


def _aad(field, tenant, record, header):
    return tuple_bytes(b"CF1/payload", field.domain_id.bytes, tenant.bytes, field.field_id.bytes,
                       record, field.digest, header)


def seal_value(value: str | bool | int | date | datetime | Decimal | UUID | None, field: FieldDescriptor, tenant: UUID,
              record: UUID | int, keys: PreparedKeys) -> bytes | None:
    """Seal the pinned value codec with active keys and a fresh OS nonce."""
    typed = _context(field, tenant, record, keys)
    payload_generation = keys.policy.payload_generation
    payload = keys._resolve(field.domain_id, tenant, "payload", payload_generation)
    if value is None:
        return None
    encoded = _encode_value(value, field)
    search_generation = 0
    term = b""
    if field.equality:
        search_generation = keys.policy.search_generation
        search = keys._resolve(field.domain_id, tenant, "search", search_generation)
        term = _term(encoded, field, search)
    header = (_MAGIC + bytes([field.flags]) + payload_generation.to_bytes(4, "big") +
              search_generation.to_bytes(4, "big") + term)
    if field.prefixed:
        header += _prefix_block(encoded, field, search)
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


def open_value(frame: bytes | None, field: FieldDescriptor, tenant: UUID,
               record: UUID | int, keys: PreparedKeys) -> str | bool | int | date | datetime | Decimal | UUID | None:
    """Authenticate before decode or release. Header IDs cannot select custody."""
    typed = _context(field, tenant, record, keys)
    if frame is None:
        keys._resolve(field.domain_id, tenant, "payload", keys.policy.payload_generation)
        return None
    header_size, overhead = field.header_size, field.overhead
    if type(frame) is not bytes or not overhead <= len(frame) <= MAX_TEXT_BYTES + overhead:
        raise InvalidFrame()
    if frame[:5] != _MAGIC or frame[5] not in (0, 1, 5):
        raise InvalidFrame()
    if frame[5] != field.flags:
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
    if field.prefixed and not compare_digest(header[46:], _prefix_block(encoded, field, search)):
        raise RepresentationMismatch()
    if field.value_codec == _JSONB_CODEC:
        from .._jsonb import JsonbValue
        value = JsonbValue(encoded)
    elif field.value_codec == "boolean-u8/v1":
        if encoded not in (b"\x00", b"\x01"):
            raise InvalidValue()
        value = encoded == b"\x01"
    elif field.value_codec == 'uuid-bytes16/v1':
        if len(encoded) != 16:
            raise InvalidValue()
        value = UUID(bytes=encoded)
    elif field.value_codec == 'date-ordinal-u32/v1':
        if len(encoded) != 4:
            raise InvalidValue()
        try:
            value = date.fromordinal(int.from_bytes(encoded, 'big'))
        except (ValueError, OverflowError):
            raise InvalidValue() from None
    elif field.value_codec == _DATE_CODEC:
        if len(encoded) != 4:
            raise InvalidValue()
        try:
            value = _DATE_EPOCH + timedelta(days=int.from_bytes(encoded, 'big', signed=True))
        except OverflowError:
            raise InvalidValue() from None
    elif field.value_codec == _NUMERIC_CODEC:
        from .._numeric import numeric_value
        try:
            if not 1 <= len(encoded) <= 147457:
                raise InvalidValue()
            raw = encoded.decode('ascii')
            value = numeric_value(Decimal(raw))
            if format(value, 'f') != raw:
                raise InvalidValue()
        except (UnicodeError, ValueError, InvalidOperation):
            raise InvalidValue() from None
    elif field.value_codec in (_TIMESTAMP_CODEC, _TIMESTAMPTZ_CODEC):
        if len(encoded) != 8:
            raise InvalidValue()
        try:
            value = _TIMESTAMP_EPOCH + timedelta(microseconds=int.from_bytes(encoded, 'big', signed=True))
            if field.value_codec == _TIMESTAMPTZ_CODEC:
                value = value.replace(tzinfo=timezone.utc)
        except OverflowError:
            raise InvalidValue() from None
    elif field.value_codec in _INTEGER_WIDTHS:
        if len(encoded) != _INTEGER_WIDTHS[field.value_codec]:
            raise InvalidValue()
        value = int.from_bytes(encoded, 'big', signed=True)
    else:
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


def seal_text(value: str | None, field: FieldDescriptor, tenant: UUID,
              record: UUID | int, keys: PreparedKeys) -> bytes | None:
    """Retain the exact text contract through the shared authenticated codec."""
    if not isinstance(field, FieldDescriptor) or field.value_codec != "utf8-exact/v1":
        raise InvalidContext()
    return seal_value(value, field, tenant, record, keys)


def open_text(frame: bytes | None, field: FieldDescriptor, tenant: UUID,
              record: UUID | int, keys: PreparedKeys) -> str | None:
    """Authenticate and release only the existing exact text codec."""
    if not isinstance(field, FieldDescriptor) or field.value_codec != "utf8-exact/v1":
        raise InvalidContext()
    return open_value(frame, field, tenant, record, keys)
