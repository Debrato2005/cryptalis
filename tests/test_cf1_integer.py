"""Signed integer codecs retain CF1 authentication and exact native widths."""
import hashlib
import json
import os
import struct
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptalis.crypto import cf1
from cryptalis.crypto.keys import AuthenticationFailed, CryptoFailure, InvalidContext
from test_cf1 import DOMAIN, TABLE, FIELD, TENANT, RECORD, setup_keys


def document(bits):
    return dict(schema='cryptalis.context/v2', domain_id=str(DOMAIN), table_id=str(TABLE), field_id=str(FIELD),
        value_codec='pg-int' + str(bits // 8) + '-be/v1', normalizer='identity/v1', null_policy='sql-null/v1',
        record_codec='uuid16/v1', tenant_codec='uuid16/v1', representation='cf1-storage/v1')


def descriptor(doc):
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return cf1.FieldDescriptor.from_compiled(doc, digest)


def independent_frame(raw, field, nonce):
    # Literal framing and public fixture roots avoid the production codec/KDF helpers.
    def tuple_bytes(*parts):
        return len(parts).to_bytes(4, 'big') + b''.join(len(part).to_bytes(4, 'big') + part for part in parts)
    salt = hashlib.sha256(tuple_bytes(b'CF1/root', DOMAIN.bytes, TENANT.bytes, UUID(int=6).bytes, b'\0\0\0\1')).digest()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
        info=tuple_bytes(b'CF1/payload-key', FIELD.bytes, RECORD.bytes)).derive(bytes(range(32)))
    header = b'CF1\0\1\0\0\0\0\1\0\0\0\0'
    aad = tuple_bytes(b'CF1/payload', DOMAIN.bytes, TENANT.bytes, FIELD.bytes, RECORD.bytes, field.digest, header)
    return header + nonce + AESGCMSIV(key).encrypt(nonce, raw, aad)


@pytest.mark.parametrize('bits,fmt', [(16, '>h'), (32, '>i'), (64, '>q')])
def test_independent_signed_integer_frames_types_null_bounds_and_context(bits, fmt, monkeypatch):
    field = descriptor(document(bits))
    _, ring = setup_keys()
    material = ring.prepare()
    nonce = bytes(range(12))
    monkeypatch.setattr(os, 'urandom', lambda length: nonce if length == 12 else bytes(length))
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    for value in (lower, -1, 0, 1, upper):
        frame = independent_frame(struct.pack(fmt, value), field, nonce)
        assert len(frame) == 42 + bits // 8
        assert cf1.seal_value(value, field, TENANT, RECORD, material) == frame
        opened = cf1.open_value(frame, field, TENANT, RECORD, material)
        assert opened == value and type(opened) is int
        with pytest.raises(AuthenticationFailed):
            cf1.open_value(frame, field, TENANT, UUID(int=99), material)
        altered = frame[:-1] + bytes([frame[-1] ^ 1])
        with pytest.raises(CryptoFailure):
            cf1.open_value(altered, field, TENANT, RECORD, material)
    assert cf1.seal_value(None, field, TENANT, RECORD, material) is None
    assert cf1.open_value(None, field, TENANT, RECORD, material) is None
    class CustomInt(int): pass
    for invalid in (lower - 1, upper + 1, True, False, 1.0, '1', b'1', CustomInt(1)):
        with pytest.raises(CryptoFailure) as refused:
            cf1.seal_value(invalid, field, TENANT, RECORD, material)
        assert refused.value.code == 'InvalidValue'
    for width in (0, bits // 8 - 1, bits // 8 + 1):
        frame = independent_frame(b'\0' * width, field, nonce)
        with pytest.raises(CryptoFailure) as refused:
            cf1.open_value(frame, field, TENANT, RECORD, material)
        assert refused.value.code == 'InvalidValue'
    other = descriptor(document(32 if bits != 32 else 16))
    frame = independent_frame(struct.pack(fmt, 1), field, nonce)
    with pytest.raises(AuthenticationFailed):
        cf1.open_value(frame, other, TENANT, RECORD, material)
    with pytest.raises(InvalidContext):
        cf1.open_text(frame, field, TENANT, RECORD, material)
    changed = dict(document(bits), representation='cf1-packed-equality/v1')
    with pytest.raises(InvalidContext): descriptor(changed)
