"""Independent CF1 bytes, exact reader custody and bounded search transforms."""
import hashlib
import hmac
import importlib
import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis.crypto import Keyring, open_text
from cryptalis.crypto.cf1 import FieldDescriptor
from reference_cf1_vectors import encrypt, hkdf, tuple_bytes
from search_rotation_worker import target_keys
from test_migration import DOMAIN, TABLE_ID, FIELD_ID, TENANT, keys


def prepare(rows, field, tenant, source, target, **limits):
    return importlib.import_module('cryptalis.crypto._search_rotation').prepare_search_rotation_batch(
        rows, field, tenant, source=source, target=target, **limits)


def fixture(*, equality=True, codec='uuid16/v1', max_age=60):
    descriptor = dict(schema='cryptalis.context/v1', domain_id=str(DOMAIN), table_id=str(TABLE_ID),
        field_id=str(FIELD_ID), text_codec='utf8-exact/v1', normalizer='identity/v1',
        null_policy='sql-null/v1', record_codec=codec, tenant_codec='uuid16/v1',
        representation='cf1-packed-equality/v1' if equality else 'cf1-storage/v1')
    digest = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    field = FieldDescriptor.from_compiled(descriptor, digest)
    original = keys(TENANT)
    source = Keyring(original.policy, original._providers, max_age=max_age)
    changed = target_keys(TENANT, source=source)
    target = Keyring(changed.policy, changed._providers, max_age=max_age)
    return SimpleNamespace(field=field, descriptor=descriptor, source=source, target=target,
                           record=101 if codec == 'int64-be/v1' else UUID(int=101))


def independent_frame(f, value, nonce, *, target):
    """Stdlib composition and RFC8452 reference AEAD, without product sealing."""
    if value is None:
        return None
    policy = (f.target if target else f.source).policy
    payload = next(w.context for w in policy.wrappers
                   if w.context.purpose == 'payload' and w.context.generation == policy.payload_generation)
    typed_record = (tuple_bytes(b'int64', f.record.to_bytes(8, 'big', signed=True))
                    if type(f.record) is int else f.record.bytes)
    encoded = value.encode('utf8')

    def derive(context, info):
        if context.purpose == 'search' and target:
            root = hashlib.sha256(b'PUBLIC SEARCH WORKER ROOT' + TENANT.bytes
                                  + context.generation.to_bytes(4, 'big')).digest()
        else:
            root = hashlib.sha256(('PUBLIC MIGRATION FIXTURE:' + str(context)).encode()).digest()
        salt = hashlib.sha256(tuple_bytes(b'CF1/root', DOMAIN.bytes, TENANT.bytes,
            context.root_id.bytes, context.generation.to_bytes(4, 'big'))).digest()
        return hkdf(root, salt, info, 32)

    term, search_generation = b'', 0
    if f.field.equality:
        search_generation = policy.search_generation
        search = next(w.context for w in policy.wrappers
                      if w.context.purpose == 'search' and w.context.generation == search_generation)
        search_key = derive(search, tuple_bytes(b'CF1/search-key', FIELD_ID.bytes,
                                               b'utf8-exact/v1', b'identity/v1', b'equality'))
        term = hmac.digest(search_key, tuple_bytes(b'equality', encoded), 'sha256')
    header = (bytes.fromhex('4346310001') + bytes([int(f.field.equality)])
              + policy.payload_generation.to_bytes(4, 'big') + search_generation.to_bytes(4, 'big') + term)
    payload_key = derive(payload, tuple_bytes(b'CF1/payload-key', FIELD_ID.bytes, typed_record))
    descriptor_digest = hashlib.sha256(json.dumps(f.descriptor, sort_keys=True,
                                                 separators=(',', ':')).encode()).digest()
    aad = tuple_bytes(b'CF1/payload', DOMAIN.bytes, TENANT.bytes, FIELD_ID.bytes,
                      typed_record, descriptor_digest, header)
    return header + nonce + encrypt(payload_key, nonce, encoded, aad)


def logical_bytes(rows, field):
    overhead = 74 if field.equality else 42
    identity = 16 + (8 if field.record_codec == 'int64-be/v1' else 16)
    return sum(identity + (0 if body is None else 3 * len(body) - overhead) for _, body in rows)


@pytest.mark.parametrize('codec', ['uuid16/v1', 'int64-be/v1'])
@pytest.mark.parametrize('equality', [False, True])
def test_exact_reference_bytes_and_unchanged_payload_generation(codec, equality):
    f = fixture(equality=equality, codec=codec)
    text, old_nonce = 'current 雪 e\u0301 😀', bytes(range(12))
    original = independent_frame(f, text, old_nonce, target=False)
    source, target = f.source.prepare(), f.target.prepare()
    assert open_text(original, f.field, TENANT, f.record, source) == text
    rows = ((f.record, original),)
    result = prepare(rows, f.field, TENANT, source, target)
    assert type(result) is tuple and result[0][0] == f.record
    transformed = result[0][1]
    assert open_text(transformed, f.field, TENANT, f.record, target) == text
    assert rows == ((f.record, original),)
    if equality:
        nonce = transformed[46:58]
        assert nonce != old_nonce
        assert transformed == independent_frame(f, text, nonce, target=True)
        assert transformed[:10] == original[:10]
        assert int.from_bytes(transformed[10:14], 'big') == 2
        assert transformed[14:46] != original[14:46]
    else:
        assert transformed == original


