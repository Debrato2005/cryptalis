"""Inactive payload transforms: independent vectors and current native values.

All roots are public fixtures. No writer policy, runtime schema or external pin
is changed. Native staging tables below are test-owned inactive observations.
"""
from dataclasses import replace
import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis.crypto import (
    DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring, open_text,
)
from cryptalis.crypto.cf1 import FieldDescriptor
from reference_cf1_vectors import encrypt, hkdf, tuple_bytes


VECTORS = json.loads((Path(__file__).parent / 'fixtures/cf1_vectors.json').read_text())['vectors']
NEW_ROOT = bytes(range(64, 96))  # PUBLIC fixture material only.
NEW_ID = UUID(int=8108)


def prepare(rows, field, tenant, source, target, **bounds):
    return importlib.import_module('cryptalis.crypto._payload_rotation').prepare_payload_rotation_batch(
        rows, field, tenant, source=source, target=target,
        max_rows=bounds.get('max_rows', 1000), max_bytes=bounds.get('max_bytes', 64 * 1024 * 1024))


def fixture(vector, *, max_age=60):
    field = FieldDescriptor.from_compiled(vector['descriptor'], vector['descriptor_digest'])
    tenant = UUID(vector['tenant_id'])
    record = vector['record_id'] if field.record_codec == 'int64-be/v1' else UUID(vector['record_id'])
    provider = DevelopmentKeyProvider()
    payload = KeyContext(field.domain_id, tenant, 'payload', UUID(vector['payload_root_id']), vector['payload_generation'])
    wrappers = [provider.wrap(bytes.fromhex(vector['payload_root']), payload)]
    if field.equality:
        search = KeyContext(field.domain_id, tenant, 'search', UUID(vector['search_root_id']), vector['search_generation'])
        wrappers.append(provider.wrap(bytes.fromhex(vector['search_root']), search))
    policy = KeyPolicy(field.domain_id, tenant, tuple(wrappers), payload.generation,
                       vector['search_generation'] or None)
    changed = replace(payload, root_id=NEW_ID, generation=payload.generation + 1)
    successor = replace(policy, wrappers=policy.wrappers + (provider.wrap(NEW_ROOT, changed),),
                        payload_generation=changed.generation)
    return SimpleNamespace(vector=vector, field=field, tenant=tenant, record=record,
        provider=provider, payload=payload, changed=changed,
        source=Keyring(policy, {provider.provider_id: provider}, max_age=max_age),
        target=Keyring(successor, {provider.provider_id: provider}, max_age=max_age))


def independent_frame(f, value, nonce, *, target):
    """Independent stdlib KDF/framing plus existing RFC8452 reference AEAD."""
    v = f.vector
    context = f.changed if target else f.payload
    root = NEW_ROOT if target else bytes.fromhex(v['payload_root'])
    record = (tuple_bytes(b'int64', f.record.to_bytes(8, 'big', signed=True))
              if type(f.record) is int else f.record.bytes)
    salt = hashlib.sha256(tuple_bytes(b'CF1/root', context.domain_id.bytes,
        context.tenant_id.bytes, context.root_id.bytes, context.generation.to_bytes(4, 'big'))).digest()
    key = hkdf(root, salt, tuple_bytes(b'CF1/payload-key', f.field.field_id.bytes, record), 32)
    header = (bytes.fromhex('4346310001') + bytes([int(f.field.equality)]) +
        context.generation.to_bytes(4, 'big') + v['search_generation'].to_bytes(4, 'big') + bytes.fromhex(v['term']))
    digest = hashlib.sha256(json.dumps(v['descriptor'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).digest()
    aad = tuple_bytes(b'CF1/payload', context.domain_id.bytes, f.tenant.bytes,
                     f.field.field_id.bytes, record, digest, header)
    return header + nonce + encrypt(key, nonce, value.encode('utf8'), aad)


def logical_bytes(rows, field):
    # Source frame + prospective target frame + decoded UTF8 + UUID tenant
    # and native record bytes. Excludes Python/driver/provider overhead.
    overhead = 74 if field.equality else 42
    identity = 16 + (8 if field.record_codec == 'int64-be/v1' else 16)
    return sum(identity + (0 if frame is None else 2 * len(frame) + len(frame) - overhead)
               for _, frame in rows)


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['name'])
def test_frozen_source_and_independent_target_vector(vector):
    f = fixture(vector)
    original = bytes.fromhex(vector['frame'])
    assert independent_frame(f, vector['text'], bytes.fromhex(vector['nonce']), target=False) == original
    source, target = f.source.prepare(), f.target.prepare()
    rows = ((f.record, original),)
    result = prepare(rows, f.field, f.tenant, source, target)
    assert type(result) is tuple and result[0][0] == f.record
    rotated = result[0][1]
    header_size = 46 if f.field.equality else 14
    nonce = rotated[header_size:header_size + 12]
    assert nonce != bytes.fromhex(vector['nonce'])
    assert rotated == independent_frame(f, vector['text'], nonce, target=True)
    assert rotated[10:header_size] == original[10:header_size]
    assert open_text(rotated, f.field, f.tenant, f.record, target) == vector['text']
    assert open_text(original, f.field, f.tenant, f.record, source) == vector['text']
    assert rows == ((f.record, original),)


