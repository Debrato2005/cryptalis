"""Typed Boolean values share authenticated CF1 composition without text coercion."""
import json
import os
from pathlib import Path
from uuid import UUID

import pytest

from cryptalis.crypto import cf1
from cryptalis.crypto.keys import (AuthenticationFailed, CryptoFailure, DevelopmentKeyProvider,
    InvalidContext, KeyContext, KeyPolicy, Keyring)

VECTORS = json.loads((Path(__file__).parent / 'fixtures/cf1_boolean_vectors.json').read_text())


def prepared(vector):
    doc = vector['descriptor']
    domain, tenant = UUID(doc['domain_id']), UUID(vector['tenant_id'])
    provider = DevelopmentKeyProvider()
    context = KeyContext(domain, tenant, 'payload', UUID(vector['payload_root_id']), vector['payload_generation'])
    wrapper = provider.wrap(bytes.fromhex(vector['payload_root']), context)
    return Keyring(KeyPolicy(domain, tenant, (wrapper,), context.generation),
                   {provider.provider_id: provider}).prepare()


@pytest.mark.parametrize('vector', VECTORS['vectors'], ids=lambda value: value['name'])
def test_independent_boolean_vectors_retain_native_bool_and_type_binding(vector, monkeypatch):
    field = cf1.FieldDescriptor.from_compiled(vector['descriptor'], vector['descriptor_digest'])
    tenant = UUID(vector['tenant_id'])
    record = UUID(vector['record_id']) if field.record_codec == 'uuid16/v1' else vector['record_id']
    keys, frozen = prepared(vector), bytes.fromhex(vector['frame'])
    assert cf1.open_value(frozen, field, tenant, record, keys) is vector['value']
    monkeypatch.setattr(os, 'urandom', lambda size: bytes.fromhex(vector['nonce']) if size == 12 else bytes(size))
    assert cf1.seal_value(vector['value'], field, tenant, record, keys) == frozen
    assert cf1.open_value(None, field, tenant, record, keys) is None
    assert cf1.seal_value(None, field, tenant, record, keys) is None
    with pytest.raises(InvalidContext):
        cf1.seal_text(vector['value'], field, tenant, record, keys)
    with pytest.raises(InvalidContext):
        cf1.open_text(frozen, field, tenant, record, keys)
    changed = dict(vector['descriptor'], schema='cryptalis.context/v1', text_codec='utf8-exact/v1')
    del changed['value_codec']
    import hashlib
    text = cf1.FieldDescriptor.from_compiled(changed,
        hashlib.sha256(json.dumps(changed, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
    with pytest.raises(AuthenticationFailed):
        cf1.open_value(frozen, text, tenant, record, keys)
    with pytest.raises(CryptoFailure):
        cf1.open_value(frozen[:-1] + bytes([frozen[-1] ^ 1]), field, tenant, record, keys)
    for value in (0, 1, 0.0, 1.0, '', 'false', b'\x00'):
        with pytest.raises(CryptoFailure) as refused:
            cf1.seal_value(value, field, tenant, record, keys)
        assert refused.value.code == 'InvalidValue'


def test_authenticated_invalid_boolean_byte_is_refused_after_authentication():
    vector = VECTORS['malformed']
    field = cf1.FieldDescriptor.from_compiled(vector['descriptor'], vector['descriptor_digest'])
    record = UUID(vector['record_id']) if field.record_codec == 'uuid16/v1' else vector['record_id']
    with pytest.raises(CryptoFailure) as refused:
        cf1.open_value(bytes.fromhex(vector['frame']), field, UUID(vector['tenant_id']), record, prepared(vector))
    assert refused.value.code == 'InvalidValue'


@pytest.mark.parametrize('change', [
    {'schema': 'cryptalis.context/v1'}, {'schema': 'cryptalis.context/v3'},
    {'value_codec': 'utf8-exact/v1'}, {'value_codec': 'boolean-u8/v2'},
    {'text_codec': 'utf8-exact/v1'}, {'normalizer': 'truthiness/v1'},
    {'representation': 'cf1-packed-equality/v1'}, {'null_policy': 'false-is-null/v1'},
])
def test_boolean_descriptor_refuses_unknown_mixed_or_searchable_contracts(change):
    import hashlib
    document = dict(VECTORS['vectors'][0]['descriptor'], **change)
    digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    with pytest.raises(InvalidContext):
        cf1.FieldDescriptor.from_compiled(document, digest)
