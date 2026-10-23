"""Independent CF1 bytes, exact reader custody and bounded search transforms."""
from dataclasses import replace
import hashlib
import hmac
import importlib
import json
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis.crypto import CryptoFailure, DevelopmentKeyProvider, KeyContext, Keyring, open_text, seal_text
from cryptalis.crypto.cf1 import FieldDescriptor
from cryptalis.crypto.keys import KeyUnavailable
from reference_cf1_vectors import encrypt, hkdf, tuple_bytes
from search_rotation_worker import PublicSearchProvider, TARGET_PROVIDER, target_keys
from test_migration import DOMAIN, TABLE_ID, FIELD_ID, TENANT, PROVIDER, PublicFixtureProvider, keys


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


@pytest.mark.parametrize('equality', [False, True])
def test_null_empty_unicode_and_exact_logical_budget(equality):
    f = fixture(equality=equality)
    source, target = f.source.prepare(), f.target.prepare()
    expected = (None, '', '雪😀 trailing ')
    rows = tuple((UUID(int=index), seal_text(value, f.field, TENANT, UUID(int=index), source))
                 for index, value in enumerate(expected, 1))
    budget = logical_bytes(rows, f.field)
    with pytest.raises(CryptoFailure):
        prepare(rows, f.field, TENANT, source, target, max_bytes=budget - 1)
    result = prepare(rows, f.field, TENANT, source, target, max_rows=3, max_bytes=budget)
    assert tuple(open_text(frame, f.field, TENANT, identity, target) for identity, frame in result) == expected
    assert result[0][1] is None
    if not equality:
        assert result == rows


def test_storage_only_policy_without_search_copies_authenticated_frames():
    f = fixture(equality=False)
    policy = replace(f.source.policy, search_generation=None,
                     wrappers=tuple(w for w in f.source.policy.wrappers if w.context.purpose == 'payload'))
    ring = Keyring(policy, f.source._providers)
    material = ring.prepare()
    frame = seal_text('storage without a search namespace', f.field, TENANT, f.record, material)
    rows = ((f.record, frame), (UUID(int=102), None))
    assert prepare(rows, f.field, TENANT, material, material) == rows


@pytest.mark.parametrize('fault', ['tenant', 'field', 'record', 'late_tag', 'historical_source'])
def test_wrong_context_tampering_and_retained_old_generation_produce_no_batch(fault):
    f = fixture()
    source, target = f.source.prepare(), f.target.prepare()
    frame = seal_text('first current value', f.field, TENANT, f.record, source)
    rows, field, tenant = ((f.record, frame),), f.field, TENANT
    if fault == 'tenant':
        tenant = UUID(int=7001)
    elif fault == 'field':
        field = replace(field, field_id=UUID(int=7002))
    elif fault == 'record':
        rows = ((UUID(int=7003), frame),)
    elif fault == 'late_tag':
        identity = UUID(int=102)
        second = seal_text('second current value', field, tenant, identity, source)
        rows += ((identity, second[:-1] + bytes([second[-1] ^ 1])),)
    else:
        assert open_text(frame, field, tenant, f.record, target) == 'first current value'
        source = target
        target = target_keys(TENANT, source=f.target).prepare()
    before = rows
    with pytest.raises(CryptoFailure):
        prepare(rows, field, tenant, source, target)
    assert rows == before


@pytest.mark.parametrize('fault', ['same_generation', 'dropped_reader', 'payload_generation', 'nonmonotonic_history',
    'payload_material', 'retained_search_material', 'new_search_reuses_payload', 'new_search_reuses_search'])
def test_search_rotation_cannot_change_or_reuse_retained_material(fault):
    f = fixture()
    source, target = f.source.prepare(), f.target
    frame = seal_text('retained custody proof', f.field, TENANT, f.record, source)
    providers, policy = dict(target._providers), target.policy
    if fault == 'same_generation':
        target = f.source
    elif fault == 'nonmonotonic_history':
        historical = target_keys(TENANT, generation=3, source=f.source)
        old = Keyring(replace(historical.policy, search_generation=1), historical._providers)
        source = old.prepare()
        target = target_keys(TENANT, generation=2, source=old)
    elif fault == 'dropped_reader':
        policy = replace(policy, wrappers=tuple(w for w in policy.wrappers
                         if (w.context.purpose, w.context.generation) != ('search', 1)))
    elif fault == 'payload_generation':
        provider = DevelopmentKeyProvider()
        context = KeyContext(DOMAIN, TENANT, 'payload', UUID(int=7004), 2)
        policy = replace(policy, wrappers=policy.wrappers + (provider.wrap(b'x' * 32, context),),
                         payload_generation=2)
        providers[provider.provider_id] = provider
    elif fault in ('payload_material', 'retained_search_material'):
        purpose = 'payload' if fault == 'payload_material' else 'search'
        class Changed(PublicFixtureProvider):
            def unwrap(self, wrapper, context):
                return b'y' * 32 if context.purpose == purpose else super().unwrap(wrapper, context)
        providers[PROVIDER] = Changed()
    else:
        purpose = 'payload' if fault == 'new_search_reuses_payload' else 'search'
        old = next(w for w in f.source.policy.wrappers if w.context.purpose == purpose)
        reused = PublicFixtureProvider().unwrap(old, old.context)
        class Reused(PublicSearchProvider):
            def unwrap(self, wrapper, context):
                super().unwrap(wrapper, context)
                return reused
        providers[TARGET_PROVIDER] = Reused()
    if fault not in ('same_generation', 'nonmonotonic_history'):
        target = Keyring(policy, providers)
    with pytest.raises(CryptoFailure):
        prepare(((f.record, frame),), f.field, TENANT, source, target.prepare())


@pytest.mark.parametrize('fault', ['duplicate', 'iterator', 'bool_rows', 'zero_rows',
    'large_rows', 'bool_bytes', 'zero_bytes', 'large_bytes'])
def test_invalid_batch_shapes_and_bounds_fail_without_changing_inputs(fault):
    f = fixture()
    source, target = f.source.prepare(), f.target.prepare()
    frame = seal_text('bounded input', f.field, TENANT, f.record, source)
    rows = ((f.record, frame),)
    limits = {}
    if fault == 'duplicate':
        rows += rows
    elif fault == 'iterator':
        rows = iter(rows)
    elif fault in ('bool_rows', 'zero_rows', 'large_rows'):
        limits['max_rows'] = {'bool_rows': True, 'zero_rows': 0, 'large_rows': 5001}[fault]
    else:
        limits['max_bytes'] = {'bool_bytes': True, 'zero_bytes': 0, 'large_bytes': 1024**3 + 1}[fault]
    with pytest.raises(CryptoFailure):
        prepare(rows, f.field, TENANT, source, target, **limits)
    assert open_text(frame, f.field, TENANT, f.record, source) == 'bounded input'


@pytest.mark.parametrize('which', ['source', 'target'])
@pytest.mark.parametrize('fault', ['fork', 'expiry_after_last_seal'])
def test_fork_or_expiry_cannot_release_a_completed_batch(which, fault, monkeypatch):
    import cryptalis.crypto.keys as key_module
    now = [100.0]
    monkeypatch.setattr(key_module, 'time', SimpleNamespace(
        monotonic=lambda: now[0], monotonic_ns=lambda: int(now[0] * 1e9)))
    f = fixture(max_age=10)
    first = (f.source if which == 'source' else f.target).prepare()
    now[0] = 105.0
    second = (f.target if which == 'source' else f.source).prepare()
    source, target = (first, second) if which == 'source' else (second, first)
    rows = tuple((UUID(int=index), seal_text('current-' + str(index), f.field, TENANT,
                 UUID(int=index), source)) for index in (1, 2))
    if fault == 'fork':
        if which == 'source':
            source = replace(source, _pid=-1)
        else:
            target = replace(target, _pid=-1)
    else:
        module = importlib.import_module('cryptalis.crypto._search_rotation')
        actual = module.seal_value
        calls = []
        def expire_after_second(*args, **kwargs):
            result = actual(*args, **kwargs)
            calls.append(True)
            if len(calls) == 2:
                now[0] = 110.0
            return result
        monkeypatch.setattr(module, 'seal_value', expire_after_second)
    before = rows
    with pytest.raises(KeyUnavailable):
        prepare(rows, f.field, TENANT, source, target)
    assert rows == before
