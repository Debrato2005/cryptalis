"""Inactive bounded CF1 payload preparation, without publication authority.

No SQL, provider calls, policy installation, mutation of inputs, or new format.
The caller must integrate complete results into an approved journaled lifecycle
before any database switch. Historical readers and current authority are separate.
"""
from hmac import compare_digest

from .cf1 import FieldDescriptor, MAX_TEXT_BYTES, open_text, seal_text
from .keys import InvalidContext, InvalidFrame, KeyUnavailable, PreparedKeys, RepresentationMismatch


MAX_BATCH_ROWS = 5000
MAX_BATCH_BYTES = 1024 ** 3


def _binding(field, tenant, source, target):
    if (not isinstance(field, FieldDescriptor) or
            not isinstance(source, PreparedKeys) or not isinstance(target, PreparedKeys)):
        raise InvalidContext()
    if ((source.policy.domain_id, source.policy.tenant_id) != (field.domain_id, tenant) or
            (target.policy.domain_id, target.policy.tenant_id) != (field.domain_id, tenant)):
        raise KeyUnavailable()
    old, new = source.policy.payload_generation, target.policy.payload_generation
    if old == new or source.policy.search_generation != target.policy.search_generation:
        raise InvalidContext()
    # _resolve retains the existing per-use lease and originating-process check.
    old_payload = source._resolve(field.domain_id, tenant, 'payload', old)
    new_payload = target._resolve(field.domain_id, tenant, 'payload', new)
    if (old_payload.context.root_id == new_payload.context.root_id or
            compare_digest(old_payload.root, new_payload.root)):
        raise InvalidContext()
    generation = source.policy.search_generation
    if field.equality and generation is None:
        raise InvalidContext()
    if generation is not None:
        old_search = source._resolve(field.domain_id, tenant, 'search', generation)
        new_search = target._resolve(field.domain_id, tenant, 'search', generation)
        if (old_search.context != new_search.context or
                not compare_digest(old_search.root, new_search.root)):
            raise InvalidContext()


def prepare_payload_rotation_batch(rows, field, tenant, *, source, target,
                                   max_rows=1000, max_bytes=64 * 1024 * 1024):
    """Return the complete immutable inactive batch, or raise without a batch.

One field/tenant per call; identities and current source frames are immutable.
The selected source generation is exact, not any retained reader generation.
Source + target frames + decoded UTF8 + native identities form the logical byte
budget. Object/allocator/provider/driver overhead is outside that budget.
"""
    if (type(rows) is not tuple or type(max_rows) is not int or
            not 1 <= max_rows <= MAX_BATCH_ROWS or len(rows) > max_rows or
            type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BATCH_BYTES):
        raise InvalidContext()
    _binding(field, tenant, source, target)
    overhead = 74 if field.equality else 42
    identity_bytes = 16 + (8 if field.record_codec == 'int64-be/v1' else 16)
    budget = 0
    seen = set()
    for row in rows:
        if type(row) is not tuple or len(row) != 2:
            raise InvalidContext()
        record, frame = row
        typed_record = field._record(tenant, record)
        if typed_record in seen:
            raise InvalidContext()
        seen.add(typed_record)
        budget += identity_bytes
        if frame is not None:
            if type(frame) is not bytes or not overhead <= len(frame) <= MAX_TEXT_BYTES + overhead:
                raise InvalidFrame()
            # Same representation and exact text imply the same output size.
            budget += 2 * len(frame) + len(frame) - overhead
        if budget > max_bytes:
            raise InvalidContext()

    result = []
    header_size = 46 if field.equality else 14
    for record, frame in rows:
        if frame is not None and (
                int.from_bytes(frame[6:10], 'big') != source.policy.payload_generation or
                int.from_bytes(frame[10:14], 'big') != (source.policy.search_generation if field.equality else 0)):
            raise RepresentationMismatch()
        value = open_text(frame, field, tenant, record, source)
        transformed = seal_text(value, field, tenant, record, target)
        if frame is None:
            if transformed is not None:
                raise RepresentationMismatch()
        elif (type(transformed) is not bytes or len(transformed) != len(frame) or
                transformed[:6] != frame[:6] or
                int.from_bytes(transformed[6:10], 'big') != target.policy.payload_generation or
                transformed[10:header_size] != frame[10:header_size]):
            raise RepresentationMismatch()
        result.append((record, transformed))
    # No prefix is exposed as a generator. A source/target lease which expired
    # during later work cannot yield an earlier prepared successful batch.
    _binding(field, tenant, source, target)
    return tuple(result)
