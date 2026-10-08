"""Offline CF1 research vectors and mutation tests. No audited/runtime claim."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'CF1\x00'
U32 = lambda value: struct.pack('>I', value)
I64 = lambda value: struct.pack('>q', value)
DOMAIN = bytes.fromhex('00112233445566778899aabbccddeeff')
TENANT = bytes.fromhex('11112233445566778899aabbccddeeff')
FIELD = bytes.fromhex('22112233445566778899aabbccddeeff')
ROOT_ID = bytes.fromhex('33112233445566778899aabbccddeeff')
SEARCH_ID = bytes.fromhex('44112233445566778899aabbccddeeff')
SEARCH_DOMAIN = bytes.fromhex('55112233445566778899aabbccddeeff')
REPRESENTATION = bytes.fromhex('66112233445566778899aabbccddeeff')
ROOTS = {1: bytes(range(32)), 2: bytes(range(32,64))}  # Public synthetic lab roots.
SEARCH_ROOTS = {1: bytes(range(31,-1,-1)), 2: bytes(range(63,31,-1))}


class FrameRejected(ValueError):
    pass


class KeyUnavailable(ValueError):
    pass


def t(*parts):
    if any(not isinstance(value, bytes) for value in parts):
        raise FrameRejected('Exact byte components required')
    return U32(len(parts)) + b''.join(U32(len(value)) + value for value in parts)


def descriptor():
    # Narrow proposed text fixture descriptor. Other SQL codecs are unqualified.
    return t(b'CF1/descriptor', b'utf8-text', U32(1024), b'SQL_NULL', b'pg:C:UTF8:exact')


def derive(root, root_id, generation, info, tenant=TENANT):
    salt = hashlib.sha256(t(b'CF1/root', DOMAIN, tenant, root_id, U32(generation))).digest()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(root)


def payload_key(generation, field, record, tenant):
    if generation not in ROOTS:
        raise KeyUnavailable('Payload generation unavailable')
    return derive(ROOTS[generation], ROOT_ID, generation,
                  t(b'CF1/payload-key', field, t(b'int64', I64(record))), tenant)


def term(value, generation, capability=b'equality', tenant=TENANT, field=FIELD):
    if generation not in SEARCH_ROOTS:
        raise KeyUnavailable('Search generation unavailable')
    search_domain = SEARCH_DOMAIN if capability == b'equality' else field
    key = derive(SEARCH_ROOTS[generation], SEARCH_ID, generation,
                 t(b'CF1/search-key', search_domain, b'utf8-text', b'exact', capability), tenant)
    return hmac.digest(key, t(capability, value.encode('utf-8')), 'sha256')


def prefixes(value, generation, tenant=TENANT, field=FIELD):
    return sorted({term(value[:end], generation, b'prefix', tenant, field) for end in range(len(value)+1)})


def commitment(companions):
    entries = []
    for capability in sorted(companions):
        values = companions[capability]
        if not values or len(values) != len(set(values)) or any(len(value) != 32 for value in values):
            raise FrameRejected('Malformed companion terms')
        entries.append(t(capability, REPRESENTATION, t(*sorted(values))))
    return hashlib.sha256(t(b'CF1/companions', *entries)).digest()


def aad(header, field, record, tenant):
    return t(b'CF1/payload', DOMAIN, tenant, field, t(b'int64', I64(record)),
             hashlib.sha256(descriptor()).digest(), header)


def seal(value, record, *, equality=False, prefix=False, payload_generation=1, search_generation=1,
         tenant=TENANT, field=FIELD, vector_nonce=None):
    if type(value) is not str or '\x00' in value or len(value.encode('utf-8')) > 1024:
        raise FrameRejected('Fixture text contract exceeded')
    companions = {b'prefix': prefixes(value, search_generation, tenant, field)} if prefix else {}
    flags = int(equality) | (2 if companions else 0)
    generation = search_generation if flags else 0
    header = MAGIC + bytes((1, flags)) + U32(payload_generation) + U32(generation)
    if equality:
        header += term(value, search_generation, tenant=tenant, field=field)
    if companions:
        header += commitment(companions)
    nonce = os.urandom(12) if vector_nonce is None else vector_nonce
    if len(nonce) != 12:
        raise FrameRejected('Invalid nonce size')
    sealed = AESGCMSIV(payload_key(payload_generation, field, record, tenant)).encrypt(
        nonce, value.encode('utf-8'), aad(header, field, record, tenant))
    return header + nonce + sealed, companions


def open_frame(frame, record, companions, *, tenant=TENANT, field=FIELD, admitted=(1,2), admitted_search=(1,2)):
    if len(frame) < 42 or len(frame) > 1130 or frame[:4] != MAGIC or frame[4] != 1:
        raise FrameRejected('Malformed/unknown frame')
    flags = frame[5]
    if flags & ~3:
        raise FrameRejected('Unknown flags')
    generation, search_generation = struct.unpack('>II', frame[6:14])
    if generation == 0 or generation not in admitted:
        raise KeyUnavailable('Payload generation not admitted')
    if bool(flags) != bool(search_generation) or (search_generation and (search_generation not in SEARCH_ROOTS or search_generation not in admitted_search)):
        raise KeyUnavailable('Search generation unavailable')
    end = 14 + (32 if flags & 1 else 0) + (32 if flags & 2 else 0)
    if len(frame) < end + 28:
        raise FrameRejected('Truncated frame')
    header = frame[:end]
    if flags & 2:
        expected = header[-32:]
        if not hmac.compare_digest(expected, commitment(companions)):
            raise FrameRejected('Companion commitment mismatch')
    elif companions:
        raise FrameRejected('Unexpected companion representation')
    value = AESGCMSIV(payload_key(generation, field, record, tenant)).decrypt(
        frame[end:end+12], frame[end+12:], aad(header, field, record, tenant)).decode('utf-8')
    if '\x00' in value or len(value.encode('utf-8')) > 1024:
        raise FrameRejected('Fixture text contract exceeded')
    if flags & 1 and not hmac.compare_digest(header[14:46], term(value, search_generation, tenant=tenant, field=field)):
        raise FrameRejected('Equality representation mismatch')
    if flags & 2 and {key: sorted(values) for key,values in companions.items()} != {b'prefix': prefixes(value, search_generation, tenant, field)}:
        raise FrameRejected('Derived companion mismatch')
    return value


def main():
    outcomes = {}
    def check(name, result):
        assert result, name
        outcomes[name] = 'PASS'
    def rejected(name, work, classes=(FrameRejected, KeyUnavailable, InvalidTag)):
        try:
            work()
        except classes:
            outcomes[name] = 'PASS'
        else:
            raise AssertionError(name)
    check('independent_T_encoding_vector', t(b'A', 'é'.encode()).hex() == '00000002000000014100000002c3a9')
    vectors = []
    for equality, prefix in ((False,False),(True,False),(False,True),(True,True)):
        frame, companions = seal('Déb', 42, equality=equality, prefix=prefix, vector_nonce=bytes(range(12)))
        check(f'roundtrip_{int(equality)}_{int(prefix)}', open_frame(frame,42,companions) == 'Déb')
        check(f'exact_overhead_{int(equality)}_{int(prefix)}', len(frame)-len('Déb'.encode()) == 42+32*int(equality)+32*int(prefix))
        vectors.append({'equality':equality,'prefix':prefix,'frame_hex':frame.hex(),
                        'companions':{key.decode():[value.hex() for value in values] for key,values in companions.items()}})
    frame, companions = seal('current-data',42,equality=True,prefix=True)
    for label, field, tenant, record in (('wrong_field',bytes(16),TENANT,42),('wrong_tenant',FIELD,bytes(16),42),('wrong_record',FIELD,TENANT,43)):
        rejected(label, lambda field=field,tenant=tenant,record=record:open_frame(frame,record,companions,field=field,tenant=tenant))
    damaged = frame[:-1]+bytes((frame[-1]^1,))
    rejected('payload_tamper',lambda:open_frame(damaged,42,companions))
    malformed = bytearray(frame);malformed[5]|=128
    rejected('unknown_flags',lambda:open_frame(bytes(malformed),42,companions))
    rejected('truncation',lambda:open_frame(frame[:20],42,companions))
    rejected('retired_generation',lambda:open_frame(frame,42,companions,admitted=(2,)))
    rejected('retired_search_generation',lambda:open_frame(frame,42,companions,admitted_search=(2,)))
    reordered={key:list(reversed(values)) for key,values in companions.items()}
    check('companion_set_order_preserved',open_frame(frame,42,reordered)=='current-data')
    other_tenant, other_terms=seal('current-data',42,equality=True,prefix=True,tenant=bytes(16))
    check('tenant_search_domains_separated',other_tenant[14:46]!=frame[14:46] and other_terms!=companions and open_frame(other_tenant,42,other_terms,tenant=bytes(16))=='current-data')
    other_field, other_field_terms=seal('current-data',42,equality=True,prefix=True,field=bytes(16))
    check('explicit_equality_join_prefix_field_scope',other_field[14:46]==frame[14:46] and other_field_terms!=companions and open_frame(other_field,42,other_field_terms,field=bytes(16))=='current-data')
    wrong = {b'prefix': [bytes(32)]}
    rejected('returned_companion_tamper',lambda:open_frame(frame,42,wrong))
    reindexed, new_companions = seal('current-data',42,equality=True,prefix=True,search_generation=2)
    check('search_rotation_reseals_current_payload',open_frame(reindexed,42,new_companions)=='current-data' and reindexed!=frame)
    rejected('old_header_new_companions',lambda:open_frame(frame,42,new_companions))
    rejected('new_header_old_companions',lambda:open_frame(reindexed,42,companions))
    no_prefix, empty = seal('current-data',42,equality=True,prefix=False)
    check('remove_capability_reseals',open_frame(no_prefix,42,empty)=='current-data' and no_prefix!=frame)
    rejected('removed_header_old_companions',lambda:open_frame(no_prefix,42,companions))
    rotated, retained = seal('current-data',42,equality=True,prefix=True,payload_generation=2)
    check('payload_rotation_keeps_search_terms',retained==companions and rotated[14:46]==frame[14:46] and open_frame(rotated,42,retained)=='current-data')
    rejected('NUL_text_rejected',lambda:seal('bad\x00text',42))
    rejected('oversized_fixture_text_rejected',lambda:seal('x'*1025,42))
    check('empty_nonnull_text',open_frame(*_open_arguments(seal('',42),42))=='')
    result = {'cell':'offline CF1 synthetic text profile','outcomes':outcomes,'vectors':vectors,
              'limits':['Same AEAD library seals/opens; no independent AEAD implementation comparison',
                        'Fixture descriptor/keys are public lab choices, not qualified generic SQL codecs',
                        'No provider, ORM, PostgreSQL, NULL presence authentication, or usage-bound proof',
                        'Search collision detection and hostile completeness remain absent',
                        'Vector-only fixed nonces are not the runtime RNG rule']}
    Path(__file__).with_name('results').joinpath('cf1.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':len(outcomes),'independent_vector':'T bytes only','crypto_review':'NOT_DONE'}))


def _open_arguments(sealed, record):
    frame, companions = sealed
    return frame, record, companions


if __name__=='__main__':
    main()
