"""Public Boolean CF1 fixtures from the existing independent RFC8452 reference."""
import hashlib
import json
from pathlib import Path
import sys

from reference_cf1_vectors import encrypt, hkdf, tuple_bytes, verify_published_vectors

FIXTURE = Path(__file__).parent / 'fixtures' / 'cf1_boolean_vectors.json'


def generate():
    primitive_vectors = verify_published_vectors()
    old = json.loads((FIXTURE.parent / 'cf1_vectors.json').read_text())
    vectors = []
    for source in old['vectors']:
        if source['search_generation']:
            continue
        for value in (False, True):
            descriptor = dict(source['descriptor'])
            descriptor['schema'] = 'cryptalis.context/v2'
            del descriptor['text_codec']
            descriptor['value_codec'] = 'boolean-u8/v1'
            canonical = json.dumps(descriptor, ensure_ascii=False, sort_keys=True,
                                   separators=(',', ':')).encode()
            digest = hashlib.sha256(canonical).digest()
            encoded = bytes([int(value)])
            aad = tuple_bytes(b'CF1/payload', bytes.fromhex(source['domain_id'].replace('-', '')),
                bytes.fromhex(source['tenant_id'].replace('-', '')),
                bytes.fromhex(source['field_id'].replace('-', '')), bytes.fromhex(source['typed_record_id']),
                digest, bytes.fromhex(source['header']))
            key = hkdf(bytes.fromhex(source['payload_root']), bytes.fromhex(source['payload_salt']),
                tuple_bytes(b'CF1/payload-key', bytes.fromhex(source['field_id'].replace('-', '')),
                            bytes.fromhex(source['typed_record_id'])), 32)
            sealed = encrypt(key, bytes.fromhex(source['nonce']), encoded, aad)
            vectors.append({name: source[name] for name in ('domain_id', 'table_id', 'field_id',
                'tenant_id', 'record_id', 'payload_root_id', 'payload_generation', 'payload_root', 'nonce', 'header')}
                | dict(name=source['name'] + '-' + str(value).lower(), descriptor=descriptor,
                    descriptor_digest=digest.hex(), value=value, encoded_value=encoded.hex(),
                    frame=source['header'] + source['nonce'] + sealed.hex()))
    malformed = dict(vectors[0])
    source = next(value for value in old['vectors'] if value['name'] + '-false' == malformed['name'])
    digest = bytes.fromhex(malformed['descriptor_digest'])
    aad = tuple_bytes(b'CF1/payload', bytes.fromhex(source['domain_id'].replace('-', '')),
        bytes.fromhex(source['tenant_id'].replace('-', '')), bytes.fromhex(source['field_id'].replace('-', '')),
        bytes.fromhex(source['typed_record_id']), digest, bytes.fromhex(source['header']))
    malformed.update(name='authenticated-invalid-boolean-byte', encoded_value='02', value=None,
        frame=source['header'] + source['nonce'] + encrypt(bytes.fromhex(source['payload_key']),
            bytes.fromhex(source['nonce']), b'\x02', aad).hex())
    return dict(oracle='Existing independent RFC8452/POLYVAL/OpenSSL AES blocks and stdlib HKDF; public fixture keys only; no product imports',
                primitive_vectors=primitive_vectors, vectors=vectors, malformed=malformed)


if __name__ == '__main__':
    result = generate()
    if sys.argv[1:] == ['--write']:
        with FIXTURE.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    else:
        assert result == json.loads(FIXTURE.read_text())
    print('Independent Boolean fixtures verified')
