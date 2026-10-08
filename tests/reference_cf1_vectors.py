"""Independent, offline CF1 fixture generator. PUBLIC FIXTURE KEYS ONLY.

This slow RFC 8452 reference is test evidence, never runtime cryptography.
AES blocks use the system OpenSSL executable; POLYVAL and CTR follow RFC 8452
sections 3 and 4. HKDF/HMAC use stdlib, not product imports or cryptography.
Run: .venv/bin/python tests/reference_cf1_vectors.py
The default checks the frozen file. Use --write only to review a format change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
from uuid import UUID


FIXTURE = Path(__file__).parent / "fixtures" / "cf1_vectors.json"
POLYNOMIAL = (1 << 128) | (1 << 127) | (1 << 126) | (1 << 121) | 1
INVERSE_X128 = (1 << 127) | (1 << 124) | (1 << 121) | (1 << 114) | 1


def tuple_bytes(*parts: bytes) -> bytes:
    return len(parts).to_bytes(4, "big") + b"".join(
        len(part).to_bytes(4, "big") + part for part in parts
    )


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.digest(salt, ikm, "sha256")
    output = b""
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        output += previous
    return output[:length]


def aes_block(key: bytes, block: bytes) -> bytes:
    if len(key) != 32 or len(block) != 16:
        raise ValueError("Reference accepts AES-256 single blocks only")
    # Only public keys defined in this file are passed to the CLI.
    result = subprocess.run(
        ["openssl", "enc", "-aes-256-ecb", "-K", key.hex(), "-nopad", "-nosalt"],
        input=block, capture_output=True, check=True,
    ).stdout
    if len(result) != 16:
        raise RuntimeError("OpenSSL returned an invalid AES block")
    return result


def field_multiply(left: int, right: int) -> int:
    product = 0
    for bit in range(128):
        if (right >> bit) & 1:
            product ^= left << bit
    for bit in range(254, 127, -1):
        if (product >> bit) & 1:
            product ^= POLYNOMIAL << (bit - 128)
    return product


def polyval(key: bytes, blocks: bytes) -> bytes:
    if len(key) != 16 or len(blocks) % 16:
        raise ValueError("Invalid POLYVAL inputs")
    multiplier = field_multiply(int.from_bytes(key, "little"), INVERSE_X128)
    state = 0
    for offset in range(0, len(blocks), 16):
        state = field_multiply(
            state ^ int.from_bytes(blocks[offset:offset + 16], "little"), multiplier
        )
    return state.to_bytes(16, "little")


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValueError("Nonce must contain 12 bytes")
    material = b"".join(
        aes_block(key, counter.to_bytes(4, "little") + nonce)[:8]
        for counter in range(6)
    )
    auth_key, encryption_key = material[:16], material[16:]
    padded_aad = aad + bytes((-len(aad)) % 16)
    padded_plaintext = plaintext + bytes((-len(plaintext)) % 16)
    lengths = (len(aad) * 8).to_bytes(8, "little") + (len(plaintext) * 8).to_bytes(8, "little")
    synthetic = bytearray(polyval(auth_key, padded_aad + padded_plaintext + lengths))
    for index in range(12):
        synthetic[index] ^= nonce[index]
    synthetic[15] &= 0x7f
    tag = aes_block(encryption_key, bytes(synthetic))
    counter_block = bytearray(tag)
    counter_block[15] |= 0x80
    ciphertext = b""
    for offset in range(0, len(plaintext), 16):
        stream = aes_block(encryption_key, bytes(counter_block))
        block = plaintext[offset:offset + 16]
        ciphertext += bytes(value ^ mask for value, mask in zip(block, stream))
        counter = (int.from_bytes(counter_block[:4], "little") + 1) % (1 << 32)
        counter_block[:4] = counter.to_bytes(4, "little")
    return ciphertext + tag


def verify_published_vectors() -> dict:
    """Literal published results, independent of this reference implementation."""
    key = bytes.fromhex("01" + "00" * 31)
    nonce = bytes.fromhex("03" + "00" * 11)
    # RFC 8452 Appendix C.2: empty, partial-block, AAD, multi-block.
    aead = [
        ("", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        ("0100000000000000", "", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
        ("0200000000000000", "01", "1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
        ("01" + "00" * 15 + "02" + "00" * 15, "",
         "4a6a9db4c8c6549201b9edb53006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632eb5d"),
    ]
    for plaintext, aad, expected in aead:
        if encrypt(key, nonce, bytes.fromhex(plaintext), bytes.fromhex(aad)).hex() != expected:
            raise AssertionError("RFC 8452 AES-256-GCM-SIV oracle mismatch")
    # RFC 8452 section 7: multiplication and dot examples.
    left = int.from_bytes(bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"), "little")
    right = int.from_bytes(bytes.fromhex("ff000000000000000000000000000000"), "little")
    if field_multiply(left, right).to_bytes(16, "little").hex() != "37856175e9dc9df26ebc6d6171aa0ae9":
        raise AssertionError("RFC 8452 field multiplication mismatch")
    dot = field_multiply(field_multiply(left, right), INVERSE_X128)
    if dot.to_bytes(16, "little").hex() != "ebe563401e7e91ea3ad6426b8140c394":
        raise AssertionError("RFC 8452 dot mismatch")
    # RFC 5869 Appendix A.1 and RFC 4231 section 4.2.
    hkdf_expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    if hkdf(bytes.fromhex("0b" * 22), bytes(range(13)), bytes(range(240, 250)), 42).hex() != hkdf_expected:
        raise AssertionError("RFC 5869 HKDF oracle mismatch")
    hmac_expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    if hmac.digest(bytes.fromhex("0b" * 20), b"Hi There", "sha256").hex() != hmac_expected:
        raise AssertionError("RFC 4231 HMAC oracle mismatch")
    return {
        "aes256_gcm_siv": [{"key": key.hex(), "nonce": nonce.hex(), "plaintext": p,
                            "aad": a, "sealed": c} for p, a, c in aead],
        "hkdf_sha256": {"ikm": "0b" * 22, "salt": bytes(range(13)).hex(),
                        "info": bytes(range(240, 250)).hex(), "length": 42, "output": hkdf_expected},
        "hmac_sha256": {"key": "0b" * 20, "message": b"Hi There".hex(), "output": hmac_expected},
    }


def make_vector(name: str, equality: bool, record: str | int, text: str, nonce: bytes,
                *, single_tenant: bool = False) -> dict:
    domain = UUID("11111111-1111-4111-8111-111111111111")
    table = UUID("22222222-2222-4222-8222-222222222222")
    field = UUID("33333333-3333-4333-8333-333333333333")
    tenant = table if single_tenant else UUID("44444444-4444-4444-8444-444444444444")
    payload_id = UUID("55555555-5555-4555-8555-555555555555")
    search_id = UUID("66666666-6666-4666-8666-666666666666")
    payload_root, search_root = bytes(range(32)), bytes(range(32, 64))
    payload_generation, search_generation = 7, 11 if equality else 0
    record_codec = "int64-be/v1" if isinstance(record, int) else "uuid16/v1"
    typed_record = (tuple_bytes(b"int64", record.to_bytes(8, "big", signed=True))
                    if isinstance(record, int) else UUID(record).bytes)
    descriptor = {
        "schema": "cryptalis.context/v1", "domain_id": str(domain), "table_id": str(table),
        "field_id": str(field), "text_codec": "utf8-exact/v1", "normalizer": "identity/v1",
        "null_policy": "sql-null/v1", "record_codec": record_codec,
        "tenant_codec": "single-tenant-uuid/v1" if single_tenant else "uuid16/v1",
        "representation": "cf1-packed-equality/v1" if equality else "cf1-storage/v1",
    }
    canonical_descriptor = json.dumps(descriptor, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    digest = hashlib.sha256(canonical_descriptor).digest()
    payload_salt = hashlib.sha256(tuple_bytes(b"CF1/root", domain.bytes, tenant.bytes,
        payload_id.bytes, payload_generation.to_bytes(4, "big"))).digest()
    payload_key = hkdf(payload_root, payload_salt,
                       tuple_bytes(b"CF1/payload-key", field.bytes, typed_record), 32)
    encoded = text.encode("utf-8", "strict")
    search_salt = search_key = term = b""
    if equality:
        search_salt = hashlib.sha256(tuple_bytes(b"CF1/root", domain.bytes, tenant.bytes,
            search_id.bytes, search_generation.to_bytes(4, "big"))).digest()
        search_key = hkdf(search_root, search_salt, tuple_bytes(b"CF1/search-key", field.bytes,
            b"utf8-exact/v1", b"identity/v1", b"equality"), 32)
        term = hmac.digest(search_key, tuple_bytes(b"equality", encoded), "sha256")
    header = (b"CF1\x00\x01" + bytes([int(equality)]) + payload_generation.to_bytes(4, "big")
              + search_generation.to_bytes(4, "big") + term)
    aad = tuple_bytes(b"CF1/payload", domain.bytes, tenant.bytes, field.bytes,
                      typed_record, digest, header)
    sealed = encrypt(payload_key, nonce, encoded, aad)
    return {
        "name": name, "descriptor": descriptor, "descriptor_digest": digest.hex(),
        "canonical_descriptor": canonical_descriptor.hex(), "domain_id": str(domain),
        "table_id": str(table), "field_id": str(field), "tenant_id": str(tenant),
        "record_id": record, "typed_record_id": typed_record.hex(),
        "payload_root_id": str(payload_id), "search_root_id": str(search_id),
        "payload_generation": payload_generation, "search_generation": search_generation,
        "payload_root": payload_root.hex(), "search_root": search_root.hex(),
        "nonce": nonce.hex(), "text": text, "encoded_text": encoded.hex(),
        "payload_salt": payload_salt.hex(), "payload_key": payload_key.hex(),
        "search_salt": search_salt.hex(), "search_key": search_key.hex(), "term": term.hex(),
        "header": header.hex(), "aad": aad.hex(), "sealed": sealed.hex(),
        "frame": (header + nonce + sealed).hex(),
    }


def generate() -> dict:
    primitives = verify_published_vectors()
    uuid_record = "77777777-7777-4777-8777-777777777777"
    return {
        "oracle": {
            "implementation": "Test-only RFC8452 reference; system OpenSSL AES-256 ECB; stdlib SHA256/HKDF/HMAC",
            "sources": ["https://www.rfc-editor.org/rfc/rfc8452#appendix-C.2",
                        "https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1",
                        "https://www.rfc-editor.org/rfc/rfc4231#section-4.2", "docs/security.md"],
            "keys": "All roots and nonces in this fixture are public deterministic test data",
        },
        "primitive_vectors": primitives,
        "vectors": [
            make_vector("uuid-storage-unicode", False, uuid_record, "Cryptalis — café e\u0301 🗝️", bytes(range(12))),
            make_vector("uuid-equality-unicode", True, uuid_record, "Cryptalis — café e\u0301 🗝️", bytes(range(12, 24))),
            make_vector("int64-storage-empty", False, -(1 << 63), "", bytes(range(24, 36))),
            make_vector("int64-equality-unicode", True, -42, "Å\n東京", bytes(range(36, 48))),
            make_vector("single-uuid-storage-unicode", False, uuid_record,
                        "Cryptalis — café e\u0301 🗝️", bytes(range(48, 60)), single_tenant=True),
            make_vector("single-uuid-equality-unicode", True, uuid_record,
                        "Cryptalis — café e\u0301 🗝️", bytes(range(60, 72)), single_tenant=True),
            make_vector("single-int64-storage-empty", False, -(1 << 63), "",
                        bytes(range(72, 84)), single_tenant=True),
            make_vector("single-int64-equality-unicode", True, -42, "Å\n東京",
                        bytes(range(84, 96)), single_tenant=True),
        ],
    }


if __name__ == "__main__":
    generated = generate()
    if sys.argv[1:] == ["--write"]:
        FIXTURE.parent.mkdir(parents=True, exist_ok=True)
        if FIXTURE.exists():
            raise SystemExit("Refusing to overwrite existing fixtures; review a new output file instead")
        FIXTURE.write_text(json.dumps(generated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Created public CF1 vectors after published primitive checks")
    elif sys.argv[1:]:
        raise SystemExit("Usage: reference_cf1_vectors.py [--write]")
    else:
        if json.loads(FIXTURE.read_text(encoding="utf-8")) != generated:
            raise SystemExit("Independent CF1 fixture reproduction failed")
        print("Published primitive vectors and independent CF1 fixture reproduction passed")
