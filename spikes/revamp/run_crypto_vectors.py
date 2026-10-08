"""Frozen independent AES-256-GCM-SIV primitive vectors. CF1 remains unqualified."""
import hashlib
import json
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV


# RFC 8452 Appendix C.2, pages 30 and 33. These are public test keys/nonces.
# They are never development roots. Runtime nonces still use os.urandom.
SOURCE = "https://www.rfc-editor.org/rfc/rfc8452.html#appendix-C.2"
VECTORS = (
    ("empty", "", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
    ("eight_bytes", "0100000000000000", "", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
    ("with_aad", "0200000000000000", "01", "1de22967237a813291213f267e3b452f02d01ae33e4ec854"),
)


def cases():
    cipher = AESGCMSIV(bytes.fromhex("01" + "00" * 31))
    nonce = bytes.fromhex("03" + "00" * 11)
    outcomes = {}
    for name, plaintext, aad, expected in VECTORS:
        plaintext, aad, expected = map(bytes.fromhex, (plaintext, aad, expected))
        if cipher.encrypt(nonce, plaintext, aad) != expected:
            raise AssertionError(name + "_encryption_mismatch")
        outcomes[name + "_encrypt"] = "PASS"
        if cipher.decrypt(nonce, expected, aad) != plaintext:
            raise AssertionError(name + "_decryption_mismatch")
        outcomes[name + "_decrypt"] = "PASS"
        try:
            cipher.decrypt(nonce, expected[:-1] + bytes([expected[-1] ^ 1]), aad)
        except InvalidTag:
            outcomes[name + "_changed_tag_rejected"] = "PASS"
        else:
            raise AssertionError(name + "_changed_tag_accepted")
    return outcomes


if __name__ == "__main__":
    print(json.dumps({"status": "PASS_INDEPENDENT_PRIMITIVE_VECTORS_ONLY", "source": SOURCE,
                      "cryptography_version": cryptography.__version__, "outcomes": cases(),
                      "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "vectors_sha256": hashlib.sha256(json.dumps(VECTORS, separators=(",", ":")).encode()).hexdigest(),
                      "limits": ["Three published primitive vectors, not full CF1/codec/KDF/HMAC/companion vectors",
                                 "No nonce-lifetime bound, independent human review or provider qualification",
                                 "G-CRYPTO remains UNKNOWN"]}, indent=2))
