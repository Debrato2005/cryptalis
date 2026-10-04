import json
from hashlib import sha256

from cryptalis.manifest.parser import decode_manifest_json


_MANIFEST_DIGEST_PREFIX = b"cryptalis-manifest-v1\x00"


def canonicalize_manifest_json(raw: bytes) -> bytes:
    """Return restricted RFC 8785 bytes for one manifest JSON object."""
    document = decode_manifest_json(raw)
    text = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def digest_manifest_json(raw: bytes) -> str:
    """Return the domain-separated digest of restricted manifest JSON."""
    digest = sha256(_MANIFEST_DIGEST_PREFIX)
    digest.update(canonicalize_manifest_json(raw))
    return digest.hexdigest()
