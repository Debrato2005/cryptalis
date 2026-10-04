import json

from cryptalis.manifest.parser import decode_manifest_json


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
