"""Structural field-format bytes and digests without catalogue approval."""

from hashlib import sha256
from uuid import UUID

from cryptalis.manifest.canonical import canonicalize_manifest_json
from cryptalis.manifest.parser import ManifestInvalid, decode_manifest_json


_UUID_MEMBERS = ("model_id", "table_id", "field_id")
_CATALOGUE_MEMBERS = (
    "suite_id",
    "envelope_version",
    "kdf_domain_version",
    "aad_binding_version",
    "codec_entry_id",
    "codec_version",
)
_VERSION_MEMBERS = ("descriptor_schema", "identity_encoding_version")
_MEMBERS = frozenset(
    (
        *_UUID_MEMBERS,
        *_CATALOGUE_MEMBERS,
        *_VERSION_MEMBERS,
        "access_mode",
        "null_policy",
        "codec_parameters",
    )
)
_FIELD_FORMAT_DIGEST_PREFIX = b"cryptalis-field-format-v1\x00"


def canonicalize_field_format_json(raw: bytes) -> bytes:
    """Check descriptor structure and return restricted RFC 8785 bytes.

    This function does not approve catalogue IDs or codec parameter semantics.
    """
    document = decode_manifest_json(raw)
    if document.keys() != _MEMBERS:
        raise ManifestInvalid("Field format must contain exactly the required members")

    for member in _VERSION_MEMBERS:
        value = document[member]
        if type(value) is not int or value != 1:
            raise ManifestInvalid("Field format versions must be the integer 1")

    for member in _UUID_MEMBERS:
        value = document[member]
        if not isinstance(value, str):
            raise ManifestInvalid("Field format IDs must be lowercase canonical UUIDs")
        try:
            parsed = UUID(value)
        except ValueError:
            raise ManifestInvalid(
                "Field format IDs must be lowercase canonical UUIDs"
            ) from None
        if str(parsed) != value:
            raise ManifestInvalid("Field format IDs must be lowercase canonical UUIDs")

    for member in _CATALOGUE_MEMBERS:
        value = document[member]
        if type(value) is not int or not 1 <= value <= 65535:
            raise ManifestInvalid(
                "Field format catalogue IDs must be integers in 1..65535"
            )

    if document["access_mode"] not in ("transparent", "controlled"):
        raise ManifestInvalid(
            "Field format access mode must be transparent or controlled"
        )
    if document["null_policy"] not in ("sql_null", "encrypted_null"):
        raise ManifestInvalid(
            "Field format null policy must be sql_null or encrypted_null"
        )
    if not isinstance(document["codec_parameters"], dict):
        raise ManifestInvalid("Field format codec parameters must be an object")

    return canonicalize_manifest_json(raw)


def digest_field_format_json(raw: bytes) -> str:
    """Return a field-format digest without authenticating or approving it."""
    digest = sha256(_FIELD_FORMAT_DIGEST_PREFIX)
    digest.update(canonicalize_field_format_json(raw))
    return digest.hexdigest()
