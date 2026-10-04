import re
from dataclasses import dataclass
from uuid import UUID

from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.parser import ManifestInvalid, decode_manifest_json


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ManifestHeader:
    """Manifest identity and version fields."""

    schema_version: int
    manifest_id: UUID
    revision: int
    parent_digest: str | None


def _required(document: dict[str, object], name: str) -> object:
    try:
        return document[name]
    except KeyError:
        raise ManifestInvalid(
            f"Manifest header does not contain the required member: {name}"
        ) from None


def _schema_version(document: dict[str, object]) -> int:
    value = _required(document, "schema_version")
    if type(value) is not int or value != 1:
        raise ManifestInvalid("Manifest schema version must be the integer 1")
    return value


def _manifest_id(document: dict[str, object]) -> UUID:
    value = _required(document, "manifest_id")
    if not isinstance(value, str):
        raise ManifestInvalid(
            "Manifest ID must be a lowercase UUID in canonical form"
        )

    try:
        parsed = UUID(value)
    except ValueError:
        raise ManifestInvalid(
            "Manifest ID must be a lowercase UUID in canonical form"
        ) from None

    if str(parsed) != value:
        raise ManifestInvalid(
            "Manifest ID must be a lowercase UUID in canonical form"
        )
    return parsed


def _revision(document: dict[str, object]) -> int:
    value = _required(document, "revision")
    if type(value) is not int:
        raise ManifestInvalid("Manifest revision must be an integer")
    return value


def _parent_digest(document: dict[str, object]) -> str | None:
    value = _required(document, "parent_digest")
    if value is None:
        return None
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise ManifestInvalid(
            "Manifest parent digest must be null or have 64 lowercase "
            "hexadecimal characters"
        )
    return value


def _validate_local_parent_link(
    revision: int, parent_digest: str | None
) -> None:
    if revision == 0 and parent_digest is not None:
        raise ManifestInvalid(
            "Manifest revision 0 requires a null parent digest"
        )
    if revision > 0 and parent_digest is None:
        raise ManifestInvalid(
            "A manifest revision after 0 requires a parent digest"
        )


def decode_manifest_header(raw: bytes) -> ManifestHeader:
    """Decode and validate the identity header from manifest JSON bytes."""
    document = decode_manifest_json(raw)
    schema_version = _schema_version(document)
    manifest_id = _manifest_id(document)
    revision = _revision(document)
    parent_digest = _parent_digest(document)
    _validate_local_parent_link(revision, parent_digest)
    return ManifestHeader(
        schema_version=schema_version,
        manifest_id=manifest_id,
        revision=revision,
        parent_digest=parent_digest,
    )


def validate_manifest_parent_link(raw: bytes, parent_raw: bytes) -> ManifestHeader:
    """Validate one parent link without authenticating policy or ancestry."""
    header = decode_manifest_header(raw)
    parent = decode_manifest_header(parent_raw)
    if header.manifest_id != parent.manifest_id:
        raise ManifestInvalid("Manifest and parent IDs must match")
    if header.revision <= parent.revision:
        raise ManifestInvalid("Manifest revision must exceed its parent revision")
    if header.parent_digest != digest_manifest_json(parent_raw):
        raise ManifestInvalid("Manifest parent digest does not match")
    return header
