"""Structural ActiveState contracts without authority authentication or activation."""

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from cryptalis.manifest.parser import (
    MAX_DOCUMENT_BYTES,
    ManifestInvalid,
    decode_manifest_json,
)


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_ACTIVE_STATE_DIGEST_PREFIX = b"cryptalis-active-state-v1\x00"
_MAX_HISTORY_DOCUMENTS = 4096
_MAX_HISTORY_BYTES = MAX_DOCUMENT_BYTES


class ActiveStateInvalid(ValueError):
    """ActiveState input violates the structural contract."""


@dataclass(frozen=True, slots=True)
class ActiveStateHeader:
    """Immutable identity and monotonic fields from one ActiveState document."""

    schema_version: int
    protection_domain_id: UUID
    authority_revision: int
    parent_digest: str | None
    active_manifest_id: UUID
    active_manifest_revision: int
    active_manifest_digest: str
    schema_generation: int
    current_operation_id: UUID | None


def _decode_document(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes:
        raise ActiveStateInvalid("ActiveState input must be immutable bytes")
    try:
        return decode_manifest_json(raw)
    except ManifestInvalid as error:
        raise ActiveStateInvalid("ActiveState JSON is invalid") from error


def _required(document: dict[str, object], name: str) -> object:
    try:
        return document[name]
    except KeyError:
        raise ActiveStateInvalid(
            f"ActiveState header does not contain the required member: {name}"
        ) from None


def _version(document: dict[str, object]) -> int:
    value = _required(document, "schema_version")
    if type(value) is not int or value != 1:
        raise ActiveStateInvalid("ActiveState schema version must be the integer 1")
    return value


def _uuid(document: dict[str, object], name: str, label: str) -> UUID:
    value = _required(document, name)
    if not isinstance(value, str):
        raise ActiveStateInvalid(f"{label} must be a lowercase canonical UUID")
    try:
        parsed = UUID(value)
    except ValueError:
        raise ActiveStateInvalid(
            f"{label} must be a lowercase canonical UUID"
        ) from None
    if str(parsed) != value:
        raise ActiveStateInvalid(f"{label} must be a lowercase canonical UUID")
    return parsed


def _nullable_uuid(
    document: dict[str, object], name: str, label: str
) -> UUID | None:
    value = _required(document, name)
    if value is None:
        return None
    return _uuid(document, name, label)


def _counter(document: dict[str, object], name: str, label: str) -> int:
    value = _required(document, name)
    if type(value) is not int or value < 0:
        raise ActiveStateInvalid(f"{label} must be a nonnegative integer")
    return value


def _required_digest(
    document: dict[str, object], name: str, label: str
) -> str:
    value = _required(document, name)
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise ActiveStateInvalid(
            f"{label} must be 64 lowercase hexadecimal characters"
        )
    return value


def _nullable_digest(
    document: dict[str, object], name: str, label: str
) -> str | None:
    value = _required(document, name)
    if value is None:
        return None
    return _required_digest(document, name, label)


def _header(document: dict[str, object]) -> ActiveStateHeader:
    header = ActiveStateHeader(
        schema_version=_version(document),
        protection_domain_id=_uuid(
            document, "protection_domain_id", "Protection domain ID"
        ),
        authority_revision=_counter(
            document, "authority_revision", "Authority revision"
        ),
        parent_digest=_nullable_digest(
            document,
            "parent_digest",
            "ActiveState parent digest",
        ),
        active_manifest_id=_uuid(
            document, "active_manifest_id", "Active manifest ID"
        ),
        active_manifest_revision=_counter(
            document, "active_manifest_revision", "Active manifest revision"
        ),
        active_manifest_digest=_required_digest(
            document, "active_manifest_digest", "Active manifest digest"
        ),
        schema_generation=_counter(
            document, "schema_generation", "Schema generation"
        ),
        current_operation_id=_nullable_uuid(
            document, "current_operation_id", "Current operation ID"
        ),
    )
    if header.authority_revision == 0 and header.parent_digest is not None:
        raise ActiveStateInvalid(
            "ActiveState authority revision 0 requires a null parent digest"
        )
    if header.authority_revision > 0 and header.parent_digest is None:
        raise ActiveStateInvalid(
            "ActiveState authority revisions after 0 require a parent digest"
        )
    return header


def decode_active_state_header(raw: bytes) -> ActiveStateHeader:
    """Decode structural authority fields without authenticating the document."""
    return _header(_decode_document(raw))


def _canonical_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest_active_state_json(raw: bytes) -> str:
    """Return a domain-separated structural digest without authentication."""
    document = _decode_document(raw)
    _header(document)
    digest = sha256(_ACTIVE_STATE_DIGEST_PREFIX)
    digest.update(_canonical_bytes(document))
    return digest.hexdigest()


def _validate_successor(
    current: ActiveStateHeader,
    previous: ActiveStateHeader,
    previous_raw: bytes,
) -> None:
    if current.protection_domain_id != previous.protection_domain_id:
        raise ActiveStateInvalid("ActiveState protection domains must match")
    if current.active_manifest_id != previous.active_manifest_id:
        raise ActiveStateInvalid("ActiveState manifest IDs must match")
    if current.authority_revision <= previous.authority_revision:
        raise ActiveStateInvalid("ActiveState authority revision must increase")
    if current.active_manifest_revision < previous.active_manifest_revision:
        raise ActiveStateInvalid("Active manifest revision cannot decrease")
    if current.schema_generation < previous.schema_generation:
        raise ActiveStateInvalid("Active schema generation cannot decrease")
    if (
        current.active_manifest_revision == previous.active_manifest_revision
        and current.active_manifest_digest != previous.active_manifest_digest
    ):
        raise ActiveStateInvalid(
            "One active manifest revision cannot have different digests"
        )
    if (
        current.active_manifest_revision > previous.active_manifest_revision
        and current.active_manifest_digest == previous.active_manifest_digest
    ):
        raise ActiveStateInvalid(
            "Different active manifest revisions cannot have one digest"
        )
    if current.parent_digest != digest_active_state_json(previous_raw):
        raise ActiveStateInvalid("ActiveState parent digest does not match")


def validate_active_state_parent_link(
    raw: bytes, parent_raw: bytes
) -> ActiveStateHeader:
    """Validate one structural parent link without authenticating authority."""
    current = decode_active_state_header(raw)
    previous = decode_active_state_header(parent_raw)
    _validate_successor(current, previous, parent_raw)
    return current


def validate_active_state_history(
    raw_documents: tuple[bytes, ...],
) -> ActiveStateHeader:
    """Validate one bounded genesis-to-head history without authentication."""
    if type(raw_documents) is not tuple or not raw_documents:
        raise ActiveStateInvalid(
            "ActiveState history must be a nonempty immutable sequence"
        )
    if len(raw_documents) > _MAX_HISTORY_DOCUMENTS:
        raise ActiveStateInvalid("ActiveState history exceeds the document limit")

    total_bytes = 0
    for raw in raw_documents:
        if type(raw) is not bytes:
            raise ActiveStateInvalid(
                "ActiveState history documents must be immutable bytes"
            )
        total_bytes += len(raw)
        if total_bytes > _MAX_HISTORY_BYTES:
            raise ActiveStateInvalid("ActiveState history exceeds the size limit")

    previous_raw = raw_documents[0]
    previous = decode_active_state_header(previous_raw)
    if previous.authority_revision != 0:
        raise ActiveStateInvalid(
            "ActiveState history must start with authority revision 0"
        )

    for raw in raw_documents[1:]:
        current = decode_active_state_header(raw)
        _validate_successor(current, previous, previous_raw)
        previous_raw = raw
        previous = current

    return previous
