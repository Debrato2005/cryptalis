import json
from typing import Never


_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_NESTING_DEPTH = 32


class ManifestInvalid(ValueError):
    """Manifest input violates the supported format."""


def _unique_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if not key.isascii():
            raise ManifestInvalid("Manifest property names must be ASCII")
        if key in result:
            raise ManifestInvalid("Duplicate manifest member")
        result[key] = value

    return result


def _parse_counter(token: str) -> int:
    if len(token) > 16:
        raise ManifestInvalid("Manifest integer outside supported range")

    value = int(token)

    if not 0 <= value <= 2**53 - 1:
        raise ManifestInvalid("Manifest integer outside supported range")

    return value


def _reject_non_integer(_token: str) -> Never:
    raise ManifestInvalid("Manifest numbers must use integer syntax")


def _check_nesting(raw: bytes) -> None:
    """Bound container depth before the JSON decoder allocates containers."""
    depth = 0
    in_string = False
    escaped = False

    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # Backslash.
                escaped = True
            elif byte == 0x22:  # Double quote.
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):  # Opening object or array.
            depth += 1
            if depth > _MAX_NESTING_DEPTH:
                raise ManifestInvalid("Manifest nesting depth exceeds 32")
        elif byte in (0x7D, 0x5D):  # Closing object or array.
            depth -= 1
            if depth < 0:
                raise ManifestInvalid("Invalid manifest JSON")

    if in_string or depth != 0:
        raise ManifestInvalid("Invalid manifest JSON")


def _check_unicode(value: object) -> None:
    """Reject lone surrogates without changing valid Unicode values."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ManifestInvalid("Manifest strings contain invalid Unicode") from None
    elif isinstance(value, dict):
        for member in value.values():
            _check_unicode(member)
    elif isinstance(value, list):
        for member in value:
            _check_unicode(member)


def decode_manifest_json(raw: bytes) -> dict[str, object]:
    """Decode bounded UTF-8 JSON; semantic manifest schema checks are separate."""
    if not isinstance(raw, bytes):
        raise ManifestInvalid("Manifest input must be bytes")
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise ManifestInvalid("Manifest document exceeds 16 MiB")

    _check_nesting(raw)

    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_int=_parse_counter,
            parse_float=_reject_non_integer,
            parse_constant=_reject_non_integer,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ManifestInvalid("Invalid manifest JSON") from None

    if not isinstance(document, dict):
        raise ManifestInvalid("Manifest root must be an object")

    _check_unicode(document)
    return document
