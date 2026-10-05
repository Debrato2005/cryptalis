import json
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.header import (
    ManifestHeader,
    decode_manifest_header,
    validate_manifest_history,
)
from cryptalis.manifest.parser import ManifestInvalid


_MANIFEST_ID = "018f4f87-6f95-7e2a-9d95-38f9b7646f24"
_PARENT_DIGEST = "a" * 64
_BASE_HEADER = {
    "schema_version": 1,
    "manifest_id": _MANIFEST_ID,
    "revision": 0,
    "parent_digest": None,
}


def _header_json(**changes: object) -> bytes:
    return json.dumps({**_BASE_HEADER, **changes}).encode("utf-8")


def _history(length: int) -> tuple[bytes, ...]:
    documents = [_header_json()]
    for revision in range(1, length):
        documents.append(
            _header_json(
                revision=revision,
                parent_digest=digest_manifest_json(documents[-1]),
            )
        )
    return tuple(documents)


def test_decodes_typed_manifest_header():
    raw = _header_json(models=[])

    assert decode_manifest_header(raw) == ManifestHeader(
        schema_version=1,
        manifest_id=UUID(_MANIFEST_ID),
        revision=0,
        parent_digest=None,
    )


def test_accepts_canonical_parent_digest():
    header = decode_manifest_header(
        _header_json(revision=1, parent_digest=_PARENT_DIGEST)
    )

    assert header.parent_digest == _PARENT_DIGEST


@pytest.mark.parametrize(
    ("revision", "parent_digest"),
    [
        pytest.param(0, _PARENT_DIGEST, id="genesis-with-parent"),
        pytest.param(1, None, id="successor-without-parent"),
    ],
)
def test_rejects_invalid_local_parent_link(revision, parent_digest):
    with pytest.raises(ManifestInvalid):
        decode_manifest_header(
            _header_json(revision=revision, parent_digest=parent_digest)
        )


def test_manifest_header_is_immutable():
    header = decode_manifest_header(_header_json())

    with pytest.raises(FrozenInstanceError):
        setattr(header, "revision", 1)


@pytest.mark.parametrize(
    "member",
    ["schema_version", "manifest_id", "revision", "parent_digest"],
)
def test_rejects_missing_header_member(member):
    document = dict(_BASE_HEADER)
    del document[member]

    with pytest.raises(ManifestInvalid):
        decode_manifest_header(json.dumps(document).encode("utf-8"))


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param(
            {"schema_version": True}, id="boolean-schema-version"
        ),
        pytest.param(
            {"schema_version": 2}, id="unsupported-schema-version"
        ),
        pytest.param(
            {"manifest_id": _MANIFEST_ID.upper()}, id="uppercase-uuid"
        ),
        pytest.param(
            {"manifest_id": _MANIFEST_ID.replace("-", "")},
            id="unhyphenated-uuid",
        ),
        pytest.param({"manifest_id": "not-a-uuid"}, id="invalid-uuid"),
        pytest.param({"revision": True}, id="boolean-revision"),
        pytest.param(
            {"parent_digest": "A" * 64}, id="uppercase-digest"
        ),
        pytest.param(
            {"parent_digest": "a" * 63}, id="short-digest"
        ),
        pytest.param({"parent_digest": 0}, id="non-string-digest"),
    ],
)
def test_rejects_invalid_header_value(changes):
    with pytest.raises(ManifestInvalid):
        decode_manifest_header(_header_json(**changes))


def test_validates_complete_history_and_returns_its_head():
    genesis = _header_json(note="genesis")
    revision_two = _header_json(
        revision=2,
        parent_digest=digest_manifest_json(genesis),
        note="skipped revision numbers are valid",
    )
    head = _header_json(
        revision=7,
        parent_digest=digest_manifest_json(revision_two),
        note="head",
    )

    result = validate_manifest_history((genesis, revision_two, head))

    assert result == decode_manifest_header(head)


def test_manifest_history_accepts_one_genesis_document():
    genesis = _header_json()

    assert validate_manifest_history((genesis,)) == decode_manifest_header(genesis)


@pytest.mark.parametrize("history", [(), [], iter(())])
def test_manifest_history_requires_a_nonempty_immutable_sequence(history):
    with pytest.raises(ManifestInvalid):
        validate_manifest_history(history)


def test_manifest_history_rejects_a_non_genesis_first_document():
    raw = _header_json(revision=1, parent_digest=_PARENT_DIGEST)

    with pytest.raises(ManifestInvalid, match="genesis"):
        validate_manifest_history((raw,))


def test_manifest_history_rejects_mixed_manifest_ids():
    genesis = _header_json()
    child = _header_json(
        manifest_id="018f4f87-6f95-7e2a-9d95-38f9b7646f25",
        revision=1,
        parent_digest=digest_manifest_json(genesis),
    )

    with pytest.raises(ManifestInvalid):
        validate_manifest_history((genesis, child))


def test_manifest_history_rejects_reordering_and_digest_substitution():
    genesis, child, head = _history(3)
    substituted = _header_json(
        revision=1,
        parent_digest=digest_manifest_json(genesis),
        marker="different canonical document",
    )

    for history in ((genesis, head, child), (genesis, substituted, head)):
        with pytest.raises(ManifestInvalid):
            validate_manifest_history(history)


def test_manifest_history_rejects_a_truncated_prefix_without_genesis():
    _genesis, child, head = _history(3)

    with pytest.raises(ManifestInvalid, match="genesis"):
        validate_manifest_history((child, head))


def test_manifest_history_rejects_more_than_4096_documents_before_parsing():
    history = (b"do-not-echo-history",) * 4097

    with pytest.raises(ManifestInvalid, match="document limit") as error:
        validate_manifest_history(history)

    assert "do-not-echo-history" not in str(error.value)


def test_manifest_history_accepts_exactly_4096_linked_documents():
    history = _history(4096)

    assert validate_manifest_history(history).revision == 4095


def test_manifest_history_rejects_more_than_16_mib_before_parsing():
    oversized = b"do-not-echo-history" + b" " * (16 * 1024 * 1024)

    with pytest.raises(ManifestInvalid, match="size limit") as error:
        validate_manifest_history((oversized,))

    assert "do-not-echo-history" not in str(error.value)


def test_manifest_history_rejects_mutable_or_nonbyte_documents():
    for raw in (bytearray(b"{}"), memoryview(b"{}"), "{}", None):
        with pytest.raises(ManifestInvalid):
            validate_manifest_history((raw,))
