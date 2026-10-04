import json
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from cryptalis.manifest.header import ManifestHeader, decode_manifest_header
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
