import json
from pathlib import Path

import pytest

from cryptalis.manifest.canonical import (
    canonicalize_manifest_json,
    digest_manifest_json,
)
from cryptalis.manifest.descriptor import (
    canonicalize_field_format_json,
    digest_field_format_json,
)
from cryptalis.manifest.parser import ManifestInvalid


_FIELD_FORMAT = {
    "descriptor_schema": 1,
    "model_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f21",
    "table_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f22",
    "field_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f23",
    "access_mode": "transparent",
    "suite_id": 1,
    "envelope_version": 1,
    "kdf_domain_version": 1,
    "aad_binding_version": 1,
    "codec_entry_id": 1,
    "codec_version": 1,
    "codec_parameters": {},
    "null_policy": "sql_null",
    "identity_encoding_version": 1,
}
_CANONICAL_FIELD_FORMAT = (
    b'{"aad_binding_version":1,"access_mode":"transparent",'
    b'"codec_entry_id":1,"codec_parameters":{},"codec_version":1,'
    b'"descriptor_schema":1,"envelope_version":1,'
    b'"field_id":"018f4f87-6f95-7e2a-9d95-38f9b7646f23",'
    b'"identity_encoding_version":1,"kdf_domain_version":1,'
    b'"model_id":"018f4f87-6f95-7e2a-9d95-38f9b7646f21",'
    b'"null_policy":"sql_null","suite_id":1,'
    b'"table_id":"018f4f87-6f95-7e2a-9d95-38f9b7646f22"}'
)


def test_field_format_emits_exact_canonical_bytes():
    raw = (
        Path(__file__).parent.parent
        / "examples"
        / "field-formats"
        / "parameterless.json"
    ).read_bytes()

    assert canonicalize_field_format_json(raw) == _CANONICAL_FIELD_FORMAT
    assert canonicalize_field_format_json(_CANONICAL_FIELD_FORMAT) == (
        _CANONICAL_FIELD_FORMAT
    )


@pytest.mark.parametrize("member", list(_FIELD_FORMAT))
def test_field_format_requires_every_member(member):
    document = dict(_FIELD_FORMAT)
    del document[member]

    with pytest.raises(ManifestInvalid):
        canonicalize_field_format_json(json.dumps(document).encode("utf-8"))


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("descriptor_schema", True),
        ("descriptor_schema", 2),
        ("identity_encoding_version", True),
        ("identity_encoding_version", 2),
        ("model_id", _FIELD_FORMAT["model_id"].upper()),
        ("table_id", "not-a-uuid"),
        ("field_id", _FIELD_FORMAT["field_id"].replace("-", "")),
        ("field_id", None),
        ("access_mode", "unknown"),
        ("access_mode", []),
        ("null_policy", None),
        ("null_policy", "unknown"),
        ("codec_parameters", []),
        ("codec_parameters", None),
    ],
)
def test_field_format_rejects_invalid_representations(member, value):
    raw = json.dumps({**_FIELD_FORMAT, member: value}).encode("utf-8")

    with pytest.raises(ManifestInvalid) as error:
        canonicalize_field_format_json(raw)
    assert "not-a-uuid" not in str(error.value)


@pytest.mark.parametrize(
    "member",
    [
        "suite_id",
        "envelope_version",
        "kdf_domain_version",
        "aad_binding_version",
        "codec_entry_id",
        "codec_version",
    ],
)
@pytest.mark.parametrize("value", [0, 65536, True, "1", None])
def test_field_format_rejects_invalid_catalogue_id_ranges(member, value):
    raw = json.dumps({**_FIELD_FORMAT, member: value}).encode("utf-8")

    with pytest.raises(ManifestInvalid):
        canonicalize_field_format_json(raw)


@pytest.mark.parametrize(
    "member",
    ["revision", "description", "normalization", "digest", "signature", "extra"],
)
def test_field_format_rejects_non_format_members_without_echo(member):
    raw = json.dumps({**_FIELD_FORMAT, member: "do-not-echo-value"}).encode("utf-8")

    with pytest.raises(ManifestInvalid) as error:
        digest_field_format_json(raw)
    assert "do-not-echo-value" not in str(error.value)


@pytest.mark.parametrize(
    "raw",
    [
        _CANONICAL_FIELD_FORMAT[:-1] + b',"suite_id":2}',
        _CANONICAL_FIELD_FORMAT.replace(b'"suite_id":1', b'"suite_id":1.0'),
        _CANONICAL_FIELD_FORMAT.replace(
            b'"codec_parameters":{}',
            b'"codec_parameters":{"scale":1,"scale":2}',
        ),
        _CANONICAL_FIELD_FORMAT.replace(
            b'"codec_parameters":{}',
            br'"codec_parameters":{"value":"\ud800"}',
        ),
    ],
    ids=["duplicate-root", "float-id", "duplicate-parameter", "invalid-unicode"],
)
def test_field_format_rejects_ambiguous_json(raw):
    with pytest.raises(ManifestInvalid):
        digest_field_format_json(raw)


def test_field_format_digest_matches_separate_domain_vector():
    # Hand-ordered bytes, independently hashed with sha256sum.
    expected = "b96d954389cb35bb7ccd4d59cac9ccf70cb0028a4073fae3fd4057587663417f"
    raw = json.dumps(_FIELD_FORMAT, indent=2).encode("utf-8")

    assert digest_field_format_json(raw) == expected
    assert digest_field_format_json(_CANONICAL_FIELD_FORMAT) == expected
    assert digest_manifest_json(raw) != expected


@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("model_id", "018f4f87-6f95-7e2a-9d95-38f9b7646f24"),
        ("table_id", "018f4f87-6f95-7e2a-9d95-38f9b7646f24"),
        ("field_id", "018f4f87-6f95-7e2a-9d95-38f9b7646f24"),
        ("access_mode", "controlled"),
        ("suite_id", 65535),
        ("envelope_version", 65535),
        ("kdf_domain_version", 65535),
        ("aad_binding_version", 65535),
        ("codec_entry_id", 65535),
        ("codec_version", 65535),
        ("codec_parameters", {"scale": "2"}),
        ("null_policy", "encrypted_null"),
    ],
)
def test_field_format_digest_binds_every_changeable_member(member, value):
    raw = json.dumps({**_FIELD_FORMAT, member: value}).encode("utf-8")

    assert digest_field_format_json(raw) != (
        "b96d954389cb35bb7ccd4d59cac9ccf70cb0028a4073fae3fd4057587663417f"
    )


def test_field_format_preserves_parameter_unicode_without_normalization():
    raw = json.dumps({**_FIELD_FORMAT, "codec_parameters": {"value": "é|e\u0301"}})
    expected = _CANONICAL_FIELD_FORMAT.replace(
        b'"codec_parameters":{}',
        '"codec_parameters":{"value":"é|e\u0301"}'.encode("utf-8"),
    )

    assert canonicalize_field_format_json(raw.encode("utf-8")) == expected


def test_emits_restricted_jcs_bytes():
    raw = (
        b'{"z":[3,{"b":true,"a":null}],'
        br'"unicode":"\u00e9|e\u0301|\ud83d\ude00|\u2028",'
        br'"controls":"\u000f\n\t",'
        br'"quote":"\"\\/",'
        b'"a":{"ab":4,"a":2,"aa":3,"":1}}'
    )
    expected = (
        '{"a":{"":1,"a":2,"aa":3,"ab":4},'
        '"controls":"\\u000f\\n\\t",'
        '"quote":"\\"\\\\/",'
        '"unicode":"é|e\u0301|😀|\u2028",'
        '"z":[3,{"a":null,"b":true}]}'
    ).encode("utf-8")

    assert canonicalize_manifest_json(raw) == expected


def test_equivalent_documents_have_identical_bytes():
    escaped = br'{"z":0,"a":"\u00e9"}'
    utf8 = '{ "a" : "é", "z" : 0 }'.encode("utf-8")

    assert canonicalize_manifest_json(escaped) == canonicalize_manifest_json(
        utf8
    )


def test_canonical_bytes_are_idempotent():
    canonical = canonicalize_manifest_json(
        b'{"models":[{"z":2,"a":1}],"revision":0}'
    )

    assert canonicalize_manifest_json(canonical) == canonical


def test_rejects_ambiguous_input_before_serialization():
    with pytest.raises(ManifestInvalid):
        canonicalize_manifest_json(b'{"revision":0,"revision":1}')


def test_manifest_digest_matches_domain_separated_vector():
    raw = (
        b'{"schema_version":1,'
        b'"manifest_id":"018f4f87-6f95-7e2a-9d95-38f9b7646f24",'
        b'"revision":0,"parent_digest":null}'
    )

    assert digest_manifest_json(raw) == (
        "7b7c4bdb543a0a89ba3493e06735ada4"
        "5a3457f686fb4a65c23d3562e5525e3e"
    )


def test_equivalent_documents_have_identical_manifest_digests():
    escaped = br'{"z":0,"description":"caf\u00e9"}'
    utf8 = '{ "description": "café", "z": 0 }'.encode("utf-8")

    assert digest_manifest_json(escaped) == digest_manifest_json(utf8)


def test_manifest_digest_rejects_ambiguous_input():
    with pytest.raises(ManifestInvalid):
        digest_manifest_json(b'{"revision":0,"revision":1}')


def test_manifest_digest_hashes_every_supplied_member():
    without_annotation = b'{"revision":0}'
    with_annotation = b'{"revision":0,"description":"draft"}'

    assert digest_manifest_json(without_annotation) != digest_manifest_json(
        with_annotation
    )
