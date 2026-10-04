import pytest

from cryptalis.manifest.canonical import (
    canonicalize_manifest_json,
    digest_manifest_json,
)
from cryptalis.manifest.parser import ManifestInvalid


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
