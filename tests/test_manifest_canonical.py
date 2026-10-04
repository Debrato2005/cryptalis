import pytest

from cryptalis.manifest.canonical import canonicalize_manifest_json
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
