import pytest

from cryptalis.manifest.parser import ManifestInvalid, decode_manifest_json


def test_decodes_unambiguous_json():
    document = decode_manifest_json(
        b'{"schema_version":1,"revision":0,"models":[]}'
    )

    assert document == {
        "schema_version": 1,
        "revision": 0,
        "models": [],
    }


@pytest.mark.parametrize(
    "raw",
    [
        b'{"revision":1,"revision":2}',
        b'{"models":[{"fields":[{"access_mode":"transparent",'
        b'"access_mode":"controlled"}]}]}',
        b'{"revision":1,"\\u0072evision":2}',
    ],
    ids=["root", "nested-policy", "escaped-key"],
)
def test_rejects_duplicate_keys(raw):
    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"revision":1.5}',
        b'{"revision":1e0}',
        b'{"revision":NaN}',
        b'{"revision":Infinity}',
        b'{"revision":-Infinity}',
        b'{"revision":-1}',
        b'{"revision":9007199254740992}',
    ],
    ids=[
        "fraction",
        "exponent",
        "nan",
        "positive-infinity",
        "negative-infinity",
        "negative-counter",
        "unsafe-integer",
    ],
)
def test_rejects_invalid_numbers(raw):
    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b'{"revision":0}', 0),
        (b'{"revision":9007199254740991}', 9007199254740991),
    ],
    ids=["minimum", "maximum"],
)
def test_accepts_counter_boundaries(raw, expected):
    assert decode_manifest_json(raw)["revision"] == expected

@pytest.mark.parametrize(
    ("size", "accepted"),
    [
        (16 * 1024 * 1024, True),
        (16 * 1024 * 1024 + 1, False),
    ],
    ids=["size-limit", "size-limit-exceeded"],
)
def test_document_size_boundary(size, accepted):
    prefix = b'{"padding":"'
    suffix = b'"}'
    padding_size = size - len(prefix) - len(suffix)
    raw = prefix + b"a" * padding_size + suffix

    if accepted:
        document = decode_manifest_json(raw)
        assert document["padding"] == "a" * padding_size
    else:
        with pytest.raises(ManifestInvalid):
            decode_manifest_json(raw)


@pytest.mark.parametrize(
    ("depth", "accepted"),
    [
        (32, True),
        (33, False),
        (2000, False),
    ],
    ids=["depth-limit", "depth-limit-exceeded", "extreme-depth"],
)
def test_document_depth_boundary(depth, accepted):
    array_depth = depth - 1
    raw = (
        b'{"value":'
        + b"[" * array_depth
        + b"0"
        + b"]" * array_depth
        + b"}"
    )

    if accepted:
        document = decode_manifest_json(raw)
        value = document["value"]
        for _ in range(array_depth):
            assert isinstance(value, list)
            assert len(value) == 1
            value = value[0]
        assert value == 0
    else:
        with pytest.raises(ManifestInvalid):
            decode_manifest_json(raw)


def test_brackets_inside_escaped_string_do_not_increase_depth():
    raw = b'{"value":"\\"' + b"[" * 64 + b'\\""}'

    assert decode_manifest_json(raw) == {
        "value": '"' + "[" * 64 + '"',
    }


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":"\\ud800"}',
        b'{"value":[{"nested":"\\udfff"}]}',
        b'{"\\ud800":0}',
        b'{"caf\\u00e9":0}',
        '{"café":0}'.encode("utf-8"),
    ],
    ids=[
        "high-surrogate-value",
        "nested-low-surrogate-value",
        "surrogate-key",
        "escaped-non-ascii-key",
        "utf8-non-ascii-key",
    ],
)
def test_rejects_invalid_manifest_unicode(raw):
    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)


def test_preserves_unicode_values_without_normalization():
    raw = '{"composed":"é","decomposed":"e\u0301","emoji":"😀"}'.encode(
        "utf-8"
    )

    assert decode_manifest_json(raw) == {
        "composed": "é",
        "decomposed": "e\u0301",
        "emoji": "😀",
    }


def test_accepts_json_surrogate_pair_as_unicode_scalar():
    assert decode_manifest_json(b'{"value":"\\ud83d\\ude00"}') == {
        "value": "😀",
    }


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":"\xff"}',
        b'{"value":',
        b'{"value":1,}',
        b'{"value":[0}',
        b'{"value":"unterminated}',
        b'{"value":0}{"value":1}',
        b"[]",
        b"null",
    ],
    ids=[
        "invalid-utf8",
        "truncated-json",
        "trailing-comma",
        "mismatched-containers",
        "unterminated-string",
        "multiple-documents",
        "array-root",
        "null-root",
    ],
)
def test_invalid_json_has_manifest_error(raw):
    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)


def test_escaped_backslash_does_not_hide_following_containers():
    raw = b'{"value":"\\\\","nested":' + b"[" * 32 + b"0" + b"]" * 32 + b"}"

    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)


def test_mixed_containers_share_depth_limit():
    raw = b'{"value":' + b'{"nested":[' * 16 + b"0" + b"]}" * 16 + b"}"

    with pytest.raises(ManifestInvalid):
        decode_manifest_json(raw)
