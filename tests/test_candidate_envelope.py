"""F1 structural vectors. These bytes contain no authenticated ciphertext."""

import importlib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


# Hand-encoded from the candidate offset table, without a production encoder.
_HEADER = bytes.fromhex(
    "43525950" "01" "01" "0000" "006c" "0c" "10" "00000005"
    "00112233445566778899aabbccddeeff"
    "0000000000000001"
    "b96d954389cb35bb7ccd4d59cac9ccf70cb0028a4073fae3fd4057587663417f"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "0001" "0001"
)
_NONCE = bytes.fromhex("202122232425262728292a2b")
_CIPHERTEXT = bytes.fromhex("3031323334")
_TAG = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
_ENVELOPE = _HEADER + _NONCE + _CIPHERTEXT + _TAG


def _api():
    return importlib.import_module("cryptalis.crypto._candidate_envelope")


def _replace(raw, offset, value):
    return raw[:offset] + value + raw[offset + len(value):]


def test_candidate_parser_extracts_exact_unauthenticated_bytes():
    fixture = (
        Path(__file__).parent.parent / "examples" / "envelopes" / "f1-structural.hex"
    )
    result = _api().parse_candidate_envelope(bytes.fromhex(fixture.read_text()))

    assert result.header == _HEADER
    assert result.suite_id == 1
    assert result.subject_key_handle == bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    assert result.subject_generation == 1
    assert result.creation_policy_digest == bytes.fromhex(
        "b96d954389cb35bb7ccd4d59cac9ccf70cb0028a4073fae3fd4057587663417f"
    )
    assert result.value_seed == bytes(range(32))
    assert result.codec_entry_id == 1
    assert result.aad_binding_version == 1
    assert result.nonce == _NONCE
    assert result.ciphertext == _CIPHERTEXT
    assert result.tag == _TAG
    with pytest.raises(FrozenInstanceError):
        result.subject_generation = 2


@pytest.mark.parametrize("suite_id,nonce_length", [(1, 12), (2, 12), (3, 24), (4, 12)])
def test_candidate_suites_require_their_declared_nonce_length(suite_id, nonce_length):
    api = _api()
    header = _replace(_HEADER, 5, bytes([suite_id]))
    header = _replace(header, 10, bytes([nonce_length]))
    nonce = bytes(range(nonce_length))

    result = api.parse_candidate_envelope(header + nonce + _CIPHERTEXT + _TAG)

    assert result.suite_id == suite_id
    assert result.nonce == nonce
    assert result.ciphertext == _CIPHERTEXT
    wrong_length = 12 if nonce_length == 24 else 24
    wrong_header = _replace(header, 10, bytes([wrong_length]))
    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_envelope(
            wrong_header + bytes(wrong_length) + _CIPHERTEXT + _TAG
        )


@pytest.mark.parametrize(
    "offset,value,error_name",
    [
        (0, b"NOPE", "EnvelopeMalformed"),
        (4, b"\x00", "EnvelopeUnsupportedFormat"),
        (4, b"\x02", "EnvelopeUnsupportedFormat"),
        (5, b"\x00", "EnvelopeUnsupportedFormat"),
        (5, b"\xff", "EnvelopeUnsupportedFormat"),
        (6, b"\x00\x01", "EnvelopeUnsupportedFormat"),
        (6, b"\x80\x00", "EnvelopeUnsupportedFormat"),
        (8, b"\x00\x6b", "EnvelopeMalformed"),
        (8, b"\x00\x6d", "EnvelopeMalformed"),
        (10, b"\x00", "EnvelopeMalformed"),
        (11, b"\x0f", "EnvelopeMalformed"),
        (11, b"\x11", "EnvelopeMalformed"),
        (12, b"\x00\x00\x00\x00", "EnvelopeMalformed"),
        (12, b"\x00\x00\x00\x04", "EnvelopeMalformed"),
        (12, b"\xff\xff\xff\xff", "EnvelopeOversize"),
        (32, bytes(8), "EnvelopeMalformed"),
        (104, b"\x00\x00", "EnvelopeUnsupportedFormat"),
        (104, b"\x00\x05", "EnvelopeUnsupportedFormat"),
        (104, b"\xff\xff", "EnvelopeUnsupportedFormat"),
        (106, b"\x00\x00", "EnvelopeUnsupportedFormat"),
        (106, b"\x00\x02", "EnvelopeUnsupportedFormat"),
    ],
)
def test_candidate_parser_rejects_invalid_headers(offset, value, error_name):
    api = _api()
    raw = _replace(_ENVELOPE, offset, value)

    with pytest.raises(getattr(api, error_name)):
        api.parse_candidate_envelope(raw)


@pytest.mark.parametrize("size", [0, 4, 16, 107, 108, 119, 120, 124, 125, 140])
def test_candidate_parser_rejects_truncated_header_and_body(size):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_envelope(_ENVELOPE[:size])


@pytest.mark.parametrize("declared_length", [6, 1048576])
def test_candidate_parser_rejects_body_shorter_than_declared_length(declared_length):
    api = _api()
    raw = _replace(_ENVELOPE, 12, declared_length.to_bytes(4, "big"))

    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_envelope(raw)


def test_candidate_parser_rejects_trailing_bytes_without_echo():
    api = _api()

    with pytest.raises(api.EnvelopeMalformed) as error:
        api.parse_candidate_envelope(_ENVELOPE + b"do-not-echo-value")
    assert "do-not-echo-value" not in str(error.value)


@pytest.mark.parametrize("codec_entry_id", [1, 2, 3, 4])
def test_candidate_parser_recognizes_only_the_candidate_scalar_codecs(codec_entry_id):
    raw = _replace(_ENVELOPE, 104, codec_entry_id.to_bytes(2, "big"))

    assert _api().parse_candidate_envelope(raw).codec_entry_id == codec_entry_id


def test_candidate_parser_preserves_maximum_unsigned_generation():
    raw = _replace(_ENVELOPE, 32, b"\xff" * 8)

    assert _api().parse_candidate_envelope(raw).subject_generation == 2**64 - 1


@pytest.mark.parametrize("suite_id,nonce_length", [(1, 12), (3, 24)])
def test_candidate_parser_accepts_exact_payload_size_limit(suite_id, nonce_length):
    header = _replace(_HEADER, 5, bytes([suite_id]))
    header = _replace(header, 10, bytes([nonce_length]))
    header = _replace(header, 12, (1048576).to_bytes(4, "big"))
    raw = header + bytes(nonce_length) + b"c" * 1048576 + _TAG

    result = _api().parse_candidate_envelope(raw)

    assert result.ciphertext == b"c" * 1048576
    assert result.tag == _TAG


@pytest.mark.parametrize("suite_id,nonce_length", [(1, 12), (3, 24)])
def test_candidate_parser_rejects_payload_above_limit(suite_id, nonce_length):
    api = _api()
    header = _replace(_HEADER, 5, bytes([suite_id]))
    header = _replace(header, 10, bytes([nonce_length]))
    header = _replace(header, 12, (1048577).to_bytes(4, "big"))
    raw = header + bytes(nonce_length) + b"c" * 1048577 + _TAG

    with pytest.raises(api.EnvelopeOversize):
        api.parse_candidate_envelope(raw)


def test_candidate_parser_rejects_oversize_before_header_interpretation():
    api = _api()

    with pytest.raises(api.EnvelopeOversize):
        api.parse_candidate_envelope(b"x" * 1048725)


@pytest.mark.parametrize("raw", [None, "CRYP", bytearray(_ENVELOPE), memoryview(_ENVELOPE)])
def test_candidate_parser_requires_immutable_bytes(raw):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_envelope(raw)


def test_candidate_parser_does_not_claim_authentication():
    altered = _replace(_ENVELOPE, 40, b"\xff" * 32)
    altered = _replace(altered, len(altered) - 16, b"\xff" * 16)

    result = _api().parse_candidate_envelope(altered)

    assert result.creation_policy_digest == b"\xff" * 32
    assert result.tag == b"\xff" * 16


def test_candidate_result_repr_excludes_ciphertext_bytes():
    marker = b"do-not-echo-value"
    header = _replace(_HEADER, 12, len(marker).to_bytes(4, "big"))
    result = _api().parse_candidate_envelope(header + _NONCE + marker + _TAG)

    assert result.ciphertext == marker
    assert marker.decode() not in repr(result)
