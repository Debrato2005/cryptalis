"""W1 structural vectors. These bytes contain no authenticated ciphertext."""

import importlib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest


# Hand-encoded from the candidate offset table, without a production encoder.
_HEADER = bytes.fromhex(
    "43525957" "01" "01" "01" "00" "0060" "0c" "10"
    "00112233445566778899aabbccddeeff" "0000000000000001"
    "ffeeddccbbaa99887766554433221100" "0000000000000002"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "00000020"
)
_NONCE = bytes.fromhex("202122232425262728292a2b")
_CIPHERTEXT = bytes(range(48, 80))
_TAG = bytes.fromhex("505152535455565758595a5b5c5d5e5f")
_WRAP = _HEADER + _NONCE + _CIPHERTEXT + _TAG


def _api():
    return importlib.import_module("cryptalis.crypto._candidate_wrap")


def _replace(raw, offset, value):
    return raw[:offset] + value + raw[offset + len(value):]


def test_wrap_parser_preserves_exact_unauthenticated_bytes():
    result = _api().parse_candidate_wrap(_WRAP)

    assert result.header == _HEADER
    assert result.suite_id == 1
    assert result.kind == 1
    assert result.parent_branch_handle == bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    assert result.parent_generation == 1
    assert result.child_handle == bytes.fromhex(
        "ffeeddccbbaa99887766554433221100"
    )
    assert result.child_generation == 2
    assert result.wrapper_seed == bytes(range(32))
    assert result.nonce == _NONCE
    assert result.ciphertext == _CIPHERTEXT
    assert result.tag == _TAG
    with pytest.raises(FrozenInstanceError):
        result.parent_generation = 2


@pytest.mark.parametrize("suite_id,nonce_length", [(1, 12), (2, 12), (3, 24), (4, 12)])
@pytest.mark.parametrize("kind", [1, 2])
def test_wrap_suites_and_kinds_require_exact_frame_lengths(suite_id, nonce_length, kind):
    api = _api()
    header = _replace(_HEADER, 5, bytes([suite_id, kind]))
    header = _replace(header, 10, bytes([nonce_length]))
    nonce = bytes(range(nonce_length))
    raw = header + nonce + _CIPHERTEXT + _TAG

    result = api.parse_candidate_wrap(raw)

    assert result.suite_id == suite_id
    assert result.kind == kind
    assert result.nonce == nonce
    assert result.ciphertext == _CIPHERTEXT
    assert result.tag == _TAG
    wrong_length = 12 if nonce_length == 24 else 24
    wrong_header = _replace(header, 10, bytes([wrong_length]))
    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_wrap(wrong_header + bytes(wrong_length) + _CIPHERTEXT + _TAG)
    for size in range(len(raw)):
        with pytest.raises(api.EnvelopeMalformed):
            api.parse_candidate_wrap(raw[:size])
    with pytest.raises(api.EnvelopeInvalid):
        api.parse_candidate_wrap(raw + b"\x00")


@pytest.mark.parametrize(
    "offset,value,error_name",
    [
        (0, b"CRYP", "EnvelopeMalformed"),
        (4, b"\x00", "EnvelopeUnsupportedFormat"),
        (4, b"\x02", "EnvelopeUnsupportedFormat"),
        (5, b"\x00", "EnvelopeUnsupportedFormat"),
        (5, b"\xff", "EnvelopeUnsupportedFormat"),
        (6, b"\x00", "EnvelopeUnsupportedFormat"),
        (6, b"\x03", "EnvelopeUnsupportedFormat"),
        (6, b"\xff", "EnvelopeUnsupportedFormat"),
        (7, b"\x01", "EnvelopeUnsupportedFormat"),
        (7, b"\x80", "EnvelopeUnsupportedFormat"),
        (8, b"\x00\x5f", "EnvelopeMalformed"),
        (8, b"\x00\x61", "EnvelopeMalformed"),
        (8, b"\x60\x00", "EnvelopeMalformed"),
        (10, b"\x00", "EnvelopeMalformed"),
        (11, b"\x0f", "EnvelopeMalformed"),
        (11, b"\x11", "EnvelopeMalformed"),
        (28, bytes(8), "EnvelopeMalformed"),
        (52, bytes(8), "EnvelopeMalformed"),
        (92, b"\x00\x00\x00\x00", "EnvelopeMalformed"),
        (92, b"\x00\x00\x00\x1f", "EnvelopeMalformed"),
        (92, b"\x00\x00\x00\x21", "EnvelopeMalformed"),
        (92, b"\x20\x00\x00\x00", "EnvelopeMalformed"),
        (92, b"\xff\xff\xff\xff", "EnvelopeMalformed"),
    ],
)
def test_wrap_parser_rejects_invalid_headers(offset, value, error_name):
    api = _api()

    with pytest.raises(getattr(api, error_name)) as error:
        api.parse_candidate_wrap(_replace(_WRAP, offset, value))
    assert "W1" in str(error.value)


@pytest.mark.parametrize("offset,field_name", [(4, "version"), (5, "suite"), (7, "flags")])
def test_wrap_unsupported_selector_identifies_the_failed_field(offset, field_name):
    api = _api()

    with pytest.raises(api.EnvelopeUnsupportedFormat) as error:
        api.parse_candidate_wrap(_replace(_WRAP, offset, b"\xff"))

    assert field_name in str(error.value)


def test_wrap_parser_rejects_oversize_before_header_parsing():
    api = _api()

    with pytest.raises(api.EnvelopeOversize):
        api.parse_candidate_wrap(bytes(169))
    with pytest.raises(api.EnvelopeOversize):
        api.parse_candidate_wrap(_WRAP + bytes(16_384))


@pytest.mark.parametrize("raw", [None, "CRYW", bytearray(_WRAP), memoryview(_WRAP)])
def test_wrap_parser_rejects_nonimmutable_input(raw):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.parse_candidate_wrap(raw)


def test_wrap_parser_preserves_maximum_unsigned_generations():
    raw = _replace(_WRAP, 28, b"\xff" * 8)
    raw = _replace(raw, 52, b"\xff" * 8)

    result = _api().parse_candidate_wrap(raw)

    assert result.parent_generation == 2**64 - 1
    assert result.child_generation == 2**64 - 1


def test_wrap_structure_does_not_authenticate_ownership_freshness_or_tag():
    raw = _replace(_WRAP, 12, bytes(16))
    raw = _replace(raw, 36, bytes(16))
    raw = _replace(raw, 60, bytes(32))
    raw = _replace(raw, 96, bytes(12))
    raw = _replace(raw, 140, bytes(16))

    result = _api().parse_candidate_wrap(raw)

    assert result.parent_branch_handle == bytes(16)
    assert result.child_handle == bytes(16)
    assert result.wrapper_seed == bytes(32)
    assert result.nonce == bytes(12)
    assert result.tag == bytes(16)


def test_wrap_diagnostics_and_repr_exclude_all_input_bytes():
    api = _api()
    marker = b"secret-marker-do-not-echo"
    raw = _replace(_WRAP, 108, marker)
    result = api.parse_candidate_wrap(raw)

    assert "secret-marker" not in repr(result)
    for field_name in (
        "header", "parent_branch_handle", "child_handle", "wrapper_seed",
        "nonce", "ciphertext", "tag",
    ):
        assert f"{field_name}=" not in repr(result)
    with pytest.raises(api.EnvelopeMalformed) as error:
        api.parse_candidate_wrap(raw + b"secret")
    assert "secret" not in str(error.value)


def test_wrap_example_matches_the_hand_encoded_vector():
    path = Path(__file__).parent.parent / "examples" / "envelopes" / "w1-structural.hex"

    result = _api().parse_candidate_wrap(bytes.fromhex(path.read_text()))

    assert result.header == _HEADER
    assert result.nonce == _NONCE
    assert result.ciphertext == _CIPHERTEXT
    assert result.tag == _TAG
