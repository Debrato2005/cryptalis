"""Candidate scalar vectors. These bytes contain no authenticated ciphertext."""

import importlib
import json
import sys
from decimal import Decimal, localcontext
from pathlib import Path

import pytest


_VECTORS = json.loads(
    (Path(__file__).parent.parent / "examples/scalars/candidate-vectors.json").read_text()
)


def _api():
    return importlib.import_module("cryptalis.crypto._candidate_scalar")


def _record(payload, state=1):
    return bytes([state]) + len(payload).to_bytes(4, "big") + payload


def _decimal_record(sign, scale, coefficient):
    return _record(
        bytes([sign]) + scale.to_bytes(4, "big", signed=True)
        + len(coefficient).to_bytes(4, "big") + coefficient
    )


@pytest.mark.parametrize("vector", _VECTORS)
def test_scalar_decoder_preserves_fixed_typed_vectors(vector):
    result = _api().decode_candidate_scalar(vector["codec"], bytes.fromhex(vector["hex"]))

    if "decimal_tuple" in vector:
        sign, digits, exponent = vector["decimal_tuple"]
        assert type(result) is Decimal
        assert result.as_tuple() == (sign, tuple(digits), exponent)
    elif "bytes_hex" in vector:
        assert type(result) is bytes
        assert result == bytes.fromhex(vector["bytes_hex"])
    else:
        assert type(result) is type(vector["value"])
        assert result == vector["value"]


@pytest.mark.parametrize("codec", [1, 2, 3, 4])
def test_scalar_null_requires_an_exact_empty_frame(codec):
    api = _api()

    assert api.decode_candidate_scalar(codec, bytes(5)) is None
    for raw in (bytes(4), bytes(6), _record(b"x", state=0)):
        with pytest.raises(api.EnvelopeMalformed):
            api.decode_candidate_scalar(codec, raw)


@pytest.mark.parametrize("codec", [0, 5, 65535, -1])
def test_scalar_unknown_codec_cannot_bypass_validation_with_null(codec):
    api = _api()

    with pytest.raises(api.EnvelopeUnsupportedFormat):
        api.decode_candidate_scalar(codec, bytes(5))


@pytest.mark.parametrize("codec", [True, False, 1.0, "1", None])
def test_scalar_selector_has_no_implicit_coercion(codec):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.decode_candidate_scalar(codec, bytes(5))


@pytest.mark.parametrize("raw", [None, "hello", bytearray(5), memoryview(bytes(5))])
def test_scalar_requires_immutable_input_bytes(raw):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.decode_candidate_scalar(1, raw)


@pytest.mark.parametrize("state", [2, 255])
def test_scalar_unknown_state_does_not_substitute_null(state):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.decode_candidate_scalar(1, _record(b"", state=state))


def test_scalar_rejects_truncation_length_mismatch_and_trailing_bytes():
    api = _api()
    raw = bytes.fromhex("010000000568656c6c6f")

    for size in range(len(raw)):
        with pytest.raises(api.EnvelopeMalformed):
            api.decode_candidate_scalar(1, raw[:size])
    for bad in (raw + b"x", b"\x01\x00\x00\x00\x04hello"):
        with pytest.raises(api.EnvelopeMalformed):
            api.decode_candidate_scalar(1, bad)
    with pytest.raises(api.EnvelopeOversize):
        api.decode_candidate_scalar(1, b"\x01\xff\xff\xff\xff")


@pytest.mark.parametrize("codec,payload_byte", [(1, b"x"), (2, b"\xff")])
def test_scalar_enforces_the_encoded_mebibyte_limit(codec, payload_byte):
    api = _api()
    payload = payload_byte * 1_048_571

    result = api.decode_candidate_scalar(codec, _record(payload))

    assert len(result) == 1_048_571
    with pytest.raises(api.EnvelopeOversize):
        api.decode_candidate_scalar(codec, _record(payload + payload_byte))
    with pytest.raises(api.EnvelopeOversize):
        api.decode_candidate_scalar(codec, bytes(1_048_577))


@pytest.mark.parametrize(
    "payload", [b"\xff", b"\xc0\x80", b"\xe2\x82", b"\xed\xa0\x80", b"\xf4\x90\x80\x80"]
)
def test_scalar_rejects_invalid_utf8_and_preserves_the_original_cause(payload):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed) as error:
        api.decode_candidate_scalar(1, _record(b"do-not-echo-secret" + payload))

    assert isinstance(error.value.__cause__, UnicodeDecodeError)
    assert "do-not-echo-secret" not in str(error.value)
    assert "text" in str(error.value)


@pytest.mark.parametrize(
    "payload", [b"", b"+1", b"01", b"-0", b"-01", b" 1", b"1\n", b"1.0", b"1e2", b"--1", b"\xff"]
)
def test_scalar_integer_requires_minimal_ascii_decimal(payload):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.decode_candidate_scalar(3, _record(payload))


@pytest.mark.parametrize("sign", [b"", b"-"])
def test_scalar_integer_accepts_1024_digits_and_rejects_1025(sign):
    api = _api()

    result = api.decode_candidate_scalar(3, _record(sign + b"9" * 1024))

    magnitude = 10**1024 - 1
    assert result == (-magnitude if sign else magnitude)
    with pytest.raises(api.EnvelopeOversize):
        api.decode_candidate_scalar(3, _record(sign + b"9" * 1025))


def test_scalar_integer_is_independent_of_the_interpreter_string_digit_limit():
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        result = _api().decode_candidate_scalar(3, _record(b"9" * 1024))
        assert result == 10**1024 - 1
        assert sys.get_int_max_str_digits() == 640
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize("scale", [-1024, 1024])
@pytest.mark.parametrize("sign", [0, 1])
def test_scalar_decimal_preserves_digit_and_scale_bounds_without_context_rounding(scale, sign):
    raw = _decimal_record(sign, scale, b"9" * 1024)
    with localcontext() as context:
        context.prec = 1
        context.Emax = 1
        context.Emin = -1
        for signal in context.traps:
            context.traps[signal] = True

        result = _api().decode_candidate_scalar(4, raw)

        assert result.as_tuple() == (sign, (9,) * 1024, -scale)


@pytest.mark.parametrize("scale", [-2147483648, -1025, 1025, 2147483647])
def test_scalar_decimal_rejects_scale_outside_the_candidate_range(scale):
    api = _api()

    with pytest.raises(api.EnvelopeOversize):
        api.decode_candidate_scalar(4, _decimal_record(0, scale, b"1"))


@pytest.mark.parametrize("coefficient", [b"", b"00", b"01", b"-1", b"+1", b"1.0", b"NaN", b"Infinity", b"\xff"])
def test_scalar_decimal_requires_a_minimal_unsigned_ascii_coefficient(coefficient):
    api = _api()

    with pytest.raises(api.EnvelopeMalformed):
        api.decode_candidate_scalar(4, _decimal_record(0, 0, coefficient))


def test_scalar_decimal_rejects_invalid_nested_framing_without_partial_values():
    api = _api()
    body = bytes.fromhex("0000000002000000053132333030")

    for size in range(len(body)):
        with pytest.raises(api.EnvelopeMalformed):
            api.decode_candidate_scalar(4, _record(body[:size]))
    for bad in (
        b"\x02" + body[1:], body + b"x",
        body[:5] + (4).to_bytes(4, "big") + body[9:],
    ):
        with pytest.raises(api.EnvelopeMalformed):
            api.decode_candidate_scalar(4, _record(bad))
    for bad in (
        _decimal_record(0, 0, b"1" * 1025),
        _record(body[:5] + b"\xff\xff\xff\xff"),
    ):
        with pytest.raises(api.EnvelopeOversize):
            api.decode_candidate_scalar(4, bad)


def test_scalar_syntax_does_not_authenticate_a_synthetic_f1_payload():
    scalar = bytes.fromhex("010000000568656c6c6f")
    path = Path(__file__).parent.parent / "examples/envelopes/f1-structural.hex"
    envelope = bytes.fromhex(path.read_text())
    envelope = envelope[:12] + len(scalar).to_bytes(4, "big") + envelope[16:120] + scalar + bytes(16)
    parse = importlib.import_module("cryptalis.crypto._candidate_envelope").parse_candidate_envelope

    untrusted = parse(envelope)

    assert _api().decode_candidate_scalar(untrusted.codec_entry_id, untrusted.ciphertext) == "hello"
    assert untrusted.tag == bytes(16)
