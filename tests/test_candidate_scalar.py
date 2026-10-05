"""Candidate scalar vectors. These bytes contain no authenticated ciphertext."""

import importlib
import json
import random
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


@pytest.mark.parametrize("vector", _VECTORS)
def test_scalar_encoder_matches_fixed_wire_vectors(vector):
    if "decimal_tuple" in vector:
        sign, digits, exponent = vector["decimal_tuple"]
        value = Decimal((sign, tuple(digits), exponent))
    elif "bytes_hex" in vector:
        value = bytes.fromhex(vector["bytes_hex"])
    else:
        value = vector["value"]

    raw = _api().encode_candidate_scalar(vector["codec"], value)

    assert type(raw) is bytes
    assert raw == bytes.fromhex(vector["hex"])


@pytest.mark.parametrize("codec", [True, False, 1.0, "1", None])
def test_scalar_encoder_rejects_selector_coercion_even_for_null(codec):
    api = _api()
    with pytest.raises(api.EnvelopeMalformed):
        api.encode_candidate_scalar(codec, None)


@pytest.mark.parametrize("codec", [0, 5, 65535, -1])
def test_scalar_encoder_rejects_unknown_selectors_even_for_null(codec):
    api = _api()
    with pytest.raises(api.EnvelopeUnsupportedFormat):
        api.encode_candidate_scalar(codec, None)


@pytest.mark.parametrize("codec,value", [
    (1, b"secret-canary"), (2, "secret-canary"),
    (2, bytearray(b"secret-canary")), (2, memoryview(b"secret-canary")),
    (3, True), (3, 1.0), (3, "secret-canary"), (3, Decimal("1")),
    (4, 1), (4, 1.0), (4, "secret-canary"),
    (1, type("TextSubclass", (str,), {})("secret-canary")),
    (2, type("BytesSubclass", (bytes,), {})(b"secret-canary")),
    (3, type("IntegerSubclass", (int,), {})(1)),
    (4, type("DecimalSubclass", (Decimal,), {})("1")),
])
def test_scalar_encoder_rejects_mismatched_types_without_echoing_values(codec, value):
    api = _api()
    with pytest.raises(api.EnvelopeMalformed) as error:
        api.encode_candidate_scalar(codec, value)
    assert "secret-canary" not in str(error.value)


@pytest.mark.parametrize("value", ["secret-canary\ud800", "secret-canary\udfff"])
def test_scalar_encoder_rejects_lone_surrogates_with_safe_diagnostics(value):
    api = _api()
    with pytest.raises(api.EnvelopeMalformed) as error:
        api.encode_candidate_scalar(1, value)
    assert "secret-canary" not in str(error.value)
    assert isinstance(error.value.__cause__, UnicodeEncodeError)


@pytest.mark.parametrize("codec,value", [
    (1, "x" * 1_048_571),
    (1, "😀" * 262_142 + "abc"),
    (2, b"\xff" * 1_048_571),
], ids=["text-ascii-limit", "text-utf8-limit", "bytes-limit"])
def test_scalar_encoder_enforces_encoded_byte_limits(codec, value):
    api = _api()
    raw = api.encode_candidate_scalar(codec, value)
    assert len(raw) == 1_048_576
    assert api.decode_candidate_scalar(codec, raw) == value
    extra = b"x" if codec == 2 else "x"
    with pytest.raises(api.EnvelopeOversize):
        api.encode_candidate_scalar(codec, value + extra)


@pytest.mark.parametrize("sign", [1, -1])
def test_scalar_encoder_integer_bounds_survive_the_interpreter_digit_limit(sign):
    api = _api()
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        value = sign * (10**1024 - 1)
        raw = api.encode_candidate_scalar(3, value)
        assert raw == _record((b"-" if sign < 0 else b"") + b"9" * 1024)
        assert api.decode_candidate_scalar(3, raw) == value
        with pytest.raises(api.EnvelopeOversize):
            api.encode_candidate_scalar(3, sign * 10**1024)
        assert sys.get_int_max_str_digits() == 640
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize("sign", [0, 1])
@pytest.mark.parametrize("exponent", [-1024, 1024])
@pytest.mark.parametrize("digits", [(0,), (9,) * 1024])
def test_scalar_encoder_decimal_preserves_representation_without_context_changes(sign, exponent, digits):
    api = _api()
    value = Decimal((sign, digits, exponent))
    with localcontext() as context:
        context.prec = 1
        context.Emax = 1
        context.Emin = -1
        context.clamp = 1
        for signal in context.traps:
            context.traps[signal] = True
        flags = context.flags.copy()
        raw = api.encode_candidate_scalar(4, value)
        result = api.decode_candidate_scalar(4, raw)
        assert result.as_tuple() == value.as_tuple()
        assert context.flags == flags
        assert (context.prec, context.Emax, context.Emin, context.clamp) == (1, 1, -1, 1)
        assert all(context.traps.values())


@pytest.mark.parametrize("value", [
    Decimal("NaN"), Decimal("-NaN123"), Decimal("sNaN"),
    Decimal("Infinity"), Decimal("-Infinity"),
])
def test_scalar_encoder_rejects_nonfinite_decimal_values(value):
    api = _api()
    with pytest.raises(api.EnvelopeMalformed):
        api.encode_candidate_scalar(4, value)


@pytest.mark.parametrize("value", [
    Decimal((0, (1,) * 1025, 0)),
    Decimal((0, (1,) + (0,) * 1024, -1024)),
    Decimal((0, (1,) * 100_000, -99_999)),
    Decimal("1E-1025"), Decimal("1E+1025"),
    Decimal("-0E-1025"), Decimal("-0E+1025"),
    Decimal("1E-999999999"), Decimal("0E+999999999"),
])
def test_scalar_encoder_rejects_decimal_resource_overflow_without_rounding(value):
    api = _api()
    with pytest.raises(api.EnvelopeOversize):
        api.encode_candidate_scalar(4, value)


def test_scalar_codec_round_trips_a_seeded_typed_corpus():
    api = _api()
    rng = random.Random(20261005)
    alphabet = "\x00\ufefféеe\u0301😀\U0010ffff"
    for _ in range(200):
        digits = (rng.randrange(1, 10),) + tuple(rng.randrange(10) for _ in range(rng.randrange(1, 1024)))
        values = [
            "".join(rng.choice(alphabet) for _ in range(rng.randrange(50))),
            rng.randbytes(rng.randrange(50)),
            rng.randrange(-10**1024 + 1, 10**1024),
            Decimal((rng.randrange(2), digits, rng.randrange(-1024, 1025))),
        ]
        for codec, value in enumerate(values, 1):
            raw = api.encode_candidate_scalar(codec, value)
            result = api.decode_candidate_scalar(codec, raw)
            assert type(result) is type(value)
            if codec == 4:
                assert result.as_tuple() == value.as_tuple()
            else:
                assert result == value
            assert api.encode_candidate_scalar(codec, result) == raw
