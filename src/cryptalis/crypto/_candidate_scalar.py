"""Bounded candidate scalar syntax without authentication or field-policy admission."""

from decimal import Context, Decimal, InvalidOperation
from struct import Struct
from typing import cast

from ._candidate_envelope import (
    EnvelopeInvalid as EnvelopeInvalid,
    EnvelopeMalformed,
    EnvelopeOversize,
    EnvelopeUnsupportedFormat,
    _MAX_CIPHERTEXT_BYTES as _MAX_SCALAR_BYTES,
)


_HEADER = Struct(">BI")
_DECIMAL_HEADER = Struct(">BiI")
_MAX_VALUE_BYTES = _MAX_SCALAR_BYTES - _HEADER.size
_MAX_DIGITS = 1024
_MAX_SCALE = 1024
_INTEGER_LIMIT = 10**_MAX_DIGITS


def _encode_integer(value: int) -> bytes:
    if not -_INTEGER_LIMIT < value < _INTEGER_LIMIT:
        raise EnvelopeOversize("Scalar integer exceeds the digit limit.")
    magnitude = abs(value)
    digits = bytearray()
    while magnitude:
        magnitude, digit = divmod(magnitude, 10)
        digits.append(48 + digit)
    digits.reverse()
    return (b"-" if value < 0 else b"") + (bytes(digits) if digits else b"0")


def _encode_decimal(value: Decimal) -> bytes:
    if not value.is_finite():
        raise EnvelopeMalformed("Scalar decimal must be finite.")
    # Equal exponents prevent rounding. Bound coefficient allocation before as_tuple.
    context = Context(
        prec=_MAX_DIGITS,
        Emin=-_MAX_SCALE,
        Emax=_MAX_SCALE + _MAX_DIGITS - 1,
        traps=[InvalidOperation],
        clamp=0,
    )
    try:
        bounded = value.quantize(value, context=context)
    except InvalidOperation as error:
        raise EnvelopeOversize("Scalar decimal exceeds the representation limits.") from error
    sign, digits, exponent = bounded.as_tuple()
    scale = -cast(int, exponent)
    if not -_MAX_SCALE <= scale <= _MAX_SCALE:
        raise EnvelopeOversize("Scalar decimal scale exceeds the limit.")
    coefficient = bytes(48 + digit for digit in digits)
    return _DECIMAL_HEADER.pack(sign, scale, len(coefficient)) + coefficient


def encode_candidate_scalar(
    codec_entry_id: int, value: str | bytes | int | Decimal | None
) -> bytes:
    """Encode candidate scalar syntax without field-policy admission or encryption.

    Exact types are required. Returned bytes contain the unprotected value.
    """
    if type(codec_entry_id) is not int:
        raise EnvelopeMalformed("Scalar encoder requires an integer codec selector.")
    if codec_entry_id not in (1, 2, 3, 4):
        raise EnvelopeUnsupportedFormat("Scalar encoder does not support this codec.")
    if value is None:
        return _HEADER.pack(0, 0)

    expected_type = (str, bytes, int, Decimal)[codec_entry_id - 1]
    if type(value) is not expected_type:
        raise EnvelopeMalformed("Scalar value type does not match the codec.")
    if codec_entry_id == 1:
        text = cast(str, value)
        if len(text) > _MAX_VALUE_BYTES:
            raise EnvelopeOversize("Scalar text exceeds the size limit.")
        try:
            payload = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise EnvelopeMalformed("Scalar text contains invalid Unicode.") from error
    elif codec_entry_id == 2:
        payload = cast(bytes, value)
    elif codec_entry_id == 3:
        payload = _encode_integer(cast(int, value))
    else:
        payload = _encode_decimal(cast(Decimal, value))
    if len(payload) > _MAX_VALUE_BYTES:
        raise EnvelopeOversize("Scalar value exceeds the size limit.")
    return _HEADER.pack(1, len(payload)) + payload


def _canonical_coefficient(raw: bytes) -> bool:
    return (
        bool(raw)
        and (len(raw) == 1 or raw[0] != 48)
        and all(48 <= digit <= 57 for digit in raw)
    )


def _decode_integer(raw: bytes) -> int:
    negative = raw.startswith(b"-")
    digits = raw[1:] if negative else raw
    if len(digits) > _MAX_DIGITS:
        raise EnvelopeOversize("Scalar integer exceeds the digit limit.")
    if not _canonical_coefficient(digits) or (negative and digits == b"0"):
        raise EnvelopeMalformed("Scalar integer contains a noncanonical value.")

    value = 0
    for digit in digits:
        value = value * 10 + digit - 48
    return -value if negative else value


def _decode_decimal(raw: bytes) -> Decimal:
    if len(raw) < _DECIMAL_HEADER.size:
        raise EnvelopeMalformed("Scalar decimal header is incomplete.")
    sign, scale, coefficient_length = _DECIMAL_HEADER.unpack_from(raw)
    if sign not in (0, 1):
        raise EnvelopeMalformed("Scalar decimal sign is invalid.")
    if not -_MAX_SCALE <= scale <= _MAX_SCALE:
        raise EnvelopeOversize("Scalar decimal scale exceeds the limit.")
    if coefficient_length > _MAX_DIGITS:
        raise EnvelopeOversize("Scalar decimal coefficient exceeds the digit limit.")
    if len(raw) != _DECIMAL_HEADER.size + coefficient_length:
        raise EnvelopeMalformed("Scalar decimal coefficient length is invalid.")
    coefficient = raw[_DECIMAL_HEADER.size:]
    if not _canonical_coefficient(coefficient):
        raise EnvelopeMalformed("Scalar decimal coefficient contains a noncanonical value.")

    return Decimal((sign, tuple(digit - 48 for digit in coefficient), -scale))


def decode_candidate_scalar(
    codec_entry_id: int, raw: bytes
) -> str | bytes | int | Decimal | None:
    """Decode candidate scalar syntax without authentication or descriptor admission.

    The caller must authenticate bytes and approve field constraints before release.
    """
    if type(codec_entry_id) is not int:
        raise EnvelopeMalformed("Scalar decoder requires an integer codec selector.")
    if codec_entry_id not in (1, 2, 3, 4):
        raise EnvelopeUnsupportedFormat("Scalar decoder does not support this codec.")
    if type(raw) is not bytes:
        raise EnvelopeMalformed("Scalar decoder input must be immutable bytes.")
    if len(raw) > _MAX_SCALAR_BYTES:
        raise EnvelopeOversize("Scalar record exceeds the size limit.")
    if len(raw) < _HEADER.size:
        raise EnvelopeMalformed("Scalar header is incomplete.")

    state, value_length = _HEADER.unpack_from(raw)
    if state not in (0, 1):
        raise EnvelopeMalformed("Scalar state is invalid.")
    if value_length > _MAX_VALUE_BYTES:
        raise EnvelopeOversize("Scalar declared length exceeds the size limit.")
    if len(raw) != _HEADER.size + value_length:
        raise EnvelopeMalformed("Scalar total length is invalid.")
    if state == 0:
        if value_length != 0:
            raise EnvelopeMalformed("Scalar null length must be zero.")
        return None

    value = raw[_HEADER.size:]
    if codec_entry_id == 1:
        try:
            return value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise EnvelopeMalformed("Scalar text contains invalid UTF-8.") from error
    if codec_entry_id == 2:
        return value
    if codec_entry_id == 3:
        return _decode_integer(value)
    if codec_entry_id == 4:
        return _decode_decimal(value)
    raise EnvelopeUnsupportedFormat("Scalar decoder does not support this codec.")
