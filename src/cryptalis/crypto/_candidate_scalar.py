"""Bounded candidate scalar decoding without authentication or field-policy admission."""

from decimal import Decimal
from struct import Struct

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
