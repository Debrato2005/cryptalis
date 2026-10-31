"""Finite native NUMERIC admission and context-independent decimal conversion."""
from decimal import Context, Decimal, InvalidOperation, ROUND_HALF_UP, localcontext

from .crypto.keys import InvalidValue, RepresentationMismatch


class NumericOverflow(InvalidValue):
    """A finite value exceeds the native NUMERIC storage domain."""


def numeric_parameters(typmod):
    if typmod == '-1':
        return None
    if type(typmod) is not str or not typmod.isascii() or not typmod.isdecimal():
        raise ValueError
    number = int(typmod) - 4
    precision = (number >> 16) & 65535
    scale = number & 2047
    scale = scale - 2048 if scale >= 1024 else scale
    if (not 1 <= precision <= 1000 or not -1000 <= scale <= 1000
            or typmod != str(((precision << 16) | (scale & 2047)) + 4)):
        raise ValueError
    return precision, scale


def numeric_typmod(precision, scale):
    if precision is None and scale is None:
        return '-1'
    scale = 0 if scale is None else scale
    if type(precision) is not int or type(scale) is not int or not 1 <= precision <= 1000 or not -1000 <= scale <= 1000:
        raise ValueError
    return str(((precision << 16) | (scale & 2047)) + 4)


def numeric_value(value, typmod='-1'):
    """Match finite NUMERIC coercion; caller context/traps never affect rounding."""
    if value is None:
        return None
    if type(value) is int:
        value = Decimal(value)
    if type(value) is not Decimal or not value.is_finite():
        raise InvalidValue()
    if value.is_zero() and value.as_tuple().exponent > 0:
        value = Decimal(0)
    digits = value.as_tuple()
    if len(digits.digits) > 147455 or value.adjusted() >= 131072 or digits.exponent < -16383:
        raise NumericOverflow()
    parameters = numeric_parameters(typmod)
    if parameters is not None:
        precision, scale = parameters
        context = Context(prec=max(len(digits.digits), precision) + abs(scale) + 2,
                          rounding=ROUND_HALF_UP, Emin=-999999, Emax=999999,
                          capitals=1, clamp=0, flags=[], traps=[InvalidOperation])
        try:
            with localcontext(context):
                value = value.quantize(Decimal((0, (1,), -scale)))
        except InvalidOperation:
            raise NumericOverflow() from None
        if not value.is_zero() and value.adjusted() >= precision - scale:
            raise NumericOverflow()
    if value.is_zero():
        value = value.copy_abs()
    # Native numeric output has no positive exponent, preserving fractional scale.
    return Decimal(format(value, 'f'))


def numeric_sql_type(typmod):
    parameters = numeric_parameters(typmod)
    return 'pg_catalog.numeric' + (f'({parameters[0]},{parameters[1]})' if parameters else '')


def validate_numeric(value, typmod):
    """Authenticated storage must already have the pinned native scale and range."""
    if value is not None:
        try:
            if numeric_value(value, typmod).as_tuple() != value.as_tuple():
                raise RepresentationMismatch()
        except InvalidValue:
            raise RepresentationMismatch() from None
    return value
