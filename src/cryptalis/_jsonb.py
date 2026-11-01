"""Lossless PostgreSQL JSONB text at the encrypted storage boundary."""
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
import json

from ._numeric import numeric_value
from .crypto.keys import InvalidValue, RepresentationMismatch


_MAX_BYTES = 16 * 1024 * 1024


def _constant(value):
    raise InvalidValue()


def _parse(text):
    try:
        return json.loads(text, parse_int=Decimal, parse_float=Decimal, parse_constant=_constant)
    except (ValueError, InvalidOperation, RecursionError):
        raise InvalidValue() from None


def _string(value):
    if '\x00' in value:
        raise InvalidValue()
    try:
        return json.dumps(value, ensure_ascii=False).encode('utf8')
    except UnicodeError:
        raise InvalidValue() from None


def _canonical(value):
    # Iteration adds no recursion limit below the native stdlib JSON parser.
    output, size, pending = [], 0, [(False, value)]
    while pending:
        literal, part = pending.pop()
        if literal:
            encoded = part
        elif part is None:
            encoded = b'null'
        elif type(part) is bool:
            encoded = b'true' if part else b'false'
        elif type(part) is str:
            encoded = _string(part)
        elif type(part) is Decimal:
            encoded = format(numeric_value(part), 'f').encode('ascii')
        elif type(part) is list:
            encoded = b'['
            pending.append((True, b']'))
            for index in range(len(part) - 1, -1, -1):
                pending.append((False, part[index]))
                if index:
                    pending.append((True, b', '))
        elif type(part) is dict:
            encoded = b'{'
            # jsonb uses UTF-8 byte length first, then bytewise key ordering.
            keys = [(key.encode('utf8'), key) for key in part]
            keys.sort(key=lambda item: (len(item[0]), item[0]))
            pending.append((True, b'}'))
            for index in range(len(keys) - 1, -1, -1):
                key = keys[index][1]
                pending.append((False, part[key]))
                pending.append((True, b': '))
                pending.append((True, _string(key)))
                if index:
                    pending.append((True, b', '))
        else:
            raise InvalidValue()
        size += len(encoded)
        if size > _MAX_BYTES:
            raise InvalidValue()
        output.append(encoded)
    return b''.join(output)


@dataclass(frozen=True)
class JsonbValue:
    """A native canonical document, distinct from SQL NULL and lossy app values."""
    data: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.data) is not bytes or not 0 < len(self.data) <= _MAX_BYTES:
            raise InvalidValue()
        try:
            parsed = _parse(self.data.decode('utf8'))
            if _canonical(parsed) != self.data:
                raise RepresentationMismatch()
        except UnicodeError:
            raise InvalidValue() from None

    def to_python(self):
        # Match the admitted native JSON loader only at the application edge.
        return json.loads(self.data)


def jsonb_value(value):
    """Apply native stdlib input coercions, then retain exact JSONB numbers."""
    try:
        text = json.dumps(value)
    except TypeError:
        raise TypeError('Invalid native JSONB assignment. Roll back before retry.') from None
    except (ValueError, OverflowError, RecursionError):
        raise InvalidValue() from None
    try:
        return JsonbValue(_canonical(_parse(text)))
    except UnicodeError:
        raise InvalidValue() from None


def native_json_adapters(adapters):
    """Recognize the pinned driver's effective JSON hooks, including globals."""
    from psycopg.adapt import PyFormat
    from psycopg.pq import Format
    from psycopg.types import json as native
    for oid, text, binary in ((114, native.JsonLoader, native.JsonBinaryLoader),
                              (3802, native.JsonbLoader, native.JsonbBinaryLoader)):
        for format_, expected in ((Format.TEXT, text), (Format.BINARY, binary)):
            actual = adapters.get_loader(oid, format_)
            if actual is not expected or actual._loads is not json.loads:
                return False
    for wrapper, text, binary in ((native.Json, native.JsonDumper, native.JsonBinaryDumper),
                                  (native.Jsonb, native.JsonbDumper, native.JsonbBinaryDumper)):
        for format_, expected in ((PyFormat.AUTO, text), (PyFormat.TEXT, text), (PyFormat.BINARY, binary)):
            actual = adapters.get_dumper(wrapper, format_)
            if actual is not expected or actual._dumps is not json.dumps:
                return False
    return True
