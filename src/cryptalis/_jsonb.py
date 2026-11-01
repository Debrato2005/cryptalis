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


def _canonical(value, *, equality=False):
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
            number = format(numeric_value(part), 'f')
            if equality and '.' in number:
                number = number.rstrip('0').rstrip('.')
            encoded = number.encode('ascii')
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


def jsonb_search_bytes(encoded: bytes) -> bytes:
    """Preserve native structure while ignoring only fractional numeric scale."""
    value = JsonbValue(encoded)
    return _canonical(_parse(value.data.decode('utf8')), equality=True)


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


def jsonb_default(value):
    """Pin a native literal without losing Python types or dictionary key order."""
    from sqlalchemy import JSON
    try:
        jsonb_value(None if value is JSON.NULL else value)
        tokens, pending = [], [value]
        while pending:
            part = pending.pop()
            kind = type(part)
            if part is JSON.NULL:
                if tokens:
                    raise InvalidValue()
                tokens.append(['json-null'])
            elif part is None:
                tokens.append(['none'])
            elif kind is bool:
                tokens.append(['bool', part])
            elif kind is str:
                tokens.append(['str', part.encode('utf8', 'surrogatepass').hex()])
            elif kind is int:
                tokens.append(['int', str(part)])
            elif kind is float:
                tokens.append(['float', part.hex()])
            elif kind in (list, tuple):
                tokens.append(['list' if kind is list else 'tuple', len(part)])
                pending.extend(reversed(part))
            elif kind is dict:
                tokens.append(['dict', len(part)])
                for key, item in reversed(tuple(part.items())):
                    if type(key) not in (str, int, float, bool, type(None)):
                        raise InvalidValue()
                    pending.extend((item, key))
            else:
                raise InvalidValue()
        raw = json.dumps(tokens, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        if len(raw.encode('utf8')) > _MAX_BYTES:
            raise InvalidValue()
        return raw
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise InvalidValue() from None


def read_jsonb_default(raw):
    """Read only the canonical bounded literal encoding emitted above."""
    from sqlalchemy import JSON
    try:
        if type(raw) is not str or not 0 < len(raw.encode('utf8')) <= _MAX_BYTES:
            raise InvalidValue()
        tokens = json.loads(raw)
        if type(tokens) is not list:
            raise InvalidValue()
        values = []
        for token in reversed(tokens):
            if type(token) is not list or not token or type(token[0]) is not str:
                raise InvalidValue()
            kind = token[0]
            if len(token) == 1 and kind in ('none', 'json-null'):
                value = JSON.NULL if kind == 'json-null' else None
            elif len(token) == 2:
                part = token[1]
                if kind == 'bool' and type(part) is bool:
                    value = part
                elif kind == 'str' and type(part) is str:
                    value = bytes.fromhex(part).decode('utf8', 'surrogatepass')
                elif kind == 'int' and type(part) is str:
                    value = int(part)
                elif kind == 'float' and type(part) is str:
                    value = float.fromhex(part)
                elif kind in ('list', 'tuple', 'dict') and type(part) is int and part >= 0:
                    count = part * (2 if kind == 'dict' else 1)
                    if count > len(values):
                        raise InvalidValue()
                    items = [values.pop() for _ in range(count)]
                    if kind == 'dict':
                        value = dict(zip(items[::2], items[1::2]))
                        if len(value) != part:
                            raise InvalidValue()
                    else:
                        value = tuple(items) if kind == 'tuple' else items
                else:
                    raise InvalidValue()
            else:
                raise InvalidValue()
            values.append(value)
        if len(values) != 1 or jsonb_default(values[0]) != raw:
            raise InvalidValue()
        return values[0]
    except (TypeError, ValueError, OverflowError, RecursionError):
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
