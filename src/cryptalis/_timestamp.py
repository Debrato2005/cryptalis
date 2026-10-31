"""Finite aware timestamp inputs and reproducible literal defaults."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from .crypto.keys import InvalidValue


def aware_value(value):
    if value is None:
        return None
    if type(value) is not datetime or type(value.tzinfo) not in (timezone, ZoneInfo):
        raise InvalidValue()
    try:
        if value.utcoffset().microseconds:
            raise InvalidValue()
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise InvalidValue() from None


def aware_default(value):
    if value is None:
        raise InvalidValue()
    aware_value(value)
    zone = value.tzinfo.key if type(value.tzinfo) is ZoneInfo else None
    name = value.tzname() if zone is None else None
    if (type(value.tzinfo) is ZoneInfo and type(zone) is not str or
            zone is not None and len(zone) > 255 or name is not None and len(name) > 128):
        raise ValueError
    return {'iso': value.isoformat(timespec='microseconds'), 'zone': zone,
            'name': name, 'fold': value.fold}


def read_aware_default(raw):
    if (type(raw) is not dict or set(raw) != {'iso', 'zone', 'name', 'fold'} or
            type(raw['iso']) is not str or len(raw['iso']) > 42 or
            type(raw['fold']) is not int or raw['fold'] not in (0, 1) or
            raw['zone'] is not None and (type(raw['zone']) is not str or len(raw['zone']) > 255) or
            raw['name'] is not None and (type(raw['name']) is not str or len(raw['name']) > 128)):
        raise ValueError
    try:
        value = datetime.fromisoformat(raw['iso'])
        zone = ZoneInfo(raw['zone']) if raw['zone'] is not None else timezone(value.utcoffset(), raw['name'])
        value = value.replace(tzinfo=zone, fold=raw['fold'])
        if aware_default(value) != raw:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, InvalidValue):
        raise ValueError from None


def datetime_state(value):
    """Datetime equality alone ignores fold when both values share a timezone."""
    return (value.year, value.month, value.day, value.hour, value.minute, value.second,
            value.microsecond, value.fold, type(value.tzinfo), id(value.tzinfo),
            value.tzinfo, value.utcoffset())
