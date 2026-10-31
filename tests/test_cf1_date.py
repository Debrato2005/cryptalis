"""Independent DATE encodings protect exact types, domains and CF1 context."""
from datetime import date, datetime
import os
import struct
from uuid import UUID

import pytest

from cryptalis.crypto import cf1
from cryptalis.crypto.keys import AuthenticationFailed, InvalidContext, InvalidValue
from test_cf1 import TENANT, RECORD, setup_keys
from test_cf1_integer import descriptor, document, independent_frame


def date_descriptor():
    return descriptor(dict(document(32), value_codec='pg-date-days-be/v1'))


def test_date_independent_epoch_frames_null_domain_and_context(monkeypatch):
    field = date_descriptor()
    _, ring = setup_keys()
    keys, nonce = ring.prepare(), bytes(range(12))
    monkeypatch.setattr(os, 'urandom', lambda size: nonce if size == 12 else bytes(size))
    # Independently specified PostgreSQL epoch offsets, including leap day.
    for value, days in ((date.min, -730119), (date(1970, 1, 1), -10957),
                        (date(2000, 1, 1), 0), (date(2000, 2, 29), 59),
                        (date.max, 2921939)):
        frame = independent_frame(struct.pack('>i', days), field, nonce)
        assert len(frame) == 46
        assert cf1.seal_value(value, field, TENANT, RECORD, keys) == frame
        actual = cf1.open_value(frame, field, TENANT, RECORD, keys)
        assert type(actual) is date and actual == value
        with pytest.raises(AuthenticationFailed):
            cf1.open_value(frame, field, TENANT, UUID(int=99), keys)
        with pytest.raises(AuthenticationFailed):
            cf1.open_value(frame, descriptor(document(32)), TENANT, RECORD, keys)
        with pytest.raises(InvalidContext):
            cf1.open_text(frame, field, TENANT, RECORD, keys)
    assert cf1.seal_value(None, field, TENANT, RECORD, keys) is None
    assert cf1.open_value(None, field, TENANT, RECORD, keys) is None
    class CustomDate(date): pass
    for value in (datetime(2000, 1, 1), CustomDate(2000, 1, 1), '2000-01-01',
                  b'2000-01-01', 0, False):
        with pytest.raises(InvalidValue):
            cf1.seal_value(value, field, TENANT, RECORD, keys)
    for raw in (b'', b'\0' * 3, b'\0' * 5,
                *(struct.pack('>i', days) for days in (-2147483648, -730120, 2921940, 2147483647))):
        with pytest.raises(InvalidValue):
            cf1.open_value(independent_frame(raw, field, nonce), field, TENANT, RECORD, keys)
    with pytest.raises(InvalidContext):
        descriptor(dict(document(32), value_codec='pg-date-days-be/v1', representation='cf1-packed-equality/v1'))
