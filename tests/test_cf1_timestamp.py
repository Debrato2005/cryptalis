"""Native PostgreSQL binary values and independent CF1 framing are the oracle."""
from datetime import date, datetime, timezone
import os
import struct
from uuid import UUID

import pytest

from cryptalis.crypto import cf1
from cryptalis.crypto.keys import AuthenticationFailed, InvalidContext, InvalidValue
from test_cf1 import TENANT, RECORD, setup_keys
from test_cf1_integer import descriptor, document, independent_frame
from test_migration import engine


def test_timestamp_native_binary_vectors_and_independent_frames(monkeypatch):
    field = descriptor(dict(document(64), value_codec='pg-timestamp-us-be/v1'))
    _, ring = setup_keys()
    material, nonce = ring.prepare(), bytes(range(12))
    database = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    try:
        with database.connect() as connection:
            # Fixed PostgreSQL epoch offsets: no production temporal encoder is reused.
            values = ((datetime.min, -63082281600000000),
                      (datetime(1999, 12, 31, 23, 59, 59, 999999), -1),
                      (datetime(2000, 1, 1), 0),
                      (datetime(2000, 1, 1, microsecond=1), 1),
                      (datetime.max, 252455615999999999))
            for value, microseconds in values:
                raw = connection.exec_driver_sql('SELECT pg_catalog.timestamp_send(%s::timestamp)',
                                                  (value,)).scalar_one()
                assert raw == struct.pack('>q', microseconds)
                frame = independent_frame(raw, field, nonce)
                with monkeypatch.context() as fixed_nonce:
                    fixed_nonce.setattr(os, 'urandom', lambda size: nonce if size == 12 else bytes(size))
                    assert cf1.seal_value(value, field, TENANT, RECORD, material) == frame
                decoded = cf1.open_value(frame, field, TENANT, RECORD, material)
                assert type(decoded) is datetime and decoded == value and decoded.tzinfo is None
                with pytest.raises(AuthenticationFailed):
                    cf1.open_value(frame, field, TENANT, UUID(int=99), material)
                with pytest.raises(AuthenticationFailed):
                    cf1.open_value(frame, descriptor(document(64)), TENANT, RECORD, material)
    finally:
        database.dispose()
    assert cf1.seal_value(None, field, TENANT, RECORD, material) is None
    assert cf1.open_value(None, field, TENANT, RECORD, material) is None
    class CustomTimestamp(datetime): pass
    for value in (date(2000, 1, 1), datetime(2000, 1, 1, tzinfo=timezone.utc),
                  CustomTimestamp(2000, 1, 1), '2000-01-01', 0):
        with pytest.raises(InvalidValue):
            cf1.seal_value(value, field, TENANT, RECORD, material)
    for raw in (b'', b'\0' * 7, b'\0' * 9,
                struct.pack('>q', -63082281600000001), struct.pack('>q', 252455616000000000)):
        with pytest.raises(InvalidValue):
            cf1.open_value(independent_frame(raw, field, nonce), field, TENANT, RECORD, material)
    with pytest.raises(InvalidContext):
        descriptor(dict(document(64), value_codec='pg-timestamp-us-be/v1', representation='cf1-packed-equality/v1'))
