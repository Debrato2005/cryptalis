"""Date codecs retain CF1 authentication and finite Gregorian ordinals."""
import os
import struct
from datetime import date, datetime
from uuid import UUID

import pytest
from test_cf1 import RECORD, setup_keys
from test_cf1 import TENANT as CRYPTO_TENANT
from test_cf1_integer import descriptor, document, independent_frame

from cryptalis.crypto import AuthenticationFailed, CryptoFailure, cf1


def test_independent_date_frames_ordinals_bounds_and_invalid_typed_values(monkeypatch):
    field = descriptor(dict(document(32), value_codec='date-ordinal-u32/v1'))
    _, ring = setup_keys()
    material, nonce = ring.prepare(), bytes(range(12))
    monkeypatch.setattr(os, 'urandom', lambda length: nonce if length == 12 else bytes(length))
    for value, ordinal in ((date.min, 1), (date(1970, 1, 1), 719163),
                           (date(2000, 2, 29), 730179), (date.max, 3652059)):
        frame = independent_frame(struct.pack('>I', ordinal), field, nonce)
        assert len(frame) == 46
        assert cf1.seal_value(value, field, CRYPTO_TENANT, RECORD, material) == frame
        opened = cf1.open_value(frame, field, CRYPTO_TENANT, RECORD, material)
        assert opened == value and type(opened) is date
        for expected, identity in ((field, UUID(int=99)), (descriptor(document(32)), RECORD)):
            with pytest.raises(AuthenticationFailed):
                cf1.open_value(frame, expected, CRYPTO_TENANT, identity, material)
    assert cf1.seal_value(None, field, CRYPTO_TENANT, RECORD, material) is None
    assert cf1.open_value(None, field, CRYPTO_TENANT, RECORD, material) is None
    for invalid in (datetime(2000, 1, 1), '2000-01-01', 1, True, b'2000-01-01'):
        with pytest.raises(CryptoFailure):
            cf1.seal_value(invalid, field, CRYPTO_TENANT, RECORD, material)
    for raw in (b'', b'\0', struct.pack('>I', 0), struct.pack('>I', 3652060),
                struct.pack('>I', 1 << 31), struct.pack('>I', (1 << 32) - 1), b'\0' * 5):
        with pytest.raises(CryptoFailure):
            cf1.open_value(independent_frame(raw, field, nonce), field, CRYPTO_TENANT, RECORD, material)
