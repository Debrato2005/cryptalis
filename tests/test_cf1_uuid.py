"""UUID value bytes retain typed field and record authentication."""
import os
from uuid import UUID

import pytest
from test_cf1 import RECORD, TENANT, setup_keys
from test_cf1_integer import descriptor, document, independent_frame

from cryptalis.crypto import AuthenticationFailed, CryptoFailure, cf1


def test_independent_uuid_value_frames_types_nulls_and_context(monkeypatch):
    field = descriptor(dict(document(32), value_codec='uuid-bytes16/v1'))
    _, ring = setup_keys()
    material, nonce = ring.prepare(), bytes(range(12))
    monkeypatch.setattr(os, 'urandom', lambda length: nonce if length == 12 else bytes(length))
    for value in (UUID(int=0), UUID(bytes=bytes(range(16))), UUID(int=(1 << 128) - 1)):
        frame = independent_frame(value.bytes, field, nonce)
        assert len(frame) == 58
        assert cf1.seal_value(value, field, TENANT, RECORD, material) == frame
        opened = cf1.open_value(frame, field, TENANT, RECORD, material)
        assert opened == value and type(opened) is UUID
        with pytest.raises(AuthenticationFailed):
            cf1.open_value(frame, field, TENANT, UUID(int=99), material)
    assert cf1.seal_value(None, field, TENANT, RECORD, material) is None
    assert cf1.open_value(None, field, TENANT, RECORD, material) is None
    for invalid in (str(UUID(int=1)), UUID(int=1).bytes, 1, True):
        with pytest.raises(CryptoFailure):
            cf1.seal_value(invalid, field, TENANT, RECORD, material)
    for length in (0, 15, 17):
        with pytest.raises(CryptoFailure):
            cf1.open_value(independent_frame(b'\0' * length, field, nonce), field, TENANT, RECORD, material)
