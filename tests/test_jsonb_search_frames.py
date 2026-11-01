"""Frozen JSONB equality bytes and a separate HKDF/HMAC decoder verify frames."""
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_migration import FIELD_ID, TENANT, application, frames, independent_open, keys, publish, run


VECTORS = (
    ('{"n":1.2000,"nested":[-0.000,{"x":1000.000}]}',
     b'{"n": 1.2, "nested": [0, {"x": 1000}]}'),
    ('{"nested":[0,{"x":1000}],"n":1.20}',
     b'{"n": 1.2, "nested": [0, {"x": 1000}]}'),
    ('{"n":"1.20","nested":[false,{"x":1000}]}',
     b'{"n": "1.20", "nested": [false, {"x": 1000}]}'),
    ('1.000', b'1'), ('[1.00]', b'[1]'), ('null', b'null'), ('"null"', b'"null"'),
)


def test_jsonb_frozen_nested_numeric_equality_terms_preserve_exact_native_payload_and_authentication():
    def seed(connection, schema, role):
        for index, (raw, _) in enumerate(VECTORS):
            connection.exec_driver_sql(f'INSERT INTO "{schema}".customer(id,tenant_id,name,label) '
                'VALUES (%s,%s,%s::pg_catalog.jsonb,%s)',
                (UUID(int=800 + index), TENANT, raw, 'frozen JSONB equality fixture'))
    with application(rows=0, value_type=JSONB(), unique=False, queries=['equality'], setup=seed) as app:
        with app.owner.connect() as connection:
            native = {identity: bytes(value) for identity, value in connection.exec_driver_sql(
                f'SELECT id,pg_catalog.convert_to(name::text,\'UTF8\') FROM "{app.schema}".customer ORDER BY id')}
            for left, (raw, _) in enumerate(VECTORS):
                for right, (other, _) in enumerate(VECTORS):
                    actual = connection.exec_driver_sql('SELECT %s::pg_catalog.jsonb=%s::pg_catalog.jsonb',
                                                        (raw, other)).scalar_one()
                    assert actual is (VECTORS[left][1] == VECTORS[right][1])
        run(app); publish(app)
        descriptor = next(field['descriptor'] for model in app.plan.document['lock']['models']
                          for field in model['fields'] if field['field_id'] == str(FIELD_ID))
        bodies = frames(app, True)
        for index, (_, expected) in enumerate(VECTORS):
            identity = UUID(int=800 + index)
            assert independent_open(bodies[identity], descriptor, TENANT, identity,
                return_bytes=True, search_bytes=expected) == native[identity]
        assert bodies[UUID(int=800)][14:46] == bodies[UUID(int=801)][14:46]
        assert bodies[UUID(int=803)][14:46] != bodies[UUID(int=804)][14:46]
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        frame = bodies[UUID(int=800)]
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                (frame[:14] + bytes([frame[14] ^ 1]) + frame[15:], UUID(int=800)))
        with factory(tenant_id=TENANT) as session:
            with pytest.raises(CryptoFailure):
                session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=800)))
