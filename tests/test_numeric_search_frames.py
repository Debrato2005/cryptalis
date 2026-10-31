"""PostgreSQL normalization plus separate HKDF/HMAC checks stored search frames."""
from decimal import Decimal, Inexact, Rounded, localcontext
import json
from uuid import UUID

import pytest
from sqlalchemy import Numeric, select

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_migration import application, frames, independent_open, keys, publish, run, TENANT


@pytest.mark.parametrize('dtype,values', [
    (Numeric(), ('1.20', '1.2000', '-0.00', '0.000', '-1200.00', '.0001200', None)),
    (Numeric(8, 2), ('1.235', '1.2400', '-.004', '0', '-999999.99', '1000', None)),
    (Numeric(2, -3), ('14500', '15000', '-499', '0', '-99000', '2000', None)),
    (Numeric(3, 5), ('.000125', '.00013', '-.000004', '0', '-.009994', '.0012', None)),
])
def test_numeric_native_canonical_terms_exact_payload_and_tamper_refusal(dtype, values):
    values = tuple(Decimal(value) if value is not None else None for value in values)
    with application(value_type=dtype, unique=False, queries=['equality'], protected_values=values) as app:
        # This oracle uses native scale/trim_scale and string operations, without
        # importing the implementation's Decimal canonicalizer.
        with app.owner.connect() as connection:
            expected = {identity: (value, canonical) for identity, value, canonical in connection.exec_driver_sql(f'''
                SELECT id, name, CASE WHEN name=0 THEN '0' ELSE
                    CASE WHEN name<0 THEN '-' ELSE '' END || rtrim(digits, '0') || 'e' ||
                    (length(digits)-length(rtrim(digits, '0'))-scale(trim_scale(name)))::text END
                FROM (SELECT id, name,
                    ltrim(replace(abs(trim_scale(name))::text, '.', ''), '0') AS digits
                    FROM "{app.schema}".customer) AS native
            ''')}
        run(app); publish(app)
        descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
        stored = frames(app, switched=True)
        for identity, (value, canonical) in expected.items():
            assert independent_open(stored[identity], descriptor, TENANT, identity,
                return_bytes=True, search_bytes=canonical.encode('ascii') if canonical is not None else None
            ) == (format(value, 'f').encode('ascii') if value is not None else None)
        assert stored[UUID(int=100)][14:46] == stored[UUID(int=101)][14:46]
        assert stored[UUID(int=102)][14:46] == stored[UUID(int=103)][14:46]

        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        identity = UUID(int=100)
        original = stored[identity]
        for offset in (14, 46, len(original)-1):
            damaged = bytearray(original)
            damaged[offset] ^= 1
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                           (bytes(damaged), identity))
            try:
                with sessions(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.scalar(select(app.Customer.name).where(app.Customer.id == identity))
            finally:
                with app.owner.begin() as connection:
                    connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                               (original, identity))


def test_numeric_search_native_digit_limits_ignore_host_decimal_context():
    from sqlalchemy.orm import Session
    values = (Decimal('1e131071'), Decimal('1.0e131071'),
              Decimal('1e-16382'), Decimal('1.0e-16382'), None)
    pivots = (*values[:-1], Decimal('1.1e131071'), Decimal('-1e-16382'))
    with application(rows=5, value_type=Numeric(), unique=False,
                     queries=['equality'], protected_values=values) as app:
        def observe(session):
            return [list(session.scalars(select(app.Customer.id).where(
                app.Customer.tenant_id == TENANT, app.Customer.name == pivot).order_by(app.Customer.id)))
                for pivot in pivots]
        with Session(app.runtime) as session:
            expected = observe(session)
        assert expected[:2] == [[UUID(int=100), UUID(int=101)]] * 2
        assert expected[2:4] == [[UUID(int=102), UUID(int=103)]] * 2
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with localcontext() as context:
            context.prec = 2
            context.traps[Inexact] = context.traps[Rounded] = True
            with sessions(tenant_id=TENANT) as session:
                assert observe(session) == expected
