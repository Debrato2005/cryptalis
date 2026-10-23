"""Native SQL identity transforms cannot enter attached flush or bulk INSERT."""
import hashlib
from uuid import UUID

import pytest
from sqlalchemy import Text, Uuid, cast, func, insert
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach, PolicyMismatch
from test_bulk_insert_native import native_application, row
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import TENANT, keys, publish, run


class SqlEncodedUuid(TypeDecorator):
    impl = Uuid
    cache_ok = True

    def bind_expression(self, value):
        return cast(func.md5(cast(value, Text())), Uuid())


@pytest.mark.parametrize("identity", ["id", "tenant_id"])
@pytest.mark.parametrize("route", ["bulk_insert", "flush_insert"])
def test_valid_plan_then_identity_variant_remap_refuses_before_write(identity, route, monkeypatch):
    with native_application(False) as app:
        column = app.table.c[identity]
        original_type = column.type
        variant = Uuid().with_variant(SqlEncodedUuid(), "postgresql")
        values = row(1000, None, label="public native oracle")

        # Native control: the supported SQLAlchemy API changes the stored UUID
        # in SQL, although its Python input and sent UUID placeholder stay exact.
        column.type = variant
        with fresh_mapping(app):
            with Session(app.runtime) as session:
                if route == "bulk_insert":
                    session.execute(insert(app.Customer), [values])
                else:
                    session.add(app.Customer(**values))
                    session.flush()
                stored = session.connection().exec_driver_sql(
                    f'SELECT id,tenant_id FROM "{app.schema}".customer WHERE label=%s',
                    (values["label"],)).one()
                expected = {"id": values["id"], "tenant_id": TENANT}
                expected[identity] = UUID(hashlib.md5(str(expected[identity]).encode()).hexdigest())
                assert tuple(stored) == (expected["id"], expected["tenant_id"])
                session.rollback()

        # Compile/activate with the original admitted mapping. A new mapping
        # over the same valid plan must recheck effective identity codecs.
        column.type = original_type
        run(app)
        publish(app)
        column.type = variant
        with fresh_mapping(app):
            resolutions = []
            def resolve(tenant):
                resolutions.append(tenant)
                return keys(tenant)
            with raw_calls(monkeypatch, app.schema, "INSERT") as sent:
                with pytest.raises(PolicyMismatch):
                    attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                           keys=resolve, deployment=(app.plan, app.pin))
                assert resolutions == sent == []



@pytest.mark.parametrize("route", ["bulk_insert", "flush_insert"])
def test_late_identity_variant_refuses_before_key_resolution_or_write(route, monkeypatch):
    with native_application(False) as app:
        run(app)
        publish(app)
        resolutions = []
        def resolve(tenant):
            resolutions.append(tenant)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=resolve, deployment=(app.plan, app.pin))
        values = row(1000, None, label="late variant must refuse")
        with raw_calls(monkeypatch, app.schema, "INSERT") as sent:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                app.table.c.tenant_id.type = Uuid().with_variant(SqlEncodedUuid(), "postgresql")
                try:
                    with pytest.raises(CryptoFailure):
                        if route == "bulk_insert":
                            session.execute(insert(app.Customer), [values])
                        else:
                            session.add(app.Customer(**values))
                            session.flush()
                    assert resolutions == sent == []
                finally:
                    session.rollback()
