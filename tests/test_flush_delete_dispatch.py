"""Ordinary ORM deletes require native compiler nodes before driver dispatch."""
from uuid import UUID

import pytest
from sqlalchemy import event, select
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session
from sqlalchemy.sql.dml import Delete

from cryptalis.crypto import CryptoFailure
from test_bulk_insert import protect
from test_bulk_insert_native import native_application, stored
from test_driver_event_boundary import raw_calls
from test_migration import TENANT
from test_rewrap_plan import _snapshot


@pytest.mark.parametrize('count,varchar', [(1, False), (2, False), (1, True), (2, True)])
def test_equivalent_delete_subclass_refuses_flush_before_driver_then_native_retry(count, varchar, monkeypatch):
    class EquivalentDelete(Delete):
        inherit_cache = True

    with native_application(varchar) as app:
        identities = [UUID(int=value) for value in range(101, 101 + count)]
        replaced = []

        def equivalent(connection, statement, multiparams, params, options):
            if isinstance(statement, Delete) and statement.table.schema == app.schema:
                replaced.append(True)
                statement = EquivalentDelete(statement.table).where(statement.whereclause)
            return statement, multiparams, params

        def mark_deleted(session):
            instances = [session.get(app.Customer, identity) for identity in identities]
            assert all(instance is not None for instance in instances)
            for instance in instances:
                session.delete(instance)

        with app.runtime.connect() as connection:
            original = stored(app, connection)
        event.listen(app.runtime, 'before_execute', equivalent, retval=True)
        try:
            # The replacement inherits native compilation and changes no SQL meaning.
            with Session(app.runtime) as native:
                mark_deleted(native)
                native.flush()
                assert native.scalars(select(app.Customer.id).where(
                    app.Customer.id.in_(identities))).all() == []
                native.rollback()
            assert replaced
        finally:
            event.remove(app.runtime, 'before_execute', equivalent)
        with app.runtime.connect() as connection:
            assert stored(app, connection) == original

        factory = protect(app)
        before = _snapshot(app)
        replaced.clear()
        event.listen(Connection, 'before_execute', equivalent, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
                with factory(tenant_id=TENANT) as session:
                    mark_deleted(session)
                    with pytest.raises(CryptoFailure):
                        session.flush()
                    session.rollback()
                assert replaced and sent == []
        finally:
            event.remove(Connection, 'before_execute', equivalent)
        assert _snapshot(app) == before

        with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with factory(tenant_id=TENANT) as session:
                mark_deleted(session)
                session.flush()
                assert session.scalars(select(app.Customer.id).where(
                    app.Customer.id.in_(identities))).all() == []
                session.rollback()
            assert len(sent) == 1
        assert _snapshot(app) == before
