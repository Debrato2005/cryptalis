"""Entity and table projections must inspect expanded public column types."""

from uuid import UUID

import pytest
from sqlalchemy import Column, MetaData, Table, Text, Uuid, cast, func, inspect, select
from sqlalchemy.orm import Session, column_property
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure
from test_bulk_insert_native import native_application
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import TENANT
from test_select_type_hooks import protect


@pytest.mark.parametrize("projection", ["entity", "table"])
def test_expanded_projection_cannot_hide_public_column_expression(projection, monkeypatch):
    with native_application(False) as app:
        class HiddenProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def column_expression(self, column):
                return cast(app.table.c.name, Text())

        app.table.c.label.type = HiddenProtectedRead()
        with fresh_mapping(app):
            def statement():
                return select(app.Customer if projection == "entity" else app.table).where(
                    app.Customer.id == UUID(int=102))

            def label(result):
                row = result.one()
                return row[0].label if projection == "entity" else row._mapping["label"]

            with Session(app.runtime) as native:
                assert label(native.execute(statement())) == "雪😀"
                native.rollback()

            resolutions = []
            factory = protect(app, resolutions)
            with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    try:
                        try:
                            actual = label(session.execute(statement()))
                        except CryptoFailure:
                            pass
                        else:
                            assert type(actual) is str and actual.startswith("\\x43463100")
                            pytest.fail("Expanded public column released the hex representation of a protected CF1 frame")
                        assert resolutions == sent == []
                    finally:
                        session.rollback()


@pytest.mark.parametrize("projection", ["entity", "table", "nested"])
def test_expanded_native_projections_keep_authenticated_values_and_python_codecs(projection):
    class PublicText(TypeDecorator):
        impl = Text
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return None if value is None else value.upper()

        def process_result_value(self, value, dialect):
            return None if value is None else "read:" + value

    with native_application(False) as app:
        app.table.c.label.type = PublicText()
        with fresh_mapping(app):
            def statement():
                if projection == "nested":
                    label = select(app.Customer.label).where(
                        app.Customer.label == "mixed").scalar_subquery()
                    return select(app.Customer.name, label).where(app.Customer.id == UUID(int=102))
                return select(app.Customer if projection == "entity" else app.table).where(
                    app.Customer.id == UUID(int=102))

            def values(result):
                row = result.one()
                if projection == "entity":
                    return row[0].name, row[0].label
                if projection == "table":
                    return row._mapping["name"], row._mapping["label"]
                return tuple(row)

            with Session(app.runtime) as native:
                native.get(app.Customer, UUID(int=102)).label = "mixed"
                native.commit()
                expected = values(native.execute(statement()))
                assert expected == ("雪😀", "read:MIXED")
                native.rollback()
            factory = protect(app, [])
            with factory(tenant_id=TENANT) as session:
                assert values(session.execute(statement())) == expected
                session.rollback()


def test_expanded_alternate_table_refuses_non_owned_protected_column_lineage(monkeypatch):
    with native_application(False) as app:
        alternate = Table(app.table.name, MetaData(), Column("id", Uuid),
                          Column("name", Text), schema=app.schema)
        statement = select(alternate).where(alternate.c.id == UUID(int=102))
        with Session(app.runtime) as native:
            assert native.execute(statement).one()._mapping["name"] == "雪😀"
            native.rollback()
        resolutions = []
        factory = protect(app, resolutions)
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                try:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement)
                    assert resolutions == sent == []
                finally:
                    session.rollback()


@pytest.mark.parametrize("protected", [False, True], ids=["public", "protected"])
@pytest.mark.parametrize("projection", ["direct", "entity"])
def test_mapper_expression_uses_the_same_admission_as_direct_projection(protected, projection, monkeypatch):
    with native_application(False) as app:
        with fresh_mapping(app):
            column = app.table.c.name if protected else app.table.c.label
            inspect(app.Customer).add_property("value_length", column_property(func.length(column)))

            def statement():
                return select(app.Customer if projection == "entity" else app.Customer.value_length).where(
                    app.Customer.id == UUID(int=102))

            def value(result):
                row = result.one()
                return row[0].value_length if projection == "entity" else row[0]

            with Session(app.runtime) as native:
                expected = value(native.execute(statement()))
                assert expected == (2 if protected else 9)
                native.rollback()

            resolutions = []
            factory = protect(app, resolutions)
            with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    try:
                        if protected:
                            with pytest.raises(CryptoFailure):
                                value(session.execute(statement()))
                            assert resolutions == sent == []
                        else:
                            assert value(session.execute(statement())) == expected
                    finally:
                        session.rollback()
