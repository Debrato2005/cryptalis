"""Native SELECT type hooks must not hide protected reads during compilation."""

from uuid import UUID

import pytest
from sqlalchemy import Enum, Text, bindparam, cast, func, literal, select, type_coerce
from sqlalchemy.ext.compiler import compiles, deregister
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeDecorator, UserDefinedType

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_insert_native import native_application
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import TENANT, keys, publish, run


def protect(app, resolutions):
    run(app)
    publish(app)
    def resolve(tenant):
        resolutions.append(tenant)
        return keys(tenant)
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                  keys=resolve, deployment=(app.plan, app.pin))


@pytest.mark.parametrize("placement", ["mapped", "type_coerce", "variant"])
def test_public_column_expression_cannot_project_unrewritten_protected_storage(placement, monkeypatch):
    with native_application(False) as app:
        class HiddenProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def column_expression(self, column):
                return cast(app.table.c.name, Text())

        dtype = HiddenProtectedRead()
        if placement == "mapped":
            app.table.c.label.type = dtype
        with fresh_mapping(app):
            def statement():
                selected = (app.Customer.label if placement == "mapped" else
                            type_coerce(app.Customer.label, Text().with_variant(dtype, "postgresql")
                                        if placement == "variant" else dtype))
                return select(selected).where(app.Customer.id == UUID(int=102))

            with Session(app.runtime) as native:
                assert native.scalar(statement()) == "雪😀"
                native.rollback()
            resolutions = []
            factory = protect(app, resolutions)
            with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
                with factory(tenant_id=TENANT) as session:
                    resolutions.clear()
                    try:
                        try:
                            actual = session.scalar(statement())
                        except CryptoFailure:
                            pass
                        else:
                            assert type(actual) is str and actual.startswith("\\x43463100")
                            pytest.fail("Public result released the hex representation of a protected CF1 frame")
                        assert resolutions == sent == []
                    finally:
                        session.rollback()


def test_public_bind_expression_cannot_hide_protected_predicate_semantics(monkeypatch):
    with native_application(False) as app:
        class HiddenProtectedPredicate(TypeDecorator):
            impl = Text
            cache_ok = True

            def bind_expression(self, value):
                return func.concat(value, cast(app.table.c.name, Text()))

        def statement():
            return select(app.Customer.id).where(
                app.Customer.id == UUID(int=101),
                app.Customer.label == bindparam("public_label", "label-101",
                                                 type_=HiddenProtectedPredicate()))

        with Session(app.runtime) as native:
            # name is the empty native text here, so the predicate is true.
            assert list(native.scalars(statement())) == [UUID(int=101)]
            native.rollback()
        resolutions = []
        factory = protect(app, resolutions)
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                resolutions.clear()
                try:
                    try:
                        actual = list(session.scalars(statement()))
                    except CryptoFailure:
                        pass
                    else:
                        assert actual == []
                        pytest.fail("Hidden protected-storage predicate changed a native matching row to no match")
                    assert resolutions == sent == []
                finally:
                    session.rollback()


def test_python_public_bind_and_result_codecs_preserve_native_values():
    class PublicCase(TypeDecorator):
        impl = Text
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return None if value is None else value.upper()

        def process_result_value(self, value, dialect):
            return None if value is None else "read:" + value

    with native_application(False) as app:
        app.table.c.label.type = PublicCase()
        with fresh_mapping(app):
            def statement():
                return select(app.Customer.label, literal(True),
                              literal("a", Enum("a", "b", native_enum=False))).where(
                    app.Customer.id == UUID(int=101), app.Customer.label == "mixed")

            with Session(app.runtime) as native:
                item = native.get(app.Customer, UUID(int=101))
                item.label = "mixed"
                native.commit()
                expected = native.execute(statement()).one()
                assert tuple(expected) == ("read:MIXED", True, "a")
            factory = protect(app, [])
            with factory(tenant_id=TENANT) as session:
                assert session.execute(statement()).one() == expected
                session.rollback()


def test_literal_execute_type_processor_cannot_add_a_hidden_protected_predicate(monkeypatch):
    with native_application(False) as app:
        class HiddenLiteral(TypeDecorator):
            impl = Text
            cache_ok = True

            def literal_processor(self, dialect):
                return lambda value: (f"pg_catalog.concat('label-101', "
                    f'CAST("{app.schema}".customer.name AS TEXT))')

        def statement():
            return select(app.Customer.id).where(
                app.Customer.id == UUID(int=101), app.Customer.label == bindparam(
                    "public_literal", "label-101", type_=HiddenLiteral(), literal_execute=True))

        with Session(app.runtime) as native:
            assert list(native.scalars(statement())) == [UUID(int=101)]
        factory = protect(app, [])
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                try:
                    with pytest.raises(CryptoFailure):
                        list(session.scalars(statement()))
                    assert sent == []
                finally:
                    session.rollback()


def test_nested_user_defined_cast_type_cannot_add_a_hidden_protected_projection(monkeypatch):
    with native_application(False) as app:
        class HiddenCast(UserDefinedType):
            cache_ok = True

            def get_col_spec(self, **kwargs):
                return f'TEXT) || CAST("{app.schema}".customer.name AS TEXT) || CAST(\'\' AS TEXT'

        class WrappedCast(TypeDecorator):
            impl = HiddenCast
            cache_ok = True

        def statement():
            return select(cast(app.Customer.label, WrappedCast())).where(app.Customer.id == UUID(int=102))

        with Session(app.runtime) as native:
            assert native.scalar(statement()) == "label-102雪😀"
        factory = protect(app, [])
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                try:
                    with pytest.raises(CryptoFailure):
                        session.scalar(statement())
                    assert sent == []
                finally:
                    session.rollback()


def test_copied_internal_payload_type_does_not_inherit_projection_authority(monkeypatch):
    with native_application(False) as app:
        factory = protect(app, [])
        class HiddenProtectedRead(TypeDecorator):
            impl = Text
            cache_ok = True

            def column_expression(self, column):
                return cast(app.table.c.name, Text())

        copied = app.table.c.name.type.with_variant(HiddenProtectedRead(), "postgresql")
        statement = select(type_coerce(app.Customer.label, copied)).where(app.Customer.id == UUID(int=102))
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                try:
                    with pytest.raises(CryptoFailure):
                        session.scalar(statement)
                    assert sent == []
                finally:
                    session.rollback()


@pytest.mark.parametrize("dispatch", ["registered", "new_visit"])
def test_custom_type_compilation_cannot_add_a_hidden_protected_projection(dispatch, monkeypatch):
    with native_application(False) as app:
        def sql_type():
            return f'TEXT) || CAST("{app.schema}".customer.name AS TEXT) || CAST(\'\' AS TEXT'

        if dispatch == "registered":
            class HiddenText(Text):
                pass
            @compiles(HiddenText, "postgresql")
            def render(dtype, compiler, **kwargs):
                return sql_type()
        else:
            class HiddenText(Text):
                __visit_name__ = "user_defined"

                def get_col_spec(self, **kwargs):
                    return sql_type()

        try:
            def statement():
                return select(cast(app.Customer.label, HiddenText())).where(app.Customer.id == UUID(int=102))
            with Session(app.runtime) as native:
                assert native.scalar(statement()) == "label-102雪😀"
            factory = protect(app, [])
            with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
                with factory(tenant_id=TENANT) as session:
                    try:
                        with pytest.raises(CryptoFailure):
                            session.scalar(statement())
                        assert sent == []
                    finally:
                        session.rollback()
        finally:
            if dispatch == "registered":
                deregister(HiddenText)


def test_custom_internal_payload_type_renderer_does_not_inherit_projection_authority(monkeypatch):
    with native_application(False) as app:
        factory = protect(app, [])
        dtype = app.table.c.name.type
        @compiles(type(dtype), "postgresql")
        def render(dtype, compiler, **kwargs):
            return f'TEXT) || CAST("{app.schema}".customer.name AS TEXT) || CAST(\'\' AS TEXT'
        try:
            statement = select(cast(app.Customer.label, dtype)).where(app.Customer.id == UUID(int=102))
            with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
                with factory(tenant_id=TENANT) as session:
                    try:
                        with pytest.raises(CryptoFailure):
                            session.scalar(statement)
                        assert sent == []
                    finally:
                        session.rollback()
        finally:
            deregister(type(dtype))


def test_dispatch_callable_cannot_spoof_a_native_method_identity(monkeypatch):
    with native_application(False) as app:
        class HiddenText(Text):
            pass

        class SpoofedDispatch:
            def __init__(self):
                self.__func__ = Text._original_compiler_dispatch

            def __call__(self, compiler, **kwargs):
                return f'TEXT) || CAST("{app.schema}".customer.name AS TEXT) || CAST(\'\' AS TEXT'

        dtype = HiddenText()
        dtype._compiler_dispatch = SpoofedDispatch()
        def statement():
            return select(cast(app.Customer.label, dtype)).where(app.Customer.id == UUID(int=102))

        with Session(app.runtime) as native:
            assert native.scalar(statement()) == "label-102雪😀"
        factory = protect(app, [])
        with raw_calls(monkeypatch, app.schema, "SELECT") as sent:
            with factory(tenant_id=TENANT) as session:
                try:
                    with pytest.raises(CryptoFailure):
                        session.scalar(statement())
                    assert sent == []
                finally:
                    session.rollback()
