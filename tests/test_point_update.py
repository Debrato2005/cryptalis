"""Native single-record UPDATE values, cursor results and tenant isolation."""

import asyncio
import os
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String, bindparam, event, func, or_, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError, ResourceClosedError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, VarcharLengthExceeded, attach
from test_bulk_insert import protect
from test_bulk_returning import fresh_mapping
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, publish, run, TENANT
from test_rewrap_plan import _snapshot


def statement(app, value, identity=UUID(int=101)):
    return update(app.Customer).where(app.Customer.tenant_id == TENANT,
        app.Customer.id == identity).values(name=value, label="public point edit")


def execute(session, clause):
    return session.execute(clause, execution_options={"synchronize_session": False})


def no_rows(result, count):
    assert result.rowcount == count and result.returns_rows is False
    with pytest.raises(ResourceClosedError):
        result.all()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("varchar", [False, True])
@pytest.mark.parametrize("value", [None, "雪 e\u0301"])
def test_point_update_matches_native_cursor_state_rollback_and_current_values(mode, varchar, value):
    with application(rows=3, value_type=String(8, collation="C") if varchar else None) as app:
        def scenario(session):
            loaded = session.get(app.Customer, UUID(int=101))
            old = loaded.name
            no_rows(execute(session, statement(app, value)), 1)
            assert loaded.name == old
            session.refresh(loaded)
            assert loaded.name == value and loaded.label == "public point edit"
            no_rows(execute(session, statement(app, value, UUID(int=999))), 0)
            observed = session.execute(select(app.Customer.id, app.Customer.name,
                app.Customer.label).order_by(app.Customer.id)).all()
            session.rollback()
            assert session.get(app.Customer, UUID(int=101)).name == old
            return observed
        with Session(app.runtime) as session:
            expected = scenario(session)
        before_sql = []
        def capture(connection, cursor, sql, values, context, many):
            if sql.lstrip().upper().startswith("UPDATE "):
                before_sql.append(repr(values))
        with fresh_mapping(app):
            if mode == "sync":
                factory = protect(app)
                event.listen(app.runtime, "before_cursor_execute", capture)
                try:
                    with factory(tenant_id=TENANT) as session:
                        assert scenario(session) == expected
                        no_rows(execute(session, statement(app, value)), 1)
                        session.commit()
                        assert session.get(app.Customer, UUID(int=101)).name == value
                finally:
                    event.remove(app.runtime, "before_cursor_execute", capture)
            else:
                run(app); publish(app)
                async def asynchronous():
                    engine = create_async_engine("postgresql+psycopg://", hide_parameters=True,
                        async_creator=lambda: psycopg.AsyncConnection.connect(
                            os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
                    try:
                        factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                            keys=keys, deployment=(app.plan, app.pin))
                        event.listen(engine.sync_engine, "before_cursor_execute", capture)
                        async with factory(tenant_id=TENANT) as session:
                            loaded = await session.get(app.Customer, UUID(int=101))
                            old = loaded.name
                            no_rows(await execute(session, statement(app, value)), 1)
                            assert loaded.name == old
                            await session.refresh(loaded)
                            assert loaded.name == value
                            no_rows(await execute(session, statement(app, value, UUID(int=999))), 0)
                            actual = (await session.execute(select(app.Customer.id, app.Customer.name,
                                app.Customer.label).order_by(app.Customer.id))).all()
                            assert actual == expected
                            await session.rollback()
                            no_rows(await execute(session, statement(app, value)), 1)
                            await session.commit()
                    finally:
                        await engine.dispose()
                asyncio.run(asynchronous())
        assert before_sql
        if value is not None:
            assert value not in "".join(before_sql)


@pytest.mark.parametrize("target", [UUID(int=101), UUID(int=999), UUID(int=888)])
def test_varchar_native_error_timing_preserves_zero_matches_and_foreign_tenant(target):
    def foreign(connection, schema, role):
        connection.exec_driver_sql(f'INSERT INTO "{schema}".customer VALUES (%s,%s,%s,%s)',
            (UUID(int=888), UUID(int=333), "else", "foreign"))
    with application(rows=3, value_type=String(4, collation="C"), setup=foreign) as app:
        value = "PRIVATE_OVERFLOW"
        native_error = None
        with Session(app.runtime) as session:
            try:
                no_rows(execute(session, statement(app, value, target)), 0)
            except DBAPIError as error:
                native_error = error.orig.sqlstate
                assert native_error == "22001"
            session.rollback()
        factory = protect(app)
        before = _snapshot(app)
        with factory(tenant_id=TENANT) as session:
            if native_error is not None:
                with pytest.raises(VarcharLengthExceeded):
                    execute(session, statement(app, value, target))
            else:
                no_rows(execute(session, statement(app, value, target)), 0)
            session.rollback()
        assert _snapshot(app) == before


def test_point_update_native_unique_savepoint_and_successful_autoflush():
    with application(rows=3) as app:
        def scenario(session):
            session.add(app.Customer(id=UUID(int=1000), tenant_id=TENANT,
                name="outer protected", label="outer"))
            session.flush()
            nested = session.begin_nested()
            with pytest.raises(IntegrityError) as refused:
                execute(session, statement(app, "outer protected"))
            assert refused.value.orig.sqlstate == "23505"
            nested.rollback()
            assert session.get(app.Customer, UUID(int=1000)).name == "outer protected"
            loaded = session.get(app.Customer, UUID(int=102))
            loaded.label = "autoflush first"
            no_rows(execute(session, statement(app, "after savepoint")), 1)
            actual = session.execute(select(app.Customer.id, app.Customer.name,
                app.Customer.label).order_by(app.Customer.id)).all()
            session.rollback()
            return actual
        with Session(app.runtime) as session:
            expected = scenario(session)
        factory = protect(app)
        with factory(tenant_id=TENANT) as session:
            assert scenario(session) == expected


@pytest.mark.parametrize("fault", ["payload", "identity", "tenant", "sql"])
def test_point_update_late_mutation_refuses_before_driver_and_healthy_retry(fault, monkeypatch):
    with application(rows=3) as app:
        factory = protect(app)
        before = _snapshot(app)
        observed = []
        def mutate(connection, cursor, sql, parameters, context, many):
            if sql.lstrip().upper().startswith("UPDATE "):
                observed.append(True)
                if fault == "payload":
                    parameters["name"].obj = b"PRIVATE_PLAINTEXT"
                elif fault == "identity":
                    key = next(k for k in parameters if k.startswith("id"))
                    parameters[key] = UUID(int=102)
                elif fault == "tenant":
                    key = next(k for k in parameters if k.startswith("tenant_id"))
                    parameters[key] = UUID(int=333)
                else:
                    sql += " /* changed */"
            return sql, parameters
        event.listen(app.runtime, "before_cursor_execute", mutate, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, "UPDATE") as calls:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        execute(session, statement(app, "private edit"))
                    session.rollback()
                assert observed and calls == []
        finally:
            event.remove(app.runtime, "before_cursor_execute", mutate)
        assert _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            no_rows(execute(session, statement(app, "private edit")), 1)
            session.commit()


@pytest.mark.parametrize("fault", ["missing_id", "missing_scope", "wrong_scope", "or",
    "expression", "returning", "tenant_assignment", "id_assignment", "callable",
    "typed_assignment", "ordered", "labeled_target", "core", "parameters"])
def test_unadmitted_point_shapes_refuse_before_keys_and_sql(fault):
    with application(rows=3) as app:
        calls, sql = [], []
        def resolve(tenant):
            calls.append(tenant)
            return keys(tenant)
        factory = protect(app, resolver=resolve)
        clause, parameters = statement(app, "private point value"), None
        if fault == "missing_id":
            clause = update(app.Customer).where(app.Customer.tenant_id == TENANT).values(name="x")
        elif fault == "missing_scope":
            clause = update(app.Customer).where(app.Customer.id == UUID(int=101)).values(name="x")
        elif fault == "wrong_scope":
            clause = update(app.Customer).where(app.Customer.id == UUID(int=101),
                app.Customer.tenant_id == UUID(int=9)).values(name="x")
        elif fault == "or":
            clause = update(app.Customer).where(or_(app.Customer.id == UUID(int=101),
                app.Customer.tenant_id == TENANT)).values(name="x")
        elif fault == "expression":
            clause = clause.values(name=func.upper("x"))
        elif fault == "returning":
            clause = clause.returning(app.Customer.name)
        elif fault == "tenant_assignment":
            clause = clause.values(tenant_id=TENANT)
        elif fault == "id_assignment":
            clause = clause.values(id=UUID(int=102))
        elif fault == "callable":
            clause = clause.values(name=bindparam("value", callable_=lambda: "x"))
        elif fault == "typed_assignment":
            clause = clause.values(name=bindparam("value", value="x", type_=String()))
        elif fault == "ordered":
            clause = update(app.Customer).where(app.Customer.tenant_id == TENANT,
                app.Customer.id == UUID(int=101)).ordered_values((app.Customer.name, "x"))
        elif fault == "labeled_target":
            clause = update(app.Customer).where(app.Customer.tenant_id == TENANT,
                app.Customer.id == UUID(int=101)).values({app.Customer.name.label("label"): "x"})
        elif fault == "core":
            clause = update(app.table).where(app.table.c.tenant_id == TENANT,
                app.table.c.id == UUID(int=101)).values(name="x")
        else:
            parameters = {"name": "x"}
        calls.clear()
        def capture(*args):
            sql.append(True)
        event.listen(app.runtime, "before_cursor_execute", capture)
        try:
            with factory(tenant_id=TENANT) as session:
                calls.clear()
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(clause, parameters,
                        execution_options={"synchronize_session": False})
                session.rollback()
            assert calls == [] and sql == []
        finally:
            event.remove(app.runtime, "before_cursor_execute", capture)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("fault", ["identity", "value"])
def test_provider_callback_cannot_change_original_point_update(mode, fault, monkeypatch):
    with application(rows=3) as app:
        run(app); publish(app)
        clause, armed, changed = statement(app, "private original"), [False], []
        def resolve(tenant):
            if armed[0] and not changed:
                for node in visitors.iterate(clause):
                    if isinstance(node, BindParameter) and (
                            node.value == UUID(int=101) if fault == "identity" else
                            node.value == "private original"):
                        node.value = UUID(int=102) if fault == "identity" else "private replacement"
                        changed.append(True)
                        break
            return keys(tenant)
        before = _snapshot(app)
        if mode == "sync":
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                keys=resolve, deployment=(app.plan, app.pin))
            with raw_calls(monkeypatch, app.schema, "UPDATE") as calls:
                with factory(tenant_id=TENANT) as session:
                    armed[0] = True
                    with pytest.raises(CryptoFailure):
                        execute(session, clause)
                    session.rollback()
                assert changed and calls == []
        else:
            async def asynchronous():
                engine = create_async_engine("postgresql+psycopg://", hide_parameters=True,
                    async_creator=lambda: psycopg.AsyncConnection.connect(
                        os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
                try:
                    factory = await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                        keys=resolve, deployment=(app.plan, app.pin))
                    with raw_calls(monkeypatch, app.schema, "UPDATE", asynchronous=True) as calls:
                        async with factory(tenant_id=TENANT) as session:
                            armed[0] = True
                            with pytest.raises(CryptoFailure):
                                await execute(session, clause)
                            await session.rollback()
                        assert changed and calls == []
                finally:
                    await engine.dispose()
            asyncio.run(asynchronous())
        assert _snapshot(app) == before
