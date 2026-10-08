"""Restricted-service experiments. Public lab keys; no product attachment claim."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import threading
import time
import uuid

from cryptography.exceptions import InvalidTag
import psycopg
from psycopg import sql
from sqlalchemy import BigInteger, Column, Identity, String, create_engine, event, inspect, select, text, update
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, aliased
from sqlalchemy.pool import NullPool
from sqlalchemy.schema import CreateSchema, DropSchema
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, TextClause

import probe_service
from run_adapter import FIELD, ProtectedText, UnsupportedProtectedOperation, protect, reveal, token


RESULT = Path(__file__).with_name("results") / "native-service.json"
MARKERS = {"same@example.test", "changed@example.test", "async@example.test"}


def connect():
    connection = psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], **probe_service.EXPECTED,
                                 hostaddr="127.0.0.1", connect_timeout=3)
    try:
        row = connection.execute("SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
        if row[:2] != ("cryptalis_test", "cryptalis_migrator") or any(row[2:]):
            raise ValueError("RESTRICTED_ROLE_REQUIRED")
        connection.commit()
        return connection
    except BaseException:
        connection.close()
        raise


async def async_connect():
    connection = await psycopg.AsyncConnection.connect(
        os.environ["CRYPTALIS_TEST_DATABASE_URL"], **probe_service.EXPECTED,
        hostaddr="127.0.0.1", connect_timeout=3)
    try:
        cursor = await connection.execute("SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user")
        row = await cursor.fetchone()
        if row[:2] != ("cryptalis_test", "cryptalis_migrator") or any(row[2:]):
            raise ValueError("RESTRICTED_ROLE_REQUIRED")
        await connection.commit()
        return connection
    except BaseException:
        await connection.close()
        raise


class PreparedFrame(bytes):
    pass


class NativeText(ProtectedText):
    cache_ok = False
    pg = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, PreparedFrame):
            raise UnsupportedProtectedOperation("Prepared row parameters required")
        return bytes(value)


class Base(DeclarativeBase):
    pass


class Contact(Base):
    __tablename__ = "contact"
    id = Column(BigInteger, Identity(), primary_key=True)
    email = Column(String)
    name = Column(String)


class LabSession(Session):
    pass


def attach_candidate(engine, schema):
    """One text field/context. This does not implement the public manifest API."""
    @event.listens_for(engine, "before_execute", retval=True)
    def bind_rows(connection, statement, multiparams, params, options):
        if isinstance(statement, TextClause):
            raise UnsupportedProtectedOperation("Raw SQL is outside the attached lab path")
        if not (getattr(statement, "is_insert", False) or getattr(statement, "is_update", False)):
            return statement, multiparams, params
        if getattr(statement, "table", None) is not Contact.__table__:
            return statement, multiparams, params
        prepared = connection.info.get("revamp_rows", {})
        if not prepared:
            raise UnsupportedProtectedOperation("Only prepared instance writes are admitted")
        changed = []
        for parameters in (list(multiparams) if multiparams else [params]):
            row = dict(parameters)
            identity = row.get("id")
            if identity is None and getattr(statement, "is_update", False):
                for node in visitors.iterate(statement.whereclause):
                    if isinstance(node, BinaryExpression) and node.left.compare(Contact.__table__.c.id) and isinstance(node.right, BindParameter):
                        identity = row.get(node.right.key)
            if identity not in prepared:
                raise UnsupportedProtectedOperation("Row context is unavailable")
            if "email" in row:
                original, sealed = prepared[identity]
                if row["email"] != original:
                    raise UnsupportedProtectedOperation("Prepared value changed")
                row["email"] = sealed
            changed.append(row)
        return (statement, changed, {}) if multiparams else (statement, [], changed[0])

    @event.listens_for(engine, "before_cursor_execute")
    def reject_driver_sql(connection, cursor, statement, parameters, context, many):
        if context.compiled is None:
            raise UnsupportedProtectedOperation("Direct driver SQL is outside the attached lab path")


@event.listens_for(LabSession, "before_flush")
def prepare(session, context, instances):
    connection = session.connection()
    session.info["revamp_connections"] = [connection]
    prepared = {}
    for obj in session.new | session.dirty:
        if not isinstance(obj, Contact):
            continue
        state = inspect(obj)
        if state.persistent and state.attrs.id.history.has_changes():
            raise UnsupportedProtectedOperation("Stable identity required")
        if obj.id is None:
            # Deliberately reject until the original sequence/default contract is qualified.
            raise UnsupportedProtectedOperation("Generated identity preparation is not qualified")
        if obj.email is not None and type(obj.email) is not str:
            raise UnsupportedProtectedOperation("Exact text required")
        prepared[obj.id] = (obj.email, None if obj.email is None else PreparedFrame(protect(obj.id, obj.email)))
    connection.info["revamp_rows"] = prepared


def clear(session, *args):
    for connection in session.info.pop("revamp_connections", []):
        if not connection.closed:
            connection.info.pop("revamp_rows", None)


event.listen(LabSession, "after_flush_postexec", clear)
event.listen(LabSession, "after_soft_rollback", clear)


def rejected(outcomes, name, action):
    try:
        action()
    except UnsupportedProtectedOperation:
        outcomes[name] = "PASS"
    except StatementError as failure:
        if not isinstance(failure.orig, UnsupportedProtectedOperation):
            raise
        outcomes[name] = "PASS"
    else:
        raise AssertionError(name)


def check(outcomes, name, condition):
    if not condition:
        raise AssertionError(name)
    outcomes[name] = "PASS"


def sync_cases(engine, admin, schema, outcomes):
    observed = {"exposure": False}

    def inspect_binds(connection, cursor, statement, parameters, context, many):
        def exposed(value):
            if isinstance(value, str):
                return value in MARKERS
            if isinstance(value, dict):
                return any(exposed(item) for item in value.values())
            if isinstance(value, (list, tuple)):
                return any(exposed(item) for item in value)
            return False
        observed["exposure"] |= exposed(parameters)

    event.listen(engine, "before_cursor_execute", inspect_binds)
    with engine.connect() as connection:
        connection.execute(select(1).where(text(":marker = :marker")), {"marker": "same@example.test"})
    check(outcomes, "bind_collector_positive_control", observed["exposure"])
    observed["exposure"] = False
    with LabSession(engine) as session:
        rows = [Contact(id=1, email="same@example.test", name="One"),
                Contact(id=2, email="same@example.test", name="Two"),
                Contact(id=3, email=None, name="Null"), Contact(id=4, email="", name="Empty")]
        session.add_all(rows)
        session.flush()
        check(outcomes, "exact_str_after_batched_insert", all(type(row.email) is str for row in (rows[0], rows[1], rows[3])))
        check(outcomes, "batched_row_context", session.scalars(select(Contact.email).order_by(Contact.id)).all() == ["same@example.test", "same@example.test", None, ""])
        check(outcomes, "no_protected_plaintext_bind", not observed["exposure"])
        check(outcomes, "preparation_cleared_after_flush", "revamp_rows" not in session.connection().info)
        check(outcomes, "equal_ids", session.scalars(select(Contact.id).where(Contact.email == "same@example.test").order_by(Contact.id)).all() == [1, 2])
        check(outcomes, "mixed_null_in", session.scalars(select(Contact.id).where(Contact.email.in_([None, "same@example.test"])).order_by(Contact.id)).all() == [1, 2])
        check(outcomes, "empty_in", not session.scalars(select(Contact.id).where(Contact.email.in_([]))).all())
        check(outcomes, "not_in_null", not session.scalars(select(Contact.id).where(Contact.email.not_in([None, "same@example.test"]))).all())
        check(outcomes, "null_presence", session.scalars(select(Contact.id).where(Contact.email.is_(None))).all() == [3])
        other = aliased(Contact)
        check(outcomes, "aliased_scalar_projection", session.scalar(select(other.email).where(other.id == 2)) == "same@example.test")
        check(outcomes, "null_outer_join_projection", session.execute(select(Contact.id, other.email).outerjoin(other, other.id == Contact.id + 100).order_by(Contact.id)).all() == [(1, None), (2, None), (3, None), (4, None)])
        session.commit()
        rows[0].email = "changed@example.test"
        rows[1].email = "second@example.test"
        session.flush()
        check(outcomes, "batched_update_row_context", session.scalars(select(Contact.email).where(Contact.id.in_([1, 2])).order_by(Contact.id)).all() == ["changed@example.test", "second@example.test"])
        check(outcomes, "history_after_update", not inspect(rows[0]).attrs.email.history.has_changes() and type(rows[0].email) is str)
        session.rollback()
        check(outcomes, "rollback_native_value", rows[0].email == "same@example.test" and type(rows[0].email) is str)
        rows[0].email = "discard@example.test"
        session.refresh(rows[0])
        check(outcomes, "refresh_pending_value", rows[0].email == "same@example.test")
        session.expire(rows[0])
        check(outcomes, "expiry_native_value", type(rows[0].email) is str)
        merged = session.merge(Contact(id=1, email="merged@example.test", name="One"))
        session.flush()
        check(outcomes, "merge_native_value", merged.email == "merged@example.test" and type(merged.email) is str)
        rows[1].email = "changed@example.test"
        check(outcomes, "autoflush_native_value", session.scalar(select(Contact.email).where(Contact.id == 2)) == "changed@example.test")
        session.rollback()
        rejected(outcomes, "bulk_update_rejected", lambda: session.execute(update(Contact).values(email="bypass@example.test")))
        rejected(outcomes, "raw_session_rejected", lambda: session.execute(text("SELECT 1")))
        rejected(outcomes, "generated_id_rejected", lambda: (session.add(Contact(email="generated@example.test")), session.flush()))
        session.rollback()
        check(outcomes, "failed_flush_cleanup", "revamp_rows" not in session.connection().info)
        rejected(outcomes, "identity_mutation_rejected", lambda: (setattr(rows[0], "id", 99), session.flush()))
        session.rollback()
        session.expunge_all()
        session.add(Contact(id=1, email="duplicate@example.test"))
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
        else:
            raise AssertionError("database_failed_flush")
        check(outcomes, "database_failed_flush_cleanup", "revamp_rows" not in session.connection().info)
        session.add(Contact(id=8, email="recovered@example.test", name="Recovered"))
        session.commit()
        check(outcomes, "after_failed_flush_recovery", session.get(Contact, 8).email == "recovered@example.test")
        check(outcomes, "updated_plaintext_markers_absent", not observed["exposure"])
    with engine.connect() as connection:
        rejected(outcomes, "unprepared_core_rejected", lambda: connection.execute(Contact.__table__.insert(), {"id": 9, "email": "raw@example.test"}))
        rejected(outcomes, "exec_driver_sql_rejected", lambda: connection.exec_driver_sql("SELECT 1"))
    with admin.connect() as connection:
        frames = connection.exec_driver_sql('SELECT id,email FROM "' + schema + '".contact ORDER BY id').all()
        check(outcomes, "randomized_duplicate_payloads", frames[0][1] != frames[1][1])
        check(outcomes, "database_bytes_only", all(payload is None or isinstance(payload, bytes) for _, payload in frames))
        frame = frames[0][1]
        for name, identity, damaged in [("tamper_rejected", 1, frame[:-1] + bytes([frame[-1] ^ 1])), ("relocation_rejected", 2, frame)]:
            try:
                reveal(identity, damaged)
            except InvalidTag:
                outcomes[name] = "PASS"
            else:
                raise AssertionError(name)
    with connect() as connection:
        with connection.cursor() as cursor:
            # Known independent privileged writer: bypass remains visible, not called safe.
            with cursor.copy(sql.SQL("COPY {}.contact (id,email,name) FROM STDIN").format(sql.Identifier(schema))) as copy:
                copy.write_row((50, b"plaintext-bypass", "Copy control"))
        check(outcomes, "copy_bypass_positive_control", connection.execute(sql.SQL("SELECT email FROM {}.contact WHERE id=50").format(sql.Identifier(schema))).fetchone()[0] == b"plaintext-bypass")
        connection.rollback()
    # Verify rejection through SQLAlchemy result processing, before a value is returned.
    for name, damaged in (("orm_tamper_rejected", frame[:-1] + bytes([frame[-1] ^ 1])),
                          ("orm_row_relocation_rejected", frames[1][1])):
        with admin.begin() as connection:
            connection.exec_driver_sql('UPDATE "' + schema + '".contact SET email=%s WHERE id=1', (damaged,))
        try:
            with LabSession(engine) as session:
                session.scalar(select(Contact.email).where(Contact.id == 1))
        except InvalidTag:
            outcomes[name] = "PASS"
        else:
            raise AssertionError(name)
        finally:
            with admin.begin() as connection:
                connection.exec_driver_sql('UPDATE "' + schema + '".contact SET email=%s WHERE id=1', (frame,))
    event.remove(engine, "before_cursor_execute", inspect_binds)


def uniqueness_case(schema, outcomes):
    barrier = threading.Barrier(2)

    def writer(identity):
        with connect() as connection:
            connection.execute("SET LOCAL statement_timeout='10s'")
            barrier.wait(timeout=10)
            try:
                connection.execute(sql.SQL("INSERT INTO {}.unique_terms VALUES (%s,%s)").format(sql.Identifier(schema)), (identity, token("unique@example.test")))
                connection.commit()
                return "COMMITTED"
            except psycopg.errors.UniqueViolation:
                connection.rollback()
                return "UNIQUE_REJECTED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first, second = executor.submit(writer, 1), executor.submit(writer, 2)
        results = [first.result(timeout=15), second.result(timeout=15)]
    check(outcomes, "concurrent_term_uniqueness", sorted(results) == ["COMMITTED", "UNIQUE_REJECTED"])
    with connect() as connection:
        count = connection.execute(sql.SQL("SELECT count(*) FROM {}.unique_terms").format(sql.Identifier(schema))).fetchone()[0]
        check(outcomes, "concurrent_single_committed_row", count == 1)


async def async_cases(schema, outcomes):
    engine = create_async_engine("postgresql+psycopg://", async_creator=async_connect, hide_parameters=True, poolclass=NullPool)
    engine = engine.execution_options(schema_translate_map={None: schema})
    attach_candidate(engine.sync_engine, schema)
    try:
        async def worker(identity, value):
            async with AsyncSession(engine, sync_session_class=LabSession, expire_on_commit=False) as session:
                session.add(Contact(id=identity, email=value, name="Async"))
                await session.flush()
                row = await session.get(Contact, identity)
                if type(row.email) is not str or row.email != value:
                    raise AssertionError("async_original_type")
                await session.commit()
                await session.refresh(row)
                return row.email
        values = await asyncio.gather(worker(101, "async@example.test"), worker(102, "other-async@example.test"))
        check(outcomes, "async_concurrent_session_isolation", values == ["async@example.test", "other-async@example.test"])
        async with AsyncSession(engine, sync_session_class=LabSession) as session:
            check(outcomes, "async_scalar_projection", await session.scalar(select(Contact.email).where(Contact.id == 101)) == "async@example.test")
            row = await session.get(Contact, 101)
            row.email = "async-rollback@example.test"
            await session.flush()
            await session.rollback()
            await session.refresh(row)
            check(outcomes, "async_rollback_refresh", row.email == "async@example.test" and type(row.email) is str)
    finally:
        await engine.dispose()

    # A real driver cancellation, not a synthetic provider cancellation result.
    connection = await async_connect()
    observer = await async_connect()
    try:
        cursor = await connection.execute("SELECT pg_backend_pid()")
        pid = (await cursor.fetchone())[0]
        await connection.commit()
        running = asyncio.create_task(connection.execute("SELECT pg_sleep(30)"))
        deadline = time.monotonic() + 5
        while True:
            cursor = await observer.execute("SELECT wait_event FROM pg_stat_activity WHERE pid=%s", (pid,))
            wait_event = (await cursor.fetchone())[0]
            await observer.rollback()
            if wait_event == "PgSleep":
                break
            if time.monotonic() > deadline:
                raise AssertionError("cancel_query_not_observed")
            await asyncio.sleep(0.02)
        running.cancel()
        try:
            await running
        except asyncio.CancelledError:
            outcomes["async_driver_cancellation_observed"] = "PASS"
        else:
            raise AssertionError("async_driver_cancellation_observed")
        await connection.rollback()
        cursor = await connection.execute("SELECT 1")
        check(outcomes, "async_connection_usable_after_cancel_rollback", (await cursor.fetchone())[0] == 1)
    finally:
        await connection.close()
        await observer.close()


def main():
    try:
        probe_service.main()
    except SystemExit as stopped:
        if stopped.code != 0:
            raise
    schema = "revamp_native_service_" + uuid.uuid4().hex
    outcomes = {}
    result = {"status": "UNKNOWN", "schema": schema, "connection_url": "NEVER_RECORDED", "outcomes": outcomes,
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "dependencies_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ("run_adapter.py", "plain_app.py", "probe_service.py")},
              "gates": {name: "INCOMPLETE" for name in ("G-ADAPTER", "G-CRYPTO", "G-QUERY", "G-LIFECYCLE", "G-PROVIDER", "G-POLICY", "G-RELEASE")},
              "raw_independent_copy": "BYPASS_EXPECTED_NEGATIVE_CONTROL", "protected_application_oracle": "NOT_RUN",
              "limits": ["Public lab keys and old lab frame, not CF1", "One synthetic text field and fixed context; no tenant integration", "Explicit bigint IDs only; generated identities rejected", "No full clause guard, cascade or manifest compiler", "No remote provider; cancellation is driver-only", "Migration role used throughout; no runtime-role isolation", "Independent COPY can bypass attached hooks", "Original application remains unqualified; no acceptance cases removed"]}
    admin = create_engine("postgresql+psycopg://", creator=connect, hide_parameters=True, poolclass=NullPool)
    engine = create_engine("postgresql+psycopg://", creator=connect, hide_parameters=True, poolclass=NullPool)
    created = False
    stage = "create_owned_schema"
    try:
        with admin.begin() as connection:
            connection.execute(CreateSchema(schema))
        created = True
        Contact.__table__.c.email.type = NativeText(FIELD)
        Base.metadata.create_all(admin.execution_options(schema_translate_map={None: schema}))
        with connect() as connection:
            connection.execute(sql.SQL("CREATE TABLE {}.unique_terms(id bigint PRIMARY KEY, term bytea UNIQUE)").format(sql.Identifier(schema)))
        engine = engine.execution_options(schema_translate_map={None: schema})
        attach_candidate(engine, schema)
        stage = "sync_native_adapter"
        sync_cases(engine, admin, schema, outcomes)
        stage = "concurrent_uniqueness"
        uniqueness_case(schema, outcomes)
        stage = "async_and_cancellation"
        asyncio.run(async_cases(schema, outcomes))
        result["status"] = "PASS_LISTED_SERVICE_CASES_ONLY"
    except Exception as failure:
        result.update(status="FAIL", stage=stage, exception_type=type(failure).__name__, sqlstate=getattr(failure, "sqlstate", None), details="WITHHELD")
        if isinstance(failure, AssertionError) and len(failure.args) == 1 and str(failure.args[0]).replace("_", "").isalnum():
            result["failed_check"] = failure.args[0]
    finally:
        engine.dispose()
        if created:
            try:
                with admin.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
                result["cleanup"] = "OWN_SCHEMA_DROPPED"
            except Exception as failure:
                result.update(status="FAIL", cleanup="FAILED", cleanup_exception_type=type(failure).__name__)
        admin.dispose()
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "passed": len(outcomes), "stage": result.get("stage"), "exception_type": result.get("exception_type"), "failed_check": result.get("failed_check"), "cleanup": result.get("cleanup")}))
    raise SystemExit(0 if result["status"] == "PASS_LISTED_SERVICE_CASES_ONLY" else 1)


if __name__ == "__main__":
    main()
