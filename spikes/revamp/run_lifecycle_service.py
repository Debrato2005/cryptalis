"""Disposable service lifecycle and CF1 transport lab; not a transition runtime."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid

from cryptography.exceptions import InvalidTag
import psycopg
from psycopg import sql

import probe_service
from run_cf1 import FrameRejected, KeyUnavailable, open_frame, seal
from run_native_service import check, connect


RESULT = Path(__file__).with_name("results") / "lifecycle-service.json"
ROWS = 1000


class TransitionIncomplete(ValueError):
    pass


class ResetMutant(Exception):
    pass


def owned(schema, table):
    if not schema.startswith("revamp_lifecycle_service_") or len(schema) != len("revamp_lifecycle_service_") + 32:
        raise ValueError("OWNED_SCHEMA_REQUIRED")
    uuid.UUID(hex=schema.removeprefix("revamp_lifecycle_service_"))
    return sql.Identifier(schema, table)


def chunk(schema, start, end, operation, stop_after_commit=False):
    with connect() as connection:
        selected = connection.execute(sql.SQL("SELECT operation FROM {} WHERE id=1").format(owned(schema, "operations"))).fetchone()
        if selected != (operation,):
            raise TransitionIncomplete("Operation identity mismatch")
        if connection.execute(sql.SQL("SELECT 1 FROM {} WHERE first_id=%s AND last_id=%s").format(owned(schema, "chunks")), (start, end)).fetchone():
            return "ALREADY_COMMITTED"
        rows = connection.execute(sql.SQL("SELECT id,value FROM {} WHERE id BETWEEN %s AND %s ORDER BY id").format(owned(schema, "source")), (start, end)).fetchall()
        if [row[0] for row in rows] != list(range(start, end + 1)):
            raise TransitionIncomplete("Chunk membership mismatch")
        for identity, value in rows:
            payload, companions = (None, {}) if value is None else seal(value, identity, equality=True, prefix=True)
            connection.execute(sql.SQL("INSERT INTO {} VALUES (%s,%s,%s)").format(owned(schema, "shadow")), (identity, payload, companions.get(b"prefix")))
        connection.execute(sql.SQL("INSERT INTO {} VALUES (%s,%s,%s)").format(owned(schema, "chunks")), (start, end, len(rows)))
        connection.commit()
        if stop_after_commit:
            os._exit(70)  # Durable commit; process ends before it reports completion.
        return "COMMITTED"


def decode_transport(value, expected_record):
    if not isinstance(value, bytes) or len(value) < 16 or len(value) > 40_000:
        raise FrameRejected("Transport bounds exceeded")
    record, size = struct.unpack(">qi", value[:12])
    if record != expected_record or size < 42 or size > 1130 or len(value) < 16 + size:
        raise FrameRejected("Invalid expected context or payload size")
    payload = value[12:12 + size]
    count = struct.unpack(">i", value[12 + size:16 + size])[0]
    if count < 0 or count > 1025:
        raise FrameRejected("Invalid companion count")
    position = 16 + size
    terms = []
    for _ in range(count):
        if len(value) < position + 4:
            raise FrameRejected("Truncated companion length")
        size = struct.unpack(">i", value[position:position + 4])[0]
        position += 4
        if size != 32 or len(value) < position + size:
            raise FrameRejected("Invalid companion term")
        terms.append(value[position:position + size])
        position += size
    if position != len(value) or len(terms) != len(set(terms)):
        raise FrameRejected("Trailing or duplicate companion data")
    return open_frame(payload, record, {b"prefix": terms})


def projection(schema, table):
    # Built-in binary transport from the architecture, with actual returned arrays.
    return sql.SQL("""SELECT id, CASE WHEN payload IS NULL THEN NULL ELSE
        int8send(id) || int4send(octet_length(payload)) || payload ||
        int4send(COALESCE(cardinality(prefix),-1)) || COALESCE(
          (SELECT string_agg(int4send(COALESCE(octet_length(term),-1)) || COALESCE(term,''::bytea),''::bytea ORDER BY ordinal)
           FROM unnest(prefix) WITH ORDINALITY AS terms(term,ordinal)),''::bytea)
        END AS transport FROM {} ORDER BY id""").format(owned(schema, table))


def verify(connection, schema, table, expected, index_name):
    rows = connection.execute(projection(schema, table)).fetchall()
    if [row[0] for row in rows] != sorted(expected):
        raise TransitionIncomplete("Full membership mismatch")
    for identity, transport in rows:
        try:
            value = None if transport is None else decode_transport(transport, identity)
        except (FrameRejected, KeyUnavailable, InvalidTag, UnicodeError) as failure:
            raise TransitionIncomplete("Protected representation rejected") from failure
        if value != expected[identity] or type(value) is not type(expected[identity]):
            raise TransitionIncomplete("Value or type mismatch")
    index = connection.execute("SELECT i.indisvalid,i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s", (schema, index_name)).fetchone()
    if index != (True, True):
        raise TransitionIncomplete("Required valid index absent")


def mutant(connection, schema, outcomes, expected, name, statement, parameters=()):
    try:
        with connection.transaction():
            connection.execute(statement, parameters)
            try:
                verify(connection, schema, "shadow", expected, "shadow_eq")
            except TransitionIncomplete:
                outcomes[name] = "PASS"
            else:
                raise AssertionError(name)
            raise ResetMutant()
    except ResetMutant:
        pass


PACKAGE_FREE = r'''
import hashlib
import importlib.abc
import json
import os
import sys
import psycopg
from psycopg.conninfo import conninfo_to_dict
from sqlalchemy import BigInteger, Column, MetaData, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Session
class BlockCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname.split('.')[0] in ('cryptalis','cryptography','run_cf1','run_adapter','run_native_service'):
            raise ImportError('Cryptalis and lab readers are excluded')
sys.meta_path.insert(0, BlockCryptalis())
schema, expected_digest = sys.argv[1:]
expected = {'host':'127.0.0.1','port':'55432','dbname':'cryptalis_test','user':'cryptalis_migrator'}
def creator():
    config = conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
    if any(str(config.get(key)) != value for key,value in expected.items()):
        raise ValueError('Target not authorized')
    connection = psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], **expected, hostaddr='127.0.0.1', connect_timeout=3)
    row = connection.execute('SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
    if row[:2] != ('cryptalis_test','cryptalis_migrator') or any(row[2:]):
        connection.close()
        raise ValueError('Restricted role required')
    connection.commit()
    return connection
class Base(DeclarativeBase):
    metadata = MetaData(schema=schema)
class Ordinary(Base):
    __tablename__ = 'plain'
    id = Column(BigInteger,primary_key=True)
    value = Column(String)
try:
    engine = create_engine('postgresql+psycopg://',creator=creator,hide_parameters=True)
    with Session(engine) as session:
        rows = session.execute(select(Ordinary.id,Ordinary.value).order_by(Ordinary.id)).all()
        digest = hashlib.sha256(json.dumps([list(row) for row in rows],ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        if digest != expected_digest or any(value is not None and type(value) is not str for _,value in rows):
            raise ValueError('Native application result mismatch')
        session.get(Ordinary,10).value = 'package-free-edit'
        session.commit()
    engine.dispose()
    if any(name.split('.')[0] in ('cryptalis','cryptography','run_cf1','run_adapter','run_native_service') for name in sys.modules):
        raise ValueError('Excluded reader imported')
    print(json.dumps({'status':'PASS_ORDINARY_APPLICATION_ONLY','rows':len(rows),'excluded_readers_loaded':False}))
except Exception as failure:
    print(json.dumps({'status':'FAIL','exception_type':type(failure).__name__,'details':'WITHHELD'}))
    raise SystemExit(1)
'''


def main():
    if sys.argv[1:2] == ["--chunk"]:
        try:
            _, schema, start, end, operation, mode = sys.argv[1:]
            chunk(schema, int(start), int(end), operation, mode == "stop-after-commit")
        except Exception as failure:
            print(json.dumps({"status": "FAIL_CHUNK", "exception_type": type(failure).__name__, "details": "WITHHELD"}))
            raise SystemExit(1)
        return
    if sys.argv[1:]:
        raise SystemExit("Use no arguments for the service lab")
    try:
        probe_service.main()
    except SystemExit as stopped:
        if stopped.code != 0:
            raise
    schema = "revamp_lifecycle_service_" + uuid.uuid4().hex
    operation = uuid.uuid4().hex
    lock_id = int(operation[:15], 16)
    expected = {identity: None if identity % 17 == 0 else f"synthetic-{identity}" for identity in range(1, ROWS + 1)}
    expected.update({1: "", 2: "é", 3: "e\u0301", 4: "a%b"})
    outcomes = {}
    result = {"status": "UNKNOWN", "schema": schema, "rows": ROWS, "outcomes": outcomes, "connection_url": "NEVER_RECORDED",
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "dependencies_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ("run_native_service.py", "run_cf1.py", "probe_service.py")},
              "gates": {"G-LIFECYCLE": "INCOMPLETE", "G-CRYPTO": "INCOMPLETE", "G-POLICY": "INCOMPLETE", "G-PROVIDER": "INCOMPLETE"},
              "limits": ["1000 synthetic rows; public offline CF1 roots and narrow text codec", "Table lock excludes one tested writer; no deployment worker inventory/drain proof", "Post-commit process exit suppresses completion; no transport-level lost COMMIT reply fault", "No live provider rewrap/deletion or authenticated deployment-policy publication", "Native package-free two-column application only; original three-model oracle remains unqualified", "Companion transport uses actual PG/psycopg bytes; no advanced SQLAlchemy adapter qualification", "No retained backup/old-reader retirement proof or scale/pause budget"]}
    created = False
    connection = None
    stage = "create_owned_fixture"
    try:
        with connect() as setup:
            setup.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            setup.execute(sql.SQL("CREATE TABLE {}(id bigint PRIMARY KEY,value text)").format(owned(schema, "source")))
            setup.execute(sql.SQL("CREATE TABLE {}(id bigint PRIMARY KEY,payload bytea,prefix bytea[])").format(owned(schema, "shadow")))
            setup.execute(sql.SQL("CREATE TABLE {}(id int PRIMARY KEY,operation text NOT NULL,phase text NOT NULL)").format(owned(schema, "operations")))
            setup.execute(sql.SQL("CREATE TABLE {}(first_id int PRIMARY KEY,last_id int NOT NULL,row_count int NOT NULL)").format(owned(schema, "chunks")))
            setup.execute(sql.SQL("INSERT INTO {} VALUES(1,%s,'BACKFILL')").format(owned(schema, "operations")), (operation,))
            with setup.cursor().copy(sql.SQL("COPY {} FROM STDIN").format(owned(schema, "source"))) as copy:
                for row in expected.items():
                    copy.write_row(row)
        created = True
        connection = connect()
        connection.execute("SELECT pg_advisory_lock(%s)", (lock_id,))
        connection.commit()
        with connect() as second:
            check(outcomes, "second_executor_lock_denied", second.execute("SELECT pg_try_advisory_lock(%s)", (lock_id,)).fetchone() == (False,))
        connection.execute(sql.SQL("LOCK TABLE {} IN SHARE MODE").format(owned(schema, "source")))
        with connect() as writer:
            writer.execute("SET LOCAL lock_timeout='150ms'")
            try:
                writer.execute(sql.SQL("INSERT INTO {} VALUES(1001,'blocked-control')").format(owned(schema, "source")))
            except psycopg.errors.LockNotAvailable:
                outcomes["concurrent_writer_blocked_by_table_lock"] = "PASS"
                writer.rollback()
            else:
                raise AssertionError("concurrent_writer_blocked_by_table_lock")
        stage = "post_commit_process_interruption"
        stopped = subprocess.run([sys.executable, str(Path(__file__)), "--chunk", schema, "1", "100", operation, "stop-after-commit"], capture_output=True)
        check(outcomes, "worker_process_ended_after_commit", stopped.returncode == 70 and not stopped.stdout and not stopped.stderr)
        with connect() as inspect_connection:
            marker = inspect_connection.execute(sql.SQL("SELECT first_id,last_id,row_count FROM {}").format(owned(schema, "chunks"))).fetchall()
            before = inspect_connection.execute(sql.SQL("SELECT id,payload,prefix FROM {} ORDER BY id").format(owned(schema, "shadow"))).fetchall()
        check(outcomes, "chunk_and_marker_committed_together", marker == [(1, 100, 100)] and len(before) == 100)
        check(outcomes, "inspected_retry_idempotent", chunk(schema, 1, 100, operation) == "ALREADY_COMMITTED")
        with connect() as inspect_connection:
            after = inspect_connection.execute(sql.SQL("SELECT id,payload,prefix FROM {} ORDER BY id").format(owned(schema, "shadow"))).fetchall()
        check(outcomes, "retry_keeps_committed_ciphertext", before == after)
        for start in range(101, ROWS + 1, 100):
            chunk(schema, start, start + 99, operation)
        connection.execute(sql.SQL("CREATE UNIQUE INDEX shadow_eq ON {} ((substring(payload FROM 15 FOR 32)))").format(owned(schema, "shadow")))
        stage = "full_verification_mutants"
        verify(connection, schema, "shadow", expected, "shadow_eq")
        outcomes["full_resume_verification"] = "PASS"
        original, terms = connection.execute(sql.SQL("SELECT payload,prefix FROM {} WHERE id=10").format(owned(schema, "shadow"))).fetchone()
        update = sql.SQL("UPDATE {} SET payload=%s WHERE id=10").format(owned(schema, "shadow"))
        update_terms = sql.SQL("UPDATE {} SET prefix=%s WHERE id=10").format(owned(schema, "shadow"))
        mutant(connection, schema, outcomes, expected, "tamper_blocks_verification", update, (original[:-1] + bytes([original[-1] ^ 1]),))
        mutant(connection, schema, outcomes, expected, "missing_row_blocks_verification", sql.SQL("DELETE FROM {} WHERE id=10").format(owned(schema, "shadow")))
        mutant(connection, schema, outcomes, expected, "extra_row_blocks_verification", sql.SQL("INSERT INTO {} VALUES(1001,NULL,NULL)").format(owned(schema, "shadow")))
        mutant(connection, schema, outcomes, expected, "unexpected_null_payload_blocks_verification", update, (None,))
        mutant(connection, schema, outcomes, expected, "missing_companions_blocks_verification", update_terms, (None,))
        mutant(connection, schema, outcomes, expected, "null_term_blocks_verification", update_terms, ([None],))
        mutant(connection, schema, outcomes, expected, "short_term_blocks_verification", update_terms, ([b"short"],))
        mutant(connection, schema, outcomes, expected, "duplicate_terms_blocks_verification", update_terms, ([terms[0], terms[0]],))
        other, _ = seal(expected[10], 11, equality=True, prefix=True)
        mutant(connection, schema, outcomes, expected, "relocation_blocks_verification", update, (other,))
        _, new_terms = seal(expected[10], 10, equality=True, prefix=True, search_generation=2)
        mutant(connection, schema, outcomes, expected, "mixed_search_generation_blocks_verification", update_terms, (new_terms[b"prefix"],))
        mutant(connection, schema, outcomes, expected, "missing_index_blocks_verification", sql.SQL("DROP INDEX {}").format(owned(schema, "shadow_eq")))
        transported = connection.execute(projection(schema, "shadow")).fetchall()[9][1]
        for name, damaged in (("trailing_transport_rejected", transported + b"x"),
                              ("negative_payload_length_rejected", transported[:8] + struct.pack(">i", -1) + transported[12:])):
            try:
                decode_transport(damaged, 10)
            except FrameRejected:
                outcomes[name] = "PASS"
            else:
                raise AssertionError(name)
        check(outcomes, "failed_verification_did_not_switch", connection.execute(sql.SQL("SELECT phase FROM {} WHERE id=1").format(owned(schema, "operations"))).fetchone() == ("BACKFILL",))
        verify(connection, schema, "shadow", expected, "shadow_eq")
        stage = "verified_database_switch"
        connection.execute(sql.SQL("DROP TABLE {}").format(owned(schema, "source")))
        connection.execute(sql.SQL("ALTER TABLE {} RENAME TO active").format(owned(schema, "shadow")))
        connection.execute(sql.SQL("UPDATE {} SET phase='ACTIVE' WHERE id=1").format(owned(schema, "operations")))
        connection.commit()
        stage = "current_protected_edit_and_rotations"
        expected[10] = "current-protected-edit"
        frame, companions = seal(expected[10], 10, equality=True, prefix=True)
        connection.execute(sql.SQL("UPDATE {} SET payload=%s,prefix=%s WHERE id=10").format(owned(schema, "active")), (frame, companions[b"prefix"]))
        for payload_generation, search_generation in ((2, 1), (2, 2)):
            before_terms = dict(connection.execute(sql.SQL("SELECT id,prefix FROM {} ORDER BY id").format(owned(schema, "active"))).fetchall())
            for identity, value in expected.items():
                if value is None:
                    continue
                frame, companions = seal(value, identity, equality=True, prefix=True, payload_generation=payload_generation, search_generation=search_generation)
                connection.execute(sql.SQL("UPDATE {} SET payload=%s,prefix=%s WHERE id=%s").format(owned(schema, "active")), (frame, companions[b"prefix"], identity))
            verify(connection, schema, "active", expected, "shadow_eq")
            after_terms = dict(connection.execute(sql.SQL("SELECT id,prefix FROM {} ORDER BY id").format(owned(schema, "active"))).fetchall())
            check(outcomes, "payload_rotation_keeps_companions" if search_generation == 1 else "search_rotation_changes_companions", before_terms == after_terms if search_generation == 1 else all(before_terms[key] != after_terms[key] for key in expected if expected[key] is not None))
            connection.commit()
        stage = "verified_current_data_decrypt_back"
        verify(connection, schema, "active", expected, "shadow_eq")
        connection.execute(sql.SQL("CREATE TABLE {}(id bigint PRIMARY KEY,value text)").format(owned(schema, "plain")))
        for identity, transport in connection.execute(projection(schema, "active")).fetchall():
            value = None if transport is None else decode_transport(transport, identity)
            connection.execute(sql.SQL("INSERT INTO {} VALUES(%s,%s)").format(owned(schema, "plain")), (identity, value))
        current = connection.execute(sql.SQL("SELECT id,value FROM {} ORDER BY id").format(owned(schema, "plain"))).fetchall()
        check(outcomes, "decrypt_back_full_current_values", dict(current) == expected)
        connection.commit()
        digest = hashlib.sha256(json.dumps([list(row) for row in current], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        stage = "package_free_application"
        native = subprocess.run([sys.executable, "-I", "-c", PACKAGE_FREE, schema, digest], capture_output=True, text=True)
        if native.returncode != 0 or native.stderr:
            raise AssertionError("package_free_application")
        observation = json.loads(native.stdout)
        check(outcomes, "package_free_native_application", observation == {"status": "PASS_ORDINARY_APPLICATION_ONLY", "rows": ROWS, "excluded_readers_loaded": False})
        check(outcomes, "package_free_current_write", connection.execute(sql.SQL("SELECT value FROM {} WHERE id=10").format(owned(schema, "plain"))).fetchone() == ("package-free-edit",))
        stage = "retire_owned_generated_objects"
        for table in ("active", "chunks", "operations"):
            connection.execute(sql.SQL("DROP TABLE {}").format(owned(schema, table)))
        connection.commit()
        remaining = connection.execute("SELECT tablename FROM pg_tables WHERE schemaname=%s ORDER BY tablename", (schema,)).fetchall()
        check(outcomes, "generated_tables_removed_last", remaining == [("plain",)])
        result["status"] = "PASS_LISTED_LIFECYCLE_CASES_ONLY"
    except Exception as failure:
        result.update(status="FAIL", stage=stage, exception_type=type(failure).__name__, sqlstate=getattr(failure, "sqlstate", None), details="WITHHELD")
        if isinstance(failure, AssertionError) and len(failure.args) == 1 and str(failure.args[0]).replace("_", "").isalnum():
            result["failed_check"] = failure.args[0]
    finally:
        if connection is not None:
            connection.close()  # Roll back and release the session lock on every outcome.
        if created:
            try:
                with connect() as cleanup:
                    cleanup.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
                result["cleanup"] = "OWN_SCHEMA_DROPPED"
            except Exception as failure:
                result.update(status="FAIL", cleanup="FAILED", cleanup_exception_type=type(failure).__name__)
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "passed": len(outcomes), "stage": result.get("stage"), "exception_type": result.get("exception_type"), "failed_check": result.get("failed_check"), "cleanup": result.get("cleanup")}))
    raise SystemExit(0 if result["status"] == "PASS_LISTED_LIFECYCLE_CASES_ONLY" else 1)


if __name__ == "__main__":
    main()
