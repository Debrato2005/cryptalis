"""New representative retrofit evidence. Reuses completed baseline; never qualifies a full gate."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from probe_service import EXPECTED
import re
import sys
import tempfile
import uuid

from sqlalchemy import create_engine, event, insert, inspect, literal, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session, aliased
from sqlalchemy.schema import CreateSchema, DropSchema

import plain_app
from run_native_service import connect


RESULT = Path(__file__).with_name("results") / "gate-retrofit.json"
MANIFEST = {"schema": 1, "profile": "standard", "models": {"Customer": {
    "tenant": "account_id", "fields": {"email": {"protect": True,
    "queries": ["equality", "unique"], "accept_leakage": ["equality"]}}}}}


def fixture():
    original = Path(plain_app.__file__).read_text()
    old = 'connection.execute(text("UPDATE " + qualified + " SET display_name=:value WHERE id=:identity"), {"value": "Raw edited", "identity": customer_id})'
    new = 'connection.execute(update(Customer).where(Customer.id == customer_id).values(display_name="Raw edited"))'
    if original.count(old) != 1:
        raise AssertionError("frozen_writer_location_changed")
    adapted = original.replace(old, new)
    directory = Path(tempfile.mkdtemp(prefix="cryptalis-retrofit-fixture-", dir="/tmp"))
    path = directory / "adapted_app.py"
    path.write_text(adapted)
    spec = importlib.util.spec_from_file_location("cryptalis_retrofit_fixture", path)
    app = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = app
    spec.loader.exec_module(app)
    return app, {"original_source_sha256": hashlib.sha256(original.encode()).hexdigest(),
                 "adapted_source_sha256": hashlib.sha256(adapted.encode()).hexdigest(),
                 "adapted_source_path": str(path), "model_lines_changed": 0,
                 "business_query_lines_changed": 0, "writer_lines_changed": 1,
                 "assertions_changed": 0, "attachment_calls": 1,
                 "writer_change": "Opaque SQL update becomes equivalent typed Core update"}


def check(outcomes, name, condition):
    if not condition:
        raise AssertionError(name)
    outcomes[name] = "PASS"


def rejects(outcomes, name, action, failure_type):
    try:
        action()
    except failure_type:
        outcomes[name] = "PASS"
    except StatementError as failure:
        if not isinstance(failure.orig, failure_type):
            raise
        outcomes[name] = "PASS"
    else:
        raise AssertionError(name)


def cases(app, engine, attachment, outcomes, failure_type):
    # Retain every original assertion; this is the first protected representative execution.
    before = set(outcomes)
    app.exercise(engine, outcomes)
    baseline = json.loads(Path(plain_app.__file__).with_name("results").joinpath("plain-app-service.json").read_text())
    check(outcomes, "all_original_oracle_checks_retained", set(outcomes) - before == set(baseline["outcomes"]))
    protected = {"exposure": False}
    markers = {"generated@example.test", "bulk-generated@example.test", "changed@example.test"}

    @event.listens_for(engine, "before_cursor_execute")
    def collector(connection, cursor, statement, parameters, context, many):
        def contains(value):
            if isinstance(value, str):
                return value in markers
            if isinstance(value, dict):
                return any(contains(item) for item in value.values())
            if isinstance(value, (list, tuple)):
                return any(contains(item) for item in value)
            return False
        protected["exposure"] |= contains(parameters)

    with engine.connect() as connection:
        connection.execute(select(literal("generated@example.test")))
    check(outcomes, "collector_detects_injected_plaintext", protected["exposure"])
    protected["exposure"] = False
    with Session(engine) as session:
        account = app.Account(name="generated-parent")
        account.customers = [app.Customer(email="generated@example.test", display_name="Generated", age=23),
                             app.Customer(email=None, display_name="Null generated", age=None)]
        session.add(account)
        session.flush()
        child = account.customers[0]
        identity, tenant = child.id, account.id
        check(outcomes, "generated_parent_child_identity_context", type(identity) is int and child.account_id == tenant)
        check(outcomes, "generated_exact_str_and_native_history", type(child.email) is str and not inspect(child).attrs.email.history.has_changes())
        check(outcomes, "generated_scalar_read", session.scalar(select(app.Customer.email).where(app.Customer.id == identity)) == "generated@example.test")
        session.commit()
        session.execute(insert(app.Customer), [{"account_id": tenant, "email": "bulk-generated@example.test", "display_name": "Bulk generated", "age": 24},
                                               {"account_id": tenant, "email": None, "display_name": "Bulk null", "age": None}])
        session.commit()
        check(outcomes, "bulk_generated_identity_insert", app.names(session, app.lookup_email(tenant, "bulk-generated@example.test")) == ["Bulk generated"])
        alias = aliased(app.Customer)
        check(outcomes, "alias_scalar_expected_context", session.scalar(select(alias.email).where(alias.id == identity)) == "generated@example.test")
        child = session.get(app.Customer, identity)
        child.email = "changed@example.test"
        session.flush()
        session.rollback()
        check(outcomes, "generated_rollback_expiry", child.email == "generated@example.test" and type(child.email) is str)
        try:
            with session.begin_nested():
                session.add(app.Customer(account_id=tenant, email="generated@example.test", display_name="Duplicate", age=25))
                session.flush()
        except IntegrityError:
            outcomes["generated_savepoint_uniqueness"] = "PASS"
        else:
            raise AssertionError("generated_savepoint_uniqueness")
        session.add(app.Customer(account_id=tenant, email="after-failure@example.test", display_name="Recovered", age=26))
        session.commit()
        check(outcomes, "generated_failed_flush_recovery", app.names(session, app.lookup_email(tenant, "after-failure@example.test")) == ["Recovered"])
        statement = select(app.Customer.id).where(app.Customer.email == "generated@example.test")
        check(outcomes, "repeated_statement_semantics", session.scalars(statement).all() == [identity] and session.scalars(statement).all() == [identity])
        rejects(outcomes, "opaque_session_sql_rejected", lambda: session.execute(text("SELECT 1")), failure_type)
        rejects(outcomes, "protected_ordering_rejected", lambda: session.execute(select(app.Customer).order_by(app.Customer.email)), failure_type)
    check(outcomes, "protected_generated_bulk_binds_no_plaintext", not protected["exposure"])
    with engine.connect() as connection:
        wire_before = attachment.driver_executions
        rejects(outcomes, "exec_driver_sql_rejected", lambda: connection.exec_driver_sql("SELECT 1"), failure_type)
        raw = connection.connection.driver_connection
        cursor = raw.cursor()
        try:
            rejects(outcomes, "raw_cursor_execute_rejected", lambda: cursor.execute("SELECT 1"), failure_type)
            rejects(outcomes, "raw_cursor_executemany_rejected", lambda: cursor.executemany("SELECT %s", [(1,)]), failure_type)
            rejects(outcomes, "raw_copy_rejected_before_enter", lambda: cursor.copy("COPY customer FROM STDIN"), failure_type)
            rejects(outcomes, "raw_cursor_connection_copy_rejected", lambda: cursor.connection.cursor().copy("COPY customer FROM STDIN"), failure_type)
            rejects(outcomes, "raw_protocol_handle_rejected", lambda: raw.pgconn, failure_type)
        finally:
            cursor.close()
        check(outcomes, "denied_raw_paths_send_no_driver_execution", attachment.driver_executions == wire_before)
    with connect() as observer:
        payload = observer.execute('SELECT email FROM "' + attachment.physical_schema + '".customer WHERE id=%s', (identity,)).fetchone()[0]
        check(outcomes, "database_generated_value_is_cf1_bytes", isinstance(payload, bytes) and payload.startswith(b"CF1\x00"))
    event.remove(engine, "before_cursor_execute", collector)


def main():
    outcomes = {}
    result = {"status": "FAIL", "connection_url": "NEVER_RECORDED", "outcomes": outcomes,
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "gates": {gate: "UNKNOWN" for gate in ("G-ADAPTER", "G-CRYPTO", "G-QUERY", "G-LIFECYCLE", "G-PROVIDER", "G-POLICY", "G-RELEASE")},
              "external_reasons": {"provider": "NO_PRODUCTION_PROVIDER_SELECTED", "policy": "NO_DEPLOYMENT_PROCEDURE_SELECTED", "review": "EXTERNAL_REVIEW_REQUIRED", "runtime_role": "NON_OWNING_RUNTIME_ROLE_NOT_PROVISIONED"}}
    result["implementation_sha256"] = {
        name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
        for name in ("integration_adapter.py", "integration_crypto.py", "integration_transition.py", "integration_async.py", "plain_app.py")}
    engine = None
    attachment = None
    schema = "revamp_gate_retrofit_" + uuid.uuid4().hex
    created = False
    stage = "implementation_available"
    try:
        try:
            from integration_adapter import attach
            from integration_crypto import Failure, LocalKeyring
        except ModuleNotFoundError:
            raise AssertionError("new_integration_implementation_absent") from None
        app, edits = fixture()
        result["adoption_edits"] = edits
        stage = "create_owned_schema"
        url = make_url(os.environ["CRYPTALIS_TEST_DATABASE_URL"]).set(drivername="postgresql+psycopg")
        engine = create_engine(url, echo=False, hide_parameters=True, connect_args={**EXPECTED, "hostaddr": "127.0.0.1", "connect_timeout": 3})
        engine = engine.execution_options(schema_translate_map={app.APP_SCHEMA: schema})
        with engine.begin() as connection:
            connection.execute(CreateSchema(schema))
        created = True
        app.Base.metadata.create_all(engine)
        # Existing data, before attachment. No replay of the completed plaintext oracle.
        with Session(engine) as session:
            seed = app.Account(name="existing-tenant")
            seed.customers = [app.Customer(email="existing@example.test", display_name="Existing", age=31),
                              app.Customer(email=None, display_name="Existing null", age=None)]
            session.add(seed)
            session.commit()
        stage = "protect_existing_application"
        attachment = attach(app.Base.registry, engine, MANIFEST, provider=LocalKeyring(), physical_schema=schema, local_mode=True,
                            writer_inventory={"attached": ["orm", "core", "background"], "unknown": [], "unexcluded": [],
                                              "maintenance": "OWNED_LOCAL_FIXTURE_WRITERS_STOPPED"})
        stage = "representative_protected_oracle"
        cases(app, engine, attachment, outcomes, Failure)
        result.update(status="PASS_NEW_REPRESENTATIVE_CASES_ONLY", driver_executions=attachment.driver_executions)
    except Exception as failure:
        result.update(stage=stage, exception_type=type(failure).__name__, code=getattr(failure, "code", None), details="WITHHELD")
        original_failure = getattr(failure, "orig", failure)
        result["sqlstate"] = getattr(original_failure, "sqlstate", None)
        if isinstance(failure, AssertionError) and len(failure.args) == 1 and re.fullmatch(r"[a-z_]+", str(failure.args[0])):
            result["failed_check"] = failure.args[0]
        trace = failure.__traceback__
        locations = []
        while trace:
            locations.append({"file": Path(trace.tb_frame.f_code.co_filename).name, "line": trace.tb_lineno, "function": trace.tb_frame.f_code.co_name})
            trace = trace.tb_next
        result["safe_locations"] = locations
    finally:
        if attachment is not None:
            attachment.detach()
        if created:
            try:
                with engine.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
                result["cleanup"] = "OWN_SCHEMA_DROPPED"
            except Exception as failure:
                result.update(status="FAIL", cleanup="FAILED", cleanup_exception_type=type(failure).__name__)
        if engine is not None:
            engine.dispose()
    result["schema"] = schema
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result.get(key) for key in ("status", "stage", "exception_type", "code", "sqlstate", "failed_check", "safe_locations", "cleanup")}))
    print(json.dumps({"passed": len(outcomes), "full_gates": result["gates"]}))
    raise SystemExit(0 if result["status"] == "PASS_NEW_REPRESENTATIVE_CASES_ONLY" else 1)


if __name__ == "__main__":
    main()
