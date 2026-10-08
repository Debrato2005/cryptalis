"""Small regression cases for real assignment gaps and atomic transition failures."""
from psycopg import sql
import psycopg
from sqlalchemy import func, insert, literal, select, update
from sqlalchemy.orm import Session

from integration_adapter import Attachment
from integration_crypto import Failure
from integration_harness import Harness, LOCAL_WRITERS
from integration_transition import Transition
from run_gate_retrofit import MANIFEST, check, rejects


def cases(h):
    app, out = h.app, h.outcomes
    with Session(h.engine) as session:
        account = app.Account(name="fault-source")
        account.customers = [app.Customer(email="fault-" + str(n) + "@example.test", display_name="Fault", age=20) for n in range(160)]
        session.add(account)
        session.commit()
        tenant = account.id
    h.attachment = Attachment(app.Base.registry, h.engine, MANIFEST, h.provider, h.schema, True, LOCAL_WRITERS)
    transition = Transition(h.attachment, "protect", chunk_size=40)
    plan = h.attachment.plans[0]
    with transition.open() as connection:
        transition.expand(connection)
        def sql_error(connection, number):
            connection.execute("SELECT 1/0")
        rejects(out, "real_sql_error_stops_chunk", lambda: transition.backfill(connection, before_commit=sql_error), psycopg.errors.DivisionByZero)
        connection.rollback()
        marker = connection.execute(sql.SQL("SELECT count(*) FROM {} WHERE operation=%s").format(transition.markers), (transition.operation,)).fetchone()[0]
        prepared = connection.execute(sql.SQL("SELECT count({}) FROM {}").format(sql.Identifier(transition.shadow(plan)), transition.table(plan))).fetchone()[0]
        check(out, "sql_failed_chunk_data_and_marker_roll_back", marker == prepared == 0)
        connection.commit()
        original = h.provider.prepare
        calls = {"count": 0}
        def unavailable(*args, **kwargs):
            calls["count"] += 1
            if calls["count"] > 5:
                raise Failure("LOCAL_INJECTED_PROVIDER_OUTAGE")
            return original(*args, **kwargs)
        h.provider.prepare = unavailable
        try:
            rejects(out, "provider_failure_stops_chunk", lambda: transition.backfill(connection), Failure)
        finally:
            h.provider.prepare = original
        connection.rollback()
        marker = connection.execute(sql.SQL("SELECT count(*) FROM {} WHERE operation=%s").format(transition.markers), (transition.operation,)).fetchone()[0]
        prepared = connection.execute(sql.SQL("SELECT count({}) FROM {}").format(sql.Identifier(transition.shadow(plan)), transition.table(plan))).fetchone()[0]
        check(out, "provider_failed_chunk_data_and_marker_roll_back", marker == prepared == 0)
        connection.commit()
        transition.backfill(connection)
        connection.commit()
        with connection.transaction(force_rollback=True):
            connection.execute(sql.SQL("UPDATE {} SET plan_digest='changed' WHERE operation=%s").format(transition.journal), (transition.operation,))
            rejects(out, "changed_operation_plan_blocks_resume", lambda: transition.backfill(connection), Failure)
        # inspect_operation starts a read transaction; backfill commits it. Do not
        # inject a marker mutant around backfill, which is deliberately committing.
        transition.switch(connection)
    h.attachment.install()
    with Session(h.engine) as session:
        before = h.attachment.driver_executions
        rejects(out, "computed_tenant_assignment_rejected_before_wire", lambda: session.execute(update(app.Customer).where(app.Customer.id == 1).values(account_id=app.Customer.account_id + 1)), Failure)
        rejects(out, "protected_sql_function_assignment_rejected_before_wire", lambda: session.execute(update(app.Customer).where(app.Customer.id == 1).values(email=func.concat(literal("plain"), literal("@example.test")))), Failure)
        rejects(out, "insert_select_protected_writer_rejected", lambda: session.execute(insert(app.Customer).from_select(["account_id", "email", "display_name", "age"], select(literal(tenant), literal("insert-select@example.test"), literal("Opaque source"), literal(30)))), Failure)
        rejects(out, "static_multirow_insert_rejected", lambda: session.execute(insert(app.Customer).values([{"account_id": tenant, "email": "multi-a@example.test", "display_name": "A", "age": 1}, {"account_id": tenant, "email": "multi-b@example.test", "display_name": "B", "age": 2}])), Failure)
        check(out, "rejected_expression_writers_have_no_wire_execution", h.attachment.driver_executions == before)
        check(out, "failed_writer_keeps_original_authenticated_row", session.get(app.Customer, 1).email == "fault-0@example.test")
    with h.engine.connect() as connection:
        before = h.attachment.driver_executions
        forged = update(app.Customer).where(app.Customer.id == 1).values(email=func.concat(literal("plain"), literal("@example.test"))).execution_options(cl_assignment_rhs={plan.crypto.identity: (None, None)})
        rejects(out, "caller_cannot_forge_internal_dml_admission", lambda: connection.execute(forged), Failure)
        check(out, "forged_admission_has_no_wire_effect", h.attachment.driver_executions == before)
    h.result["limits"] = ["No actual disk-full or WAL quota fault was induced", "Injected provider failure is local only",
                          "Real restore/deployment provenance and independent-process provider restart remain UNKNOWN"]


if __name__ == "__main__":
    Harness("faults").run(cases, __file__)
