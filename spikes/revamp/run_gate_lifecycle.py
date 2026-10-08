"""Journal, real lost reply, current-data rollback and original-application removal evidence."""
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import psycopg
from psycopg import sql
from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from integration_adapter import Attachment
from integration_crypto import Failure, reveal
from integration_harness import Harness, LOCAL_WRITERS
from integration_transition import Transition, maintenance_connection
from run_gate_retrofit import MANIFEST, check, rejects
from run_package_free_original import snapshot


def values(connection, operation, plan):
    return connection.execute(sql.SQL("SELECT {},{} FROM {} ORDER BY {}").format(
        sql.Identifier(plan.identity.name), sql.Identifier(operation.shadow(plan)),
        operation.table(plan), sql.Identifier(plan.identity.name))).fetchall()


def cases(h):
    app, out = h.app, h.outcomes
    with Session(h.engine) as session:
        accounts = [app.Account(name="lifecycle-a"), app.Account(name="lifecycle-b")]
        session.add_all(accounts)
        session.flush()
        tenants = [account.id for account in accounts]
        session.execute(insert(app.Customer), [{"account_id": tenants[n % 2], "email": None if n % 19 == 0 else "lifecycle-" + str(n) + "@example.test",
                                               "display_name": "Lifecycle " + str(n), "age": n % 90} for n in range(1000)])
        session.commit()
    attachment = h.attachment = Attachment(app.Base.registry, h.engine, MANIFEST, h.provider, h.schema, True, LOCAL_WRITERS)
    for tenant in tenants:
        for purpose in (b"payload", b"search"):
            h.provider.prepare(tenant, purpose, 1, create=True)
    operation = Transition(attachment, "protect")
    plan = attachment.plans[0]
    with operation.open() as connection:
        operation.expand(connection)
        rejects(out, "second_executor_advisory_lock_denied", operation.open, Failure)
        connection.commit()
        with connection.transaction():
            connection.execute(sql.SQL("LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE").format(operation.table(plan)))
            def writer():
                try:
                    with maintenance_connection() as alternate:
                        alternate.execute("SET LOCAL statement_timeout='150ms'")
                        alternate.execute(sql.SQL("UPDATE {} SET display_name='Blocked' WHERE id=1").format(operation.table(plan)))
                except psycopg.errors.QueryCanceled:
                    return True
                return False
            with ThreadPoolExecutor(max_workers=1) as pool:
                check(out, "concurrent_writer_observably_blocked", pool.submit(writer).result(timeout=5))
    h.engine.dispose()
    pid = os.fork()
    if pid == 0:
        try:
            h.provider.clear_cache()
            with operation.open() as connection:
                operation.backfill(connection, after_commit=lambda connection, number: os._exit(73))
        except BaseException:
            os._exit(74)
        os._exit(75)
    _, status = os.waitpid(pid, 0)
    check(out, "process_interruption_after_first_durable_chunk", os.waitstatus_to_exitcode(status) == 73)
    with operation.open() as connection:
        markers = connection.execute(sql.SQL("SELECT members FROM {} WHERE operation=%s ORDER BY chunk").format(operation.markers), (operation.operation,)).fetchall()
        check(out, "chunk_marker_and_membership_atomic", len(markers) == 1 and markers[0][0] == list(range(1, 101)))
        prior = values(connection, operation, plan)[:100]
        connection.commit()
        operation.backfill(connection)
        check(out, "resume_preserves_committed_ciphertext", prior == values(connection, operation, plan)[:100])
        connection.commit()
        mutants = {
            "wrong_payload": sql.SQL("UPDATE {} SET {}='bad'::bytea WHERE id=2").format(operation.table(plan), sql.Identifier(operation.shadow(plan))),
            "null_target": sql.SQL("UPDATE {} SET {}=NULL WHERE id=2").format(operation.table(plan), sql.Identifier(operation.shadow(plan))),
            "missing_row": sql.SQL("DELETE FROM {} WHERE id=2").format(operation.table(plan)),
            "stale_term": sql.SQL("UPDATE {} SET {}=set_byte({},14,get_byte({},14)#1) WHERE id=2").format(operation.table(plan), *[sql.Identifier(operation.shadow(plan))] * 3),
            "duplicate_value": sql.SQL("UPDATE {} SET {}=(SELECT {} FROM {} WHERE id=3) WHERE id=2").format(operation.table(plan), sql.Identifier(operation.shadow(plan)), sql.Identifier(operation.shadow(plan)), operation.table(plan)),
        }
        for name, statement in mutants.items():
            with connection.transaction(force_rollback=True):
                connection.execute(statement)
                rejects(out, "verification_rejects_" + name, lambda: operation.verify(connection), Failure)
        constraint = connection.execute("SELECT conname FROM pg_constraint WHERE conrelid=%s::regclass AND contype='u'", (h.schema + ".customer",)).fetchone()[0]
        connection.commit()
        with connection.transaction(force_rollback=True):
            connection.execute(sql.SQL("ALTER TABLE {} DROP CONSTRAINT {}").format(operation.table(plan), sql.Identifier(constraint)))
            rejects(out, "verification_rejects_missing_index_constraint", lambda: operation.verify(connection), Failure)
        operation.switch(connection)
    attachment.install()
    with Session(h.engine) as session:
        customer = session.get(app.Customer, 2)
        customer.email = "post-cutover@example.test"
        customer.invoices.append(app.Invoice(amount=Decimal("17.25")))
        parent = app.Account(name="post-cutover-parent")
        parent.customers = [app.Customer(email="new-after-cutover@example.test", display_name="New current", age=32)]
        session.add(parent)
        session.commit()
        check(out, "post_cutover_current_application_writes", type(customer.email) is str and customer.invoices[0].amount == Decimal("17.25"))
    with maintenance_connection() as connection:
        backup = connection.execute(sql.SQL("SELECT id,account_id,email FROM {} ORDER BY id").format(operation.table(plan))).fetchall()
    check(out, "retained_local_backup_reader_route", all(reveal(plan.crypto, h.provider, tenant, identity, frame) is None or type(reveal(plan.crypto, h.provider, tenant, identity, frame)) is str for identity, tenant, frame in backup))
    h.provider.payload_generation = 2
    h.provider.admitted_payload.add(2)
    payload_rotation = Transition(attachment, "rotate")
    with payload_rotation.open() as connection:
        payload_rotation.expand(connection)
    fault = {"commit_sent": False, "receive_shutdown": False, "terminal_transaction": False,
             "matching_marker_visible": False, "reply_consumed": False}
    h.result["lost_reply"] = fault

    def lose_reply(connection, number):
        # Fault-control access is on the maintenance connection, never the runtime
        # guard. No alternate listener, target, proxy or credential is involved.
        backend = connection.info.backend_pid
        pg = connection.pgconn
        pg.send_query(b"SELECT pg_sleep(0.2); COMMIT")
        while pg.flush():
            time.sleep(0.001)
        fault["commit_sent"] = True
        receive = socket.socket(fileno=os.dup(pg.socket))
        try:
            receive.shutdown(socket.SHUT_RD)
            fault["receive_shutdown"] = True
            # Observe the actual socket EOF before COMMIT. Calling libpq's
            # error handler here also shuts down the send side and can cancel
            # the server transaction. Keep that side alive for terminal inspection;
            # never pass received bytes to libpq or call get_result().
            fault["transport_error_observed"] = receive.recv(1) == b""
            fault["receive_result"] = "EOF" if fault["transport_error_observed"] else "UNEXPECTED_BYTES"
            deadline = time.monotonic() + 5
            with maintenance_connection() as observer:
                observer.autocommit = True
                fault["marker_absent_at_receive_eof"] = observer.execute(sql.SQL("SELECT 1 FROM {} WHERE operation=%s AND chunk=%s").format(payload_rotation.markers), (payload_rotation.operation, number)).fetchone() is None
                while time.monotonic() < deadline:
                    marker = observer.execute(sql.SQL("SELECT members FROM {} WHERE operation=%s AND chunk=%s").format(payload_rotation.markers), (payload_rotation.operation, number)).fetchone()
                    state = observer.execute("SELECT xact_start,state FROM pg_stat_activity WHERE pid=%s", (backend,)).fetchone()
                    if marker is not None and state is not None and state == (None, "idle"):
                        fault["terminal_transaction"] = True
                        fault["matching_marker_visible"] = marker[0] == list(range(1, 101))
                        break
                    time.sleep(0.02)
            if not fault["terminal_transaction"]:
                raise Failure("LOST_REPLY_OUTCOME_REMAINS_UNKNOWN")
            connection.close()
            raise Failure("COMMIT_REPLY_INTENTIONALLY_LOST")
        finally:
            receive.close()

    try:
        with payload_rotation.open() as connection:
            payload_rotation.backfill(connection, before_commit=lose_reply)
    except (Failure, psycopg.OperationalError) as failure:
        fault["failure_code"] = getattr(failure, "code", type(failure).__name__)
        check(out, "real_lost_commit_reply_with_terminal_inspection", all(fault.get(key) for key in
              ("commit_sent", "receive_shutdown", "terminal_transaction", "matching_marker_visible", "transport_error_observed", "marker_absent_at_receive_eof")) and not fault["reply_consumed"])
    else:
        raise AssertionError("lost_reply_was_not_injected")
    h.result["lost_reply"] = fault
    with payload_rotation.open() as connection:
        committed = values(connection, payload_rotation, plan)[:100]
        connection.commit()
        payload_rotation.backfill(connection)
        check(out, "lost_reply_resume_preserves_ciphertext", committed == values(connection, payload_rotation, plan)[:100])
        connection.commit()
        payload_rotation.switch(connection)
    with maintenance_connection() as connection:
        frames = connection.execute(sql.SQL("SELECT id,email FROM {} ORDER BY id").format(operation.table(plan))).fetchall()
    check(out, "payload_rotation_exact_generation", all(frame is None or frame[6:14] == b"\x00\x00\x00\x02\x00\x00\x00\x01" for _, frame in frames))
    before_rewrap = hashlib.sha256(b"".join(frame or b"" for _, frame in frames)).hexdigest()
    h.provider.rewrap_local()
    with maintenance_connection() as connection:
        frames = connection.execute(sql.SQL("SELECT id,email FROM {} ORDER BY id").format(operation.table(plan))).fetchall()
    check(out, "local_rewrap_preserves_payload_bytes", before_rewrap == hashlib.sha256(b"".join(frame or b"" for _, frame in frames)).hexdigest())
    with Session(h.engine) as session:
        check(out, "cold_after_rewrap_current_read", session.get(app.Customer, 2).email == "post-cutover@example.test")
    h.provider.search_generation = 2
    h.provider.admitted_search.add(2)
    Transition(attachment, "rotate").run()
    with Session(h.engine) as session:
        check(out, "search_rotation_native_query", session.scalar(app.lookup_email(tenants[1], "post-cutover@example.test")).id == 2)
    current = snapshot(app, h.engine)
    Transition(attachment, "deprotect").run()
    attachment.detach()
    h.attachment = None
    check(out, "current_data_rollback_all_models_and_types", snapshot(app, h.engine) == current)
    # Repeat protection after decrypt-back; original constraints must permit it.
    h.attach()
    h.provider.rewrap_local()
    current = snapshot(app, h.engine)
    Transition(h.attachment, "deprotect").run()
    h.attachment.detach()
    h.attachment = None
    check(out, "reprotect_rewrap_remove_preserves_current_data", snapshot(app, h.engine) == current)
    with maintenance_connection() as connection:
        connection.execute(sql.SQL("DROP TABLE {},{}").format(operation.markers, operation.journal))
        remaining = connection.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND column_name LIKE '_cl_%%'", (h.schema,)).fetchall()
        check(out, "eligible_internal_storage_removed", not remaining)
    script = Path(__file__).with_name("run_package_free_original.py")
    child = subprocess.run([sys_executable(), str(script), h.schema, current], env=os.environ.copy(), capture_output=True, text=True, timeout=30)
    removed = json.loads(child.stdout) if child.stdout.strip() else {"status": "NO_SAFE_CHILD_RECEIPT"}
    h.result["package_free_original"] = removed
    if child.returncode != 0:
        raise Failure("PACKAGE_FREE_ORIGINAL_APPLICATION_FAILED")
    check(out, "package_free_all_original_assertions", removed["status"] == "PASS_PACKAGE_FREE_ORIGINAL_APPLICATION" and len(removed["outcomes"]) == 35)
    h.result["limits"] = ["Writer-role exclusion and deployment pin unqualified", "Local wrapped roots only; no production custody",
                          "Local backup reader proves decode, not durable independently retained reader/key provenance",
                          "All work is on 1000 synthetic existing rows; larger transition costs remain to measure"]


def sys_executable():
    import sys
    return sys.executable


if __name__ == "__main__":
    Harness("lifecycle").run(cases, __file__)
