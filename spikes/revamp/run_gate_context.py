"""Expected-point/context and development-provider failure evidence; no review qualification."""
from dataclasses import replace
import time

from sqlalchemy import event, select, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from integration_adapter import Attachment
from integration_crypto import Failure, Field, LocalKeyring, encoded, integer, reveal, seal, term
from integration_harness import Harness, LOCAL_WRITERS
from run_gate_retrofit import MANIFEST, check, rejects
from integration_transition import maintenance_connection
from psycopg import sql


def cases(h):
    app, out = h.app, h.outcomes
    rejects(out, "missing_inventory_blocks_before_transform", lambda: Attachment(app.Base.registry, h.engine, MANIFEST, h.provider, h.schema, True), Failure)
    for label in ("unknown", "unexcluded"):
        inventory = {**LOCAL_WRITERS, label: ["independent-copy-writer"]}
        rejects(out, label + "_writer_blocks_before_transform", lambda: Attachment(app.Base.registry, h.engine, MANIFEST, h.provider, h.schema, True, inventory), Failure)
    multi_field = {**MANIFEST, "models": {"Customer": {**MANIFEST["models"]["Customer"],
                   "fields": {**MANIFEST["models"]["Customer"]["fields"], "display_name": MANIFEST["models"]["Customer"]["fields"]["email"]}}}}
    rejects(out, "unqualified_multifield_blocks_before_transform", lambda: Attachment(app.Base.registry, h.engine, multi_field, h.provider, h.schema, True, LOCAL_WRITERS), Failure)
    with maintenance_connection() as connection:
        unchanged = connection.execute("SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name='customer' AND column_name='email'", (h.schema,)).fetchone()
        journal = connection.execute("SELECT to_regclass(%s)", (h.schema + "._cl_operation",)).fetchone()
        check(out, "rejected_plan_has_no_protected_schema_effect", unchanged == ("character varying",) and journal == (None,))
        connection.execute(sql.SQL("ALTER TABLE {} ALTER COLUMN email TYPE varchar(3)").format(sql.Identifier(h.schema, "customer")))
    rejects(out, "live_mapping_type_mismatch_blocks_plan", lambda: Attachment(app.Base.registry, h.engine, MANIFEST, h.provider, h.schema, True, LOCAL_WRITERS), Failure)
    with maintenance_connection() as connection:
        connection.execute(sql.SQL("ALTER TABLE {} ALTER COLUMN email TYPE varchar").format(sql.Identifier(h.schema, "customer")))
    h.attach()
    with Session(h.engine) as session:
        accounts = [app.Account(name="context-a"), app.Account(name="context-b")]
        for index, account in enumerate(accounts):
            account.customers = [app.Customer(email="context-" + str(index) + "@example.test", display_name="Context", age=30)]
        session.add_all(accounts)
        session.commit()
        points = [(account.id, account.customers[0].id) for account in accounts]
    armed = {"value": False}
    @event.listens_for(h.engine, "before_cursor_execute", retval=True)
    def hostile_row(connection, cursor, statement, parameters, context, many):
        if armed["value"]:
            armed["value"] = False
            parameters = {key: points[1][1] if value == points[0][1] else value for key, value in parameters.items()}
        return statement, parameters
    with Session(h.engine) as session:
        armed["value"] = True
        rejects(out, "point_read_rejects_valid_wrong_returned_row", lambda: session.get(app.Customer, points[0][1]), Failure)
        session.rollback()
        check(out, "subsequent_point_context_recovery", session.get(app.Customer, points[1][1]).email == "context-1@example.test")
        rejects(out, "core_identity_mutation_rejected", lambda: session.execute(update(app.Customer).where(app.Customer.id == points[0][1]).values(id=points[0][1] + 100)), Failure)
        rejects(out, "computed_identity_mutation_rejected", lambda: session.execute(update(app.Customer).where(app.Customer.id == points[0][1]).values(id=app.Customer.id + 100)), IntegrityError)
        session.rollback()
        check(out, "computed_identity_failure_retains_current_row", session.get(app.Customer, points[0][1]).email == "context-0@example.test")
    event.remove(h.engine, "before_cursor_execute", hostile_row)
    with h.engine.connect() as connection:
        raw = connection.connection.driver_connection
        rejects(out, "public_driver_ticket_mutation_rejected", lambda: setattr(raw, "ticket", True), Failure)
        rejects(out, "public_driver_ready_mutation_rejected", lambda: setattr(raw, "ready", False), Failure)
    plan = h.attachment.plans[0]
    tenant, record = points[0]
    with maintenance_connection() as connection:
        frame = connection.execute(sql.SQL("SELECT email FROM {} WHERE id=%s").format(sql.Identifier(h.schema, "customer")), (record,)).fetchone()[0]
    check(out, "actual_original_typed_context_roundtrip", reveal(plan.crypto, h.provider, tenant, record, frame) == "context-0@example.test")
    for label, field, target_tenant, target_record in (
        ("record", plan.crypto, tenant, record + 1),
        ("tenant", plan.crypto, points[1][0], record),
        ("field", replace(plan.crypto, identity=b"F" * 16), tenant, record),
        ("domain", replace(plan.crypto, domain=b"D" * 16), tenant, record),
        ("descriptor", replace(plan.crypto, max_bytes=100), tenant, record),
        ("original_identity_type", replace(plan.crypto, record_width=8), tenant, record),
    ):
        rejects(out, "relocation_rejects_" + label, lambda: reveal(field, h.provider, target_tenant, target_record, frame), Failure)
    for position in (0, 4, 5, 6, 10, 14, 46, 58, len(frame) - 1):
        mutant = frame[:position] + bytes([frame[position] ^ 1]) + frame[position + 1:]
        rejects(out, "frame_mutation_rejected_" + str(position), lambda: reveal(plan.crypto, h.provider, tenant, record, mutant), Failure)
    rejects(out, "truncated_frame_rejected", lambda: reveal(plan.crypto, h.provider, tenant, record, frame[:73]), Failure)
    rejects(out, "trailing_frame_rejected", lambda: reveal(plan.crypto, h.provider, tenant, record, frame + b"x"), Failure)
    for label, value in (("nul", "x\x00y"), ("surrogate", "\ud800"), ("subclass", type("StringSubclass", (str,), {})("value"))):
        rejects(out, "original_text_rejects_" + label, lambda: encoded(plan.crypto, value), Failure)
    rejects(out, "int32_width_preserved", lambda: integer(2 ** 31, 4), Failure)
    rejects(out, "integer_bool_rejected", lambda: integer(True, 4), Failure)
    check(out, "bounded_utf8_boundary", encoded(replace(plan.crypto, max_bytes=4), "😀") == "😀".encode())
    rejects(out, "bounded_utf8_overflow", lambda: encoded(replace(plan.crypto, max_bytes=3), "😀"), Failure)
    check(out, "sql_null_remains_native_none", seal(plan.crypto, h.provider, tenant, record, None) is None and reveal(plan.crypto, h.provider, tenant, record, None) is None)
    check(out, "search_roots_independent_of_payload_roots", h.provider.prepare(tenant, b"payload", 1)[1] != h.provider.prepare(tenant, b"search", 1)[1])
    provider = h.provider
    provider.clear_cache()
    provider.max_age = 0.1
    before = provider.unwraps
    reveal(plan.crypto, provider, tenant, record, frame)
    check(out, "local_cold_unwrap_observed", provider.unwraps == before + 2)
    reveal(plan.crypto, provider, tenant, record, frame)
    check(out, "local_warm_uses_same_cached_roots", provider.unwraps == before + 2)
    provider.available = False
    check(out, "local_warm_outage_before_expiry", reveal(plan.crypto, provider, tenant, record, frame) == "context-0@example.test")
    time.sleep(0.11)
    rejects(out, "local_expired_outage_denies", lambda: reveal(plan.crypto, provider, tenant, record, frame), Failure)
    provider.clear_cache()
    rejects(out, "local_cold_outage_denies", lambda: reveal(plan.crypto, provider, tenant, record, frame), Failure)
    provider.available = True
    check(out, "local_recovery_exact_root", reveal(plan.crypto, provider, tenant, record, frame) == "context-0@example.test")
    provider.admitted_payload = {2}
    rejects(out, "retired_generation_no_fallback", lambda: reveal(plan.crypto, provider, tenant, record, frame), Failure)
    provider.admitted_payload = {1}
    check(out, "same_context_replay_scope_limit", reveal(plan.crypto, provider, tenant, record, frame) == "context-0@example.test")
    h.result["crypto_qualification"] = "UNREVIEWED_COMPOSITION; GENERIC_CODECS_USAGE_LIMITS_AND_FROZEN_INDEPENDENT_VECTORS_UNKNOWN"
    h.result["local_provider_qualification"] = "LOCAL_FUNCTIONAL_ONLY; G_PROVIDER_UNKNOWN"
    h.result["replay_scope"] = "SAME_CONTEXT_REPLAY_ACCEPTED; NO_FRESHNESS_OR_COMPLETENESS_CLAIM"


if __name__ == "__main__":
    Harness("context").run(cases, __file__)
