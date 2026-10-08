"""New adversarial expression/write cases for the integrated representation."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import String, bindparam, cast, event, func, insert, literal, literal_column, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from integration_crypto import Failure
from integration_harness import Harness
from run_gate_retrofit import check, rejects


def cases(h):
    app, engine, out = h.app, h.engine, h.outcomes
    h.attach()
    with Session(engine) as session:
        first, second = app.Account(name="scope-a"), app.Account(name="scope-b")
        first.customers = [app.Customer(email="edge@example.test", display_name="First", age=1),
                           app.Customer(email=None, display_name="Null", age=None)]
        second.customers = [app.Customer(email="edge@example.test", display_name="Second", age=2)]
        session.add_all([first, second])
        session.commit()
        tenants = first.id, second.id
        record = first.customers[0].id
        second_record = second.customers[0].id

    exposure = {"seen": False}
    @event.listens_for(engine, "before_cursor_execute")
    def collector(connection, cursor, statement, parameters, context, many):
        def contains(value):
            if isinstance(value, str):
                return value.endswith("@example.test")
            if isinstance(value, dict):
                return any(contains(item) for item in value.values())
            if isinstance(value, (tuple, list)):
                return any(contains(item) for item in value)
            return False
        exposure["seen"] |= contains(parameters)

    with Session(engine) as session:
        query = select(app.Customer.id).where(app.Customer.email == bindparam("email_input"))
        check(out, "late_bound_equality", set(session.scalars(query, {"email_input": "edge@example.test"})) == {record, second_record})
        check(out, "reverse_equality", set(session.scalars(select(app.Customer.id).where(literal("edge@example.test") == app.Customer.email))) == {record, second_record})
        check(out, "membership_null_semantics", session.scalars(select(app.Customer.id).where(app.Customer.account_id == tenants[0], app.Customer.email.in_(["edge@example.test", None]))).all() == [record])
        check(out, "empty_membership", session.scalars(select(app.Customer.id).where(app.Customer.email.in_([]))).all() == [])
        check(out, "not_membership_null_semantics", session.scalars(select(app.Customer.id).where(app.Customer.email.not_in([None]))).all() == [])
        check(out, "scoped_distinct", session.scalar(select(func.count(func.distinct(app.Customer.email))).where(app.Customer.account_id == tenants[0])) == 1)
        rejects(out, "unscoped_distinct_rejected", lambda: session.scalar(select(func.count(func.distinct(app.Customer.email)))), Failure)
        rejects(out, "cast_predicate_rejected_before_wire", lambda: session.scalar(select(app.Customer.id).where(cast(app.Customer.email, String) == "edge@example.test")), Failure)
        rejects(out, "literal_column_rejected", lambda: session.execute(select(literal_column("email")).select_from(app.Customer)), Failure)
        rejects(out, "protected_function_rejected", lambda: session.execute(select(func.lower(app.Customer.email))), Failure)
        rejects(out, "protected_grouping_rejected", lambda: session.execute(select(app.Customer.email).group_by(app.Customer.email)), Failure)
        rejects(out, "protected_reverse_order_rejected", lambda: session.execute(select(app.Customer.id).where(literal("edge@example.test") < app.Customer.email)), Failure)
        session.execute(update(app.Customer).where(app.Customer.id == record).values(email="core-change@example.test"))
        session.commit()
        check(out, "typed_point_update_prepares_row", session.get(app.Customer, record).email == "core-change@example.test")
        session.execute(update(app.Customer), [{"id": record, "email": "bulk-update@example.test"}])
        session.commit()
        check(out, "bulk_update_mapping_prepares_row", session.get(app.Customer, record).email == "bulk-update@example.test")
        customer = session.get(app.Customer, record)
        customer.account_id = tenants[1]
        session.commit()
        session.expire_all()
        check(out, "tenant_move_reseals_complete_context", session.get(app.Customer, record).email == "bulk-update@example.test")
        customer = session.get(app.Customer, record)
        customer.account = session.get(app.Account, tenants[0])
        session.commit()
        session.expire_all()
        check(out, "relationship_tenant_move_reseals_context", session.get(app.Customer, record).email == "bulk-update@example.test" and session.get(app.Customer, record).account_id == tenants[0])
        rejects(out, "unprepared_tenant_update_rejected", lambda: session.execute(update(app.Customer).where(app.Customer.id == record).values(account_id=tenants[0])), Failure)
        rejects(out, "unprepared_multirow_payload_update_rejected", lambda: session.execute(update(app.Customer).values(email="all@example.test")), Failure)
        customer = session.get(app.Customer, record)
        customer.id += 1000
        rejects(out, "identity_mutation_rejected", session.flush, Failure)
        session.rollback()
    check(out, "all_new_protected_binds_opaque", not exposure["seen"])
    with engine.connect() as connection:
        before = h.attachment.driver_executions
        raw = connection.connection.driver_connection
        rejects(out, "connection_info_protocol_handle_rejected", lambda: raw.info.pgconn, Failure)
        rejects(out, "connection_info_credentials_rejected", lambda: raw.info.password, Failure)
        check(out, "info_rejection_has_no_wire_effect", h.attachment.driver_executions == before)

    barrier = Barrier(2)
    def allocate(index):
        with Session(engine) as session:
            barrier.wait(timeout=10)
            parent = app.Account(name="concurrent-" + str(index))
            parent.customers = [app.Customer(email="concurrent-" + str(index) + "@example.test", display_name="Concurrent", age=index)]
            session.add(parent)
            session.commit()
            return parent.id, parent.customers[0].id
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(allocate, range(2)))
    check(out, "concurrent_original_sequences_disjoint", len({row[0] for row in rows}) == 2 and len({row[1] for row in rows}) == 2)
    barrier = Barrier(2)
    def collide(index):
        with Session(engine) as session:
            session.add(app.Customer(account_id=tenants[0], email="collision@example.test", display_name="Conflict", age=index))
            barrier.wait(timeout=10)
            try:
                session.commit()
                return "committed"
            except IntegrityError:
                session.rollback()
                return "unique-conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(collide, range(2)))
    check(out, "concurrent_scoped_uniqueness", sorted(results) == ["committed", "unique-conflict"])
    event.remove(engine, "before_cursor_execute", collector)


if __name__ == "__main__":
    Harness("boundary").run(cases, __file__)
