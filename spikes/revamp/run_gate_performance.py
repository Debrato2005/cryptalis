"""Actual million-row CF1 retrofit and whole client/ORM timings. No full budget qualification."""
from decimal import Decimal
import hashlib
import json
import math
import resource
import time

from psycopg import sql
from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from integration_crypto import term
from integration_harness import Harness
from integration_transition import maintenance_connection
from run_gate_retrofit import check


ROWS = 1_000_000


def stats(values):
    ordered = sorted(values)
    return {"samples": len(values), "p50_ms": ordered[math.ceil(len(values) * .5) - 1],
            "p95_ms": ordered[math.ceil(len(values) * .95) - 1],
            "p99_ms": ordered[math.ceil(len(values) * .99) - 1], "total_ms": sum(values)}


def sizes(h):
    with maintenance_connection() as connection:
        rows = connection.execute("SELECT c.relname,pg_relation_size(c.oid),pg_indexes_size(c.oid),pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname", (h.schema,)).fetchall()
    return {name: {"heap_bytes": heap, "index_bytes": indexes, "total_bytes": total} for name, heap, indexes, total in rows}


def observer_counters():
    with maintenance_connection() as connection:
        return connection.execute("SELECT pg_current_wal_lsn()::text,temp_bytes FROM pg_stat_database WHERE datname=current_database()").fetchone()


def metric_digest(value):
    return hashlib.sha256(repr(value).encode()).hexdigest()


def read_workloads(h, tenants):
    app = h.app
    n = ROWS // 2 + 23
    tenant = tenants[n % 10]
    email = "person-" + str(n) + "@example.test"
    work = {
        "point_entity": (100, lambda session: session.get(app.Customer, n + 1)),
        "equality_entity": (100, lambda session: session.scalar(app.lookup_email(tenant, email))),
        "membership_entities": (100, lambda session: session.scalars(app.lookup_emails(tenant, ["person-" + str(n + offset * 10) + "@example.test" for offset in range(20)])).all()),
        "native_unprotected_range_prefix_page": (20, lambda session: session.scalars(app.browse_customers(tenant, 20, "Name 2", 0, 5)).all()),
        "native_join_decimal": (100, lambda session: session.execute(app.invoice_export(tenants[0])).all()),
    }
    result, truth = {}, {}
    def materialize(value):
        if isinstance(value, app.Customer):
            return (value.id, value.account_id, value.email, value.display_name, value.age, value.created_at.isoformat())
        if isinstance(value, list):
            return [materialize(item) for item in value]
        return tuple(value) if hasattr(value, "_mapping") else value
    for name, (samples, action) in work.items():
        with Session(h.engine) as session:
            expected = materialize(action(session))
        truth[name] = metric_digest(expected)
        timings = []
        cpu = time.process_time()
        wall = time.perf_counter()
        for _ in range(samples):
            start = time.perf_counter()
            with Session(h.engine) as session:
                actual = materialize(action(session))
            timings.append((time.perf_counter() - start) * 1000)
            if actual != expected:
                raise AssertionError("read_workload_results_changed")
        result[name] = {**stats(timings), "cpu_seconds": time.process_time() - cpu,
                        "throughput_ops_s": samples / (time.perf_counter() - wall),
                        "rows_materialized_per_sample": len(expected) if isinstance(expected, list) else 1}
    return result, truth


def write_workload(h, restore):
    app = h.app
    timings = []
    originals = {}
    cpu = time.process_time()
    wall = time.perf_counter()
    for first in range(2, 402, 40):
        start = time.perf_counter()
        with Session(h.engine) as session:
            customers = session.scalars(select(app.Customer).where(app.Customer.id >= first, app.Customer.id < first + 40).order_by(app.Customer.id)).all()
            for customer in customers:
                originals[customer.id] = customer.email
                customer.email = "updated-" + str(customer.id) + "@example.test"
            session.commit()
        timings.append((time.perf_counter() - start) * 1000)
    result = {**stats(timings), "rows": 400, "batch_rows": 40, "cpu_seconds": time.process_time() - cpu,
              "throughput_rows_s": 400 / (time.perf_counter() - wall)}
    if restore:
        with Session(h.engine) as session:
            for customer in session.scalars(select(app.Customer).where(app.Customer.id.in_(list(originals)))):
                customer.email = originals[customer.id]
            session.commit()
    return result


def cases(h):
    app, out = h.app, h.outcomes
    started = time.perf_counter()
    with Session(h.engine) as session:
        accounts = [app.Account(name="benchmark-" + str(n)) for n in range(10)]
        session.add_all(accounts)
        session.commit()
        tenants = [account.id for account in accounts]
    for start in range(0, ROWS, 10_000):
        with Session(h.engine) as session:
            session.execute(insert(app.Customer), [{"account_id": tenants[n % 10], "email": None if n % 100 == 0 else "person-" + str(n) + "@example.test",
                                                   "display_name": "Name " + str(n % 1000), "age": n % 100} for n in range(start, start + 10_000)])
            session.commit()
        if (start + 10_000) % 100_000 == 0:
            print(json.dumps({"stage": "native_baseline_loaded", "rows": start + 10_000}), flush=True)
    with Session(h.engine) as session:
        session.add_all([app.Invoice(customer_id=10_001 + n, amount=Decimal("20.00")) for n in range(10)])
        session.commit()
    h.result["native_load_seconds"] = time.perf_counter() - started
    with maintenance_connection() as connection:
        connection.autocommit = True
        connection.execute(sql.SQL("ANALYZE {}").format(sql.Identifier(h.schema, "customer")))
    plain_sizes = sizes(h)
    plain_reads, plain_truth = read_workloads(h, tenants)
    plain_writes = write_workload(h, restore=True)
    print(json.dumps({"stage": "whole_path_plain_baseline_complete", "rows": ROWS}), flush=True)
    before_lsn, before_temp = observer_counters()
    wall, cpu = time.perf_counter(), time.process_time()
    h.attach()
    migration_wall, migration_cpu = time.perf_counter() - wall, time.process_time() - cpu
    print(json.dumps({"stage": "actual_cf1_protection_and_full_verify_complete", "rows": ROWS}), flush=True)
    with maintenance_connection() as connection:
        connection.autocommit = True
        connection.execute(sql.SQL("VACUUM (ANALYZE) {}").format(sql.Identifier(h.schema, "customer")))
    total_pause = time.perf_counter() - wall
    after_lsn, after_temp = observer_counters()
    with maintenance_connection() as connection:
        wal = connection.execute("SELECT pg_wal_lsn_diff(%s::pg_lsn,%s::pg_lsn)", (after_lsn, before_lsn)).fetchone()[0]
    protected_sizes = sizes(h)
    protected_reads, protected_truth = read_workloads(h, tenants)
    check(out, "identical_native_results_all_workloads", protected_truth == plain_truth)
    n = ROWS // 2 + 23
    token = term(h.attachment.plans[0].crypto, h.provider, tenants[n % 10], "person-" + str(n) + "@example.test")
    with maintenance_connection() as connection:
        plan = connection.execute(sql.SQL("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT id FROM {} WHERE account_id=%s AND substring(email FROM 15 FOR 32)=%s").format(sql.Identifier(h.schema, "customer")), (tenants[n % 10], token)).fetchone()[0][0]
        count = connection.execute(sql.SQL("SELECT count(*),count(email) FROM {}").format(sql.Identifier(h.schema, "customer"))).fetchone()
    def nodes(value):
        yield value
        for child in value.get("Plans", []):
            yield from nodes(child)
    index_names = [node["Index Name"] for node in nodes(plan["Plan"]) if "Index Name" in node]
    check(out, "selective_actual_cf1_index_plan", bool(index_names) and plan["Plan"]["Actual Rows"] == 1)
    check(out, "million_row_membership_and_nulls", count == (ROWS, ROWS - ROWS // 100))
    protected_writes = write_workload(h, restore=False)
    h.result.update(rows=ROWS, distribution={"tenants": 10, "rows_per_tenant": ROWS // 10, "null_fraction": .01,
                     "non_null_email": "unique ASCII synthetic addresses", "age": "0..99", "display_name": "1000 labels; plaintext declared"},
                    baseline={"sizes": plain_sizes, "reads": plain_reads, "writes": plain_writes},
                    protected={"sizes": protected_sizes, "reads": protected_reads, "writes": protected_writes},
                    equality_plan={"index_names": index_names, "actual_rows": plan["Plan"]["Actual Rows"], "execution_ms": plan["Execution Time"]},
                    migration={"wall_seconds": migration_wall, "cpu_seconds": migration_cpu, "rows_s": ROWS / migration_wall,
                               "total_pause_seconds_including_vacuum_analyze": total_pause,
                               "cluster_wal_delta_bytes": int(wal), "database_temp_delta_bytes": after_temp - before_temp},
                    process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                    query_compilation_cache="DISABLED_PUBLIC_OPTION_FOR_HOST_POINT_CONTEXT",
                    production_budgets="UNKNOWN_NO_APPROVED_BUDGETS_OR_PROVIDER",
                    limits=["Local memory provider only; no mature-provider RPC cost", "Warm local PostgreSQL 16.15; no 14-18 matrix",
                            "20 samples for native range/prefix; its p99 estimate is coarse", "WAL/temp deltas include unrelated cluster/database activity if present",
                            "No advanced encrypted range/prefix fields in this manifest", "Sustained writes: 400 rows, ten batches; longer soak not qualified",
                            "No production deployment procedure, fault-storage quota or independent review qualification"])


if __name__ == "__main__":
    Harness("performance").run(cases, __file__)
