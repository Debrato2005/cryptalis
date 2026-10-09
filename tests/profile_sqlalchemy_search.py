"""Matched million-row search profile; an optional local receipt, not a test.

Load both private URL files in the invoking shell, then run this file with the
project Python. Setup owns only temporary schemas. Applications use the
restricted runtime role and ordinary ORM writes. No connection URL is output.
"""

import argparse
from contextlib import ExitStack
import cProfile
import hashlib
import json
import os
import platform
import pstats
import resource
import statistics
import time
from uuid import UUID

import cryptography
import psycopg
import sqlalchemy
from sqlalchemy import bindparam, event, select
from cryptalis.crypto import KeyUnavailable

from test_sqlalchemy_search import TENANT, search_application


def identity(rank):
    return UUID(int=rank + 100)


def name(rank, revision=0):
    # A realistic 53-byte email-shaped identifier with 128-bit varying content.
    digest = hashlib.blake2b(f"synthetic:{rank}:{revision}".encode(), digest_size=16).hexdigest()
    return f"user-{digest}@example.invalid"


def label(rank):
    return f"synthetic-{rank:07d}"


def percentile(values, quantile):
    return sorted(values)[max(0, int(len(values) * quantile + 0.999999) - 1)]


def category(filename, function):
    if filename.endswith("cryptalis/_sqlalchemy_guard.py"):
        return "admission_and_guard"
    if filename.endswith("cryptalis/_sqlalchemy_search.py"):
        return "search_rewrite_and_terms"
    if filename.endswith("cryptalis/sqlalchemy.py"):
        if function in ("admit", "protected", "_protected", "_check", "_fingerprint", "before_execute", "check_cursor", "_points"):
            return "admission_and_guard"
        if function == "process_result_value":
            return "decoding_materialization"
        return "attachment_dispatch"
    if filename.endswith("cryptalis/crypto/keys.py"):
        return "key_preparation"
    if "/sqlalchemy/sql/compiler.py" in filename or function in ("_compile_w_cache", "_compiler", "_generate_cache_key", "_gen_cache_key"):
        return "compilation_cache"
    if "/psycopg/" in filename:
        return "driver_database"
    if "/sqlalchemy/engine/result.py" in filename or "/sqlalchemy/engine/cursor.py" in filename or "/sqlalchemy/engine/_processors_cy" in filename or "/sqlalchemy/orm/loading.py" in filename:
        return "decoding_materialization"
    return "other_orm_engine_python"


def profile(call, samples=10):
    collector = cProfile.Profile()
    collector.enable()
    for _ in range(samples):
        call()
    collector.disable()
    stats = pstats.Stats(collector)
    categories, largest = {}, []
    for (filename, line, function), (_, calls, exclusive, cumulative, _) in stats.stats.items():
        bucket = category(filename, function)
        categories[bucket] = categories.get(bucket, 0.0) + exclusive
        largest.append({"category": bucket, "function": function, "calls": calls,
                        "cumulative_ms_per_query": round(cumulative * 1000 / samples, 4)})
    return {"samples": samples, "profiled_ms_per_query": round(stats.total_tt * 1000 / samples, 4),
            "exclusive_ms_per_query": {key: round(value * 1000 / samples, 4) for key, value in sorted(categories.items())},
            "largest_cumulative_calls": sorted(largest, key=lambda item: item["cumulative_ms_per_query"], reverse=True)[:12]}


def summarize(timings, target=None):
    result = {"native_p50_ms": round(statistics.median(timings[0]), 4),
              "native_p95_ms": round(percentile(timings[0], .95), 4),
              "native_p99_ms": round(percentile(timings[0], .99), 4),
              "attached_p50_ms": round(statistics.median(timings[1]), 4),
              "attached_p95_ms": round(percentile(timings[1], .95), 4),
              "attached_p99_ms": round(percentile(timings[1], .99), 4),
              "median_paired_added_ms": round(statistics.median([b - a for a, b in zip(*timings)]), 4),
              "added_p95_ms": round(percentile(timings[1], .95) - percentile(timings[0], .95), 4)}
    if target is not None:
        result.update(target_added_p95_ms=target, target_met=result["added_p95_ms"] <= target)
    return result


def safe_plan(document):
    # EXPLAIN expressions can contain search terms. Retain only cost/shape facts.
    allowed = {"Node Type", "Index Name", "Relation Name", "Actual Rows", "Actual Loops", "Actual Startup Time", "Actual Total Time",
               "Shared Hit Blocks", "Shared Read Blocks", "Temp Read Blocks", "Temp Written Blocks", "Rows Removed by Filter"}

    def node(value):
        result = {key: item for key, item in value.items() if key in allowed}
        if "Plans" in value:
            result["Plans"] = [node(item) for item in value["Plans"]]
        return result

    return {"planning_ms": document[0]["Planning Time"], "execution_ms": document[0]["Execution Time"], "plan": node(document[0]["Plan"])}


def storage(app):
    with app.owner_engine.connect() as connection:
        column_bytes = connection.exec_driver_sql(f'SELECT sum(pg_column_size(name)) FROM "{app.schema}".customer').scalar_one()
        # The fixture exports the exact index owner. Exclude PK/rank/label sizes.
        index_bytes = connection.exec_driver_sql("SELECT pg_relation_size(%s::regclass)", (f'"{app.schema}"."{app.name_index_name}"',)).scalar_one()
        total_bytes = connection.exec_driver_sql("SELECT pg_total_relation_size(%s::regclass)", (f'"{app.schema}".customer',)).scalar_one()
        table_bytes = connection.exec_driver_sql("SELECT pg_relation_size(%s::regclass)", (f'"{app.schema}".customer',)).scalar_one()
    return {"name_column_bytes": column_bytes, "name_equality_index_bytes": index_bytes,
            "isolated_column_and_index_bytes": column_bytes + index_bytes,
            "whole_table_heap_bytes_context_only": table_bytes, "whole_relation_and_all_indexes_bytes_context_only": total_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=1_000_000)
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--chunk", type=int, default=2000)
    options = parser.parse_args()
    if not (1000 <= options.rows <= 1_000_000 and 40 <= options.samples <= 200 and 100 <= options.chunk <= 5000):
        parser.error("Use rows 1000..1000000, samples 40..200, chunk 100..5000")
    fingerprints = {}
    server = None
    # Print only hashes, even if startup fails. Both variables must be refreshed
    # by the shell; this script never falls back to inherited alternatives.
    errors = []
    for variable in ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL"):
        url = os.environ.get(variable)
        fingerprints[variable] = hashlib.sha256(url.encode()).hexdigest()[:8] if url else None
        if not url:
            errors.append({"variable": variable, "error": "variable is not set"})
            continue
        try:
            with psycopg.connect(url, connect_timeout=5) as connection:
                assert connection.execute("select 1").fetchone() == (1,)
                server = connection.execute("show server_version").fetchone()[0]
                assert int(connection.execute("show server_version_num").fetchone()[0]) // 10000 == 16
        except psycopg.Error as error:
            errors.append({"variable": variable, "error": type(error).__name__, "sqlstate": error.sqlstate})
    if errors:
        print(json.dumps({"fingerprints": fingerprints, "startup_errors": errors}))
        raise SystemExit(2)
    started = time.perf_counter()
    initial_cpu = time.process_time()
    with ExitStack() as stack:
        applications = [stack.enter_context(search_application(protected=value)) for value in (False, True)]
        seed_receipts = []
        for app in applications:
            seed_start = time.perf_counter()
            lease_recoveries = []
            for lower in range(0, options.rows, options.chunk):
                for attempt in range(2):
                    try:
                        with app.sessions(tenant_id=TENANT) as session:
                            session.add_all([app.Customer(id=identity(rank), tenant_id=TENANT, name=name(rank), label=label(rank), rank=rank)
                                             for rank in range(lower, min(options.rows, lower + options.chunk))])
                            session.commit()
                        break
                    except KeyUnavailable:
                        # Absolute key leases can expire while an otherwise
                        # bounded chunk is being sealed. Closing the failed
                        # session rolls it back. Retry this chunk once with a
                        # new session and freshly prepared keys; never extend
                        # the lease or suppress a second failure.
                        if attempt:
                            raise
                        lease_recoveries.append({"first_rank": lower, "rows": min(options.chunk, options.rows - lower)})
            seed_elapsed = time.perf_counter() - seed_start
            with app.owner_engine.begin() as connection:
                connection.exec_driver_sql(f'ANALYZE "{app.schema}".customer')
                assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == options.rows
            seed_receipts.append({"seconds": round(seed_elapsed, 3), "rows_per_second": round(options.rows / seed_elapsed, 1),
                                  "key_unavailable_rollback_and_retry": lease_recoveries})
        storage_receipts = [storage(app) for app in applications]
        sessions = [stack.enter_context(app.sessions(tenant_id=TENANT)) for app in applications]
        driver_queries, cache_hits = [None, None], [[], []]

        def capture(path):
            def after(conn, cursor, statement, parameters, context, many):
                driver_queries[path] = (statement, parameters)
                cache_hits[path].append(context.cache_hit.name)
            return after

        for path, app in enumerate(applications):
            event.listen(app.engine, "after_cursor_execute", capture(path))
        statements = {"point_entity": [], "equality_entity": [], "in20_entities": [], "plaintext_page": [], "plaintext_filter_entities": []}
        for app in applications:
            model = app.Customer
            scope = model.tenant_id == TENANT
            statements["point_entity"].append(select(model).where(scope, model.id == bindparam("point")))
            statements["equality_entity"].append(select(model).where(scope, model.name == bindparam("value")))
            statements["in20_entities"].append(select(model).where(scope, model.name.in_(bindparam("values", expanding=True))))
            statements["plaintext_page"].append(select(model.id, model.label, model.rank).where(scope, model.rank >= bindparam("floor"),
                                                      model.label.like("synthetic-%")).order_by(model.rank).limit(100).offset(bindparam("start")))
            # The historical helper selected a full protected entity with
            # plaintext range/prefix filters. This is that structural control,
            # separate from the entirely unprotected page projection above.
            statements["plaintext_filter_entities"].append(select(model).where(scope, model.rank >= 20,
                                                     model.label.startswith("synthetic-00000", autoescape=True))
                                                     .order_by(model.rank, model.id).limit(5).offset(0))
        measurements, plans = {}, {}
        for workload, paired in statements.items():
            timings = [[], []]
            for entries in cache_hits:
                entries.clear()
            for sample in range(options.samples + 10):
                rank = (sample * 7919 + 13) % (options.rows - 100)
                if workload == "point_entity":
                    parameters, ranks = {"point": identity(rank)}, [rank]
                elif workload == "equality_entity":
                    parameters, ranks = {"value": name(rank)}, [rank]
                elif workload == "in20_entities":
                    ranks = [(rank + delta * 977) % options.rows for delta in range(20)]
                    parameters = {"values": [name(value) for value in ranks]}
                elif workload == "plaintext_filter_entities":
                    parameters, ranks = {}, list(range(20, 25))
                else:
                    floor = (sample * 17) % min(1000, options.rows - 100)
                    offset = (sample * 15427) % (options.rows - floor - 100)
                    parameters, ranks = {"floor": floor, "start": offset}, list(range(floor + offset, floor + offset + 100))
                results = [None, None]
                for path in ((0, 1) if sample % 2 == 0 else (1, 0)):
                    before = time.perf_counter()
                    response = sessions[path].execute(paired[path], parameters)
                    if workload == "plaintext_page":
                        rows = response.all()
                    else:
                        entities = response.scalars().all()
                        rows = [(row.id, row.tenant_id, row.name, row.label, row.rank) for row in entities]
                    elapsed = (time.perf_counter() - before) * 1000
                    expected = ([(identity(value), label(value), value) for value in ranks] if workload == "plaintext_page" else
                                [(identity(value), TENANT, name(value), label(value), value) for value in ranks])
                    assert sorted(rows) == sorted(expected)
                    results[path] = sorted(rows)
                    if sample >= 10:
                        timings[path].append(elapsed)
                    # Expunge between reads: every whole-path sample materializes
                    # fresh entities instead of returning identity-map instances.
                    sessions[path].expunge_all()
                assert results[0] == results[1]
            measurements[workload] = summarize(timings, {"point_entity": 3, "equality_entity": 3, "in20_entities": 8}.get(workload))
            plans[workload] = []
            for path, app in enumerate(applications):
                sql_statement, sql_parameters = driver_queries[path]
                with app.owner_engine.connect() as connection:
                    document = connection.exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql_statement, sql_parameters).scalar_one()
                plans[workload].append(safe_plan(document))
            measurements[workload]["compilation_cache_events"] = [{value: entries.count(value) for value in set(entries)} for entries in cache_hits]
            expected = ([(identity(value), label(value), value) for value in ranks] if workload == "plaintext_page" else
                        [(identity(value), TENANT, name(value), label(value), value) for value in ranks])

            def profiled_call(path):
                def call():
                    response = sessions[path].execute(paired[path], parameters)
                    actual = (response.all() if workload == "plaintext_page" else
                              [(row.id, row.tenant_id, row.name, row.label, row.rank) for row in response.scalars()])
                    assert sorted(actual) == sorted(expected)
                    sessions[path].expunge_all()
                return call

            measurements[workload]["exclusive_profiles_native_attached"] = [profile(profiled_call(path)) for path in (0, 1)]
        for session in sessions:
            session.rollback()
        update_receipts = []
        update_count = min(1000, options.rows)
        for app in applications:
            before = time.perf_counter()
            for lower in range(0, update_count, 100):
                with app.sessions(tenant_id=TENANT) as session:
                    rows = session.scalars(select(app.Customer).where(app.Customer.tenant_id == TENANT,
                                                    app.Customer.id.in_([identity(rank) for rank in range(lower, lower + 100)]))).all()
                    assert len(rows) == 100
                    for row in rows:
                        row.name = name(row.rank, 1)
                    session.commit()
            elapsed = time.perf_counter() - before
            with app.sessions(tenant_id=TENANT) as session:
                row = session.scalar(select(app.Customer).where(app.Customer.tenant_id == TENANT, app.Customer.name == name(17, 1)))
                assert (row.id, row.name) == (identity(17), name(17, 1))
                assert session.scalar(select(app.Customer).where(app.Customer.tenant_id == TENANT, app.Customer.name == name(17))) is None
            update_receipts.append({"committed_rows": update_count, "transactions": update_count // 100,
                                    "seconds": round(elapsed, 3), "rows_per_second": round(update_count / elapsed, 1)})
        ratio = storage_receipts[1]["isolated_column_and_index_bytes"] / storage_receipts[0]["isolated_column_and_index_bytes"]
        page = measurements["plaintext_page"]
        receipt = {"boundary": "Local synchronous warm-provider runtime ORM; no production qualification; all seven gates UNKNOWN",
                   "fingerprints": fingerprints,
                   "cell": {"python": platform.python_version(), "sqlalchemy": sqlalchemy.__version__, "psycopg": psycopg.__version__,
                            "cryptography": cryptography.__version__, "postgresql": server},
                   "data": {"rows_per_path": options.rows, "name_utf8_bytes": len(name(0).encode()), "distribution": "unique 128-bit synthetic email-shaped identifiers",
                            "ids": "same application-assigned UUIDs", "tenants": 1, "insert_chunk": options.chunk},
                   "paired_samples_per_workload": options.samples, "warmup_samples_per_workload": 10,
                   "read_session": "same long-lived transaction; expunge after each entity read", "equal_native_and_attached_results": True,
                   "whole_path": measurements, "explain_analyze_buffers_native_attached": plans,
                   "seed_native_attached": seed_receipts, "committed_updates_native_attached": update_receipts,
                   "storage_native_attached": storage_receipts, "isolated_storage_ratio": round(ratio, 4),
                   "storage_target_ratio": 2, "storage_target_met": ratio <= 2,
                   "equality_index_shapes": {"native": "name B-tree", "attached": "tenant_id plus full keyed term expression B-tree",
                                             "same_application_predicate": "tenant_id plus exact name equality"},
                   "plaintext_anomaly": {"historical_p95_native_attached_ms": [23.852, 127.098],
                                         "historical_shape": "full Customer including protected email, plaintext filters; not a plaintext-only projection",
                                         "source": "spikes/revamp/plain_app.py:active_customers and browse_customers; read-only source inspection",
                                         "current_controls": ["plaintext_page", "plaintext_filter_entities"],
                                         "disposition": "historical receipt and plaintext-only label retired as current-product evidence; historical root cause remains UNKNOWN",
                                         "limits": "Current fixture uses UUID IDs, one tenant, unique labels and increasing ranks; it is not the historical data distribution"},
                   "process_cpu_seconds_including_seed": round(time.process_time() - initial_cpu, 3),
                   "process_max_rss_kib_including_seed": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                   "elapsed_seconds_including_seed": round(time.perf_counter() - started, 3),
                   "limits": ["Single local host and warm development provider; sync only", "No provider, migration, outage, independent review or deployment qualification",
                              "Shared-host activity uncontrolled; p99 estimate from 40 samples is weak", "Driver profile includes network/PostgreSQL wait; EXPLAIN is separate server timing",
                              "Exclusive cProfile categories do not overlap; cumulative calls overlap and profiling changes timing",
                              "Update throughput is an observation, not an approved budget or sustained-load qualification",
                              "No protected range, prefix, order, or broader search capability follows from plaintext page queries"]}
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
