"""Million-row stock PostgreSQL service experiment, not a protected application."""
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import psycopg
from psycopg import sql

import probe_service
from run_native_service import check, connect
from run_stock_postgres import KEY, NAMES, WEIGHTS, cover, prefix_terms, range_terms, term


RESULT = Path(__file__).with_name("results") / "physical-service.json"
ROWS = 1_000_000


def plan_nodes(node):
    yield node
    for child in node.get("Plans", []):
        yield from plan_nodes(child)


def measured(connection, query, parameters, index):
    observations = []
    for _ in range(21):
        row = connection.execute(sql.SQL("EXPLAIN (ANALYZE,BUFFERS,TIMING OFF,FORMAT JSON) ") + query, parameters).fetchone()[0][0]
        nodes = list(plan_nodes(row["Plan"]))
        observations.append({"execution_ms": row["Execution Time"],
                             "index_used": any(node.get("Index Name") == index for node in nodes),
                             "node_types": [node["Node Type"] for node in nodes],
                             "actual_rows": row["Plan"]["Actual Rows"]})
    times = [observation["execution_ms"] for observation in observations[1:]]
    return {"warm_runs": 20, "p50_ms": statistics.median(times),
            "p95_ms": sorted(times)[math.ceil(len(times) * .95) - 1],
            "required_index_used_every_run": all(observation["index_used"] for observation in observations),
            "first_plan_node_types": observations[0]["node_types"],
            "actual_rows": observations[-1]["actual_rows"], "observations": observations}


def main():
    try:
        probe_service.main()
    except SystemExit as stopped:
        if stopped.code != 0:
            raise
    schema = "revamp_physical_service_" + uuid.uuid4().hex
    outcomes = {}
    result = {"status": "UNKNOWN", "schema": schema, "rows": ROWS, "outcomes": outcomes,
              "connection_url": "NEVER_RECORDED", "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "dependencies_sha256": {name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ("run_native_service.py", "run_stock_postgres.py", "probe_service.py")},
              "gates": {"G-QUERY": "INCOMPLETE", "G-RELEASE": "INCOMPLETE"},
              "limits": ["Synthetic physical fixture; plaintext control intentionally stored", "Only email has an encrypted payload; name/age arrays have no complete field payload path", "CF1-shaped packed surrogate is not CF1 cryptographic evidence", "No ORM/provider/whole-backend timing", "Warm sequential EXPLAIN samples; no p99 or production tail claim", "Column sizes are marginal bytes, not isolated per-capability total storage", "No advanced structural attacks or other PostgreSQL/provider qualification"]}
    owned = False
    stage = "create_schema"
    started = time.perf_counter()
    try:
        with connect() as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            owned = True
            connection.execute(sql.SQL("CREATE TABLE {}.plain(id bigint PRIMARY KEY,email text COLLATE \"C\",name text COLLATE \"C\",age bigint)").format(sql.Identifier(schema)))
            connection.execute(sql.SQL("CREATE TABLE {}.protected(id bigint PRIMARY KEY,payload bytea NOT NULL,prefix bytea[] NOT NULL,range_terms bytea[] NOT NULL,CHECK(octet_length(payload)>=74 AND substring(payload FROM 1 FOR 6)=decode('434631000101','hex')))").format(sql.Identifier(schema)))
            result["server_version"] = connection.execute("SHOW server_version").fetchone()[0]
            result["installed_extensions"] = [row[0] for row in connection.execute("SELECT extname FROM pg_extension ORDER BY extname")]
        stage = "client_generation_and_copy"
        generator = random.Random(20261007)
        cipher = AESGCMSIV(KEY)
        prefixes = {name: prefix_terms(name) for name in NAMES}
        ranges = {age: range_terms(age) for age in range(18, 96)}
        copy_started = time.perf_counter()
        with connect() as plain_connection, connect() as protected_connection:
            with plain_connection.cursor().copy(sql.SQL("COPY {}.plain FROM STDIN").format(sql.Identifier(schema))) as plain_copy:
                with protected_connection.cursor().copy(sql.SQL("COPY {}.protected FROM STDIN").format(sql.Identifier(schema))) as protected_copy:
                    for identity in range(1, ROWS + 1):
                        email = f"user{identity}@example.test"
                        name = generator.choices(NAMES, weights=WEIGHTS, k=1)[0]
                        age = max(18, min(95, round(generator.gauss(40, 17))))
                        equality = term("equality", email.encode())
                        header = b"CF1\x00\x01\x01" + (1).to_bytes(4, "big") * 2 + equality
                        nonce = os.urandom(12)
                        payload = header + nonce + cipher.encrypt(nonce, email.encode(), identity.to_bytes(8, "big") + header)
                        plain_copy.write_row((identity, email, name, age))
                        protected_copy.write_row((identity, payload, prefixes[name], ranges[age]))
        result["client_generation_and_two_copy_seconds"] = time.perf_counter() - copy_started
        stage = "restricted_role_indexes"
        ddl = [
            "CREATE UNIQUE INDEX plain_eq ON {s}.plain USING btree(email)",
            "CREATE INDEX plain_prefix ON {s}.plain USING btree(name text_pattern_ops)",
            "CREATE INDEX plain_range ON {s}.plain USING btree(age)",
            "CREATE UNIQUE INDEX packed_eq ON {s}.protected USING btree((substring(payload FROM 15 FOR 32)) bytea_ops)",
            "CREATE INDEX protected_prefix ON {s}.protected USING gin(prefix array_ops)",
            "CREATE INDEX protected_range ON {s}.protected USING gin(range_terms array_ops)",
            "ANALYZE {s}.plain", "ANALYZE {s}.protected",
        ]
        with connect() as connection:
            index_started = time.perf_counter()
            for statement in ddl:
                connection.execute(sql.SQL(statement).format(s=sql.Identifier(schema)))
            result["index_build_and_analyze_seconds"] = time.perf_counter() - index_started
            check(outcomes, "million_rows_loaded", connection.execute(sql.SQL("SELECT (SELECT count(*) FROM {}.plain),(SELECT count(*) FROM {}.protected)").format(sql.Identifier(schema), sql.Identifier(schema))).fetchone() == (ROWS, ROWS))
            classes = connection.execute("SELECT DISTINCT a.amname,o.opcname FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_am a ON a.oid=c.relam JOIN LATERAL unnest(i.indclass) k(oid) ON true JOIN pg_opclass o ON o.oid=k.oid WHERE n.nspname=%s ORDER BY 1,2", (schema,)).fetchall()
            result["actual_index_classes"] = classes
            check(outcomes, "built_in_bytea_and_array_classes", ("btree", "bytea_ops") in classes and ("gin", "array_ops") in classes)
        stage = "physical_query_comparison"
        queries = {
            "equality": ("SELECT id FROM {s}.plain WHERE email=%s", ("user500000@example.test",), "plain_eq", "SELECT id FROM {s}.protected WHERE substring(payload FROM 15 FOR 32)=%s", (term("equality", b"user500000@example.test"),), "packed_eq"),
            "prefix": ("SELECT id FROM {s}.plain WHERE name LIKE %s", ("Z%",), "plain_prefix", "SELECT id FROM {s}.protected WHERE prefix @> %s::bytea[]", ([term("prefix", b"Z")],), "protected_prefix"),
            "range": ("SELECT id FROM {s}.plain WHERE age BETWEEN %s AND %s", (94, 95), "plain_range", "SELECT id FROM {s}.protected WHERE range_terms && %s::bytea[]", (cover(94, 95),), "protected_range"),
        }
        result["queries"] = {}
        with connect() as connection:
            for capability, (plain_sql, plain_parameters, plain_index, protected_sql, protected_parameters, protected_index) in queries.items():
                plain_query = sql.SQL(plain_sql).format(s=sql.Identifier(schema))
                protected_query = sql.SQL(protected_sql).format(s=sql.Identifier(schema))
                plain_ids = sorted(row[0] for row in connection.execute(plain_query, plain_parameters))
                protected_ids = sorted(row[0] for row in connection.execute(protected_query, protected_parameters))
                check(outcomes, capability + "_exact_ids", plain_ids == protected_ids)
                plain_result = measured(connection, plain_query, plain_parameters, plain_index)
                protected_result = measured(connection, protected_query, protected_parameters, protected_index)
                check(outcomes, capability + "_selective_index", protected_result["required_index_used_every_run"])
                result["queries"][capability] = {"selected_rows": len(plain_ids), "selectivity": len(plain_ids) / ROWS, "exact_selected_ids": True,
                                                 "plain": plain_result, "protected": protected_result}
            result["relation_bytes"] = dict(connection.execute("SELECT c.relname,pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='r' ORDER BY c.relname", (schema,)))
            result["index_bytes"] = dict(connection.execute("SELECT c.relname,pg_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relkind='i' ORDER BY c.relname", (schema,)))
            result["column_datum_bytes"] = dict(zip(("payload", "prefix", "range_terms"), connection.execute(sql.SQL("SELECT sum(pg_column_size(payload)),sum(pg_column_size(prefix)),sum(pg_column_size(range_terms)) FROM {}.protected").format(sql.Identifier(schema))).fetchone()))
            result["bundle_storage_multiplier"] = result["relation_bytes"]["protected"] / result["relation_bytes"]["plain"]
            stage = "uniqueness_negative_control"
            try:
                with connection.transaction():
                    connection.execute(sql.SQL("INSERT INTO {}.protected SELECT %s,payload,prefix,range_terms FROM {}.protected WHERE id=1").format(sql.Identifier(schema), sql.Identifier(schema)), (ROWS + 1,))
            except psycopg.errors.UniqueViolation:
                outcomes["packed_duplicate_rejected"] = "PASS"
            else:
                raise AssertionError("packed_duplicate_rejected")
        result["status"] = "PASS_LISTED_PHYSICAL_CASES_ONLY"
    except Exception as failure:
        result.update(status="FAIL", stage=stage, exception_type=type(failure).__name__, sqlstate=getattr(failure, "sqlstate", None), details="WITHHELD")
        if isinstance(failure, AssertionError) and len(failure.args) == 1 and str(failure.args[0]).replace("_", "").isalnum():
            result["failed_check"] = failure.args[0]
    finally:
        if owned:
            try:
                with connect() as connection:
                    connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
                result["cleanup"] = "OWN_SCHEMA_DROPPED"
            except Exception as failure:
                result.update(status="FAIL", cleanup="FAILED", cleanup_exception_type=type(failure).__name__)
    result["total_seconds_including_cleanup"] = time.perf_counter() - started
    RESULT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "passed": len(outcomes), "rows": ROWS, "stage": result.get("stage"), "exception_type": result.get("exception_type"), "failed_check": result.get("failed_check"), "cleanup": result.get("cleanup")}))
    raise SystemExit(0 if result["status"] == "PASS_LISTED_PHYSICAL_CASES_ONLY" else 1)


if __name__ == "__main__":
    main()
