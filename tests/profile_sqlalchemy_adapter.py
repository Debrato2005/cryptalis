"""Paired native/attached plaintext-page profile on disposable PostgreSQL 16.

Run with ``.venv/bin/python tests/profile_sqlalchemy_adapter.py``. This is a
bounded development receipt, not a release benchmark or explanation of a
historical spike result. The connection variable is never included in output.
"""

import argparse
import cProfile
import json
import os
import platform
import pstats
import statistics
import time
from uuid import UUID, uuid4

import cryptography
import psycopg
import sqlalchemy
from psycopg import sql
from sqlalchemy import Column, Index, Integer, MetaData, Table, Text, Uuid, bindparam, create_engine, event, select
from sqlalchemy.orm import registry, sessionmaker

from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring, create_root
from cryptalis.manifest.compiler import Writer, WriterInventory, compile_protection
from cryptalis.sqlalchemy import attach


DOMAIN, TABLE_ID, FIELD_ID, TENANT = (UUID(int=i) for i in range(101, 105))


def _percentile(values, quantile):
    return sorted(values)[max(0, int(len(values) * quantile + 0.999999) - 1)]


def _category(filename, function):
    if filename.endswith("cryptalis/_sqlalchemy_guard.py"):
        return "admission_and_guard"
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
    if "/sqlalchemy/engine/result.py" in filename or "/sqlalchemy/engine/cursor.py" in filename or "/sqlalchemy/engine/_processors_cy" in filename:
        return "decoding_materialization"
    return "other_orm_engine_python"


def _profile(session, statement, parameters, samples, expected):
    profile = cProfile.Profile()
    profile.enable()
    for _ in range(samples):
        assert session.execute(statement, parameters).all() == expected
    profile.disable()
    stats = pstats.Stats(profile)
    categories = {}
    calls = []
    for (filename, line, function), (primitive, total, exclusive, cumulative, callers) in stats.stats.items():
        category = _category(filename, function)
        categories[category] = categories.get(category, 0.0) + exclusive
        if category in ("admission_and_guard", "compilation_cache", "driver_database", "key_preparation"):
            calls.append({"category": category, "function": function, "calls": total,
                          "cumulative_ms_per_query": round(cumulative * 1000 / samples, 4)})
    return {"samples": samples, "profiled_ms_per_query": round(stats.total_tt * 1000 / samples, 4),
            "exclusive_ms_per_query": {key: round(value * 1000 / samples, 4) for key, value in sorted(categories.items())},
            "largest_cumulative_calls": sorted(calls, key=lambda item: item["cumulative_ms_per_query"], reverse=True)[:12]}


def _application(connection_url, schema, protected, owned_schemas):
    engine = create_engine("postgresql+psycopg://", creator=lambda: psycopg.connect(connection_url),
                           hide_parameters=True, echo=False)
    mapping = registry(metadata=MetaData(schema=schema))
    customer = Table("customer", mapping.metadata, Column("id", Uuid, primary_key=True),
                     Column("tenant_id", Uuid, nullable=False), Column("name", Text, nullable=False),
                     Column("rank", Integer, nullable=False), Column("note", Text))
    Index("customer_rank", customer.c.rank)

    class Customer:
        pass

    mapping.map_imperatively(Customer, customer)
    with engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
    owned_schemas.append(schema)
    mapping.metadata.create_all(engine)
    if protected:
        declaration = {"schema": "cryptalis.protection/v1", "profile": "cf1", "domain_id": str(DOMAIN),
                       "models": [{"model": "Customer", "table_id": str(TABLE_ID), "tenancy": {"column": "tenant_id"},
                                   "fields": [{"name": "note", "field_id": str(FIELD_ID), "protect": True,
                                               "queries": [], "accept_leakage": []}]}]}
        plan = compile_protection(json.dumps(declaration).encode(), mapping, engine,
                                  writers=WriterInventory(True, (Writer(TABLE_ID, "profile", "sqlalchemy", evidence="owned synthetic profile"),)))
        provider = DevelopmentKeyProvider()
        context = KeyContext(DOMAIN, TENANT, "payload", uuid4(), 1)
        ring = Keyring(KeyPolicy(DOMAIN, TENANT, (create_root(provider, context),), 1), {provider.provider_id: provider})
        with engine.begin() as connection:
            # Empty synthetic fixture only. This is not a product migration.
            connection.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN note TYPE pg_catalog.bytea USING NULL::pg_catalog.bytea')
        factory = attach(mapping, engine, lock=plan.lock_bytes, keys=ring)
    else:
        native = sessionmaker(engine)
        factory = lambda **kwargs: native()
    return engine, mapping, Customer, factory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--page", type=int, default=100)
    options = parser.parse_args()
    if not (1000 <= options.rows <= 10000 and 10 <= options.samples <= 200 and 10 <= options.page <= 200):
        parser.error("Use rows 1000..10000, samples 10..200, and page 10..200")
    connection_url = os.environ.get("CRYPTALIS_TEST_DATABASE_URL")
    if not connection_url:
        raise SystemExit("CRYPTALIS_TEST_DATABASE_URL is required")
    with psycopg.connect(connection_url, connect_timeout=5) as connection:
        assert connection.execute("select 1").fetchone() == (1,)
        server = connection.execute("show server_version").fetchone()[0]
        assert int(connection.execute("show server_version_num").fetchone()[0]) // 10000 == 16
        assert connection.execute("select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname=current_user").fetchone() == (True,)
    schemas = ["cryptalis_profile_" + uuid4().hex for _ in range(2)]
    applications, owned_schemas = [], []
    sessions = []
    try:
        for schema, protected in zip(schemas, (False, True)):
            applications.append(_application(connection_url, schema, protected, owned_schemas))
        identities = [uuid4() for _ in range(options.rows)]
        statements, cache_hits = [], [[], []]
        for path, (engine, mapping, model, factory) in enumerate(applications):
            with factory(tenant_id=TENANT) as session:
                session.add_all([model(id=identity, tenant_id=TENANT, name=f"synthetic-{rank:05d}", rank=rank,
                                       note="synthetic protected fixture text") for rank, identity in enumerate(identities)])
                session.commit()
            event.listen(engine, "after_cursor_execute", lambda conn, cursor, statement, parameters, context, many, path=path: cache_hits[path].append(context.cache_hit.name))
            statements.append(select(model.id, model.name, model.rank).where(model.tenant_id == TENANT, model.rank >= bindparam("floor"),
                                                                             model.name.like("synthetic-%")).order_by(model.rank).limit(options.page).offset(bindparam("start")))
            sessions.append(factory(tenant_id=TENANT))
        parameters = {"floor": 10, "start": 0}
        first_ms = []
        for path in (0, 1):
            started = time.perf_counter()
            result = sessions[path].execute(statements[path], parameters).all()
            first_ms.append((time.perf_counter() - started) * 1000)
            expected = [(identities[rank], f"synthetic-{rank:05d}", rank) for rank in range(10, 10 + options.page)]
            assert result == expected
        for _ in range(10):
            for path in (0, 1):
                assert sessions[path].execute(statements[path], parameters).all() == expected
        timings = [[], []]
        for sample in range(options.samples):
            parameters = {"floor": 10, "start": (sample * 13) % (options.rows - options.page - 10)}
            results = [None, None]
            for path in ((0, 1) if sample % 2 == 0 else (1, 0)):
                started = time.perf_counter()
                results[path] = sessions[path].execute(statements[path], parameters).all()
                timings[path].append((time.perf_counter() - started) * 1000)
            assert results[0] == results[1]
            start = 10 + parameters["start"]
            expected = [(identities[rank], f"synthetic-{rank:05d}", rank) for rank in range(start, start + options.page)]
            assert results[0] == expected
        profiles = [_profile(sessions[path], statements[path], parameters, 10, expected) for path in (0, 1)]
        page_cache_hits = [list(values) for values in cache_hits]
        point_statements = [select(model).where(model.id == bindparam("point"))
                            for engine, mapping, model, factory in applications]
        point_timings = [[], []]
        for sample in range(options.samples + 10):
            rank = (sample * 37) % options.rows
            values = []
            for path in ((0, 1) if sample % 2 == 0 else (1, 0)):
                started = time.perf_counter()
                row = sessions[path].scalar(point_statements[path], {"point": identities[rank]})
                elapsed = (time.perf_counter() - started) * 1000
                assert (row.id, row.name, row.rank, row.note) == (
                    identities[rank], f"synthetic-{rank:05d}", rank, "synthetic protected fixture text")
                assert type(row.note) is str
                values.append((row.id, row.name, row.rank, row.note))
                if sample >= 10:
                    point_timings[path].append(elapsed)
            assert values[0] == values[1]
        receipt = {"boundary": "Bounded local plaintext projection; historical million-row anomaly remains UNKNOWN",
                   "cell": {"python": platform.python_version(), "sqlalchemy": sqlalchemy.__version__, "psycopg": psycopg.__version__,
                            "cryptography": cryptography.__version__, "postgresql": server, "mode": "sync"},
                   "rows": options.rows, "page_rows": options.page, "paired_samples": options.samples,
                   "equal_results": True, "protected_columns_selected": False, "protected_rows_seeded_through_orm": True,
                   "native": {"first_query_ms": round(first_ms[0], 4), "median_ms": round(statistics.median(timings[0]), 4),
                              "p95_ms": round(_percentile(timings[0], .95), 4), "cache_hits": {value: page_cache_hits[0].count(value) for value in set(page_cache_hits[0])}, "profile": profiles[0]},
                   "attached": {"first_query_ms": round(first_ms[1], 4), "median_ms": round(statistics.median(timings[1]), 4),
                                "p95_ms": round(_percentile(timings[1], .95), 4), "cache_hits": {value: page_cache_hits[1].count(value) for value in set(page_cache_hits[1])}, "profile": profiles[1]},
                   "median_added_ms": round(statistics.median([attached - native for native, attached in zip(*timings)]), 4),
                   "point_reads": {"paired_samples": options.samples, "equal_values_and_types": True,
                                   "native_p50_ms": round(statistics.median(point_timings[0]), 4),
                                   "native_p95_ms": round(_percentile(point_timings[0], .95), 4),
                                   "attached_p50_ms": round(statistics.median(point_timings[1]), 4),
                                   "attached_p95_ms": round(_percentile(point_timings[1], .95), 4),
                                   "added_p95_ms": round(_percentile(point_timings[1], .95) - _percentile(point_timings[0], .95), 4),
                                   "target_added_p95_ms": 3},
                   "application_edits": ["One manifest", "One attach call replacing the session factory", "Authenticated tenant_id passed to factory", "Application-generated UUID primary keys"],
                   "fixture_only_edits": ["Owned empty schema protected column converted to bytea; product transition is not implemented"],
                   "measurement_limits": ["cProfile changes timings; exclusive categories sum without overlap, cumulative calls overlap", "Driver category includes wait/network/PostgreSQL time; these components are not independently separated", "Same long-lived read session and warm keys; no production-provider cost", "5000-row local evidence does not explain the earlier million-row result"]}
        print(json.dumps(receipt, indent=2, sort_keys=True))
    finally:
        for session in sessions:
            session.close()
        for engine, mapping, model, factory in applications:
            engine.dispose()
            mapping.dispose()
        with psycopg.connect(connection_url) as connection:
            for schema in owned_schemas:
                connection.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
