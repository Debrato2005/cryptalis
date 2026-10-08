"""Compiler decisions use native PostgreSQL schema and application behavior."""

import copy
import json
import os
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import BigInteger, Column, MetaData, Table, Text, UniqueConstraint, Uuid
from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.orm import Session, registry

from cryptalis.manifest.compiler import (
    PlanningRejected, InspectionUnavailable, SearchReview, Writer, WriterInventory,
    compile_protection,
)
from cryptalis.manifest.parser import ManifestInvalid


DOMAIN = "10000000-0000-0000-0000-000000000001"
TABLE = "20000000-0000-0000-0000-000000000001"
FIELD = "30000000-0000-0000-0000-000000000001"


def declaration(*, queries=("unique",), single=False):
    return {
        "schema": "cryptalis.protection/v1", "profile": "cf1", "domain_id": DOMAIN,
        "models": [{
            "model": "Customer", "table_id": TABLE,
            "tenancy": {"single_tenant": True} if single else {"column": "tenant_id"},
            "fields": [{"name": "email", "field_id": FIELD, "protect": True,
                        "queries": list(queries),
                        "accept_leakage": ["equality", "unique"] if "unique" in queries else list(queries)}],
        }],
    }


def inventory(*, route="sqlalchemy", excluded=False, complete=True):
    return WriterInventory(complete, (Writer(UUID(TABLE), "application", route, excluded,
                                            "native application fixture"),))


def reviews(*, small=False):
    return (SearchReview(UUID(FIELD), small, "host review: free-form email, no finite value set"),)


@pytest.fixture(scope="module")
def engine():
    if not os.environ.get("CRYPTALIS_TEST_DATABASE_URL"):
        pytest.skip("Real PostgreSQL evidence needs CRYPTALIS_TEST_DATABASE_URL")
    try:
        with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], connect_timeout=5) as c:
            assert c.execute("select 1").fetchone() == (1,)
            assert int(c.execute("show server_version_num").fetchone()[0]) // 10000 == 16
            assert c.execute("select not rolsuper and not rolcreatedb and not rolcreaterole "
                             "and not rolreplication and not rolbypassrls from pg_roles "
                             "where rolname=current_user").fetchone() == (True,)
    except psycopg.Error as error:
        # No connection string or credentials enter pytest's exception output.
        pytest.fail(f"Database preflight failed: {type(error).__name__}; SQLSTATE {error.sqlstate}", pytrace=False)
    result = create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], connect_timeout=5))
    yield result
    result.dispose()


@pytest.fixture
def app(engine):
    schema = "cryptalis_compiler_" + uuid4().hex
    with engine.begin() as c:
        c.execute(text(f'CREATE SCHEMA "{schema}"'))
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table("customer", mapping.metadata,
                  Column("id", Uuid, primary_key=True),
                  Column("tenant_id", Uuid, nullable=False),
                  Column("email", Text(collation="C")),
                  Column("note", Text),
                  UniqueConstraint("tenant_id", "email", name="email_unique"))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    try:
        mapping.metadata.create_all(engine)
        tenant = uuid4()
        with Session(engine) as s:
            for email in (None, None, "", "é", "e\u0301"):
                s.add(Customer(id=uuid4(), tenant_id=tenant, email=email))
            s.commit()
        yield engine, mapping, Customer, schema
    finally:
        mapping.dispose()
        with engine.begin() as c:
            c.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def compile_app(app, doc=None, **kwargs):
    engine, mapping, _, _ = app
    return compile_protection(json.dumps(doc or declaration()).encode(), mapping, engine,
                              writers=kwargs.pop("writers", inventory()),
                              search_reviews=kwargs.pop("search_reviews", reviews()), **kwargs)


def snapshot(app):
    engine, _, Customer, schema = app
    with engine.connect() as c:
        columns = [{**column, "type": str(column["type"].compile(dialect=c.dialect))}
                   for column in inspect(c).get_columns("customer", schema=schema)]
        indexes = c.execute(text("SELECT pg_catalog.pg_get_indexdef(i.indexrelid) "
                                 "FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indrelid "
                                 "JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace "
                                 "WHERE n.nspname=:schema ORDER BY i.indexrelid"), {"schema": schema}).all()
        rows = c.execute(select(Customer.__table__).order_by(Customer.id)).all()
    return columns, indexes, rows


def test_native_schema_compiles_deterministically_without_effects(app):
    before = snapshot(app)
    plan = compile_app(app)
    repeated = compile_app(app)
    assert plan.lock_bytes == repeated.lock_bytes
    lock = json.loads(plan.lock_bytes)
    model = lock["models"][0]
    assert model["record"]["codec"] == "uuid16/v1"
    assert model["tenancy"] == {"column": "tenant_id", "codec": "uuid16/v1"}
    field = model["fields"][0]
    assert field["descriptor"]["text_codec"] == "utf8-exact/v1"
    assert field["descriptor"]["null_policy"] == "sql-null/v1"
    assert field["descriptor"]["normalizer"] == "identity/v1"
    assert field["queries"] == ["equality", "unique"]
    assert field["source"]["type"] == "text"
    assert field["source"]["nullable"] is True
    assert field["source"]["collation"] == "pg_catalog.C"
    assert [step.kind for step in plan.changes] == ["protect_field", "preserve_unique"]
    assert plan.effects == "NONE"
    assert snapshot(app) == before


@pytest.mark.parametrize("queries", [(), ("unique",)])
def test_single_tenant_and_app_assigned_int64(app, queries):
    engine, _, _, schema = app
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table("single_customer", mapping.metadata,
                  Column("id", BigInteger, primary_key=True, autoincrement=False),
                  Column("email", Text(collation="C")))
    if queries:
        table.append_constraint(UniqueConstraint("email", name="single_email_unique"))
    Customer = type("Customer", (), {})
    mapping.map_imperatively(Customer, table)
    mapping.metadata.create_all(engine)
    try:
        with engine.begin() as c:
            c.execute(table.insert(), [{"id": -(2**63), "email": None},
                                       {"id": 2**63-1, "email": ""}])
        plan = compile_protection(json.dumps(declaration(single=True, queries=queries)).encode(),
                                  mapping, engine, writers=inventory(), search_reviews=reviews() if queries else ())
        model = json.loads(plan.lock_bytes)["models"][0]
        assert model["record"]["codec"] == "int64-be/v1"
        assert model["tenancy"] == {"single_tenant": True, "context_id": TABLE}
        assert model["fields"][0]["representation"] == ("cf1-packed-equality/v1" if queries else "cf1-storage/v1")
    finally:
        mapping.dispose()


@pytest.mark.parametrize(("ddl", "code"), [
    ('ALTER TABLE {table} ALTER COLUMN id SET DEFAULT gen_random_uuid()', "server_generated_key"),
    ('ALTER TABLE {table} ALTER COLUMN email TYPE varchar(80)', "unsupported_type"),
    ('ALTER TABLE {table} ALTER COLUMN email TYPE integer USING NULL', "unsupported_type"),
    ('ALTER TABLE {table} ALTER COLUMN email SET DEFAULT \'private-default-marker\'', "protected_default"),
    ('ALTER TABLE {table} ADD CONSTRAINT allowed CHECK(email IN (\'a\', \'b\') OR email IS NULL) NOT VALID', "unsupported_constraint"),
    ('CREATE INDEX hidden_predicate ON {table} (id) WHERE email IS NOT NULL', "unsupported_index"),
    ('CREATE INDEX hidden_include ON {table} (id) INCLUDE(email)', "unsupported_index"),
    ('CREATE INDEX hidden_expression ON {table} (lower(email))', "unsupported_index"),
    ('CREATE UNIQUE INDEX global_unique ON {table} (email)', "unsupported_uniqueness"),
    ('CREATE UNIQUE INDEX strict_nulls ON {table} (tenant_id,email) NULLS NOT DISTINCT', "unsupported_uniqueness"),
    ('ALTER TABLE {table} ADD CONSTRAINT deferred_unique UNIQUE(tenant_id,email) DEFERRABLE', "unsupported_uniqueness"),
    ('ALTER TABLE {table} ADD COLUMN email_lower text GENERATED ALWAYS AS (lower(email)) STORED', "unsupported_dependency"),
    ('CREATE VIEW {schema}.email_view AS SELECT email FROM {table}', "unsupported_dependency"),
    ('ALTER TABLE {table} ALTER COLUMN tenant_id DROP NOT NULL', "tenant_context"),
    ('ALTER TABLE {table} ENABLE ROW LEVEL SECURITY', "unsupported_table"),
    ('ALTER TABLE {table} ADD COLUMN email_ref text COLLATE "C", ADD CONSTRAINT self_ref '
     'FOREIGN KEY(tenant_id,email_ref) REFERENCES {table}(tenant_id,email)', "unsupported_constraint"),
    ('CREATE TABLE {schema}.child (tenant_id uuid, email text COLLATE "C", '
     'FOREIGN KEY(tenant_id,email) REFERENCES {table}(tenant_id,email))', "unsupported_constraint"),
])
def test_schema_attacks_reject_before_effects(app, ddl, code):
    engine, _, _, schema = app
    with engine.begin() as c:
        if "NULLS NOT DISTINCT" in ddl:
            c.execute(text(f'UPDATE "{schema}".customer SET tenant_id=gen_random_uuid() WHERE email IS NULL'))
        c.execute(text(ddl.format(table=f'"{schema}".customer', schema=f'"{schema}"')))
    before = snapshot(app)
    with pytest.raises(PlanningRejected) as caught:
        compile_app(app)
    assert code in {issue.code for issue in caught.value.issues}
    assert all(issue.remedy for issue in caught.value.issues)
    assert "private-default-marker" not in str(caught.value)
    assert caught.value.effects == "NONE"
    assert snapshot(app) == before


@pytest.mark.parametrize(("writers", "search_reviews", "code"), [
    (inventory(complete=False), reviews(), "writer_inventory"),
    (WriterInventory(True, ()), reviews(), "writer_inventory"),
    (inventory(route="raw_sql"), reviews(), "unsupported_writer"),
    (inventory(route="unknown", excluded=True), reviews(), "unsupported_writer"),
    (inventory(), (), "search_domain_unknown"),
    (inventory(), reviews(small=True), "small_search_domain"),
])
def test_missing_security_evidence_rejects(app, writers, search_reviews, code):
    with pytest.raises(PlanningRejected) as caught:
        compile_app(app, writers=writers, search_reviews=search_reviews)
    assert code in {issue.code for issue in caught.value.issues}


def test_excluded_known_writer_is_recorded_as_host_evidence(app):
    writers = WriterInventory(True, inventory().writers +
                              (Writer(UUID(TABLE), "legacy", "copy", True, "host disables the credential"),))
    plan = compile_app(app, writers=writers)
    lock = json.loads(plan.lock_bytes)
    assert lock["writer_inventory"]["evidence_kind"] == "host_assertion"
    assert lock["writer_inventory"]["writers"][1]["excluded"] is True
    assert lock["search_reviews"][0]["evidence_kind"] == "host_assertion"


def test_unique_intent_cannot_remove_existing_constraint(app):
    with pytest.raises(PlanningRejected) as caught:
        compile_app(app, declaration(queries=("equality",)))
    assert "undeclared_uniqueness" in {issue.code for issue in caught.value.issues}


def test_changed_schema_changes_lock_and_semantic_plan(app):
    original = compile_app(app)
    engine, _, _, schema = app
    with engine.begin() as c:
        c.execute(text(f'CREATE INDEX note_index ON "{schema}".customer(note)'))
    changed = compile_app(app, previous_lock=original.lock_bytes)
    assert changed.lock_bytes != original.lock_bytes
    assert changed.source_lock_digest == original.lock_digest
    assert "schema_changed" in {step.kind for step in changed.changes}


@pytest.mark.parametrize("mutation", ["missing_tenant", "missing_leakage", "range", "duplicate_field", "wrong_model"])
def test_ambiguous_intent_cannot_reach_schema_admission(app, mutation):
    doc = declaration()
    model = doc["models"][0]
    field = model["fields"][0]
    if mutation == "missing_tenant":
        del model["tenancy"]
    elif mutation == "missing_leakage":
        field["accept_leakage"] = []
    elif mutation == "range":
        field["queries"] = field["accept_leakage"] = ["range"]
    elif mutation == "duplicate_field":
        model["fields"].append(copy.deepcopy(field))
    else:
        model["model"] = "not.a.module.to.import"
    with pytest.raises((ManifestInvalid, PlanningRejected)):
        compile_app(app, doc)


@pytest.mark.parametrize("autocommit", [False, True])
def test_read_only_transaction_rejects_real_write_injection(app, autocommit):
    engine, _, _, schema = app
    before = snapshot(app)
    def inject(conn, cursor, statement, parameters, context, executemany):
        if "pg_catalog.pg_class" in statement:
            cursor.execute(f'INSERT INTO "{schema}".customer(id,tenant_id,email) '
                           "VALUES(gen_random_uuid(),gen_random_uuid(),'private-injection-marker')")
    event.listen(engine, "before_cursor_execute", inject)
    try:
        with pytest.raises(InspectionUnavailable) as caught:
            if autocommit:
                compile_protection(json.dumps(declaration()).encode(), app[1],
                                   engine.execution_options(isolation_level="AUTOCOMMIT"),
                                   writers=inventory(), search_reviews=reviews())
            else:
                compile_app(app)
        assert caught.value.sqlstate == "25006"
        assert "private-injection-marker" not in str(caught.value)
        assert caught.value.effects == "NONE"
    finally:
        event.remove(engine, "before_cursor_execute", inject)
    assert snapshot(app) == before


@pytest.mark.parametrize("generation", ["bigserial", "bigint GENERATED ALWAYS AS IDENTITY", "bigint DEFAULT 7"])
def test_actual_server_generated_keys_cannot_hide_behind_mapping(app, generation):
    engine, _, _, schema = app
    with engine.begin() as c:
        c.execute(text(f'CREATE TABLE "{schema}".generated (id {generation} PRIMARY KEY, '
                       'email text COLLATE "C")'))
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table("generated", mapping.metadata, Column("id", BigInteger, primary_key=True, autoincrement=False),
                  Column("email", Text(collation="C")))
    Customer = type("Customer", (), {})
    mapping.map_imperatively(Customer, table)
    try:
        with pytest.raises(PlanningRejected) as caught:
            compile_protection(json.dumps(declaration(single=True, queries=())).encode(),
                               mapping, engine, writers=inventory())
        assert "server_generated_key" in {issue.code for issue in caught.value.issues}
    finally:
        mapping.dispose()


def test_storage_only_needs_no_search_collation_or_domain_review(app):
    engine, mapping, Customer, schema = app
    Customer.__table__.c.email.type.collation = None
    with engine.begin() as c:
        c.execute(text(f'ALTER TABLE "{schema}".customer DROP CONSTRAINT email_unique'))
        c.execute(text(f'ALTER TABLE "{schema}".customer ALTER COLUMN email TYPE text COLLATE "default"'))
    # The source constraint is gone intentionally; mirror the ordinary native model.
    Customer.__table__.constraints = {x for x in Customer.__table__.constraints
                                     if not isinstance(x, UniqueConstraint)}
    plan = compile_app(app, declaration(queries=()), search_reviews=())
    assert json.loads(plan.lock_bytes)["models"][0]["fields"][0]["representation"] == "cf1-storage/v1"


def test_tenant_context_change_requires_an_explicit_transition(app):
    engine, _, Customer, schema = app
    with engine.begin() as c:
        c.execute(text(f'ALTER TABLE "{schema}".customer ADD COLUMN tenant_b uuid NOT NULL DEFAULT gen_random_uuid()'))
        c.execute(text(f'ALTER TABLE "{schema}".customer ALTER COLUMN tenant_b DROP DEFAULT'))
        c.execute(text(f'ALTER TABLE "{schema}".customer DROP CONSTRAINT email_unique'))
    table = Customer.__table__
    table.constraints = {x for x in table.constraints if not isinstance(x, UniqueConstraint)}
    table.append_column(Column("tenant_b", Uuid, nullable=False))
    inspect(Customer).add_property("tenant_b", table.c.tenant_b)
    original = compile_app(app, declaration(queries=("equality",)))
    doc = declaration(queries=("equality",))
    doc["models"][0]["tenancy"] = {"column": "tenant_b"}
    changed = compile_app(app, doc, previous_lock=original.lock_bytes)
    assert "context_changed" in {step.kind for step in changed.changes}


def test_rename_does_not_change_cryptographic_descriptor(app):
    engine, _, Customer, schema = app
    original = compile_app(app)
    with engine.begin() as c:
        c.execute(text(f'ALTER TABLE "{schema}".customer RENAME TO renamed_customer'))
    Customer.__table__.name = "renamed_customer"
    renamed = compile_app(app, previous_lock=original.lock_bytes)
    a = json.loads(original.lock_bytes)["models"][0]["fields"][0]
    b = json.loads(renamed.lock_bytes)["models"][0]["fields"][0]
    assert a["descriptor_digest"] == b["descriptor_digest"]
    assert "mapping_changed" in {step.kind for step in renamed.changes}


@pytest.mark.parametrize("mutation", ["omit_field", "duplicate_model", "alter_descriptor", "wrong_members", "wrong_type",
                                      "empty_source", "missing_pk", "false_field_type", "phantom_unique", "false_original"])
def test_malformed_previous_lock_is_a_typed_refusal(app, mutation):
    old = json.loads(compile_app(app).lock_bytes)
    if mutation == "omit_field":
        old["models"][0]["fields"] = []
    elif mutation == "duplicate_model":
        old["models"].append(copy.deepcopy(old["models"][0]))
    elif mutation == "alter_descriptor":
        old["models"][0]["fields"][0]["descriptor"]["normalizer"] = "casefold"
    elif mutation == "wrong_members":
        del old["models"][0]["tenancy"]
    elif mutation == "wrong_type":
        old["models"][0]["fields"][0]["queries"] = None
    elif mutation == "empty_source":
        old["models"][0]["source_schema"]["columns"] = []
    elif mutation == "missing_pk":
        old["models"][0]["record"]["column"] = "missing"
    elif mutation == "false_field_type":
        old["models"][0]["fields"][0]["source"]["type"] = "integer"
    elif mutation == "phantom_unique":
        old["models"][0]["fields"][0]["unique_indexes"] = ["phantom"]
    else:
        old["models"][0]["fields"][0]["original"]["constraints"][0]["definition"] = "UNIQUE (email)"
    with pytest.raises(ManifestInvalid):
        compile_app(app, previous_lock=json.dumps(old).encode())


def test_replacing_stable_identity_is_not_a_silent_reprotection(app):
    original = compile_app(app)
    doc = declaration()
    replacement = uuid4()
    doc["models"][0]["fields"][0]["field_id"] = str(replacement)
    review = (SearchReview(replacement, False, "free-form email host review"),)
    with pytest.raises(PlanningRejected) as caught:
        compile_app(app, doc, search_reviews=review, previous_lock=original.lock_bytes)
    assert "stable_identity_changed" in {issue.code for issue in caught.value.issues}


def test_proposed_ddl_uses_native_postgresql_constraints(app):
    engine, _, _, schema = app
    plan = compile_app(app)
    lock = json.loads(plan.lock_bytes)
    assert lock["required_readers"] == ["cf1/v1", "utf8-exact/v1", "uuid16/v1"]
    field = lock["models"][0]["fields"][0]
    assert field["original"]["constraints"][0]["name"] == "email_unique"
    assert "UNIQUE (tenant_id, email)" in field["original"]["constraints"][0]["definition"]
    payload = field["payload_column"]
    # Execute only the proposal's additive DDL in this test-owned schema.
    with engine.begin() as c:
        for statement in lock["ddl"]["expand"]:
            c.execute(text(statement))
    reflected = inspect(engine).get_columns("customer", schema=schema)
    assert str(next(c["type"] for c in reflected if c["name"] == payload)) == "BYTEA"
    # The native target unique index must allow NULL and reject a duplicate term.
    from sqlalchemy.exc import IntegrityError
    with engine.begin() as c:
        ids = c.execute(text(f'SELECT id FROM "{schema}".customer WHERE email IS NOT NULL ORDER BY id')).scalars().all()
        c.execute(text(f'UPDATE "{schema}".customer SET "{payload}"=:frame WHERE id=:id'),
                  {"frame": b"\x00" * 14 + b"x" * 32, "id": ids[0]})
    with pytest.raises(IntegrityError):
        with engine.begin() as c:
            c.execute(text(f'UPDATE "{schema}".customer SET "{payload}"=:frame WHERE id=:id'),
                      {"frame": b"\x00" * 14 + b"x" * 32, "id": ids[1]})


def test_unrelated_schema_literals_do_not_enter_public_lock(app):
    engine, _, _, schema = app
    with engine.begin() as c:
        c.execute(text(f'ALTER TABLE "{schema}".customer ALTER COLUMN note SET DEFAULT \'private-note-marker\''))
        c.execute(text(f'ALTER TABLE "{schema}".customer ADD CHECK(note <> \'private-check-marker\')'))
    plan = compile_app(app)
    assert b"private-note-marker" not in plan.lock_bytes
    assert b"private-check-marker" not in plan.lock_bytes


def test_non_text_mapping_raises_a_typed_refusal(app):
    engine, _, _, schema = app
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table("integer_value", mapping.metadata,
                  Column("id", Uuid, primary_key=True), Column("email", BigInteger))
    Customer = type("Customer", (), {})
    mapping.map_imperatively(Customer, table)
    mapping.metadata.create_all(engine)
    try:
        with pytest.raises(PlanningRejected) as caught:
            compile_protection(json.dumps(declaration(single=True, queries=())).encode(),
                               mapping, engine, writers=inventory())
        assert "unsupported_type" in {issue.code for issue in caught.value.issues}
    finally:
        mapping.dispose()


def test_schema_translation_cannot_plan_the_wrong_table(app):
    engine, mapping, _, schema = app
    translated = engine.execution_options(schema_translate_map={schema: "different_schema"})
    with pytest.raises(PlanningRejected) as caught:
        compile_protection(json.dumps(declaration()).encode(), mapping, translated,
                           writers=inventory(), search_reviews=reviews())
    assert "unsupported_mapping" in {issue.code for issue in caught.value.issues}


def test_unqualified_mapping_resolves_native_search_path(app):
    engine, mapping, Customer, schema = app
    Customer.__table__.schema = None
    def scope(dbapi_connection, connection_record, connection_proxy):
        with dbapi_connection.cursor() as cursor:
            cursor.execute(f'SET search_path TO "{schema}",pg_catalog')
        dbapi_connection.commit()
    event.listen(engine, "checkout", scope)
    try:
        with Session(engine) as s:
            assert len(s.scalars(select(Customer)).all()) == 5
        plan = compile_protection(json.dumps(declaration()).encode(), mapping, engine,
                                  writers=inventory(), search_reviews=reviews())
        assert json.loads(plan.lock_bytes)["models"][0]["schema"] == schema
    finally:
        event.remove(engine, "checkout", scope)
        with engine.begin() as c:
            c.execute(text("RESET search_path"))
