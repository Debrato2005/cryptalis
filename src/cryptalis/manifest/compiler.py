"""Read-only admission of protection intent against a native PostgreSQL schema.

This compiler proposes protection. It does not attach, encrypt, or migrate.
Writer and value-domain evidence comes from the trusted host, not the database.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, Column, Table, Text, UUID as SQLUUID, Uuid
from sqlalchemy import UniqueConstraint, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import registry as Registry

from cryptalis.manifest.declaration import parse_protection_declaration
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid, decode_manifest_json


@dataclass(frozen=True)
class Writer:
    table_id: UUID
    name: str
    route: str
    excluded: bool = False
    evidence: str = ""


@dataclass(frozen=True)
class WriterInventory:
    complete: bool
    writers: tuple[Writer, ...]


@dataclass(frozen=True)
class SearchReview:
    field_id: UUID
    small_domain: bool
    evidence: str


@dataclass(frozen=True)
class Issue:
    code: str
    location: str
    remedy: str


class PlanningRejected(ValueError):
    """Known incompatibilities block the entire proposal."""

    stage = "schema_admission"
    effects = "NONE"
    retry = "after_correction"

    def __init__(self, issues: list[Issue]):
        self.operation_id = str(uuid4())
        self.issues = tuple(sorted(set(issues), key=lambda i: (i.location, i.code, i.remedy)))
        super().__init__("Protection plan rejected: " + "; ".join(
            f"{i.code} at {i.location}: {i.remedy}" for i in self.issues))


class InspectionUnavailable(RuntimeError):
    """Inspection failed. No schema admission or transition follows."""

    code = "inspection_unavailable"
    stage = "schema_inspection"
    effects = "NONE"
    retry = "after_inspection"
    remedy = "Restore database access. Inspect the current schema, then compile a new plan."

    def __init__(self, sqlstate: str | None):
        self.operation_id = str(uuid4())
        self.sqlstate = sqlstate
        super().__init__(f"Database inspection failed. SQLSTATE: {sqlstate or 'UNKNOWN'}. {self.remedy}")


@dataclass(frozen=True)
class Change:
    kind: str
    table_id: str
    field_id: str | None
    explanation: str


@dataclass(frozen=True)
class ProtectionPlan:
    lock_bytes: bytes
    changes: tuple[Change, ...]
    source_lock_digest: str | None = None
    effects: str = "NONE"

    @property
    def lock_digest(self) -> str:
        return hashlib.sha256(self.lock_bytes).hexdigest()


def _canonical(document: object) -> bytes:
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ManifestInvalid("Compiler artifact exceeds 16 MiB")
    return raw


def _digest(document: object) -> str:
    return hashlib.sha256(_canonical(document)).hexdigest()


def _rows(connection, sql, **params):
    return [dict(row) for row in connection.execute(text(sql), params).mappings()]


def _schema_facts(connection, schema: str, table: str):
    relations = _rows(connection, """
        SELECT t.oid, t.relkind, t.relpersistence, t.relrowsecurity, t.relforcerowsecurity,
               t.relhasrules,
               EXISTS(SELECT 1 FROM pg_catalog.pg_inherits h
                      WHERE h.inhrelid=t.oid OR h.inhparent=t.oid) AS inherited,
               EXISTS(SELECT 1 FROM pg_catalog.pg_trigger g
                      WHERE g.tgrelid=t.oid AND NOT g.tgisinternal) AS user_triggers
        FROM pg_catalog.pg_class t JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname=:schema AND t.relname=:table
    """, schema=schema, table=table)
    if not relations:
        return None
    relation = relations[0]
    oid = relation.pop("oid")
    columns = _rows(connection, """
        SELECT a.attnum, a.attname AS name, ty.typname AS type, ns.nspname AS type_schema,
               a.atttypmod AS typmod, NOT a.attnotnull AS nullable,
               a.attidentity AS identity, a.attgenerated AS generated,
               co.collname AS collation_name, cn.nspname AS collation_schema,
               co.collisdeterministic AS deterministic, co.collprovider AS provider,
               pg_catalog.pg_get_expr(ad.adbin,ad.adrelid) AS default_expression
        FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type ty ON ty.oid=a.atttypid
        JOIN pg_catalog.pg_namespace ns ON ns.oid=ty.typnamespace
        LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
        LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
        LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
        WHERE a.attrelid=:oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum
    """, oid=oid)
    for column in columns:
        column["typmod"] = str(column["typmod"])
        expression = column.pop("default_expression")
        column["default_digest"] = _digest(expression) if expression is not None else None
        column["collation"] = (f"{column['collation_schema']}.{column['collation_name']}"
                               if column["collation_name"] else None)
    constraints = _rows(connection, """
        SELECT co.conname AS name, co.contype AS kind, co.condeferrable AS deferrable,
               co.condeferred AS deferred, co.convalidated AS validated,
               co.conrelid=:oid AS outgoing,
               co.confrelid=:oid AS incoming,
               n.nspname AS schema, t.relname AS "table",
               ARRAY(SELECT a.attname FROM unnest(co.conkey) WITH ORDINALITY k(num,pos)
                     JOIN pg_catalog.pg_attribute a ON a.attrelid=co.conrelid AND a.attnum=k.num
                     ORDER BY k.pos) AS columns,
               ARRAY(SELECT a.attname FROM unnest(co.confkey) WITH ORDINALITY k(num,pos)
                     JOIN pg_catalog.pg_attribute a ON a.attrelid=co.confrelid AND a.attnum=k.num
                     ORDER BY k.pos) AS referenced_columns,
               pg_catalog.pg_get_constraintdef(co.oid) AS definition
        FROM pg_catalog.pg_constraint co
        JOIN pg_catalog.pg_class t ON t.oid=co.conrelid
        JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
        WHERE co.conrelid=:oid OR co.confrelid=:oid ORDER BY n.nspname,t.relname,co.conname
    """, oid=oid)
    indexes = _rows(connection, """
        SELECT t.relname AS name, i.indisprimary AS "primary", i.indisunique AS "unique",
               i.indisexclusion AS exclusion, i.indnullsnotdistinct AS nulls_not_distinct,
               i.indimmediate AS immediate, i.indisvalid AS valid, i.indisready AS ready,
               i.indislive AS live, i.indisreplident AS replica_identity,
               i.indnatts AS total_columns, i.indnkeyatts AS key_columns, am.amname AS method,
               i.indpred IS NOT NULL AS partial, i.indexprs IS NOT NULL AS expression,
               ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(num,pos)
                     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.num
                     ORDER BY k.pos) AS columns,
               ARRAY(SELECT DISTINCT a.attname FROM pg_catalog.pg_depend d
                     JOIN pg_catalog.pg_attribute a ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
                     WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=i.indexrelid
                     AND d.refobjid=i.indrelid ORDER BY a.attname) AS dependency_columns,
               ARRAY(SELECT ns.nspname || '.' || op.opcname FROM unnest(i.indclass)
                     WITH ORDINALITY k(num,pos) JOIN pg_catalog.pg_opclass op ON op.oid=k.num
                     JOIN pg_catalog.pg_namespace ns ON ns.oid=op.opcnamespace ORDER BY k.pos) AS opclasses,
               ARRAY(SELECT ns.nspname || '.' || co.collname FROM unnest(i.indcollation)
                     WITH ORDINALITY k(num,pos) LEFT JOIN pg_catalog.pg_collation co ON co.oid=k.num
                     LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=co.collnamespace ORDER BY k.pos) AS collations,
               co.conname AS constraint_name,
               pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class t ON t.oid=i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid=t.relam
        LEFT JOIN pg_catalog.pg_constraint co ON co.conindid=i.indexrelid AND co.contype IN ('p','u','x')
        WHERE i.indrelid=:oid ORDER BY t.relname
    """, oid=oid)
    dependencies = _rows(connection, """
        SELECT DISTINCT a.attname AS "column", d.classid::regclass::text AS kind
        FROM pg_catalog.pg_depend d
        LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
        WHERE d.refclassid='pg_catalog.pg_class'::regclass AND d.refobjid=:oid
          AND d.classid IN ('pg_catalog.pg_rewrite'::regclass, 'pg_catalog.pg_attrdef'::regclass,
                            'pg_catalog.pg_proc'::regclass)
        ORDER BY kind,"column"
    """, oid=oid)
    for item in constraints + indexes:
        item["definition_digest"] = _digest(item["definition"])
    relation_names = _rows(connection, """
        SELECT t.relname AS name FROM pg_catalog.pg_class t
        JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=:schema
    """, schema=schema)
    return {"relation": relation, "columns": columns, "constraints": constraints,
            "indexes": indexes, "dependencies": dependencies,
            "_relation_names": {r["name"] for r in relation_names}}


def _id_codec(column, actual):
    if actual["type_schema"] != "pg_catalog":
        return None
    if type(column.type) in (Uuid, SQLUUID, postgresql.UUID) and column.type.as_uuid:
        if getattr(column.type, "native_uuid", True) and actual["type"] == "uuid":
            return "uuid16/v1"
    if type(column.type) is BigInteger and actual["type"] == "int8":
        return "int64-be/v1"
    return None


def _server_generation(column, actual):
    return (actual["identity"] or actual["generated"] or actual["default_digest"]
            or column.server_default is not None or column.server_onupdate is not None
            or column.identity is not None or column.computed is not None
            or (column.default is not None and not column.default.is_callable
                and not column.default.is_scalar))


def _host_evidence(declaration, writers, search_reviews, issues):
    def refuse(code, location, remedy):
        issues.append(Issue(code, location, remedy))
    table_ids = {m.table_id for m in declaration.models}
    field_ids = {f.field_id for m in declaration.models for f in m.fields if f.queries}
    if (not isinstance(writers, WriterInventory) or writers.complete is not True
            or not isinstance(writers.writers, tuple) or not isinstance(search_reviews, tuple)):
        refuse("writer_inventory", "writers", "Supply a complete inventory for every protected table.")
        return {}, []
    records = []
    names = set()
    for writer in writers.writers:
        if not isinstance(writer, Writer) or writer.table_id not in table_ids:
            refuse("writer_inventory", "writers", "Use writer records for declared table IDs only.")
            continue
        if (not isinstance(writer.name, str) or not writer.name.strip()
                or not isinstance(writer.evidence, str) or not writer.evidence.strip()
                or (writer.table_id, writer.name) in names or type(writer.excluded) is not bool):
            refuse("writer_inventory", "writers", "Give each writer a distinct name and evidence reference.")
            continue
        names.add((writer.table_id, writer.name))
        if writer.route not in ("sqlalchemy", "raw_sql", "copy", "external") or (
                writer.route != "sqlalchemy" and not writer.excluded):
            refuse("unsupported_writer", "writers", "Exclude opaque SQL, COPY, and separate drivers. Resolve unknown routes.")
        records.append({**asdict(writer), "table_id": str(writer.table_id)})
    for model in declaration.models:
        if not any(w.table_id == model.table_id for w in writers.writers if isinstance(w, Writer)):
            refuse("writer_inventory", model.model, "Inventory the writers for this protected table.")
    domain_records = []
    seen = set()
    for review in search_reviews:
        if not isinstance(review, SearchReview) or review.field_id not in field_ids:
            refuse("search_domain_unknown", "search_reviews", "Review declared searchable fields only.")
            continue
        if (review.field_id in seen or type(review.small_domain) is not bool
                or not isinstance(review.evidence, str) or not review.evidence.strip()):
            refuse("search_domain_unknown", "search_reviews", "Give each searchable field one domain review and evidence reference.")
            continue
        seen.add(review.field_id)
        if review.small_domain:
            refuse("small_search_domain", str(review.field_id), "Use storage-only protection for an enumerable value domain.")
        domain_records.append({**asdict(review), "field_id": str(review.field_id), "evidence_kind": "host_assertion"})
    for field_id in field_ids - seen:
        refuse("search_domain_unknown", str(field_id), "Review the value domain. Missing evidence blocks search admission.")
    return {"complete": True, "evidence_kind": "host_assertion",
            "writers": sorted(records, key=lambda w: (w["table_id"], w["name"]))}, sorted(domain_records, key=lambda r: r["field_id"])


def _compile_model(model, mapper, facts, issues, schema):
    def refuse(code, location, remedy):
        issues.append(Issue(code, f"{model.model}.{location}" if location else model.model, remedy))
    table = mapper.local_table
    relation_names = facts.pop("_relation_names")
    relation = facts["relation"]
    if (relation["relkind"] != "r" or relation["relpersistence"] != "p"
            or any(relation[k] for k in ("relrowsecurity", "relforcerowsecurity", "relhasrules", "inherited", "user_triggers"))):
        refuse("unsupported_table", "", "Use an ordinary table without inheritance, RLS, rules, or user triggers.")
    columns = {c["name"]: c for c in facts["columns"]}
    mapped = {}
    for prop in mapper.column_attrs:
        if len(prop.columns) == 1 and isinstance(prop.columns[0], Column) and prop.columns[0].table is table:
            mapped[prop.key] = prop.columns[0]
    primary = [c for c in facts["constraints"] if c["kind"] == "p" and c["outgoing"]]
    pk = list(mapper.primary_key)
    if (len(pk) != 1 or len(primary) != 1 or primary[0]["columns"] != [pk[0].name]
            or list(table.primary_key.columns) != pk or pk[0].name not in columns):
        refuse("record_identity", "", "Use one mapped, non-null primary key with an admitted context codec.")
        return None
    pk_column = pk[0]
    actual_pk = columns[pk_column.name]
    record_codec = _id_codec(pk_column, actual_pk)
    if not record_codec or actual_pk["nullable"] or pk_column.nullable:
        refuse("record_identity", pk_column.name, "Use a non-null native UUID or bigint application key.")
    if _server_generation(pk_column, actual_pk) or pk_column.onupdate is not None:
        refuse("server_generated_key", pk_column.name, "Assign keys in the application. Remove identity, serial, and database defaults.")
    tenancy = {"single_tenant": True, "context_id": str(model.table_id)}
    tenant_name = None
    if model.tenant_column is not None:
        tenant = mapped.get(model.tenant_column)
        actual = columns.get(tenant.name) if tenant is not None else None
        if (actual is None or _id_codec(tenant, actual) != "uuid16/v1" or actual["nullable"]
                or tenant.nullable or _server_generation(tenant, actual)
                or tenant.onupdate is not None):
            refuse("tenant_context", model.tenant_column, "Use a mapped, non-null, application-assigned UUID tenant column.")
        else:
            tenant_name = tenant.name
            tenancy = {"column": tenant_name, "codec": "uuid16/v1"}
    fields = []
    used_columns = set()
    for field in model.fields:
        column = mapped.get(field.name)
        actual = columns.get(column.name) if column is not None else None
        if actual is None:
            refuse("mapping_mismatch", field.name, "Map the field to one existing native table column.")
            continue
        if column.name in used_columns:
            refuse("ambiguous_field", field.name, "Declare each physical protected column once.")
        used_columns.add(column.name)
        if column is pk_column or column.name == tenant_name:
            refuse("context_field", field.name, "Keep primary-key and tenant context columns unprotected.")
        if (type(column.type) not in (Text, postgresql.TEXT) or actual["type"] != "text"
                or actual["type_schema"] != "pg_catalog" or actual["typmod"] != "-1"):
            refuse("unsupported_type", field.name, "Use native PostgreSQL text and a standard SQLAlchemy Text mapping.")
        if column.nullable != actual["nullable"]:
            refuse("mapping_mismatch", field.name, "Match mapped and database nullability before planning.")
        if (_server_generation(column, actual) or column.default is not None
                or column.onupdate is not None):
            refuse("protected_default", field.name, "Remove protected defaults and generated values. Assign values through admitted writes.")
        # Exact C identity matters. A user-defined collation called C is not this collation.
        if field.queries and (actual["collation"] != "pg_catalog.C" or actual["deterministic"] is not True
                or actual["provider"] != "c" or getattr(column.type, "collation", None) != "C"):
            refuse("unsupported_collation", field.name, "Use explicit pg_catalog C text equivalence in the schema and mapping.")
        unique_indexes = []
        expected_scope = [column.name] if model.tenant_column is None else [tenant_name, column.name]
        for constraint in facts["constraints"]:
            affected = ((constraint["outgoing"] and column.name in constraint["columns"])
                        or (constraint["incoming"] and column.name in constraint["referenced_columns"]))
            if affected and constraint["kind"] != "u":
                refuse("unsupported_constraint", field.name, "Exclude this field from CHECK, foreign-key, and exclusion constraints.")
        for dep in facts["dependencies"]:
            if dep["column"] in (None, column.name):
                refuse("unsupported_dependency", field.name, "Remove dependent views, generated columns, or stored routines before protection.")
        for index in facts["indexes"]:
            if column.name not in index["columns"] + index["dependency_columns"]:
                continue
            base_ok = (index["method"] == "btree" and index["valid"] and index["ready"]
                       and index["live"] and not index["partial"] and not index["expression"]
                       and index["total_columns"] == index["key_columns"]
                       and not index["exclusion"] and not index["replica_identity"])
            expected_ops = ["pg_catalog.text_ops"] if model.tenant_column is None else ["pg_catalog.uuid_ops", "pg_catalog.text_ops"]
            expected_collations = ["pg_catalog.C"] if model.tenant_column is None else [None, "pg_catalog.C"]
            if index["unique"]:
                if (not base_ok or index["columns"] != expected_scope or index["nulls_not_distinct"]
                        or not index["immediate"] or index["opclasses"] != expected_ops
                        or index["collations"] != expected_collations):
                    refuse("unsupported_uniqueness", field.name, "Use immediate tenant-scoped uniqueness with default distinct-NULL behavior.")
                else:
                    unique_indexes.append(index["name"])
                if "unique" not in field.queries:
                    refuse("undeclared_uniqueness", field.name, "Declare unique and accept its leakage. Existing uniqueness cannot disappear.")
            elif (not base_ok or index["columns"] != [column.name]
                  or index["opclasses"] != ["pg_catalog.text_ops"] or index["collations"] != ["pg_catalog.C"]
                  or "equality" not in field.queries):
                refuse("unsupported_index", field.name, "Use an ordinary equality index, or exclude the field from this index.")
        for constraint in table.constraints:
            if isinstance(constraint, UniqueConstraint) and column.name in [c.name for c in constraint.columns]:
                names = [c.name for c in constraint.columns]
                if not any(c["outgoing"] and c["kind"] == "u" and c["columns"] == names for c in facts["constraints"]):
                    refuse("mapping_mismatch", field.name, "Restore the mapped unique constraint in the native schema before planning.")
        if "unique" in field.queries and not unique_indexes:
            refuse("missing_uniqueness", field.name, "Create and qualify the native tenant-scoped unique constraint before protection.")
        representation = "cf1-packed-equality/v1" if field.queries else "cf1-storage/v1"
        descriptor = _descriptor(None, str(model.table_id), str(field.field_id), record_codec,
                                 "uuid16/v1" if model.tenant_column is not None else "single-tenant-uuid/v1", representation)
        payload = "_cryptalis_" + field.field_id.hex
        if payload in columns:
            refuse("generated_name_collision", field.name, "Resolve the generated payload-column name collision before planning.")
        if field.queries and payload + "_eq" in relation_names:
            refuse("generated_name_collision", field.name, "Resolve the generated equality-index name collision before planning.")
        fields.append({"name": field.name, "column": column.name, "field_id": str(field.field_id),
                       "queries": list(field.queries), "representation": representation,
                       "payload_column": payload, "unique_indexes": unique_indexes,
                       "original": {
                           "constraints": [{"name": c["name"], "definition": c["definition"]}
                                           for c in facts["constraints"] if c["outgoing"] and c["kind"] == "u"
                                           and column.name in c["columns"]],
                           "indexes": [{"name": i["name"], "definition": i["definition"]}
                                       for i in facts["indexes"] if column.name in i["columns"]
                                       and i["constraint_name"] is None and not i["partial"] and not i["expression"]],
                       },
                       "source": {"type": actual["type"], "nullable": actual["nullable"], "collation": actual["collation"]},
                       "descriptor": descriptor})
    for item in facts["constraints"] + facts["indexes"]:
        del item["definition"]
    return {"model": model.model, "table_id": str(model.table_id),
            "schema": schema, "table": table.name,
            "record": {"column": pk_column.name, "codec": record_codec},
            "tenancy": tenancy, "fields": fields, "source_schema": facts}


def _descriptor(domain_id, table_id, field_id, record_codec, tenant_codec, representation):
    return {"schema": "cryptalis.context/v1", "domain_id": domain_id,
            "table_id": table_id, "field_id": field_id, "text_codec": "utf8-exact/v1",
            "normalizer": "identity/v1", "null_policy": "sql-null/v1",
            "record_codec": record_codec, "tenant_codec": tenant_codec, "representation": representation}


def _ddl(document, engine):
    quote = engine.dialect.identifier_preparer.quote_identifier
    statements = []
    for model in document["models"]:
        table = f'{quote(model["schema"])}.{quote(model["table"])}'
        for field in model["fields"]:
            payload = quote(field["payload_column"])
            statements.append(f"ALTER TABLE {table} ADD COLUMN {payload} pg_catalog.bytea")
            if field["queries"]:
                name = quote("_cryptalis_" + UUID(field["field_id"]).hex + "_eq")
                tenant = (quote(model["tenancy"]["column"]) + ", "
                          if "column" in model["tenancy"] else "")
                unique = "UNIQUE " if "unique" in field["queries"] else ""
                statements.append(f"CREATE {unique}INDEX {name} ON {table} USING btree "
                                  f"({tenant}(pg_catalog.substring({payload}, 15, 32)) pg_catalog.bytea_ops)")
    return {"expand": statements,
            "requires_before_switch": ["qualified_cf1_framing", "writer_exclusion", "full_value_verification", "matching_deployment_policy"]}


def _previous_lock(raw, current, engine):
    """Reject inconsistent compiler artifacts before computing a semantic diff."""
    old = decode_manifest_json(raw)
    try:
        if (old.keys() != current.keys() or old["schema"] != "cryptalis.lock/v1"
                or old["profile"] != "cf1" or old["domain_id"] != current["domain_id"]
                or old["database"] != {"major": 16, "encoding": "UTF8"}):
            raise ValueError
        declaration = parse_protection_declaration(_canonical(old["declaration"]))
        if str(declaration.domain_id) != old["domain_id"] or not isinstance(old["models"], list):
            raise ValueError
        if len(old["models"]) != len(declaration.models):
            raise ValueError
        seen = set()
        for model, declared in zip(old["models"], declaration.models, strict=True):
            if model.keys() != current["models"][0].keys() or model["table_id"] != str(declared.table_id) or model["model"] != declared.model:
                raise ValueError
            if model["table_id"] in seen or not isinstance(model["schema"], str) or not isinstance(model["table"], str):
                raise ValueError
            seen.add(model["table_id"])
            if model["record"].keys() != {"column", "codec"} or model["record"]["codec"] not in ("uuid16/v1", "int64-be/v1"):
                raise ValueError
            if declared.tenant_column is None:
                if model["tenancy"] != {"single_tenant": True, "context_id": model["table_id"]}:
                    raise ValueError
                tenant_codec = "single-tenant-uuid/v1"
            else:
                if model["tenancy"].keys() != {"column", "codec"} or model["tenancy"]["codec"] != "uuid16/v1":
                    raise ValueError
                tenant_codec = "uuid16/v1"
            if model["source_schema"].keys() != {"relation", "columns", "constraints", "indexes", "dependencies"}:
                raise ValueError
            if not isinstance(model["fields"], list) or len(model["fields"]) != len(declared.fields):
                raise ValueError
            for field, intent in zip(model["fields"], declared.fields, strict=True):
                if field.keys() != current["models"][0]["fields"][0].keys() or field["field_id"] != str(intent.field_id) or field["name"] != intent.name:
                    raise ValueError
                if field["queries"] != list(intent.queries) or not isinstance(field["column"], str):
                    raise ValueError
                representation = "cf1-packed-equality/v1" if intent.queries else "cf1-storage/v1"
                expected = _descriptor(old["domain_id"], model["table_id"], field["field_id"], model["record"]["codec"], tenant_codec, representation)
                if (field["descriptor"] != expected or field["descriptor_digest"] != _digest(expected)
                        or field["representation"] != representation
                        or field["payload_column"] != "_cryptalis_" + intent.field_id.hex):
                    raise ValueError
                if field["original"].keys() != {"constraints", "indexes"}:
                    raise ValueError
                for originals in field["original"].values():
                    if not isinstance(originals, list) or any(x.keys() != {"name", "definition"} or not all(isinstance(v, str) for v in x.values()) for x in originals):
                        raise ValueError
            if any(not isinstance(model["source_schema"][key], list) for key in ("columns", "constraints", "indexes", "dependencies")):
                raise ValueError
            _validate_prior_source(model)
        inventory = old["writer_inventory"]
        if inventory.keys() != {"complete", "evidence_kind", "writers"} or inventory["evidence_kind"] != "host_assertion":
            raise ValueError
        writers = WriterInventory(inventory["complete"], tuple(Writer(UUID(w["table_id"]), w["name"], w["route"], w["excluded"], w["evidence"]) for w in inventory["writers"]))
        reviews = tuple(SearchReview(UUID(r["field_id"]), r["small_domain"], r["evidence"]) for r in old["search_reviews"])
        errors = []
        host, domain_reviews = _host_evidence(declaration, writers, reviews, errors)
        if errors or inventory != host or domain_reviews != old["search_reviews"] or old["ddl"] != _ddl(old, engine):
            raise ValueError
        readers = sorted({"cf1/v1", "utf8-exact/v1"} | {m["record"]["codec"] for m in old["models"]} | {"uuid16/v1" for m in old["models"] if "column" in m["tenancy"]})
        if old["required_readers"] != readers:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ManifestInvalid("Previous lock has an invalid compiler structure or inconsistent context") from None
    return old


def _validate_prior_source(model):
    """Check a prior snapshot's shape and admitted facts without trusting its hash."""
    def require(condition):
        if not condition:
            raise ValueError
    def members(value, keys, bool_keys=(), int_keys=(), list_keys=(), optional_keys=()):
        require(isinstance(value, dict) and value.keys() == set(keys.split()))
        for key, item in value.items():
            if key in optional_keys and item is None:
                continue
            elif key in bool_keys:
                require(type(item) is bool)
            elif key in int_keys:
                require(type(item) is int and item >= 0)
            elif key in list_keys:
                require(isinstance(item, list) and all(isinstance(v, str) or v is None for v in item))
            else:
                require(isinstance(item, str))
    facts = model["source_schema"]
    members(facts["relation"], "relkind relpersistence relrowsecurity relforcerowsecurity relhasrules inherited user_triggers",
            bool_keys=("relrowsecurity", "relforcerowsecurity", "relhasrules", "inherited", "user_triggers"))
    require(facts["relation"]["relkind"] == "r" and facts["relation"]["relpersistence"] == "p")
    require(not any(facts["relation"][k] for k in ("relrowsecurity", "relforcerowsecurity", "relhasrules", "inherited", "user_triggers")))
    columns = {}
    for column in facts["columns"]:
        members(column, "attnum name type type_schema typmod nullable identity generated collation_name collation_schema deterministic provider default_digest collation",
                bool_keys=("nullable", "deterministic"), int_keys=("attnum",),
                optional_keys=("collation_name", "collation_schema", "provider", "default_digest", "collation", "deterministic"))
        # Determinism is nullable for non-collatable types.
        require(column["deterministic"] is None or type(column["deterministic"]) is bool)
        require(column["name"] not in columns and column["attnum"] > 0)
        require(column["collation"] == (f'{column["collation_schema"]}.{column["collation_name"]}' if column["collation_name"] else None))
        columns[column["name"]] = column
    for constraint in facts["constraints"]:
        members(constraint, "name kind deferrable deferred validated outgoing incoming schema table columns referenced_columns definition_digest",
                bool_keys=("deferrable", "deferred", "validated", "outgoing", "incoming"),
                list_keys=("columns", "referenced_columns"))
    for index in facts["indexes"]:
        members(index, "name primary unique exclusion nulls_not_distinct immediate valid ready live replica_identity total_columns key_columns method partial expression columns dependency_columns opclasses collations constraint_name definition_digest",
                bool_keys=("primary", "unique", "exclusion", "nulls_not_distinct", "immediate", "valid", "ready", "live", "replica_identity", "partial", "expression"),
                int_keys=("total_columns", "key_columns"), list_keys=("columns", "dependency_columns", "opclasses", "collations"),
                optional_keys=("constraint_name",))
        require(index["total_columns"] == len(index["columns"]) and index["key_columns"] <= index["total_columns"])
    for dep in facts["dependencies"]:
        members(dep, "column kind", optional_keys=("column",))
    pk = columns.get(model["record"]["column"])
    require(pk is not None and not pk["nullable"] and pk["type_schema"] == "pg_catalog")
    require(pk["type"] == {"uuid16/v1": "uuid", "int64-be/v1": "int8"}[model["record"]["codec"]])
    require(not any(pk[k] for k in ("identity", "generated", "default_digest")))
    primary = [c for c in facts["constraints"] if c["outgoing"] and c["kind"] == "p"]
    require(len(primary) == 1 and primary[0]["columns"] == [pk["name"]])
    tenant_name = model["tenancy"].get("column")
    if tenant_name is not None:
        tenant = columns.get(tenant_name)
        require(tenant is not None and tenant["type"] == "uuid" and tenant["type_schema"] == "pg_catalog" and not tenant["nullable"])
        require(not any(tenant[k] for k in ("identity", "generated", "default_digest")))
    require(len({f["column"] for f in model["fields"]}) == len(model["fields"]))
    for field in model["fields"]:
        source = columns.get(field["column"])
        require(source is not None and source["type"] == "text" and source["type_schema"] == "pg_catalog" and source["typmod"] == "-1")
        require(field["column"] not in (pk["name"], tenant_name))
        require(not any(source[k] for k in ("identity", "generated", "default_digest")))
        require(field["source"] == {"type": "text", "nullable": source["nullable"], "collation": source["collation"]})
        if field["queries"]:
            require(source["collation"] == "pg_catalog.C" and source["deterministic"] is True and source["provider"] == "c")
        affected = [i for i in facts["indexes"] if field["column"] in i["columns"] + i["dependency_columns"]]
        require(field["unique_indexes"] == [i["name"] for i in affected if i["unique"]])
        require(bool(field["unique_indexes"]) == ("unique" in field["queries"]))
        scope = [tenant_name, field["column"]] if tenant_name is not None else [field["column"]]
        for constraint in facts["constraints"]:
            if ((constraint["outgoing"] and field["column"] in constraint["columns"])
                    or (constraint["incoming"] and field["column"] in constraint["referenced_columns"])):
                require(constraint["kind"] == "u" and constraint["outgoing"] and constraint["columns"] == scope)
                require(not constraint["deferrable"] and constraint["validated"])
        require(not any(d["column"] in (None, field["column"]) for d in facts["dependencies"]))
        for index in affected:
            require(index["method"] == "btree" and all(index[k] for k in ("valid", "ready", "live", "immediate")))
            require(not any(index[k] for k in ("primary", "exclusion", "nulls_not_distinct", "replica_identity", "partial", "expression")))
            require(index["total_columns"] == index["key_columns"])
            require(index["columns"] == (scope if index["unique"] else [field["column"]]))
            ops = (["pg_catalog.uuid_ops"] if tenant_name is not None else []) + ["pg_catalog.text_ops"]
            collations = ([None] if tenant_name is not None else []) + ["pg_catalog.C"]
            require(index["opclasses"] == (ops if index["unique"] else ["pg_catalog.text_ops"]))
            require(index["collations"] == (collations if index["unique"] else ["pg_catalog.C"]))
        for key, items in (("constraints", facts["constraints"]), ("indexes", facts["indexes"])):
            originals = field["original"][key]
            candidates = {i["name"]: i for i in items if field["column"] in i["columns"]
                          and (i["outgoing"] and i["kind"] == "u" if key == "constraints" else i["constraint_name"] is None)}
            require(len(originals) == len(candidates) and {o["name"] for o in originals} == set(candidates))
            for original in originals:
                native = candidates.get(original["name"])
                require(native is not None and _digest(original["definition"]) == native["definition_digest"])


def _changes(current, previous):
    changes = []
    old_models = {m["table_id"]: m for m in previous["models"]} if previous else {}
    for model in current["models"]:
        old = old_models.get(model["table_id"])
        old_fields = {f["field_id"]: f for f in old["fields"]} if old else {}
        if old and (old["tenancy"] != model["tenancy"] or old["record"] != model["record"]):
            changes.append(Change("context_changed", model["table_id"], None,
                                  "Reseal every affected current value under its new record and tenant context. Verify before switch."))
        if old and any(old[key] != model[key] for key in ("model", "schema", "table")):
            changes.append(Change("mapping_changed", model["table_id"], None,
                                  "Inspect the new physical mapping. SQL names do not change cryptographic identities."))
        if old and old["source_schema"] != model["source_schema"]:
            changes.append(Change("schema_changed", model["table_id"], None,
                                  "The native schema changed. Inspect dependencies and compile a fresh transition."))
        for field in model["fields"]:
            prior = old_fields.get(field["field_id"])
            if not prior:
                changes.append(Change("protect_field", model["table_id"], field["field_id"],
                                      "Stage a bytea payload. Preserve exact text and SQL NULL. Verify before switch."))
                if "unique" in field["queries"]:
                    changes.append(Change("preserve_unique", model["table_id"], field["field_id"],
                                          "Replace native scoped uniqueness with the same scope and distinct-NULL behavior."))
            elif prior != field:
                kind = "representation_changed" if prior["descriptor"] != field["descriptor"] else "mapping_changed"
                changes.append(Change(kind, model["table_id"], field["field_id"],
                                      "Transform and verify current values. A changed lock cannot activate protection."))
        for field_id in sorted(old_fields.keys() - {f["field_id"] for f in model["fields"]}):
            changes.append(Change("decrypt_back_required", model["table_id"], field_id,
                                  "Recover and verify current values before removing protection."))
    for table_id in sorted(old_models.keys() - {m["table_id"] for m in current["models"]}):
        changes.append(Change("decrypt_back_required", table_id, None,
                              "Recover and verify current values before removing the protected table from the lock."))
    if previous and (current["writer_inventory"] != previous["writer_inventory"]
                     or current["search_reviews"] != previous["search_reviews"]):
        changes.append(Change("host_evidence_changed", "", None,
                              "Inspect changed writer and value-domain evidence before a transition."))
    return tuple(changes)


def compile_protection(raw: bytes, mapping: Registry, engine: Engine, *,
                       writers: WriterInventory, search_reviews: tuple[SearchReview, ...] = (),
                       previous_lock: bytes | None = None) -> ProtectionPlan:
    """Inspect one declaration and native schema. Return an unapplied proposal.

    The engine must be a synchronous psycopg PostgreSQL engine. Inspection owns
    a fresh REPEATABLE READ, READ ONLY transaction. It never reads application
    values. A lock digest detects changes; it is not an authorization signature.
    """
    declaration = parse_protection_declaration(raw)
    issues = []
    host, reviews = _host_evidence(declaration, writers, search_reviews, issues)
    if not isinstance(mapping, Registry) or not isinstance(engine, Engine):
        issues.append(Issue("unsupported_stack", "compiler", "Supply a SQLAlchemy registry and synchronous PostgreSQL engine."))
    elif engine.dialect.name != "postgresql" or engine.dialect.driver != "psycopg":
        issues.append(Issue("unsupported_stack", "engine", "Use SQLAlchemy 2.x with psycopg 3 and PostgreSQL 16."))
    elif engine.get_execution_options().get("schema_translate_map"):
        issues.append(Issue("unsupported_mapping", "engine", "Use physical table schemas. Schema translation requires separate admission."))
    if issues:
        raise PlanningRejected(issues)
    mappers = {}
    for mapper in mapping.mappers:
        mappers.setdefault(mapper.class_.__name__, []).append(mapper)
    models = []
    used_tables = set()
    try:
        with engine.connect().execution_options(isolation_level="REPEATABLE READ", postgresql_readonly=True) as connection, connection.begin():
            if connection.exec_driver_sql("SHOW transaction_read_only").scalar_one() != "on":
                raise InspectionUnavailable(None)
            resolved = {}
            for model in declaration.models:
                matches = mappers.get(model.model, [])
                if len(matches) == 1 and isinstance(matches[0].local_table, Table):
                    table = matches[0].local_table
                    if table.schema is None:
                        rows = _rows(connection, """
                            SELECT n.nspname AS schema FROM pg_catalog.pg_class t
                            JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
                            WHERE t.oid=pg_catalog.to_regclass(:name)
                        """, name=engine.dialect.identifier_preparer.quote_identifier(table.name))
                        resolved[model.model] = rows[0]["schema"] if rows else None
            connection.exec_driver_sql("SET LOCAL search_path = pg_catalog")
            version = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
            encoding = connection.exec_driver_sql("SHOW server_encoding").scalar_one()
            if version // 10000 != 16 or encoding != "UTF8":
                issues.append(Issue("unsupported_database", "database", "Use PostgreSQL 16 with UTF8 server encoding."))
            for model in declaration.models:
                matches = mappers.get(model.model, [])
                if len(matches) != 1:
                    issues.append(Issue("model_resolution", model.model, "Use one unambiguous model name from the supplied registry."))
                    continue
                mapper = matches[0]
                table = mapper.local_table
                if (not isinstance(table, Table) or mapper.inherits is not None
                        or mapper.persist_selectable is not table):
                    issues.append(Issue("unsupported_mapping", model.model, "Use a direct mapping to one ordinary table."))
                    continue
                schema = table.schema if table.schema is not None else resolved.get(model.model)
                if schema is None:
                    issues.append(Issue("missing_table", model.model, "Create the native application table on the current search path before planning."))
                    continue
                address = (schema, table.name)
                if address in used_tables:
                    issues.append(Issue("ambiguous_table", model.model, "Declare each protected physical table once."))
                    continue
                used_tables.add(address)
                facts = _schema_facts(connection, *address)
                if facts is None:
                    issues.append(Issue("missing_table", model.model, "Create the native application table before planning."))
                    continue
                compiled = _compile_model(model, mapper, facts, issues, schema)
                if compiled:
                    for field in compiled["fields"]:
                        field["descriptor"]["domain_id"] = str(declaration.domain_id)
                        field["descriptor_digest"] = _digest(field["descriptor"])
                    models.append(compiled)
    except SQLAlchemyError as error:
        sqlstate = getattr(getattr(error, "orig", None), "sqlstate", None)
        raise InspectionUnavailable(sqlstate) from None
    if issues:
        raise PlanningRejected(issues)
    document = {"schema": "cryptalis.lock/v1", "profile": "cf1",
                "domain_id": str(declaration.domain_id), "database": {"major": 16, "encoding": "UTF8"},
                "declaration": json.loads(declaration.canonical_bytes()), "models": models,
                "writer_inventory": host, "search_reviews": reviews}
    document["ddl"] = _ddl(document, engine)
    document["required_readers"] = sorted({"cf1/v1", "utf8-exact/v1"}
        | {m["record"]["codec"] for m in models}
        | {"uuid16/v1" for m in models if "column" in m["tenancy"]})
    previous = None
    if previous_lock is not None:
        previous = _previous_lock(previous_lock, document, engine)
        old_paths = {(m["schema"], m["table"]): m for m in previous["models"]}
        for model in models:
            old = old_paths.get((model["schema"], model["table"]))
            if old and old["table_id"] != model["table_id"]:
                issues.append(Issue("stable_identity_changed", model["model"], "Retain the stable table ID. Identity replacement needs an explicit verified transition."))
            if old:
                old_fields = {f["column"]: f for f in old["fields"]}
                for field in model["fields"]:
                    prior = old_fields.get(field["column"])
                    if prior and prior["field_id"] != field["field_id"]:
                        issues.append(Issue("stable_identity_changed", field["name"], "Retain the stable field ID. Identity replacement needs an explicit verified transition."))
        if issues:
            raise PlanningRejected(issues)
        changes = _changes(document, previous)
    else:
        changes = _changes(document, None)
    return ProtectionPlan(_canonical(document), changes,
                          _digest(previous) if previous is not None else None)
