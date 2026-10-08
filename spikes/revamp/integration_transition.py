"""One journaled transition path for the owned local fixture. External exclusion/policy unqualified."""
import hashlib
import json
import os
import uuid

import psycopg
from psycopg import sql

from integration_crypto import Failure, reveal, seal
from probe_service import EXPECTED


def maintenance_connection():
    connection = psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], **EXPECTED, hostaddr="127.0.0.1", connect_timeout=3)
    try:
        row = connection.execute("SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
        if row[:2] != ("cryptalis_test", "cryptalis_migrator") or any(row[2:]):
            raise Failure("AUTHORIZED_RESTRICTED_TARGET_REQUIRED")
        connection.commit()
        return connection
    except BaseException:
        connection.close()
        raise


class Transition:
    """Immutable operation identity; each chunk and membership marker commit together."""
    def __init__(self, attachment, mode, *, operation=None, chunk_size=100):
        if mode not in ("protect", "rotate", "deprotect") or type(chunk_size) is not int or not 1 <= chunk_size <= 10_000:
            raise Failure("TRANSITION_PLAN_NOT_ADMITTED")
        inventory = attachment.writer_inventory
        if inventory.get("unknown") or inventory.get("unexcluded") or inventory.get("maintenance") != "OWNED_LOCAL_FIXTURE_WRITERS_STOPPED":
            raise Failure("WRITER_EXCLUSION_REQUIRED")
        if not attachment.physical_schema.startswith("revamp_gate_"):
            raise Failure("OWNED_LOCAL_TRANSITION_SCOPE_REQUIRED")
        self.attachment, self.mode = attachment, mode
        self.operation = operation or uuid.uuid4()
        self.chunk_size = chunk_size
        self.schema = attachment.physical_schema
        self.journal = sql.Identifier(self.schema, "_cl_operation")
        self.markers = sql.Identifier(self.schema, "_cl_chunk")
        self.lock = int.from_bytes(hashlib.sha256(self.schema.encode()).digest()[:8], "big", signed=True)
        plan = {"target": "cryptalis_test", "schema": self.schema, "mode": mode,
                "domain": attachment.domain.hex(), "manifest": attachment.manifest,
                "payload_generation": attachment.provider.payload_generation,
                "search_generation": attachment.provider.search_generation,
                "source_generations": attachment.active_generations,
                "fields": [{"table": p.mapper.local_table.name, "column": p.column.name,
                            "descriptor": hashlib.sha256(p.crypto.descriptor()).hexdigest(),
                            "field": p.crypto.identity.hex(), "search_domain": p.crypto.search_domain.hex(),
                            "original_type": str(p.original_type)} for p in attachment.plans]}
        with maintenance_connection() as connection:
            for field in plan["fields"]:
                field["source_indexes"] = connection.execute(
                    "SELECT c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=%s::regclass ORDER BY c.relname",
                    (self.schema + "." + field["table"],)).fetchall()
        self.plan_digest = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.public_plan = plan

    def table(self, plan):
        return sql.Identifier(self.schema, plan.mapper.local_table.name)

    def shadow(self, plan):
        return "_cl_" + plan.column.name + "_" + self.operation.hex[:12]

    def open(self):
        connection = maintenance_connection()
        try:
            acquired = connection.execute("SELECT pg_try_advisory_lock(%s)", (self.lock,)).fetchone()[0]
            connection.commit()
            if not acquired:
                raise Failure("TRANSITION_EXECUTOR_ALREADY_ACTIVE")
            return connection
        except BaseException:
            connection.close()
            raise

    def inspect_operation(self, connection):
        row = connection.execute(sql.SQL("SELECT plan_digest,phase FROM {} WHERE operation=%s").format(self.journal), (self.operation,)).fetchone()
        if row is None or row[0] != self.plan_digest:
            raise Failure("OPERATION_PLAN_OR_TARGET_MISMATCH")
        return row[1]

    def expand(self, connection):
        with connection.transaction():
            connection.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (operation uuid PRIMARY KEY,plan_digest text NOT NULL,plan jsonb NOT NULL,phase text NOT NULL)").format(self.journal))
            connection.execute(sql.SQL("CREATE TABLE IF NOT EXISTS {} (operation uuid NOT NULL,field text NOT NULL,chunk integer NOT NULL,members bigint[] NOT NULL,PRIMARY KEY(operation,field,chunk))").format(self.markers))
            existing = connection.execute(sql.SQL("SELECT plan_digest FROM {} WHERE operation=%s").format(self.journal), (self.operation,)).fetchone()
            if existing is not None:
                if existing[0] != self.plan_digest:
                    raise Failure("OPERATION_PLAN_OR_TARGET_MISMATCH")
                return
            for plan in self.attachment.plans:
                connection.execute(sql.SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(self.table(plan)))
                target_type = sql.SQL(str(plan.original_type)) if self.mode == "deprotect" else sql.SQL("bytea")
                connection.execute(sql.SQL("ALTER TABLE {} ADD COLUMN {} {}").format(self.table(plan), sql.Identifier(self.shadow(plan)), target_type))
            connection.execute(sql.SQL("INSERT INTO {} VALUES (%s,%s,%s,'BACKFILL')").format(self.journal),
                               (self.operation, self.plan_digest, json.dumps(self.public_plan, sort_keys=True)))

    def source(self, plan, value, tenant, record):
        if self.mode != "protect" and value is not None:
            generations = tuple(int.from_bytes(value[start:start + 4], "big") for start in (6, 10))
            if generations != self.public_plan["source_generations"]:
                raise Failure("TRANSITION_SOURCE_GENERATION_MISMATCH")
        return value if self.mode == "protect" else reveal(plan.crypto, self.attachment.provider, tenant, record, value)

    def target(self, plan, value, tenant, record):
        return value if self.mode == "deprotect" else seal(plan.crypto, self.attachment.provider, tenant, record, value)

    def backfill(self, connection, *, after_commit=None, before_commit=None):
        if self.inspect_operation(connection) not in ("BACKFILL", "VERIFIED"):
            raise Failure("TRANSITION_PHASE_NOT_BACKFILL")
        connection.commit()
        for plan in self.attachment.plans:
            field = plan.crypto.identity.hex()
            last = None
            number = 0
            while True:
                committed = False
                with connection.transaction():
                    connection.execute(sql.SQL("LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE").format(self.table(plan)))
                    predicate = sql.SQL("") if last is None else sql.SQL(" WHERE {}>%s").format(sql.Identifier(plan.identity.name))
                    arguments = (self.chunk_size,) if last is None else (last, self.chunk_size)
                    batch = connection.execute(sql.SQL("SELECT {},{},{} FROM {}{} ORDER BY {} LIMIT %s").format(
                        sql.Identifier(plan.identity.name), sql.Identifier(plan.tenant.name), sql.Identifier(plan.column.name),
                        self.table(plan), predicate, sql.Identifier(plan.identity.name)), arguments).fetchall()
                    if not batch:
                        break
                    members = [row[0] for row in batch]
                    marker = connection.execute(sql.SQL("SELECT members FROM {} WHERE operation=%s AND field=%s AND chunk=%s").format(self.markers), (self.operation, field, number)).fetchone()
                    if marker is not None:
                        if marker[0] != members:
                            raise Failure("COMMITTED_CHUNK_MEMBERSHIP_CHANGED")
                    else:
                        prepared = [(self.target(plan, self.source(plan, value, tenant, record), tenant, record), record)
                                    for record, tenant, value in batch]
                        with connection.cursor() as cursor:
                            cursor.executemany(sql.SQL("UPDATE {} SET {}=%s WHERE {}=%s").format(
                                self.table(plan), sql.Identifier(self.shadow(plan)), sql.Identifier(plan.identity.name)), prepared)
                        connection.execute(sql.SQL("INSERT INTO {} VALUES (%s,%s,%s,%s)").format(self.markers),
                                           (self.operation, field, number, members))
                        if before_commit is not None:
                            before_commit(connection, number)
                        committed = True
                last = members[-1]
                if committed and after_commit is not None:
                    after_commit(connection, number)
                number += 1

    def verify(self, connection):
        with connection.transaction():
            for plan in self.attachment.plans:
                connection.execute(sql.SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(self.table(plan)))
                current_indexes = connection.execute(
                    "SELECT c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=%s::regclass ORDER BY c.relname",
                    (self.schema + "." + plan.mapper.local_table.name,)).fetchall()
                expected = next(field["source_indexes"] for field in self.public_plan["fields"] if field["field"] == plan.crypto.identity.hex())
                if current_indexes != expected or any(not row[2] or not row[3] for row in current_indexes):
                    raise Failure("TRANSITION_SOURCE_INDEX_CHANGED_OR_INVALID")
                with connection.cursor(name="cl_rows_" + uuid.uuid4().hex) as rows, connection.cursor(name="cl_members_" + uuid.uuid4().hex) as members:
                    rows.execute(sql.SQL("SELECT {},{},{},{} FROM {} ORDER BY {}").format(
                        sql.Identifier(plan.identity.name), sql.Identifier(plan.tenant.name), sql.Identifier(plan.column.name),
                        sql.Identifier(self.shadow(plan)), self.table(plan), sql.Identifier(plan.identity.name)))
                    members.execute(sql.SQL("SELECT unnest(members) FROM {} WHERE operation=%s AND field=%s ORDER BY chunk").format(self.markers), (self.operation, plan.crypto.identity.hex()))
                    rows.itersize = members.itersize = self.chunk_size
                    expected_members = iter(members)
                    for record, tenant, original, target in rows:
                        if next(expected_members, None) != (record,):
                            raise Failure("TRANSITION_MEMBERSHIP_MISMATCH")
                        decoded = self.source(plan, original, tenant, record)
                        actual = target if self.mode == "deprotect" else reveal(plan.crypto, self.attachment.provider, tenant, record, target)
                        if decoded != actual or type(decoded) is not type(actual):
                            raise Failure("TRANSITION_VALUE_TYPE_NULL_MISMATCH")
                        if self.mode != "deprotect" and target is not None:
                            if int.from_bytes(target[6:10], "big") != self.public_plan["payload_generation"] or int.from_bytes(target[10:14], "big") != self.public_plan["search_generation"]:
                                raise Failure("TRANSITION_TARGET_GENERATION_MISMATCH")
                    if next(expected_members, None) is not None:
                        raise Failure("TRANSITION_MEMBERSHIP_MISMATCH")
                # Full value equality plus the inspected valid source uniqueness
                # and the target unique-index build preserve scoped uniqueness.
            self.inspect_operation(connection)
            connection.execute(sql.SQL("UPDATE {} SET phase='VERIFIED' WHERE operation=%s").format(self.journal), (self.operation,))

    def switch(self, connection):
        # Verify and switch inside the same transaction/locks. A previous receipt
        # cannot authorize a switch of subsequently changed data.
        with connection.transaction():
            self.verify(connection)
            quote = sql.Identifier
            for plan in self.attachment.plans:
                index = plan.index_name + "_" + self.operation.hex[:12]
                identity_function = sql.Identifier(self.schema, "_cl_stable_" + plan.mapper.local_table.name)
                identity_trigger = quote("_cl_stable_identity")
                if self.mode == "protect":
                    # Computed PK assignments have no public SQLAlchemy SET-map
                    # accessor. PostgreSQL can enforce this exact public row
                    # invariant without inspecting SQL text or knowing any key.
                    connection.execute(sql.SQL("CREATE FUNCTION {}() RETURNS trigger LANGUAGE plpgsql AS $cl$ BEGIN IF NEW.{} IS DISTINCT FROM OLD.{} THEN RAISE EXCEPTION 'STABLE_RECORD_IDENTITY_REQUIRED' USING ERRCODE='23514'; END IF; RETURN NEW; END $cl$").format(identity_function, quote(plan.identity.name), quote(plan.identity.name)))
                    connection.execute(sql.SQL("CREATE TRIGGER {} BEFORE UPDATE OF {} ON {} FOR EACH ROW EXECUTE FUNCTION {}()").format(identity_trigger, quote(plan.identity.name), self.table(plan), identity_function))
                elif self.mode == "deprotect":
                    connection.execute(sql.SQL("DROP TRIGGER {} ON {}").format(identity_trigger, self.table(plan)))
                    connection.execute(sql.SQL("DROP FUNCTION {}()").format(identity_function))
                if self.mode == "deprotect":
                    connection.execute(sql.SQL("CREATE UNIQUE INDEX {} ON {} ({},{})").format(quote(index), self.table(plan), quote(plan.tenant.name), quote(self.shadow(plan))))
                else:
                    connection.execute(sql.SQL("CREATE UNIQUE INDEX {} ON {} ({},(substring({} FROM 15 FOR 32)))").format(quote(index), self.table(plan), quote(plan.tenant.name), quote(self.shadow(plan))))
                facts = connection.execute("SELECT indisvalid,indisready FROM pg_index WHERE indexrelid=%s::regclass", (self.schema + "." + index,)).fetchone()
                if facts != (True, True):
                    raise Failure("TRANSITION_INDEX_NOT_VALID_READY")
                connection.execute(sql.SQL("ALTER TABLE {} DROP COLUMN {}").format(self.table(plan), quote(plan.column.name)))
                connection.execute(sql.SQL("ALTER TABLE {} RENAME COLUMN {} TO {}").format(self.table(plan), quote(self.shadow(plan)), quote(plan.column.name)))
                if self.mode == "deprotect":
                    from sqlalchemy import UniqueConstraint
                    original = next(constraint for constraint in plan.mapper.local_table.constraints
                                    if isinstance(constraint, UniqueConstraint) and list(constraint.columns) == [plan.tenant, plan.column])
                    name = original.name or index
                    connection.execute(sql.SQL("ALTER TABLE {} ADD CONSTRAINT {} UNIQUE USING INDEX {}").format(self.table(plan), quote(name), quote(index)))
                if not plan.column.nullable:
                    connection.execute(sql.SQL("ALTER TABLE {} ALTER COLUMN {} SET NOT NULL").format(self.table(plan), quote(plan.column.name)))
            connection.execute(sql.SQL("UPDATE {} SET phase='SWITCHED_DATABASE_POLICY_PENDING' WHERE operation=%s").format(self.journal), (self.operation,))
        self.attachment.active_generations = (self.public_plan["payload_generation"], self.public_plan["search_generation"])

    def run(self):
        with self.open() as connection:
            self.expand(connection)
            self.backfill(connection)
            self.switch(connection)
        return self.operation
