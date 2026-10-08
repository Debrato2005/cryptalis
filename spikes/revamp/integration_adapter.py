"""Integrated local attachment candidate. No production or full-gate qualification."""
from dataclasses import dataclass
from contextvars import ContextVar
from collections import Counter
import struct
import uuid

from sqlalchemy import BigInteger, LargeBinary, Select, String, and_, bindparam, case, cast, create_engine, event, func, inspect, literal, or_, select, type_coerce
from sqlalchemy.dialects.postgresql import REGCLASS
from sqlalchemy.orm import Session, attributes
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, BooleanClauseList, Cast, ColumnClause, ColumnElement, TextClause, TypeCoerce
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.types import TypeDecorator

from integration_crypto import Failure, Field, reveal, seal, term


class PreparedFrame(bytes):
    pass


@dataclass(frozen=True)
class _DMLShapes:
    token: object
    values: dict


class ProtectedPredicate(ColumnElement):
    inherit_cache = False

    def __init__(self, column, op, value):
        self.column, self.op, self.value = column, op, value
        from sqlalchemy import Boolean
        self.type = Boolean()


class ContextualRead(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, plan, expected=(None, None)):
        self.plan = plan
        self.expected = expected
        super().__init__()

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, bytes) or len(value) < 16:
            raise Failure("EXPECTED_ROW_CONTEXT_MISSING")
        record, tenant = struct.unpack(">qq", value[:16])
        expected_record, expected_tenant = self.expected
        if expected_record is not None and record != expected_record:
            raise Failure("EXPECTED_RECORD_CONTEXT_MISMATCH")
        if expected_tenant is not None and tenant != expected_tenant:
            raise Failure("EXPECTED_TENANT_CONTEXT_MISMATCH")
        return reveal(self.plan.crypto, self.plan.attachment.provider, tenant, record, value[16:])


class SealedText(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, plan):
        self.plan = plan
        super().__init__()

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, PreparedFrame):
            raise Failure("COMPLETE_PREPARED_ROW_REQUIRED")
        return bytes(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        raise Failure("UNPROJECTED_PROTECTED_VALUE_REJECTED")

    def column_expression(self, column):
        table = column.table
        identity = table.c[self.plan.identity.name]
        tenant = table.c[self.plan.tenant.name]
        raw = type_coerce(column, LargeBinary)
        projection = func.int8send(cast(identity, BigInteger)).op("||")(
            func.int8send(cast(tenant, BigInteger))).op("||")(raw)
        expected = self.plan.attachment.read_points.get().get(self.plan.crypto.identity, (None, None))
        return type_coerce(case((raw.is_(None), None), else_=projection), ContextualRead(self.plan, expected))


@dataclass
class Plan:
    attachment: object
    mapper: object
    column: object
    identity: object
    tenant: object
    original_type: object
    crypto: Field
    index_name: str


class BoundaryCursor:
    """DBAPI surface only. No SQL text parser or caller-selected bypass."""
    def __init__(self, connection, cursor):
        self.connection = connection
        self._cursor = cursor

    def execute(self, query, parameters=None, **kwargs):
        self.connection.consume()
        self._cursor.execute(query, parameters, **kwargs)
        return self

    def executemany(self, query, parameters, **kwargs):
        self.connection.consume()
        self._cursor.executemany(query, parameters, **kwargs)
        return self

    def copy(self, *args, **kwargs):
        raise Failure("COPY_NOT_ADMITTED_BEFORE_WIRE")

    def close(self):
        self._cursor.close()

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchmany(self, *args):
        return self._cursor.fetchmany(*args)

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self):
        return iter(self._cursor)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def arraysize(self):
        return self._cursor.arraysize

    @arraysize.setter
    def arraysize(self, value):
        self._cursor.arraysize = value


class BoundaryInfo:
    """Expose dialect metadata without libpq handles or connection secrets."""
    _allowed = frozenset({"encoding", "transaction_status", "pipeline_status", "status",
                          "server_version", "backend_pid", "timezone", "protocol_version"})

    def __init__(self, info):
        self._info = info

    def __getattr__(self, name):
        if name not in self._allowed:
            raise Failure("CONNECTION_INFO_CAPABILITY_NOT_ADMITTED")
        return getattr(self._info, name)


class BoundaryConnection:
    # SQLAlchemy's documented psycopg surface; raw protocol handles are omitted.
    _properties = frozenset({"autocommit", "isolation_level", "read_only", "deferrable", "closed", "broken", "info", "adapters"})

    def __init__(self, raw, attachment):
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "attachment", attachment)
        object.__setattr__(self, "_ready", False)
        object.__setattr__(self, "_ticket", False)

    def __getattr__(self, name):
        if name == "info":
            return BoundaryInfo(self._raw.info)
        if name in self._properties:
            return getattr(self._raw, name)
        raise Failure("RAW_DBAPI_CAPABILITY_NOT_ADMITTED")

    def __setattr__(self, name, value):
        if name in self._properties:
            setattr(self._raw, name, value)
        elif name in {"_ready", "_ticket"}:
            object.__setattr__(self, name, value)
        else:
            raise Failure("DBAPI_MUTATION_NOT_ADMITTED")

    def consume(self):
        if self._ready and not self._ticket:
            raise Failure("DIRECT_DBAPI_EXECUTION_NOT_ADMITTED")
        self._ticket = False
        self.attachment.driver_executions += 1

    def cursor(self, *args, **kwargs):
        return BoundaryCursor(self, self._raw.cursor(*args, **kwargs))

    def execute(self, query, parameters=None, **kwargs):
        return self.cursor().execute(query, parameters, **kwargs)

    def commit(self):
        return self._raw.commit()

    def rollback(self):
        self._ticket = False
        return self._raw.rollback()

    def close(self):
        return self._raw.close()

    def add_notice_handler(self, handler):
        return self._raw.add_notice_handler(handler)

    def remove_notice_handler(self, handler):
        return self._raw.remove_notice_handler(handler)


class Attachment:
    def __init__(self, registry, engine, manifest, provider, physical_schema, local_mode, writer_inventory=None):
        if local_mode is not True or getattr(provider, "development_only", False) is not True:
            raise Failure("LOCAL_FIXTURE_PROFILE_REQUIRED")
        if manifest.get("schema") != 1 or manifest.get("profile") != "standard":
            raise Failure("MANIFEST_PROFILE_NOT_ADMITTED")
        if not isinstance(writer_inventory, dict) or any(type(writer_inventory.get(key)) is not list for key in ("attached", "unknown", "unexcluded")) or not writer_inventory.get("attached"):
            raise Failure("WRITER_INVENTORY_REQUIRED_BEFORE_TRANSFORMATION")
        if any(route not in ("orm", "core", "async", "background") for route in writer_inventory["attached"]):
            raise Failure("WRITER_ROUTE_NOT_ADMITTED")
        if writer_inventory.get("unknown") or writer_inventory.get("unexcluded"):
            raise Failure("UNKNOWN_OR_UNEXCLUDED_WRITER_BLOCKS_TRANSFORMATION")
        if writer_inventory.get("maintenance") != "OWNED_LOCAL_FIXTURE_WRITERS_STOPPED":
            raise Failure("MAINTENANCE_EXCLUSION_NOT_ESTABLISHED")
        self.writer_inventory = writer_inventory
        self.manifest = manifest
        self.registry, self.engine, self.provider = registry, engine, provider
        self.physical_schema = physical_schema
        self.driver_executions = 0
        self.listeners = []
        self.runtime_engines = []
        self.plans = []
        self.sequences = {}
        self.domain = uuid.uuid4().bytes
        self.active_generations = (provider.payload_generation, provider.search_generation)
        self.read_points = ContextVar("cryptalis_read_points_" + uuid.uuid4().hex, default={})
        self._shape_token = object()
        self._compile(manifest)

    def _compile(self, manifest):
        # This evidence candidate covers one protected field. Do not migrate
        # an unqualified multi-field plan through single-field row preparation.
        if sum(len(model.get("fields", {})) for model in manifest.get("models", {}).values()) != 1:
            raise Failure("ONE_PROTECTED_FIELD_EVIDENCE_SCOPE_REQUIRED")
        by_name = {mapper.class_.__name__: mapper for mapper in self.registry.mappers}
        with self.engine.connect() as connection:
            inspector = inspect(connection)
            if connection.scalar(select(func.current_setting("server_encoding"))) != "UTF8":
                raise Failure("ORIGINAL_DATABASE_ENCODING_UNQUALIFIED")
            for name, declaration in manifest["models"].items():
                if name not in by_name or not declaration.get("tenant"):
                    raise Failure("EXPLICIT_MAPPED_TENANT_REQUIRED")
                mapper = by_name[name]
                table = mapper.local_table
                if len(mapper.primary_key) != 1:
                    raise Failure("COMPOSITE_IDENTITY_UNQUALIFIED")
                identity = mapper.primary_key[0]
                tenant = table.c[declaration["tenant"]]
                for column in (identity, tenant):
                    if not isinstance(column.type, (BigInteger,)) and column.type.__visit_name__ != "integer":
                        raise Failure("ORIGINAL_INTEGER_CONTEXT_REQUIRED")
                for attribute, field in declaration["fields"].items():
                    column = table.c[attribute]
                    if field.get("protect") is not True or set(field.get("queries", [])) != {"equality", "unique"} or field.get("accept_leakage") != ["equality"]:
                        raise Failure("UNQUALIFIED_MANIFEST_CAPABILITY")
                    if not isinstance(column.type, String) or column.default is not None or column.server_default is not None:
                        raise Failure("ORIGINAL_TEXT_DEFAULT_OR_CODEC_UNQUALIFIED")
                    if column.type.length is not None or column.type.collation is not None:
                        raise Failure("BOUNDED_OR_EXPLICIT_COLLATION_TEXT_UNQUALIFIED")
                    actual = next(item for item in inspector.get_columns(table.name, schema=self.physical_schema) if item["name"] == column.name)
                    if str(actual["type"]) != str(column.type) or actual["nullable"] != column.nullable or actual["default"] is not None:
                        raise Failure("ORIGINAL_MAPPING_AND_DATABASE_DISAGREE")
                    deterministic = connection.exec_driver_sql("SELECT c.collisdeterministic FROM pg_attribute a JOIN pg_collation c ON c.oid=a.attcollation WHERE a.attrelid=%s::regclass AND a.attname=%s", (self.qualified(table), column.name)).scalar_one()
                    if not deterministic:
                        raise Failure("NONDETERMINISTIC_COLLATION_UNQUALIFIED")
                    constraints = inspector.get_unique_constraints(table.name, schema=self.physical_schema)
                    if not any(item["column_names"] == [tenant.name, column.name] for item in constraints):
                        raise Failure("ORIGINAL_SCOPED_UNIQUENESS_UNQUALIFIED")
                    field_id = uuid.uuid4().bytes
                    crypto = Field(self.domain, field_id, field_id, 8 if isinstance(identity.type, BigInteger) else 4,
                                   8 if isinstance(tenant.type, BigInteger) else 4)
                    self.plans.append(Plan(self, mapper, column, identity, tenant, column.type, crypto,
                                           "cl_" + field_id.hex()[:20] + "_eq"))
            # Inspect every original generated identity; parents can be needed before child encryption.
            for mapper in self.registry.mappers:
                if len(mapper.primary_key) != 1:
                    raise Failure("ORIGINAL_IDENTITY_UNQUALIFIED")
                column = mapper.primary_key[0]
                if column.identity is not None and column.identity.always:
                    raise Failure("IDENTITY_ALWAYS_PREALLOCATION_UNQUALIFIED")
                row = connection.execute(select(func.pg_get_serial_sequence(self.qualified(mapper.local_table), column.name))).scalar_one()
                if row is None:
                    raise Failure("ORIGINAL_SEQUENCE_NOT_FOUND")
                self.sequences[mapper.class_] = (column, row)

    def qualified(self, table):
        preparer = self.engine.dialect.identifier_preparer
        return preparer.quote_identifier(self.physical_schema) + "." + preparer.quote_identifier(table.name)

    def reserve(self, connection, mapper_class):
        column, sequence = self.sequences[mapper_class]
        value = connection.scalar(select(func.nextval(cast(literal(sequence), REGCLASS))))
        width = 8 if isinstance(column.type, BigInteger) else 4
        if type(value) is not int or not -(2 ** (width * 8 - 1)) <= value < 2 ** (width * 8 - 1):
            raise Failure("ORIGINAL_SEQUENCE_VALUE_OUT_OF_RANGE")
        return value

    def protect_existing(self):
        from integration_transition import Transition
        self.protection_operation = Transition(self, "protect").run()

    def listen(self, target, event_name, callback, **kwargs):
        event.listen(target, event_name, callback, **kwargs)
        self.listeners.append((target, event_name, callback))

    def install(self, engine=None):
        engine = self.engine if engine is None else engine
        self.runtime_engines.append(engine)
        # Engine configuration is retained; only new DBAPI connections receive the method guard.
        engine.dispose()
        engine.clear_compiled_cache()
        # Native ORM entity cache keys can omit a changed column type. This
        # candidate freezes per-execution host context into result processors,
        # so cached processors would carry another request's point. Use the
        # public engine option until a cache-safe context path is qualified.
        engine.update_execution_options(compiled_cache=None)
        for plan in self.plans:
            plan.column.type = SealedText(plan)

        def do_connect(dialect, record, arguments, parameters):
            raw = dialect.dbapi.connect(*arguments, **parameters)
            try:
                if dialect.is_async and not isinstance(raw.driver_connection, BoundaryConnection):
                    raise Failure("ASYNC_BOUNDARY_CREATOR_REQUIRED")
                row = raw.execute("SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
                if row[:2] != ("cryptalis_test", "cryptalis_migrator") or any(row[2:]):
                    raise Failure("AUTHORIZED_RESTRICTED_TARGET_REQUIRED")
                raw.commit()
                return raw if dialect.is_async else BoundaryConnection(raw, self)
            except BaseException:
                raw.close()
                raise

        def checkout(connection, record, proxy):
            if engine.dialect.is_async:
                connection = connection.driver_connection
            if not isinstance(connection, BoundaryConnection):
                raise Failure("UNGUARDED_CONNECTION_NOT_ADMITTED")
            connection._ready = True
            connection._ticket = False

        def cursor_gate(connection, cursor, statement, parameters, context, many):
            boundary = connection.connection.driver_connection
            if not isinstance(boundary, BoundaryConnection):
                raise Failure("UNGUARDED_CONNECTION_NOT_ADMITTED")
            if boundary._ready and context.compiled is None:
                raise Failure("OPAQUE_DRIVER_SQL_NOT_ADMITTED")
            boundary._ticket = True

        self.listen(engine, "do_connect", do_connect)
        self.listen(engine, "checkout", checkout)
        self.listen(engine, "before_cursor_execute", cursor_gate)
        self.listen(engine, "before_execute", self.before_execute, retval=True)
        if len(self.runtime_engines) == 1:
            self.listen(Session, "do_orm_execute", self.orm_execution)
            self.listen(Session, "before_flush", self.before_flush)
            self.listen(Session, "after_flush_postexec", self.clear)
            self.listen(Session, "after_soft_rollback", self.clear)

    def belongs(self, session):
        bound = session.get_bind()
        pool = getattr(bound, "pool", getattr(getattr(bound, "engine", None), "pool", None))
        return any(pool is engine.pool for engine in self.runtime_engines)

    def orm_execution(self, state):
        if not self.belongs(state.session) or not (state.is_insert or state.is_update):
            return
        statement = state.statement
        table = getattr(statement, "table", None)
        shapes = {}
        for plan in self.plans:
            if table is not None and plan.column.name in table.c and table.c[plan.column.name].shares_lineage(plan.column):
                if state.is_insert and getattr(statement, "select", None) is not None:
                    raise Failure("PROTECTED_INSERT_SELECT_NOT_ADMITTED")
                shapes[plan.crypto.identity] = (self.assignment_rhs(statement, plan.tenant), self.assignment_rhs(statement, plan.column))
        # The public ORM event precedes conversion to a Core DML statement.
        # Some converted statements cannot call values() again. Carry inspected
        # RHS nodes as internal execution metadata, never SQL text or an allowlist.
        if shapes:
            state.statement = statement.execution_options(cl_assignment_rhs=_DMLShapes(self._shape_token, shapes))

    def before_flush(self, session, context, instances):
        if not self.belongs(session):
            return
        connection = session.connection()
        session.info["cl_connections"] = [connection]
        for obj in list(session.new):
            if type(obj) in self.sequences:
                identity_column, _ = self.sequences[type(obj)]
                if getattr(obj, identity_column.key) is None:
                    setattr(obj, identity_column.key, self.reserve(connection, type(obj)))
        prepared = {}
        for plan in self.plans:
            for obj in session.new | session.dirty:
                if not isinstance(obj, plan.mapper.class_):
                    continue
                state = inspect(obj)
                if state.persistent and state.attrs[plan.identity.key].history.has_changes():
                    raise Failure("STABLE_RECORD_IDENTITY_REQUIRED")
                relationships = [relationship for relationship in plan.mapper.relationships if plan.tenant in relationship.local_columns]
                relationship_changed = any(state.attrs[relationship.key].history.has_changes() for relationship in relationships)
                tenant_changed = state.attrs[plan.tenant.key].history.has_changes() or relationship_changed
                if state.persistent and not tenant_changed and not state.attrs[plan.column.key].history.has_changes():
                    continue
                identity = getattr(obj, plan.identity.key)
                tenant = getattr(obj, plan.tenant.key)
                if tenant is None or relationship_changed:
                    if len(relationships) != 1:
                        raise Failure("TENANT_RELATIONSHIP_AMBIGUOUS")
                    parent = state.dict.get(relationships[0].key)
                    if parent is None:
                        raise Failure("COMPLETE_TENANT_CONTEXT_REQUIRED")
                    parent_mapper = inspect(type(parent))
                    tenant = getattr(parent, parent_mapper.primary_key[0].key)
                    setattr(obj, plan.tenant.key, tenant)
                value = getattr(obj, plan.column.key)
                if state.persistent and tenant_changed:
                    attributes.flag_modified(obj, plan.column.key)
                payload = seal(plan.crypto, self.provider, tenant, identity, value)
                prepared[(plan.mapper.local_table, identity)] = (tenant, value, None if payload is None else PreparedFrame(payload))
        connection.info["cl_prepared"] = prepared

    def clear(self, session, *args):
        if not self.belongs(session):
            return
        for connection in session.info.pop("cl_connections", []):
            if not connection.closed:
                connection.info.pop("cl_prepared", None)

    def predicate(self, node, parameters):
        plan = self.plan_for(node.column)
        value = node.value
        if isinstance(value, BindParameter):
            value = parameters.get(value.key, value.value)
        if isinstance(value, ColumnElement) or hasattr(value, "__clause_element__"):
            raise Failure("SHARED_JOIN_DOMAIN_UNQUALIFIED")
        tenants = self.provider.tenants()
        if not tenants:
            raise Failure("PREPARED_QUERY_SCOPE_REQUIRED")
        token_expression = func.substring(type_coerce(node.column, LargeBinary), 15, 32)
        tenant_expression = node.column.table.c[plan.tenant.name]
        expressions = []
        for tenant in tenants:
            if node.op in (operators.in_op, operators.not_in_op):
                if not isinstance(value, (list, tuple)) or len(value) > 10_000:
                    raise Failure("BOUNDED_MEMBERSHIP_REQUIRED")
                query = node.op(token_expression, [term(plan.crypto, self.provider, tenant, item) for item in value])
            else:
                query = node.op(token_expression, term(plan.crypto, self.provider, tenant, value))
            expressions.append(and_(tenant_expression == tenant, query))
        return or_(*expressions)

    def plan_for(self, column):
        for plan in self.plans:
            if hasattr(column, "shares_lineage") and column.shares_lineage(plan.column):
                return plan
        return None

    def assignment_rhs(self, statement, column):
        # Public generative probing: replacing one assignment removes its RHS
        # from get_children(). This handles computed SET values without a SQL
        # parser or access to SQLAlchemy's private value dictionaries.
        children = list(statement.get_children())
        for key in (column, column.name):
            probe = statement.values({key: bindparam("cl_assignment_probe")})
            remaining = Counter(id(node) for node in probe.get_children())
            removed = []
            for node in children:
                if remaining[id(node)]:
                    remaining[id(node)] -= 1
                else:
                    removed.append(node)
            if removed:
                if len(removed) != 1:
                    raise Failure("DML_ASSIGNMENT_SHAPE_UNQUALIFIED")
                return removed[0]
        return None

    def before_execute(self, connection, statement, multiparams, params, options):
        boundary = connection.connection.driver_connection
        if isinstance(boundary, BoundaryConnection) and not boundary._ready:
            return statement, multiparams, params
        def requested(clause, column):
            if isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
                values = [requested(child, column) for child in clause.clauses]
                return next((value for value in values if value is not None), None)
            if isinstance(clause, BinaryExpression) and clause.operator is operators.eq:
                for candidate, value in ((clause.left, clause.right), (clause.right, clause.left)):
                    if hasattr(candidate, "shares_lineage") and candidate.shares_lineage(column) and isinstance(value, BindParameter):
                        value = params.get(value.key, value.value)
                        return value if type(value) is int else None
            return None
        where = getattr(statement, "whereclause", None)
        points = {plan.crypto.identity: (requested(where, plan.identity), requested(where, plan.tenant))
                  for plan in self.plans} if getattr(statement, "is_select", False) else {}
        # The compiler freezes host expectations into each result processor.
        # A later query or streamed row cannot change an earlier processor's point.
        self.read_points.set(points)
        # The unit of work can supply its own documented compiled_cache option,
        # which overrides the engine option. Evict that supplied mapping through
        # the public event argument; never access or reset mapper private state.
        supplied_cache = options.get("compiled_cache")
        if supplied_cache is not None:
            supplied_cache.clear()
        nodes = list(visitors.iterate(statement))
        # SELECT DISTINCT compares randomized payloads, not logical values.
        # Public generative comparison also detects DISTINCT ON. Inspect nested
        # selects before rewriting, while protected column lineage is intact.
        if any(isinstance(node, Select) and node.compare(node.distinct()) and
               any(self.plan_for(child) is not None for child in
                   [*node.selected_columns, *visitors.iterate(node)])
               for node in nodes):
            raise Failure("PROTECTED_SELECT_DISTINCT_NOT_ADMITTED")
        if any(isinstance(node, TextClause) for node in nodes):
            raise Failure("OPAQUE_SQL_NOT_ADMITTED")
        if any(isinstance(node, ColumnClause) and node.is_literal for node in nodes):
            raise Failure("OPAQUE_COLUMN_NOT_ADMITTED")
        if any(isinstance(node, (Cast, TypeCoerce)) and
               any(self.plan_for(child) is not None for child in visitors.iterate(node)) for node in nodes):
            raise Failure("PROTECTED_CAST_NOT_ADMITTED")
        if getattr(statement, "is_ddl", False):
            raise Failure("DDL_NOT_ADMITTED_THROUGH_RUNTIME")
        # Public traversal: rewrite only the qualified predicate and COUNT DISTINCT shapes.
        def exact_tenant_predicate(clause, tenant_column):
            if isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
                return any(exact_tenant_predicate(child, tenant_column) for child in clause.clauses)
            if isinstance(clause, BinaryExpression) and clause.operator is operators.eq:
                for column, value in ((clause.left, clause.right), (clause.right, clause.left)):
                    if hasattr(column, "shares_lineage") and column.shares_lineage(tenant_column) and isinstance(value, BindParameter):
                        return type(params.get(value.key, value.value)) is int
            return False

        def replace(node):
            if isinstance(node, ProtectedPredicate):
                return self.predicate(node, params)
            if isinstance(node, BinaryExpression) and self.plan_for(node.left) is not None:
                if node.operator in (operators.is_, operators.is_not):
                    from sqlalchemy.sql.elements import Null
                    if not isinstance(node.right, Null):
                        raise Failure("ONLY_NULL_PRESENCE_ADMITTED")
                    return node.operator(type_coerce(node.left, LargeBinary), None)
                if node.operator not in (operators.eq, operators.ne, operators.in_op, operators.not_in_op):
                    raise Failure("QUERY_CAPABILITY_NOT_ADMITTED")
                return self.predicate(ProtectedPredicate(node.left, node.operator, node.right), params)
            if isinstance(node, BinaryExpression) and self.plan_for(node.right) is not None:
                if node.operator not in (operators.eq, operators.ne):
                    raise Failure("REVERSE_PROTECTED_OPERATOR_NOT_ADMITTED")
                return self.predicate(ProtectedPredicate(node.right, node.operator, node.left), params)
            if isinstance(node, FunctionElement):
                protected = [child for child in visitors.iterate(node) if self.plan_for(child) is not None]
                if protected:
                    if node.name.lower() == "distinct" and len(list(node.clauses)) == 1:
                        column = list(node.clauses)[0]
                        plan = self.plan_for(column)
                        if plan is None or not exact_tenant_predicate(getattr(statement, "whereclause", None), column.table.c[plan.tenant.name]):
                            raise Failure("SINGLE_TENANT_DISTINCT_REQUIRED")
                        return func.distinct(func.substring(type_coerce(column, LargeBinary), 15, 32))
                    if node.name.lower() != "count":
                        raise Failure("PROTECTED_FUNCTION_NOT_ADMITTED")
            return None
        # Inspect assignments on the original public AST. Predicate traversal
        # can change ORM plugin annotations on a Core-executed mapped UPDATE.
        assignment_statement = statement
        statement = visitors.replacement_traverse(statement, {}, replace)
        if hasattr(statement, "get_children") and getattr(statement, "is_select", False):
            # Native selected entities stay intact; inspect public child roles.
            selected = list(getattr(statement, "selected_columns", []))
            where = getattr(statement, "whereclause", None)
            where_nodes = list(visitors.iterate(where)) if where is not None else []
            from_nodes = [node for relation in statement.get_final_froms() for node in visitors.iterate(relation)]
            for child in statement.get_children():
                if any(child is candidate for candidate in where_nodes + from_nodes):
                    continue
                matching = next((index for index, column in enumerate(selected) if child.compare(column)), None)
                if matching is not None:
                    selected.pop(matching)
                    continue
                if any(self.plan_for(node) is not None for node in visitors.iterate(child)):
                    raise Failure("PROTECTED_CLAUSE_NOT_ADMITTED")
        table = getattr(statement, "table", None)
        # ORM bulk statements annotate their target table. Match public column
        # lineage, rather than Python object identity, for the same mapped table.
        plans = [plan for plan in self.plans if table is not None
                 and plan.column.name in table.c
                 and table.c[plan.column.name].shares_lineage(plan.column)]
        if not plans or not (getattr(statement, "is_insert", False) or getattr(statement, "is_update", False)):
            return statement, multiparams, params
        if getattr(statement, "is_insert", False) and getattr(statement, "select", None) is not None:
            raise Failure("PROTECTED_INSERT_SELECT_NOT_ADMITTED")
        assignments = {}
        metadata = options.get("cl_assignment_rhs")
        if metadata is not None and (not isinstance(metadata, _DMLShapes) or metadata.token is not self._shape_token):
            raise Failure("DML_EXECUTION_METADATA_NOT_ADMITTED")
        for plan in plans:
            inspected = metadata.values.get(plan.crypto.identity) if metadata is not None else None
            if inspected is None:
                inspected = (self.assignment_rhs(assignment_statement, plan.tenant), self.assignment_rhs(assignment_statement, plan.column))
            tenant_rhs, rhs = inspected
            if getattr(statement, "is_update", False) and tenant_rhs is not None and not isinstance(tenant_rhs, BindParameter):
                raise Failure("COMPUTED_TENANT_ASSIGNMENT_NOT_ADMITTED")
            from sqlalchemy.sql.elements import Null
            if rhs is not None and not isinstance(rhs, (BindParameter, Null)):
                raise Failure("PROTECTED_SQL_ASSIGNMENT_NOT_ADMITTED")
            assignments[plan.crypto.identity] = rhs
        original_statement = statement
        named_binds = {node.key for node in visitors.iterate(statement) if isinstance(node, BindParameter) and not node.unique}
        changed = []
        for supplied in (list(multiparams) if multiparams else [params]):
            row = dict(supplied)
            # Match SQLAlchemy's execution-time column set. Compiling a generic
            # UPDATE without column_keys invents NULL placeholders for columns
            # the unit of work is not writing.
            compiled_values = original_statement.compile(dialect=self.engine.dialect, column_keys=list(row)).params
            if getattr(statement, "is_insert", False) and any(key not in table.c and key not in named_binds for key in compiled_values):
                raise Failure("PROTECTED_INSERT_PARAMETER_SHAPE_UNQUALIFIED")
            for plan in plans:
                if getattr(statement, "is_update", False) and plan.identity.name in compiled_values:
                    raise Failure("STABLE_RECORD_IDENTITY_REQUIRED")
                if not getattr(statement, "is_insert", False) and plan.tenant.name in compiled_values:
                    preparation = connection.info.get("cl_prepared", {})
                    if not preparation:
                        raise Failure("UNPREPARED_TENANT_UPDATE_NOT_ADMITTED")
                rhs = assignments[plan.crypto.identity]
                if plan.column.name not in row and plan.column.name not in compiled_values and rhs is None:
                    continue
                identity = row.get(plan.identity.name)
                if getattr(statement, "is_insert", False) and identity is None:
                    identity = self.reserve(connection, plan.mapper.class_)
                    row[plan.identity.name] = identity
                if identity is None and getattr(statement, "whereclause", None) is not None:
                    for node in visitors.iterate(statement.whereclause):
                        if getattr(node, "operator", None) is operators.eq and hasattr(node, "left") and node.left.compare(plan.identity) and isinstance(node.right, BindParameter):
                            identity = row.get(node.right.key, node.right.value)
                value = row.get(plan.column.name, compiled_values.get(plan.column.name))
                if isinstance(rhs, BindParameter):
                    if rhs.required and rhs.key not in row:
                        raise Failure("REQUIRED_PROTECTED_BIND_MISSING")
                    value = row.get(rhs.key, rhs.value) if plan.column.name not in row else row[plan.column.name]
                preparation = connection.info.get("cl_prepared", {}).get((plan.mapper.local_table, identity))
                if preparation is not None:
                    tenant, original, payload = preparation
                    if value != original:
                        raise Failure("PREPARED_VALUE_CHANGED")
                    if plan.tenant.name in row and row[plan.tenant.name] != tenant:
                        raise Failure("PREPARED_TENANT_CHANGED")
                elif getattr(statement, "is_insert", False):
                    tenant = row.get(plan.tenant.name, compiled_values.get(plan.tenant.name))
                    if tenant is None:
                        raise Failure("COMPLETE_BULK_TENANT_REQUIRED")
                    sealed = seal(plan.crypto, self.provider, tenant, identity, value)
                    payload = None if sealed is None else PreparedFrame(sealed)
                else:
                    if type(identity) is not int:
                        raise Failure("PROTECTED_BULK_UPDATE_CONTEXT_UNQUALIFIED")
                    # The exact point is a host input. Lock its public tenant
                    # context in this transaction before preparing its payload.
                    current = connection.execute(select(plan.tenant).where(plan.identity == identity).with_for_update()).first()
                    if current is None:
                        payload = None  # zero-row UPDATE; no plaintext parameter
                    else:
                        tenant = current[0]
                        sealed = seal(plan.crypto, self.provider, tenant, identity, value)
                        payload = None if sealed is None else PreparedFrame(sealed)
                row[plan.column.name] = payload
                if isinstance(rhs, BindParameter) and rhs.key in row:
                    row[rhs.key] = payload
            changed.append(row)
        return (statement, changed, {}) if multiparams else (statement, [], changed[0])

    def detach(self):
        for target, name, callback in reversed(self.listeners):
            event.remove(target, name, callback)
        self.listeners.clear()
        for engine in self.runtime_engines:
            engine.dispose()
            engine.clear_compiled_cache()
        for plan in self.plans:
            plan.column.type = plan.original_type


def attach(registry, engine, manifest, *, provider, physical_schema, local_mode=False, writer_inventory=None):
    attachment = Attachment(registry, engine, manifest, provider, physical_schema, local_mode, writer_inventory)
    attachment.protect_existing()
    attachment.install()
    return attachment
