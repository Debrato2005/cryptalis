"""Bounded text storage and equality through public SQLAlchemy hooks.

The host supplies a trusted lock and authenticated tenant scope. This module
does not migrate schemas or qualify external writers. Research prototype.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from hashlib import sha256
import json
from uuid import UUID

from sqlalchemy import BigInteger, LargeBinary, Text, Uuid, event, func, inspect, type_coerce
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, AsyncSessionTransaction
from sqlalchemy.orm import Session, registry
from sqlalchemy.orm.attributes import NO_VALUE
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, BooleanClauseList, Cast, ColumnClause, Grouping, Label, TextClause, UnaryExpression
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.sql.selectable import Alias, CTE, FromClause, Select, Join, Subquery
from sqlalchemy.sql.dml import Insert, Update, Delete
from sqlalchemy.types import JSON, NullType, TypeDecorator

from ._sqlalchemy_guard import install_guard
from ._sqlalchemy_search import rewrite_search, search_shape, validate_search_storage
from .crypto import CryptoFailure, AuthenticationFailed, FieldDescriptor, Keyring, KeyUnavailable, MAX_TEXT_BYTES, open_text, seal_text
from .manifest.parser import decode_manifest_json


class UnsupportedProtectedOperation(CryptoFailure):
    stage = "SQLAlchemy admission"
    remedy = "Use the attached factory, ordinary ORM writes, direct projections, and declared equality/IN with ordinary text binds. Remove unsupported SQL or bind codecs."


class PolicyMismatch(CryptoFailure):
    stage = "attachment validation"
    remedy = "Check the trusted lock, bytea target, search index/check, tenant key policy, mapping, and guarded engine configuration. Attach before application use."


@dataclass(frozen=True)
class _Binding:
    column: object
    attribute: str
    descriptor: FieldDescriptor
    record: object
    record_attribute: str
    tenant: object | None
    tenant_attribute: str | None
    model: type


@dataclass(frozen=True)
class _Sealed:
    body: bytes | None = field(repr=False)
    permit: object = field(repr=False)
    binding: _Binding = field(repr=False)


@dataclass
class _Operation:
    owner: object
    keys: object = field(repr=False)
    tenant: UUID
    session: object
    flushing: bool = False
    prepared: dict = field(default_factory=dict, repr=False)
    rows: dict = field(default_factory=dict, repr=False)
    points: tuple = ()
    search_nodes: list = field(default_factory=list, repr=False)
    search_identities: dict = field(default_factory=dict, repr=False)
    parameters: dict = field(default_factory=dict, repr=False)

    def generated(self, node):
        if self.search_identities.get(id(node)) is node:
            return True
        for permitted in self.search_nodes:
            if isinstance(node, type(permitted)) and node.compare(permitted):
                # Keep the reference alive until the operation ends; an object
                # ID alone could be reused after garbage collection.
                self.search_identities[id(node)] = node
                return True
        return False


_operation = ContextVar("cryptalis_sqlalchemy_operation", default=None)


class _ReadText(TypeDecorator):
    impl = JSON
    cache_ok = False

    def __init__(self, binding, operation, record_column):
        super().__init__()
        self.binding = binding
        self.keys = operation.keys
        self.tenant = operation.tenant
        self.points = tuple(value for column, value in operation.points if column.compare(record_column))

    def process_result_value(self, value, dialect):
        if type(value) is not list or len(value) != 3:
            raise AuthenticationFailed()
        payload, record, tenant = value
        descriptor = self.binding.descriptor
        if record is None:
            valid_null_scope = (tenant is None if descriptor.tenant_codec == "uuid16/v1" else
                                tenant == str(descriptor.table_id) == str(self.tenant))
            if payload is not None or not valid_null_scope:
                raise AuthenticationFailed()
            return None  # Native NULL side of an outer join.
        try:
            if descriptor.record_codec == "uuid16/v1":
                record = UUID(record)
            elif type(record) is not int:
                raise AuthenticationFailed()
            tenant = UUID(tenant)
            if tenant != self.tenant or any(
                    record not in expected if isinstance(expected, frozenset) else record != expected
                    for expected in self.points):
                raise AuthenticationFailed()
            if payload is not None:
                if type(payload) is not str or len(payload) > 2 * (MAX_TEXT_BYTES + 74):
                    raise AuthenticationFailed()
                payload = bytes.fromhex(payload)
        except CryptoFailure:
            raise
        except Exception:
            raise AuthenticationFailed() from None
        return open_text(payload, descriptor, tenant, record, self.keys)


class _Payload(TypeDecorator):
    impl = LargeBinary
    # Protected projections capture an operation's keys. They MUST be compiled
    # afresh. Native unprotected statements can still use the engine cache.
    cache_ok = False

    def __init__(self, binding, owner):
        super().__init__()
        self.binding, self.owner = binding, owner

    def process_bind_param(self, value, dialect):
        operation = _operation.get()
        if (not isinstance(value, _Sealed) or operation is None or value.permit is not operation or
                value.binding is not self.binding or not operation.flushing):
            raise UnsupportedProtectedOperation()
        return value.body

    def process_result_value(self, value, dialect):
        # Raw bytea is never a public protected result.
        raise UnsupportedProtectedOperation()

    def column_expression(self, column):
        operation = _operation.get()
        if operation is None or operation.owner is not self.owner:
            raise UnsupportedProtectedOperation()
        original = column
        while isinstance(original, Label):
            original = original.element
        table = getattr(original, "table", None)
        if table is None or self.binding.record.key not in table.c:
            raise UnsupportedProtectedOperation()
        record = table.c[self.binding.record.key]
        if self.binding.tenant is not None:
            if self.binding.tenant.key not in table.c:
                raise UnsupportedProtectedOperation()
            tenant = table.c[self.binding.tenant.key]
        else:
            tenant = str(self.binding.descriptor.table_id)
        packed = func.pg_catalog.jsonb_build_array(
            func.pg_catalog.encode(type_coerce(column, LargeBinary()), "hex"), record, tenant)
        return type_coerce(packed, _ReadText(self.binding, operation, record))


def _protected(expression):
    return any(isinstance(getattr(node, "type", None), _Payload) for node in visitors.iterate(expression))


def _points(statement, parameters):
    """Capture row constraints before SQL; never let absent bind data waive one.

    A callable default, transformed identity, or compiler-specific override is
    outside this bounded grammar. Explicit public binds remain native values.
    IN captures the admitted set, including relationship-loader batches.
    """
    result = []
    inputs = {}
    for node in visitors.iterate(statement):
        if isinstance(node, BindParameter):
            inputs.setdefault(node.key, {})[id(node)] = node

    def ungroup(expression):
        while isinstance(expression, Grouping):
            expression = expression.element
        return expression

    def primary(expression):
        return any(isinstance(node, ColumnClause) and node.primary_key
                   for node in visitors.iterate(expression))

    def value_of(bind, column):
        if (type(column.type) not in (Uuid, BigInteger) or
                type(bind.type) not in (type(column.type), NullType) or
                any(type(other.type) not in (type(column.type), NullType)
                    for other in inputs[bind.key].values()) or
                isinstance(statement, Select) and any(key not in inputs for key in parameters)):
            raise UnsupportedProtectedOperation()
        if bind.key in parameters:
            value = parameters[bind.key]
        else:
            if bind.callable is not None or bind.required or len(inputs[bind.key]) != 1:
                raise UnsupportedProtectedOperation()
            value = bind.value
        # Other occurrences of this placeholder can change its compiled
        # semantics. Refuse callable collisions even if this occurrence is plain.
        if bind.key not in parameters and any(other.callable is not None for other in inputs[bind.key].values()):
            raise UnsupportedProtectedOperation()
        values = value if bind.expanding else [value]
        if not isinstance(values, (list, tuple)):
            raise UnsupportedProtectedOperation()
        expected_type = UUID if type(column.type) is Uuid else int
        if any(item is not None and type(item) is not expected_type for item in values):
            raise UnsupportedProtectedOperation()
        return frozenset(item for item in values if item is not None) if bind.expanding else value

    def visit(expression):
        expression = ungroup(expression)
        if isinstance(expression, BooleanClauseList) and expression.operator is operators.and_:
            for clause in expression.clauses:
                visit(clause)
            return
        if not primary(expression):
            return
        if isinstance(expression, BinaryExpression) and expression.operator in (operators.eq, operators.in_op):
            left, right = ungroup(expression.left), ungroup(expression.right)
            if isinstance(left, BindParameter):
                left, right = right, left
            if (isinstance(left, ColumnClause) and left.primary_key and isinstance(right, BindParameter) and
                    right.expanding == (expression.operator is operators.in_op)):
                result.append((left, value_of(right, left)))
                return
        # A primary-key predicate cannot silently lose requested-row validation.
        # Tuple, OR, cast/function, subquery, and opaque forms need admission.
        raise UnsupportedProtectedOperation()
    if statement.whereclause is not None:
        visit(statement.whereclause)
    if isinstance(statement, Select):
        where_nodes = {id(node) for node in visitors.iterate(statement.whereclause)} if statement.whereclause is not None else set()
        for node in visitors.iterate(statement):
            if (isinstance(node, BinaryExpression) and id(node) not in where_nodes and primary(node) and
                    any(isinstance(child, BindParameter) for child in visitors.iterate(node))):
                # ON and HAVING are not unconditional WHERE constraints. Do not
                # drop them or turn an outer join's nullable side into a point.
                raise UnsupportedProtectedOperation()
    return tuple(result)


class _Attachment:
    def __init__(self, mapping, engine, document, keys, deployment=None):
        self.mapping, self.engine, self.document, self.keys = mapping, engine, document, keys
        self.deployment = deployment
        self.bindings = []
        self.models = {}
        self.fingerprint = ()
        self.search_pins = {}

    def protected(self, expression):
        # ORM annotations can retain a native type from mapping construction.
        # Stable column lineage is authoritative, not a mutable type hint.
        return any(isinstance(node, ColumnClause) and any(node.shares_lineage(b.column) for b in self.bindings)
                   for node in visitors.iterate(expression))

    def _ring(self, tenant):
        if not isinstance(tenant, UUID):
            raise PolicyMismatch()
        try:
            ring = self.keys if isinstance(self.keys, Keyring) else self.keys(tenant)
        except Exception:
            raise KeyUnavailable() from None
        if (not isinstance(ring, Keyring) or ring.policy.tenant_id != tenant or
                str(ring.policy.domain_id) != self.document["domain_id"]):
            raise PolicyMismatch()
        if self.deployment is not None:
            from cryptalis.migration import _policy
            plan, _ = self.deployment
            if _policy(ring) != plan.document["key_policies"].get(str(tenant)):
                raise PolicyMismatch()
        if any(binding.descriptor.equality for binding in self.bindings):
            roots = [wrapper for wrapper in ring.policy.wrappers if wrapper.context.purpose == "search"]
            if len(roots) != 1 or roots[0].context.generation != ring.policy.search_generation:
                raise PolicyMismatch()
            root = roots[0]
            pin = (root.provider_id, root.context, sha256(root.sealed).digest())
            if self.search_pins.setdefault(tenant, pin) != pin:
                raise PolicyMismatch()
        return ring

    def prepare(self, tenant):
        return self._ring(tenant).prepare()

    async def prepare_async(self, tenant):
        return await self._ring(tenant).prepare_async()

    def validate(self, connection):
        from cryptalis.migration import check_attachment
        check_attachment(connection, json.dumps(self.document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(), self.deployment)
        if connection.dialect.name != "postgresql" or connection.dialect.driver != "psycopg":
            raise PolicyMismatch()
        if (connection.get_execution_options().get("schema_translate_map") or
                int(connection.exec_driver_sql("show server_version_num").scalar_one()) // 10000 != 16 or
                connection.exec_driver_sql("show server_encoding").scalar_one() != "UTF8"):
            raise PolicyMismatch()
        native = inspect(connection)
        for model in self.document["models"]:
            mappers = [m for m in self.mapping.mappers if m.class_.__name__ == model["model"]]
            if len(mappers) != 1:
                raise PolicyMismatch()
            mapper = mappers[0]
            table = mapper.local_table
            if (mapper.inherits is not None or mapper.persist_selectable is not table or table.name != model["table"] or
                    table.schema not in (None, model["schema"]) or len(mapper.primary_key) != 1):
                raise PolicyMismatch()
            columns = {c["name"]: c for c in native.get_columns(model["table"], schema=model["schema"])}
            record = table.c[model["record"]["column"]]
            tenant = table.c[model["tenancy"]["column"]] if "column" in model["tenancy"] else None
            codec_type = {"uuid16/v1": Uuid, "int64-be/v1": BigInteger}[model["record"]["codec"]]
            if (mapper.primary_key != (record,) or
                    native.get_pk_constraint(model["table"], schema=model["schema"])["constrained_columns"] != [record.name] or
                    not isinstance(record.type, codec_type) or not isinstance(columns[record.name]["type"], codec_type)):
                raise PolicyMismatch()
            for column in (record, tenant):
                if column is None:
                    continue
                actual = columns[column.name]
                generated_default = column.default is not None and not (column.default.is_callable or column.default.is_scalar)
                if (column.nullable or actual["nullable"] or generated_default or column.server_default is not None or
                        column.onupdate is not None or column.server_onupdate is not None or actual.get("default") is not None or
                        actual.get("identity") is not None or actual.get("computed") is not None):
                    raise PolicyMismatch()
                if isinstance(column.type, Uuid) and not column.type.as_uuid:
                    raise PolicyMismatch()
            if tenant is not None and (not isinstance(tenant.type, Uuid) or not isinstance(columns[tenant.name]["type"], Uuid)):
                raise PolicyMismatch()
            for field in model["fields"]:
                column = table.c[field["column"]]
                actual = columns[field["column"]]
                if (not isinstance(actual["type"], LargeBinary) or not isinstance(column.type, Text) or
                        actual["nullable"] != field["source"]["nullable"] or column.nullable != actual["nullable"] or
                        column.default is not None or column.server_default is not None or column.onupdate is not None or
                        column.server_onupdate is not None or actual.get("default") is not None or actual.get("computed") is not None):
                    raise PolicyMismatch()
                if field["queries"]:
                    if (not isinstance(field["queries"], list) or not field["queries"] or
                            not set(field["queries"]) <= {"equality", "unique"}):
                        raise PolicyMismatch()
                    validate_search_storage(connection, model, field)
                descriptor = FieldDescriptor.from_compiled(field["descriptor"], field["descriptor_digest"])
                if (str(descriptor.domain_id), str(descriptor.table_id), str(descriptor.field_id)) != (
                        self.document["domain_id"], model["table_id"], field["field_id"]):
                    raise PolicyMismatch()
                if (descriptor.record_codec != model["record"]["codec"] or
                        descriptor.tenant_codec != ("uuid16/v1" if tenant is not None else "single-tenant-uuid/v1") or
                        descriptor.representation != field["representation"] or descriptor.equality != bool(field["queries"])):
                    raise PolicyMismatch()
                binding = _Binding(column, mapper.get_property_by_column(column).key, descriptor,
                                   record, mapper.get_property_by_column(record).key, tenant,
                                   mapper.get_property_by_column(tenant).key if tenant is not None else None, mapper.class_)
                self.bindings.append(binding)
            self.models[mapper.class_] = tuple(b for b in self.bindings if b.model is mapper.class_)

    def activate(self):
        engine = self.engine.sync_engine if isinstance(self.engine, AsyncEngine) else self.engine
        if engine.echo or not engine.hide_parameters or engine.pool.checkedout():
            raise PolicyMismatch()
        self.mapping.configure()
        for binding in self.bindings:
            # Freeze physical schema resolution, including initially unqualified
            # mappings. Existing FK columns are already resolved by configure().
            model = next(m for m in self.document["models"] if m["model"] == binding.model.__name__)
            binding.column.table.schema = model["schema"]
            binding.column.type = _Payload(binding, self)
        self.fingerprint = self._fingerprint()
        engine.clear_compiled_cache()
        install_guard(engine, UnsupportedProtectedOperation, self.before_execute, self.check_cursor)
        native_compiler = engine.dialect.statement_compiler
        class StorageCompiler(native_compiler):
            def get_select_precolumns(compiler, select, **kw):
                modifier = super().get_select_precolumns(select, **kw)
                # PostgreSQL's public compiler hook emits only DISTINCT here.
                # Check its modifier, not arbitrary user SQL text.
                if modifier and (any(self.protected(c) for c in select.selected_columns) or self.protected(select)):
                    raise UnsupportedProtectedOperation()
                return modifier
        engine.dialect.statement_compiler = StorageCompiler

    def _fingerprint(self):
        def column(c):
            if c is None:
                return None
            return (c.name, c.key, c.type, c.nullable, c.primary_key, c.default, c.server_default,
                    c.onupdate, c.server_onupdate, c.identity, c.computed,
                    c.type.as_uuid if isinstance(c.type, Uuid) else None)
        try:
            return tuple((b.column.table.schema, b.column.table.name, column(b.column), column(b.record), column(b.tenant),
                          inspect(b.model).primary_key, inspect(b.model).get_property_by_column(b.column).key,
                          b.column.type.binding, b.column.type.owner) for b in self.bindings)
        except Exception:
            raise PolicyMismatch() from None

    def _check(self):
        engine = self.engine.sync_engine if isinstance(self.engine, AsyncEngine) else self.engine
        if (self._fingerprint() != self.fingerprint or engine.echo or not engine.hide_parameters or
                engine.get_execution_options().get("schema_translate_map")):
            raise PolicyMismatch()
        operation = _operation.get()
        if operation is None or operation.owner is not self:
            raise UnsupportedProtectedOperation()
        return operation

    def admit(self, statement, flushing=False):
        if flushing and isinstance(statement, (Insert, Update, Delete)):
            return
        if not isinstance(statement, Select):
            raise UnsupportedProtectedOperation()
        safe_count_stars = set()
        for node in visitors.iterate(statement):
            operation = _operation.get()
            generated = operation is not None and operation.owner is self and operation.generated(node)
            if generated:
                continue
            if isinstance(node, FunctionElement) and node.name == "count":
                arguments = list(node.clauses)
                if len(arguments) == 1 and isinstance(arguments[0], ColumnClause) and arguments[0].name == "*":
                    safe_count_stars.add(id(arguments[0]))
        for node in visitors.iterate(statement):
            if isinstance(node, TextClause):
                raise UnsupportedProtectedOperation()
            if isinstance(node, Join) and self.protected(node.onclause):
                raise UnsupportedProtectedOperation()
            operation = _operation.get()
            if operation is not None and operation.owner is self and operation.generated(node):
                continue
            if isinstance(node, ColumnClause) and node.is_literal and id(node) not in safe_count_stars:
                raise UnsupportedProtectedOperation()
            if isinstance(node, ColumnClause) and id(node) not in safe_count_stars:
                table = node.table
                source = table
                while isinstance(source, Alias):
                    source = source.element
                if isinstance(source, (Subquery, CTE)) and self.protected(node):
                    raise UnsupportedProtectedOperation()
                if table is None:
                    raise UnsupportedProtectedOperation()
                for binding in self.bindings:
                    target = binding.column.table
                    for origin in node.base_columns:
                        physical = getattr(origin, "table", None)
                        if (physical is not None and origin.name == binding.column.name and physical.name == target.name and
                                physical.schema in (None, target.schema) and not origin.shares_lineage(binding.column)):
                            raise UnsupportedProtectedOperation()
            if self.protected(node) and not isinstance(node, (Select, FromClause, ColumnClause, Label)):
                boolean = isinstance(node, BooleanClauseList) and node.operator in (operators.and_, operators.or_)
                if not boolean and search_shape(self, node) is None:
                    raise UnsupportedProtectedOperation()
            if isinstance(node, Select):
                # ORM join predicates appear as direct public children before
                # they become Join objects. Consume only WHERE/projection
                # occurrences; an additional protected ON occurrence refuses.
                eligible = list(node.selected_columns)
                children = tuple(node.get_children())
                where = node.whereclause
                if where is not None:
                    # Multiple .where() criteria form a new AND wrapper. Its
                    # direct clauses are the SELECT children; descendants of
                    # an explicit AND/OR must never become spare ON permits.
                    def ungroup(expression):
                        while isinstance(expression, Grouping):
                            expression = expression.element
                        return expression
                    root = ungroup(where)
                    if any(root is child for child in children):
                        eligible.append(root)
                    elif isinstance(root, BooleanClauseList) and root.operator is operators.and_:
                        eligible.extend(ungroup(clause) for clause in root.clauses)
                    elif self.protected(root):
                        raise UnsupportedProtectedOperation()
                    predicates = [where]
                    while predicates:
                        predicate = predicates.pop()
                        predicate = ungroup(predicate)
                        if operation is not None and operation.owner is self and operation.generated(predicate):
                            continue
                        if isinstance(predicate, BooleanClauseList) and predicate.operator in (operators.and_, operators.or_):
                            predicates.extend(predicate.clauses)
                        elif self.protected(predicate) and search_shape(self, predicate) is None:
                            raise UnsupportedProtectedOperation()
                for child in children:
                    if self.protected(child) and not isinstance(child, FromClause):
                        match = next((i for i, allowed in enumerate(eligible) if child is allowed), None)
                        if match is None:
                            raise UnsupportedProtectedOperation()
                        eligible.pop(match)
                remaining = list(node.order_by(None).group_by(None).get_children())
                for child in node.get_children():
                    match = next((i for i, candidate in enumerate(remaining) if child is candidate or child.compare(candidate)), None)
                    if match is not None:
                        remaining.pop(match)
                        continue
                    textual = getattr(child, "element", None)
                    labeled = type(textual) is str and any(c.key == textual and self.protected(c) for c in node.selected_columns)
                    if self.protected(child) or labeled:
                        raise UnsupportedProtectedOperation()

    def prepare_rows(self, session, operation):
        for obj in tuple(session.new) + tuple(session.dirty) + tuple(session.deleted):
            bindings = self.models.get(type(obj))
            if not bindings:
                continue
            state = inspect(obj)
            first = bindings[0]
            if state.persistent and (state.attrs[first.record_attribute].history.has_changes() or
                                    first.tenant_attribute is not None and state.attrs[first.tenant_attribute].history.has_changes()):
                raise UnsupportedProtectedOperation()
            record = state.attrs[first.record_attribute].loaded_value
            tenant = state.attrs[first.tenant_attribute].loaded_value if first.tenant is not None else first.descriptor.table_id
            if state.persistent:
                if record is NO_VALUE:
                    record = state.identity[0]
                if tenant is NO_VALUE:
                    # Native expiration reloads context within the flush's
                    # greenlet on async paths; never infer tenant from the host.
                    tenant = getattr(obj, first.tenant_attribute)
            if record is NO_VALUE or record is None or tenant is NO_VALUE:
                raise UnsupportedProtectedOperation()
            if tenant != operation.tenant:
                raise AuthenticationFailed()
            operation.rows[(first.column.table.schema, first.column.table.name, record)] = tenant
            if obj in session.deleted:
                continue
            for binding in bindings:
                attribute = state.attrs[binding.attribute]
                if state.persistent and not attribute.history.has_changes():
                    continue
                value = attribute.loaded_value
                if value is NO_VALUE:
                    value = None if state.pending and binding.column.nullable else NO_VALUE
                if value is NO_VALUE:
                    raise UnsupportedProtectedOperation()
                body = seal_text(value, binding.descriptor, tenant, record, operation.keys)
                operation.prepared[(binding.column.table.schema, binding.column.table.name, record, binding.column.key)] = (value, _Sealed(body, operation, binding))

    def before_execute(self, connection, statement, multiparams, params, execution_options):
        operation = self._check()
        if execution_options.get("schema_translate_map"):
            raise PolicyMismatch()
        self.admit(statement, operation.flushing)
        if isinstance(statement, (Insert, Update)):
            groups = multiparams if multiparams else [params]
            changed = []
            bindings = [b for b in self.bindings if b.column.table.name == statement.table.name and b.column.table.schema == statement.table.schema]
            for group in groups:
                output = dict(group)
                if bindings:
                    first = bindings[0]
                    if isinstance(statement, Insert):
                        record = output.get(first.record.key)
                    else:
                        points = _points(statement, output)
                        matches = [value for column, value in points if column.shares_lineage(first.record)]
                        if len(matches) != 1:
                            raise UnsupportedProtectedOperation()
                        record = matches[0]
                    if (statement.table.schema, statement.table.name, record) not in operation.rows:
                        raise UnsupportedProtectedOperation()
                    for binding in bindings:
                        if binding.column.key not in output:
                            continue
                        prepared = operation.prepared.get((statement.table.schema, statement.table.name, record, binding.column.key))
                        if prepared is None or output[binding.column.key] != prepared[0]:
                            raise UnsupportedProtectedOperation()
                        output[binding.column.key] = prepared[1]
                changed.append(output)
            return statement, changed if multiparams else [], {} if multiparams else changed[0]
        return statement, multiparams, params

    def check_cursor(self, context):
        operation = self._check()
        if context.compiled is None:
            raise UnsupportedProtectedOperation()
        self.admit(context.compiled.statement, operation.flushing)


class _Session(Session):
    def __init__(self, *args, _owner, tenant_id, _asynchronous=False, **kwargs):
        super().__init__(*args, **kwargs)
        self._owner, self._tenant, self._asynchronous = _owner, tenant_id, _asynchronous
        self._prepared = None

    def _keys(self):
        if self._asynchronous:
            if self._prepared is None:
                raise KeyUnavailable()
            return self._prepared
        return self._owner.prepare(self._tenant)

    def flush(self, objects=None):
        if not (self.new or self.dirty or self.deleted):
            return super().flush(objects)
        operation = _Operation(self._owner, self._keys(), self._tenant, self, flushing=True)
        token = _operation.set(operation)
        try:
            return super().flush(objects)
        finally:
            operation.prepared.clear()
            operation.rows.clear()
            _operation.reset(token)


@event.listens_for(_Session, "before_flush")
def _before_flush(session, context, instances):
    operation = _operation.get()
    if operation is None or operation.session is not session:
        raise UnsupportedProtectedOperation()
    session._owner.prepare_rows(session, operation)


@event.listens_for(_Session, "do_orm_execute", retval=True)
def _execute(state):
    session = state.session
    session._owner.admit(state.statement)
    parameters = state.parameters if isinstance(state.parameters, dict) else {}
    protected_read = any(session._owner.protected(c) for c in state.statement.selected_columns)
    operation = _Operation(session._owner, session._keys(), session._tenant, session,
                           points=_points(state.statement, parameters) if protected_read else (), parameters=parameters)
    if protected_read or session._owner.protected(state.statement):
        # Entity SELECT cache keys can name the Table without its column types.
        # Disable the ORM's cache too, so no compiled processor retains another
        # operation's tenant, requested point or prepared material.
        state.update_execution_options(compiled_cache=None)
    token = _operation.set(operation)
    try:
        state.statement = rewrite_search(session._owner, state.statement, operation)
        return state.invoke_statement()
    finally:
        _operation.reset(token)


class _AsyncTransaction(AsyncSessionTransaction):
    async def start(self, is_ctxmanager=False):
        await self.session._prepare()
        return await super().start(is_ctxmanager)

    async def __aexit__(self, *args):
        if args[0] is None:
            await self.session._prepare()
        return await super().__aexit__(*args)

    async def commit(self):
        await self.session._prepare()
        return await super().commit()


class _AsyncSession(AsyncSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, sync_session_class=_Session, _asynchronous=True, **kwargs)

    async def _prepare(self):
        session = self.sync_session
        session._prepared = await session._owner.prepare_async(session._tenant)

    def begin(self):
        return _AsyncTransaction(self)

    def begin_nested(self):
        return _AsyncTransaction(self, nested=True)


def _async_method(name):
    native = getattr(AsyncSession, name)
    @wraps(native)
    async def method(self, *args, **kwargs):
        await self._prepare()
        return await native(self, *args, **kwargs)
    return method


for _name in ("execute", "scalar", "scalars", "stream", "stream_scalars", "get", "get_one", "flush", "commit", "refresh", "merge", "delete", "run_sync"):
    setattr(_AsyncSession, _name, _async_method(_name))


class _Factory:
    def __init__(self, owner):
        self._owner = owner

    def __call__(self, *, tenant_id, **options):
        if any(k in options for k in ("bind", "binds", "class_", "sync_session_class", "_owner", "_asynchronous")):
            raise UnsupportedProtectedOperation()
        self._owner._ring(tenant_id)
        cls = _AsyncSession if isinstance(self._owner.engine, AsyncEngine) else _Session
        return cls(bind=self._owner.engine, _owner=self._owner, tenant_id=tenant_id, **options)


def attach(mapping: registry, engine: Engine | AsyncEngine, *, lock: bytes, keys, deployment=None):
    """Attach an already protected target. Await this call for an AsyncEngine.

    Schema transition is not performed. The host authenticates the lock and the
    tenant passed to the returned factory. Only ORM flush writes are admitted.
    """
    try:
        document = decode_manifest_json(lock)
        if (not isinstance(mapping, registry) or not isinstance(engine, (Engine, AsyncEngine)) or
                document["schema"] != "cryptalis.lock/v1" or document["profile"] != "cf1"):
            raise PolicyMismatch()
        owner = _Attachment(mapping, engine, document, keys, deployment)
    except Exception:
        raise PolicyMismatch() from None
    if isinstance(engine, AsyncEngine):
        async def asynchronous():
            try:
                if engine.sync_engine.pool.checkedout():
                    raise PolicyMismatch()
                async with engine.connect() as connection:
                    await connection.run_sync(owner.validate)
                await engine.dispose()
                owner.activate()
                return _Factory(owner)
            except CryptoFailure:
                raise
            except Exception:
                raise PolicyMismatch() from None
        return asynchronous()
    try:
        if engine.pool.checkedout():
            raise PolicyMismatch()
        with engine.connect() as connection:
            owner.validate(connection)
        engine.dispose()
        owner.activate()
        return _Factory(owner)
    except CryptoFailure:
        raise
    except Exception:
        raise PolicyMismatch() from None
