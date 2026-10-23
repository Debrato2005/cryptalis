"""Bounded text storage and equality through public SQLAlchemy hooks.

The host supplies a trusted lock and authenticated tenant scope. This module
does not migrate schemas or qualify external writers. Research prototype.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from hashlib import sha256
import json
from types import MappingProxyType, MethodType
from uuid import UUID

from sqlalchemy import BigInteger, Boolean, Column, Enum, LargeBinary, String, Table, Text, Uuid, UUID as SQLUUID, bindparam, case, cast, event, func, inspect, literal, select, type_coerce
from sqlalchemy.engine import Engine
from sqlalchemy.dialects import postgresql as _postgresql_types
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, AsyncSessionTransaction
from sqlalchemy.exc import DBAPIError, DontWrapMixin
from sqlalchemy.orm import Session, registry
from sqlalchemy.orm.attributes import NO_VALUE
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.annotation import Annotated, annotated_classes
from sqlalchemy.sql import sqltypes as _native_types
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, BooleanClauseList, Cast, ClauseElement, ColumnClause, Grouping, Label, SavepointClause, RollbackToSavepointClause, ReleaseSavepointClause, TextClause, TypeCoerce, UnaryExpression, quoted_name, _anonymous_label, _truncated_label
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.sql.selectable import Alias, CTE, FromClause, Select, Join, Subquery
from sqlalchemy.sql.dml import Insert, Update, Delete
from sqlalchemy.types import JSON, NullType, TypeDecorator, TypeEngine, UserDefinedType

from ._sqlalchemy_guard import install_guard
from ._sqlmodel_types import autostring_impl
from ._sqlalchemy_search import rewrite_search, search_shape, validate_search_storage
from .crypto import CryptoFailure, AuthenticationFailed, FieldDescriptor, Keyring, KeyUnavailable, MAX_TEXT_BYTES, open_value, seal_value
from .crypto.cf1 import _encode
from .crypto.keys import InvalidText, RepresentationMismatch
from .manifest.compiler import _boolean_default, _native_text_length, _previous_lock, _value_mapping_matches
from .manifest.parser import decode_manifest_json


_NATIVE_TYPE_DISPATCH = frozenset(
    dtype._original_compiler_dispatch
    for namespace in (vars(_native_types), vars(_postgresql_types))
    for dtype in namespace.values()
    if isinstance(dtype, type) and issubclass(dtype, TypeEngine)
    and hasattr(dtype, '_original_compiler_dispatch')
)


class UnsupportedProtectedOperation(CryptoFailure):
    stage = "SQLAlchemy admission"
    remedy = "Use the attached factory, ordinary ORM writes, direct projections, and declared equality/IN with ordinary text binds. Remove unsupported SQL or bind codecs."


class PolicyMismatch(CryptoFailure):
    stage = "attachment validation"
    remedy = "Check the trusted lock, bytea target, search index/check, tenant key policy, mapping, and guarded engine configuration. Attach before application use."


class UnsafeEngineLogging(PolicyMismatch):
    stage = "engine logging admission"
    remedy = "Create the runtime engine with echo=False and hide_parameters=True. Keep those settings for the attached engine and review host logging separately."


class UnsafeDriverEvent(UnsupportedProtectedOperation):
    stage = 'driver event admission'
    remedy = 'Attach before cursor listeners. Register engine observers after attachment. Remove class/connection cursor hooks and driver SQL/parameter changes. Roll back before retry.'


class VarcharLengthExceeded(InvalidText, DontWrapMixin):
    stage = 'PostgreSQL VARCHAR assignment'
    sqlstate = '22001'
    remedy = 'Use a value within the declared VARCHAR character limit. Roll back before retry.'


class BulkVarcharFailureUnavailable(PolicyMismatch):
    stage = 'bulk VARCHAR failure'
    remedy = 'Check PostgreSQL 16 VARCHAR coercion access and transaction state. Roll back before retry.'


def _varchar_assignment(value, limit):
    if limit is not None and type(value) is str and len(value) > limit:
        _encode(value)
        if value[limit:].strip(' '):
            raise VarcharLengthExceeded()
        return value[:limit]
    return value


_VARCHAR_UPDATE_INVALID = b'PUBLIC VARCHAR OVERFLOW SENTINEL'


def _update_bind_name(value):
    if type(value) not in (str, quoted_name, _anonymous_label, _truncated_label):
        raise UnsupportedProtectedOperation()
    return str.__str__(value)


@dataclass(frozen=True)
class _UpdateCarrier:
    statement: object = field(repr=False)
    sql: str = field(repr=False)
    names: tuple = field(repr=False)
    constants: tuple = field(repr=False)
    scope_key: str
    record_key: str
    bindings: tuple = field(repr=False)


@dataclass(frozen=True)
class _UpdateRequest:
    mapper: object = field(repr=False)
    table: object = field(repr=False)
    tenant: UUID
    columns: tuple = field(repr=False)
    rows: tuple = field(repr=False)


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
    max_characters: int | None = None
    boolean_processor: object = field(default=None, repr=False)
    application_default: bool | None = None


def _assignment(value, binding):
    if binding.boolean_processor is not None:
        try:
            return binding.boolean_processor(value)
        except (TypeError, ValueError) as failure:
            raise type(failure)('Invalid native Boolean assignment. Roll back before retry.') from None
    return _varchar_assignment(value, binding.max_characters)


@dataclass(frozen=True)
class _Sealed:
    body: bytes | None = field(repr=False)
    permit: object = field(repr=False)
    binding: _Binding = field(repr=False)
    failure: Exception | None = field(default=None, repr=False)
    record: object = field(default=None, repr=False)
    tenant: object = field(default=None, repr=False)


@dataclass
class _Operation:
    owner: object
    keys: object = field(repr=False)
    tenant: UUID
    session: object
    flushing: bool = False
    bulk_insert: object = field(default=None, repr=False)
    bulk_update: object = field(default=None, repr=False)
    update_carrier: object = field(default=None, repr=False)
    scoped_delete: object = field(default=None, repr=False)
    bulk_returning: object = field(default=None, repr=False)
    bulk_seals: dict = field(default_factory=dict, repr=False)
    bulk_batch: tuple = field(default=(), repr=False)
    bulk_inputs: tuple = field(default=(), repr=False)
    bulk_position: int = 0
    prepared: dict = field(default_factory=dict, repr=False)
    rows: dict = field(default_factory=dict, repr=False)
    points: tuple = ()
    search_nodes: list = field(default_factory=list, repr=False)
    search_identities: dict = field(default_factory=dict, repr=False)
    parameters: dict = field(default_factory=dict, repr=False)

    @property
    def bulk_table(self):
        return self.bulk_insert if self.bulk_insert is not None else self.bulk_update

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
_SAVEPOINT_CONTROLS = (SavepointClause, RollbackToSavepointClause, ReleaseSavepointClause)


@dataclass(frozen=True)
class _DeletePermit:
    table: object
    record: object
    scope: object
    identity: object
    tenant: UUID


def _delete_node(node, native):
    dispatch = getattr(node, '_compiler_dispatch', None)
    if type(dispatch) is not MethodType or dispatch.__self__ is not node:
        raise UnsupportedProtectedOperation()
    if type(node) is annotated_classes.get(native):
        if dispatch.__func__ is not Annotated._compiler_dispatch:
            raise UnsupportedProtectedOperation()
        node = Annotated._deannotate(node)
        dispatch = node._compiler_dispatch
    if (type(node) is not native or type(dispatch) is not MethodType or dispatch.__self__ is not node or
            dispatch.__func__ is not native._original_compiler_dispatch or
            native._compiler_dispatch is not native._original_compiler_dispatch):
        raise UnsupportedProtectedOperation()


class _ReadText(TypeDecorator):
    impl = JSON
    cache_ok = False

    def __init__(self, binding, operation, record_column):
        super().__init__()
        self.binding = binding
        self.keys = operation.keys
        self.tenant = operation.tenant
        self.points = tuple(value for column, value in operation.points if column.compare(record_column))
        self.returning_frames = None
        if operation.bulk_returning is binding:
            if not operation.bulk_batch:
                raise UnsupportedProtectedOperation()
            frames = {}
            for row in operation.bulk_batch:
                sealed = row.get(binding.column.key)
                body = sealed.body if sealed is not None else None
                frames.setdefault(row[binding.record.key], set()).add(body)
            self.returning_frames = MappingProxyType({record: frozenset(bodies)
                                                      for record, bodies in frames.items()})

    def process_result_value(self, value, dialect):
        if type(value) is not list or len(value) != 3:
            raise AuthenticationFailed()
        payload, record, tenant = value
        descriptor = self.binding.descriptor
        if record is None:
            if self.returning_frames is not None:
                raise AuthenticationFailed()
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
            if self.returning_frames is not None and (
                    record not in self.returning_frames or payload not in self.returning_frames[record]):
                raise AuthenticationFailed()
        except CryptoFailure:
            raise
        except Exception:
            raise AuthenticationFailed() from None
        plain = open_value(payload, descriptor, tenant, record, self.keys)
        if plain is not None and self.binding.max_characters is not None and len(plain) > self.binding.max_characters:
            raise RepresentationMismatch()
        return plain


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
                value.binding is not self.binding or not (operation.flushing or operation.bulk_table is not None)):
            raise UnsupportedProtectedOperation()
        if operation.bulk_table is not None and operation.bulk_seals.get(id(value)) is not value:
            raise UnsupportedProtectedOperation()
        if value.failure is not None:
            carrier = operation.update_carrier
            if not (operation.bulk_update is not None and carrier is not None and
                    type(value.failure) is VarcharLengthExceeded and value.body is _VARCHAR_UPDATE_INVALID and
                    any(binding is value.binding for binding in carrier.bindings)):
                raise value.failure
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

    def _admit_textual_references(self, statement):
        # Label references have no column lineage. Check every local occurrence,
        # not just outer ORDER/GROUP clauses; nested SELECTs own their namespace.
        selected_roots = tuple(statement._all_selected_columns)
        order_roots = tuple(statement._order_by_clauses)
        group_roots = tuple(statement._group_by_clauses)
        distinct_roots = tuple(statement._distinct_on)
        roots = [(c, True, True) for c in selected_roots]
        roots += [(c, False, False) for c in order_roots + distinct_roots]
        roots += [(c, False, True) for c in group_roots]
        assigned = {id(c) for c in selected_roots + order_roots + group_roots + distinct_roots}
        roots += [(c, False, True) for c in statement.get_children() if id(c) not in assigned]
        resolution = None

        def references(part, within_columns, input_first):
            if isinstance(part, Select):
                return
            visit = getattr(part, "__visit_name__", None)
            if visit == "postgresql_distinct_on":
                # SQLAlchemy 2.1 syntax extension; 2.0 uses _distinct_on above.
                for child in part._distinct_on:
                    yield from references(child, False, False)
                return
            if visit == "textual_label_reference":
                yield part.element, within_columns, input_first
                return
            transparent = isinstance(part, (Grouping, TypeCoerce)) or (
                isinstance(part, UnaryExpression) and part.modifier in (
                    operators.asc_op, operators.desc_op,
                    operators.nulls_first_op, operators.nulls_last_op))
            # A comma-separated ORDER BY list preserves each bare label.
            transparent = transparent or visit == "order_by_list"
            for child in part.get_children():
                yield from references(child, within_columns, input_first or not transparent)

        for root, within_columns, input_first in roots:
            if any(root is clause for clause in order_roots + group_roots) and self.protected(root):
                raise UnsupportedProtectedOperation()
            for textual, within_columns, input_first in references(root, within_columns, input_first):
                if resolution is None:
                    try:
                        # Empty compilation state supplies the native namespaces
                        # without rendering protected columns or capturing keys.
                        dialect = self.engine.dialect
                        state = statement._compile_state_factory(
                            statement, dialect.statement_compiler(dialect, None))
                        combined, from_only, _ = state._label_resolve_dict
                        selected = tuple(state.statement._all_selected_columns)
                        sources = tuple(c for source in state.froms for c in source.c)
                        resolution = combined, from_only, selected, sources
                    except Exception:
                        raise UnsupportedProtectedOperation() from None
                combined, from_only, selected, sources = resolution
                resolved = (from_only if within_columns else combined).get(textual)
                if resolved is None:
                    raise UnsupportedProtectedOperation()
                if within_columns:
                    candidates = tuple(c for c in sources if c._allow_label_resolve and c.key == textual)
                else:
                    # Labels render unqualified. GROUP BY and names embedded in
                    # expressions use PostgreSQL input-name precedence; bare
                    # ORDER BY / DISTINCT ON output labels retain precedence.
                    inputs = tuple(c for c in sources if c.name == resolved.name)
                    if isinstance(resolved, Label) and input_first and inputs:
                        candidates = inputs
                    else:
                        candidates = tuple(c for c in selected if c._allow_label_resolve and
                                           (c._tq_label or c.key) == textual)
                        if not candidates:
                            candidates = tuple(c for c in sources if c._allow_label_resolve and c.key == textual)
                if not candidates or any(self.protected(c) for c in candidates):
                    raise UnsupportedProtectedOperation()

    def _ring(self, tenant):
        self._check_configuration()
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
            plan = self.deployment[0]
            if _policy(ring) != plan.document["key_policies"].get(str(tenant)):
                raise PolicyMismatch()
        if any(binding.descriptor.equality for binding in self.bindings):
            roots = [wrapper for wrapper in ring.policy.wrappers if wrapper.context.purpose == "search"]
            selected = [root for root in roots if root.context.generation == ring.policy.search_generation]
            if len(selected) != 1 or (self.deployment is None and len(roots) != 1):
                raise PolicyMismatch()
            root = selected[0]
            pin = (root.provider_id, root.context, sha256(root.sealed).digest())
            if self.search_pins.setdefault(tenant, pin) != pin:
                raise PolicyMismatch()
        return ring

    def prepare(self, tenant):
        return self._ring(tenant).prepare()

    async def prepare_async(self, tenant):
        return await self._ring(tenant).prepare_async()

    def validate(self, connection):
        if tuple(connection.dispatch.before_cursor_execute):
            raise UnsafeDriverEvent()
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
                self.identity_type(column.type, uuid_only=column is tenant)
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
                source = next(c for c in model['source_schema']['columns'] if c['name'] == field['column'])
                boolean = source['type'] == 'bool'
                try:
                    default_matches = (_boolean_default(column) is field['application_default'] if boolean
                                       else column.default is None)
                except ValueError:
                    raise PolicyMismatch() from None
                if (not isinstance(actual["type"], LargeBinary) or not _value_mapping_matches(column, source) or
                        actual["nullable"] != field["source"]["nullable"] or column.nullable != actual["nullable"] or
                        not default_matches or column.server_default is not None or column.onupdate is not None or
                        column.server_onupdate is not None or actual.get("default") is not None or actual.get("computed") is not None):
                    raise PolicyMismatch()
                if field["queries"]:
                    if (not isinstance(field["queries"], list) or not field["queries"] or
                            not set(field["queries"]) <= {"equality", "unique"}):
                        raise PolicyMismatch()
                    admitted = None
                    if self.deployment is not None and len(self.deployment) == 3:
                        from cryptalis.restore import _frame_expression, admitted_frame
                        item = admitted_frame(self.deployment[2], model, field)
                        admitted = _frame_expression(item['definition']) if item is not None else None
                    validate_search_storage(connection, model, field, admitted=admitted)
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
                                   mapper.get_property_by_column(tenant).key if tenant is not None else None,
                                   mapper.class_, None if boolean else _native_text_length(source),
                                   column.type.bind_processor(connection.dialect) if boolean else None,
                                   field.get('application_default'))
                self.bindings.append(binding)
            self.models[mapper.class_] = tuple(b for b in self.bindings if b.model is mapper.class_)

    def activate(self):
        engine = self.engine.sync_engine if isinstance(self.engine, AsyncEngine) else self.engine
        if engine.echo or not engine.hide_parameters or engine.pool.checkedout():
            raise PolicyMismatch()
        if tuple(engine.dispatch.before_cursor_execute):
            raise UnsafeDriverEvent()
        self.mapping.configure()
        for binding in self.bindings:
            # Freeze physical schema resolution, including initially unqualified
            # mappings. Existing FK columns are already resolved by configure().
            model = next(m for m in self.document["models"] if m["model"] == binding.model.__name__)
            binding.column.table.schema = model["schema"]
            binding.column.type = _Payload(binding, self)
        self.fingerprint = self._fingerprint()
        for model in self.models:
            # ORM flush uses a mapper cache that engine.clear_compiled_cache()
            # does not clear. Native statements can retain plaintext processors.
            inspect(model).base_mapper._compiled_cache.clear()
        engine.clear_compiled_cache()
        install_guard(engine, UnsupportedProtectedOperation, self.before_execute, self.check_cursor,
                      UnsafeDriverEvent, self.prepare_many)
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
            for binding in self.bindings:
                self.identity_type(binding.record.type)
                if binding.tenant is not None:
                    self.identity_type(binding.tenant.type, uuid_only=True)
                if binding.boolean_processor is not None and _boolean_default(binding.column) is not binding.application_default:
                    raise PolicyMismatch()
            return tuple((b.column.table.schema, b.column.table.name, column(b.column), column(b.record), column(b.tenant),
                          inspect(b.model).primary_key, inspect(b.model).get_property_by_column(b.column).key,
                          b.column.type.binding, b.column.type.owner) for b in self.bindings)
        except Exception:
            raise PolicyMismatch() from None

    def _check_configuration(self):
        engine = self.engine.sync_engine if isinstance(self.engine, AsyncEngine) else self.engine
        if (self._fingerprint() != self.fingerprint or engine.echo or not engine.hide_parameters or
                engine.get_execution_options().get("schema_translate_map")):
            raise PolicyMismatch()

    def _check(self):
        self._check_configuration()
        operation = _operation.get()
        if operation is None or operation.owner is not self:
            raise UnsupportedProtectedOperation()
        return operation

    def returning_binding(self, statement, bulk):
        if not statement._returning:
            return None
        if (len(statement._returning) != 1 or statement._with_options or
                type(statement._sort_by_parameter_order) is not bool):
            raise UnsupportedProtectedOperation()
        return self.returning_column(statement._returning[0], bulk)

    def returning_column(self, column, bulk):
        if not isinstance(column, ColumnClause) or column.is_literal or column.table is not bulk:
            raise UnsupportedProtectedOperation()
        # ORM annotations can retain native types. Resolve the owned physical
        # column by lineage, as for SELECT; native compilation deannotates it.
        bindings = [binding for binding in self.bindings if binding.column.table is bulk and
                    column.shares_lineage(binding.column)]
        if len(bindings) != 1:
            raise UnsupportedProtectedOperation()
        return bindings[0]

    @classmethod
    def identity_type(cls, dtype, *, uuid_only=False):
        if type(dtype) not in ((Uuid, SQLUUID) if uuid_only else (Uuid, SQLUUID, BigInteger)):
            raise PolicyMismatch()
        if isinstance(dtype, Uuid) and (not dtype.as_uuid or not getattr(dtype, 'native_uuid', True)):
            raise PolicyMismatch()
        try:
            cls.bind_type(dtype)
        except UnsupportedProtectedOperation:
            raise PolicyMismatch() from None

    @staticmethod
    def select_dispatch(dtype):
        original = getattr(type(dtype), '_original_compiler_dispatch', None)
        dispatch = dtype._compiler_dispatch
        if (type(dispatch) is not MethodType or dispatch.__self__ is not dtype or
                dispatch.__func__ is not original or original not in _NATIVE_TYPE_DISPATCH):
            raise UnsupportedProtectedOperation()

    @classmethod
    def bind_type(cls, dtype, *, selecting=False, column_expression=None):
        # The SELECT path also checks native output hooks and SQL type text.
        adapt = (TypeEngine.adapt, Uuid.adapt, Boolean.adapt, Enum.adapt) if selecting else (TypeEngine.adapt, Uuid.adapt, Boolean.adapt)
        seen = set()
        while True:
            try:
                sqlmodel_impl = autostring_impl(dtype)
            except (TypeError, ValueError):
                raise UnsupportedProtectedOperation() from None
            if selecting:
                cls.select_dispatch(dtype)
            if (id(dtype) in seen or dtype._variant_mapping or dtype._has_bind_expression or
                    selecting and (dtype._has_column_expression and dtype is not column_expression or
                                   isinstance(dtype, UserDefinedType)) or
                    type(dtype).dialect_impl is not TypeEngine.dialect_impl or
                    type(dtype).adapt not in adapt):
                raise UnsupportedProtectedOperation()
            seen.add(id(dtype))
            if sqlmodel_impl is not None:
                dtype = sqlmodel_impl
                continue
            if selecting and isinstance(dtype, _native_types.ARRAY):
                dtype = dtype.item_type
                continue
            if selecting and isinstance(dtype, _native_types.TupleType):
                for item in dtype.types:
                    cls.bind_type(item, selecting=True)
                return
            if not isinstance(dtype, TypeDecorator):
                return
            if (type(dtype).load_dialect_impl is not TypeDecorator.load_dialect_impl or
                    type(dtype).type_engine is not TypeDecorator.type_engine or
                    type(dtype).copy is not TypeDecorator.copy):
                raise UnsupportedProtectedOperation()
            dtype = dtype.impl_instance

    def select_types(self, statement):
        try:
            nodes = list(visitors.iterate(statement))
            seen = {id(node) for node in nodes}
            for node in nodes:
                if isinstance(node, Select):
                    for column in node.selected_columns:
                        for child in visitors.iterate(column):
                            if id(child) not in seen:
                                seen.add(id(child))
                                nodes.append(child)
            for node in nodes:
                if isinstance(node, BindParameter) and node.literal_execute:
                    raise UnsupportedProtectedOperation()
                dtype = getattr(node, 'type', None)
                if dtype is None:
                    continue
                self.select_dispatch(dtype)
                column_expression = None
                if type(dtype) is _Payload:
                    # Only the owned physical type can generate its authenticated
                    # projection. A copy can inherit owner/binding fields while
                    # carrying an unadmitted dialect variant.
                    if (dtype.owner is not self or not any(
                            binding is dtype.binding and binding.column.type is dtype
                            for binding in self.bindings)):
                        raise UnsupportedProtectedOperation()
                    column_expression = dtype
                self.bind_type(dtype, selecting=True, column_expression=column_expression)
            return tuple(nodes)
        except CryptoFailure:
            raise
        except Exception:
            raise UnsupportedProtectedOperation() from None

    def delete_context(self, statement, tenant, expected=None):
        _delete_node(statement, Delete)
        if type(tenant) is not UUID:
            raise UnsupportedProtectedOperation()
        if expected is None:
            mapper = statement._propagate_attrs.get('plugin_subject')
            if (mapper is None or getattr(mapper, 'class_', None) not in self.models or
                    mapper is not inspect(mapper.class_) or mapper.inherits is not None or
                    mapper.version_id_col is not None):
                raise UnsupportedProtectedOperation()
            first = self.models[mapper.class_][0]
            table = first.column.table
            if mapper.local_table is not table or len(mapper.primary_key) != 1 or mapper.primary_key[0] is not first.record:
                raise UnsupportedProtectedOperation()
        else:
            table = expected.table
            first = next(binding for binding in self.bindings if binding.column.table is table)
        if (not isinstance(statement, Delete) or first.tenant is None or
                statement.table.name != table.name or statement.table.schema != table.schema or
                not all(column.key in statement.table.c and statement.table.c[column.key].shares_lineage(column)
                        for column in table.c) or statement._returning or statement._return_defaults or
                statement._with_options or statement._prefixes or statement._hints or
                statement._independent_ctes or statement.dialect_kwargs):
            raise UnsupportedProtectedOperation()
        _delete_node(table, Table)
        _delete_node(statement.table, Table)
        for column in (first.record, first.tenant):
            self.identity_type(column.type, uuid_only=column is first.tenant)
            self.bind_type(column.type, selecting=True)
        clauses, pending = [], [statement.whereclause]
        while pending:
            clause = pending.pop()
            if isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
                _delete_node(clause, BooleanClauseList)
                pending.extend(reversed(clause.clauses))
            else:
                clauses.append(clause)
        if len(clauses) != 2:
            raise UnsupportedProtectedOperation()
        scope = record = None
        for clause in clauses:
            _delete_node(clause, BinaryExpression)
            if not isinstance(clause, BinaryExpression) or clause.operator is not operators.eq:
                raise UnsupportedProtectedOperation()
            left, right = clause.left, clause.right
            if isinstance(left, BindParameter):
                left, right = right, left
            if (not isinstance(left, ColumnClause) or left.table is not table or left.is_literal or
                    not isinstance(right, BindParameter) or right.required or right.callable is not None or
                    right.expanding or right.literal_execute or type(right.type) is not type(left.type)):
                raise UnsupportedProtectedOperation()
            _delete_node(left, Column)
            _delete_node(right, BindParameter)
            self.bind_type(right.type, selecting=True)
            if left.shares_lineage(first.tenant) and scope is None:
                if type(right.value) is not UUID or right.value != tenant:
                    raise UnsupportedProtectedOperation()
                scope = right
            elif left.shares_lineage(first.record) and record is None:
                if first.descriptor.record_codec == 'uuid16/v1' and type(right.value) is not UUID:
                    raise UnsupportedProtectedOperation()
                first.descriptor._record(tenant, right.value)
                record = right
            else:
                raise UnsupportedProtectedOperation()
        if scope is None or record is None or scope.key == record.key:
            raise UnsupportedProtectedOperation()
        identity = UUID(bytes=record.value.bytes) if type(record.value) is UUID else record.value
        permit = _DeletePermit(table, first.record, first.tenant, identity, UUID(bytes=tenant.bytes))
        if expected is not None:
            if (permit.table is not expected.table or permit.record is not expected.record or
                    permit.scope is not expected.scope or type(permit.identity) is not type(expected.identity) or
                    permit.identity != expected.identity or permit.tenant != expected.tenant):
                raise UnsupportedProtectedOperation()
            permit = expected
        return permit, scope, record

    def update_context(self, statement, table, tenant, *, generated):
        _delete_node(statement, Update)
        _delete_node(statement.table, Table)
        if (not isinstance(statement, Update) or statement.table.name != table.name or
                statement.table.schema != table.schema or
                not all(column.key in statement.table.c and
                        statement.table.c[column.key].shares_lineage(column) for column in table.c) or
                statement._values or getattr(statement, '_ordered_values', None) or statement._returning or
                statement._return_defaults or statement._with_options or statement._prefixes or
                statement._hints or statement._independent_ctes or statement.dialect_kwargs):
            raise UnsupportedProtectedOperation()
        bindings = [binding for binding in self.bindings if binding.column.table is table]
        first = bindings[0]
        if first.tenant is None:
            raise UnsupportedProtectedOperation()
        self.bind_type(first.record.type)
        self.bind_type(first.tenant.type)
        clauses, pending = [], [statement.whereclause]
        while pending:
            clause = pending.pop()
            if isinstance(clause, BooleanClauseList) and clause.operator is operators.and_:
                _delete_node(clause, BooleanClauseList)
                pending.extend(reversed(clause.clauses))
            else:
                clauses.append(clause)
        if len(clauses) != (2 if generated else 1):
            raise UnsupportedProtectedOperation()
        scope, record = None, None
        for clause in clauses:
            _delete_node(clause, BinaryExpression)
            if not isinstance(clause, BinaryExpression) or clause.operator is not operators.eq:
                raise UnsupportedProtectedOperation()
            left, right = clause.left, clause.right
            if isinstance(left, BindParameter):
                left, right = right, left
            if (not isinstance(left, ColumnClause) or left.table is not table or left.is_literal or
                    not isinstance(right, BindParameter) or right.callable is not None or right.expanding or
                    type(right.type) is not type(left.type)):
                raise UnsupportedProtectedOperation()
            self.bind_type(right.type)
            _delete_node(left, Column)
            _delete_node(right, BindParameter)
            if left.shares_lineage(first.tenant) and scope is None:
                if right.required or type(right.value) is not UUID or right.value != tenant:
                    raise UnsupportedProtectedOperation()
                scope = right
            elif generated and left.shares_lineage(first.record) and record is None:
                record = right
            else:
                raise UnsupportedProtectedOperation()
        if scope is None or generated and record is None:
            raise UnsupportedProtectedOperation()
        return scope, record

    def admit(self, statement, flushing=False, bulk=None):
        if flushing and isinstance(statement, (Insert, Update, Delete)):
            if isinstance(statement, Delete):
                for node in visitors.iterate(statement):
                    for native in (Delete, Table, Column, BooleanClauseList, BinaryExpression, BindParameter):
                        if isinstance(node, native):
                            _delete_node(node, native)
                            break
                    else:
                        raise UnsupportedProtectedOperation()
            return
        if isinstance(statement, Delete):
            operation = self._check()
            if operation.scoped_delete is None:
                raise UnsupportedProtectedOperation()
            self.delete_context(statement, operation.tenant, operation.scoped_delete)
            return
        if bulk is not None and isinstance(statement, Update):
            operation = self._check()
            if operation.bulk_update is not bulk:
                raise UnsupportedProtectedOperation()
            if operation.update_carrier is not None and statement is operation.update_carrier.statement:
                return
            self.update_context(statement, bulk, operation.tenant, generated=True)
            return
        if bulk is not None and isinstance(statement, Insert):
            if (statement.table.name != bulk.name or statement.table.schema != bulk.schema or
                    not all(column.key in statement.table.c and
                            statement.table.c[column.key].shares_lineage(column) for column in bulk.c) or
                    statement._values or statement._multi_values or
                    statement._post_values_clause is not None or
                    statement.select is not None or statement._prefixes or statement._hints or
                    statement._independent_ctes or statement.dialect_kwargs):
                raise UnsupportedProtectedOperation()
            operation = _operation.get()
            current = operation is not None and operation.owner is self and operation.bulk_insert is bulk
            if statement._return_defaults:
                binding = operation.bulk_returning if current else None
                primary = inspect(binding.model).primary_key if binding is not None else ()
                defaults = statement._return_defaults_columns or ()
                supplemental = statement._supplemental_returning or ()
                if (binding is None or len(defaults) != len(primary) or
                        any(not isinstance(left, ColumnClause) or left.is_literal or left.table is not bulk or
                            not left.shares_lineage(right) for left, right in zip(defaults, primary)) or
                        statement._with_options or type(statement._sort_by_parameter_order) is not bool):
                    raise UnsupportedProtectedOperation()
                if statement._returning:
                    if supplemental or self.returning_binding(statement, bulk) is not binding:
                        raise UnsupportedProtectedOperation()
                elif len(supplemental) != 1 or self.returning_column(supplemental[0], bulk) is not binding:
                    raise UnsupportedProtectedOperation()
            else:
                binding = self.returning_binding(statement, bulk)
                if current and binding is not operation.bulk_returning:
                    raise UnsupportedProtectedOperation()
            return
        if not isinstance(statement, Select):
            raise UnsupportedProtectedOperation()
        nodes = self.select_types(statement)
        safe_count_stars = set()
        for node in nodes:
            operation = _operation.get()
            generated = operation is not None and operation.owner is self and operation.generated(node)
            if generated:
                continue
            if isinstance(node, FunctionElement) and node.name == "count":
                arguments = list(node.clauses)
                if len(arguments) == 1 and isinstance(arguments[0], ColumnClause) and arguments[0].name == "*":
                    safe_count_stars.add(id(arguments[0]))
        for node in nodes:
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
            # Parentheses carry no new operation. Their children still pass
            # every admission check below; do not reject native AND/OR grouping.
            if self.protected(node) and not isinstance(node, (Select, FromClause, ColumnClause, Label, Grouping)):
                boolean = isinstance(node, BooleanClauseList) and node.operator in (operators.and_, operators.or_)
                if not boolean and search_shape(self, node) is None:
                    raise UnsupportedProtectedOperation()
            if isinstance(node, Select):
                def ungroup(expression):
                    while isinstance(expression, Grouping):
                        expression = expression.element
                    return expression
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
                    root = ungroup(where)
                    if any(where is child for child in children):
                        eligible.append(where)
                    elif any(root is child for child in children):
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
                        match = next((i for i, allowed in enumerate(eligible) if ungroup(child) is ungroup(allowed)), None)
                        if match is None:
                            raise UnsupportedProtectedOperation()
                        eligible.pop(match)
                self._admit_textual_references(node)

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
                if (state.pending and binding.application_default is not None
                        and (value is NO_VALUE or value is None)):
                    value = binding.application_default
                    setattr(obj, binding.attribute, value)
                if value is NO_VALUE:
                    value = None if state.pending and (binding.column.nullable or binding.boolean_processor is not None) else NO_VALUE
                if value is NO_VALUE:
                    raise UnsupportedProtectedOperation()
                try:
                    stored = _assignment(value, binding)
                except (VarcharLengthExceeded, TypeError, ValueError) as failure:
                    if binding.boolean_processor is None and not isinstance(failure, VarcharLengthExceeded):
                        raise
                    # Bind processing occurs inside the native flush transaction.
                    sealed = _Sealed(None, operation, binding, failure)
                else:
                    body = seal_value(stored, binding.descriptor, tenant, record, operation.keys)
                    sealed = _Sealed(body, operation, binding)
                operation.prepared[(binding.column.table.schema, binding.column.table.name, record, binding.column.key)] = (value, sealed)

    def before_execute(self, connection, statement, multiparams, params, execution_options):
        if type(statement) in _SAVEPOINT_CONTROLS:
            self._check_configuration()
            if multiparams or params or execution_options.get('schema_translate_map'):
                raise UnsupportedProtectedOperation()
            return statement, multiparams, params
        operation = self._check()
        if execution_options.get("schema_translate_map"):
            raise PolicyMismatch()
        self.admit(statement, operation.flushing, operation.bulk_table)
        if operation.scoped_delete is not None and isinstance(statement, Delete):
            if multiparams or params:
                raise UnsupportedProtectedOperation()
            return statement, multiparams, params
        if operation.bulk_update is not None and isinstance(statement, Update):
            groups = multiparams if multiparams else [params]
            scope, record_bind = self.update_context(statement, operation.bulk_update, operation.tenant, generated=True)
            for group in groups:
                if type(group) is not dict or operation.bulk_position >= len(operation.bulk_inputs):
                    raise UnsupportedProtectedOperation()
                record, values = operation.bulk_inputs[operation.bulk_position]
                expected = dict(values, **{record_bind.key: record})
                if (set(group) != set(expected) or type(group[record_bind.key]) is not type(record) or
                        any(group[key] is not value and
                            (isinstance(value, _Sealed) or type(group[key]) is not type(value) or group[key] != value)
                            for key, value in expected.items())):
                    raise UnsupportedProtectedOperation()
                operation.bulk_position += 1
            operation.bulk_batch = tuple(dict(group) for group in groups)
            operation.update_carrier = self.prepare_update_carrier(connection, statement, groups, scope, record_bind)
            return (operation.update_carrier.statement if operation.update_carrier is not None else statement), multiparams, params
        if operation.bulk_insert is not None and isinstance(statement, Insert):
            groups = multiparams if multiparams else [params]
            self.check_bulk_rows(operation, groups)
            operation.bulk_batch = tuple(dict(group) for group in groups)
            return statement, multiparams, params
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

    def prepare_update_carrier(self, connection, statement, groups, scope, record):
        bindings = tuple(binding for binding in self.bindings
                         if binding.column.table is _operation.get().bulk_update and
                         binding.max_characters is not None and binding.column.key in groups[0])
        if not bindings:
            return None
        constants, assignments = [], {}
        for binding in bindings:
            body = bindparam(binding.column.key, type_=binding.column.type)
            sentinel, text, limit, explicit = (literal(_VARCHAR_UPDATE_INVALID, LargeBinary()),
                literal('xx', String()), literal(5), literal(False))
            constants.extend((sentinel, text, limit, explicit))
            overflow = func.pg_catalog.varchar(cast(text, String()), limit, explicit)
            assignments[binding.column] = case((body == sentinel, cast(overflow, LargeBinary())), else_=body)
        generated = statement.values(assignments)
        compiled = generated.compile(dialect=connection.dialect, column_keys=sorted(groups[0]),
                                     for_executemany=len(groups) > 1)
        names = tuple((_update_bind_name(bind.key), _update_bind_name(name)) for bind, name in compiled.bind_names.items())
        if len({key for key, _ in names}) != len(names) or len({name for _, name in names}) != len(names):
            raise UnsupportedProtectedOperation()
        return _UpdateCarrier(generated, str(compiled), names,
                              tuple((_update_bind_name(bind.key), bind.value) for bind in constants),
                              _update_bind_name(scope.key), _update_bind_name(record.key), bindings)

    def prepare_many(self, context, parameters):
        operation = self._check()
        if operation.bulk_insert is None or operation.bulk_returning is None:
            return False
        if context.compiled is None:
            raise UnsupportedProtectedOperation()
        self.admit(context.compiled.statement, bulk=operation.bulk_insert)
        self.check_bulk_parameters(operation, context, parameters)
        return True

    def check_cursor(self, context, statement, parameters, native_page=False):
        if context.compiled is None:
            raise UnsupportedProtectedOperation()
        if type(context.compiled.statement) in _SAVEPOINT_CONTROLS:
            self._check_configuration()
            expected = str(context.compiled.statement.compile(dialect=context.dialect))
            if statement != expected or parameters:
                raise UnsupportedProtectedOperation()
            return
        operation = self._check()
        self.admit(context.compiled.statement, operation.flushing, operation.bulk_table)
        if operation.scoped_delete is not None and isinstance(context.compiled.statement, Delete):
            permit, scope, record = self.delete_context(context.compiled.statement, operation.tenant,
                                                       operation.scoped_delete)
            names = [context.compiled.bind_names.get(bind) for bind in (scope, record)]
            if (context.executemany or statement != str(context.compiled) or any(type(name) is not str for name in names) or
                    names[0] == names[1] or len(context.compiled.bind_names) != 2 or
                    len(context.compiled_parameters) != 1):
                raise UnsupportedProtectedOperation()
            expected = dict(zip(names, (permit.tenant, permit.identity)))
            for group in (context.compiled_parameters[0], parameters):
                if (type(group) is not dict or set(group) != set(expected) or
                        any(type(group[name]) is not type(value) or group[name] != value
                            for name, value in expected.items())):
                    raise UnsupportedProtectedOperation()
            return
        if operation.bulk_update is not None and isinstance(context.compiled.statement, Update):
            carrier = operation.update_carrier
            if (statement != str(context.compiled) or carrier is not None and
                    (context.compiled.statement is not carrier.statement or statement != carrier.sql)):
                raise UnsupportedProtectedOperation()
            self.check_update_parameters(operation, context, parameters if context.executemany else [parameters])
            return
        if operation.bulk_insert is not None and isinstance(context.compiled.statement, Insert):
            if native_page:
                if operation.bulk_returning is None:
                    raise UnsupportedProtectedOperation()
                return
            if statement != str(context.compiled):
                raise UnsupportedProtectedOperation()
            actual = parameters if context.executemany else [parameters]
            self.check_bulk_parameters(operation, context, actual)

    def check_update_parameters(self, operation, context, actual):
        carrier = operation.update_carrier
        native_names = tuple((_update_bind_name(bind.key), _update_bind_name(name)) for bind, name in context.compiled.bind_names.items())
        if carrier is not None:
            if context.compiled.statement is not carrier.statement or native_names != carrier.names:
                raise UnsupportedProtectedOperation()
            names, scope_key, record_key = dict(carrier.names), carrier.scope_key, carrier.record_key
            constants = {names[key]: value for key, value in carrier.constants}
        else:
            scope, record = self.update_context(context.compiled.statement, operation.bulk_update,
                                                operation.tenant, generated=True)
            names, scope_key, record_key = dict(native_names), _update_bind_name(scope.key), _update_bind_name(record.key)
            constants = {}
        if (scope_key not in names or record_key not in names or
                any(type(name) is not str for name in names.values()) or
                len(names) != len(native_names) or len(set(names.values())) != len(names)):
            raise UnsupportedProtectedOperation()
        for bind in context.compiled.bind_names:
            owned_constant = carrier is not None and any(
                _update_bind_name(bind.key) == key for key, _ in carrier.constants)
            self.bind_type(bind.type, selecting=owned_constant)
        groups = context.compiled_parameters
        if len(groups) != len(actual) or len(groups) != len(operation.bulk_batch):
            raise UnsupportedProtectedOperation()
        binary = context.dialect.dbapi.Binary
        for group, sent, admitted in zip(groups, actual, operation.bulk_batch):
            if any(key not in names for key in admitted):
                raise UnsupportedProtectedOperation()
            expected = {names[key]: value for key, value in admitted.items()}
            expected[names[scope_key]] = operation.tenant
            expected.update(constants)
            if type(sent) is not dict or set(sent) != set(expected) or set(group) != set(expected):
                raise UnsupportedProtectedOperation()
            for name, value in expected.items():
                if name in constants:
                    if type(group[name]) is not type(value) or group[name] != value:
                        raise UnsupportedProtectedOperation()
                    if type(value) is bytes:
                        if type(sent[name]) is not binary or type(sent[name].obj) is not bytes or sent[name].obj != value:
                            raise UnsupportedProtectedOperation()
                    elif type(sent[name]) is not type(value) or sent[name] != value:
                        raise UnsupportedProtectedOperation()
                elif isinstance(value, _Sealed):
                    if (operation.bulk_seals.get(id(value)) is not value or value.permit is not operation or
                            group[name] is not value or value.record != admitted[record_key] or
                            value.tenant != operation.tenant or
                            (sent[name] is not None if value.body is None else
                             type(sent[name]) is not binary or type(sent[name].obj) is not bytes or sent[name].obj != value.body)):
                        raise UnsupportedProtectedOperation()
                else:
                    if (group[name] is not value and
                            (type(group[name]) is not type(value) or group[name] != value)):
                        raise UnsupportedProtectedOperation()
                    if (name in (names[scope_key], names[record_key]) and
                            (type(sent[name]) is not type(value) or sent[name] != value)):
                        raise UnsupportedProtectedOperation()

    def check_bulk_parameters(self, operation, context, actual):
        self.check_bulk_rows(operation, context.compiled_parameters)
        groups = context.compiled_parameters
        if len(groups) != len(actual) or len(groups) != len(operation.bulk_batch):
            raise UnsupportedProtectedOperation()
        bindings = [b for b in self.bindings if b.column.table is operation.bulk_insert]
        first = bindings[0]
        columns = [first.record] + ([first.tenant] if first.tenant is not None else [])
        binary = context.dialect.dbapi.Binary
        for group, sent, admitted in zip(groups, actual, operation.bulk_batch):
            if type(sent) is not dict or set(sent) != set(group):
                raise UnsupportedProtectedOperation()
            for column in columns:
                value = admitted[column.key]
                if (type(sent[column.key]) is not type(value) or sent[column.key] != value or
                        group[column.key] != value):
                    raise UnsupportedProtectedOperation()
            for binding in bindings:
                key = binding.column.key
                if (key in group) != (key in admitted):
                    raise UnsupportedProtectedOperation()
                if key not in group:
                    continue
                sealed = admitted[key]
                value = sent[key]
                if group[key] is not sealed or (value is not None if sealed.body is None else
                        type(value) is not binary or type(value.obj) is not bytes or value.obj != sealed.body):
                    raise UnsupportedProtectedOperation()

    def check_bulk_rows(self, operation, groups):
        bindings = [b for b in self.bindings if b.column.table is operation.bulk_insert]
        first = bindings[0]
        for group in groups:
            record = group.get(first.record.key)
            tenant = group.get(first.tenant.key) if first.tenant is not None else first.descriptor.table_id
            first.descriptor._record(tenant, record)
            if (tenant != operation.tenant or
                    (first.column.table.schema, first.column.table.name, record) not in operation.rows):
                raise UnsupportedProtectedOperation()
            for binding in bindings:
                if binding.column.key not in group:
                    continue
                value = group[binding.column.key]
                if (not isinstance(value, _Sealed) or operation.bulk_seals.get(id(value)) is not value or
                        value.permit is not operation or value.binding is not binding or
                        value.record != record or value.tenant != tenant):
                    raise UnsupportedProtectedOperation()


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

    def scalar(self, statement, *args, **kwargs):
        if isinstance(statement, (Delete, Update)):
            raise UnsupportedProtectedOperation()
        return super().scalar(statement, *args, **kwargs)

    def scalars(self, statement, *args, **kwargs):
        if isinstance(statement, (Delete, Update)):
            raise UnsupportedProtectedOperation()
        return super().scalars(statement, *args, **kwargs)

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
    if isinstance(state.statement, Insert):
        return _bulk_insert(state)
    if isinstance(state.statement, Update):
        return _bulk_update(state)
    if isinstance(state.statement, Delete):
        return _scoped_delete(state)
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


def _scoped_delete(state):
    session, statement = state.session, state.statement
    owner, mapper = session._owner, state.bind_mapper
    if (not state.is_orm_statement or mapper is None or mapper.class_ not in owner.models or
            mapper is not statement._propagate_attrs.get('plugin_subject') or
            state.parameters is not None or set(state.bind_arguments) - {'clause', 'mapper'}):
        raise UnsupportedProtectedOperation()
    owner._check_configuration()
    tenant = session._tenant
    permit, _, _ = owner.delete_context(statement, tenant)
    options = state.execution_options
    if (set(options) - {'synchronize_session', 'autoflush', 'prebuffer_rows', 'dml_strategy',
                       '_sa_orm_update_options', '_result_disable_adapt_to_context'} or
            options.get('synchronize_session') is not False or
            any(type(options[name]) is not bool for name in ('autoflush', 'prebuffer_rows') if name in options) or
            options.get('dml_strategy', 'auto') not in ('auto', 'orm')):
        raise UnsupportedProtectedOperation()
    native = options.get('_sa_orm_update_options')
    if (native is None or native._subject_mapper is not mapper or native._dml_strategy != 'orm' or
            native._synchronize_session is not False):
        raise UnsupportedProtectedOperation()
    material = session._keys()
    if session._tenant != permit.tenant:
        raise UnsupportedProtectedOperation()
    owner.delete_context(statement, permit.tenant, permit)
    operation = _Operation(owner, material, permit.tenant, session, scoped_delete=permit)
    state.update_execution_options(compiled_cache=None)
    token = _operation.set(operation)
    try:
        return state.invoke_statement()
    finally:
        _operation.reset(token)


def _bulk_insert(state):
    session, statement = state.session, state.statement
    owner, mapper = session._owner, state.bind_mapper
    if (not state.is_orm_statement or mapper is None or mapper.class_ not in owner.models or
            type(state.parameters) is not list or not state.parameters or
            set(state.bind_arguments) - {'clause', 'mapper'}):
        raise UnsupportedProtectedOperation()
    bindings = owner.models[mapper.class_]
    first = bindings[0]
    table = first.column.table
    if statement._return_defaults:
        raise UnsupportedProtectedOperation()
    owner.admit(statement, bulk=table)
    returning = owner.returning_binding(statement, table)
    options = state.execution_options
    if (set(options) - {'render_nulls', 'autoflush', 'dml_strategy', 'prebuffer_rows',
                       '_sa_orm_insert_options', '_result_disable_adapt_to_context'} or
            any(type(options[name]) is not bool for name in
                ('render_nulls', 'autoflush', 'prebuffer_rows') if name in options) or
            options.get('dml_strategy', 'bulk') not in ('auto', 'bulk')):
        raise UnsupportedProtectedOperation()
    native = options.get('_sa_orm_insert_options')
    if (native is None or native._subject_mapper is not mapper or native._dml_strategy != 'bulk'):
        raise UnsupportedProtectedOperation()
    render_nulls = options.get('render_nulls', False)
    columns = {prop.key: prop.columns[0] for prop in mapper.column_attrs if len(prop.columns) == 1}
    rows = []
    for original in state.parameters:
        if (type(original) is not dict or set(original) - columns.keys() or
                any(hasattr(value, '__clause_element__') or isinstance(value, ClauseElement)
                    for value in original.values())):
            raise UnsupportedProtectedOperation()
        row = dict(original)
        record = row.get(first.record_attribute)
        tenant = row.get(first.tenant_attribute) if first.tenant is not None else first.descriptor.table_id
        first.descriptor._record(tenant, record)
        if tenant != session._tenant:
            raise AuthenticationFailed()
        for attribute, column in columns.items():
            omitted = attribute not in row or (row[attribute] is None and not render_nulls
                                               and not column.type.should_evaluate_none)
            if omitted and (column.server_default is not None or
                            column.default is not None and not column.default.is_scalar):
                raise UnsupportedProtectedOperation()
        rows.append(row)
    operation = _Operation(owner, session._keys(), session._tenant, session,
                           bulk_insert=table, bulk_returning=returning)
    failed_index = None
    for index, row in enumerate(rows):
        record = row[first.record_attribute]
        tenant = row[first.tenant_attribute] if first.tenant is not None else first.descriptor.table_id
        operation.rows[(table.schema, table.name, record)] = tenant
        for binding in bindings:
            if binding.attribute not in row or row[binding.attribute] is None and not render_nulls:
                if binding.application_default is None:
                    continue  # Preserve native NULL omission and heterogeneous grouping.
                row[binding.attribute] = binding.application_default
            value = row[binding.attribute]
            try:
                stored = _assignment(value, binding)
            except (VarcharLengthExceeded, TypeError, ValueError) as failure:
                if binding.boolean_processor is None and not isinstance(failure, VarcharLengthExceeded):
                    raise
                if type(failure) is VarcharLengthExceeded and failed_index is None:
                    failed_index = index
                sealed = _Sealed(None, operation, binding, failure, record, tenant)
            else:
                sealed = _Sealed(seal_value(stored, binding.descriptor, tenant, record, operation.keys),
                                 operation, binding, record=record, tenant=tenant)
            operation.bulk_seals[id(sealed)] = sealed
            row[binding.attribute] = sealed
    original_parameters = state.parameters
    state.update_execution_options(compiled_cache=None)
    token = _operation.set(operation)
    try:
        if failed_index is not None:
            # Preserve native constraint precedence before this known length
            # error. An empty list would instead insert DEFAULT VALUES.
            if failed_index:
                state.parameters = rows[:failed_index]
                state.invoke_statement()
            state.parameters = [rows[failed_index]]
            try:
                state.invoke_statement()  # Includes native autoflush before binding.
            except VarcharLengthExceeded as failure:
                if not any(value.failure is failure for value in operation.bulk_seals.values()):
                    raise
                try:
                    # PG16 assignment coercion, with public constants only.
                    # Abort this transaction/savepoint without plaintext SQL.
                    session.connection().execute(select(func.pg_catalog.varchar(
                        cast(literal('xx'), String()), 5, False)))
                except DBAPIError as error:
                    if getattr(error.orig, 'sqlstate', None) != '22001':
                        raise BulkVarcharFailureUnavailable() from None
                    raise failure from None
                raise BulkVarcharFailureUnavailable()
            raise BulkVarcharFailureUnavailable()
        state.parameters = rows
        return state.invoke_statement()
    finally:
        state.parameters = original_parameters
        operation.bulk_seals.clear()
        operation.bulk_batch = ()
        operation.rows.clear()
        _operation.reset(token)


def _capture_update(owner, mapper, statement, parameters, tenant):
    if (mapper is None or getattr(mapper, 'class_', None) not in owner.models or
            mapper is not inspect(mapper.class_) or mapper.version_id_col is not None or
            type(parameters) is not list or not parameters or type(tenant) is not UUID):
        raise UnsupportedProtectedOperation()
    bindings = owner.models[mapper.class_]
    first = bindings[0]
    table = first.column.table
    tenant = UUID(bytes=tenant.bytes)
    owner.update_context(statement, table, tenant, generated=False)
    columns = {prop.key: prop.columns[0] for prop in mapper.column_attrs
               if len(prop.columns) == 1 and isinstance(prop.columns[0], ColumnClause) and
               prop.columns[0].table is table and table.c.get(prop.columns[0].key) is prop.columns[0] and
               mapper.get_property_by_column(prop.columns[0]) is prop}
    rows = []
    for original in parameters:
        if (type(original) is not dict or any(type(key) is not str for key in original) or
                set(original) - columns.keys() or
                first.tenant_attribute in original or
                any(hasattr(value, '__clause_element__') or isinstance(value, ClauseElement)
                    for value in original.values())):
            raise UnsupportedProtectedOperation()
        row = dict(original)
        for attribute in row:
            owner.bind_type(columns[attribute].type)
        record = row.get(first.record_attribute)
        if first.descriptor.record_codec == 'uuid16/v1':
            if type(record) is not UUID:
                raise UnsupportedProtectedOperation()
            row[first.record_attribute] = UUID(bytes=record.bytes)
        first.descriptor._record(tenant, record)
        if any(column.onupdate is not None or column.server_onupdate is not None
               for attribute, column in columns.items() if attribute not in row):
            raise UnsupportedProtectedOperation()
        rows.append(tuple(row.items()))
    return _UpdateRequest(mapper, table, tenant, tuple(columns.items()), tuple(rows))


def _same_update_request(original, current):
    if (original.mapper is not current.mapper or original.table is not current.table or
            original.tenant != current.tenant or len(original.rows) != len(current.rows) or
            len(original.columns) != len(current.columns) or any(
                left[0] != right[0] or left[1] is not right[1]
                for left, right in zip(original.columns, current.columns))):
        return False
    for left, right in zip(original.rows, current.rows):
        if len(left) != len(right) or any(
                lkey != rkey or lvalue is not rvalue and
                (type(lvalue) is not type(rvalue) or lvalue != rvalue)
                for (lkey, lvalue), (rkey, rvalue) in zip(left, right)):
            return False
    return True


def _bulk_update(state):
    session, statement = state.session, state.statement
    owner, mapper = session._owner, state.bind_mapper
    if not state.is_orm_statement or set(state.bind_arguments) - {'clause', 'mapper'}:
        raise UnsupportedProtectedOperation()
    request = _capture_update(owner, mapper, statement, state.parameters, session._tenant)
    options = state.execution_options
    if (set(options) - {'synchronize_session', 'autoflush', 'prebuffer_rows', 'dml_strategy',
                       '_sa_orm_update_options', '_result_disable_adapt_to_context'} or
            options.get('synchronize_session') is not False or
            any(type(options[name]) is not bool for name in ('autoflush', 'prebuffer_rows') if name in options) or
            options.get('dml_strategy', 'bulk') not in ('auto', 'bulk')):
        raise UnsupportedProtectedOperation()
    native = options.get('_sa_orm_update_options')
    if (native is None or native._subject_mapper is not mapper or native._dml_strategy != 'bulk' or
            native._synchronize_session is not False):
        raise UnsupportedProtectedOperation()
    material = session._keys()
    current = _capture_update(owner, mapper, statement, state.parameters, session._tenant)
    if not _same_update_request(request, current):
        raise UnsupportedProtectedOperation()
    table, tenant = request.table, request.tenant
    columns, rows = dict(request.columns), [dict(row) for row in request.rows]
    bindings = owner.models[mapper.class_]
    first = bindings[0]
    operation = _Operation(owner, material, tenant, session, bulk_update=table)
    ledger = []
    for row in rows:
        record = row[first.record_attribute]
        for binding in bindings:
            if binding.attribute in row:
                try:
                    stored = _assignment(row[binding.attribute], binding)
                except (VarcharLengthExceeded, TypeError, ValueError) as failure:
                    if binding.boolean_processor is None and not isinstance(failure, VarcharLengthExceeded):
                        raise
                    sealed = _Sealed(_VARCHAR_UPDATE_INVALID if type(failure) is VarcharLengthExceeded else None,
                                     operation, binding, failure, record, tenant)
                else:
                    body = seal_value(stored, binding.descriptor, tenant, record, operation.keys)
                    sealed = _Sealed(body, operation, binding, record=record, tenant=tenant)
                operation.bulk_seals[id(sealed)] = sealed
                row[binding.attribute] = sealed
        values = {columns[attribute].key: value for attribute, value in row.items()
                  if attribute != first.record_attribute}
        if values:
            ledger.append((record, values))
    operation.bulk_inputs = tuple(ledger)
    original_parameters = state.parameters
    state.update_execution_options(compiled_cache=None)
    token = _operation.set(operation)
    try:
        state.parameters = rows
        result = state.invoke_statement()
        if operation.bulk_position != len(operation.bulk_inputs):
            raise UnsupportedProtectedOperation()
        return result
    except DBAPIError as error:
        if getattr(error.orig, 'sqlstate', None) == '22001' and operation.update_carrier is not None:
            for row in operation.bulk_batch:
                for value in row.values():
                    if (type(value) is _Sealed and operation.bulk_seals.get(id(value)) is value and
                            type(value.failure) is VarcharLengthExceeded):
                        raise value.failure from None
        raise
    finally:
        state.parameters = original_parameters
        operation.bulk_seals.clear()
        operation.bulk_batch = operation.bulk_inputs = ()
        operation.update_carrier = None
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
        statement = args[0] if args else kwargs.get('statement')
        permit = request = None
        if isinstance(statement, Delete):
            if name != 'execute':
                raise UnsupportedProtectedOperation()
            session = self.sync_session
            session._owner._check_configuration()
            permit, _, _ = session._owner.delete_context(statement, session._tenant)
        if isinstance(statement, Update):
            if name != 'execute':
                raise UnsupportedProtectedOperation()
            session = self.sync_session
            session._owner._check_configuration()
            parameters = args[1] if len(args) > 1 else kwargs.get('params')
            request = _capture_update(session._owner, statement._propagate_attrs.get('plugin_subject'),
                                      statement, parameters, session._tenant)
        try:
            await self._prepare()
            if permit is not None:
                if session._tenant != permit.tenant:
                    raise UnsupportedProtectedOperation()
                session._owner.delete_context(statement, permit.tenant, permit)
            if request is not None:
                current = _capture_update(session._owner, request.mapper, statement, parameters, session._tenant)
                if not _same_update_request(request, current):
                    raise UnsupportedProtectedOperation()
            return await native(self, *args, **kwargs)
        finally:
            permit = request = None
    return method


for _name in ("execute", "scalar", "scalars", "stream", "stream_scalars", "get", "get_one", "flush", "commit", "refresh", "merge", "delete", "run_sync"):
    setattr(_AsyncSession, _name, _async_method(_name))


class _Factory:
    _sync_session = _Session

    def __init__(self, owner):
        self._owner = owner

    def __call__(self, *, tenant_id, **options):
        if any(k in options for k in ("bind", "binds", "class_", "sync_session_class", "_owner", "_asynchronous")):
            raise UnsupportedProtectedOperation()
        self._owner._ring(tenant_id)
        cls = _AsyncSession if isinstance(self._owner.engine, AsyncEngine) else self._sync_session
        return cls(bind=self._owner.engine, _owner=self._owner, tenant_id=tenant_id, **options)


def attach(mapping: registry, engine: Engine | AsyncEngine, *, lock: bytes, keys, deployment=None):
    """Attach an already protected target. Await this call for an AsyncEngine.

    Schema transition is not performed. The host authenticates the lock and the
    tenant passed to the returned factory. ORM flush and bounded mapped
    dictionary INSERT, tenant-scoped TEXT UPDATE, and single-record tenant-scoped
    DELETE writes are admitted. Mapped DELETE requires execute() with explicit
    tenant/record equality and synchronize_session=False, without RETURNING.

    ``deployment`` is ``(plan, pin)`` or ``(plan, pin, restore_binding)``. The
    third element is an adopted ``cryptalis.restore/v1`` binding when the
    target is a restored protected copy.
    """
    try:
        document = decode_manifest_json(lock)
        if (not isinstance(mapping, registry) or not isinstance(engine, (Engine, AsyncEngine)) or
                document["schema"] not in ("cryptalis.lock/v1", "cryptalis.lock/v2", "cryptalis.lock/v3", "cryptalis.lock/v4") or document["profile"] != "cf1"):
            raise PolicyMismatch()
        native_engine = engine.sync_engine if isinstance(engine, AsyncEngine) else engine
        if native_engine.echo or not native_engine.hide_parameters:
            raise UnsafeEngineLogging()
        if tuple(native_engine.dispatch.before_cursor_execute):
            raise UnsafeDriverEvent()
        _previous_lock(lock, document, native_engine)
        owner = _Attachment(mapping, engine, document, keys, deployment)
    except CryptoFailure:
        raise
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
