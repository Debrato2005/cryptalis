"""Bounded equality admission, deferred terms, and native index validation."""

from sqlalchemy import LargeBinary, String, Text, Unicode, UnicodeText, Uuid, and_, bindparam, func, literal, literal_column, type_coerce
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, ColumnClause, Null
from sqlalchemy.types import NullType, TypeDecorator

from .crypto.cf1 import equality_term


class _SearchValue(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, binding, operation):
        super().__init__()
        self.binding, self.keys, self.tenant = binding, operation.keys, operation.tenant

    def process_bind_param(self, value, dialect):
        return equality_term(value, self.binding.descriptor, self.tenant, self.keys)


def ordinary_bind(owner, value):
    return (type(value.type) in (String, Text, Unicode, UnicodeText, NullType) or
            any(type(value.type) is type(binding.column.type) for binding in owner.bindings))


def search_shape(owner, expression):
    """Only a direct declared column and a typed/deferred value are admitted."""
    if not isinstance(expression, BinaryExpression):
        return None
    left, right = expression.left, expression.right
    if expression.operator is operators.eq and isinstance(left, BindParameter):
        left, right = right, left
    if not isinstance(left, ColumnClause) or left.is_literal:
        return None
    bindings = [binding for binding in owner.bindings if left.shares_lineage(binding.column)]
    if len(bindings) != 1 or not bindings[0].descriptor.equality:
        return None
    null = expression.operator is operators.is_ and isinstance(right, Null)
    if not null and not (expression.operator in (operators.eq, operators.in_op) and isinstance(right, BindParameter)):
        return None
    if not null and not ordinary_bind(owner, right):
        return None
    if not null and right.callable is not None:
        return None
    if expression.operator is operators.in_op and not right.expanding:
        return None
    return bindings[0], left, right, null


def rewrite_search(owner, statement, operation):
    # SQLAlchemy merges named placeholders. Multiple definitions without an
    # explicit value have compiler-dependent default precedence, outside this
    # bounded grammar. A shared bind object and supplied values are unambiguous.
    inputs = {}
    search_keys = set()
    for node in visitors.iterate(statement):
        if isinstance(node, BindParameter):
            inputs.setdefault(node.key, {})[id(node)] = node
        shape = search_shape(owner, node)
        if shape is not None and not shape[3]:
            search_keys.add(shape[2].key)
    ambiguous = any(len(inputs[key]) > 1 and key not in operation.parameters for key in search_keys)
    codec_collision = any(not ordinary_bind(owner, value) or value.callable is not None
                          for key in search_keys for value in inputs[key].values())
    generated_names = search_keys and any(key not in inputs for key in operation.parameters)
    if ambiguous or codec_collision or generated_names:
        from .sqlalchemy import UnsupportedProtectedOperation
        raise UnsupportedProtectedOperation()

    def replace(node):
        shape = search_shape(owner, node)
        if shape is None:
            return None
        binding, column, value, null = shape
        physical = type_coerce(column, LargeBinary())
        if null:
            predicate = physical.is_(None)
        else:
            # Fixed offsets must be SQL constants, so PostgreSQL generic plans
            # match the expression index as well as custom plans.
            term = func.pg_catalog.substring(physical, literal_column("15"), literal_column("32"), type_=LargeBinary())
            # A separate placeholder per occurrence preserves shared named binds
            # across fields and native expressions, which use different codecs.
            supplied = value.key in operation.parameters
            prepared = bindparam(None, value=operation.parameters[value.key] if supplied else value.value,
                                 type_=_SearchValue(binding, operation), required=False if supplied else value.required,
                                 expanding=value.expanding, callable_=None if supplied else value.callable)
            predicate = BinaryExpression(term, prepared, node.operator)
        if binding.tenant is not None:
            tenant_column = column.table.c[binding.tenant.key]
            predicate = and_(tenant_column == literal(operation.tenant, Uuid()), predicate)
        # Admit these generated nodes and SQLAlchemy's structural clones only
        # within this operation. Original SQL is admitted before rewriting.
        # Caller-supplied execution options cannot manufacture this permit.
        nodes = tuple(visitors.iterate(predicate))
        operation.search_nodes.extend(nodes)
        operation.search_identities.update((id(node), node) for node in nodes)
        return predicate
    return visitors.replacement_traverse(statement, {}, replace)


def validate_search_storage(connection, model, field):
    """Accept only the selected PG16 expression and validated framing check.

    No write, SQL parser, extension, or permission change occurs here. Strict
    catalog definitions are deliberate: an equivalent unqualified variant
    must be inspected and admitted before it becomes a compatibility cell.
    """
    # Catalog deparsing must qualify functions from every untrusted schema.
    # The attachment connection rolls this transaction-local setting back.
    connection.exec_driver_sql("SET LOCAL search_path = pg_catalog")
    quote = connection.dialect.identifier_preparer.quote
    target = connection.dialect.identifier_preparer.quote_identifier(model["schema"]) + "." + connection.dialect.identifier_preparer.quote_identifier(model["table"])
    column = quote(field["column"])
    suffix = field["field_id"].replace("-", "")
    index = connection.exec_driver_sql("""
        SELECT i.indisunique, i.indisvalid, i.indisready, i.indislive,
               i.indimmediate, i.indnullsnotdistinct, i.indpred IS NULL,
               am.amname, i.indnkeyatts, i.indnatts,
               pg_catalog.pg_get_expr(i.indexprs, i.indrelid),
               ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n)
                     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY n),
               ARRAY(SELECT n.nspname || '.' || o.opcname FROM unnest(i.indclass) WITH ORDINALITY k(op,n)
                     JOIN pg_catalog.pg_opclass o ON o.oid=k.op JOIN pg_catalog.pg_namespace n ON n.oid=o.opcnamespace ORDER BY k.n),
               ARRAY(SELECT c FROM unnest(i.indcollation) c)
        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ix ON ix.oid=i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid=ix.relam
        WHERE i.indrelid=pg_catalog.to_regclass(%s) AND ix.relname=%s
        """, (target, "_cryptalis_" + suffix + "_eq")).one_or_none()
    scoped = "column" in model["tenancy"]
    count = 2 if scoped else 1
    columns = [model["tenancy"]["column"], None] if scoped else [None]
    opclasses = ["pg_catalog.uuid_ops", "pg_catalog.bytea_ops"] if scoped else ["pg_catalog.bytea_ops"]
    expected = ("unique" in field["queries"], True, True, True, True, False, True, "btree", count, count,
                f'"substring"({column}, 15, 32)', columns, opclasses, [0] * count)
    if index is None or tuple(index) != expected:
        raise ValueError("Unqualified search index")
    check = connection.exec_driver_sql("""
        SELECT convalidated, connoinherit, pg_catalog.pg_get_expr(conbin, conrelid)
        FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass(%s)
        AND conname=%s AND contype='c'
        """, (target, "_cryptalis_" + suffix + "_frame")).one_or_none()
    expected_check = (
        f"(({column} IS NULL) OR (((octet_length({column}) >= 74) AND (octet_length({column}) <= 16777290)) "
        f"AND (\"substring\"({column}, 1, 6) = decode('434631000101'::text, 'hex'::text)) "
        f"AND (\"substring\"({column}, 7, 4) <> decode('00000000'::text, 'hex'::text)) "
        f"AND (\"substring\"({column}, 11, 4) <> decode('00000000'::text, 'hex'::text))))"
    )
    if check is None or tuple(check) != (True, False, expected_check):
        raise ValueError("Unqualified framing check")
