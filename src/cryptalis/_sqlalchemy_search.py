"""Bounded equality and order admission, deferred terms, and native index validation."""

from sqlalchemy import BigInteger, Boolean, Date, DateTime, Integer, LargeBinary, SmallInteger, String, Table, Text, TEXT, Unicode, UnicodeText, Uuid, VARCHAR, and_, or_, bindparam, func, literal, literal_column, type_coerce
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter, BooleanClauseList, ColumnClause, Grouping, Label, Null, UnaryExpression
from sqlalchemy.sql.functions import count
from sqlalchemy.sql.selectable import Alias, Select
from sqlalchemy.types import NullType, TypeDecorator

from .crypto.cf1 import equality_term
from .manifest.compiler import _catalog_path, _fixed_value_width
from ._sqlmodel_types import autostring_impl
from ._sqlalchemy_aggregate import _one_tenant, count_shape, distinct_projection, identity_distinct, extrema_shape


_NULL_SAFE = (operators.is_distinct_from, operators.is_not_distinct_from)
_ORDER_OPERATORS = (operators.lt, operators.le, operators.gt, operators.ge)
_SORT_MODIFIERS = (operators.asc_op, operators.desc_op, operators.nulls_first_op, operators.nulls_last_op)


class _SearchValue(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, binding, operation):
        super().__init__()
        self.binding, self.keys, self.tenant = binding, operation.keys_for(binding), operation.scope(binding)

    def process_bind_param(self, value, dialect):
        return equality_term(value, self.binding.descriptor, self.tenant, self.keys)


def ordinary_bind(owner, value):
    if getattr(value.type, '_variant_mapping', None):
        return False
    if type(value.type) in (DateTime, TIMESTAMP) and value.type.timezone is not False:
        # A native timestamptz cast can change comparison semantics across DST.
        return False
    try:
        optional_string = autostring_impl(value.type) is not None
    except ValueError:
        return False
    if type(value.type) in (Integer, SmallInteger, BigInteger, Date, DateTime, TIMESTAMP):
        # The field codec refuses any value the column could not hold.
        return any(binding.descriptor.ordered for binding in owner.bindings)
    return (optional_string or type(value.type) in (String, Text, TEXT, Unicode, UnicodeText, VARCHAR, NullType) or
            any(type(value.type) is type(binding.column.type) for binding in owner.bindings))


def search_shape(owner, expression, *, _nullsafe_candidate=False):
    """Only a direct declared column and a typed/deferred value are admitted."""
    # Internal qualification can exercise this implementation. Normal attachment
    # cannot admit a new operator before the six capability gates pass.
    null_safe = _NULL_SAFE if _nullsafe_candidate is True else ()
    if not isinstance(expression, BinaryExpression):
        return None
    left, right = expression.left, expression.right
    if (expression.operator in (operators.eq, operators.ne, *null_safe) and isinstance(left, BindParameter) or
            expression.operator in null_safe and isinstance(left, Null)):
        left, right = right, left
    if not isinstance(left, ColumnClause) or left.is_literal:
        return None
    bindings = [binding for binding in owner.bindings if left.shares_lineage(binding.column)]
    if len(bindings) != 1:
        return None
    # Rewriting must not discard a custom renderer's native SQL semantics.
    # Reuse exact native/annotated dispatch admission before resolving keys.
    from .sqlalchemy import _delete_node
    _delete_node(expression, BinaryExpression)
    null = expression.operator in (operators.is_, operators.is_not, *null_safe) and isinstance(right, Null)
    if not null and not bindings[0].descriptor.equality:
        return None
    ordered = expression.operator in _ORDER_OPERATORS and bindings[0].descriptor.ordered
    if not null and not ((ordered or expression.operator in (operators.eq, operators.ne, operators.in_op, operators.not_in_op, *null_safe))
                         and isinstance(right, BindParameter)):
        return None
    if not null and not ordinary_bind(owner, right):
        return None
    if not null and right.callable is not None:
        return None
    if expression.operator in (operators.in_op, operators.not_in_op) and not right.expanding:
        return None
    if expression.operator in _NULL_SAFE and isinstance(right, BindParameter) and right.expanding:
        return None
    return bindings[0], left, right, null


def between_predicate(owner, expression):
    """Return native BETWEEN as its defining comparisons, or None when not admitted."""
    if (not isinstance(expression, BinaryExpression) or expression.modifiers.get('symmetric')
            or expression.operator not in (operators.between_op, operators.not_between_op)):
        return None
    lower, upper = expression.right.clauses
    within = expression.operator is operators.between_op
    first = BinaryExpression(expression.left, lower, operators.ge if within else operators.lt, type_=expression.type)
    second = BinaryExpression(expression.left, upper, operators.le if within else operators.gt, type_=expression.type)
    if search_shape(owner, first) is None or search_shape(owner, second) is None:
        return None
    return and_(first, second) if within else or_(first, second)


def order_shape(owner, clause, selection):
    """One direct order-searchable column under native sort modifiers and one tenant.

    Terms use per-tenant keys, so they sort meaningfully only within one tenant.
    """
    from .sqlalchemy import _delete_node
    root = clause
    while isinstance(root, UnaryExpression) and root.operator is None and root.modifier in _SORT_MODIFIERS:
        _delete_node(root, UnaryExpression)
        root = root.element
    if not isinstance(root, ColumnClause) or root.is_literal or selection._group_by_clauses or selection._distinct:
        return None
    bindings = [binding for binding in owner.bindings if root.shares_lineage(binding.column)]
    if len(bindings) != 1 or not bindings[0].descriptor.ordered or not _one_tenant(selection, root, bindings[0].tenant):
        return None
    return bindings[0], root


def equality_expression(column):
    """Match the frozen equality index in both custom and generic PG plans."""
    return func.pg_catalog.substring(type_coerce(column, LargeBinary()),
                                     literal_column("15"), literal_column("32"), type_=LargeBinary())


def boolean_children(expression):
    """Inspect native Boolean containers before rewriting any protected child."""
    from .sqlalchemy import _delete_node, UnsupportedProtectedOperation
    if isinstance(expression, BooleanClauseList):
        native = _delete_node(expression, BooleanClauseList)
        if (expression.operator not in (operators.and_, operators.or_)
                or expression.operator is not native.operator
                or expression.clauses is not native.clauses
                or type(expression.type) is not Boolean or expression.type is not native.type):
            raise UnsupportedProtectedOperation()
        return expression.clauses
    if isinstance(expression, UnaryExpression):
        native = _delete_node(expression, UnaryExpression)
        if (expression.operator is not operators.inv or native.operator is not operators.inv
                or expression.modifier is not None or native.modifier is not None
                or expression.element is not native.element
                or type(expression.type) not in (Boolean, NullType) or expression.type is not native.type):
            raise UnsupportedProtectedOperation()
        return (expression.element,)
    if isinstance(expression, Grouping):
        native = _delete_node(expression, Grouping)
        if expression.element is not native.element or expression.type is not native.type:
            raise UnsupportedProtectedOperation()
        return (expression.element,)
    return None


def _normalize_negation(owner, expression):
    """Push NOT through admitted predicates before adding positive tenant guards.

    Use SQL's three-valued De Morgan identities and explicit native operator
    pairs. Caller-mutable ``negate`` metadata is not rewrite authority.
    Public subexpressions retain their original SQL under a native NOT wrapper.
    """
    inverse = {operators.eq: operators.ne, operators.ne: operators.eq,
               operators.in_op: operators.not_in_op, operators.not_in_op: operators.in_op,
               operators.is_: operators.is_not, operators.is_not: operators.is_,
               operators.lt: operators.ge, operators.ge: operators.lt,
               operators.gt: operators.le, operators.le: operators.gt}

    def normalize(node, negate=False):
        if not owner.protected(node):
            return UnaryExpression(node.self_group(), operator=operators.inv) if negate else node
        children = boolean_children(node)
        if isinstance(node, Grouping):
            return normalize(children[0], negate)
        if isinstance(node, UnaryExpression):
            return normalize(children[0], not negate)
        if isinstance(node, BooleanClauseList):
            conjunction = (node.operator is operators.and_) != negate
            return (and_ if conjunction else or_)(*(normalize(child, negate) for child in children))
        between = between_predicate(owner, node)
        if between is not None:
            return normalize(between, negate)
        if search_shape(owner, node) is None:
            from .sqlalchemy import UnsupportedProtectedOperation
            raise UnsupportedProtectedOperation()
        return BinaryExpression(node.left, node.right, inverse[node.operator], type_=node.type) if negate else node

    return normalize(expression)


def rewrite_search(owner, statement, operation):
    identity = identity_distinct(owner, statement)
    distinct = distinct_projection(owner, statement) if identity is None else None
    outputs = tuple(statement.selected_columns) if identity is not None or distinct is not None else ()
    projections = {id(output) for output in outputs}
    for output in statement.selected_columns:
        root = output
        while isinstance(root, (Label, Grouping)):
            root = root.element
        if isinstance(root, (BinaryExpression, BooleanClauseList, UnaryExpression)) and owner.protected(root):
            # Keep the original expression in SQLAlchemy's ORM result metadata.
            # The owned compiler rewrites its SQL using the same token path.
            projections.add(id(output))
    # SQLAlchemy merges named placeholders. Multiple definitions without an
    # explicit value have compiler-dependent default precedence, outside this
    # bounded grammar. A shared bind object and supplied values are unambiguous.
    inputs = {}
    search_keys = set()
    for node in visitors.iterate(statement):
        if isinstance(node, BindParameter):
            inputs.setdefault(node.key, {})[id(node)] = node
        between = between_predicate(owner, node)
        for candidate in (node,) if between is None else between.clauses:
            shape = search_shape(owner, candidate)
            if shape is not None and not shape[3]:
                search_keys.add(shape[2].key)
    ambiguous = any(len(inputs[key]) > 1 and key not in operation.parameters for key in search_keys)
    codec_collision = any(not ordinary_bind(owner, value) or value.callable is not None
                          for key in search_keys for value in inputs[key].values())
    generated_names = search_keys and any(key not in inputs for key in operation.parameters)
    if ambiguous or codec_collision or generated_names:
        from .sqlalchemy import UnsupportedProtectedOperation
        raise UnsupportedProtectedOperation()

    rewritten = visitors.replacement_traverse(statement, {}, _predicate_replacer(owner, statement, operation, projections))
    if isinstance(statement, Select) and any(owner.protected(clause) for clause in statement._order_by_clauses):
        # Rewrite the sort list directly. A bare sort column can be the very object
        # selected as output, so replacing it during traversal would corrupt results.
        clauses = [plain if term is None else term for term, plain in (
            (_order_term_clause(owner, original, statement, operation), plain)
            for original, plain in zip(statement._order_by_clauses, rewritten._order_by_clauses, strict=True))]
        rewritten = rewritten.order_by(None).order_by(*clauses)
    return rewritten


def _order_term_clause(owner, clause, selection, operation):
    shape = order_shape(owner, clause, selection) if owner.protected(clause) else None
    if shape is None:
        return None
    column = shape[1]
    rewritten = visitors.replacement_traverse(clause, {}, lambda part: equality_expression(part) if part is column else None)
    nodes = tuple(visitors.iterate(rewritten))
    operation.search_nodes.extend(nodes)
    operation.search_identities.update((id(node), node) for node in nodes)
    return rewritten


def rewrite_predicate(owner, expression, statement, operation):
    """Compile an admitted predicate without replacing its public result key."""
    rewritten = visitors.replacement_traverse(expression, {}, _predicate_replacer(owner, statement, operation, ()))
    # Include the composed root, so compiler recursion never rewrites a guard.
    nodes = tuple(visitors.iterate(rewritten))
    operation.search_nodes.extend(nodes)
    operation.search_identities.update((id(node), node) for node in nodes)
    return rewritten


def _predicate_replacer(owner, statement, operation, projections):
    from .sqlalchemy import _projection_column

    def replace(node):
        if isinstance(node, Alias):
            source = node.element
            while isinstance(source, Alias):
                source = source.element
            if isinstance(source, Table):
                # Retained projections and rewritten predicates must keep the
                # same exact FROM identity, including nested native aliases.
                return node
        if isinstance(node, (Label, Grouping)) and _projection_column(node) is not None:
            # A direct projection contains no predicate to rewrite. Preserve
            # the caller's native expression identity in ORM result metadata.
            return node
        # Counts have no search predicates inside their admitted arguments.
        # Keep their identity so ORM result mappings retain expression keys.
        if (id(node) in projections or isinstance(node, count) or count_shape(owner, node, statement) is not None
                or extrema_shape(owner, node, statement) is not None):
            return node
        if isinstance(node, UnaryExpression) and node.operator is operators.inv and owner.protected(node):
            # Rewrite only the normalized subtree. A separate whole-statement
            # clone would discard aggregate/projection expression result keys.
            return visitors.replacement_traverse(_normalize_negation(owner, node), {}, replace)
        between = between_predicate(owner, node)
        if between is not None:
            return visitors.replacement_traverse(between, {}, replace)
        shape = search_shape(owner, node)
        if shape is None:
            return None
        binding, column, value, null = shape
        physical = type_coerce(column, LargeBinary())
        if null:
            predicate = physical.is_(None) if node.operator in (operators.is_, operators.is_not_distinct_from) else physical.is_not(None)
        else:
            # Fixed offsets must be SQL constants, so PostgreSQL generic plans
            # match the expression index as well as custom plans.
            term = equality_expression(column)
            # A separate placeholder per occurrence preserves shared named binds
            # across fields and native expressions, which use different codecs.
            supplied = value.key in operation.parameters
            prepared = bindparam(None, value=operation.parameters[value.key] if supplied else value.value,
                                 type_=_SearchValue(binding, operation), required=False if supplied else value.required,
                                 expanding=value.expanding, callable_=None if supplied else value.callable)
            predicate = BinaryExpression(term, prepared, node.operator)
        if binding.tenant is not None:
            tenant_column = column.table.c[binding.tenant.key]
            scope = tenant_column == literal(operation.scope(binding), Uuid())
            if null or node.operator in (operators.not_in_op, *_NULL_SAFE):
                # Empty NOT IN is TRUE even on a null-extended row.
                # NULL-safe predicates can also be TRUE on an absent row.
                # Attachment validates the record column as a non-null primary
                # key. Its NULL value identifies an absent outer-joined row,
                # whose IS NULL result must remain TRUE. Resolve the key by
                # lineage, never by a possibly ambiguous joined-column name.
                records = [candidate for candidate in column.table.c
                           if candidate.shares_lineage(binding.record)]
                if len(records) != 1:
                    from .sqlalchemy import UnsupportedProtectedOperation
                    raise UnsupportedProtectedOperation()
                scope = or_(records[0].is_(None), scope)
            predicate = and_(scope, predicate)
        # Admit these generated nodes and SQLAlchemy's structural clones only
        # within this operation. Original SQL is admitted before rewriting.
        # Caller-supplied execution options cannot manufacture this permit.
        nodes = tuple(visitors.iterate(predicate))
        operation.search_nodes.extend(nodes)
        operation.search_identities.update((id(node), node) for node in nodes)
        return predicate
    return replace


def validate_search_storage(connection, model, field, *, admitted=None):
    """Accept only the selected PG16 expression and validated framing check.

    No write, SQL parser, extension, or permission change occurs here. Strict
    catalog definitions are deliberate: an equivalent unqualified variant
    must be inspected and admitted before it becomes a compatibility cell.

    ``admitted`` is an inspected restatement from an adopted
    ``cryptalis.restore/v1`` binding. The live definition must equal the
    adopted text exactly and belong to the declared policy's known PG16 forms.
    Adoption also checks malformed frames with savepoint probes.
    """
    with _catalog_path(connection):
        _validate_search_storage(connection, model, field)
        _validate_frame_storage(connection, model, field, admitted=admitted)


def _validate_search_storage(connection, model, field):
    target = connection.dialect.identifier_preparer.quote_identifier(model["schema"]) + "." + connection.dialect.identifier_preparer.quote_identifier(model["table"])
    suffix = field["field_id"].replace("-", "")
    index = connection.exec_driver_sql("""
        SELECT pg_catalog.quote_ident(%s),
               i.indisunique, i.indisvalid, i.indisready, i.indislive,
               i.indimmediate, i.indnullsnotdistinct, i.indpred IS NULL,
               am.amname, i.indnkeyatts, i.indnatts,
               pg_catalog.pg_get_expr(i.indexprs, i.indrelid),
               ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY k(attnum,n)
                     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY n),
               ARRAY(SELECT n.nspname || '.' || o.opcname FROM unnest(i.indclass) WITH ORDINALITY k(op,n)
                     JOIN pg_catalog.pg_opclass o ON o.oid=k.op JOIN pg_catalog.pg_namespace n ON n.oid=o.opcnamespace ORDER BY k.n),
               ARRAY(SELECT c FROM unnest(i.indcollation) c),
               ARRAY(SELECT o FROM unnest(i.indoption) o)
        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class ix ON ix.oid=i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid=ix.relam
        WHERE i.indrelid=pg_catalog.to_regclass(%s) AND ix.relname=%s
        """, (field["column"], target, "_cryptalis_" + suffix + "_eq")).one_or_none()
    if index is None:
        raise ValueError("Unqualified search index")
    # Match PostgreSQL deparser spelling without an extra catalog round trip.
    column, *index = index
    scoped = "column" in model["tenancy"]
    count = 2 if scoped else 1
    columns = [model["tenancy"]["column"], None] if scoped else [None]
    opclasses = ["pg_catalog.uuid_ops", "pg_catalog.bytea_ops"] if scoped else ["pg_catalog.bytea_ops"]
    expected = ("unique" in field["queries"], True, True, True, True, False, True, "btree", count, count,
                f'"substring"({column}, 15, 32)', columns, opclasses, [0] * count, [0] * count)
    if tuple(index) != expected:
        raise ValueError("Unqualified search index")


def validate_frame_storage(connection, model, field, *, admitted=None):
    """Inspect the exact declared CF1 check, including storage-only fields."""
    with _catalog_path(connection):
        _validate_frame_storage(connection, model, field, admitted=admitted)


def _frame_expressions(field, quote):
    """Known PG16 forms of one declared CF1 policy, including dump/restore."""
    # Keep the original nested/flattened pair first. Every alternative spells
    # the same identifier through the supplied native PostgreSQL preparer.
    columns = dict.fromkeys((quote(field['column']),
                             quote.__self__.quote_identifier(field['column'])))
    overhead = 74 if field['queries'] else 42
    width = _fixed_value_width(field['source'])
    minimum, maximum = (overhead + width, overhead + width) if width is not None else (overhead, 16777216 + overhead)
    magic = '434631000101' if field['queries'] else '434631000100'
    comparison = '<>' if field['queries'] else '='
    forms = []
    for column in columns:
        terms = [f'(octet_length({column}) >= {minimum})',
                 f'(octet_length({column}) <= {maximum})',
                 f"(\"substring\"({column}, 1, 6) = decode('{magic}'::text, 'hex'::text))",
                 f"(\"substring\"({column}, 7, 4) <> decode('00000000'::text, 'hex'::text))",
                 f"(\"substring\"({column}, 11, 4) {comparison} decode('00000000'::text, 'hex'::text))"]
        nested = f'({terms[0]} AND {terms[1]}) AND ' + ' AND '.join(terms[2:])
        flattened = ' AND '.join(terms)
        forms.extend(f'(({column} IS NULL) OR ({body}))' for body in (nested, flattened))
    return tuple(forms)


def _validate_frame_storage(connection, model, field, *, admitted=None):
    quote = connection.dialect.identifier_preparer.quote
    target = connection.dialect.identifier_preparer.quote_identifier(model['schema']) + '.' + connection.dialect.identifier_preparer.quote_identifier(model['table'])
    suffix = field['field_id'].replace('-', '')
    check = connection.exec_driver_sql("""
        SELECT c.convalidated, c.connoinherit, pg_catalog.pg_get_expr(c.conbin, c.conrelid),
               ARRAY(SELECT a.attname FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY k(attnum,n)
                     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
                     ORDER BY k.n)
        FROM pg_catalog.pg_constraint c WHERE c.conrelid=pg_catalog.to_regclass(%s)
        AND c.conname=%s AND c.contype='c'
        """, (target, "_cryptalis_" + suffix + "_frame")).one_or_none()
    if check is None or (check[0], check[1], check[3]) != (True, False, [field['column']]):
        raise ValueError('Unqualified framing check')
    forms = _frame_expressions(field, quote)
    if admitted is not None and admitted not in forms:
        raise ValueError('Unqualified framing check')
    # Keep ordinary admission nested-only; a restored flattened expression
    # still needs its exact separately inspected restatement.
    expected_checks = forms[::2] if admitted is None else (admitted,)
    if check[2] not in expected_checks:
        raise ValueError("Unqualified framing check")
