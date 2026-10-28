"""Finite native count projections over directly protected columns."""
from sqlalchemy import Column, Integer
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import (
    BinaryExpression,
    BindParameter,
    BooleanClauseList,
    ClauseList,
    ColumnClause,
    FunctionFilter,
    Grouping,
    Label,
    Over,
    UnaryExpression,
)
from sqlalchemy.sql.functions import count
from sqlalchemy.sql.selectable import Alias, Select


def _one_tenant(selection, column, tenant):
    if tenant is None:
        return True
    if not isinstance(selection, Select):
        return False
    from .sqlalchemy import (
        UnsupportedProtectedOperation,
        _delete_name_state,
        _delete_node,
        _select_node,
    )
    _select_node(selection)

    def scope_column(node):
        if (not isinstance(node, ColumnClause) or node.is_literal
                or node.table is not column.table or not node.shares_lineage(tenant)):
            return False
        _delete_node(node, Column if isinstance(node, Column) else ColumnClause,
                     allow_type_annotation=True)
        if _delete_name_state(node.name) != _delete_name_state(tenant.name):
            raise UnsupportedProtectedOperation()
        return True

    if any(scope_column(node) for node in selection._group_by_clauses):
        return True
    predicates = list(selection._where_criteria)
    while predicates:
        node = predicates.pop()
        if isinstance(node, Grouping):
            _delete_node(node, Grouping)
            predicates.append(node.element)
        elif isinstance(node, BooleanClauseList) and node.operator is operators.and_:
            _delete_node(node, BooleanClauseList)
            predicates.extend(node.clauses)
        elif isinstance(node, BinaryExpression) and node.operator is operators.eq:
            for left, right in ((node.left, node.right), (node.right, node.left)):
                if isinstance(right, BindParameter) and not right.expanding and scope_column(left):
                    _delete_node(node, BinaryExpression)
                    _delete_node(right, BindParameter)
                    return True
    return False


def count_shape(owner, expression, selection=None):
    wrappers = []
    while isinstance(expression, (Label, Grouping)):
        wrappers.append((expression, Label if isinstance(expression, Label) else Grouping))
        expression = expression.element
    root = expression
    window = False
    while isinstance(expression, (FunctionFilter, Over)):
        wrappers.append((expression, FunctionFilter if isinstance(expression, FunctionFilter) else Over))
        if isinstance(expression, FunctionFilter):
            if owner.protected(expression.criterion):
                return None
            expression = expression.func
        else:
            if any(part is not None and owner.protected(part)
                   for part in (expression.partition_by, expression.order_by)):
                return None
            window = True
            expression = expression.element
    if not isinstance(expression, count):
        return None
    arguments = tuple(expression.clauses)
    if len(arguments) != 1:
        return None
    column = arguments[0]
    distinct = isinstance(column, UnaryExpression) and column.operator is operators.distinct_op
    if distinct:
        if column.modifier is not None or window:
            return None
        wrappers.append((column, UnaryExpression))
        column = column.element
    if not isinstance(column, ColumnClause) or column.is_literal:
        return None
    bindings = [binding for binding in owner.bindings if column.shares_lineage(binding.column)]
    if len(bindings) != 1:
        return None
    if distinct and (not bindings[0].descriptor.equality
                     or not _one_tenant(selection, column, bindings[0].tenant)):
        return None
    from .sqlalchemy import (
        UnsupportedProtectedOperation,
        _delete_name_state,
        _delete_node,
    )
    source = column.table
    while isinstance(source, Alias):
        _delete_node(source, Alias)
        source = source.element
    if (source is not bindings[0].column.table
            or _delete_name_state(column.name) != _delete_name_state(bindings[0].column.name)):
        raise UnsupportedProtectedOperation()
    for node, native in (*wrappers, (expression, count), (expression.clause_expr, Grouping),
                         (expression.clause_expr.element, ClauseList)):
        _delete_node(node, native)
    # SELECT type admission checks hooks; an older annotation may retain Text.
    _delete_node(column, Column if isinstance(column, Column) else ColumnClause,
                 allow_type_annotation=True)
    if (type(expression.name) is not str or expression.name != 'count'
            or expression.packagenames or expression._with_ordinality
            or type(expression.type) is not Integer
            or expression.clause_expr.element.operator is not operators.comma_op):
        raise UnsupportedProtectedOperation()
    return root, bindings[0], column, distinct


def distinct_projection(owner, statement):
    if (statement._distinct is not True or statement._distinct_on
            or getattr(statement, '_pre_columns_clause', None) is not None
            or statement._order_by_clauses or statement._group_by_clauses or statement._having_criteria
            or any(part is not None for part in (statement._limit_clause, statement._offset_clause,
                                                statement._fetch_clause, statement._for_update_arg))):
        return None
    columns = tuple(statement.selected_columns)
    if len(columns) != 1:
        return None
    return _projection(owner, columns[0], statement, distinct=True)


def _projection(owner, output, statement, *, distinct):
    from .sqlalchemy import _delete_node, _Payload
    column, wrappers = output, []
    while isinstance(column, (Label, Grouping)):
        _delete_node(column, Label if isinstance(column, Label) else Grouping)
        wrappers.append(column)
        column = column.element
    if not isinstance(column, ColumnClause) or column.is_literal:
        return None
    argument = UnaryExpression(column, operator=operators.distinct_op) if distinct else column
    shape = count_shape(owner, count(argument), statement)
    if shape is None:
        return None
    payload = shape[1].column.type
    if any(node.type is not column.type and node.type is not payload for node in wrappers):
        return None
    if type(column.type) is _Payload and column.type is not payload:
        return None
    effective = _delete_node(column, Column if isinstance(column, Column) else ColumnClause,
                             allow_type_annotation=True)
    if type(payload) is _Payload and effective.type is not payload:
        return None
    return column, shape[1]


def identity_distinct(owner, statement):
    if (statement._distinct is not True or statement._distinct_on
            or getattr(statement, '_pre_columns_clause', None) is not None):
        return None
    from .sqlalchemy import (
        UnsupportedProtectedOperation,
        _delete_name_state,
        _delete_node,
    )
    roots, private = [], []
    for output in statement.selected_columns:
        column = output
        while isinstance(column, (Label, Grouping)):
            _delete_node(column, Label if isinstance(column, Label) else Grouping)
            column = column.element
        if isinstance(column, ColumnClause) and not column.is_literal:
            roots.append(column)
        if owner.protected(output):
            shape = _projection(owner, output, statement, distinct=False)
            if shape is None:
                return None
            private.append((output, *shape))
    for _, column, binding in private:
        candidates = [root for root in roots if root.table is column.table and root.shares_lineage(binding.record)]
        if not candidates:
            return None
        for candidate in candidates:
            native = _delete_node(candidate, Column if isinstance(candidate, Column) else ColumnClause,
                                  allow_type_annotation=True)
            if _delete_name_state(native.name) != _delete_name_state(binding.record.name):
                raise UnsupportedProtectedOperation()
    return tuple(private) if private else None
