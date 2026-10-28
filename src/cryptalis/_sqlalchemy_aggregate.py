"""Finite native count projections over directly protected columns."""
from types import MethodType

from sqlalchemy import Column, Integer
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import (
    BinaryExpression,
    BindParameter,
    BooleanClauseList,
    ClauseList,
    ColumnClause,
    Grouping,
    Label,
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
    )
    dispatch = selection._compiler_dispatch
    if (type(dispatch) is not MethodType or dispatch.__self__ is not selection
            or dispatch.__func__ is not Select._original_compiler_dispatch):
        raise UnsupportedProtectedOperation()

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
    if not isinstance(expression, count):
        return None
    arguments = tuple(expression.clauses)
    if len(arguments) != 1:
        return None
    column = arguments[0]
    distinct = isinstance(column, UnaryExpression) and column.operator is operators.distinct_op
    if distinct:
        if column.modifier is not None:
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
    return expression, bindings[0], column, distinct
