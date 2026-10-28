"""Finite native count projections over directly protected columns."""
from sqlalchemy import Column, Integer
from sqlalchemy.sql import operators
from sqlalchemy.sql.elements import ClauseList, ColumnClause, Grouping, Label
from sqlalchemy.sql.functions import count


def count_shape(owner, expression):
    wrappers = []
    while isinstance(expression, (Label, Grouping)):
        wrappers.append((expression, Label if isinstance(expression, Label) else Grouping))
        expression = expression.element
    if not isinstance(expression, count):
        return None
    arguments = tuple(expression.clauses)
    if len(arguments) != 1 or not isinstance(arguments[0], ColumnClause) or arguments[0].is_literal:
        return None
    column = arguments[0]
    bindings = [binding for binding in owner.bindings if column.shares_lineage(binding.column)]
    if len(bindings) != 1:
        return None
    from .sqlalchemy import UnsupportedProtectedOperation, _delete_node
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
    return expression, bindings[0], column
