"""M5 supplement: public expression validation and real PostgreSQL truth/error cases."""
import json
from pathlib import Path
import psycopg
from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table, and_, cast, func, or_
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import (BinaryExpression, BindParameter, BooleanClauseList,
                                     False_, Null, True_, UnaryExpression)


class UnsupportedProtectedQuery(Exception): pass


table = Table("logical_fixture", MetaData(), Column("email", String, info={"protected": True}),
              Column("denominator", Integer), Column("active", Boolean))


def validate(node):
    if isinstance(node, (True_, False_, Null)): return
    if isinstance(node, BooleanClauseList) and node.operator in (operators.and_, operators.or_):
        for child in node.clauses: validate(child)
        return
    if isinstance(node, UnaryExpression) and node.operator is operators.inv:
        # Plain NOT only. Recursively reject any protected leaf.
        if any(getattr(x, "info", {}).get("protected") for x in visitors.iterate(node)):
            raise UnsupportedProtectedQuery("Protected negation")
        validate(node.element); return
    if isinstance(node, BinaryExpression) and isinstance(node.left, Column):
        protected = node.left.info.get("protected", False)
        allowed = (operators.eq, operators.in_op, operators.is_, operators.is_not)
        if not protected: allowed += (operators.ne, operators.lt, operators.le, operators.gt, operators.ge)
        if node.operator not in allowed: raise UnsupportedProtectedQuery("Unknown operator")
        if isinstance(node.right, Null): return
        if isinstance(node.right, (True_, False_)):
            if protected or not isinstance(node.left.type, Boolean):
                raise UnsupportedProtectedQuery("Boolean predicate on non-Boolean")
            return
        if not isinstance(node.right, BindParameter): raise UnsupportedProtectedQuery("Expression RHS")
        values = list(node.right.value) if node.right.expanding else [node.right.value]
        if len(values) > 1000: raise UnsupportedProtectedQuery("Bind budget")
        wanted = str if isinstance(node.left.type, String) else bool if isinstance(node.left.type, Boolean) else int
        if any(v is not None and type(v) is not wanted for v in values):
            raise UnsupportedProtectedQuery("Bind type")
        if wanted is int and any(v is not None and not -(2**31) <= v < 2**31 for v in values):
            raise UnsupportedProtectedQuery("Bind range")
        return
    raise UnsupportedProtectedQuery("Non-total or unclassified expression")


def main():
    email, denominator = table.c.email, table.c.denominator
    admitted = [email == "x", email.in_([]), email.in_([None]), email.in_(["x", None]),
                email.is_(None), email.is_not(None), or_(email == "x", denominator > 0),
                and_(email == "x", denominator.in_([0, 1]))]
    for expr in admitted: validate(expr)
    rejected = [or_(email == "x", 1 / denominator > 0), cast(email, Integer) == 1,
                func.lower(email) == "x", email.ilike("x"), email != "x", email.not_in(["x"]),
                email == denominator, denominator == 2**40,
                ~or_(email == "x", denominator > 0), email.is_(True)]
    for expr in rejected:
        try: validate(expr)
        except UnsupportedProtectedQuery: pass
        else: raise AssertionError("Unclassified expression admitted")
    dsn = "dbname=postgres user=debrato host=/tmp/cryptalis-hardening-postgres port=55432"
    with psycopg.connect(dsn) as conn:
        truth = conn.execute("SELECT NULL::text IN ('x',NULL), 'x' IN ('x',NULL), 'y' IN ('x',NULL), NULL::text = ANY(ARRAY[]::text[]), TRUE OR NULL::boolean, FALSE AND NULL::boolean").fetchone()
        assert truth == (None, True, None, False, True, False)
        # This shows why projecting a non-total plain atom is unsafe; the adapter rejects it before SQL.
        safe = conn.execute("SELECT id FROM (VALUES (1,'x',0)) AS v(id,email,denominator) WHERE email='x' OR 1/denominator>0").fetchall()
        assert safe == [(1,)]
    with psycopg.connect(dsn) as conn:
        try: conn.execute("SELECT 1/denominator>0 FROM (VALUES (1,'x',0)) AS v(id,email,denominator) WHERE email='x' OR 1/denominator>0").fetchall()
        except psycopg.errors.DivisionByZero: error = "HIDDEN_PROJECTION_DIVISION_ERROR"
        else: raise AssertionError("Expected forced projection error")
    result = {"status": "PASS_LOCAL_SUPPLEMENT", "admitted": len(admitted), "rejected": len(rejected),
              "three_valued_results": list(truth), "non_total_counterexample": error,
              "limits": ["small grammar subset", "not full runtime differential query oracle", "joins/complete Result unqualified"]}
    (Path(__file__).parent / "results" / "M5.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
