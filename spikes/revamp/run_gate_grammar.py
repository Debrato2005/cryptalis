"""Offline admission regression. No database, provider or full-grammar qualification."""
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import aliased
from sqlalchemy.sql import visitors

from integration_adapter import Attachment
from integration_crypto import Failure
from plain_app import Customer


def cases():
    table = Customer.__table__
    # Only the actual expression admission hook runs. The inert connection
    # cannot execute SQL. Planner, mapping, DBAPI and provider are not qualified.
    attachment = object.__new__(Attachment)
    plan = SimpleNamespace(column=table.c.email, identity=table.c.id,
                           tenant=table.c.account_id,
                           crypto=SimpleNamespace(identity=b"F" * 16))
    attachment.plans = [plan]
    attachment.read_points = ContextVar("offline_grammar_points", default={})
    connection = SimpleNamespace(connection=SimpleNamespace(driver_connection=None))
    outcomes = {}

    def admit(statement):
        return attachment.before_execute(connection, statement, [], {}, {})[0]

    alias = table.alias("other")
    denied = {
        "protected_scalar_distinct": select(table.c.email).distinct(),
        "protected_entity_columns_distinct": select(table).distinct(),
        "protected_alias_distinct": select(alias.c.email).distinct(),
        "protected_labeled_distinct": select(table.c.email.label("address")).distinct(),
        "protected_nested_distinct": select(select(table.c.email).distinct().subquery()),
        "protected_union_member_distinct": select(table.c.email).distinct().union_all(select(table.c.email)),
        "protected_orm_entity_distinct": select(Customer).distinct(),
        "protected_orm_alias_distinct": select(aliased(Customer)).distinct(),
    }
    # Use the installed public PostgreSQL DISTINCT ON extension API.
    from sqlalchemy.dialects.postgresql import distinct_on
    denied["protected_distinct_on"] = select(table.c.id).ext(distinct_on(table.c.email))
    for name, statement in denied.items():
        try:
            admit(statement)
        except Failure as failure:
            if failure.code != "PROTECTED_SELECT_DISTINCT_NOT_ADMITTED":
                raise AssertionError(name + "_wrong_failure") from None
        else:
            raise AssertionError(name + "_accepted")
        outcomes[name] = "PASS"

    for name, statement in {
        "ordinary_protected_projection": select(table.c.email),
        "plaintext_distinct": select(table.c.account_id).distinct(),
        "plaintext_distinct_on": select(table.c.id).ext(distinct_on(table.c.account_id)),
    }.items():
        actual = admit(statement)
        if not actual.compare(statement):
            raise AssertionError(name + "_changed")
        outcomes[name] = "PASS"
    counted = admit(select(func.count(func.distinct(table.c.email))).where(table.c.account_id == 1))
    functions = [node.name for node in visitors.iterate(counted) if hasattr(node, "name")]
    if "substring" not in functions:
        raise AssertionError("scoped_count_distinct_lost_term_rewrite")
    # Compilation is local. It does not establish PostgreSQL result semantics.
    counted.compile(dialect=postgresql.dialect())
    outcomes["scoped_count_distinct_retains_existing_rewrite"] = "PASS"
    return outcomes


if __name__ == "__main__":
    print(json.dumps({"status": "PASS_OFFLINE_ADMISSION_ONLY", "outcomes": cases(),
                      "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "adapter_sha256": hashlib.sha256(Path(__file__).with_name("integration_adapter.py").read_bytes()).hexdigest(),
                      "limits": ["Inert connection; no PostgreSQL or driver execution", "Planner/provider bypassed for expression admission only",
                                 "Complete grammar and every full gate remain UNKNOWN"]}, indent=2))
