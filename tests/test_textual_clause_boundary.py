"""Finite native oracles for remaining textual-name consuming SQL clauses.

These owned synthetic controls require protected operations to refuse before
the driver. They do not admit DISTINCT, windows, or aggregates on protected data.
"""
import asyncio

import pytest
from sqlalchemy import desc, event, func, nulls_last, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import aliased
from sqlalchemy.sql.functions import FunctionElement

from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_sqlalchemy_search import _async_factory, search_application
from test_textual_from_boundary import _rows


CLAUSES = ("distinct_legacy", "distinct_extension", "window_order",
           "window_partition", "within_group", "aggregate_order")


def _distinct(statement, expression, clause):
    if clause == "distinct_extension":
        extension = getattr(postgresql, "distinct_on", None)
        if extension is None:
            pytest.skip("Native SQLAlchemy 2.0 has no distinct_on syntax extension")
        return statement.ext(extension(expression))
    return statement.distinct(expression)


def _queries(app, clause, alias, public, *, shadow=False):
    model = aliased(app.Customer, name="subject") if alias else app.Customer
    chosen = model.rank if public else model.name
    textual = "rank" if public else "name"
    scope = model.tenant_id == app.tenant
    if clause.startswith("distinct"):
        columns = [model.rank.label("name") if shadow else model.rank]
        base = select(*columns).where(scope)
        return (_distinct(base, "name" if shadow else textual, clause),
                _distinct(base, model.rank if shadow else chosen, clause), 6)

    def expression(value):
        if clause == "window_order":
            return func.row_number().over(order_by=[nulls_last(desc(value)), model.id])
        if clause == "window_partition":
            return func.count().over(partition_by=value)
        if clause == "aggregate_order":
            return func.array_agg(model.rank).aggregate_order_by(value, model.id)
        # The schema-qualified native function uses driver result typing.
        # SQLAlchemy's specialized func.mode infers its type from a concrete
        # expression and cannot infer it from a textual ordering reference.
        return func.pg_catalog.mode().within_group(value)

    def statement(value):
        if clause in ("within_group", "aggregate_order"):
            # A projected public aggregate alias cannot shadow a WITHIN GROUP
            # input-column reference in the same select list.
            return select(func.count().label("name"), expression(value)).select_from(model).where(scope)
        # Window names in the select list use FROM resolution even when this
        # public output alias has the same name as a protected input column.
        return select(model.id, model.rank.label("name"), expression(value).label("window_value")).where(scope).order_by(model.id)

    return statement(textual), statement(chosen), 1 if clause in ("within_group", "aggregate_order") else 7


def _exercise(protected, mode, clause, alias, *, public, refuse, shadow=False):
    # Skip before creating a database fixture when the native API is absent.
    if clause == "distinct_extension" and not hasattr(postgresql, "distinct_on"):
        pytest.skip("Native SQLAlchemy 2.0 has no distinct_on syntax extension")
    if clause == "aggregate_order" and not hasattr(FunctionElement, "aggregate_order_by"):
        pytest.skip("Native SQLAlchemy 2.0 has no generic aggregate_order_by API")
    with search_application(protected, attach_now=mode == "sync") as app:
        def consume(result):
            return sorted((tuple(row) for row in result), key=repr)

        def observer(engine):
            calls = []
            listener = lambda *args: calls.append(True)
            event.listen(engine, "before_cursor_execute", listener)
            return calls, listener

        if mode == "sync":
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all(_rows(app))
                session.commit()
                candidate, direct, count = _queries(app, clause, alias, public, shadow=shadow)
                if refuse:
                    calls, listener = observer(app.engine)
                    try:
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(candidate)
                        assert calls == [], "Protected textual clause reached the driver"
                    finally:
                        event.remove(app.engine, "before_cursor_execute", listener)
                    return None
                actual = consume(session.execute(candidate))
                assert actual == consume(session.execute(direct))
                assert len(actual) == count
                return actual

        async def scenario():
            engine, sessions = await _async_factory(app)
            try:
                async with sessions(tenant_id=app.tenant) as session:
                    session.add_all(_rows(app))
                    await session.commit()
                    candidate, direct, count = _queries(app, clause, alias, public, shadow=shadow)
                    if refuse:
                        calls, listener = observer(engine.sync_engine)
                        try:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(candidate)
                            assert calls == [], "Protected textual clause reached the driver"
                        finally:
                            event.remove(engine.sync_engine, "before_cursor_execute", listener)
                        return None
                    actual = consume(await session.execute(candidate))
                    assert actual == consume(await session.execute(direct))
                    assert len(actual) == count
                    return actual
            finally:
                await engine.dispose()
        return asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("alias", [False, True], ids=["table", "alias"])
@pytest.mark.parametrize("clause", CLAUSES)
def test_protected_textual_clause_requires_predriver_refusal(protected, mode, alias, clause):
    _exercise(protected, mode, clause, alias, public=False, refuse=protected)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("alias", [False, True], ids=["table", "alias"])
@pytest.mark.parametrize("clause", CLAUSES)
def test_public_textual_clause_matches_native(mode, alias, clause):
    outcomes = [_exercise(protected, mode, clause, alias, public=True, refuse=False)
                for protected in (False, True)]
    assert outcomes[0] == outcomes[1]


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("alias", [False, True], ids=["table", "alias"])
@pytest.mark.parametrize("clause", ["distinct_legacy", "distinct_extension"])
def test_public_distinct_output_label_shadows_protected_from_name(mode, alias, clause):
    outcomes = [_exercise(protected, mode, clause, alias, public=True, refuse=False, shadow=True)
                for protected in (False, True)]
    assert outcomes[0] == outcomes[1]
