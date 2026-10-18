"""Native textual name resolution must not admit protected sort/group work.

These synthetic, owned-fixture controls require pre-driver refusal. Public
labels that shadow a protected FROM name retain native resolution and values.
"""
import asyncio
from uuid import UUID

import pytest
from sqlalchemy import Text, asc, desc, event, func, nulls_last, select, type_coerce
from sqlalchemy.orm import aliased

from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_sqlalchemy_search import _async_factory, _row, search_application


VALUES = (None, "z", "a", "é", "", "雪", "a")
RANKS = (None, 3, 1, -1, 0, 2, 1)
MODIFIERS = ("plain", "desc_nulls_last", "coerced_asc")


def _rows(app):
    rows = [_row(app, value, rank) for value, rank in zip(VALUES, RANKS)]
    for number, row in enumerate(rows, 1):
        row.id = UUID(int=number)
    return rows


def _order(value, modifier):
    if modifier == "plain":
        return value
    if modifier == "desc_nulls_last":
        return nulls_last(desc(value))
    return type_coerce(asc(value), Text())


def _queries(app, shape, modifier="plain", *, public=False, grouped=False):
    alias = shape.startswith("alias")
    model = aliased(app.Customer, name="subject") if alias else app.Customer
    if grouped:
        base = select(func.count()).select_from(model).where(model.tenant_id == app.tenant)
        return base.group_by("name"), base.group_by(model.name)
    chosen = model.rank if public else model.name
    columns = [model.id]
    if shape.endswith("qualified"):
        columns.append(chosen)
        prefix = "subject" if alias else app.schema + "_customer"
        name = prefix + ("_rank" if public else "_name")
    elif shape.endswith("shadow"):
        assert public
        columns.append(chosen.label("name"))
        name = "name"
    else:
        name = "rank" if public else "name"
    base = select(*columns).where(model.tenant_id == app.tenant)
    return (base.order_by(_order(name, modifier), model.id).offset(1).limit(4),
            base.order_by(_order(chosen, modifier), model.id).offset(1).limit(4))


def _exercise(protected, mode, build, *, refuse, grouped=False):
    with search_application(protected, attach_now=mode == "sync") as app:
        def consume(result):
            rows = [tuple(row) for row in result]
            return sorted(rows) if grouped else rows

        def observe(engine):
            calls = []
            listener = lambda *args: calls.append(True)
            event.listen(engine, "before_cursor_execute", listener)
            return calls, listener

        if mode == "sync":
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all(_rows(app))
                session.commit()
                candidate, direct = build(app)
                if refuse:
                    calls, listener = observe(app.engine)
                    try:
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(candidate)
                        assert calls == [], "Protected textual ordering/grouping reached the driver"
                    finally:
                        event.remove(app.engine, "before_cursor_execute", listener)
                    return None
                actual = consume(session.execute(candidate))
                assert actual == consume(session.execute(direct))
                assert len(actual) == (6 if grouped else 4)
                return actual

        async def scenario():
            engine, sessions = await _async_factory(app)
            try:
                async with sessions(tenant_id=app.tenant) as session:
                    session.add_all(_rows(app))
                    await session.commit()
                    candidate, direct = build(app)
                    if refuse:
                        calls, listener = observe(engine.sync_engine)
                        try:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(candidate)
                            assert calls == [], "Protected textual ordering/grouping reached the driver"
                        finally:
                            event.remove(engine.sync_engine, "before_cursor_execute", listener)
                        return None
                    actual = consume(await session.execute(candidate))
                    assert actual == consume(await session.execute(direct))
                    assert len(actual) == (6 if grouped else 4)
                    return actual
            finally:
                await engine.dispose()
        return asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("shape", ["from_bare", "alias_from_bare", "table_qualified", "alias_qualified"])
@pytest.mark.parametrize("modifier", MODIFIERS)
def test_protected_textual_from_or_qualified_name_requires_refusal(protected, mode, shape, modifier):
    _exercise(protected, mode, lambda app: _queries(app, shape, modifier), refuse=protected)


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("shape", ["from_bare", "alias_from_bare"])
def test_unprojected_protected_textual_group_requires_refusal(protected, mode, shape):
    _exercise(protected, mode, lambda app: _queries(app, shape, grouped=True),
              refuse=protected, grouped=True)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("shape", ["from_bare", "table_shadow", "alias_shadow", "table_qualified"])
@pytest.mark.parametrize("modifier", MODIFIERS)
def test_public_textual_names_and_shadow_labels_keep_native_resolution(mode, shape, modifier):
    outcomes = [_exercise(protected, mode, lambda app: _queries(app, shape, modifier, public=True),
                          refuse=False) for protected in (False, True)]
    assert outcomes[0] == outcomes[1]
