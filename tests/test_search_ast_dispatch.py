"""Native predicate rendering must not gain authenticated rewrite authority."""
import asyncio
from types import MethodType

import pytest
from sqlalchemy import and_, event, or_, select
from sqlalchemy.ext.compiler import compiles, deregister
from sqlalchemy.sql.elements import BinaryExpression

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_sqlalchemy_search import search_application, _row, _scope, _async_factory


@pytest.mark.parametrize('dispatch', ['subclass', 'instance'])
@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_custom_equality_renderer_is_native_false_or_refuses_before_keys(dispatch, protected, mode):
    """Replacing an unadmitted renderer would silently change native FALSE to TRUE."""
    class ConstantFalse(BinaryExpression):
        inherit_cache = False

    if dispatch == 'subclass':
        @compiles(ConstantFalse, 'postgresql')
        def render_false(expression, compiler, **kwargs):
            return 'FALSE'

    try:
        with search_application(protected, attach_now=False) as app:
            calls, observed = [], []
            original = app.keys
            def resolve(tenant):
                calls.append(tenant)
                return original(tenant)
            expression = app.Customer.name == 'matching account'
            if dispatch == 'subclass':
                expression = ConstantFalse(expression.left, expression.right, expression.operator,
                                           type_=expression.type)
            else:
                expression._compiler_dispatch = MethodType(
                    lambda self, compiler, **kwargs: 'FALSE', expression)
            statement = select(app.Customer.rank, expression.label('truth')).where(_scope(app))

            def check(session):
                session.add(_row(app, 'matching account', 1))
                session.commit()
                calls.clear()
                event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
                if protected:
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(statement)
                    assert calls == [] and observed == []
                else:
                    assert [tuple(row) for row in session.execute(statement)] == [(1, False)]

            if mode == 'sync':
                if protected:
                    app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
                with app.sessions(tenant_id=app.tenant) as session:
                    check(session)
            else:
                async def scenario():
                    if protected:
                        app.keys = resolve
                    engine, sessions = await _async_factory(app)
                    try:
                        async with sessions(tenant_id=app.tenant) as session:
                            session.add(_row(app, 'matching account', 1))
                            await session.commit()
                            calls.clear()
                            event.listen(engine.sync_engine, 'before_cursor_execute', lambda *args: observed.append(True))
                            if protected:
                                with pytest.raises(UnsupportedProtectedOperation):
                                    await session.execute(statement)
                                assert calls == [] and observed == []
                            else:
                                assert [tuple(row) for row in await session.execute(statement)] == [(1, False)]
                    finally:
                        await engine.dispose()
                asyncio.run(scenario())
    finally:
        if dispatch == 'subclass':
            deregister(ConstantFalse)


@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_native_predicate_nodes_keep_equality_membership_null_and_boolean_truth(mode):
    """Ordinary native nodes retain their NULL and composed-predicate semantics."""
    outcomes = []
    for protected in (False, True):
        with search_application(protected, attach_now=mode == 'sync') as app:
            column = app.Customer.name
            predicates = [column == 'matching account', column != 'matching account',
                          column.in_(['matching account', None]), column.not_in([]),
                          column.is_(None), column.is_not(None),
                          or_(column == 'matching account', column.is_(None)),
                          and_(column != 'other account', column.is_not(None))]
            statements = [select(app.Customer.rank, predicate.label('truth')).where(_scope(app)).order_by(app.Customer.rank)
                          for predicate in predicates]
            rows = [_row(app, value, rank) for rank, value in enumerate(['matching account', 'other account', None])]
            if mode == 'sync':
                with app.sessions(tenant_id=app.tenant) as session:
                    session.add_all(rows)
                    session.commit()
                    actual = [[tuple(row) for row in session.execute(statement)] for statement in statements]
            else:
                async def scenario():
                    engine, sessions = await _async_factory(app)
                    try:
                        async with sessions(tenant_id=app.tenant) as session:
                            session.add_all(rows)
                            await session.commit()
                            return [[tuple(row) for row in await session.execute(statement)] for statement in statements]
                    finally:
                        await engine.dispose()
                actual = asyncio.run(scenario())
            outcomes.append(actual)
    assert outcomes[0][0] == [(0, True), (1, False), (2, None)]
    assert outcomes[0][4] == [(0, False), (1, False), (2, True)]
    assert outcomes[1] == outcomes[0]
