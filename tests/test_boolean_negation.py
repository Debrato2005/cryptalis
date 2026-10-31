"""Native Boolean NOT truth must retain positive authenticated tenant guards."""
import asyncio
import os
from types import MethodType

import psycopg
import pytest
from sqlalchemy import Text, and_, bindparam, event, not_, or_, select
from sqlalchemy.sql import operators
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import Session, aliased

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TENANT
from test_sqlalchemy_search import search_application, _row, _async_factory, OTHER


def predicates(model):
    column = model.name
    return [
        (not_(and_(column == 'a', column.is_not(None))), {}),
        (not_(or_(column == 'a', column.is_(None))), {}),
        (not_(and_(column.in_(['a', None]), column != 'b')), {}),
        (not_(or_(column.not_in([]), column.is_not(None))), {}),
        (not_(and_(or_(column == 'a', column.is_(None)),
                   not_(and_(column.in_(bindparam('choices', expanding=True, type_=Text())),
                             model.label.like('label-%'))))), {'choices': ['a', None]}),
        (not_(or_(bindparam('value', type_=Text()) == column, column.is_(None))), {'value': 'a'}),
    ]


@pytest.mark.parametrize('mode', ['sync', 'async', 'sqlmodel', 'sqlmodel_async'])
def test_migrated_negation_matches_native_truth_nulls_aliases_and_membership(mode):
    with application(rows=7, unique=False, protected_values=(None, 'a', 'b', 'é', 'e\u0301', '', 'a ')) as app:
        def queries():
            model = aliased(app.Customer)
            for expression, parameters in predicates(model):
                statement = select(model.id, model.name, expression.label('truth')).where(
                    model.tenant_id == TENANT).order_by(model.id)
                yield statement, parameters
                yield statement.where(expression).offset(1).limit(3), parameters

        def sync(factory=None):
            native = Session
            if mode == 'sqlmodel':
                from sqlmodel import Session as native
            with (factory(tenant_id=TENANT) if factory else native(app.runtime)) as session:
                execute = session.exec if mode == 'sqlmodel' else session.execute
                return [[tuple(row) for row in execute(statement, params=parameters).all()]
                        for statement, parameters in queries()]

        async def asynchronous(protected):
            native, selected = AsyncSession, attach
            if mode == 'sqlmodel_async':
                from sqlmodel.ext.asyncio.session import AsyncSession as native
                from cryptalis.sqlmodel import attach as selected
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else None
                async with (factory(tenant_id=TENANT) if protected else native(engine)) as session:
                    execute = session.exec if mode == 'sqlmodel_async' else session.execute
                    return [[tuple(row) for row in (await execute(statement, params=parameters)).all()]
                            for statement, parameters in queries()]
            finally:
                await engine.dispose()

        expected = asyncio.run(asynchronous(False)) if 'async' in mode else sync()
        with fresh_mapping(app):
            run(app); publish(app)
            if 'async' in mode:
                observed = asyncio.run(asynchronous(True))
            else:
                selected = attach
                if mode == 'sqlmodel':
                    from cryptalis.sqlmodel import attach as selected
                observed = sync(selected(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)))
            assert observed == expected


@pytest.mark.parametrize('combine', [and_, or_], ids=['and', 'or'])
@pytest.mark.parametrize('wrapped', [False, True], ids=['plain', 'negated'])
def test_custom_boolean_container_refuses_before_keys_or_driver(combine, wrapped):
    with application(rows=3) as app:
        run(app); publish(app)
        calls, sent = [], []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
            deployment=(app.plan, app.pin))
        expression = combine(app.Customer.name == 'absent', app.Customer.label == 'absent')
        expression._compiler_dispatch = MethodType(lambda self, compiler, **kwargs: 'TRUE', expression)
        if wrapped:
            expression = not_(expression)
        statement = select(app.Customer.id).where(expression)
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: sent.append(True))
        with factory(tenant_id=TENANT) as session:
            calls.clear()
            with pytest.raises(CryptoFailure):
                session.execute(statement).all()
            assert calls == sent == []


@pytest.mark.parametrize('combine', [and_, or_], ids=['and', 'or'])
def test_negation_cannot_invert_search_tenant_guards_even_for_public_only_results(combine):
    with search_application(True) as app:
        for tenant, rank in ((app.tenant, 1), (OTHER, 2)):
            with app.sessions(tenant_id=tenant) as session:
                session.add(_row(app, 'present', rank, tenant)); session.commit()
        expression = not_(combine(app.Customer.name == 'absent', app.Customer.name.in_(['absent'])))
        with app.sessions(tenant_id=app.tenant) as session:
            assert session.scalars(select(app.Customer.rank).where(expression)).all() == [1]


@pytest.mark.parametrize('when', ['before', 'provider'])
@pytest.mark.parametrize('changed', ['not-renderer', 'group-renderer', 'not-modifier',
    'annotated-operator', 'annotated-element', 'result-type'])
def test_negation_refuses_changed_native_structure_before_driver(when, changed):
    with application(rows=3) as app:
        run(app); publish(app)
        calls, sent, active = [], [], []
        expression = not_(and_(app.Customer.name == 'absent', app.Customer.label == 'absent'))
        if changed.startswith('annotated-'):
            expression = expression._annotate({'test_origin': True})
        def mutate():
            if changed.endswith('renderer'):
                node = expression if changed == 'not-renderer' else expression.element
                node._compiler_dispatch = MethodType(lambda self, compiler, **kwargs: 'TRUE', node)
            elif changed == 'not-modifier': expression.modifier = operators.desc_op
            elif changed == 'annotated-operator': expression.operator = operators.is_false
            elif changed == 'annotated-element': expression.element = app.Customer.name == 'different'
            else: expression.type = Text()
        def resolve(tenant):
            if active:
                calls.append(True)
                if when == 'provider': mutate()
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
            deployment=(app.plan, app.pin))
        statement = select(app.Customer.id).where(expression)
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: sent.append(True))
        with factory(tenant_id=TENANT) as session:
            active.append(True)
            if when == 'before': mutate()
            with pytest.raises(CryptoFailure): session.execute(statement).all()
            assert sent == []
            assert bool(calls) is (when == 'provider')


def test_negation_preserves_caller_tree_and_ignores_non_sql_negate_metadata():
    with search_application(True) as app:
        with app.sessions(tenant_id=app.tenant) as session:
            session.add_all([_row(app, 'present', 1), _row(app, 'different', 2)])
            session.commit()
            leaf = app.Customer.name == 'present'
            leaf.negate = operators.eq  # Compilation still means equality.
            expression = not_(and_(leaf, app.Customer.name.is_not(None)))
            statement = select(app.Customer.rank, expression.label('truth')).where(
                app.Customer.tenant_id == app.tenant).order_by(app.Customer.rank)
            original = str(statement)
            for _ in range(2):
                assert [tuple(row) for row in session.execute(statement)] == [(1, False), (2, True)]
                assert str(statement) == original
                assert leaf.operator is operators.eq and leaf.negate is operators.eq


@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('labelled', [False, True])
@pytest.mark.parametrize('kind', ['equality', 'and', 'not'])
def test_predicate_result_expression_lookup_matches_native(mode, labelled, kind):
    outcomes = []
    for protected in (False, True):
        with search_application(protected, attach_now=False) as app:
            expression = app.Customer.name == 'present'
            if kind != 'equality':
                expression = and_(expression, app.Customer.name.is_not(None))
            if kind == 'not':
                expression = not_(expression)
            if labelled:
                expression = expression.label('truth')
            statement = select(app.Customer.rank, expression).where(
                app.Customer.tenant_id == app.tenant).order_by(app.Customer.rank)
            def exercise(session):
                session.add_all(_row(app, value, index) for index, value in enumerate(('present', 'other', None)))
                session.commit()
                observed = []
                def observe(connection, cursor, sql, parameters, context, many):
                    observed.extend(parameters.values() if isinstance(parameters, dict) else parameters)
                engine = session.get_bind()
                event.listen(engine, 'before_cursor_execute', observe)
                try:
                    result = session.execute(statement)
                finally:
                    event.remove(engine, 'before_cursor_execute', observe)
                # The native control proves that the observer sees search input.
                assert ('present' in observed) is (not protected)
                names = tuple(result.keys())
                rows = result.all()
                assert [row._mapping[expression] for row in rows] == [row[1] for row in rows]
                assert [row._mapping[app.Customer.rank] for row in rows] == [0, 1, 2]
                return names, [tuple(row) for row in rows]
            if mode == 'sync':
                if protected:
                    app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
                with app.sessions(tenant_id=app.tenant) as session:
                    actual = exercise(session)
            else:
                async def scenario():
                    engine, sessions = await _async_factory(app)
                    try:
                        async with sessions(tenant_id=app.tenant) as session:
                            return await session.run_sync(exercise)
                    finally:
                        await engine.dispose()
                actual = asyncio.run(scenario())
            outcomes.append(actual)
    assert outcomes[1] == outcomes[0]


@pytest.mark.parametrize('when', ['before', 'provider'])
def test_predicate_projection_rejects_custom_label_rendering(when):
    with application(rows=3) as app:
        run(app); publish(app)
        calls, sent, armed = [], [], []
        expression = not_(and_(app.Customer.name == 'absent', app.Customer.name.is_not(None))).label('truth')
        def mutate():
            expression._compiler_dispatch = MethodType(lambda self, compiler, **kwargs: 'TRUE', expression)
        def resolve(tenant):
            if armed:
                calls.append(True)
                if when == 'provider': mutate()
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
            deployment=(app.plan, app.pin))
        event.listen(app.runtime, 'before_cursor_execute', lambda *args: sent.append(True))
        with factory(tenant_id=TENANT) as session:
            armed.append(True)
            if when == 'before': mutate()
            with pytest.raises(CryptoFailure): session.execute(select(app.Customer.id, expression)).all()
            assert sent == [] and bool(calls) is (when == 'provider')
