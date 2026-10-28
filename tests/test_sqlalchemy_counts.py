"""Native PostgreSQL counts are the oracle for protected count projections."""
import asyncio
import json
from types import MethodType

import pytest
from sqlalchemy import Boolean, Text, event, func, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql.functions import count
from test_migration import TENANT, application, keys, publish, run
from test_sqlalchemy_search import _async_factory, _row, _scope, search_application

from cryptalis.doctor import preflight
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach


def count_cases(app):
    model, other = app.Customer, aliased(app.Customer)
    yield select(func.count(model.name)).where(_scope(app)), 7
    yield select(func.count(other.name).label('present')).where(_scope(app, other)), 7
    yield select(func.count(model.name)).where(_scope(app), model.rank < 0), 0
    yield select(func.count(model.name)).where(_scope(app), model.rank == 0), 0
    yield select(func.count(model.name)).where(_scope(app), model.name == 'repeat'), 2


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('single_tenant', [False, True])
def test_nonnull_counts_match_native_with_aliases_filters_groups_and_nulls(protected, mode, single_tenant):
    with search_application(protected, single_tenant=single_tenant, attach_now=False) as app:
        values = [None, '', 'repeat', 'repeat', '雪', '雪', 'é', 'e\u0301']
        statements = tuple(count_cases(app))
        model = app.Customer
        grouped = select(model.rank, func.count(model.name)).where(_scope(app)).group_by(
            model.rank).order_by(model.rank)
        combined = select(func.count(), func.count(model.name)).where(_scope(app))

        def check(result, expected):
            assert result == expected
            assert type(result) is int

        if mode == 'sync':
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all(_row(app, value, rank) for rank, value in enumerate(values))
                session.commit()
                for statement, expected in statements:
                    check(session.scalar(statement), expected)
                assert session.execute(combined).one() == (8, 7)
                assert session.execute(grouped).all() == [(rank, int(value is not None))
                                                         for rank, value in enumerate(values)]
                row = session.scalars(select(model).where(_scope(app), model.rank == 1)).one()
                row.name = None
                session.flush()
                assert session.scalar(statements[0][0]) == 6
                session.rollback()
                assert session.scalar(statements[0][0]) == 7
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add_all(_row(app, value, rank) for rank, value in enumerate(values))
                        await session.commit()
                        for statement, expected in statements:
                            check(await session.scalar(statement), expected)
                        assert (await session.execute(combined)).one() == (8, 7)
                        assert (await session.execute(grouped)).all() == [
                            (rank, int(value is not None)) for rank, value in enumerate(values)]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize('dtype,values', [(Text(collation='C'), (None, '', 'repeat', 'repeat')),
                                       (Boolean(), (None, False, True, False))])
def test_storage_only_counts_survive_real_protection_and_native_nulls(dtype, values):
    with application(rows=4, value_type=dtype, queries=[], protected_values=values) as app:
        assert run(app).phase == 'PENDING'
        publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(func.count(app.Customer.name))) == 3
            assert session.scalar(select(func.count()).select_from(app.Customer)) == 4


def test_count_preflight_uses_the_same_admission_without_keys_or_attachment():
    with search_application(protected=False) as app:
        report = preflight(json.dumps(app.declaration).encode(), app.mapping, app.owner_engine,
                           writers=app.writers, search_reviews=app.reviews,
                           queries=(select(func.count(app.Customer.name).label('present')),))
        assert report['checks']['query_samples'] == 'PASS'
        assert report['checks']['query_routes'] == 'UNKNOWN'
        assert report['query_samples']['execution'] == 'NOT_PERFORMED'


def test_custom_counts_and_unadmitted_aggregate_wrappers_refuse_before_keys_and_sql():
    with search_application(attach_now=False) as app:
        model = app.Customer

        class CustomCount(count):
            inherit_cache = False

            def _compiler_dispatch(self, visitor, **kwargs):
                return 'count(*)'

        mutated = func.count(model.name)
        mutated._compiler_dispatch = MethodType(lambda self, visitor, **kw: 'count(*)', mutated)
        shared = func.count(model.name)
        statements = (
            select(CustomCount(model.name)), select(mutated),
            select(func.pg_catalog.count(model.name)),
            select(func.count(model.name.label('not_a_direct_column'))),
            select(func.count(model.name + 'suffix')),
            select(func.count(func.lower(model.name))),
            select(func.count(model.name).over()),
            select(func.count(model.name).filter(model.rank > 0)),
            select(func.count(model.name.distinct())),
            select(shared, shared.clause_expr), select(shared.clause_expr, shared),
            select(shared, shared.clause_expr.element), select(shared.clause_expr.element, shared),
        )
        called, observed = [], []

        def resolve(tenant):
            called.append(tenant)
            return app.keys(tenant)

        sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
        called.clear()
        event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
        with sessions(tenant_id=app.tenant) as session:
            called.clear()  # Factory construction validates the tenant's policy.
            for statement in statements:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.scalar(statement)
                assert called == [] and observed == []
