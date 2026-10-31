"""Protected DISTINCT returns native logical values through authenticated carriers."""
import asyncio
from types import MethodType

import pytest
from sqlalchemy import and_, event, func, inspect, not_, or_, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import aliased
from test_sqlalchemy_search import (
    OTHER,
    _async_factory,
    _row,
    _scope,
    search_application,
)

from cryptalis.crypto import AuthenticationFailed
from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach


def cases(app):
    expected = {None, '', 'repeat', '雪', 'é', 'e\u0301', 'A', 'a', 'trailing '}
    for model in (app.Customer, aliased(app.Customer)):
        base = select(model.name).where(_scope(app, model)).distinct()
        yield base, expected
        yield base.with_only_columns(model.name.label('value')), expected
        yield base.where(model.name.in_(['repeat', '雪', None])), {'repeat', '雪'}
        yield base.where(model.name.is_(None)), {None}
        yield base.where(not_(and_(model.name != 'repeat', model.name.is_not(None)))), {None, 'repeat'}
        yield base.where(model.rank < 0), set()


def check(rows, expected, column):
    values = [row._mapping[column] for row in rows]
    assert set(values) == expected and len(values) == len(expected)
    assert all(value is None or type(value) is str for value in values)


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('single_tenant', [False, True])
def test_distinct_direct_value_sets_types_aliases_labels_nulls_and_filters(protected, mode, single_tenant):
    with search_application(protected, single_tenant=single_tenant, attach_now=False) as app:
        values = [None, None, '', '', 'repeat', 'repeat', '雪', 'é', 'e\u0301', 'A', 'a', 'trailing ']
        if mode == 'sync':
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all(_row(app, value, rank) for rank, value in enumerate(values))
                session.commit()
                for statement, expected in cases(app):
                    check(session.execute(statement).all(), expected, statement.selected_columns[0])
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add_all(_row(app, value, rank) for rank, value in enumerate(values))
                        await session.commit()
                        for statement, expected in cases(app):
                            check((await session.execute(statement)).all(), expected, statement.selected_columns[0])
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


def test_unadmitted_distinct_shapes_refuse_before_statement_keys_and_sql():
    with search_application(attach_now=False) as app:
        model, other = app.Customer, aliased(app.Customer)
        base = select(model.name).where(_scope(app)).distinct()
        spoofed = model.tenant_id == app.tenant
        spoofed._compiler_dispatch = MethodType(lambda self, visitor, **kw: 'TRUE', spoofed)
        changed = aliased(model)
        inspect(changed).selectable.c.name.name = 'label'
        statements = (
            select(model.name).distinct(),
            select(model.name).where(or_(model.tenant_id == app.tenant, model.tenant_id == OTHER)).distinct(),
            select(model.name).where(spoofed).distinct(),
            select(model.name).join(other, model.rank == other.rank).where(other.tenant_id == app.tenant).distinct(),
            select(changed.name).where(_scope(app, changed)).distinct(),
            base.add_columns(model.rank), base.with_only_columns(func.lower(model.name)),
            base.order_by(model.name), base.group_by(model.name), base.having(model.rank > 0),
            base.limit(1), base.offset(1), base.fetch(1), base.with_for_update(),
            select(model.name).where(_scope(app)).ext(distinct_on(model.name)),
        )
        called, observed = [], []
        def resolve(tenant):
            called.append(tenant)
            return app.keys(tenant)
        sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
        event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
        with sessions(tenant_id=app.tenant) as session:
            called.clear()
            for statement in statements:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(statement)
                assert called == [] and observed == []


def test_distinct_authenticates_its_selected_representative_frame():
    with search_application() as app:
        model = app.Customer
        with app.sessions(tenant_id=app.tenant) as session:
            row = _row(app, 'only value', 0)
            session.add(row)
            session.commit()
            identity = row.id
        with app.owner_engine.begin() as connection:
            frame = bytes(connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer').scalar_one())
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                      (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with app.sessions(tenant_id=app.tenant) as session, pytest.raises(AuthenticationFailed):
            session.scalars(select(model.name).where(_scope(app)).distinct()).all()
