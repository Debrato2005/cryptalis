"""Public DISTINCT keeps native semantics with an encrypted search filter."""
import asyncio

import pytest
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import aliased
from test_sqlalchemy_search import _async_factory, _row, _scope, search_application

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_public_distinct_with_protected_filters_aliases_and_pagination(protected, mode):
    with search_application(protected, attach_now=False) as app:
        values = [('repeat', 1), ('repeat', 1), ('repeat', 2), ('different', 3), (None, 4)]
        cases = []
        refused = []
        for model in (app.Customer, aliased(app.Customer)):
            filtered = select(model.rank).where(_scope(app, model), model.name == 'repeat')
            cases.extend(((filtered.distinct().order_by(model.rank), [1, 2]),
                          (filtered.distinct().order_by(model.rank).offset(1).limit(1), [2]),
                          (filtered.ext(distinct_on(model.rank)).order_by(model.rank), [1, 2]),
                          (select(model.rank).where(_scope(app, model), model.name.is_(None)).distinct(), [4])))
            refused.extend((select(model.name, model.rank).where(_scope(app, model)).distinct(),
                            filtered.ext(distinct_on(model.name))))

        if mode == 'sync':
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all(_row(app, value, rank) for value, rank in values)
                session.commit()
                for statement, expected in cases:
                    assert session.scalars(statement).all() == expected
                if protected:
                    for statement in refused:
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(statement)
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add_all(_row(app, value, rank) for value, rank in values)
                        await session.commit()
                        for statement, expected in cases:
                            assert (await session.scalars(statement)).all() == expected
                        if protected:
                            for statement in refused:
                                with pytest.raises(UnsupportedProtectedOperation):
                                    await session.execute(statement)
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
