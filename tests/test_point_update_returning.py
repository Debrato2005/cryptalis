"""Compare mapped single-record UPDATE RETURNING with the native database."""
from uuid import UUID

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from test_bulk_returning import fresh_mapping
from test_migration import application, keys, publish, run, TENANT


def statement(app, identity, kind):
    columns = (app.Customer.name,) if kind == 'scalar' else (app.Customer.id, app.Customer.name, app.Customer.label)
    return update(app.Customer).where(app.Customer.id == identity,
        app.Customer.tenant_id == TENANT).returning(*columns)


def journey(app, factory, kind, *, commit):
    with factory() as session:
        loaded = session.get(app.Customer, UUID(int=101))
        result = session.execute(statement(app, UUID(int=101), kind),
            {'name': 'PUBLIC updated 雪😀', 'label': 'public label'},
            execution_options={'synchronize_session': False})
        names = tuple(result.keys())
        rows = result.all()
        observed = (names, rows, [(type(row), tuple(type(value) for value in row)) for row in rows])
        assert loaded.name == ''  # Native synchronize_session=False preserves stale identity state.
        session.refresh(loaded)
        assert loaded.name == 'PUBLIC updated 雪😀'
        with session.begin_nested():
            nulls = session.execute(statement(app, UUID(int=100), 'scalar'), {'name': None},
                execution_options={'synchronize_session': False}).scalars().all()
            assert nulls == [None]
        missing = session.execute(statement(app, UUID(int=9999), kind), {'name': 'PUBLIC missing'},
            execution_options={'synchronize_session': False}).all()
        assert missing == []
        assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=101))) == 'PUBLIC updated 雪😀'
        session.commit() if commit else session.rollback()
        return observed


@pytest.mark.parametrize('kind', ['scalar', 'tuple'])
def test_point_update_returning_native_values_types_nulls_missing_rows_and_identity(kind):
    with application(rows=3) as app:
        expected = journey(app, lambda: Session(app.runtime), kind, commit=False)
        with fresh_mapping(app):
            run(app); publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                             deployment=(app.plan, app.pin))
            sent = []
            def observe(connection, cursor, query, parameters, context, many):
                if query.lstrip().upper().startswith('UPDATE '):
                    sent.append(repr(parameters))
                    assert not many and 'RETURNING' in query
            event.listen(app.runtime, 'before_cursor_execute', observe)
            try:
                assert journey(app, lambda: factory(tenant_id=TENANT), kind, commit=True) == expected
            finally:
                event.remove(app.runtime, 'before_cursor_execute', observe)
            assert len(sent) == 3 and 'PUBLIC updated' not in repr(sent) and 'PUBLIC missing' not in repr(sent)
            with factory(tenant_id=TENANT) as session:
                assert session.get(app.Customer, UUID(int=101)).name == 'PUBLIC updated 雪😀'
