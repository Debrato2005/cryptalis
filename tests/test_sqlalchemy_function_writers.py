"""Database functions must not bypass attached-engine write preparation."""

import pytest
from sqlalchemy import event, func, literal, select

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_sqlalchemy_search import _row, search_application


def test_database_function_writer_is_refused_before_key_or_driver():
    with search_application(attach_now=False) as app:
        # This invoker function uses the runtime role's ordinary UPDATE grant.
        # The public label makes a plaintext leak observable independently of
        # frame checks on the protected name column.
        with app.owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f'''CREATE FUNCTION "{app.schema}".write_secret(target uuid, secret text)
                    RETURNS integer LANGUAGE plpgsql AS $$
                    BEGIN
                      UPDATE "{app.schema}".customer SET label = secret WHERE id = target;
                      RETURN 1;
                    END $$'''
            )
        key_calls = []

        def keys(tenant):
            key_calls.append(tenant)
            return app.keys(tenant)

        sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=keys)
        with sessions(tenant_id=app.tenant) as session:
            row = _row(app, "sealed", 1)
            session.add(row)
            session.commit()
            identity = row.id
            key_calls.clear()
            calls = []
            listener = lambda *args: calls.append(True)
            event.listen(app.engine, "before_cursor_execute", listener)
            try:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.execute(select(getattr(func, app.schema).write_secret(identity, "plaintext secret")))
                assert not key_calls
                assert not calls
            finally:
                event.remove(app.engine, "before_cursor_execute", listener)
        with app.owner_engine.connect() as connection:
            assert connection.exec_driver_sql(
                f'SELECT label FROM "{app.schema}".customer WHERE id = %s', (identity,)
            ).scalar_one() == "label-1"


def test_supported_function_resolution_uses_catalog_and_preserves_sql_syntax():
    with search_application(attach_now=False) as app:
        with app.owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f'''CREATE FUNCTION "{app.schema}".length(text) RETURNS integer
                    LANGUAGE SQL IMMUTABLE AS 'SELECT 999' '''
            )
        with app.engine.begin() as connection:
            connection.exec_driver_sql(f'SET search_path TO "{app.schema}", pg_catalog')
            # The native positive control proves that this connection really
            # resolves the deliberately shadowed unqualified function.
            assert connection.scalar(select(func.length(literal('native')))) == 999
        sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
        with sessions(tenant_id=app.tenant) as session:
            statement = select(func.length(literal('native')),
                               func.pg_catalog.length(literal('native')),
                               func.substring(literal('native'), 1, 3),
                               func.coalesce(literal(None), literal('fallback')),
                               func.concat(literal('na'), literal('tive')),
                               func.rank().over(order_by=literal(1)),
                               func.dense_rank().over(order_by=literal(1)),
                               func.count())
            assert tuple(session.execute(statement).one()) == (6, 6, 'nat', 'fallback', 'native', 1, 1, 1)
