"""Native identity variants cannot masquerade as unchanged row context codecs."""
import hashlib
from uuid import UUID

import pytest
from sqlalchemy import Text, Uuid, cast, func, insert
from sqlalchemy.types import TypeDecorator

from cryptalis.manifest.compiler import PlanningRejected
from test_protection_compiler import app, compile_app, engine


class SqlIdentity(TypeDecorator):
    impl = Uuid
    cache_ok = True

    def bind_expression(self, value):
        return cast(func.md5(cast(value, Text)), Uuid)


@pytest.mark.parametrize('column,code', [('id', 'record_identity'), ('tenant_id', 'tenant_context')])
def test_native_identity_sql_variant_is_refused_by_protection_plan(app, column, code):
    engine, mapping, Customer, schema = app
    table = Customer.__table__ if hasattr(Customer, '__table__') else next(iter(mapping.metadata.tables.values()))
    table.c[column].type = Uuid().with_variant(SqlIdentity(), 'postgresql')
    record, tenant = UUID(int=9000), UUID(int=9001)
    inputs = {'id': record, 'tenant_id': tenant, 'email': 'identity variant', 'note': 'public'}
    statement = f'SELECT id, tenant_id, email, note FROM "{schema}".customer ORDER BY id'
    with engine.connect() as connection:
        before = connection.exec_driver_sql(statement).all()
        connection.rollback()
        with connection.begin() as transaction:
            connection.execute(insert(table), inputs)
            stored = connection.exec_driver_sql(
                f'SELECT id, tenant_id FROM "{schema}".customer WHERE email=%s',
                ('identity variant',)).one()
            expected = UUID(hashlib.md5(str(inputs[column]).encode()).hexdigest())
            assert stored[0 if column == 'id' else 1] == expected != inputs[column]
            transaction.rollback()
        assert connection.exec_driver_sql(statement).all() == before
    with pytest.raises(PlanningRejected) as failure:
        compile_app(app)
    assert code in {issue.code for issue in failure.value.issues}
    with engine.connect() as connection:
        assert connection.exec_driver_sql(statement).all() == before
