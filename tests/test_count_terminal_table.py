"""Native table dispatch must preserve the one-tenant equality-count premise."""
from types import MethodType

import pytest
from sqlalchemy import bindparam, event, func, select, Uuid
from sqlalchemy.orm import aliased

from cryptalis.sqlalchemy import UnsupportedProtectedOperation, attach
from test_sqlalchemy_search import OTHER, TENANT, _row, search_application


def seed(app):
    for tenant, values in ((TENANT, ('shared', 'shared', None)),
                           (OTHER, ('shared', 'other only'))):
        with app.sessions(tenant_id=tenant) as session:
            session.add_all(_row(app, value, index, tenant) for index, value in enumerate(values))
            session.commit()


@pytest.mark.parametrize('nested', [False, True])
def test_counterfeit_terminal_table_refuses_before_statement_keys_and_sql(nested):
    # The native renderer below changes public tenant labels, not text values.
    # Native logical DISTINCT sees two text values across the two tenants.
    for protected in (False, True):
        with search_application(protected, attach_now=False) as app:
            called, observed = [], []
            if protected:
                def resolver(tenant):
                    called.append(tenant)
                    return app.keys(tenant)
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolver)
            seed(app)
            table = app.Customer.__table__
            source = table.alias('source_rows')
            if nested:
                source = source.alias('nested_rows')
            model = aliased(app.Customer, source)
            statement = select(func.count(model.name.distinct())).where(model.tenant_id == TENANT)
            original = table._compiler_dispatch
            def counterfeit(self, compiler, **kwargs):
                quote = compiler.preparer.quote_identifier
                columns = ', '.join("'%s'::uuid AS %s" % (TENANT, quote(column.name))
                    if column.name == 'tenant_id' else quote(column.name) for column in table.c)
                return '(SELECT %s FROM %s.%s)' % (columns, quote(app.schema), quote(table.name))
            try:
                table._compiler_dispatch = MethodType(counterfeit, table)
                if protected:
                    event.listen(app.engine, 'before_cursor_execute', lambda *args: observed.append(True))
                with app.sessions(tenant_id=TENANT) as session:
                    called.clear()
                    if protected:
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.scalar(statement)
                        assert called == [] and observed == []
                    else:
                        assert session.scalar(statement) == 2
            finally:
                table._compiler_dispatch = original


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
def test_native_alias_chains_keep_public_tenant_statistics_and_distinct_groups(protected):
    with search_application(protected) as app:
        seed(app)
        table = app.Customer.__table__
        models = (app.Customer, aliased(app.Customer), aliased(aliased(app.Customer)),
            aliased(app.Customer, table.alias('source_rows')))
        with app.sessions(tenant_id=TENANT) as session:
            for model in models:
                present = select(func.count(model.name))
                distinct = select(func.count(model.name.distinct())).where(
                    model.tenant_id == bindparam('scope', type_=Uuid()))
                grouped = select(model.tenant_id, func.count(model.name.distinct())).group_by(
                    model.tenant_id).order_by(model.tenant_id)
                # Counts are public statistics: cross-host-tenant scope and
                # separate tenant groups remain native admitted workflows.
                assert session.scalar(present) == 4
                assert session.scalar(distinct, {'scope': TENANT}) == 1
                assert session.scalar(distinct, {'scope': OTHER}) == 2
                assert session.execute(grouped).all() == sorted([(TENANT, 1), (OTHER, 2)])
            nested = aliased(app.Customer, table.alias('inner_rows').alias('outer_rows'))
            assert session.scalar(select(func.count(nested.name))) == 4
