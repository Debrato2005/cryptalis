"""Native least-privilege refusal before provider work and active admission."""
import json
from contextlib import contextmanager

import pytest
from sqlalchemy import event

from cryptalis import migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_migration import application, engine, keys, publish, run, TABLE_ID, FIELD_ID, frames


def privilege_change(app,fault):
    quote=app.owner.dialect.identifier_preparer.quote_identifier
    role=quote(app.role)
    table=f'{quote(app.schema)}.customer'
    journal=f'{quote(app.schema)}.{quote(m.JOURNAL)}'
    database=quote(app.plan.document['target'][0])
    return {
        'database_create':(f'GRANT CREATE ON DATABASE {database} TO {role}',f'REVOKE CREATE ON DATABASE {database} FROM {role}'),
        'schema_create':(f'GRANT CREATE ON SCHEMA {quote(app.schema)} TO {role}',f'REVOKE CREATE ON SCHEMA {quote(app.schema)} FROM {role}'),
        'table_trigger':(f'GRANT TRIGGER ON {table} TO {role}',f'REVOKE TRIGGER ON {table} FROM {role}'),
        'table_truncate':(f'GRANT TRUNCATE ON {table} TO {role}',f'REVOKE TRUNCATE ON {table} FROM {role}'),
        'journal_update':(f'GRANT UPDATE ON {journal} TO {role}',f'REVOKE UPDATE ON {journal} FROM {role}'),
        'journal_column_update':(f'GRANT UPDATE (state) ON {journal} TO {role}',f'REVOKE UPDATE (state) ON {journal} FROM {role}'),
    }[fault]


@contextmanager
def unsafe_rights(app, fault):
    grant, revoke = privilege_change(app, fault)
    if fault != 'database_create':
        try:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(grant)
            yield
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(revoke)
        return

    # Database ACLs affect every worker's runtime role. Inject this real grant
    # only in the planner's observation transaction, which refusal rolls back.
    # The compiler owns a preceding read-only transaction and must stay read-only.
    observed = []
    observer = engine('CRYPTALIS_TEST_DATABASE_URL')
    def inject(connection):
        if observed or connection.get_execution_options().get('postgresql_readonly'):
            return
        connection.exec_driver_sql(grant)
        observed.append(connection.exec_driver_sql(
            "SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')",
            (app.role,)).scalar_one())
        with observer.connect() as independent:
            assert independent.exec_driver_sql(
                "SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')",
                (app.role,)).scalar_one() is False

    event.listen(app.owner, 'begin', inject)
    try:
        yield
    finally:
        event.remove(app.owner, 'begin', inject)
        try:
            with observer.connect() as independent:
                assert independent.exec_driver_sql(
                    "SELECT pg_catalog.has_database_privilege(%s,current_database(),'CREATE')",
                    (app.role,)).scalar_one() is False
        finally:
            observer.dispose()
    assert observed == [True]


@pytest.mark.parametrize('fault',['database_create','schema_create','table_trigger','table_truncate'])
def test_initial_admission_refuses_effective_unsafe_rights_before_keys(fault):
    with application() as app:
        called=[]
        def forbidden(tenant):
            called.append(tenant)
            raise AssertionError('unsafe roles cannot reach key work')
        with unsafe_rights(app, fault):
            with pytest.raises(m.TransitionFailure,match='unsafe_runtime_role'):
                m.plan(json.dumps(app.plan.document['lock']['declaration']).encode(),app.mapping,app.owner,
                    writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='native role refusal'),)),
                    search_reviews=(SearchReview(FIELD_ID,False,'synthetic fixture'),),keys=forbidden,
                    runtime_role=app.role,target_id=app.plan.target_id,backfill_rows_per_second=1000,
                    verify_rows_per_second=1000,temporary_bytes_per_row=700,wal_bytes_per_row=700)
            assert called==[]
            with app.owner.connect() as c:
                assert c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(f'{app.schema}.{m.JOURNAL}',)).scalar_one() is None


@pytest.mark.parametrize('fault',['journal_update','journal_column_update','schema_create'])
def test_active_and_maintenance_admission_refuse_later_unsafe_rights(fault):
    with application() as app:
        run(app);publish(app)
        before=frames(app,True)
        grant,revoke=privilege_change(app,fault)
        called=[]
        def forbidden(tenant):
            called.append(tenant)
            raise AssertionError('unsafe maintenance cannot reach keys')
        try:
            with app.owner.begin() as c:c.exec_driver_sql(grant)
            with pytest.raises(m.TransitionFailure,match='unsafe_runtime_role'):
                m.check_deployment(app.plan,app.owner,pin=app.pin)
            with pytest.raises(m.TransitionFailure,match='unsafe_runtime_role'):
                m.apply(app.plan,app.owner,keys=forbidden,pin=app.pin,approval=app.approval,until='ACTIVE')
            assert called==[] and frames(app,True)==before
        finally:
            with app.owner.begin() as c:c.exec_driver_sql(revoke)
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None
