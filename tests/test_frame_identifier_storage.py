"""Native identifier spelling must preserve exact storage/search admission."""
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Column, Index, Integer, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import migration as m
from cryptalis._sqlalchemy_search import validate_frame_storage
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory, _catalog_path
from cryptalis.sqlalchemy import PolicyMismatch, attach
import test_deprotection as reverse
import test_migration as fixture
from test_owned_sequences import finish_reverse
from test_public_slots import select_layout


@contextmanager
def application(column_name, *, integer=False):
    owner, runtime = fixture.engine('CRYPTALIS_TEST_DATABASE_URL'), fixture.engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'frame_identifier_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False), Column('tenant_id', Uuid, nullable=False),
        Column(column_name, Integer() if integer else Text(collation='C'), quote=True), Column('label', Text))
    value_column = table.c[column_name]
    queries = [] if integer else ['equality']
    if queries:
        Index('native_name', value_column)
    class Customer: pass
    mapping.map_imperatively(Customer, table, properties={'name': value_column})
    declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(fixture.DOMAIN),
        'models': [{'model': 'Customer', 'table_id': str(fixture.TABLE_ID), 'tenancy': {'column': 'tenant_id'},
            'fields': [{'name': 'name', 'field_id': str(fixture.FIELD_ID), 'protect': True,
                        'queries': queries, 'accept_leakage': queries}]}]}
    with runtime.connect() as connection:
        role = connection.exec_driver_sql('SELECT current_user').scalar_one()
    values = (None, -17, 0) if integer else (None, 'é', '雪')
    source = {UUID(int=100 + index): (fixture.TENANT, value) for index, value in enumerate(values)}
    try:
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote_identifier
            connection.exec_driver_sql(f'CREATE SCHEMA {quote(schema)}')
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote_identifier
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA {quote(schema)} FROM PUBLIC')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA {quote(schema)} TO {quote(role)}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON {quote(schema)}.customer TO {quote(role)}')
        with sessionmaker(runtime)() as session:
            session.add_all(Customer(id=identity, tenant_id=tenant, name=value, label='public fixture')
                            for identity, (tenant, value) in source.items())
            session.commit()
        plan = m.plan(m._canonical(declaration), mapping, owner,
            writers=WriterInventory(True, (Writer(fixture.TABLE_ID, 'app', 'sqlalchemy', evidence='public identifier fixture'),)),
            search_reviews=(SearchReview(fixture.FIELD_ID, False, 'synthetic unbounded names'),) if queries else (),
            keys=fixture.keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        yield SimpleNamespace(m=m, owner=owner, runtime=runtime, schema=schema, mapping=mapping, table=table,
            value_column=value_column, Customer=Customer, source=source, plan=plan, role=role,
            pin=m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, 'PREPARED'),
            approval=m.MaintenanceApproval('operator stopped public fixture writers', 3600))
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            quote = connection.dialect.identifier_preparer.quote_identifier
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS {quote(schema)} CASCADE')
        owner.dispose()
        mapping.dispose()


@pytest.mark.parametrize('public_slots', [False, True])
@pytest.mark.parametrize('column_name,integer', [
    ('integer', True), ('coalesce', False), ('collation', False),
    ('ordinary', False), ('MixedCase', False), ('embedded"quote', False),
])
def test_native_identifier_protect_search_edit_and_remove(column_name, integer, public_slots):
    with application(column_name, integer=integer) as app:
        if public_slots:
            select_layout(app)
        assert fixture.run(app).phase == 'PENDING'
        assert fixture.publish(app).phase == 'ACTIVE'
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=fixture.keys,
                          deployment=(app.plan, app.pin))
        latest = -2147483648 if integer else 'latest 雪 é'
        with sessions(tenant_id=fixture.TENANT) as session:
            observed = {row.id: row.name for row in session.scalars(select(app.Customer))}
            assert observed == {identity: value for identity, (_, value) in app.source.items()}
            session.get(app.Customer, UUID(int=100)).name = latest
            session.commit()
            session.expire_all()
            assert session.get(app.Customer, UUID(int=100)).name == latest
            if not integer:
                scope = app.Customer.tenant_id == fixture.TENANT
                assert session.scalars(select(app.Customer.id).where(
                    scope, app.Customer.name == latest)).all() == [UUID(int=100)]
                assert set(session.scalars(select(app.Customer.id).where(
                    scope, app.Customer.name.in_([latest, 'é'])))) == {UUID(int=100), UUID(int=101)}
        proposal = reverse.proposal(app)
        assert reverse.reverse(app, proposal).phase == 'PLAINTEXT_PENDING'
        finish_reverse(app, proposal)
        expected = {identity: value for identity, (_, value) in app.source.items()}
        expected[UUID(int=100)] = latest
        with app.owner.connect() as connection:
            quote = connection.dialect.identifier_preparer.quote_identifier
            assert dict(connection.exec_driver_sql(
                f'SELECT id,{quote(column_name)} FROM {quote(app.schema)}.customer').all()) == expected


@pytest.mark.parametrize('tamper', ['changed_bound', 'extra_dependency'])
def test_identifier_quoting_admission_refuses_changed_check_before_provider(tamper):
    with application('integer', integer=True) as app:
        fixture.run(app)
        fixture.publish(app)
        model = app.plan.document['lock']['models'][0]
        field = model['fields'][0]
        frame = field['payload_column'] + '_frame'
        with app.owner.begin() as connection:
            table = m._table(connection, model)
            quote = connection.dialect.identifier_preparer.quote_identifier
            definition = connection.exec_driver_sql(
                'SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint '
                'WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s', (table, frame)).scalar_one()
            if tamper == 'changed_bound':
                changed = definition.replace('>= 46', '>= 45', 1)
            else:
                changed = definition[:-1] + ' AND (label IS NULL OR label IS NOT NULL))'
            assert changed != definition
            connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {quote(frame)}')
            connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {quote(frame)} {changed}')
        calls = []
        def keys(tenant):
            calls.append(tenant)
            return fixture.keys(tenant)
        with pytest.raises((PolicyMismatch, m.TransitionFailure)):
            attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                   deployment=(app.plan, app.pin))
        assert calls == []


@pytest.mark.parametrize('column_name,integer', [('integer', True), ('coalesce', False)])
def test_native_reparsed_check_keeps_explicit_exact_restore_admission(column_name, integer):
    with application(column_name, integer=integer) as app:
        fixture.run(app)
        fixture.publish(app)
        model = app.plan.document['lock']['models'][0]
        field = model['fields'][0]
        frame = field['payload_column'] + '_frame'
        with app.owner.begin() as connection:
            table = m._table(connection, model)
            quote = connection.dialect.identifier_preparer.quote_identifier
            with _catalog_path(connection):
                definition, before = connection.exec_driver_sql(
                    'SELECT pg_catalog.pg_get_constraintdef(oid),pg_catalog.pg_get_expr(conbin,conrelid) '
                    'FROM pg_catalog.pg_constraint WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                    (table, frame)).one()
                # Reparse PostgreSQL's own dump definition; this flattens the
                # original BETWEEN-derived Boolean group on PostgreSQL 16.
                connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {quote(frame)}')
                connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {quote(frame)} {definition}')
                after = connection.exec_driver_sql(
                    'SELECT pg_catalog.pg_get_expr(conbin,conrelid) FROM pg_catalog.pg_constraint '
                    'WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s', (table, frame)).scalar_one()
            assert before != after
            with pytest.raises(ValueError):
                validate_frame_storage(connection, model, field)
            validate_frame_storage(connection, model, field, admitted=after)
            with pytest.raises(ValueError):
                validate_frame_storage(connection, model, field, admitted=before)
            changed = after.replace('>= 46', '>= 45', 1) if integer else after.replace('>= 74', '>= 73', 1)
            assert changed != after
            connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {quote(frame)}')
            connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {quote(frame)} CHECK ({changed})')
            with pytest.raises(ValueError):
                validate_frame_storage(connection, model, field, admitted=changed)
