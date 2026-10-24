"""Online native-write capture across two protected tables in one schema."""
import json
from uuid import UUID, uuid4

from sqlalchemy import Column, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import sessionmaker

from cryptalis import migration as m, online
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_migration import FIELD_ID, TABLE_ID, keys
from test_online_protection import app


def test_online_capture_and_activation_cover_multiple_same_schema_models(app):
    other_table_id, other_field_id = UUID(int=800), UUID(int=801)
    other_table = Table('other', app.mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('value', Text(collation='C'), nullable=True))

    class Other:
        pass

    app.mapping.map_imperatively(Other, other_table)
    app.mapping.metadata.create_all(app.owner)
    with app.owner.begin() as connection:
        quote = connection.dialect.identifier_preparer.quote
        connection.exec_driver_sql(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{app.schema}"."other" TO {quote(app.source_role)}')
    with sessionmaker(app.source, expire_on_commit=False)() as session:
        session.add_all((Other(id=UUID(int=i), value=f'other-{i}') for i in (40, 50)))
        session.commit()

    declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1',
        'domain_id': app.plan.document['lock']['domain_id'], 'models': [
            {'model': 'Customer', 'table_id': str(TABLE_ID), 'tenancy': {'single_tenant': True},
             'fields': [
                {'name': 'body', 'field_id': str(FIELD_ID), 'protect': True,
                 'queries': ['equality'], 'accept_leakage': ['equality']},
                {'name': 'label', 'field_id': str(UUID(int=FIELD_ID.int + 1)), 'protect': True,
                 'queries': [], 'accept_leakage': []}]},
            {'model': 'Other', 'table_id': str(other_table_id), 'tenancy': {'single_tenant': True},
             'fields': [{'name': 'value', 'field_id': str(other_field_id), 'protect': True,
                         'queries': [], 'accept_leakage': []}]}]}
    writers = WriterInventory(True, (
        Writer(TABLE_ID, 'native customer application', 'sqlalchemy', evidence='source-role CRUD'),
        Writer(other_table_id, 'native other application', 'sqlalchemy', evidence='source-role CRUD')))
    proposal = online.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        source_role=app.source_role, writers=writers, max_rows=1,
        search_reviews=(SearchReview(FIELD_ID, False,
            'Disposable opaque fixture values; equality and frequency leakage accepted.'),),
        keys=keys, runtime_role=app.target_role, target_id=uuid4(),
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
    pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    approval = app.approval

    # Keep each native table operation in an independent session, as an app would.
    with app.source_factory() as session:
        customer_before = {row.id: (row.body, row.label)
                           for row in session.scalars(select(app.Customer))}
    with sessionmaker(app.source, expire_on_commit=False)() as session:
        other_before = {row.id: row.value for row in session.scalars(select(Other))}

    progress = online.apply(proposal, app.owner, keys=keys, pin=pin,
                            approval=approval, max_chunks=1)
    assert progress.phase == 'CAPTURING'
    with app.source_factory() as session:
        row = session.get(app.Customer, UUID(int=10))
        row.body = 'updated customer during capture'
        session.commit()
    with sessionmaker(app.source, expire_on_commit=False)() as session:
        row = session.get(Other, UUID(int=40))
        row.value = 'updated other during capture'
        session.add(Other(id=UUID(int=35), value='inserted other during capture'))
        session.commit()

    fenced = online.apply(proposal, app.owner, keys=keys, pin=pin,
                          approval=approval, max_chunks=2, fence=True)
    assert fenced.phase == 'FENCED'
    with app.owner.connect() as connection:
        names = connection.exec_driver_sql('''SELECT r.relname, p.proname
            FROM pg_catalog.pg_trigger g
            JOIN pg_catalog.pg_class r ON r.oid=g.tgrelid
            JOIN pg_catalog.pg_proc p ON p.oid=g.tgfoid
            JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
            WHERE n.nspname=%s AND r.relname IN ('customer','other')
              AND g.tgname LIKE '_cryptalis_%%_capture'
            ORDER BY r.relname''', (app.schema,)).all()
    assert {table for table, _ in names} == {'customer', 'other'}
    assert len({name for _, name in names}) == 2

    online.apply(proposal, app.owner, keys=keys, pin=pin,
                 approval=approval, max_chunks=8)
    successor = online.seal(proposal, app.owner, keys=keys, pin=pin, approval=approval)
    successor = online.switch(proposal, app.owner, successor=successor,
                              keys=keys, pin=pin, approval=approval)
    activating = m.DeploymentPin(successor.target_id, successor.operation_id,
                                 successor.digest, 'ACTIVATING')
    assert m.apply(successor, app.owner, keys=keys, pin=activating,
        approval=m.MaintenanceApproval(approval.owner_writer_exclusion, 3600),
        until='ACTIVE').phase == 'ACTIVE'
    active = m.DeploymentPin(successor.target_id, successor.operation_id,
                             successor.digest, 'ACTIVE')
    protected = attach(app.mapping, app.target, lock=successor.lock_bytes,
                       keys=keys, deployment=(successor, active))
    expected_customer = dict(customer_before)
    expected_customer[UUID(int=10)] = ('updated customer during capture', 'label-10')
    expected_other = dict(other_before)
    expected_other[UUID(int=40)] = 'updated other during capture'
    expected_other[UUID(int=35)] = 'inserted other during capture'
    with protected(tenant_id=TABLE_ID, expire_on_commit=False) as session:
        observed = {row.id: (row.body, row.label)
                    for row in session.scalars(select(app.Customer))}
        assert observed == expected_customer
    with protected(tenant_id=other_table_id, expire_on_commit=False) as session:
        observed = {row.id: row.value for row in session.scalars(select(Other))}
        assert observed == expected_other
