"""Online protection preserves policy for approved native tenant scopes."""
from dataclasses import replace
import json
import os
import subprocess
import sys
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, Index, MetaData, String, Table, Text, Uuid, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import deprotection as d, migration as m, online, restore, rotation
from cryptalis.crypto import DevelopmentKeyProvider, Keyring
from cryptalis.crypto._rewrap import prepare_rewrap
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_migration import FIELD_ID, TABLE_ID, TENANT, keys
from test_online_protection import app
from test_online_recovery import engine as _engine, generation as _generation
from test_online_recovery import pg_bin as _pg_bin, pg_environment as _pg_environment


OTHER_TABLE, OTHER_FIELD, OTHER_TENANT = (UUID(int=value) for value in (3121, 3122, 3123))
NIL_TENANT = UUID(int=0)


@pytest.fixture
def tenant_app(app):
    """Extend the native SQLAlchemy source-role capture fixture with a scoped table."""
    table = Table('tenant_customer', app.mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False),
        Column('name', Text(collation='C'), nullable=True))
    Index('tenant_customer_name', table.c.tenant_id, table.c.name, unique=True)

    class TenantCustomer:
        pass

    app.mapping.map_imperatively(TenantCustomer, table)
    table.create(app.owner)
    with app.owner.begin() as connection:
        quote = connection.dialect.identifier_preparer.quote
        connection.exec_driver_sql(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{app.schema}"."tenant_customer" '
            f'TO {quote(app.source_role)}')
    with app.source_factory() as session:
        session.add_all((TenantCustomer(id=UUID(int=1001), tenant_id=TENANT, name='same-name'),
                         TenantCustomer(id=UUID(int=1002), tenant_id=OTHER_TENANT, name='same-name')))
        session.commit()

    declaration = app.plan.document['lock']['declaration']
    declaration['models'].append({'model': 'TenantCustomer', 'table_id': str(OTHER_TABLE),
        'tenancy': {'column': 'tenant_id'}, 'fields': [
            {'name': 'name', 'field_id': str(OTHER_FIELD), 'protect': True,
             'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']} ]})
    inventory = WriterInventory(True, (
        Writer(TABLE_ID, 'native application', 'sqlalchemy', evidence='fixture source-role ORM sessions'),
        Writer(OTHER_TABLE, 'native application', 'sqlalchemy', evidence='fixture source-role ORM sessions'),
    ))
    app.inventory = inventory
    proposal = online.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        source_role=app.source_role, writers=inventory,
        search_reviews=(SearchReview(FIELD_ID, False, 'Disposable opaque fixture values.'),
                        SearchReview(OTHER_FIELD, False, 'Disposable opaque fixture values.')),
        keys=keys, runtime_role=app.target_role, target_id=uuid4(),
        native_tenants=(NIL_TENANT, TENANT, OTHER_TENANT), max_rows=1,
        max_bytes=4096, backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
    app.tenant_table, app.TenantCustomer = table, TenantCustomer
    app.tenant_plan = proposal
    app.tenant_pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    yield app


def _pin(proposal, phase):
    return m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, phase)


def _transition_approval(app):
    return m.MaintenanceApproval(app.approval.owner_writer_exclusion, 3600)


def _target_id(plan):
    return plan.target_id if hasattr(plan, 'target_id') else plan.source.target_id


def _rotation_pin(plan, phase):
    return m.DeploymentPin(_target_id(plan), plan.operation_id, plan.digest, phase)


def _rotate_all_scopes(owner, source, source_keys, contract, binding):
    provider, cache = DevelopmentKeyProvider(), {}
    old_keys = source_keys

    def target_keys(tenant):
        if tenant not in cache:
            policy = prepare_rewrap(old_keys(tenant), provider)
            cache[tenant] = Keyring(policy, {provider.provider_id: provider})
        return cache[tenant]

    proposal = rotation.plan_rewrap(source, owner, source_pin=_rotation_pin(source, 'ACTIVE'),
        keys=source_keys, target_keys=target_keys, verify_rows_per_second=1000, restore=binding)
    successor = proposal.activation_plan
    assert successor.document['access_contract'] == contract
    assert successor.document['format'] == ('cryptalis.transition/v12' if binding else 'cryptalis.transition/v9')
    assert rotation.apply_rewrap(proposal, owner, keys=source_keys, target_keys=target_keys,
        pin=_rotation_pin(successor, 'PREPARED'), approval=_transition_approval_for_rotation()).phase == 'PENDING'
    assert m.apply(successor, owner, keys=target_keys, pin=_rotation_pin(successor, 'ACTIVATING'),
        approval=_transition_approval_for_rotation(), until='ACTIVE').phase == 'ACTIVE'
    source, source_keys = successor, target_keys
    for purpose, normal_format, adopted_format in (
            ('payload', 'cryptalis.transition/v10', 'cryptalis.transition/v13'),
            ('search', 'cryptalis.transition/v11', 'cryptalis.transition/v14')):
        target_keys = _generation(source_keys, purpose)
        proposal = getattr(rotation, 'plan_' + purpose + '_rotation')(
            source, owner, source_pin=_rotation_pin(source, 'ACTIVE'), keys=source_keys,
            target_keys=target_keys, backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        assert getattr(rotation, 'apply_' + purpose + '_rotation')(
            proposal, owner, keys=source_keys, target_keys=target_keys,
            pin=_rotation_pin(proposal, 'PREPARED'), approval=_transition_approval_for_rotation()).phase == 'BACKFILLED'
        successor = getattr(rotation, 'seal_' + purpose + '_rotation')(
            proposal, owner, keys=source_keys, target_keys=target_keys,
            pin=_rotation_pin(proposal, 'PREPARED'), approval=_transition_approval_for_rotation(),
            copy_rows_per_second=1000, copy_wal_bytes_per_row=3000)
        assert successor.document['format'] == (adopted_format if binding else normal_format)
        assert successor.document['access_contract'] == contract
        assert getattr(rotation, 'switch_' + purpose + '_rotation')(
            proposal, successor, owner, keys=source_keys, target_keys=target_keys,
            pin=_rotation_pin(successor, 'PREPARED'), approval=_transition_approval_for_rotation()).phase == 'PENDING'
        assert m.apply(successor, owner, keys=target_keys,
            pin=_rotation_pin(successor, 'ACTIVATING'), approval=_transition_approval_for_rotation(),
            until='ACTIVE').phase == 'ACTIVE'
        source, source_keys = successor, target_keys
    return source, source_keys


def _transition_approval_for_rotation():
    return m.MaintenanceApproval(
        'Disposable qualification harness stopped source writers and excluded owner writers.', 3600)


def test_online_tenant_authority_survives_restore_rotations_and_current_native_exit(tenant_app, tmp_path):
    destination = os.environ.get('CRYPTALIS_ONLINE_RESTORE_DATABASE')
    if not destination:
        pytest.skip('requires the explicit disposable restore database from online_qualification.py')
    app, proposal = tenant_app, tenant_app.tenant_plan
    urls = {name: os.environ[variable] for name, variable in (
        ('owner', 'CRYPTALIS_TEST_DATABASE_URL'), ('target', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'),
        ('source', 'CRYPTALIS_TEST_SOURCE_URL'))}
    restored_urls = {name: psycopg.conninfo.make_conninfo(value, dbname=destination)
                     for name, value in urls.items()}
    assert psycopg.conninfo.conninfo_to_dict(urls['owner'])['dbname'] != destination
    assert proposal.document['format'] == online.TENANT_FORMAT
    assert proposal.document['native_tenants'] == sorted(map(str, (NIL_TENANT, TENANT, OTHER_TENANT)))
    assert str(NIL_TENANT) in proposal.document['key_policies']

    expected_customer = {UUID(int=i): (f'body-{i}', f'label-{i}') for i in (10, 20, 30)}
    expected_tenant = {UUID(int=1001): (TENANT, 'same-name'),
                       UUID(int=1002): (OTHER_TENANT, 'same-name')}
    # Stage a real frame for one row in each model first. Then exercise all four
    # native invalidation forms: tenant+record move, lower-key insert,
    # delete/reinsert, and NULL value.
    assert online.apply(proposal, app.owner, keys=keys, pin=app.tenant_pin,
                        approval=app.approval, max_chunks=1).phase == 'CAPTURING'
    customer_model = next(model for model in proposal.document['lock']['models']
                          if model['table_id'] == str(TABLE_ID))
    tenant_model = next(model for model in proposal.document['lock']['models']
                        if model['table_id'] == str(OTHER_TABLE))
    dirty_column = '_cryptalis_' + proposal.operation_id.hex + '_dirty'
    customer_payloads = ','.join('"' + field['payload_column'] + '"'
                                 for field in customer_model['fields'])
    tenant_payload = tenant_model['fields'][0]['payload_column']
    for _ in range(16):
        with app.owner.connect() as connection:
            customer_shadow = connection.exec_driver_sql(
                f'SELECT {customer_payloads},"{dirty_column}" FROM "{app.schema}"."customer" WHERE id=%s',
                (UUID(int=10),)).one()
            tenant_shadow = connection.exec_driver_sql(
                f'SELECT "{tenant_payload}","{dirty_column}" FROM "{app.schema}"."tenant_customer" WHERE id=%s',
                (UUID(int=1001),)).one()
        if (all(value is not None for value in customer_shadow[:-1]) and customer_shadow[-1] is False
                and tenant_shadow[0] is not None and tenant_shadow[1] is False):
            break
        online.apply(proposal, app.owner, keys=keys, pin=app.tenant_pin,
                     approval=app.approval, max_chunks=1)
    else:
        pytest.fail('bounded capture did not stage the selected native rows')
    with app.source_factory() as session:
        customer = session.get(app.Customer, UUID(int=10))
        customer.body, customer.label = 'native changed below cursor', 'native label changed below cursor'
        moved = session.get(app.TenantCustomer, UUID(int=1001))
        moved.id = UUID(int=1101)
        moved.tenant_id, moved.name = OTHER_TENANT, 'moved during capture'
        session.add(app.TenantCustomer(id=UUID(int=999), tenant_id=TENANT, name='lower key'))
        session.delete(session.get(app.TenantCustomer, UUID(int=1002)))
        session.commit()
    with app.source_factory() as session:
        session.add_all((app.TenantCustomer(id=UUID(int=1002), tenant_id=OTHER_TENANT, name='same-name'),
                         app.TenantCustomer(id=UUID(int=1003), tenant_id=TENANT, name='new tenant value'),
                         app.TenantCustomer(id=UUID(int=1006), tenant_id=TENANT, name='same-name'),
                         app.TenantCustomer(id=UUID(int=1007), tenant_id=TENANT, name=None)))
        session.commit()
    expected_tenant.pop(UUID(int=1001))
    expected_tenant.update({UUID(int=1101): (OTHER_TENANT, 'moved during capture'),
                            UUID(int=999): (TENANT, 'lower key'),
                            UUID(int=1003): (TENANT, 'new tenant value'),
                            UUID(int=1006): (TENANT, 'same-name'),
                            UUID(int=1007): (TENANT, None)})
    expected_customer[UUID(int=10)] = ('native changed below cursor', 'native label changed below cursor')
    payload_column = tenant_model['fields'][0]['payload_column']
    with app.owner.connect() as connection:
        shadows = connection.exec_driver_sql(
            f'SELECT id,"{payload_column}","{dirty_column}" FROM "{app.schema}"."tenant_customer" '
            'WHERE id=ANY(%s)', ([UUID(int=value) for value in (1101, 1002, 999, 1003, 1006, 1007)],)).all()
    assert {row[0] for row in shadows} == {UUID(int=value) for value in (1101, 1002, 999, 1003, 1006, 1007)}
    assert all(row[1] is None and row[2] is True for row in shadows)
    with app.owner.connect() as connection:
        customer_shadows = connection.exec_driver_sql(
            f'SELECT {customer_payloads},"{dirty_column}" FROM "{app.schema}"."customer" WHERE id=%s',
            (UUID(int=10),)).one()
    assert tuple(customer_shadows[:-1]) == (None, None) and customer_shadows[-1] is True
    with pytest.raises(DBAPIError) as unknown:
        with app.source.begin() as connection:
            connection.exec_driver_sql(
                f'INSERT INTO "{app.schema}"."tenant_customer" (id,tenant_id,name) VALUES (%s,%s,%s)',
                (UUID(int=1005), UUID(int=9999), 'unapproved'))
    assert getattr(unknown.value.orig, 'sqlstate', None) == '55000'
    with pytest.raises(DBAPIError) as null_tenant:
        with app.source.begin() as connection:
            connection.exec_driver_sql(
                f'INSERT INTO "{app.schema}"."tenant_customer" (id,tenant_id,name) VALUES (%s,%s,%s)',
                (UUID(int=1008), None, 'null tenant'))
    assert getattr(null_tenant.value.orig, 'sqlstate', None) == '23502'

    assert online.apply(proposal, app.owner, keys=keys, pin=app.tenant_pin,
        approval=app.approval, max_chunks=32, fence=True).phase == 'FENCED'
    online.apply(proposal, app.owner, keys=keys, pin=app.tenant_pin,
                 approval=app.approval, max_chunks=32)
    sealed = online.seal(proposal, app.owner, keys=keys, pin=app.tenant_pin, approval=app.approval)
    successor = online.switch(proposal, app.owner, successor=sealed, keys=keys,
                              pin=app.tenant_pin, approval=app.approval)
    assert m.apply(successor, app.owner, keys=keys, pin=_pin(successor, 'ACTIVATING'),
                   approval=_transition_approval(app), until='ACTIVE').phase == 'ACTIVE'
    contract = successor.document['access_contract']

    # The protected database is the only authority after the source schema is
    # removed. The later empty-NIL write is intentionally deferred until after
    # restored adoption and all three rotations.
    dump_path = tmp_path / 'online-tenants.sql'
    dump_path.touch(mode=0o600)
    with dump_path.open('wb') as output:
        result = subprocess.run([_pg_bin('pg_dump'), '--schema=' + app.schema],
            env=_pg_environment(urls['owner']), stdout=output, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'protected tenant dump failed; diagnostics withheld'
    app.target.dispose()
    app.source.dispose()
    with app.owner.begin() as connection:
        connection.exec_driver_sql(f'DROP SCHEMA "{app.schema}" CASCADE')
        assert connection.exec_driver_sql('SELECT pg_catalog.to_regnamespace(%s)',
                                          (app.schema,)).scalar_one() is None
    restored_owner = _engine(restored_urls['owner'])
    restored_target = _engine(restored_urls['target'])
    restored_source = _engine(restored_urls['source'])
    try:
        with dump_path.open('rb') as source:
            result = subprocess.run([_pg_bin('psql'), '-X', '--set=ON_ERROR_STOP=1'],
                env=_pg_environment(restored_urls['owner']), stdin=source,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode == 0, 'protected tenant restore failed; diagnostics withheld'
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(successor, restored_owner, pin=_pin(successor, 'ACTIVE'))
        restore_approval = restore.RestoreApproval('isolated tenant qualification harness',
            'Adopt restored multi-tenant protected database after source schema decommission',
            'No application traffic until explicit restored publication', True)
        binding = restore.plan(successor, restored_owner, pin=_pin(successor, 'ACTIVE'),
                               keys=keys, approval=restore_approval)
        assert m.check_deployment(successor, restored_owner, pin=_pin(successor, 'ACTIVE'),
                                  restore=binding) is None
        successor, current_keys = _rotate_all_scopes(restored_owner, successor, keys, contract, binding)
        assert successor.document['format'] == 'cryptalis.transition/v14'
        assert set(successor.document['key_policies']) == {str(TABLE_ID), str(NIL_TENANT),
                                                           str(TENANT), str(OTHER_TENANT)}
        assert current_keys(NIL_TENANT).policy.payload_generation == 2
        assert current_keys(NIL_TENANT).policy.search_generation == 2

        sessions = attach(app.mapping, restored_target, lock=successor.lock_bytes, keys=current_keys,
                          deployment=(successor, _pin(successor, 'ACTIVE')))
        with sessions(tenant_id=TENANT, expire_on_commit=False) as session:
            assert session.scalar(select(app.TenantCustomer.id).where(
                app.TenantCustomer.name == 'same-name')) == UUID(int=1006)
            assert session.scalar(select(app.TenantCustomer.id).where(
                app.TenantCustomer.name == 'lower key')) == UUID(int=999)
            session.add(app.TenantCustomer(id=UUID(int=1099), tenant_id=TENANT, name='same-name'))
            with pytest.raises(DBAPIError) as duplicate:
                session.commit()
            assert getattr(duplicate.value.orig, 'sqlstate', None) == '23505'
            session.rollback()
            session.delete(session.get(app.TenantCustomer, UUID(int=1003)))
            session.commit()
            del expected_tenant[UUID(int=1003)]
        with sessions(tenant_id=TABLE_ID) as session:
            assert session.scalar(select(app.Customer.id).where(
                app.Customer.body == 'native changed below cursor')) == UUID(int=10)
        with sessions(tenant_id=OTHER_TENANT, expire_on_commit=False) as session:
            assert session.scalar(select(app.TenantCustomer.id).where(
                app.TenantCustomer.name == 'same-name')) == UUID(int=1002)
            moved = session.get(app.TenantCustomer, UUID(int=1101))
            assert moved.name == 'moved during capture'
            moved.name = 'latest protected tenant value'
            session.add(app.TenantCustomer(id=UUID(int=1010), tenant_id=OTHER_TENANT,
                                           name='protected other tenant'))
            session.commit()
            expected_tenant[UUID(int=1101)] = (OTHER_TENANT, 'latest protected tenant value')
            expected_tenant[UUID(int=1010)] = (OTHER_TENANT, 'protected other tenant')
        with sessions(tenant_id=NIL_TENANT) as session:
            # NIL was empty at planning, capture, backup, and restore. Its first
            # row after all rotations exercises the retained generation-2 key.
            session.add(app.TenantCustomer(id=UUID(int=1008), tenant_id=NIL_TENANT,
                                           name='first protected nil row'))
            session.commit()
            assert session.scalar(select(app.TenantCustomer.name).where(
                app.TenantCustomer.id == UUID(int=1008))) == 'first protected nil row'
            expected_tenant[UUID(int=1008)] = (NIL_TENANT, 'first protected nil row')

        reverse = d.plan(successor, restored_owner, source_pin=_pin(successor, 'ACTIVE'),
            keys=current_keys, plaintext_runtime_role=app.source_role,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            True, 'Public disposable multi-tenant fixture; test-only protected dump is retained until cleanup.')
        approval = m.MaintenanceApproval(
            'Application engines closed; only the declared owner performs the native reverse transition.', 3600)
        assert d.apply(reverse, restored_owner, keys=current_keys, pin=_pin(reverse, 'PREPARED'),
            approval=approval, consent=consent, until='PLAINTEXT_PENDING').phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, restored_owner, keys=current_keys,
            pin=_pin(reverse, 'PLAINTEXT_ACTIVATING'), approval=approval,
            consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        native_mapping = registry(metadata=MetaData(schema=app.schema))
        native_customer_table = Table('customer', native_mapping.metadata,
            Column('id', Uuid, primary_key=True, autoincrement=False),
            Column('body', Text(collation='C'), nullable=True),
            Column('label', String(64, collation='C'), nullable=True))
        native_tenant_table = Table('tenant_customer', native_mapping.metadata,
            Column('id', Uuid, primary_key=True, autoincrement=False),
            Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C'), nullable=True))
        class NativeCustomer: pass
        class NativeTenantCustomer: pass
        native_mapping.map_imperatively(NativeCustomer, native_customer_table)
        native_mapping.map_imperatively(NativeTenantCustomer, native_tenant_table)
        with sessionmaker(restored_source)() as session:
            assert {row.id: (row.body, row.label) for row in session.scalars(select(NativeCustomer))} == expected_customer
            assert {row.id: (row.tenant_id, row.name) for row in session.scalars(
                select(NativeTenantCustomer))} == expected_tenant
            session.get(NativeCustomer, UUID(int=10)).body = 'native after all tenant rotations'
            session.commit()
            expected_customer[UUID(int=10)] = ('native after all tenant rotations', 'native label changed below cursor')
        restored_target.dispose()
        revoked_target = _engine(restored_urls['target'])
        with pytest.raises(DBAPIError) as target_denied:
            with revoked_target.connect() as connection:
                connection.exec_driver_sql(f'SELECT id FROM "{app.schema}"."tenant_customer"').all()
        assert getattr(target_denied.value.orig, 'sqlstate', None) == '42501'
        revoked_target.dispose()
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'Native source role reads and edits current rows in both mapped tables.',
            'The local test dump remains with ephemeral public fixture custody until cleanup.', True)
        assert d.remove(reverse, restored_owner, pin=_pin(reverse, 'REMOVING'),
            approval=approval, removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, restored_owner, pin=_pin(reverse, 'REMOVED')) is None
        with sessionmaker(restored_source)() as session:
            assert {row.id: (row.body, row.label) for row in session.scalars(select(NativeCustomer))} == expected_customer
            assert {row.id: (row.tenant_id, row.name) for row in session.scalars(
                select(NativeTenantCustomer))} == expected_tenant
        expected = {'customer': {str(key): list(value) for key, value in expected_customer.items()},
                    'tenant_customer': {str(key): [str(value[0]), value[1]]
                                        for key, value in expected_tenant.items()}}
        program = '''
import importlib.abc,json,os,sys
class NoCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='cryptalis' or fullname.startswith('cryptalis.'):
            raise RuntimeError('Cryptalis imports are forbidden after removal')
sys.meta_path.insert(0,NoCryptalis())
import psycopg
from psycopg import sql
schema=sys.argv[1]; expected=json.loads(sys.argv[2])
with psycopg.connect(os.environ['CRYPTALIS_ONLINE_NATIVE_URL']) as c:
    customer=c.execute(sql.SQL('SELECT id,body,label FROM {}.customer ORDER BY id').format(sql.Identifier(schema))).fetchall()
    tenant=c.execute(sql.SQL('SELECT id,tenant_id,name FROM {}.tenant_customer ORDER BY id').format(sql.Identifier(schema))).fetchall()
    assert {str(r[0]):list(r[1:]) for r in customer}==expected['customer']
    assert {str(r[0]):[str(r[1]),r[2]] for r in tenant}==expected['tenant_customer']
    c.execute(sql.SQL('UPDATE {}.customer SET body=%s WHERE id=%s').format(sql.Identifier(schema)),
              ('package-free native write',customer[0][0]))
assert not any(name=='cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('package-free current multi-tenant rows and native write passed')
'''
        child = subprocess.run([sys.executable, '-I', '-c', program, app.schema, json.dumps(expected)],
            env=dict(os.environ, CRYPTALIS_ONLINE_NATIVE_URL=restored_urls['source']),
            capture_output=True, text=True, timeout=20)
        assert child.returncode == 0, 'package-free native child failed; diagnostics withheld'
        assert child.stdout.strip() == 'package-free current multi-tenant rows and native write passed'
        native_mapping.dispose()
    finally:
        with restored_owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{app.schema}" CASCADE')
        restored_target.dispose()
        restored_source.dispose()
        restored_owner.dispose()


def test_online_tenant_prepare_race_and_artifacts_reject_unapproved_scope(tenant_app):
    app, proposal = tenant_app, tenant_app.tenant_plan
    with app.source_factory() as session:
        session.add(app.TenantCustomer(id=UUID(int=1100), tenant_id=UUID(int=7777), name='bad'))
        session.commit()
    with pytest.raises(m.TransitionFailure, match='online_tenant_not_approved'):
        online.apply(proposal, app.owner, keys=keys, pin=app.tenant_pin, approval=app.approval)
    with app.owner.connect() as connection:
        assert connection.exec_driver_sql(
            'SELECT count(*) FROM information_schema.columns WHERE table_schema=%s '
            "AND pg_catalog.left(column_name,11) = '_cryptalis_'", (app.schema,)).scalar_one() == 0
    with pytest.raises(m.TransitionFailure, match='online_tenant_not_approved'):
        key_lookups = []

        def recording_keys(tenant):
            key_lookups.append(tenant)
            assert tenant != UUID(int=7777), 'unapproved tenant reached the host key resolver'
            return keys(tenant)

        online.plan(json.dumps(proposal.document['lock']['declaration']).encode(), app.mapping, app.owner,
            source_role=app.source_role, writers=app.inventory,
            search_reviews=(SearchReview(FIELD_ID, False, 'Fixture.'),
                            SearchReview(OTHER_FIELD, False, 'Fixture.')),
            keys=recording_keys, runtime_role=app.target_role, target_id=uuid4(),
            native_tenants=(NIL_TENANT, TENANT, OTHER_TENANT), max_rows=1, max_bytes=4096,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=2000, wal_bytes_per_row=4000)
    assert UUID(int=7777) not in key_lookups
    for mutate in (
            lambda document: document['native_tenants'].reverse(),
            lambda document: document['native_tenants'].append(document['native_tenants'][0]),
            lambda document: document['key_policies'].pop(str(NIL_TENANT))):
        altered = proposal.document
        mutate(altered)
        with pytest.raises(m.TransitionFailure, match='invalid_online_plan'):
            replace(proposal, artifact=m._canonical(altered))
