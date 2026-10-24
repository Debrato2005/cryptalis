"""Online access authority across all rotations and a real database restore.

The same process retains ephemeral development custody. This does not prove
independent provider recovery or a different PostgreSQL cluster.
"""
from dataclasses import replace
import os
from pathlib import Path
import runpy
import subprocess
import json
import sys
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, create_engine, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import _access_contract as access
from cryptalis import deprotection as d, migration as m, online, restore, rotation
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring
from cryptalis.crypto.keys import create_root
from cryptalis.crypto._rewrap import prepare_rewrap
from cryptalis.sqlalchemy import attach
pg_bin = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/fresh_cluster_qualification.py'))['pg_bin']
from test_online_protection import app
from test_migration import TABLE_ID, keys


MAINTENANCE = m.MaintenanceApproval(
    'Disposable online fixture: application engines closed and owner is the only maintenance writer.', 3600)


def pin(plan, phase):
    target = plan.target_id if hasattr(plan, 'target_id') else plan.source.target_id
    return m.DeploymentPin(target, plan.operation_id, plan.digest, phase)


def generation(source, purpose):
    """Test custody retains every earlier provider and independent root."""
    provider, cache = DevelopmentKeyProvider(), {}

    def resolve(tenant):
        if tenant not in cache:
            old = source(tenant)
            number = max(w.context.generation for w in old.policy.wrappers
                         if w.context.purpose == purpose) + 1
            context = KeyContext(old.policy.domain_id, tenant, purpose, uuid4(), number)
            wrapper = create_root(provider, context)
            policy = replace(old.policy, wrappers=old.policy.wrappers + (wrapper,),
                             **{purpose + '_generation': number})
            cache[tenant] = Keyring(policy, {**old._providers, provider.provider_id: provider})
        return cache[tenant]

    return resolve


def rotate_all(owner, source, source_keys, contract, *, binding=None):
    provider = DevelopmentKeyProvider()
    policy = prepare_rewrap(source_keys(TABLE_ID), provider)
    rewrapped = Keyring(policy, {provider.provider_id: provider})

    def target_keys(tenant):
        assert tenant == TABLE_ID
        return rewrapped

    before = frame_bytes(owner, source)
    proposal = rotation.plan_rewrap(source, owner, source_pin=pin(source, 'ACTIVE'),
        keys=source_keys, target_keys=target_keys, verify_rows_per_second=1000, restore=binding)
    successor = proposal.activation_plan
    assert successor.document['access_contract'] == contract
    assert successor.document['format'] == ('cryptalis.transition/v12' if binding else 'cryptalis.transition/v9')
    assert rotation.apply_rewrap(proposal, owner, keys=source_keys, target_keys=target_keys,
        pin=pin(successor, 'PREPARED'), approval=MAINTENANCE).phase == 'PENDING'
    assert frame_bytes(owner, successor) == before
    assert m.apply(successor, owner, keys=target_keys, pin=pin(successor, 'ACTIVATING'),
                   approval=MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    source, source_keys = successor, target_keys
    for purpose, normal_format, adopted_format in (
            ('payload', 'cryptalis.transition/v10', 'cryptalis.transition/v13'),
            ('search', 'cryptalis.transition/v11', 'cryptalis.transition/v14')):
        target_keys = generation(source_keys, purpose)
        proposal = getattr(rotation, 'plan_' + purpose + '_rotation')(
            source, owner, source_pin=pin(source, 'ACTIVE'), keys=source_keys, target_keys=target_keys,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        assert getattr(rotation, 'apply_' + purpose + '_rotation')(
            proposal, owner, keys=source_keys, target_keys=target_keys,
            pin=pin(proposal, 'PREPARED'), approval=MAINTENANCE).phase == 'BACKFILLED'
        successor = getattr(rotation, 'seal_' + purpose + '_rotation')(
            proposal, owner, keys=source_keys, target_keys=target_keys,
            pin=pin(proposal, 'PREPARED'), approval=MAINTENANCE,
            copy_rows_per_second=1000, copy_wal_bytes_per_row=3000)
        assert successor.document['format'] == (adopted_format if binding else normal_format)
        assert successor.document['access_contract'] == contract
        assert 'online_preparation' not in successor.document
        assert 'online_verification' not in successor.document
        malformed = successor.document
        malformed.pop('access_contract')
        with pytest.raises(m.TransitionFailure, match='invalid_plan'):
            m.MigrationPlan(m._canonical(malformed))
        assert getattr(rotation, 'switch_' + purpose + '_rotation')(
            proposal, successor, owner, keys=source_keys, target_keys=target_keys,
            pin=pin(successor, 'PREPARED'), approval=MAINTENANCE).phase == 'PENDING'
        assert m.apply(successor, owner, keys=target_keys, pin=pin(successor, 'ACTIVATING'),
                       approval=MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
        with owner.connect() as connection:
            access.check(connection, successor)
        source, source_keys = successor, target_keys
    return source, source_keys


def frame_bytes(owner, plan):
    model = plan.document['lock']['models'][0]
    with owner.connect() as connection:
        names = ','.join(m._quote(connection, field['column']) for field in model['fields'])
        rows = connection.exec_driver_sql(
            f'SELECT id,{names} FROM {m._table(connection, model)} ORDER BY id').all()
    return {row[0]: tuple(None if item is None else bytes(item) for item in row[1:]) for row in rows}


def engine(url):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
                         creator=lambda: psycopg.connect(url))


def mapped(schema):
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('body', Text(collation='C')), Column('label', String(64, collation='C')))

    class Customer:
        pass

    mapping.map_imperatively(Customer, table)
    return mapping, Customer


def protected_edits(url, schema, plan, resolver, expected, *, added, deleted, label):
    runtime = engine(url)
    mapping, Customer = mapped(schema)
    try:
        sessions = attach(mapping, runtime, lock=plan.lock_bytes, keys=resolver,
                          deployment=(plan, pin(plan, 'ACTIVE')))
        with sessions(tenant_id=TABLE_ID, expire_on_commit=False) as session:
            assert {row.id: (row.body, row.label) for row in session.scalars(select(Customer))} == expected
            current = session.get(Customer, UUID(int=10))
            current.body, current.label = 'latest ' + label, label
            session.add(Customer(id=UUID(int=added), body='new ' + label, label=label))
            session.delete(session.get(Customer, UUID(int=deleted)))
            session.commit()
            expected[UUID(int=10)] = ('latest ' + label, label)
            expected[UUID(int=added)] = ('new ' + label, label)
            del expected[UUID(int=deleted)]
            assert session.scalar(select(Customer.id).where(Customer.body == 'latest ' + label)) == UUID(int=10)
            assert {row.id: (row.body, row.label) for row in session.scalars(select(Customer))} == expected
    finally:
        runtime.dispose()
        mapping.dispose()


def pg_environment(url):
    values = psycopg.conninfo.conninfo_to_dict(url)
    return dict(os.environ, PGHOST=values.get('host', ''), PGPORT=values.get('port', ''),
                PGUSER=values['user'], PGPASSWORD=values['password'], PGDATABASE=values['dbname'])


def test_online_authority_survives_six_rotations_restore_and_latest_native_exit(app, tmp_path):
    destination = os.environ.get('CRYPTALIS_ONLINE_RESTORE_DATABASE')
    if not destination:
        pytest.skip('requires the explicit disposable restore database from online_qualification.py')
    urls = {name: os.environ[variable] for name, variable in (
        ('owner', 'CRYPTALIS_TEST_DATABASE_URL'), ('target', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'),
        ('source', 'CRYPTALIS_TEST_SOURCE_URL'))}
    restored_urls = {name: psycopg.conninfo.make_conninfo(value, dbname=destination)
                     for name, value in urls.items()}
    assert psycopg.conninfo.conninfo_to_dict(urls['owner'])['dbname'] != destination
    contract = app.plan.document['access_contract']
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval,
                 max_chunks=1, fence=True)
    online.apply(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval, max_chunks=20)
    sealed = online.seal(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
    successor = online.switch(app.plan, app.owner, successor=sealed, keys=keys,
                              pin=app.pin, approval=app.approval)
    assert m.apply(successor, app.owner, keys=keys, pin=pin(successor, 'ACTIVATING'),
                   approval=MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    successor, current_keys = rotate_all(app.owner, successor, keys, contract)
    assert current_keys(TABLE_ID).policy.payload_generation == current_keys(TABLE_ID).policy.search_generation == 2
    expected = {UUID(int=i): (f'body-{i}', f'label-{i}') for i in (10, 20, 30)}
    protected_edits(urls['target'], app.schema, successor, current_keys, expected,
                    added=40, deleted=30, label='before restore')

    dump_path = tmp_path / 'online-protected.sql'
    dump_path.touch(mode=0o600)
    with dump_path.open('wb') as output:
        result = subprocess.run([pg_bin('pg_dump'), '--schema=' + app.schema],
            env=pg_environment(urls['owner']), stdout=output, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'protected dump failed; diagnostics withheld'
    restored_owner = engine(restored_urls['owner'])
    try:
        with dump_path.open('rb') as source:
            result = subprocess.run([pg_bin('psql'), '-X', '--set=ON_ERROR_STOP=1'],
                env=pg_environment(restored_urls['owner']), stdin=source,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode == 0, 'protected restore failed; diagnostics withheld'
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(successor, restored_owner, pin=pin(successor, 'ACTIVE'))
        # The original fixture has no application workers. Its engines stop here.
        app.target.dispose()
        app.source.dispose()
        approval = restore.RestoreApproval('isolated online qualification harness',
            'Adopt the explicitly restored second disposable database',
            'No application traffic until explicit restored publication', True)
        with restored_owner.begin() as connection:
            table = m._table(connection, successor.document['lock']['models'][0])
            connection.exec_driver_sql(f'GRANT SELECT ON {table} TO {m._quote(connection, app.source_role)}')
        with pytest.raises(m.TransitionFailure, match='access_contract_changed'):
            restore.plan(successor, restored_owner, pin=pin(successor, 'ACTIVE'), keys=current_keys, approval=approval)
        with restored_owner.begin() as connection:
            connection.exec_driver_sql(f'REVOKE SELECT ON {table} FROM {m._quote(connection, app.source_role)}')
        binding = restore.plan(successor, restored_owner, pin=pin(successor, 'ACTIVE'),
                               keys=current_keys, approval=approval)
        assert m.check_deployment(successor, restored_owner, pin=pin(successor, 'ACTIVE'), restore=binding) is None
        successor, current_keys = rotate_all(restored_owner, successor, current_keys, contract, binding=binding)
        assert current_keys(TABLE_ID).policy.payload_generation == current_keys(TABLE_ID).policy.search_generation == 3
        protected_edits(restored_urls['target'], app.schema, successor, current_keys, expected,
                        added=50, deleted=20, label='after restored rotations')
        reverse = d.plan(successor, restored_owner, source_pin=pin(successor, 'ACTIVE'),
            keys=current_keys, plaintext_runtime_role=app.source_role,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            True, 'Disposable public fixture. Protected dump remains a retained test-only backup.')
        assert d.apply(reverse, restored_owner, keys=current_keys, pin=pin(reverse, 'PREPARED'),
            approval=MAINTENANCE, consent=consent, until='PLAINTEXT_PENDING').phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, restored_owner, keys=current_keys, pin=pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=MAINTENANCE, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        native, encrypted = engine(restored_urls['source']), engine(restored_urls['target'])
        mapping, Customer = mapped(app.schema)
        try:
            with sessionmaker(native)() as session:
                assert {row.id: (row.body, row.label) for row in session.scalars(select(Customer))} == expected
                session.get(Customer, UUID(int=10)).body = 'native final edit'
                session.commit()
                expected[UUID(int=10)] = ('native final edit', 'after restored rotations')
            with pytest.raises(DBAPIError) as denied:
                with encrypted.connect() as connection:
                    connection.exec_driver_sql(f'SELECT id FROM {table}').all()
            assert denied.value.orig.sqlstate == '42501'
            removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                'Original native role reads and edits all current rows through ordinary ORM sessions.',
                'Test dump retained with live ephemeral fixture custody until test cleanup.', True)
            assert d.remove(reverse, restored_owner, pin=pin(reverse, 'REMOVING'),
                approval=MAINTENANCE, removal=removal, consent=consent).phase == 'REMOVED'
            assert d.check_removed(reverse, restored_owner, pin=pin(reverse, 'REMOVED')) is None
            with sessionmaker(native)() as session:
                assert {row.id: (row.body, row.label) for row in session.scalars(select(Customer))} == expected
            program = '''
import importlib.abc,json,os,sys
class NoCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='cryptalis' or fullname.startswith('cryptalis.'):
            raise RuntimeError('Cryptalis imports are forbidden after removal')
sys.meta_path.insert(0,NoCryptalis())
import psycopg
schema=sys.argv[1]
expected=json.loads(sys.argv[2])
with psycopg.connect(os.environ['CRYPTALIS_ONLINE_NATIVE_URL']) as c:
    from psycopg import sql
    rows=c.execute(sql.SQL('SELECT id,body,label FROM {}.customer ORDER BY id').format(sql.Identifier(schema))).fetchall()
    assert {str(row[0]):list(row[1:]) for row in rows}==expected
    c.execute(sql.SQL('UPDATE {}.customer SET body=%s WHERE id=%s').format(sql.Identifier(schema)),
              ('package-free native write',rows[0][0]))
assert not any(name=='cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('package-free current rows and native write passed')
'''
            child = subprocess.run([sys.executable,'-I','-c',program,app.schema,
                                    json.dumps({str(k):list(v) for k,v in expected.items()})],
                env=dict(os.environ,CRYPTALIS_ONLINE_NATIVE_URL=restored_urls['source']),
                capture_output=True,text=True,timeout=20)
            assert child.returncode == 0, 'package-free native child failed; diagnostics withheld'
            assert child.stdout.strip() == 'package-free current rows and native write passed'
            with restored_owner.connect() as connection:
                access.check(connection, successor, plaintext=True)
        finally:
            mapping.dispose()
            native.dispose()
            encrypted.dispose()
    finally:
        with restored_owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS {m._quote(connection, app.schema)} CASCADE')
        restored_owner.dispose()
