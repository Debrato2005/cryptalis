"""Native PostgreSQL VARCHAR semantics through protection and package-free exit."""
import asyncio
from dataclasses import replace
import json
import os
import subprocess
import sys
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, MetaData, String, Table, Text, Uuid, VARCHAR, bindparam, event, select
from sqlalchemy.exc import DataError, IntegrityError, PendingRollbackError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, registry
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import CryptoFailure
from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_migration import application, keys, publish, run, TENANT
from test_deprotection import consent, d, proposal, reverse


VALUES = [None, '', 'abc', 'é' * 12, '😀' * 12, 'e\u0301' * 6,
          'abcdefghijkl', 'abcdefghijkl     ', 'abcdefghijklm',
          'abcdefghijkl\t', 'abcdefghijkl\u00a0', 'e\u0301' * 7]


def plain_mapping(app, length):
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('plain_customer', mapping.metadata, Column('id', Uuid, primary_key=True),
                  Column('name', String(length, collation='C')))
    class Plain: pass
    mapping.map_imperatively(Plain, table)
    mapping.metadata.create_all(app.owner)
    return mapping, Plain


@pytest.mark.parametrize('length', [12, None])
@pytest.mark.parametrize('value', VALUES)
def test_varchar_matches_native_assignment_pending_state_refresh_and_search(length, value):
    with application(unique=False, value_type=String(length, collation='C')) as app:
        native_mapping, Plain = plain_mapping(app, length)
        try:
            identity = uuid4()
            native_error = None
            with Session(app.owner, expire_on_commit=False) as s:
                row = Plain(id=identity, name=value)
                s.add(row)
                try:
                    s.flush()
                    pending = row.name
                    s.refresh(row)
                    stored = row.name
                    s.commit()
                except DataError as error:
                    native_error = error.orig.sqlstate
                    native_active = s.is_active
                    with pytest.raises(PendingRollbackError):
                        s.execute(select(Plain.id))
                    s.rollback()
            run(app)
            publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                             keys=keys, deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT, expire_on_commit=False) as s:
                row = app.Customer(id=identity, tenant_id=TENANT, name=value)
                s.add(row)
                if native_error:
                    assert native_error == '22001'
                    with pytest.raises(CryptoFailure) as failure:
                        s.flush()
                    assert failure.value.code == 'VarcharLengthExceeded'
                    assert failure.value.sqlstate == native_error
                    assert s.is_active is native_active is False
                    with pytest.raises(PendingRollbackError):
                        s.execute(select(app.Customer.id))
                    s.rollback()
                    assert s.get(app.Customer, identity) is None
                    return
                s.flush()
                assert row.name == pending
                s.refresh(row)
                assert row.name == stored
                s.commit()
            candidates = [value, stored, None] + ([] if value is None else [value + ' '])
            with Session(app.owner) as native, factory(tenant_id=TENANT) as protected:
                for candidate in candidates:
                    expected = native.scalar(select(Plain.id).where(Plain.id == identity, Plain.name == candidate))
                    actual = protected.scalar(select(app.Customer.id).where(
                        app.Customer.id == identity, app.Customer.name == candidate))
                    assert actual == expected
                expected = native.scalar(select(Plain.id).where(Plain.id == identity, Plain.name.in_(candidates)))
                actual = protected.scalar(select(app.Customer.id).where(
                    app.Customer.id == identity, app.Customer.name.in_(candidates)))
                assert actual == expected
        finally:
            native_mapping.dispose()


def test_attachment_recompiles_warmed_native_flush_statements():
    with application(rows=1, value_type=String(12), queries=[]) as app:
        from sqlalchemy.orm import Session
        with Session(app.runtime) as s:
            row = s.get(app.Customer, UUID(int=100))
            row.name = 'before'
            s.commit()
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as s:
            row = s.get(app.Customer, UUID(int=100))
            row.name = 'after'
            s.commit()
            s.add(app.Customer(id=UUID(int=901), tenant_id=TENANT, name='new', label='same shape'))
            s.commit()
        with factory(tenant_id=TENANT) as s:
            assert s.get(app.Customer, UUID(int=100)).name == 'after'
            assert s.get(app.Customer, UUID(int=901)).name == 'new'


def test_varchar_coercion_retains_native_scoped_uniqueness():
    with application(value_type=String(12, collation='C')) as app:
        with app.owner.begin() as c:
            c.exec_driver_sql(f'CREATE TABLE "{app.schema}".plain_unique (name varchar(12) UNIQUE)')
            c.exec_driver_sql(f'INSERT INTO "{app.schema}".plain_unique VALUES (%s)', ('abcdefghijkl',))
        with pytest.raises(IntegrityError) as native:
            with app.owner.begin() as c:
                c.exec_driver_sql(f'INSERT INTO "{app.schema}".plain_unique VALUES (%s)', ('abcdefghijkl   ',))
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as s:
            s.add(app.Customer(id=uuid4(), tenant_id=TENANT, name='abcdefghijkl'))
            s.commit()
            s.add(app.Customer(id=uuid4(), tenant_id=TENANT, name='abcdefghijkl   '))
            with pytest.raises(IntegrityError) as protected:
                s.commit()
            assert native.value.orig.sqlstate == protected.value.orig.sqlstate == '23505'
            s.rollback()


def test_varchar_decrypt_back_and_removal_restore_type_limit_and_metadata():
    def metadata(c, schema, role):
        c.exec_driver_sql(f"COMMENT ON COLUMN \"{schema}\".customer.name IS 'native varchar comment'")
        c.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN name SET STATISTICS 100')
    with application(value_type=String(12, collation='C'), setup=metadata) as app:
        lock = json.loads(app.plan.lock_bytes)
        assert lock['schema'] == 'cryptalis.lock/v3'
        assert 'pg-varchar/v1' in lock['required_readers']
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as s:
            row = s.get(app.Customer, UUID(int=101))
            row.name = 'abcdefghijkl    '
            s.commit()
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        active, pin = consent(plan, 'PLAINTEXT_ACTIVATING')
        d.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                consent=active, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                                    'native post-removal CRUD', 'synthetic recovery', True)
        assert d.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'),
                        approval=app.approval, removal=removal, consent=active).phase == 'REMOVED'
        with app.owner.connect() as c:
            facts = c.exec_driver_sql('SELECT data_type, character_maximum_length FROM information_schema.columns '
                'WHERE table_schema=%s AND table_name=%s AND column_name=%s',
                (app.schema, 'customer', 'name')).one()
            assert facts == ('character varying', 12)
            assert c.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
                                     (UUID(int=101),)).scalar_one() == 'abcdefghijkl'
        with pytest.raises(DataError) as error:
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                  ('abcdefghijklm', UUID(int=101)))
        assert error.value.orig.sqlstate == '22001'
        assert d.check_removed(plan, app.owner, pin=replace(pin, phase='REMOVED')) is None
        result = subprocess.run([sys.executable, '-I', '-c', '''
import json, os, sys
from uuid import uuid4
import psycopg
from psycopg import sql
assert 'cryptalis' not in sys.modules
schema = sys.argv[1]
table = sql.Identifier(schema, 'customer')
identity = uuid4()
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
    c.execute(sql.SQL('INSERT INTO {} (id,tenant_id,name) VALUES (%s,%s,%s)').format(table),
              (identity, sys.argv[2], 'plain exit'))
    c.execute(sql.SQL('UPDATE {} SET name=%s WHERE id=%s').format(table), ('mnopqrstuvwx   ', identity))
    assert c.execute(sql.SQL('SELECT name FROM {} WHERE id=%s').format(table), (identity,)).fetchone() == ('mnopqrstuvwx',)
    c.execute(sql.SQL('DELETE FROM {} WHERE id=%s').format(table), (identity,))
assert 'cryptalis' not in sys.modules
print(json.dumps({'native_crud': 'passed', 'cryptalis_imported': False}))
''', app.schema, str(TENANT)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, 'package-free native restart failed'
        assert json.loads(result.stdout) == {'native_crud': 'passed', 'cryptalis_imported': False}


def test_varchar_async_write_refresh_and_mapping_length_refusal():
    with application(value_type=String(12, collation='C')) as app:
        run(app)
        publish(app)
        async def check():
            engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            mapping = registry(metadata=MetaData(schema=app.schema))
            table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True),
                          Column('tenant_id', Uuid, nullable=False), Column('name', String(13, collation='C')),
                          Column('label', Text))
            class Customer: pass
            mapping.map_imperatively(Customer, table)
            try:
                with pytest.raises(PolicyMismatch):
                    await attach(mapping, engine, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
                table.c.name.type = String(12, collation='C')
                factory = await attach(mapping, engine, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
                async with factory(tenant_id=TENANT, expire_on_commit=False) as s:
                    row = await s.get(Customer, UUID(int=101))
                    row.name = '😀' * 12 + '   '
                    await s.flush()
                    assert row.name == '😀' * 12 + '   '
                    await s.refresh(row)
                    assert row.name == '😀' * 12
                    await s.commit()
            finally:
                await engine.dispose()
                mapping.dispose()
        asyncio.run(check())


@pytest.mark.parametrize('base', [String(12, collation='C'), Text(collation='C')])
def test_transformed_native_text_mappings_are_refused(base):
    class Lowercase(TypeDecorator):
        impl = base
        cache_ok = True
        def process_bind_param(self, value, dialect):
            return value.lower() if value is not None else None
    with pytest.raises(PlanningRejected) as failure:
        with application(value_type=base.with_variant(Lowercase(), 'postgresql')):
            pass
    assert 'unsupported_type' in {issue.code for issue in failure.value.issues}


@pytest.mark.parametrize('damage', ['old_reader', 'missing_reader', 'invalid_typmod'])
def test_varchar_reader_fences_refuse_inconsistent_locks_before_effects(damage):
    with application(value_type=String(12, collation='C')) as app:
        document = app.plan.document
        lock = document['lock']
        if damage == 'old_reader':
            lock['schema'] = 'cryptalis.lock/v2'
            lock['required_readers'].remove('pg-varchar/v1')
        elif damage == 'missing_reader':
            lock['required_readers'].remove('pg-varchar/v1')
        else:
            column = next(c for c in lock['models'][0]['source_schema']['columns'] if c['name'] == 'name')
            column['typmod'] = '4'
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        plan = app.m.MigrationPlan(raw)
        pin = replace(app.pin, plan_digest=plan.digest)
        with pytest.raises(app.m.TransitionFailure, match='invalid_compiler_lock'):
            app.m.apply(plan, app.owner, pin=pin, approval=app.approval, keys=keys)
        assert app.m.status(app.plan, app.owner, pin=app.pin).phase == 'PREPARED'


def test_varchar_sql_parameters_hide_plaintext_and_reads_refuse_overlength_frames():
    with application(value_type=String(12, collation='C')) as app:
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        parameters = []
        def observe(c, cursor, statement, values, context, executemany):
            parameters.append(repr(values))
        event.listen(app.runtime, 'before_cursor_execute', observe)
        try:
            with factory(tenant_id=TENANT) as s:
                row = s.get(app.Customer, UUID(int=101))
                row.name = 'PRIVATEVALUE   '
                s.commit()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', observe)
        assert parameters and not any('PRIVATEVALUE' in p for p in parameters)
        field = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
        material = keys(TENANT).prepare()
        frame = seal_text('PRIVATEVALUEZ', descriptor, TENANT, UUID(int=101), material)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s', (frame, UUID(int=101)))
        with factory(tenant_id=TENANT) as s:
            with pytest.raises(CryptoFailure) as failure:
                s.get(app.Customer, UUID(int=101))
            assert failure.value.code == 'RepresentationMismatch'
            assert 'PRIVATEVALUE' not in str(failure.value)


@pytest.mark.parametrize('damage', ['v1', 'v2', 'missing_reader'])
def test_varchar_standalone_attachment_enforces_reader_fences(damage):
    with application(value_type=String(12, collation='C')) as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'DROP TABLE "{app.schema}"._cryptalis_journal')
        lock = json.loads(app.plan.lock_bytes)
        lock['required_readers'].remove('pg-varchar/v1')
        if damage != 'missing_reader':
            lock['schema'] = 'cryptalis.lock/' + damage
            if damage == 'v1':
                lock['models'][0].pop('source_metadata')
        raw = json.dumps(lock, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.runtime, lock=raw, keys=keys)


def test_storage_only_varchar_keeps_default_collation_and_undeclared_search_refusal():
    with application(value_type=String(12), queries=()) as app:
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as s:
            row = s.get(app.Customer, UUID(int=101))
            row.name = 'PRIVATEVALUE   '
            s.commit()
            assert s.get(app.Customer, UUID(int=101)).name == 'PRIVATEVALUE'
            assert s.scalar(select(app.Customer.id).where(app.Customer.id == UUID(int=101),
                                                         app.Customer.name.is_not(None))) == UUID(int=101)
            with pytest.raises(UnsupportedProtectedOperation):
                s.scalar(select(app.Customer.id).where(app.Customer.name == 'PRIVATEVALUE'))
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT count(*) FROM pg_catalog.pg_indexes WHERE schemaname=%s '
                "AND tablename='customer' AND indexdef LIKE '%%substring%%'", (app.schema,)).scalar_one() == 0


def test_native_varchar_query_binds_keep_query_values_uncoerced():
    with application(value_type=String(12, collation='C')) as app:
        mapping, Plain = plain_mapping(app, 12)
        identity = uuid4()
        try:
            with Session(app.owner) as s:
                s.add(Plain(id=identity, name='abcdefghijkl   '))
                s.commit()
            run(app)
            publish(app)
            factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                             keys=keys, deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as s:
                s.add(app.Customer(id=identity, tenant_id=TENANT, name='abcdefghijkl   '))
                s.commit()
            native = select(Plain.id).where(Plain.id == identity, Plain.name == bindparam('query', type_=VARCHAR(12)))
            protected = select(app.Customer.id).where(app.Customer.id == identity,
                app.Customer.name == bindparam('query', type_=VARCHAR(12)))
            with Session(app.owner) as baseline, factory(tenant_id=TENANT) as attached:
                for value in ['abcdefghijkl', 'abcdefghijkl   ', 'abcdefghijklm']:
                    assert attached.scalar(protected, {'query': value}) == baseline.scalar(native, {'query': value})
        finally:
            mapping.dispose()


def test_variant_query_bind_cannot_hide_a_native_value_transform():
    class Lowercase(TypeDecorator):
        impl = String
        cache_ok = True
        def process_bind_param(self, value, dialect):
            return value.lower() if value is not None else None
    with application(value_type=String(12, collation='C')) as app:
        run(app)
        publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                         keys=keys, deployment=(app.plan, app.pin))
        parameter = bindparam('query', type_=String().with_variant(Lowercase(), 'postgresql'))
        with factory(tenant_id=TENANT) as s:
            with pytest.raises(UnsupportedProtectedOperation):
                s.scalar(select(app.Customer.id).where(app.Customer.name == parameter), {'query': 'EXACT'})
