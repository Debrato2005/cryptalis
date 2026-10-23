"""Native Boolean mappings need typed lock admission and full lifecycle behavior."""
import json
import asyncio
import os

import pytest
import psycopg
from uuid import uuid4

from sqlalchemy import Boolean, Column, MetaData, Table, Text, Uuid, insert, select, update
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry
from sqlalchemy.types import TypeDecorator

from cryptalis import migration as m
from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_migration import application, frames, keys, publish, run, TENANT


@pytest.mark.parametrize('default', [None, False, True])
def test_boolean_compiler_captures_type_default_and_rejects_unknown_old_readers(default):
    with application(rows=2, value_type=Boolean(), queries=[], value_default=default,
                     protected_values=(False, True)) as app:
        lock = app.plan.document['lock']
        assert lock['schema'] == 'cryptalis.lock/v4'
        assert 'boolean-u8/v1' in lock['required_readers']
        field = lock['models'][0]['fields'][0]
        assert field['source']['type'] == 'bool' and field['source']['collation'] is None
        assert field['application_default'] is default
        assert field['descriptor']['schema'] == 'cryptalis.context/v2'
        assert field['descriptor']['value_codec'] == 'boolean-u8/v1'
        assert m.MigrationPlan(app.plan.artifact).artifact == app.plan.artifact
        tampered = app.plan.document
        tampered['lock']['schema'] = 'cryptalis.lock/v3'
        from cryptalis.manifest.compiler import _canonical
        with pytest.raises(m.TransitionFailure):
            m.MigrationPlan(_canonical(tampered))


@pytest.mark.parametrize('default', [lambda: True, 'true', 1])
def test_boolean_custom_or_nonboolean_defaults_remain_typed_refusals(default):
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=Boolean(), queries=[], value_default=default):
            pytest.fail('Unqualified default reached a migration plan')
    assert 'protected_default' in {issue.code for issue in refused.value.issues}


def test_boolean_search_remains_refused_for_the_existing_small_domain_contract():
    with pytest.raises(PlanningRejected):
        with application(rows=2, value_type=Boolean(), queries=['equality'], protected_values=(False, True)):
            pytest.fail('Boolean search must not acquire a text search term')


@pytest.mark.parametrize('custom', ['subclass', 'decorator', 'variant', 'instance_processor'])
def test_boolean_custom_mapping_or_input_processor_remains_unadmitted(custom):
    class CustomBoolean(Boolean): pass
    class DecoratedBoolean(TypeDecorator):
        impl = Boolean
        cache_ok = True
    dtype = (CustomBoolean() if custom == 'subclass' else DecoratedBoolean() if custom == 'decorator'
             else Boolean().with_variant(Boolean(), 'postgresql') if custom == 'variant' else Boolean())
    if custom == 'instance_processor':
        dtype.bind_processor = lambda dialect: bool
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=dtype, queries=[]):
            pytest.fail('Unqualified Boolean conversion reached a migration plan')
    assert 'unsupported_type' in {issue.code for issue in refused.value.issues}


def test_boolean_lock_refuses_altered_source_codec_defaults_and_reader_requirements():
    with application(rows=0, value_type=Boolean(), queries=[], value_default=True) as app:
        def refused(change):
            document = app.plan.document
            change(document['lock'], document['lock']['models'][0]['fields'][0])
            from cryptalis.manifest.compiler import _canonical
            with pytest.raises(m.TransitionFailure):
                m.MigrationPlan(_canonical(document))
        refused(lambda lock, field: field.update(application_default=1))
        refused(lambda lock, field: field.pop('application_default'))
        refused(lambda lock, field: lock['required_readers'].remove('boolean-u8/v1'))
        refused(lambda lock, field: field['descriptor'].update(value_codec='utf8-exact/v1'))
        refused(lambda lock, field: lock['models'][0]['source_schema']['columns'][2].update(type_schema='shadow'))
        refused(lambda lock, field: lock['models'][0]['source_schema']['columns'][2].update(typmod='1'))


def test_boolean_predicates_refuse_and_literal_default_mutation_invalidates_attachment():
    with application(rows=2, value_type=Boolean(), queries=[], value_default=True,
                     protected_values=(False, True)) as app:
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            for predicate in (app.Customer.name.is_(True), app.Customer.name == True,
                              app.Customer.name.in_([True, False])):
                with pytest.raises(UnsupportedProtectedOperation):
                    session.scalars(select(app.Customer).where(predicate)).all()
                session.rollback()
            assert {row.name for row in session.scalars(select(app.Customer))} == {False, True}
        app.table.c.name.default.arg = False
        with pytest.raises(PolicyMismatch):
            with sessions(tenant_id=TENANT) as session:
                session.get(app.Customer, next(iter(app.source)))


@pytest.mark.parametrize('default', [None, False, True])
def test_boolean_migrate_native_orm_defaults_bulk_updates_projections_and_rollback(default):
    with application(rows=2, value_type=Boolean(), queries=[], value_default=default,
                     value_nullable=default is None, protected_values=(False, True)) as app:
        assert run(app, until='BACKFILLED').phase == 'BACKFILLED'
        prefix = frames(app)
        assert all(len(frame) == 43 for frame in prefix.values())
        assert run(app).phase == 'PENDING'
        publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT, expire_on_commit=False) as session:
            assert {r.id: r.name for r in session.scalars(select(app.Customer))} == {
                identity: value for identity, (_, value) in app.source.items()}
            for supplied in ({}, {'name': None}, {'name': False}, {'name': True},
                             {'name': 0}, {'name': 1}, {'name': 0.0}, {'name': 1.0}):
                row = app.Customer(id=uuid4(), tenant_id=TENANT, **supplied)
                session.add(row)
                session.flush()
                expected = default if supplied.get('name') is None else bool(supplied['name'])
                pending = default if supplied.get('name') is None else supplied['name']
                assert row.name == pending and type(row.name) is type(pending)
                session.refresh(row)
                assert row.name is expected
                session.commit()
                row.name = None
                if default is not None:
                    with pytest.raises(IntegrityError) as failure:
                        session.flush()
                    assert failure.value.orig.sqlstate == '23502' and not session.is_active
                    session.rollback()
                    assert session.get(app.Customer, row.id).name is expected
                else:
                    session.commit()
                row.name = False
                session.commit()
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == row.id)) is False
            for invalid in (2, 'PRIVATE_INVALID_BOOLEAN_VALUE', 0.5, 2.0):
                session.add(app.Customer(id=uuid4(), tenant_id=TENANT, name=invalid))
                with pytest.raises(StatementError) as refused:
                    session.flush()
                assert type(refused.value.orig) in (TypeError, ValueError)
                assert 'PRIVATE_INVALID_BOOLEAN_VALUE' not in str(refused.value)
                assert not session.is_active
                session.rollback()
            identity = uuid4()
            session.execute(insert(app.Customer), [{'id': identity, 'tenant_id': TENANT}])
            assert session.get(app.Customer, identity).name is default
            session.commit()
            for render_nulls in (False, True):
                identity = uuid4()
                statement = insert(app.Customer).returning(app.Customer.name)
                if render_nulls and default is not None:
                    with pytest.raises(IntegrityError) as failure:
                        session.execute(statement, [{'id': identity, 'tenant_id': TENANT, 'name': None}],
                                        execution_options={'render_nulls': True})
                    assert failure.value.orig.sqlstate == '23502'
                    session.rollback()
                else:
                    result = session.execute(statement,
                        [{'id': identity, 'tenant_id': TENANT, 'name': None}],
                        execution_options={'render_nulls': render_nulls})
                    assert result.scalar_one() is (None if render_nulls else default)
                    session.commit()
            identity = next(iter(app.source))
            session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                [{'id': identity, 'name': 0.0}], execution_options={'synchronize_session': False})
            session.commit()
            session.expire_all()
            assert session.get(app.Customer, identity).name is False
            projected = session.execute(select(app.table).where(app.table.c.id == identity)).one()
            assert projected.name is False
        assert all(frame is None or len(frame) == 43 for frame in frames(app, True).values())


def test_boolean_async_session_retains_native_defaults_values_and_failed_flush_rollback():
    with application(rows=2, value_type=Boolean(), queries=[], value_default=False,
                     value_nullable=False, protected_values=(False, True)) as app:
        run(app); publish(app)
        async def workload():
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            mapping = registry(metadata=MetaData(schema=app.schema))
            table = Table('customer', mapping.metadata,
                Column('id', Uuid, primary_key=True, autoincrement=False),
                Column('tenant_id', Uuid, nullable=False), Column('name', Boolean, default=False, nullable=False),
                Column('label', Text))
            class Customer: pass
            mapping.map_imperatively(Customer, table)
            try:
                sessions = await attach(mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                                        deployment=(app.plan, app.pin))
                async with sessions(tenant_id=TENANT, expire_on_commit=False) as session:
                    row = await session.get(Customer, next(iter(app.source)))
                    assert row.name is False
                    row.name = True
                    await session.commit()
                    await session.refresh(row)
                    assert row.name is True
                    created = Customer(id=uuid4(), tenant_id=TENANT)
                    session.add(created)
                    await session.flush()
                    assert created.name is False
                    await session.commit()
                    created.name = None
                    with pytest.raises(IntegrityError) as failure:
                        await session.flush()
                    assert failure.value.orig.sqlstate == '23502' and not session.is_active
                    await session.rollback()
                    await session.refresh(created)
                    assert created.name is False
                    returned = await session.execute(insert(Customer).returning(Customer.name),
                        [{'id': uuid4(), 'tenant_id': TENANT, 'name': 1.0}])
                    assert returned.scalar_one() is True
                    await session.commit()
            finally:
                await runtime.dispose()
                mapping.dispose()
        asyncio.run(workload())
