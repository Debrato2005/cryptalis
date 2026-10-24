"""Literal signed integer defaults require native ORM and dictionary parity."""
from contextlib import contextmanager
from uuid import uuid4

import pytest
from sqlalchemy import BigInteger, Column, Integer, MetaData, SmallInteger, Table, Uuid, insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, registry

from test_migration import application, engine, keys, publish, run, TENANT


@contextmanager
def native_application(dtype, default, nullable):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'integer_default_native_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('subject', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', dtype(), default=default, nullable=nullable))
    class Subject: pass
    mapping.map_imperatively(Subject, table)
    try:
        with owner.begin() as connection: connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        yield Subject, lambda: Session(owner, expire_on_commit=False)
    finally:
        mapping.dispose()
        with owner.begin() as connection: connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


def observe(factory, model, default, lower, nullable):
    results = []
    for supplied in ({}, {'name': None}, {'name': lower}):
        expected = lower if supplied.get('name') == lower else default
        with factory() as session:
            row = model(id=uuid4(), tenant_id=TENANT, **supplied)
            before = row.name
            session.add(row)
            session.flush()
            results.append(('entity', before, row.name, type(row.name).__name__))
            assert type(row.name) is int and row.name == expected
            session.refresh(row)
            assert type(row.name) is int and row.name == expected
            session.commit()
            row.name = None
            if nullable:
                session.flush(); session.refresh(row)
                assert row.name is None
                results.append(('update_null', None, session.is_active))
            else:
                with pytest.raises(IntegrityError) as failure: session.flush()
                assert failure.value.orig.sqlstate == '23502' and not session.is_active
                results.append(('update_null', failure.value.orig.sqlstate, session.is_active))
            session.rollback()
            session.refresh(row)
            assert row.name == expected
    for render_nulls in (False, True):
        for supplied in ({}, {'name': None}, {'name': lower}):
            with factory() as session:
                savepoint = session.begin_nested()
                identity = uuid4()
                params = dict(id=identity, tenant_id=TENANT, **supplied)
                if render_nulls and supplied == {'name': None} and not nullable:
                    with pytest.raises(IntegrityError) as failure:
                        session.execute(insert(model), [params], execution_options={'render_nulls': True})
                    driver = session.connection().connection.driver_connection
                    results.append(('dictionary_null', failure.value.orig.sqlstate, session.is_active,
                                    driver.info.transaction_status.name))
                    assert failure.value.orig.sqlstate == '23502'
                else:
                    expected = (None if render_nulls and supplied == {'name': None} else
                                lower if supplied.get('name') == lower else default)
                    result = session.execute(insert(model).returning(model.name), [params],
                        execution_options={'render_nulls': render_nulls}).scalar_one()
                    assert result == expected and (result is None or type(result) is int)
                    assert session.scalar(select(model.name).where(model.id == identity)) == expected
                    results.append(('dictionary', result, type(result).__name__))
                savepoint.rollback()
                assert session.get(model, identity) is None
                session.rollback()
    return results


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('nullable', [False, True])
@pytest.mark.parametrize('default_at_upper', ['zero', 'low', 'high'])
def test_integer_literal_default_matches_native_pending_refresh_null_and_savepoints(dtype, bits, nullable, default_at_upper):
    from cryptalis.sqlalchemy import attach
    lower = -(1 << (bits - 1))
    default = (1 << (bits - 1)) - 1 if default_at_upper == 'high' else lower if default_at_upper == 'low' else 0
    with native_application(dtype, default, nullable) as (model, factory):
        expected = observe(factory, model, default, lower, nullable)
    with application(rows=1, value_type=dtype(), queries=[], value_default=default, value_nullable=nullable,
                     protected_values=(default,)) as app:
        field = app.plan.document['lock']['models'][0]['fields'][0]
        assert type(field['application_default']) is str and field['application_default'] == str(default)
        assert 'pg-integer-default/v1' in app.plan.document['lock']['required_readers']
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        assert observe(lambda: sessions(tenant_id=TENANT, expire_on_commit=False), app.Customer,
                       default, lower, nullable) == expected


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
def test_integer_default_metadata_and_mutated_mapping_fail_closed(dtype, bits):
    from cryptalis import migration as m
    from cryptalis.manifest.compiler import _canonical
    from cryptalis.sqlalchemy import PolicyMismatch, attach
    with application(rows=1, value_type=dtype(), queries=[], value_default=0, protected_values=(0,)) as app:
        for raw in (None, 0, True, '-0', '+1', '01', ' 1', '1 ', '1.0', '1e0', '١', str(1 << (bits - 1))):
            document = app.plan.document
            document['lock']['models'][0]['fields'][0]['application_default'] = raw
            with pytest.raises(m.TransitionFailure): m.MigrationPlan(_canonical(document))
        document = app.plan.document
        document['lock']['required_readers'].remove('pg-integer-default/v1')
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(_canonical(document))
        run(app); publish(app)
        app.table.c.name.default.arg = 1
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))
        app.table.c.name.default.arg = 0
        prepared = []
        def resolve(tenant):
            prepared.append(tenant)
            return keys(tenant)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.name)) == 0
            calls = len(prepared)
            app.table.c.name.default.arg = 1
            with pytest.raises(PolicyMismatch): session.scalar(select(app.Customer.name))
            assert len(prepared) == calls


@pytest.mark.parametrize('default', [True, '0', 1.0, lambda: 0, -(1 << 15) - 1, 1 << 15])
def test_unqualified_integer_client_defaults_refuse_before_planning(default):
    from cryptalis.manifest.compiler import PlanningRejected
    with pytest.raises(PlanningRejected) as failure:
        with application(rows=0, value_type=SmallInteger(), queries=[], value_default=default):
            pytest.fail('unqualified client default reached a plan')
    assert 'protected_default' in {issue.code for issue in failure.value.issues}


@pytest.mark.parametrize('default', [None, -(1 << 63)])
def test_previous_integer_reader_accepts_old_lock_and_refuses_new_default_before_sql(tmp_path, default):
    import os
    import subprocess
    reader = os.environ.get('CRYPTALIS_INTEGER_PREVIOUS_READER_PYTHON')
    if not reader: pytest.skip('supply the retained installed integer reader interpreter')
    with application(rows=0, value_type=BigInteger(), queries=[], value_default=default) as app:
        artifact = tmp_path / 'integer-default-plan.json'
        artifact.write_bytes(app.plan.artifact)
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('artifact admission must not use SQL')
Engine.connect = forbidden
from cryptalis import migration as m
try:
    m.MigrationPlan(Path(sys.argv[1]).read_bytes())
except m.TransitionFailure:
    assert sys.argv[2] == 'refuse'
    print('new default refused before SQL')
else:
    assert sys.argv[2] == 'accept'
    print('unchanged integer lock accepted without SQL')
''', str(artifact), 'accept' if default is None else 'refuse'], capture_output=True, text=True, timeout=20)
        assert child.returncode == 0, 'retained-reader check failed; diagnostics withheld'
        assert child.stdout.strip() == ('unchanged integer lock accepted without SQL' if default is None else 'new default refused before SQL')


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('has_default', [False, True])
def test_integer_default_async_entity_dictionary_null_and_recovery_match_native(dtype, bits, has_default):
    import asyncio
    import os
    import psycopg
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    from cryptalis.sqlalchemy import attach
    lower = -(1 << (bits - 1))
    with application(rows=1, value_type=dtype(), queries=[], value_default=lower if has_default else None,
                     value_nullable=False, protected_values=(0,)) as app:
        async def scenario(protected):
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                factory = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else lambda **kw: AsyncSession(runtime, **kw)
                options = {'tenant_id': TENANT} if protected else {}
                async with factory(**options) as session:
                    row = app.Customer(id=uuid4(), tenant_id=TENANT, name=None if has_default else lower)
                    session.add(row)
                    await session.flush()
                    from sqlalchemy import inspect
                    assert 'name' not in inspect(row).expired_attributes
                    assert type(row.name) is int and row.name == lower
                    await session.refresh(row)
                    assert row.name == lower
                    row.name = lower + 1
                    await session.flush()
                    assert 'name' not in inspect(row).expired_attributes
                    assert row.name == lower + 1
                    values = (await session.execute(insert(app.Customer).returning(app.Customer.name),
                        [dict(id=uuid4(), tenant_id=TENANT, **({} if has_default else {'name': lower})),
                         {'id': uuid4(), 'tenant_id': TENANT, 'name': None if has_default else lower}])).scalars().all()
                    assert values == [lower, lower]
                    await session.rollback()
                async with factory(**options) as session:
                    savepoint = await session.begin_nested()
                    with pytest.raises(IntegrityError) as failure:
                        await session.execute(insert(app.Customer),
                            [{'id': uuid4(), 'tenant_id': TENANT, 'name': None}], execution_options={'render_nulls': True})
                    driver = await session.run_sync(lambda sync: sync.connection().connection.driver_connection)
                    result = failure.value.orig.sqlstate, session.is_active, driver.info.transaction_status.name
                    assert result[0] == '23502'
                    await savepoint.rollback()
                    assert (await session.scalars(select(app.Customer.name))).all() == [0]
                    await session.rollback()
                    return result
            finally:
                await runtime.dispose()
        expected = asyncio.run(scenario(False))
        run(app); publish(app)
        assert asyncio.run(scenario(True)) == expected
