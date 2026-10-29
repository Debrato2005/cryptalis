"""DATE storage uses native PostgreSQL and ORM behavior as its oracle."""
from datetime import date, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Date, event, insert, inspect, select, update
from sqlalchemy.dialects.postgresql import DATE
from sqlalchemy.orm import Session

from cryptalis import migration as m
from cryptalis.manifest.compiler import PlanningRejected, Writer, WriterInventory
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_migration import application, keys, publish, run, TENANT, TABLE_ID


VALUES = (date.min, date(2000, 2, 29), None, date.max, date(1970, 1, 1))


def replan(app):
    from cryptalis.manifest.compiler import _canonical
    return m.plan(_canonical(app.plan.document['lock']['declaration']), app.mapping, app.owner,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='public DATE fixture'),)),
        keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=2000)


def test_date_native_default_and_write_oracle():
    # Establish native semantics independently before protected construction.
    with application(rows=0, setup=None) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name TYPE date USING NULL::date')
        app.table.c.name.type = Date()
        from sqlalchemy.schema import ColumnDefault
        app.table.c.name.default = ColumnDefault(date(2000, 2, 29))
        with Session(app.runtime, expire_on_commit=False) as session:
            row = app.Customer(id=uuid4(), tenant_id=TENANT)
            session.add(row)
            assert row.name is None
            session.flush()
            assert row.name == date(2000, 2, 29) and not inspect(row).expired_attributes
            session.refresh(row)
            assert type(row.name) is date
            session.rollback()


@pytest.mark.parametrize('dtype,default', [(Date, None), (DATE, None), (Date, date.min),
                                         (Date, date(2000, 2, 29)), (Date, date.max)])
def test_date_compiler_binds_codec_defaults_and_reader_boundary(dtype, default):
    with application(value_type=dtype(), queries=[], value_default=default, protected_values=VALUES) as app:
        lock = app.plan.document['lock']
        assert lock['schema'] == 'cryptalis.lock/v8' and lock['layout'] is None
        assert lock['models'][0]['source_metadata']['owned_sequences'] == []
        field = lock['models'][0]['fields'][0]
        assert field['source']['type'] == 'date'
        assert field['descriptor']['value_codec'] == 'pg-date-days-be/v1'
        assert 'pg-date-days-be/v1' in lock['required_readers']
        assert field.get('application_default') == (default.isoformat() if default is not None else None)
        assert ('pg-date-default/v1' in lock['required_readers']) is (default is not None)
        assert m.MigrationPlan(app.plan.artifact).artifact == app.plan.artifact


@pytest.mark.parametrize('default', [datetime(2000, 1, 1), '2000-01-01', lambda: date.today()])
def test_date_unqualified_default_refuses_before_plan(default):
    with pytest.raises(PlanningRejected) as refused:
        with application(rows=0, value_type=Date(), queries=[], value_default=default):
            pytest.fail('unqualified DATE default admitted')
    assert 'protected_default' in {issue.code for issue in refused.value.issues}


@pytest.mark.parametrize('at_apply', [False, True])
@pytest.mark.parametrize('literal', ['infinity', '-infinity', '10000-01-01', '0001-01-01 BC'])
def test_date_outside_python_domain_refuses_before_effects(at_apply, literal):
    with application(value_type=Date(), queries=[], protected_values=VALUES) as app:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s::date WHERE id=%s',
                                      (literal, UUID(int=100)))
        with pytest.raises(m.TransitionFailure) as refused:
            run(app, until='EXPANDED') if at_apply else replan(app)
        assert refused.value.code == 'date_source_domain'
        assert literal not in str(refused.value)
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql('SELECT count(*) FROM information_schema.columns '
                'WHERE table_schema=%s AND column_name LIKE %s', (app.schema, '_cryptalis_%')).scalar_one() == 0
            assert not connection.exec_driver_sql('SELECT relhastriggers FROM pg_catalog.pg_class '
                'WHERE oid=pg_catalog.to_regclass(%s)', (f'"{app.schema}".customer',)).scalar_one()


def observe_dates(factory, model, default):
    result = []
    for supplied in ({}, {'name': None}, {'name': date.max}):
        expected = supplied['name'] if supplied.get('name') is not None else default
        with factory() as session:
            row = model(id=uuid4(), tenant_id=TENANT, **supplied)
            session.add(row)
            pending = row.name
            session.flush()
            result.append((pending, row.name, 'name' in inspect(row).expired_attributes))
            assert row.name == expected
            assert row.name is None or type(row.name) is date
            session.refresh(row)
            session.commit()
            row.name = date.min
            session.flush()
            assert row.name == date.min and 'name' not in inspect(row).expired_attributes
            session.rollback()
            session.refresh(row)
            assert row.name == expected
    for render_nulls in (False, True):
        with factory() as session:
            savepoint = session.begin_nested()
            identity = uuid4()
            value = session.execute(insert(model).returning(model.name),
                [{'id': identity, 'tenant_id': TENANT, 'name': None}],
                execution_options={'render_nulls': render_nulls}).scalar_one()
            assert value == (None if render_nulls else default)
            result.append(value)
            session.execute(update(model).where(model.tenant_id == TENANT),
                [{'id': identity, 'name': date.max}], execution_options={'synchronize_session': False})
            assert session.scalar(select(model.name).where(model.id == identity)) == date.max
            savepoint.rollback()
            assert session.get(model, identity) is None
    return result


@pytest.mark.parametrize('default', [None, date.min, date(2000, 2, 29), date.max])
def test_date_entity_dictionary_defaults_returning_rollback_match_native(default):
    with application(value_type=Date(), queries=[], value_default=default, protected_values=VALUES) as app:
        expected = observe_dates(lambda: Session(app.runtime, expire_on_commit=False), app.Customer, default)
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        observed_binds = []
        def inspect_binds(connection, cursor, statement, parameters, context, executemany):
            for group in parameters if isinstance(parameters, list) else [parameters]:
                values = group.values() if isinstance(group, dict) else group
                assert not any(isinstance(value, date) for value in values)
            observed_binds.append(True)
        event.listen(app.runtime, 'before_cursor_execute', inspect_binds)
        assert observe_dates(lambda: sessions(tenant_id=TENANT, expire_on_commit=False),
                             app.Customer, default) == expected
        assert observed_binds


def test_date_search_and_coercions_refuse_without_plaintext_writes():
    from cryptalis.crypto.keys import CryptoFailure
    with application(value_type=Date(), queries=[], protected_values=VALUES) as app:
        run(app); publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            assert session.scalars(select(app.Customer.name).where(app.Customer.name.is_(None))).all() == [None]
            for statement in (select(app.Customer).where(app.Customer.name == date.min),
                              select(app.Customer).where(app.Customer.name > date.min),
                              select(app.Customer).order_by(app.Customer.name)):
                with pytest.raises(UnsupportedProtectedOperation): session.execute(statement)
            for value in (datetime(2000, 1, 1), '2000-01-01', 1):
                row = session.get(app.Customer, UUID(int=100))
                row.name = value
                with pytest.raises(CryptoFailure): session.flush()
                session.rollback()
            assert session.get(app.Customer, UUID(int=100)).name == date.min


def test_date_lock_mutation_and_mapping_default_drift_refuse():
    from cryptalis.manifest.compiler import _canonical
    with application(value_type=Date(), queries=[], value_default=date.min, protected_values=VALUES) as app:
        for raw in (None, 0, '1-01-01', '0001-1-01', '2000-02-30', 'infinity', '0001-01-01 ', '10000-01-01'):
            document = app.plan.document
            document['lock']['models'][0]['fields'][0]['application_default'] = raw
            with pytest.raises(m.TransitionFailure): m.MigrationPlan(_canonical(document))
        document = app.plan.document
        document['lock']['required_readers'].remove('pg-date-days-be/v1')
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(_canonical(document))
        run(app); publish(app)
        app.table.c.name.default.arg = date.max
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan, app.pin))


def test_date_compiler_search_and_custom_mapping_refuse_before_keys():
    from cryptalis.manifest.compiler import SearchReview, _canonical
    from sqlalchemy.types import TypeDecorator
    with application(rows=0, value_type=Date(), queries=[]) as app:
        declaration = app.plan.document['lock']['declaration']
        field = declaration['models'][0]['fields'][0]
        field['queries'], field['accept_leakage'] = ['equality'], ['equality']
        def forbidden(tenant):
            pytest.fail('refused DATE mapping/search reached provider work')
        with pytest.raises(PlanningRejected) as failure:
            m.plan(_canonical(declaration), app.mapping, app.owner,
                writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='public DATE fixture'),)),
                search_reviews=(SearchReview(UUID(field['field_id']), False, 'fixture assertion cannot admit DATE search'),),
                keys=forbidden, runtime_role=app.role, target_id=app.plan.target_id,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        assert 'unsupported_query' in {issue.code for issue in failure.value.issues}
        class CustomDate(TypeDecorator):
            impl = Date
            cache_ok = True
        for dtype in (CustomDate(), Date().with_variant(Date(), 'postgresql')):
            app.table.c.name.type = dtype
            with pytest.raises(PlanningRejected) as failure: replan(app)
            assert 'unsupported_type' in {issue.code for issue in failure.value.issues}


@pytest.mark.parametrize('has_default', [False, True])
def test_date_async_native_state_defaults_dictionary_and_null_recovery(has_default):
    import asyncio
    import os
    import psycopg
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
    with application(value_type=Date(), queries=[], protected_values=VALUES,
                     value_default=date.min if has_default else None) as app:
        async def observe(protected):
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                sessions = await attach(app.mapping, runtime, lock=app.plan.lock_bytes, keys=keys,
                    deployment=(app.plan, app.pin)) if protected else lambda **options: AsyncSession(runtime, **options)
                options = {'tenant_id': TENANT} if protected else {}
                async with sessions(**options, expire_on_commit=False) as session:
                    row = app.Customer(id=uuid4(), tenant_id=TENANT, **({} if has_default else {'name': date.max}))
                    session.add(row)
                    await session.flush()
                    assert 'name' not in inspect(row).expired_attributes
                    before = row.name
                    row.name = date(2000, 2, 29)
                    await session.flush()
                    assert row.name == date(2000, 2, 29) and 'name' not in inspect(row).expired_attributes
                    await session.rollback()
                    identity = uuid4()
                    result = await session.execute(insert(app.Customer).returning(app.Customer.name),
                        [{'id': identity, 'tenant_id': TENANT, 'name': None}],
                        execution_options={'render_nulls': True})
                    assert result.scalar_one() is None
                    await session.rollback()
                    return before
            finally:
                await runtime.dispose()
        expected = asyncio.run(observe(False))
        run(app); publish(app)
        assert asyncio.run(observe(True)) == expected


@pytest.mark.parametrize('date_field', [False, True])
def test_historical_v7_reader_accepts_old_integer_and_refuses_date_before_sql(tmp_path, date_field):
    import os
    import subprocess
    from sqlalchemy import Integer
    reader = os.environ.get('CRYPTALIS_DATE_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v7 reader interpreter')
    with application(rows=0, value_type=Date() if date_field else Integer(), queries=[]) as app:
        artifact = tmp_path / 'saved-plan.json'
        artifact.write_bytes(app.plan.artifact)
        environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
def forbidden(*args, **kwargs):
    raise AssertionError('historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis import migration as m
try:
    m.MigrationPlan(Path(sys.argv[1]).read_bytes())
except m.TransitionFailure:
    assert sys.argv[2] == 'refuse'
else:
    assert sys.argv[2] == 'accept'
print('historical reader boundary passed')
''', str(artifact), 'refuse' if date_field else 'accept'], cwd='/tmp', env=environment,
            capture_output=True, text=True, timeout=20)
        assert child.returncode == 0, 'historical reader boundary failed; diagnostics withheld'
        assert child.stdout.strip() == 'historical reader boundary passed'


def test_prior_ordinal_lock_reader_keeps_its_codec_and_reports_representation_change():
    from cryptalis.manifest.compiler import _canonical, _digest, _previous_lock, _changes
    with application(value_type=Date(), queries=[], protected_values=VALUES) as app:
        current = app.plan.document['lock']
        prior = app.plan.document['lock']
        field = prior['models'][0]['fields'][0]
        field['descriptor']['value_codec'] = 'date-ordinal-u32/v1'
        field['descriptor_digest'] = _digest(field['descriptor'])
        readers = prior['required_readers']
        readers[readers.index('pg-date-days-be/v1')] = 'date-ordinal-u32/v1'
        readers.sort()
        accepted = _previous_lock(_canonical(prior), current, app.owner)
        assert accepted == prior
        assert any(change.kind == 'representation_changed' for change in _changes(current, accepted))
        field['descriptor']['value_codec'] = 'unknown-date/v1'
        field['descriptor_digest'] = _digest(field['descriptor'])
        with pytest.raises(ValueError):
            _previous_lock(_canonical(prior), current, app.owner)
