"""Native integer width and failure timing oracle; no protected-type admission."""
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import BigInteger, Column, Integer, MetaData, SmallInteger, Table, Uuid, insert, select, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, registry

from test_migration import engine


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64)])
@pytest.mark.parametrize('route', ['flush', 'dictionary_insert', 'scoped_update'])
def test_native_integer_extrema_failure_rollback_savepoint_and_zero_match(dtype, bits, route):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    schema = 'integer_native_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('subject', mapping.metadata, Column('id', Uuid, primary_key=True), Column('value', dtype))
    class Subject: pass
    mapping.map_imperatively(Subject, table)
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    identity = uuid4()
    observations = []
    def write(session, value):
        if route == 'flush':
            row = session.get(Subject, identity)
            if row is None:
                row = Subject(id=identity)
                session.add(row)
            row.value = value
            session.flush()
        elif route == 'dictionary_insert':
            session.execute(insert(Subject), [{'id': uuid4(), 'value': value}], execution_options={'render_nulls': True})
        else:
            session.execute(update(table).where(table.c.id == identity).values(value=value))
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            connection.execute(insert(table), {'id': identity, 'value': 0})
        for value in (lower, -1, 0, 1, upper, None):
            with Session(owner) as session:
                write(session, value)
                if route == 'dictionary_insert':
                    values = session.scalars(select(table.c.value)).all()
                    assert value in values
                else:
                    current = session.scalar(select(table.c.value).where(table.c.id == identity))
                    assert current == value and (current is None or type(current) is int)
                session.rollback()
        for value in (lower - 1, upper + 1):
            with Session(owner) as session:
                driver = session.connection().connection.driver_connection
                with pytest.raises(DBAPIError) as failure:
                    write(session, value)
                assert failure.value.orig.sqlstate == '22003'
                observations.append({'case': 'out_of_width', 'side': 'low' if value < lower else 'high',
                    'sqlstate': failure.value.orig.sqlstate, 'session_active': session.is_active,
                    'transaction': driver.info.transaction_status.name})
                session.rollback()
                assert session.scalar(select(table.c.value).where(table.c.id == identity)) == 0
            with Session(owner) as session:
                session.begin()
                with pytest.raises(DBAPIError) as failure:
                    with session.begin_nested():
                        write(session, value)
                assert failure.value.orig.sqlstate == '22003' and session.is_active
                assert session.scalar(select(table.c.value).where(table.c.id == identity)) == 0
                session.rollback()
        with Session(owner) as session:
            driver = session.connection().connection.driver_connection
            try:
                result = session.execute(update(table).where(table.c.id == uuid4()).values(value=upper + 1))
            except DBAPIError as failure:
                zero = {'result': 'error', 'sqlstate': failure.orig.sqlstate}
            else:
                assert result.rowcount == 0
                zero = {'result': 'zero_rows', 'rowcount': result.rowcount}
            zero.update(case='zero_match_out_of_width', session_active=session.is_active,
                        transaction=driver.info.transaction_status.name)
            observations.append(zero)
            session.rollback()
            assert session.scalar(select(table.c.value).where(table.c.id == identity)) == 0
        receipt = os.environ.get('CRYPTALIS_INTEGER_NATIVE_RECEIPT')
        if receipt:
            destination = Path(receipt)
            destination = destination.with_name(destination.stem + '-' + str(bits) + '-' + route + destination.suffix)
            with destination.open('x') as stream:
                json.dump({'bits': bits, 'route': route, 'extrema_null_rollback_savepoint': 'passed',
                    'observations': observations, 'boundary': 'Native PostgreSQL only; no protected integer codec or query admission',
                    'gates': 'all seven UNKNOWN'}, stream, indent=2)
                stream.write('\n')
    finally:
        mapping.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


@pytest.mark.parametrize('native_type,bits', [('smallint', 16), ('integer', 32), ('bigint', 64)])
@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
def test_native_prepared_zero_match_integer_failure_timing(native_type, bits, mode):
    """Observe prepared planning before selecting any protected failure carrier."""
    import psycopg
    schema = 'integer_prepared_' + uuid4().hex
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'CREATE TABLE "{schema}".subject(id uuid PRIMARY KEY, value {native_type})')
        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as connection:
            connection.execute('SET LOCAL plan_cache_mode=' + mode)
            try:
                result = connection.execute(f'UPDATE "{schema}".subject SET value=%s::{native_type} WHERE id=%s',
                    (1 << (bits - 1), uuid4()), prepare=True)
            except psycopg.Error as failure:
                assert failure.sqlstate == '22003'
                observation = dict(result='error', sqlstate=failure.sqlstate)
            else:
                assert result.rowcount == 0
                observation = dict(result='zero_rows', rowcount=result.rowcount)
            observation['transaction'] = connection.info.transaction_status.name
            expected = ('error', 'INERROR') if mode == 'force_custom_plan' else ('zero_rows', 'INTRANS')
            assert (observation['result'], observation['transaction']) == expected
            connection.rollback()
            assert connection.execute(f'SELECT count(*) FROM "{schema}".subject').fetchone() == (0,)
        receipt = os.environ.get('CRYPTALIS_INTEGER_PREPARED_RECEIPT')
        if receipt:
            target = Path(receipt)
            target = target.with_name(target.stem + '-' + str(bits) + '-' + mode + target.suffix)
            with target.open('x') as stream:
                json.dump(dict(bits=bits, plan_cache_mode=mode, observation=observation,
                    boundary='Native prepared PostgreSQL only; no protected carrier admission'), stream, indent=2)
                stream.write('\n')
    finally:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
