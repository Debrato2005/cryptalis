"""Opt-in native ALTER TYPE oracle; run only through scripts/test_postgres.py.

The fixed public CF1-like bytes are not authenticated ciphertext. This profile
qualifies no product layout, crypto, downtime target, or production gate.
"""
import hashlib
import json
import os
from pathlib import Path
import time
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError


FIELDS = ('name', 'limited', 'enabled')
TYPES = {'name': 'pg_catalog.text COLLATE pg_catalog."C"',
         'limited': 'pg_catalog.varchar(8) COLLATE pg_catalog."C"', 'enabled': 'pg_catalog.bool'}


def engine(variable):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(os.environ[variable], connect_timeout=5))


def public_frame(identity, column, value):
    if value is None:
        return None
    encoded = str(value).encode()
    nonce = hashlib.sha256(b'PUBLIC NATIVE NONCE' + identity.bytes + column.encode()).digest()[:12]
    searchable = column != 'enabled'
    header = b'CF1\0\x01' + bytes((int(searchable),)) + (1).to_bytes(4, 'big')
    header += (1 if searchable else 0).to_bytes(4, 'big')
    term = hashlib.sha256(encoded).digest() if searchable else b''
    body = hashlib.sha256(b'PUBLIC OPAQUE BYTES' + encoded).digest() if searchable else bytes((int(value),))
    return header + term + nonce + body + b'PUBLIC FIXTURE!!'


def frame_dependencies(connection, table, *, staging):
    for field in FIELDS:
        column = '_cf1_' + field if staging else field
        name = '_cf1_' + field
        magic = '434631000100' if field == 'enabled' else '434631000101'
        bound = '=43' if field == 'enabled' else ' BETWEEN 74 AND 16777290'
        connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{name}_frame" CHECK '
            f'("{column}" IS NULL OR (pg_catalog.octet_length("{column}"){bound} AND '
            f"pg_catalog.substring(\"{column}\",1,6)=pg_catalog.decode('{magic}','hex')))")
        if field != 'enabled':
            connection.exec_driver_sql(f'CREATE UNIQUE INDEX "{name}_eq" ON {table} '
                f'(tenant_id,(pg_catalog.substring("{column}",15,32)) pg_catalog.bytea_ops)')


def native_dependencies(connection, schema):
    table = f'"{schema}".customer'
    connection.exec_driver_sql(f'CREATE UNIQUE INDEX native_name ON {table} (tenant_id,name)')
    connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT limited_unique UNIQUE (tenant_id,limited)')
    connection.exec_driver_sql(f'CREATE STATISTICS "{schema}".native_stats (ndistinct,dependencies) ON name,label FROM {table}')
    connection.exec_driver_sql(f'ALTER STATISTICS "{schema}".native_stats SET STATISTICS 300')
    connection.exec_driver_sql(f"COMMENT ON STATISTICS \"{schema}\".native_stats IS 'public native statistics fixture'")
    connection.exec_driver_sql(f"COMMENT ON INDEX \"{schema}\".native_name IS 'public original index'")
    connection.exec_driver_sql(f"COMMENT ON CONSTRAINT limited_unique ON {table} IS 'public original uniqueness'")


def catalog(connection, schema):
    table = f'"{schema}".customer'
    return {
        'table': tuple(connection.exec_driver_sql('SELECT oid::text,relfilenode::text FROM pg_catalog.pg_class '
            'WHERE oid=pg_catalog.to_regclass(%s)', (table,)).one()),
        'columns': [tuple(row) for row in connection.exec_driver_sql(
            'SELECT a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,'
            'CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||\'.\'||co.collname END,'
            'a.attstattarget,a.attstorage,a.attcompression,a.attoptions::text,a.attacl::text,'
            'pg_catalog.col_description(a.attrelid,a.attnum) FROM pg_catalog.pg_attribute a '
            'LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation '
            'LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace '
            'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum', (table,))],
        'indexes': [tuple(row) for row in connection.exec_driver_sql(
            'SELECT c.relname,c.oid::text,c.relfilenode::text,pg_catalog.pg_get_indexdef(c.oid),'
            "pg_catalog.obj_description(c.oid,'pg_class') FROM pg_catalog.pg_index i "
            'JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=pg_catalog.to_regclass(%s) '
            'ORDER BY c.relname', (table,))],
        'constraints': [tuple(row) for row in connection.exec_driver_sql(
            'SELECT conname,oid::text,pg_catalog.pg_get_constraintdef(oid),'
            "pg_catalog.obj_description(oid,'pg_constraint') FROM pg_catalog.pg_constraint "
            'WHERE conrelid=pg_catalog.to_regclass(%s) ORDER BY conname', (table,))],
        'incoming_constraints': [tuple(row) for row in connection.exec_driver_sql(
            'SELECT conname,oid::text,pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint '
            'WHERE confrelid=pg_catalog.to_regclass(%s) ORDER BY conname', (table,))],
        'statistics': [tuple(row) for row in connection.exec_driver_sql(
            'SELECT stxname,oid::text,pg_catalog.pg_get_statisticsobjdef(oid),stxstattarget,'
            "pg_catalog.obj_description(oid,'pg_statistic_ext') FROM pg_catalog.pg_statistic_ext "
            'WHERE stxrelid=pg_catalog.to_regclass(%s) ORDER BY stxname', (table,))],
        'sequence': tuple(connection.exec_driver_sql(
            'SELECT c.oid::text,n.nspname,c.relname,pg_catalog.pg_get_userbyid(c.relowner),c.relpersistence,'
            's.seqtypid::regtype::text,s.seqstart::text,s.seqincrement::text,s.seqmin::text,s.seqmax::text,'
            "s.seqcache::text,s.seqcycle,c.relacl::text,pg_catalog.obj_description(c.oid,'pg_class'),"
            'd.deptype,d.refobjid::text,d.refobjsubid FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_sequence s ON s.seqrelid=c.oid '
            "JOIN pg_catalog.pg_depend d ON d.objid=c.oid AND d.classid='pg_catalog.pg_class'::regclass "
            "AND d.refclassid='pg_catalog.pg_class'::regclass AND d.refobjsubid>0 "
            "WHERE n.nspname=%s AND c.relname='native_counter'", (schema,)).one()),
        'rows': [tuple(row) for row in connection.exec_driver_sql(f'SELECT * FROM {table} ORDER BY id')],
    }


def convert(connection, schema, forward, observations, after_alter=None):
    table = f'"{schema}".customer'
    started = time.perf_counter_ns()
    if forward:
        connection.exec_driver_sql(f'DROP INDEX "{schema}".native_name')
        connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT limited_unique')
        connection.exec_driver_sql(f'DROP STATISTICS "{schema}".native_stats')
    for field in FIELDS:
        connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "_cf1_{field}_frame"')
        if field != 'enabled':
            connection.exec_driver_sql(f'DROP INDEX "{schema}"."_cf1_{field}_eq"')
    alterations = []
    for field in FIELDS:
        source = '_cf1_' + field if forward else '_plain_' + field
        target = 'pg_catalog.bytea' if forward else TYPES[field]
        alterations.append(f'ALTER COLUMN "{field}" TYPE {target} USING "{source}"')
    alter_started = time.perf_counter_ns()
    connection.exec_driver_sql(f'ALTER TABLE {table} ' + ','.join(alterations))
    alter_ns = time.perf_counter_ns() - alter_started
    modes = connection.exec_driver_sql('SELECT mode FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() '
        'AND relation=pg_catalog.to_regclass(%s) AND granted', (table,)).scalars().all()
    assert 'AccessExclusiveLock' in modes
    if after_alter is not None:
        after_alter(connection)
    if forward:
        frame_dependencies(connection, table, staging=False)
    else:
        native_dependencies(connection, schema)
        # Type conversion may change type-specific storage choices. Restore the native policy explicitly.
        connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STORAGE EXTERNAL')
        connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET COMPRESSION pglz')
    for field in FIELDS:
        shadow = '_cf1_' + field if forward else '_plain_' + field
        connection.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN "{shadow}"')
    observations.append({'direction': 'forward' if forward else 'reverse', 'alter_type_wall_ns': alter_ns,
        'protocol_wall_ns': time.perf_counter_ns() - started, 'lock_modes': sorted(set(modes))})


def test_native_type_using_shadow_preserves_original_column_identity_and_latest_values(record_property):
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'native_column_identity_' + uuid4().hex
    table = f'"{schema}".customer'
    tenant = uuid4()
    expected = {UUID(int=101): (None, None, None), UUID(int=102): ('雪😀', 'tail  ', True),
                UUID(int=103): ('é', 'space ', False)}
    frames = {identity: tuple(public_frame(identity, field, value) for field, value in zip(FIELDS, values, strict=True))
              for identity, values in expected.items()}
    observations, states = [], {}
    try:
        with runtime.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'CREATE TABLE {table} (id uuid PRIMARY KEY,tenant_id uuid NOT NULL,'
                'dropped_gap text,name text COLLATE pg_catalog."C",label text,limited varchar(8) COLLATE pg_catalog."C",'
                'enabled boolean,tail integer NOT NULL)')
            connection.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN dropped_gap')
            connection.exec_driver_sql(f'CREATE TABLE "{schema}".child (parent uuid REFERENCES {table}(id))')
            native_dependencies(connection, schema)
            connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STATISTICS 500')
            connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STORAGE EXTERNAL')
            connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET COMPRESSION pglz')
            connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET (n_distinct=10)')
            connection.exec_driver_sql(f"COMMENT ON COLUMN {table}.name IS 'public original column'")
            quoted = connection.dialect.identifier_preparer.quote(role)
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quoted}')
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON {table} TO {quoted}')
            connection.exec_driver_sql(f'GRANT SELECT(name) ON {table} TO {quoted} WITH GRANT OPTION')
            connection.exec_driver_sql(f'CREATE SEQUENCE "{schema}".native_counter INCREMENT BY 7 START WITH 101 CACHE 1')
            connection.exec_driver_sql(f'ALTER SEQUENCE "{schema}".native_counter OWNED BY {table}.name')
            connection.exec_driver_sql(f'GRANT USAGE,SELECT ON SEQUENCE "{schema}".native_counter TO {quoted}')
            connection.exec_driver_sql(f"COMMENT ON SEQUENCE \"{schema}\".native_counter IS 'public native sequence'")
            connection.exec_driver_sql(f'INSERT INTO {table} (id,tenant_id,name,label,limited,enabled,tail) '
                'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                [(identity, tenant, values[0], 'public label', values[1], values[2], index)
                 for index, (identity, values) in enumerate(expected.items())])
            connection.exec_driver_sql(f'INSERT INTO "{schema}".child VALUES (%s)', (UUID(int=102),))
            states['source'] = catalog(connection, schema)
        original = states['source']
        original_slots = {column[1]: column[0] for column in original['columns']}
        original_order = list(original_slots)
        def next_value(connection):
            return connection.exec_driver_sql('SELECT pg_catalog.nextval(%s::regclass)',
                                              (f'"{schema}".native_counter',)).scalar_one()
        with runtime.begin() as connection:
            assert next_value(connection) == 101
        for forward in (True, False):
            with owner.begin() as connection:
                for field in FIELDS:
                    shadow = '_cf1_' + field if forward else '_plain_' + field
                    target = 'pg_catalog.bytea' if forward else TYPES[field]
                    connection.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN "{shadow}" {target}')
                if forward:
                    frame_dependencies(connection, table, staging=True)
                    values = frames
                else:
                    # A new committed value while bytea is public, followed by staged current plaintext.
                    expected[UUID(int=102)] = ('latest 雪', 'new😀', False)
                    frames[UUID(int=102)] = tuple(public_frame(UUID(int=102), field, value)
                        for field, value in zip(FIELDS, expected[UUID(int=102)], strict=True))
                    connection.exec_driver_sql(f'UPDATE {table} SET name=%s,limited=%s,enabled=%s WHERE id=%s',
                                              frames[UUID(int=102)] + (UUID(int=102),))
                    values = expected
                columns = ','.join('"' + ('_cf1_' if forward else '_plain_') + field + '"=%s' for field in FIELDS)
                connection.exec_driver_sql(f'UPDATE {table} SET {columns} WHERE id=%s',
                    [tuple(row) + (identity,) for identity, row in values.items()])
                assert {row[0]: tuple(row[1:]) for row in connection.exec_driver_sql(
                    'SELECT id,' + ','.join('"' + ('_cf1_' if forward else '_plain_') + field + '"' for field in FIELDS)
                    + f' FROM {table}')} == values
                before = catalog(connection, schema)
            consumed = []
            def interrupted(connection):
                altered = catalog(connection, schema)
                assert altered['table'][0] == original['table'][0] and altered['table'][1] != before['table'][1]
                assert {column[1]: column[0] for column in altered['columns'] if column[1] in original_slots} == original_slots
                with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], connect_timeout=5) as other:
                    other.execute("SET LOCAL lock_timeout = '100ms'")
                    with pytest.raises(psycopg.errors.LockNotAvailable) as blocked:
                        other.execute(f'SELECT id FROM {table} LIMIT 1')
                    assert blocked.value.sqlstate == '55P03'
                    other.rollback()
                consumed.append(next_value(connection))
                raise RuntimeError('public interruption after real native ALTER TYPE')
            with pytest.raises(RuntimeError, match='public interruption'):
                with owner.begin() as connection:
                    convert(connection, schema, forward, observations, interrupted)
            with owner.connect() as connection:
                assert catalog(connection, schema) == before
            with runtime.begin() as connection:
                assert next_value(connection) == consumed[0] + 7
            with owner.begin() as connection:
                convert(connection, schema, forward, observations)
                state = catalog(connection, schema)
                assert state['table'][0] == original['table'][0] and state['table'][1] != before['table'][1]
                assert {column[1]: column[0] for column in state['columns']} == original_slots
                assert list(connection.exec_driver_sql(f'SELECT * FROM {table} LIMIT 0').keys()) == original_order
                assert state['sequence'] == original['sequence']
                states['protected' if forward else 'restored'] = state
            with runtime.begin() as connection:
                assert next_value(connection) == consumed[0] + 14
                actual = {row[0]: tuple(row[1:]) for row in connection.exec_driver_sql(f'SELECT id,name,limited,enabled FROM {table}')}
                assert actual == (frames if forward else expected)
                invalid = ('UPDATE ' + table + ' SET name=%s WHERE id=%s',
                           (b'bad frame', UUID(int=102)), '23514') if forward else (
                           'UPDATE ' + table + ' SET limited=%s WHERE id=%s',
                           ('too long native text', UUID(int=102)), '22001')
                duplicate = (f'INSERT INTO {table} (id,tenant_id,name,label,limited,enabled,tail) '
                             'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                             (UUID(int=104), tenant, (frames if forward else expected)[UUID(int=102)][0],
                              'public duplicate', None, None, 9), '23505')
                for statement, parameters, sqlstate in (invalid, duplicate):
                    savepoint = connection.begin_nested()
                    with pytest.raises(DBAPIError) as refused:
                        connection.exec_driver_sql(statement, parameters)
                    assert refused.value.orig.sqlstate == sqlstate
                    savepoint.rollback()
                    healthy = {row[0]: tuple(row[1:]) for row in connection.exec_driver_sql(
                        f'SELECT id,name,limited,enabled FROM {table}')}
                    assert healthy == (frames if forward else expected)
        restored = states['restored']
        assert restored['columns'] == original['columns']
        assert restored['incoming_constraints'] == original['incoming_constraints']
        assert [row[2:] for row in restored['indexes']] != [row[2:] for row in original['indexes']]  # Rebuilt physical objects.
        assert [(row[0], row[3:]) for row in restored['indexes']] == [(row[0], row[3:]) for row in original['indexes']]
        assert [(row[0], row[2:]) for row in restored['constraints']] == [(row[0], row[2:]) for row in original['constraints']]
        assert [(row[0], row[2:]) for row in restored['statistics']] == [(row[0], row[2:]) for row in original['statistics']]
        with owner.connect() as connection:
            assert connection.exec_driver_sql(f'SELECT parent FROM "{schema}".child').all() == [(UUID(int=102),)]
        receipt = {'scope': 'native_ALTER_TYPE_USING_shadow_oracle', 'cryptalis_execution': False,
            'frame_fixture': 'fixed public CF1-like bytes; no encryption/authentication claim',
            'original_dropped_slot': 3, 'original_relation_oid_and_attnums_preserved': True,
            'physical_rewrite_observed': True, 'observations': observations,
            'catalogs': states, 'locks': 'ACCESS EXCLUSIVE; separate runtime read refused 55P03',
            'limits': 'one tiny native table; no downtime, throughput, WAL or production qualification',
            'production_gates': 'all seven UNKNOWN'}
        record_property('column_identity_native_oracle', json.dumps(receipt, default=str))
        path = os.environ.get('CRYPTALIS_COLUMN_IDENTITY_RECEIPT')
        if path:
            with Path(path).open('x') as stream:
                json.dump(receipt, stream, indent=2, default=str)
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
