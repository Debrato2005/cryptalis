"""Opt-in PostgreSQL storage and GIN-maintenance observations for exact prefixes."""
import json
import os
import platform
from pathlib import Path
from uuid import UUID

import psycopg
import pytest

import sqlalchemy
from sqlalchemy import Text, select
from sqlalchemy.orm import Session

from cryptalis.sqlalchemy import attach
from test_migration import application, keys, publish, run, TENANT

pytestmark = pytest.mark.prefix_qualification


REPORT = os.environ.get('CRYPTALIS_PREFIX_COST_REPORT')
if not REPORT:
    pytest.skip('set CRYPTALIS_PREFIX_COST_REPORT to a new absolute JSON path', allow_module_level=True)

ROWS = 1200
BOUNDS = {'min': 2, 'max': 12}
FIRST = ('Amira', 'Benjamin', 'Charlotte', 'Daniel', 'Eleanor', 'Felix',
         'Gabriella', 'Hassan', 'Isabella', 'Jonathan', 'Karina', 'Leonardo')
LAST = ('Anderson', 'Bennett', 'Campbell', 'Davidson', 'Edwards', 'Fernandez',
        'Gonzalez', 'Henderson', 'Ibrahim', 'Johnson', 'Kowalski', 'Williams')
VALUES = tuple(f'{FIRST[index % len(FIRST)]} {LAST[(index // len(FIRST)) % len(LAST)]} account {index:05d}'
               for index in range(ROWS))


def storage(app):
    with app.owner.connect() as connection:
        row_count, nonnull_count, column_bytes = connection.exec_driver_sql(
            f'SELECT count(*),count(name),sum(pg_catalog.pg_column_size(name)) '
            f'FROM "{app.schema}".customer').one()
        block_size = int(connection.exec_driver_sql('SHOW block_size').scalar_one())
        indexes = connection.exec_driver_sql('''
            SELECT i.indexrelid, a.amname, pg_catalog.pg_relation_size(i.indexrelid)
            FROM pg_catalog.pg_index i
            JOIN pg_catalog.pg_class t ON t.oid=i.indrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
            JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid
            JOIN pg_catalog.pg_am a ON a.oid=x.relam
            JOIN pg_catalog.pg_attribute c ON c.attrelid=t.oid AND c.attname='name'
            WHERE n.nspname=%s AND t.relname='customer'
              AND i.indisvalid AND i.indisready AND i.indislive
              AND (c.attnum=ANY(i.indkey) OR EXISTS (
                  SELECT 1 FROM pg_catalog.pg_depend d
                  WHERE d.classid='pg_catalog.pg_class'::regclass AND d.objid=i.indexrelid
                    AND d.refclassid='pg_catalog.pg_class'::regclass
                    AND d.refobjid=t.oid AND d.refobjsubid=c.attnum))
            ORDER BY a.amname,x.relname
        ''', (app.schema,)).all()
    assert row_count == nonnull_count == ROWS
    assert type(column_bytes) is int and column_bytes > 0
    assert indexes and all(size > 0 and size % block_size == 0 for _, _, size in indexes)
    result = {'rows': row_count, 'nonnull_rows': nonnull_count, 'column_bytes': column_bytes,
              'index_bytes': sum(size for _, _, size in indexes),
              'indexes': [{'method': method, 'bytes': size, 'pages': size // block_size}
                          for _, method, size in indexes], 'block_size': block_size}
    result['column_plus_index_bytes'] = result['column_bytes'] + result['index_bytes']
    return result, [identity for identity, method, _ in indexes if method == 'gin']


def observe(session, model):
    scope = model.tenant_id == TENANT
    rows = session.execute(select(model.id, model.name).where(scope).order_by(model.id)).all()
    prefixes = ('', *(VALUES[0][:size] for size in (2, 4, 8, 12)), 'zz-unmatched')
    results = [list(session.scalars(select(model.id).where(scope,
        model.name.startswith(prefix, autoescape=True)).order_by(model.id))) for prefix in prefixes]
    results.append(list(session.scalars(select(model.id).where(scope, model.name == VALUES[17]))))
    results.append(list(session.scalars(select(model.id).where(scope,
        model.name.in_([VALUES[17], VALUES[217], None])).order_by(model.id))))
    return rows, results


def test_prefix_column_indexes_and_gin_maintenance_costs():
    destination = Path(REPORT)
    if not destination.is_absolute() or destination.exists():
        pytest.fail('Prefix cost report requires a new absolute output path.', pytrace=False)
    assert len(set(VALUES)) == ROWS and all(20 <= len(value) <= 40 for value in VALUES)

    def native_pattern_index(connection, schema, role):
        connection.exec_driver_sql(f'CREATE INDEX native_prefix ON "{schema}".customer (name text_pattern_ops)')

    with application(rows=ROWS, value_type=Text(collation='C'), unique=False,
                     queries=['equality', 'prefix'], value_prefix_bounds=BOUNDS,
                     protected_values=VALUES, setup=native_pattern_index) as app:
        with Session(app.runtime) as session:
            expected = observe(session, app.Customer)
        assert len(expected[0]) == ROWS
        assert [row.id for row in expected[0]] == [UUID(int=100 + index) for index in range(ROWS)]
        native, native_gin = storage(app)
        assert not native_gin and [entry['method'] for entry in native['indexes']] == ['btree', 'btree']
        run(app, chunk_size=128)
        publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            assert observe(session, app.Customer) == expected
        before, gin_indexes = storage(app)
        assert len(gin_indexes) == 1 and [entry['method'] for entry in before['indexes']] == ['btree', 'gin']
        with app.owner.begin() as connection:
            server = connection.exec_driver_sql('SHOW server_version').scalar_one()
            cleaned = connection.exec_driver_sql('SELECT pg_catalog.gin_clean_pending_list(%s::oid::regclass)',
                                                (gin_indexes[0],)).scalar_one()
        after, retained_gin = storage(app)
        assert retained_gin == gin_indexes and type(cleaned) is int and cleaned >= 0
        with app.owner.begin() as connection:
            empty_pass = connection.exec_driver_sql('SELECT pg_catalog.gin_clean_pending_list(%s::oid::regclass)',
                                                   (gin_indexes[0],)).scalar_one()
        assert empty_pass == 0
        with sessions(tenant_id=TENANT) as session:
            assert observe(session, app.Customer) == expected

    ratios = {name: observation['column_plus_index_bytes'] / native['column_plus_index_bytes']
              for name, observation in (('before_gin_maintenance', before), ('after_gin_maintenance', after))}
    report = {
        'format': 'cryptalis.prefix-cost-observation/v1',
        'scope': 'Small-host synthetic PostgreSQL storage observation; not latency or production qualification.',
        'dataset': {'rows': ROWS, 'distinct_values': ROWS, 'min_characters': min(map(len, VALUES)),
                    'max_characters': max(map(len, VALUES)),
                    'recipe': 'Deterministic first/family names, account label and distinct five-digit suffix.'},
        'prefix_lengths': BOUNDS,
        'versions': {'python': platform.python_version(), 'sqlalchemy': sqlalchemy.__version__,
                     'psycopg': psycopg.__version__, 'postgresql': server},
        'correctness': {'full_current_roundtrip': 'PASS', 'native_equality_in_prefix_queries': 'PASS',
                        'post_gin_maintenance_queries': 'PASS'},
        'native': native, 'protected_before_gin_maintenance': before,
        'protected_after_gin_maintenance': after,
        'gin_maintenance': {'pages_cleaned': cleaned, 'empty_followup_pages_cleaned': empty_pass},
        'ratios_to_native': ratios,
        'storage_target': {'maximum_ratio': 2, 'observed_after_gin_maintenance': ratios['after_gin_maintenance'],
                           'outcome': 'PASS' if ratios['after_gin_maintenance'] <= 2 else 'MISS'},
        'limits': ['Column bytes sum pg_column_size; table tuple, TOAST relation and free-space-map overhead are excluded.',
                   'Index observations use the main fork and include GIN pending-list allocation.',
                   'GIN cleanup may leave reusable allocated pages without shrinking the index file.',
                   'Public fixture roots and one local host do not qualify security, provider custody or performance.'],
        'production_gates': 'UNKNOWN',
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
