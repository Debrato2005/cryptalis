"""Explicit local profile; run only through scripts/test_postgres.py.

Set CRYPTALIS_PERFORMANCE_RECEIPT to a new absolute JSON path. This filename is
outside default pytest discovery. Results describe one warm synchronous TEXT
cell with public fixture keys; they do not qualify deployment performance.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import sysconfig
import time
from types import SimpleNamespace
from uuid import UUID

import cryptography
import psycopg
import pytest
import sqlalchemy
from sqlalchemy import bindparam, insert, select
from sqlalchemy.orm import Session

from cryptalis import migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from profile_sqlalchemy_search import identity, label, name, percentile, storage, summarize
from test_migration import application, keys, FIELD_ID, TABLE_ID, TENANT


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROWS, SAMPLES, WARMUPS = 10_000, 100, 10
GATES = ('G-ADAPTER', 'G-CRYPTO', 'G-QUERY', 'G-LIFECYCLE',
         'G-PROVIDER', 'G-POLICY', 'G-RELEASE')


def source_hashes():
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for directory in ('src/cryptalis', 'tests', 'scripts')
            for path in sorted((ROOT / directory).rglob('*.py'))}


def seed(app, values):
    # Both applications enter through ordinary native runtime ORM writes.
    with Session(app.runtime) as session:
        for lower in range(0, len(values), 1000):
            session.execute(insert(app.Customer), values[lower:lower + 1000])
            session.commit()


def prepare_seeded_fixture(app):
    # Finish fixture maintenance before the product's bounded lock admission.
    with app.owner.connect().execution_options(isolation_level='AUTOCOMMIT') as connection:
        timeout = connection.exec_driver_sql('SHOW statement_timeout').scalar_one()
        quote = connection.dialect.identifier_preparer.quote_identifier
        table = f'{quote(app.schema)}.{quote(app.table.name)}'
        try:
            connection.exec_driver_sql("SELECT pg_catalog.set_config('statement_timeout','120s',false)")
            connection.exec_driver_sql(f'VACUUM (ANALYZE) {table}')
        finally:
            connection.exec_driver_sql("SELECT pg_catalog.set_config('statement_timeout',%s,false)", (timeout,))


def protect(app, rings):
    declaration = app.plan.document['lock']['declaration']
    app.plan = m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
        writers=WriterInventory(True, (Writer(TABLE_ID, 'profile', 'sqlalchemy',
                                              evidence='owned public synthetic application'),)),
        search_reviews=(SearchReview(FIELD_ID, False, '53-byte public synthetic identifiers'),),
        keys=rings.__getitem__, runtime_role=app.role, target_id=app.plan.target_id,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=2000)
    app.pin = m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
    assert m.apply(app.plan, app.owner, keys=rings.__getitem__, pin=app.pin,
                   approval=app.approval, chunk_size=1000).phase == 'PENDING'
    app.pin = replace(app.pin, phase='ACTIVATING')
    assert m.apply(app.plan, app.owner, keys=rings.__getitem__, pin=app.pin,
                   approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
    app.pin = replace(app.pin, phase='ACTIVE')
    return attach(app.mapping, app.runtime, lock=app.plan.lock_bytes,
                  keys=rings.__getitem__, deployment=(app.plan, app.pin))


def cell(app):
    # Observe actual roles before attachment; measured reads use runtime below.
    with app.owner.connect() as connection:
        owner = connection.exec_driver_sql('SELECT current_user').scalar_one()
        version, number = connection.exec_driver_sql(
            "SELECT current_setting('server_version'), current_setting('server_version_num')").one()
    with app.runtime.connect() as connection:
        runtime = connection.exec_driver_sql('SELECT current_user').scalar_one()
    assert runtime == app.role and runtime != owner and int(number) // 10000 == 16
    return {'postgresql': version, 'postgresql_version_num': int(number),
            'application_uses_planned_runtime_role': True, 'owner_and_runtime_roles_separate': True}


def analyze_and_storage(app, index_name, expected_rows):
    with app.owner.begin() as connection:
        quote = connection.dialect.identifier_preparer.quote_identifier
        table = f'{quote(app.schema)}.{quote(app.table.name)}'
        connection.exec_driver_sql(f'ANALYZE {table}')
        count = connection.exec_driver_sql(f'SELECT count(*) FROM {table}').scalar_one()
    assert count == expected_rows
    result = storage(SimpleNamespace(owner_engine=app.owner, schema=app.schema,
                                     name_index_name=index_name))
    assert result['name_column_bytes'] > 0 and result['name_equality_index_bytes'] > 0
    return dict(result, actual_rows=count, equality_index_name=index_name)


def statements(app):
    customer = app.Customer
    scope = customer.tenant_id == TENANT
    result = {
        'point': select(customer.name).where(scope, customer.id == bindparam('point')),
        'equality': select(customer.id, customer.name).where(scope, customer.name == bindparam('value')),
        'in20': select(customer.id, customer.name).where(
            scope, customer.name.in_(bindparam('values', expanding=True))).order_by(customer.id),
    }
    for workload in ('point', 'equality', 'in20'):
        # Keep identical predicates/order while measuring native ORM loading.
        result[workload + '_entities'] = result[workload].with_only_columns(customer)
    return result


def inputs(workload, sample, row_count):
    base = workload.split('_', 1)[0]
    rank = (sample * 7919 + 13) % row_count
    ranks = ([(rank + delta * 977) % row_count for delta in range(20)] if base == 'in20' else [rank])
    assert len(set(ranks)) == (20 if base == 'in20' else 1)
    parameters = ({'point': identity(rank)} if base == 'point' else
                  {'value': name(rank)} if base == 'equality' else
                  {'values': [name(value) for value in ranks]})
    if workload.endswith('_entities'):
        expected = [(identity(value), TENANT, name(value), label(value)) for value in ranks]
    elif base == 'point':
        expected = [name(rank)]
    else:
        expected = [(identity(value), name(value)) for value in ranks]
    return parameters, sorted(expected) if base == 'in20' else expected


def read(session, statement, parameters, workload):
    result = session.execute(statement, parameters)
    if workload.endswith('_entities'):
        return [(row.id, row.tenant_id, row.name, row.label) for row in result.scalars().all()]
    return result.scalars().all() if workload == 'point' else [tuple(row) for row in result.all()]


def test_current_matched_application_profile(record_property):
    if '_cryptalis_test_preflight' not in sys.modules:
        pytest.fail('Run this profile through scripts/test_postgres.py.')
    requested = os.environ.get('CRYPTALIS_PERFORMANCE_RECEIPT')
    if not requested:
        pytest.fail('Set CRYPTALIS_PERFORMANCE_RECEIPT to a new absolute JSON path.')
    output = Path(requested)
    if not output.is_absolute() or output.exists() or not output.parent.is_dir():
        pytest.fail('The performance receipt needs a new absolute path in an existing directory.')
    try:
        row_count = int(os.environ.get('CRYPTALIS_PERFORMANCE_ROWS', str(DEFAULT_ROWS)))
    except ValueError:
        pytest.fail('CRYPTALIS_PERFORMANCE_ROWS must be an integer.', pytrace=False)
    if row_count not in (10_000, 100_000, 1_000_000):
        pytest.fail('Use CRYPTALIS_PERFORMANCE_ROWS=10000, 100000 or 1000000.', pytrace=False)
    profile_started, cpu_started = time.perf_counter(), time.process_time()
    before_hashes = source_hashes()
    revision = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    values = [dict(id=identity(rank), tenant_id=TENANT, name=name(rank), label=label(rank))
              for rank in range(row_count)]
    assert len({row['id'] for row in values}) == row_count
    assert len({row['name'] for row in values}) == row_count
    assert all(type(row['id']) is UUID and len(row['name'].encode('utf8')) == 53 for row in values)
    seed_digest = hashlib.sha256(json.dumps(
        [dict(row, id=str(row['id']), tenant_id=str(row['tenant_id'])) for row in values],
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    rings = {TENANT: keys(TENANT)}
    measurements, storage_results = {}, []
    with ExitStack() as stack:
        native, protected = [stack.enter_context(application(rows=0)) for _ in range(2)]
        cells = [cell(app) for app in (native, protected)]
        assert cells[0] == cells[1]
        for app in (native, protected):
            seed(app, values)
            prepare_seeded_fixture(app)
        factory = protect(protected, rings)
        native_indexes = [index.name for index in native.table.indexes]
        assert native_indexes == ['native_name']
        field = protected.plan.document['lock']['models'][0]['fields'][0]
        for app, index in ((native, native_indexes[0]), (protected, field['payload_column'] + '_eq')):
            storage_results.append(analyze_and_storage(app, index, row_count))
        sessions = [stack.enter_context(Session(native.runtime)),
                    stack.enter_context(factory(tenant_id=TENANT))]
        queries = [statements(app) for app in (native, protected)]
        for workload, target in (('point', 3), ('equality', 3), ('in20', 8),
                                 ('point_entities', 3), ('equality_entities', 3), ('in20_entities', 8)):
            timings = [[], []]
            for sample in range(WARMUPS + SAMPLES):
                parameters, expected = inputs(workload, sample, row_count)
                observed = [None, None]
                for path in ((0, 1) if sample % 2 == 0 else (1, 0)):
                    started = time.perf_counter_ns()
                    observed[path] = read(sessions[path], queries[path][workload], parameters,
                                          workload=workload)
                    elapsed = (time.perf_counter_ns() - started) / 1_000_000
                    if sample >= WARMUPS:
                        timings[path].append(elapsed)
                    assert observed[path] == expected
                    if workload.endswith('_entities'):
                        assert all(type(record) is UUID and type(tenant) is UUID and
                                   type(value) is str and type(public) is str
                                   for record, tenant, value, public in observed[path])
                    elif workload == 'point':
                        assert all(type(value) is str for value in observed[path])
                    else:
                        assert all(type(record) is UUID and type(value) is str
                                   for record, value in observed[path])
                    assert not sessions[path].identity_map
                assert observed[0] == observed[1]
            assert all(len(path) == SAMPLES for path in timings)
            summary = summarize(timings)
            added = percentile(timings[1], .95) - percentile(timings[0], .95)
            summary.update(target_added_p95_ms=target, added_p95_unrounded_ms=added,
                           target_status='PASS' if added <= target else 'FAIL',
                           samples_native_attached_ms=timings)
            measurements[workload] = summary
        for session in sessions:
            session.rollback()
        active_plan = {'format': protected.plan.document['format'],
                       'operation_id': str(protected.plan.operation_id),
                       'digest': protected.plan.digest, 'pin_phase': protected.pin.phase}
    after_hashes = source_hashes()
    stable = before_hashes == after_hashes
    ratio = storage_results[1]['isolated_column_and_index_bytes'] / storage_results[0]['isolated_column_and_index_bytes']
    targets = {workload: {'status': result['target_status'],
                          'added_p95_ms': result['added_p95_unrounded_ms'],
                          'maximum_added_p95_ms': result['target_added_p95_ms']}
               for workload, result in measurements.items()}
    targets['isolated_storage'] = {'status': 'PASS' if ratio <= 2 else 'FAIL',
                                   'observed_ratio': ratio, 'maximum_ratio': 2}
    receipt = {
        'profile': 'current_pinned_application',
        'boundary': 'Local warm synchronous TEXT with public fixture keys; no production performance qualification.',
        'base_revision': revision, 'source_test_sha256': before_hashes,
        'source_stability': {'unchanged': stable,
                             'changed_paths': sorted(path for path in before_hashes.keys() | after_hashes.keys()
                                                     if before_hashes.get(path) != after_hashes.get(path))},
        'implementation_digest': hashlib.sha256(json.dumps(before_hashes, sort_keys=True).encode()).hexdigest(),
        'cell': dict(cells[0], python=platform.python_version(), python_implementation=platform.python_implementation(),
                     python_compiler=platform.python_compiler(), platform=platform.platform(),
                     sysconfig_platform=sysconfig.get_platform(),
                     sysconfig={key: sysconfig.get_config_var(key)
                                for key in ('SOABI', 'Py_DEBUG', 'WITH_PYMALLOC', 'Py_GIL_DISABLED')},
                     sqlalchemy=sqlalchemy.__version__, psycopg=psycopg.__version__,
                     cryptography=cryptography.__version__,
                     perf_counter={'implementation': time.get_clock_info('perf_counter').implementation,
                                   'resolution_seconds': time.get_clock_info('perf_counter').resolution}),
        'data': {'rows_each': row_count, 'name_utf8_bytes': 53, 'tenants': 1,
                 'distribution': 'Unique deterministic synthetic identifiers; identical explicit UUIDs and native constraints.',
                 'seed_sha256': seed_digest, 'tenant_name_uniqueness_preserved': True,
                 'native_and_attached_results_equal': True},
        'sampling': {'paired_samples_each': SAMPLES, 'discarded_warmup_pairs_each': WARMUPS,
                     'fixture_preparation': 'Named-table VACUUM (ANALYZE) after native seeding, before product planning; a separate 120-second fixture statement limit is restored afterward.',
                     'order': 'Alternating native/attached order in each pair.',
                     'transaction': 'One long-lived read transaction per path; no retained ORM identity-map objects between samples.',
                     'materialization': 'Scalar/tuple projections plus full ORM entities converted to (id,tenant_id,name,label); IN20 ordered by native ID.',
                     'added_p95': 'Attached p95 minus native p95; targets use unrounded values.'},
        'active_deployment': active_plan, 'whole_path': measurements,
        'profile_process': {
            'cpu_seconds_including_fixture_setup_and_cleanup': time.process_time() - cpu_started,
            'elapsed_seconds_including_fixture_setup_and_cleanup': time.perf_counter() - profile_started,
            'process_peak_rss': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'process_peak_rss_unit': 'KiB' if sys.platform.startswith('linux') else 'platform_native_units',
            'peak_rss_scope': 'Process lifetime peak, including earlier pytest imports; not database-server memory.',
        },
        'storage_native_attached': storage_results, 'targets': targets,
        'gates': {gate: 'UNKNOWN' for gate in GATES},
        'limits': ['Single local host; uncontrolled shared-host load; only 100 measured pairs.',
                   'Only the recorded row count is measured; this does not qualify larger datasets.',
                   'Warm in-process public fixture provider; no custody, cold or remote provider claim.',
                   'No async, VARCHAR, concurrent load, write-throughput or maintenance-pause qualification.',
                   'Migration uses existing fixture rate/storage/WAL assumptions; those are not measurements from this profile.',
                   'Isolated storage counts only the public name column and its equality index; relation totals are context.'],
    }
    with output.open('x') as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write('\n')
    record_property('performance_receipt', str(output))
    record_property('performance_receipt_sha256', hashlib.sha256(output.read_bytes()).hexdigest())
    record_property('performance_targets', json.dumps(targets, sort_keys=True))
    print(json.dumps({'performance_receipt': str(output), 'source_stable': stable,
                      'targets': targets, 'gates': receipt['gates']}, sort_keys=True))
    assert stable, 'Source changed during the profile; the receipt is not stable-source evidence.'
    assert all(target['status'] == 'PASS' for target in targets.values()), (
        'Observed local performance target failure; inspect the immutable performance receipt.')
