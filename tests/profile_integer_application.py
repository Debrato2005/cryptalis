"""Matched integer/date cost observations; use the mandatory PostgreSQL wrapper."""
from contextlib import ExitStack
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import time
from uuid import UUID

import cryptography
import psycopg
import pytest
import sqlalchemy
from sqlalchemy import BigInteger, Date, Integer, SmallInteger, Uuid, bindparam, select
from sqlalchemy.orm import Session

from profile_current_application import cell, prepare_seeded_fixture, protect, seed
from profile_sqlalchemy_search import percentile, summarize
from test_migration import application, keys, TENANT


ROWS, SAMPLES, WARMUPS = 10_000, 100, 10


def storage(app):
    with app.owner.connect() as connection:
        table = f'"{app.schema}".customer'
        rows, nonnull, column_bytes, tuple_bytes = connection.exec_driver_sql(
            f'SELECT count(*),count(name),sum(pg_column_size(name)),sum(pg_column_size(c)) FROM {table} c').one()
        heap, total = connection.exec_driver_sql('SELECT pg_relation_size(%s::regclass),pg_total_relation_size(%s::regclass)',
                                                 (table, table)).one()
    return dict(rows=rows, nonnull=nonnull, column_bytes=int(column_bytes),
                current_tuple_bytes=int(tuple_bytes), heap_bytes_after_ordinary_vacuum=heap,
                total_relation_bytes_after_ordinary_vacuum=total, equality_index_bytes=0)


def queries(app):
    model = app.Customer
    scope = model.tenant_id == TENANT
    point = select(model.name).where(scope, model.id == bindparam('point'))
    ids20 = select(model.id, model.name).where(scope,
        model.id.in_(bindparam('ids', expanding=True))).order_by(model.id)
    return {'point_scalar': point, 'point_entities': point.with_only_columns(model),
            'ids20_tuples': ids20, 'ids20_entities': ids20.with_only_columns(model)}


def read(session, statement, parameters, workload):
    result = session.execute(statement, parameters)
    if workload.endswith('entities'):
        return [(row.id, row.tenant_id, row.name, row.label) for row in result.scalars().all()]
    return result.scalars().all() if workload == 'point_scalar' else [tuple(row) for row in result.all()]


@pytest.mark.parametrize('dtype,bits', [(SmallInteger, 16), (Integer, 32), (BigInteger, 64), (Date, 32), (Uuid, 128)])
def test_matched_integer_costs_and_native_exit(dtype, bits):
    requested = os.environ.get('CRYPTALIS_INTEGER_PERFORMANCE_RECEIPT')
    if not requested: pytest.fail('Supply a new absolute CRYPTALIS_INTEGER_PERFORMANCE_RECEIPT prefix.')
    prefix = Path(requested)
    dates = dtype is Date
    uuids = dtype is Uuid
    output = prefix.with_name(prefix.stem + '-' + ('uuid' if uuids else 'date' if dates else str(bits)) + '.json')
    assert prefix.is_absolute() and output.parent.is_dir() and not output.exists()
    started, cpu = time.perf_counter(), time.process_time()
    lower, upper = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    domain = (lower, upper, -1, 0, 1, 17, None)
    if dates:
        domain = (date.min, date.max, date(1970, 1, 1), date(2000, 2, 29), None)
    if uuids:
        domain = (UUID(int=0), UUID(int=(1 << 128) - 1), UUID(int=1), UUID(bytes=bytes(range(16))), None)
    values = [dict(id=UUID(int=rank + 100), tenant_id=TENANT, name=domain[rank % len(domain)],
                   label=f'label-{rank + 100}') for rank in range(ROWS)]
    seed_sha = hashlib.sha256(json.dumps([dict(row, id=str(row['id']), tenant_id=str(row['tenant_id']))
        for row in values], sort_keys=True, separators=(',', ':'),
        default=lambda value: str(value) if type(value) is UUID else date.isoformat(value)).encode()).hexdigest()
    rings = {TENANT: keys(TENANT)}
    timings, metadata = {}, {}
    with ExitStack() as stack:
        native, protected = [stack.enter_context(application(rows=0, value_type=dtype(), queries=[])) for _ in range(2)]
        metadata = cell(native)
        assert cell(protected) == metadata
        for app in (native, protected):
            seed(app, values)
            prepare_seeded_fixture(app)
        native_storage = storage(native)
        protection_started = time.perf_counter()
        factory = protect(protected, rings)
        protection_seconds = time.perf_counter() - protection_started
        prepare_seeded_fixture(protected)
        protected_storage = storage(protected)
        assert native_storage['rows'] == protected_storage['rows'] == ROWS
        assert native_storage['nonnull'] == protected_storage['nonnull']
        assert native_storage['column_bytes'] == native_storage['nonnull'] * (bits // 8)
        assert protected_storage['column_bytes'] == protected_storage['nonnull'] * (43 + bits // 8)
        sessions = [stack.enter_context(Session(native.runtime)), stack.enter_context(factory(tenant_id=TENANT))]
        statements = [queries(native), queries(protected)]
        for workload in statements[0]:
            samples = [[], []]
            for sample in range(SAMPLES + WARMUPS):
                rank = (sample * 7919 + 13) % ROWS
                ranks = [(rank + delta * 977) % ROWS for delta in range(20)] if workload.startswith('ids20') else [rank]
                selected = sorted((values[rank] for rank in ranks), key=lambda row: row['id'])
                parameters = {'ids': [row['id'] for row in selected]} if workload.startswith('ids20') else {'point': selected[0]['id']}
                expected = ([(row['id'], row['tenant_id'], row['name'], row['label']) for row in selected]
                    if workload.endswith('entities') else [row['name'] for row in selected]
                    if workload == 'point_scalar' else [(row['id'], row['name']) for row in selected])
                observed = []
                for index in ((0, 1) if sample % 2 == 0 else (1, 0)):
                    tick = time.perf_counter_ns()
                    result = read(sessions[index], statements[index][workload], parameters, workload)
                    elapsed = (time.perf_counter_ns() - tick) / 1_000_000
                    assert result == expected
                    if sample >= WARMUPS: samples[index].append(elapsed)
                    assert not sessions[index].identity_map
                    observed.append(result)
                assert observed[0] == observed[1]
            result = summarize(samples)
            result.update(added_p95_unrounded_ms=percentile(samples[1], .95) - percentile(samples[0], .95),
                          samples_native_attached_ms=samples)
            if workload.startswith('point'):
                result.update(target_added_p95_ms=3, target_status='PASS' if result['added_p95_unrounded_ms'] <= 3 else 'FAIL')
            else:
                result.update(target_status='NOT_APPLICABLE', reason='Public primary-key batch, not encrypted-value IN.')
            timings[workload] = result
        for session in sessions: session.close()
        from cryptalis import deprotection as d
        from test_deprotection import proposal, app_pin, consent
        reverse = proposal(protected)
        approval, pin = consent(reverse)
        reverse_started = time.perf_counter()
        assert d.apply(reverse, protected.owner, keys=keys, pin=pin, approval=protected.approval,
            consent=approval, chunk_size=1000).phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, protected.owner, keys=keys, pin=app_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=protected.approval, consent=approval, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'integer profile native exit', 'public fixture values', True)
        assert d.remove(reverse, protected.owner, pin=app_pin(reverse, 'REMOVING'), approval=protected.approval,
            removal=removal, consent=approval).phase == 'REMOVED'
        reverse_seconds = time.perf_counter() - reverse_started
        with protected.owner.connect() as connection:
            rows = connection.exec_driver_sql(f'SELECT id,name FROM "{protected.schema}".customer ORDER BY id').all()
        assert rows == [(row['id'], row['name']) for row in values]
    content = dict(scope='Warm synchronous storage-only scalar fixture costs; no production qualification.',
        value_type='uuid' if uuids else 'date' if dates else 'integer', bits=bits, rows=ROWS, seed_sha256=seed_sha, cell=dict(metadata, python=platform.python_version(),
        sqlalchemy=sqlalchemy.__version__, psycopg=psycopg.__version__, cryptography=cryptography.__version__),
        sampling=dict(pairs=SAMPLES, discarded_warmup_pairs=WARMUPS, order='Alternating native/attached order.',
                      transactions='One long-lived read transaction per path; no retained entities.'),
        whole_path=timings, storage_native=native_storage, storage_attached=protected_storage,
        isolated_column_ratio=protected_storage['column_bytes'] / native_storage['column_bytes'],
        column_ratio_scope='sum(pg_column_size(name)); includes bytea short-varlena header, excludes other columns and indexes.',
        storage_target='NOT_APPLICABLE: the 2x target requires an equality index; this candidate is storage-only.',
        lifecycle=dict(protect_and_publish_seconds=protection_seconds, reverse_and_remove_seconds=reverse_seconds,
                       native_values_after_removal='passed'),
        process=dict(elapsed_seconds=time.perf_counter() - started, cpu_seconds=time.process_time() - cpu,
                     peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        limits=['Local public fixture provider; no remote or custody cost.', 'No async or concurrent-load qualification.',
                'Only 100 measured warm pairs per workload and this exact 10k fixture.',
                'Ordinary VACUUM does not prove plaintext erasure or compact physical heap size.',
                'Whole-relation bytes include retained space and all indexes; no per-column inference.',
                'Process resources exclude server CPU/memory. Write and pause budgets remain unapproved.'],
        gates={name:'UNKNOWN' for name in ('G-ADAPTER','G-CRYPTO','G-QUERY','G-LIFECYCLE','G-PROVIDER','G-POLICY','G-RELEASE')})
    with output.open('x') as stream: json.dump(content, stream, indent=2); stream.write('\n')
