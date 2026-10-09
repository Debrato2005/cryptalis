"""Temporary measurement only. Product source is hash-checked unchanged."""
from collections import Counter, defaultdict
from dataclasses import replace
import configparser
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
from threading import Event, Thread
import time
from uuid import UUID

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get('CRYPTALIS_PROFILE_SOURCE_ROOT', str(EVIDENCE_ROOT)))
sys.path.insert(0, str(ROOT / 'tests'))
import psycopg
from psycopg._pipeline_base import BasePipeline
from sqlalchemy import event, select
import cryptalis.migration as m
from cryptalis.crypto.keys import Keyring
from cryptalis.crypto.cf1 import FieldDescriptor
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
from cryptalis.sqlalchemy import attach
from test_migration import application, keys, TABLE_ID, FIELD_ID, TENANT, independent_open


def machine():
    data = {'logical_cpus': os.cpu_count(), 'affinity_cpus': len(os.sched_getaffinity(0)),
            'load_average': os.getloadavg(), 'kernel': platform.release()}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith(('MemTotal:', 'MemAvailable:', 'SwapTotal:')):
            data[line.split(':')[0]] = line.split(':')[1].strip()
    for name in ('cpu.max', 'memory.max', 'cpuset.cpus.effective'):
        p = Path('/sys/fs/cgroup/init.scope') / name
        data['cgroup_' + name] = p.read_text().strip() if p.exists() else 'unavailable'
    cfg = configparser.ConfigParser(); cfg.read('/mnt/c/Users/Debrato/.wslconfig')
    data['wsl_overrides'] = {s: {k: v for k, v in cfg[s].items() if k in ('memory', 'processors', 'swap', 'automemoryreclaim')} for s in cfg.sections()}
    data['unrelated_programs_closed'] = 'User confirmed earlier in this session; Windows process inventory not independently verified.'
    return data


def value(i):
    return [None, '', '雪😀', 'e\u0301', 'é', 'exact', 'trailing '][i] if i < 7 else f'user-{hashlib.blake2b(str(i).encode(), digest_size=16).hexdigest()}@example.invalid'


def test_protection_profile(monkeypatch):
    n = int(os.environ.get('CRYPTALIS_PROFILE_ROWS', '1000000'))
    assert 1000 <= n <= 1_000_000
    run_label = os.environ['CRYPTALIS_PROFILE_LABEL']
    assert run_label in ('baseline-small', 'optimized-small', 'optimized-million')
    assert Path(m.__file__).resolve().is_relative_to(ROOT / 'src')
    initial = machine()
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / 'src/cryptalis').rglob('*.py')}
    metrics = defaultdict(lambda: defaultdict(float)); phase = ['setup']; owner_pids = set()
    sql_counts = defaultdict(Counter); sync_counts = Counter(); waits = defaultdict(Counter)
    reader_timings = defaultdict(list); monitor_errors = []; held = {}; strong_intervals = []
    def timed(target, name, label):
        original = getattr(target, name)
        def instrument(*args, **kwargs):
            start = time.perf_counter(); cpu = time.thread_time()
            try: return original(*args, **kwargs)
            finally:
                group = metrics[phase[0]]
                group[label + '_wall_s'] += time.perf_counter() - start
                group[label + '_cpu_s'] += time.thread_time() - cpu
                group[label + '_calls'] += 1
        monkeypatch.setattr(target, name, instrument)
    for target, name, label in ((m, '_backfill_chunk', 'backfill_chunk'), (m, '_verify', 'verification'),
            (m, 'seal_text', 'seal'), (m, 'open_text', 'open'), (m, '_scope', 'membership'),
            (m, '_ring', 'key_policy'), (Keyring, 'prepare', 'key_preparation'),
            (FieldDescriptor, 'from_compiled', 'descriptor_preparation')):
        timed(target, name, label)
    original_sync = BasePipeline._enqueue_sync
    def count_sync(self):
        if self.pgconn.backend_pid in owner_pids: sync_counts[phase[0]] += 1
        return original_sync(self)
    monkeypatch.setattr(BasePipeline, '_enqueue_sync', count_sync)
    original_commit = psycopg.Connection.commit
    def commit(self):
        start = time.perf_counter(); cpu = time.thread_time()
        try: return original_commit(self)
        finally:
            if self.info.backend_pid in owner_pids:
                metrics[phase[0]]['commit_wall_s'] += time.perf_counter() - start
                metrics[phase[0]]['commit_cpu_s'] += time.thread_time() - cpu
                metrics[phase[0]]['commit_calls'] += 1
                if self.info.backend_pid in held:
                    strong_intervals.append((phase[0], time.perf_counter() - held.pop(self.info.backend_pid)))
    monkeypatch.setattr(psycopg.Connection, 'commit', commit)
    with application(rows=0) as app:
        start = time.perf_counter()
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
            for lo in range(0, n, 2000):
                c.cursor().executemany(f'INSERT INTO "{app.schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
                    [(UUID(int=i+100), TENANT, value(i), f'label-{i}') for i in range(lo, min(n, lo+2000))])
                c.commit()
        seed_s = time.perf_counter() - start
        p = m.plan(json.dumps(app.plan.document['lock']['declaration']).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='synthetic native application'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'synthetic unbounded identifiers'),), keys=keys,
            runtime_role=app.role, target_id=app.plan.target_id, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        pin = m.DeploymentPin(p.target_id, p.operation_id, p.digest, 'PREPARED')
        print(json.dumps({'stage': 'seeded', 'rows': n, 'seconds': seed_s, 'machine': initial}), flush=True)
        def before(connection, cursor, statement, parameters, context, many):
            pid = connection.connection.driver_connection.info.backend_pid; owner_pids.add(pid)
            context.profile = (time.perf_counter(), time.thread_time(), pid)
        def after(connection, cursor, statement, parameters, context, many):
            start, cpu, pid = context.profile
            wall = time.perf_counter() - start; used = time.thread_time() - cpu
            label = ('index_construction' if statement.startswith('CREATE ') and 'INDEX ' in statement else
                     'lock_request' if statement.startswith('LOCK TABLE') else
                     'ddl' if statement.startswith(('ALTER ', 'CREATE ', 'DROP ', 'GRANT ', 'REVOKE ')) else
                     'payload_updates' if statement.startswith('UPDATE ') and many else 'inspection_or_marker')
            metrics[phase[0]][label + '_wall_s'] += wall
            metrics[phase[0]][label + '_client_cpu_s'] += used
            metrics[phase[0]]['sql_call_wall_s'] += wall
            metrics[phase[0]]['sql_call_client_cpu_s'] += used
            metrics[phase[0]]['sql_call_non_cpu_s'] += max(0, wall-used)
            sql_counts[phase[0]][label] += 1
            if many: sql_counts[phase[0]]['parameter_sets'] += len(parameters)
            if statement.startswith('LOCK TABLE') and 'ACCESS EXCLUSIVE' in statement:
                held.setdefault(pid, time.perf_counter())
            elif statement.startswith('ALTER TABLE') and 'DROP COLUMN' in statement:
                held.setdefault(pid, time.perf_counter())
        event.listen(app.owner, 'before_cursor_execute', before)
        event.listen(app.owner, 'after_cursor_execute', after)
        stop = Event(); ready = Event(); reader_pid = [None]
        def reader():
            try:
                with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], autocommit=True) as c:
                    reader_pid[0] = c.info.backend_pid
                    c.execute("SET statement_timeout='30s'"); ready.set()
                    while not stop.is_set():
                        stage = phase[0]; tick = time.perf_counter()
                        c.execute(f'SELECT id FROM "{app.schema}".customer LIMIT 1').fetchone()
                        reader_timings[stage].append(time.perf_counter()-tick)
                        stop.wait(.02)
            except Exception as exc: monitor_errors.append(('reader', type(exc).__name__))
        def sampler():
            try:
                with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'], autocommit=True) as c:
                    while not stop.is_set():
                        rows = c.execute('SELECT pid,state,wait_event_type,wait_event FROM pg_catalog.pg_stat_activity WHERE pid = ANY(%s)',
                                         (list(owner_pids) + ([reader_pid[0]] if reader_pid[0] else []),)).fetchall()
                        for pid, state, kind, detail in rows:
                            role = 'reader' if pid == reader_pid[0] else 'executor'
                            waits[phase[0]][role + ':' + str(state) + ':' + str(kind) + ':' + str(detail)] += 1
                        # A restricted owner cannot inspect another login's
                        # activity state. pg_locks still exposes lock waits.
                        if reader_pid[0]:
                            for mode, granted in c.execute('SELECT mode,granted FROM pg_catalog.pg_locks WHERE pid=%s AND locktype=%s',
                                                          (reader_pid[0], 'relation')).fetchall():
                                if not granted: waits[phase[0]]['reader:LOCK_WAIT:' + mode] += 1
                        stop.wait(.02)
            except Exception as exc: monitor_errors.append(('sampler', type(exc).__name__))
        threads = [Thread(target=reader), Thread(target=sampler)]
        for thread in threads: thread.start()
        assert ready.wait(5)
        snapshots = {}
        def snapshot():
            with app.owner.connect() as c:
                sizes = c.exec_driver_sql('SELECT indexrelname,pg_relation_size(indexrelid) FROM pg_catalog.pg_stat_user_indexes WHERE schemaname=%s AND relname=%s', (app.schema, 'customer')).all()
                return {'wal_lsn': c.exec_driver_sql('SELECT pg_current_wal_insert_lsn()::text').scalar_one(),
                        'index_bytes': {name: size for name, size in sizes},
                        'relation_bytes': c.exec_driver_sql('SELECT pg_total_relation_size(%s::regclass)', (f'"{app.schema}".customer',)).scalar_one()}
        snapshots['before'] = snapshot()
        durations = {}; cpu_times = {}; pause = time.perf_counter()
        try:
            for stage in ('EXPANDED', 'BACKFILLED', 'PENDING', 'ACTIVE'):
                phase[0] = stage
                if stage == 'ACTIVE': pin = replace(pin, phase='ACTIVATING')
                start = time.perf_counter(); cpu = time.thread_time()
                result = m.apply(p, app.owner, keys=keys, pin=pin, approval=app.approval, chunk_size=2000, until=stage)
                durations[stage] = time.perf_counter()-start; cpu_times[stage] = time.thread_time()-cpu
                assert result.phase == stage
                if stage == 'ACTIVE': total_pause_s = time.perf_counter()-pause
                snapshots[stage] = snapshot()
                print(json.dumps({'stage': stage, 'seconds': durations[stage], 'client_main_cpu_s': cpu_times[stage]}), flush=True)
        finally:
            stop.set()
            for thread in threads: thread.join(timeout=35)
            event.remove(app.owner, 'before_cursor_execute', before)
            event.remove(app.owner, 'after_cursor_execute', after)
        assert not monitor_errors, monitor_errors
        assert not any(thread.is_alive() for thread in threads)
        phase[0] = 'postcheck'
        with app.owner.connect() as c:
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == n
            rows = c.exec_driver_sql(f'SELECT id, name FROM "{app.schema}".customer WHERE id = ANY(%s)',
                ([UUID(int=i+100) for i in range(7)] + [UUID(int=n+99)],)).all()
            descriptor = p.document['lock']['models'][0]['fields'][0]['descriptor']
            for identity, frame in rows:
                assert independent_open(bytes(frame) if frame is not None else None, descriptor, TENANT, identity) == value(identity.int-100)
            wal_deltas = {stage: int(c.exec_driver_sql('SELECT pg_wal_lsn_diff(%s::pg_lsn,%s::pg_lsn)',
                (snapshots[stage]['wal_lsn'], snapshots[previous]['wal_lsn'])).scalar_one())
                for stage, previous in zip(('EXPANDED','BACKFILLED','PENDING','ACTIVE'),('before','EXPANDED','BACKFILLED','PENDING'))}
        factory = attach(app.mapping, app.runtime, lock=p.lock_bytes, keys=keys, deployment=(p, replace(pin, phase='ACTIVE')))
        with factory(tenant_id=TENANT) as session:
            row = session.get(app.Customer, UUID(int=103)); row.name = 'post-protection-edit'; session.commit()
            assert session.scalar(select(app.Customer.name).where(app.Customer.id==UUID(int=103))) == 'post-protection-edit'
    assert all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest for path, digest in hashes.items())
    result = {'scope': 'Instrumented merged protection, public synthetic roots; research prototype',
        'rows': n, 'measurement_label': run_label, 'comparison_baseline': 'step-a-protection-0383cec.json', 'source_sha256': hashes,
        'measurement_script': Path(__file__).read_text(), 'machine_start': initial, 'machine_end': machine(),
        'seed_seconds': seed_s, 'phase_seconds': durations, 'phase_client_main_cpu_seconds': cpu_times,
        'metrics': {k: dict(v) for k,v in metrics.items()}, 'sql_calls': {k: dict(v) for k,v in sql_counts.items()},
        'pipeline_sync_points': dict(sync_counts), 'wait_samples': {k: dict(v) for k,v in waits.items()},
        'wait_sampling_period_seconds': .02, 'total_writer_pause_seconds': total_pause_s,
        'plain_reader': {k: {'queries': len(v), 'max_latency_s': max(v), 'total_latency_s': sum(v)} for k,v in reader_timings.items()},
        'access_exclusive_held_intervals_seconds': strong_intervals, 'snapshots': snapshots,
        'wal_bytes_cluster_wide_context_only': wal_deltas,
        'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'limits': ['Instrumentation and observer threads add overhead; component timers overlap.',
                   'SQL call non-CPU time includes server/network/client scheduling, not isolated server time.',
                   'Pipeline sync points are measured; exact wire round trips are not available.',
                   'Per-index physical writes are not exposed by PostgreSQL 16 per-index statistics; size growth is reported.',
                   'WAL LSN deltas are cluster-wide, not attributed.', 'Immediate test publication; real publication delay is additional.'],
        'gates': {g:'UNKNOWN' for g in ('G-ADAPTER','G-CRYPTO','G-QUERY','G-LIFECYCLE','G-PROVIDER','G-POLICY','G-RELEASE')}}
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    name = f'step-a-{run_label}-{n}-{revision}.json'
    with (EVIDENCE_ROOT/'docs/_reset'/name).open('x') as stream:
        stream.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'stage':'complete', 'pause_seconds':total_pause_s, 'backfill_rows_per_second':n/durations['BACKFILLED'],
                      'verification_seconds':metrics['PENDING']['verification_wall_s']}), flush=True)
