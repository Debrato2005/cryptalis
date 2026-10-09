"""Optional native scan profile. Invoke only through scripts/test_postgres.py."""
import cProfile
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pstats
import resource
import statistics
import subprocess
import sys
import time
import tracemalloc
from uuid import UUID

EVIDENCE = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get('CRYPTALIS_MEMBERSHIP_SOURCE_ROOT', str(EVIDENCE)))
sys.path.insert(0, str(SOURCE / 'tests'))
import cryptalis.migration as migration
from cryptalis.manifest.compiler import Writer, WriterInventory, compile_protection
from test_migration import application, TABLE_ID
from test_migration_membership import membership


def test_native_membership_profile():
    assert Path(migration.__file__).resolve().is_relative_to(SOURCE / 'src')
    width = int(os.environ.get('CRYPTALIS_MEMBERSHIP_WIDTH', '32'))
    assert width in (32, 32768)
    hashes = {str(p.relative_to(SOURCE)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in (SOURCE / 'src/cryptalis').rglob('*.py')}
    baseline = None
    if directory := os.environ.get('CRYPTALIS_MEMBERSHIP_BASELINE'):
        path = Path(directory) / 'src/cryptalis/migration.py'
        committed = subprocess.run(['git', 'show', '7edd164:src/cryptalis/migration.py'],
            cwd=EVIDENCE, capture_output=True, check=True).stdout
        assert path.read_bytes() == committed
        spec = importlib.util.spec_from_file_location('cryptalis._membership_profile_baseline', path)
        baseline = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = baseline
        spec.loader.exec_module(baseline)
    initial = {'logical_cpus': os.cpu_count(), 'affinity_cpus': len(os.sched_getaffinity(0)),
               'load_average': os.getloadavg(), 'kernel': platform.release()}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith(('MemTotal:', 'MemAvailable:', 'SwapTotal:')):
            initial[line.split(':')[0]] = line.split(':')[1].strip()
    for name in ('cpu.max', 'memory.max'):
        path = Path('/sys/fs/cgroup/init.scope') / name
        initial[name] = path.read_text().strip() if path.exists() else 'unavailable'
    with application(rows=0) as app:
        with app.owner.begin() as c:
            c.exec_driver_sql(f'DROP INDEX "{app.schema}".native_name')
            c.exec_driver_sql(f'''INSERT INTO "{app.schema}".customer(id,tenant_id,name,label)
                SELECT md5(i::text)::uuid, md5((i%%3)::text)::uuid,
                       repeat(md5(i::text),%s),repeat(md5((-i)::text),%s)
                FROM generate_series(1,5000) AS i''', (width//32, width//32))
        declaration = app.plan.document['lock']['declaration']
        fields = declaration['models'][0]['fields']
        fields[0]['queries'] = []; fields[0]['accept_leakage'] = []
        fields.append({'name': 'label', 'field_id': str(UUID(int=802)),
                       'protect': True, 'queries': [], 'accept_leakage': []})
        lock = compile_protection(json.dumps(declaration).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='native scan profile'),)))
        model = json.loads(lock.lock_bytes)['models'][0]
        with app.owner.connect() as c:
            native = c.exec_driver_sql(f'SELECT id,tenant_id FROM "{app.schema}".customer ORDER BY id').all()
            expected = membership(native)
            size = c.exec_driver_sql(f'SELECT sum(octet_length(name)+octet_length(label)) FROM "{app.schema}".customer').scalar_one()
            plans = {}
            for label, columns in (('identities', 'id,tenant_id'), ('source_values', 'id,tenant_id,name,label')):
                plans[label] = c.exec_driver_sql(f'EXPLAIN (ANALYZE, BUFFERS, WAL, FORMAT JSON) SELECT {columns} FROM "{app.schema}".customer ORDER BY id LIMIT 1000').scalar_one()
            rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            paired = []
            if baseline is not None:
                for i in range(5):
                    pair = {}
                    order = [('baseline', baseline), ('fixed', migration)]
                    if i % 2: order.reverse()
                    for label, engine in order:
                        started = time.perf_counter(); cpu = time.thread_time()
                        assert engine._scope(c, model) == expected
                        pair[label] = {'seconds': time.perf_counter()-started, 'cpu_seconds': time.thread_time()-cpu}
                    paired.append(pair)
            durations, cpus = [], []
            for _ in range(5):
                started = time.perf_counter(); cpu = time.thread_time()
                assert migration._scope(c, model) == expected
                durations.append(time.perf_counter()-started); cpus.append(time.thread_time()-cpu)
            collector = cProfile.Profile(); collector.enable()
            assert migration._scope(c, model) == expected
            collector.disable(); stats = pstats.Stats(collector)
            calls = [{'file': Path(file).name, 'function': name, 'calls': count,
                      'exclusive_s': exclusive, 'cumulative_s': cumulative}
                     for (file, line, name), (_, count, exclusive, cumulative, _) in stats.stats.items()]
            tracemalloc.start()
            assert migration._scope(c, model) == expected
            _, python_peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
            rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert hashes == {path: hashlib.sha256((SOURCE / path).read_bytes()).hexdigest() for path in hashes}
    result = {'scope': 'Native membership only; no backfill or production qualification',
        'rows': 5000, 'protected_fields': 2, 'bytes_per_field': width,
        'source_bytes': size, 'expected_scope': expected, 'source_sha256': hashes,
        'machine': initial, 'load_average_end': os.getloadavg(),
        'scan_seconds': durations, 'scan_cpu_seconds': cpus,
        'paired_same_connection_scans': paired,
        'median_scan_seconds': statistics.median(durations), 'median_cpu_seconds': statistics.median(cpus),
        'peak_rss_kib_before': rss_before, 'peak_rss_kib_after': rss_after,
        'traced_python_peak_bytes': python_peak, 'native_plans': plans,
        'profile_calls': sorted(calls, key=lambda x: x['exclusive_s'], reverse=True)[:20],
        'script': Path(__file__).read_text(), 'base_revision': '7edd1647b39c933ec1eac14f24ce84ff7d29bfba',
        'limitations': ['Warm repeated scans, compressible synthetic text, two fields, three tenants.',
            'RSS is process high-water including setup; tracemalloc excludes libpq/native buffers.',
            'Paired-process RSS includes both engines; use separate-process controls for memory comparison.',
            'EXPLAIN times server execution without client row transfer/decoding.',
            'Does not establish byte-bounded backfill/verification or whole migration improvement.',
            'Current unrelated-program state is not independently established; no million-row rerun.'],
        'gates': {g: 'UNKNOWN' for g in ('G-ADAPTER','G-CRYPTO','G-QUERY','G-LIFECYCLE','G-PROVIDER','G-POLICY','G-RELEASE')}}
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    tag = 'paired' if paired else 'profile'
    receipt = EVIDENCE / 'docs/_reset' / f'membership-{tag}-{width}-{revision}.json'
    with receipt.open('x') as stream:
        stream.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'bytes_per_field': width, 'median_seconds': result['median_scan_seconds'],
                      'median_cpu_seconds': result['median_cpu_seconds'], 'rss_kib': rss_after,
                      'python_peak_bytes': python_peak}), flush=True)
    if paired:
        print(json.dumps({'paired_median_seconds': {label: statistics.median(p[label]['seconds'] for p in paired)
                                                   for label in ('baseline', 'fixed')}}), flush=True)
