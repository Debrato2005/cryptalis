"""Optional matched native/protected count profile on isolated PostgreSQL 16."""
import json
import math
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

import sqlalchemy
from sqlalchemy import func, select
from test_sqlalchemy_search import _row, search_application


def test_matched_count_profile(tmp_path):
    observations = []
    for rows in (1000, 10000):
        values = [None if index % 11 == 0 else f'value-{index % 257:04d}@college.test'
                  for index in range(rows)]
        expected = {'nonnull': sum(value is not None for value in values),
                    'distinct': len(set(values) - {None})}
        with search_application(False, single_tenant=True) as native, \
                search_application(True, single_tenant=True) as protected:
            for app in (native, protected):
                with app.sessions(tenant_id=app.tenant) as session:
                    session.add_all(_row(app, value, rank) for rank, value in enumerate(values))
                    session.commit()
                with app.owner_engine.begin() as connection:
                    connection.exec_driver_sql(f'ANALYZE "{app.schema}".customer')
            with native.sessions(tenant_id=native.tenant) as plain, \
                    protected.sessions(tenant_id=protected.tenant) as encrypted:
                paths = {'native': (plain, native.Customer), 'protected': (encrypted, protected.Customer)}
                statements = {name: {'nonnull': select(func.count(model.name)),
                                     'distinct': select(func.count(model.name.distinct()))}
                              for name, (_, model) in paths.items()}
                server = plain.connection().exec_driver_sql('SHOW server_version').scalar_one()
                for workload, result in expected.items():
                    samples = {name: [] for name in paths}
                    for name, (session, _) in paths.items():
                        for _ in range(5):
                            assert session.scalar(statements[name][workload]) == result
                    for batch in range(31):
                        order = list(paths)
                        if batch % 2:
                            order.reverse()
                        for name in order:
                            session = paths[name][0]
                            start = time.perf_counter_ns()
                            actual = session.scalar(statements[name][workload])
                            elapsed = (time.perf_counter_ns() - start) / 1_000_000
                            assert actual == result and type(actual) is int
                            samples[name].append(elapsed)
                    observations.append({'rows': rows, 'workload': workload, 'result': result,
                        'paths': {name: {'p50_ms': statistics.median(times),
                                         'p95_ms': sorted(times)[math.ceil(len(times) * .95) - 1],
                                         'samples_ms': times} for name, times in samples.items()}})
    receipt = {'scope': 'Warm synchronous count queries; native text vs attached CF1 equality fixtures',
        'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'python': platform.python_version(), 'sqlalchemy': sqlalchemy.__version__,
        'postgresql': server, 'platform': platform.platform(), 'warmups': 5, 'paired_samples': 31,
        'distribution': 'NULL every 11th row; 257 repeating text values; explicit single tenancy',
        'boundary': 'Loopback restricted-role fixture, not migration timing or production qualification',
        'observations': observations}
    destination = Path(os.environ.get('CRYPTALIS_COUNTS_REPORT', tmp_path / 'counts.json'))
    with destination.open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
