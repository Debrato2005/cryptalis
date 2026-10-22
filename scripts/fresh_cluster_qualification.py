"""Qualify protected-backup recovery on a freshly initialized PostgreSQL 16 cluster.

Step 1 runs ``tests/test_fresh_cluster_export.py`` against the primary test
cluster and writes a plaintext dump, a protected dump, and a manifest.
Step 2 initializes a new PostgreSQL 16 cluster, creates same-named roles and
databases, and runs ``tests/test_fresh_cluster_restore.py`` through
``scripts/test_postgres.py`` with a temporary HOME credential pair.
Both pytest runs use the mandatory credential wrapper. Passwords stay in the
temporary HOME and never appear in output.

Usage: .venv/bin/python scripts/fresh_cluster_qualification.py [--workdir PATH]
"""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]
DATE = datetime.date.today().strftime('%Y%m%d')


def pg_bin(name):
    found = shutil.which(name)
    if found:
        return found
    candidate = Path('/usr/lib/postgresql/16/bin') / name
    if candidate.exists():
        return str(candidate)
    raise SystemExit(f'missing PostgreSQL 16 binary: {name}')


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def receipt_path(name):
    base = ROOT / 'docs' / '_reset' / name
    path, attempt = base, 1
    while path.exists():
        attempt += 1
        path = base.with_name(f'{base.stem}-{attempt}{base.suffix}')
    return path


def run_pytest(receipt, scope, module, extra_env):
    command = [sys.executable, str(ROOT / 'scripts' / 'test_postgres.py'),
               '--receipt', str(receipt), '--scope', scope, '--', module, '-q']
    result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, **extra_env))
    if result.returncode != 0:
        raise SystemExit(f'pytest step failed: {module}')
    return json.loads(receipt.read_text())


def start_cluster(workdir):
    cluster, password = workdir / 'cluster', secrets.token_urlsafe(24)
    password_file = workdir / 'postgres-pw'
    password_file.write_text(password)
    password_file.chmod(0o600)
    subprocess.run([pg_bin('initdb'), '-D', str(cluster), '-U', 'postgres',
                    '--auth=scram-sha-256', '--pwfile', str(password_file)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    port = free_port()
    subprocess.run([pg_bin('pg_ctl'), '-D', str(cluster), '-l', str(workdir / 'postgres.log'),
                    '-o', f'-p {port} -k {workdir} -c listen_addresses=127.0.0.1',
                    '-w', 'start'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cluster, port, password


def provision(port, password, manifest, plain_database):
    with psycopg.connect(host='127.0.0.1', port=port, user='postgres', password=password,
                         dbname='postgres', autocommit=True) as c:
        credentials = {}
        for key, role in (('owner', manifest['owner_role']), ('runtime', manifest['runtime_role']),
                          ('plaintext', manifest['runtime_role'] + '_plaintext')):
            secret = secrets.token_urlsafe(24)
            existing = c.execute('SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s', (role,)).fetchone()
            if existing is None:
                c.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                                  'NOREPLICATION NOBYPASSRLS PASSWORD {}')
                          .format(sql.Identifier(role), sql.Literal(secret)))
            else:
                c.execute(sql.SQL('ALTER ROLE {} PASSWORD {}').format(sql.Identifier(role), sql.Literal(secret)))
            credentials[key] = (role, secret)
        for database in (manifest['database'], plain_database):
            existing = c.execute('SELECT 1 FROM pg_catalog.pg_database WHERE datname=%s', (database,)).fetchone()
            if existing is None:
                c.execute(sql.SQL('CREATE DATABASE {} OWNER {}').format(
                    sql.Identifier(database), sql.Identifier(manifest['owner_role'])))
    return credentials


def write_home(workdir, port, manifest, credentials):
    home = workdir / 'fresh-home'
    home.mkdir(mode=0o700, exist_ok=True)
    for filename, key in (('.cryptalis-test-url', 'owner'), ('.cryptalis-test-runtime-url', 'runtime')):
        role, secret = credentials[key]
        connection = psycopg.conninfo.make_conninfo(host='127.0.0.1', port=str(port), user=role,
                                                    password=secret, dbname=manifest['database'])
        path = home / filename
        path.write_text(connection + '\n')
        path.chmod(0o600)
    return home


def stop_cluster(cluster):
    subprocess.run([pg_bin('pg_ctl'), '-D', str(cluster), '-m', 'fast', '-w', 'stop'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, default=None)
    parser.add_argument('--varchar', action='store_true', help='Qualify a native VARCHAR(64) source and lock v3.')
    parser.add_argument('--rewrap', action='store_true', help='Qualify backup recovery after root rewrap and publication.')
    args = parser.parse_args()
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix='cryptalis-fresh-'))
    workdir.mkdir(parents=True, exist_ok=True)
    export_receipt = receipt_path(f'fresh-cluster-export-{DATE}.json')
    restore_receipt = receipt_path(f'fresh-cluster-restore-{DATE}.json')

    profile = '; root-rewrap profile' if args.rewrap else ''
    export = run_pytest(export_receipt, 'Fresh-cluster source export; primary cluster' + profile,
                        'tests/test_fresh_cluster_export.py',
                        {'CRYPTALIS_FRESH_CLUSTER_DIR': str(workdir),
                         'CRYPTALIS_FRESH_SOURCE_VARCHAR': '1' if args.varchar else '0',
                         'CRYPTALIS_FRESH_SOURCE_REWRAP': '1' if args.rewrap else '0'})
    manifest = json.loads((workdir / 'restore-manifest.json').read_text())
    if manifest.get('rewrapped') is not args.rewrap:
        raise SystemExit('FreshCluster.ProfileMismatch: export did not match the requested root-rewrap profile.')
    if args.rewrap:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (plan.get('format') != 'cryptalis.transition/v2' or plan.get('kind') != 'rewrap'
                or type(plan.get('predecessors')) is not list or not plan['predecessors']):
            raise SystemExit('FreshCluster.ProfileMismatch: root-rewrap successor evidence is missing.')
    plain_database = manifest['database'] + '_plain'
    cluster, port, password = start_cluster(workdir)
    try:
        credentials = provision(port, password, manifest, plain_database)
        home = write_home(workdir, port, manifest, credentials)
        restore = run_pytest(restore_receipt, 'Fresh-cluster protected-backup recovery and adoption; isolated cluster' + profile,
                             'tests/test_fresh_cluster_restore.py',
                             {'HOME': str(home), 'CRYPTALIS_FRESH_CLUSTER_DIR': str(workdir),
                              'CRYPTALIS_FRESH_PLAIN_DATABASE': plain_database,
                              'CRYPTALIS_FRESH_PLAINTEXT_ROLE': credentials['plaintext'][0],
                              'CRYPTALIS_FRESH_SOURCE_REWRAP': '1' if args.rewrap else '0'})
    finally:
        stop_cluster(cluster)
    print('workdir', workdir)
    for name, receipt in (('export', export), ('restore', restore)):
        print(name, receipt['counts'], receipt['exit_code'], receipt['fixing_revision'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
