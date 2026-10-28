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


def write_home(workdir, port, manifest, credentials, *, source_database=None):
    home = workdir / 'fresh-home'
    home.mkdir(mode=0o700, exist_ok=True)
    files = [('.cryptalis-test-url', 'owner', manifest['database']),
             ('.cryptalis-test-runtime-url', 'runtime', manifest['database'])]
    if source_database is not None:
        files.append(('.cryptalis-test-source-url', 'plaintext', source_database))
    for filename, key, database in files:
        role, secret = credentials[key]
        connection = psycopg.conninfo.make_conninfo(host='127.0.0.1', port=str(port), user=role,
                                                    password=secret, dbname=database)
        path = home / filename
        path.write_text(connection + '\n')
        path.chmod(0o600)
    return home


def stop_cluster(cluster):
    subprocess.run([pg_bin('pg_ctl'), '-D', str(cluster), '-m', 'fast', '-w', 'stop'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, default=None)
    parser.add_argument('--integer-default', type=int, default=None,
                        help='Qualify an exact native integer literal client default.')
    parser.add_argument('--varchar', action='store_true', help='Qualify a native VARCHAR(64) source and lock v3.')
    parser.add_argument('--restore-lease', action='store_true',
                        help='Run focused restored-target key lease and no-effects controls.')
    parser.add_argument('--public-slots', action='store_true',
                        help='Qualify explicit original-column slot preservation and restored slot authority.')
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument('--reverse-cli', action='store_true',
                          help='Qualify saved reverse planning and approved CLI removal on an adopted target.')
    profiles.add_argument('--rewrap-cli', action='store_true',
                          help='Qualify root-rewrap CLI cancellation, recovery and publication on an adopted target.')
    profiles.add_argument('--search-cli', action='store_true',
                          help='Qualify staged search CLI sealing, recovery and publication on an adopted target.')
    profiles.add_argument('--payload-cli', action='store_true',
                          help='Qualify staged payload CLI sealing, recovery and publication on an adopted target.')
    profiles.add_argument('--owned-sequences', action='store_true',
                          help='Qualify original owned sequence identity through fresh restore and native exit.')
    profiles.add_argument('--integer', type=int, choices=(16, 32, 64),
                          help='Qualify signed integer storage after payload rotation on a fresh cluster.')
    profiles.add_argument('--boolean', action='store_true',
                          help='Qualify Boolean storage after payload rotation on a fresh cluster.')
    profiles.add_argument('--date', action='store_true',
                          help='Qualify native date storage, rotations and fresh-cluster recovery.')
    profiles.add_argument('--sqlmodel-http', action='store_true',
                          help='Qualify original HTTP authentication, mail and three rotations after fresh restore.')
    profiles.add_argument('--sqlmodel-public-slots', action='store_true',
                          help='Qualify original three-field SQLModel public slots through fresh adoption and direct search.')
    profiles.add_argument('--sqlmodel-direct-search', action='store_true',
                          help='Qualify original SQLModel search rotation directly from restore authority.')
    profiles.add_argument('--sqlmodel-searchable', action='store_true',
                          help='Qualify the pinned original searchable SQLModel app on a fresh cluster.')
    profiles.add_argument('--smolink', action='store_true',
                          help='Qualify the pinned Smolink URL lifecycle on a fresh cluster.')
    profiles.add_argument('--direct-generation', action='store_true',
                          help='Qualify payload/search rotation directly from explicit restored-target authority.')
    profiles.add_argument('--adopted-search', action='store_true',
                          help='Qualify search rotation after adoption with a retained storage-only field.')
    profiles.add_argument('--adopted-payload', action='store_true',
                          help='Qualify payload rotation after adopted-target rewrap.')
    profiles.add_argument('--adopted-rewrap', action='store_true',
                          help='Qualify root rewrap after explicit fresh-target adoption.')
    profiles.add_argument('--rewrap', action='store_true', help='Qualify backup recovery after root rewrap and publication.')
    profiles.add_argument('--payload-rotation', action='store_true',
                          help='Qualify backup recovery after payload rotation and a later protected edit.')
    profiles.add_argument('--search-rotation', action='store_true',
                          help='Qualify backup recovery after search rotation and a later protected edit.')
    args = parser.parse_args()
    if args.sqlmodel_http and (args.varchar or args.restore_lease or args.public_slots or args.owned_sequences):
        parser.error('--sqlmodel-http uses the original HTTP schema and its preserved public slots.')
    if args.reverse_cli and (args.varchar or args.restore_lease or args.public_slots):
        parser.error('--reverse-cli uses the original TEXT export and focused adopted-target CLI lifecycle.')
    if args.rewrap_cli and (args.varchar or args.restore_lease or args.public_slots):
        parser.error('--rewrap-cli uses the original TEXT export and focused adopted-target CLI lifecycle.')
    if args.search_cli and (args.varchar or args.restore_lease or args.public_slots):
        parser.error('--search-cli uses the original TEXT export and focused adopted-target CLI lifecycle.')
    if args.payload_cli and (args.varchar or args.restore_lease or args.public_slots):
        parser.error('--payload-cli uses the original TEXT export and focused adopted-target CLI lifecycle.')
    if args.public_slots and (args.restore_lease or any((args.boolean, args.sqlmodel_public_slots, args.sqlmodel_http, args.sqlmodel_direct_search,
            args.sqlmodel_searchable, args.smolink, args.direct_generation, args.adopted_search,
            args.adopted_payload, args.adopted_rewrap, args.rewrap, args.payload_rotation, args.search_rotation))):
        parser.error('--public-slots supports the original TEXT/VARCHAR fixture with optional owned sequences.')
    if args.owned_sequences and (args.varchar and not args.public_slots or args.restore_lease):
        parser.error('--owned-sequences uses the sequence-bearing TEXT fixture and restore lifecycle.')
    if args.integer_default is not None and (not args.integer or not -(1 << (args.integer - 1)) <= args.integer_default < 1 << (args.integer - 1)):
        parser.error('--integer-default requires --integer and a value within that signed native width.')
    if args.integer and (args.varchar or args.restore_lease):
        parser.error('--integer uses the native signed scalar restore lifecycle.')
    if args.date and (args.varchar or args.restore_lease):
        parser.error('--date uses the native date restore lifecycle.')
    if args.boolean and (args.varchar or args.restore_lease):
        parser.error('--boolean uses the typed Boolean fixture and its restore lifecycle.')
    if (args.sqlmodel_searchable or args.sqlmodel_direct_search or args.sqlmodel_public_slots or args.sqlmodel_http) and (args.varchar or args.restore_lease):
        parser.error('--sqlmodel-searchable uses the original application schema and lifecycle.')
    if args.smolink and (args.varchar or args.restore_lease):
        parser.error('--smolink uses the original application VARCHAR schema and lifecycle.')
    if args.restore_lease and (args.direct_generation or args.adopted_search or args.adopted_payload or args.adopted_rewrap or args.rewrap or args.payload_rotation or args.search_rotation):
        parser.error('--restore-lease supports the original TEXT/VARCHAR fixture only.')
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix='cryptalis-fresh-'))
    workdir.mkdir(parents=True, exist_ok=True)
    export_receipt = receipt_path(f'fresh-cluster-export-{DATE}.json')
    restore_receipt = receipt_path(f'fresh-cluster-restore-{DATE}.json')

    profile = ('; staged search CLI sealing and publication on an adopted target' if args.search_cli else
               '; staged payload CLI sealing and publication on an adopted target' if args.payload_cli else
               '; root-rewrap CLI cancellation and publication on an adopted target' if args.rewrap_cli else
               '; saved reverse-plan and approved removal CLI on an adopted target' if args.reverse_cli else
               '; original public slots and explicit restored-slot authority' if args.public_slots else
               '; owned-sequence identity mapping and native counter profile' if args.owned_sequences else
               '; native date storage after root and payload rotation' if args.date else
               '; integer storage after payload rotation' if args.integer else
               '; Boolean storage after payload rotation' if args.boolean else
               '; pinned original HTTP/JWT and local SMTP, adopted-target root/payload/search rotation and native exit' if args.sqlmodel_http else
               '; original three-field SQLModel public slots and direct restore-binding search profile' if args.sqlmodel_public_slots else
               '; pinned SQLModel direct restore-binding search profile' if args.sqlmodel_direct_search else
               '; pinned searchable SQLModel app adoption and search-rotation profile' if (args.sqlmodel_searchable or args.sqlmodel_direct_search or args.sqlmodel_public_slots or args.sqlmodel_http) else
               '; pinned Smolink root-rewrap and payload-rotation application profile' if args.smolink else
               '; direct restored-target payload/search generation profile' if args.direct_generation else
               '; adopted-target search-rotation mixed-field profile' if args.adopted_search else
               '; adopted-target payload-rotation profile' if args.adopted_payload else
               '; adopted-target root-rewrap profile' if args.adopted_rewrap else
               '; root-rewrap profile' if args.rewrap else
               '; payload-rotation profile' if args.payload_rotation else
               '; search-rotation profile' if args.search_rotation else '')
    if args.restore_lease:
        profile += '; restored-target lease controls'
    export = run_pytest(export_receipt, 'Fresh-cluster source export; primary cluster' + profile,
                        ('tests/test_sqlmodel_searchable_export.py' if (args.sqlmodel_searchable or args.sqlmodel_direct_search or args.sqlmodel_public_slots or args.sqlmodel_http) else
                         'tests/test_fresh_boolean_export.py' if args.boolean or args.integer or args.date else
                         'tests/test_smolink_application.py' if args.smolink
                         else 'tests/test_fresh_cluster_export.py'),
                        {'CRYPTALIS_SMOLINK_FRESH_EXPORT': str(workdir) if args.smolink else '',
                         'CRYPTALIS_FRESH_CLUSTER_DIR': str(workdir),
                         'CRYPTALIS_FRESH_INTEGER_BITS': str(args.integer or 0),
                         'CRYPTALIS_FRESH_DATE': '1' if args.date else '0',
                         'CRYPTALIS_FRESH_INTEGER_DEFAULT': '' if args.integer_default is None else str(args.integer_default),
                         'CRYPTALIS_FRESH_PUBLIC_SLOTS': '1' if args.public_slots else '0',
                         'CRYPTALIS_SQLMODEL_PUBLIC_SLOTS': '1' if (args.sqlmodel_public_slots or args.sqlmodel_http) else '0',
                         'CRYPTALIS_SQLMODEL_HTTP_FRESH': '1' if args.sqlmodel_http else '0',
                         'CRYPTALIS_FRESH_OWNED_SEQUENCES': '1' if args.owned_sequences else '0',
                         'CRYPTALIS_FRESH_ADOPTED_SEARCH': '1' if (args.adopted_search or args.direct_generation) else '0',
                         'CRYPTALIS_FRESH_SOURCE_VARCHAR': '1' if args.varchar else '0',
                         'CRYPTALIS_FRESH_SOURCE_REWRAP': '1' if args.rewrap else '0',
                         'CRYPTALIS_FRESH_SOURCE_PAYLOAD_ROTATION': '1' if args.payload_rotation else '0',
                         'CRYPTALIS_FRESH_SOURCE_SEARCH_ROTATION': '1' if args.search_rotation else '0'})
    manifest = json.loads((workdir / 'restore-manifest.json').read_text())
    if manifest.get('owned_sequences', False) is not args.owned_sequences:
        raise SystemExit('FreshCluster.ProfileMismatch: owned-sequence export did not match the requested profile.')
    if manifest.get('public_slots', False) is not args.public_slots:
        raise SystemExit('FreshCluster.ProfileMismatch: public-slot export did not match the requested profile.')
    if manifest.get('adopted_search', False) is not (args.adopted_search or args.direct_generation):
        raise SystemExit('FreshCluster.ProfileMismatch: adopted-search export did not match the requested profile.')
    if manifest.get('application_default') != (None if args.integer_default is None else str(args.integer_default)):
        raise SystemExit('FreshCluster.ProfileMismatch: integer default export differs from the requested literal.')
    if args.public_slots:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (plan.get('lock', {}).get('schema') != ('cryptalis.lock/v8' if args.date else 'cryptalis.lock/v7' if args.integer else 'cryptalis.lock/v6')
                or plan['lock'].get('layout') != 'preserve-public-slots/v1'
                or not manifest.get('source_public_slots')):
            raise SystemExit('FreshCluster.ProfileMismatch: original-slot source lock is missing.')
    elif args.owned_sequences:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if plan.get('lock', {}).get('schema') != 'cryptalis.lock/v5' or not manifest.get('sequence_facts'):
            raise SystemExit('FreshCluster.ProfileMismatch: sequence-bearing source lock is missing.')
    elif args.date:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (manifest.get('application_profile') != 'native-date-storage'
                or plan.get('kind') != 'payload_rotation'
                or plan.get('lock', {}).get('schema') != 'cryptalis.lock/v8'):
            raise SystemExit('FreshCluster.ProfileMismatch: date payload successor is missing.')
    elif args.integer:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (manifest.get('application_profile') != 'integer-' + str(args.integer)
                or manifest.get('integer_bits') != args.integer
                or plan.get('kind') != 'payload_rotation'
                or plan.get('lock', {}).get('schema') != 'cryptalis.lock/v7'):
            raise SystemExit('FreshCluster.ProfileMismatch: integer payload successor is missing.')
    elif args.boolean:
        if manifest.get('application_profile') != 'boolean-storage':
            raise SystemExit('FreshCluster.ProfileMismatch: Boolean storage export is missing.')
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (plan.get('kind') != 'payload_rotation' or plan.get('format') != 'cryptalis.transition/v3'
                or plan.get('lock', {}).get('schema') != 'cryptalis.lock/v4'):
            raise SystemExit('FreshCluster.ProfileMismatch: Boolean payload successor is missing.')
    elif args.sqlmodel_public_slots or args.sqlmodel_http:
        plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
        if (manifest.get('application_profile') != ('sqlmodel-http' if args.sqlmodel_http else 'sqlmodel-public-slots')
                or manifest.get('sqlmodel_public_slots') is not True
                or plan.get('lock', {}).get('schema') != 'cryptalis.lock/v6'
                or plan['lock'].get('layout') != 'preserve-public-slots/v1'
                or not manifest.get('source_public_slots')):
            raise SystemExit('FreshCluster.ProfileMismatch: original three-field SQLModel public-slot export is missing.')
    elif args.sqlmodel_searchable or args.sqlmodel_direct_search:
        if manifest.get('application_profile') != 'sqlmodel-searchable':
            raise SystemExit('FreshCluster.ProfileMismatch: pinned searchable SQLModel export is missing.')
    elif args.smolink:
        if manifest.get('application_profile') != 'smolink':
            raise SystemExit('FreshCluster.ProfileMismatch: pinned Smolink export is missing.')
    else:
        if manifest.get('rewrapped') is not args.rewrap:
            raise SystemExit('FreshCluster.ProfileMismatch: export did not match the requested root-rewrap profile.')
        if manifest.get('payload_rotated') is not args.payload_rotation:
            raise SystemExit('FreshCluster.ProfileMismatch: export did not match the requested payload-rotation profile.')
        if manifest.get('search_rotated') is not args.search_rotation:
            raise SystemExit('FreshCluster.ProfileMismatch: export did not match the requested search-rotation profile.')
        if args.rewrap:
            plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
            if (plan.get('format') != 'cryptalis.transition/v2' or plan.get('kind') != 'rewrap'
                    or type(plan.get('predecessors')) is not list or not plan['predecessors']):
                raise SystemExit('FreshCluster.ProfileMismatch: root-rewrap successor evidence is missing.')
        if args.payload_rotation or args.search_rotation:
            purpose = 'payload' if args.payload_rotation else 'search'
            plan = json.loads(base64.b64decode(manifest['plan'], validate=True))
            predecessors = plan.get('predecessors')
            preparation_digest = plan.get(purpose + '_rotation_plan_digest')
            if (plan.get('format') != ('cryptalis.transition/v3' if args.payload_rotation else 'cryptalis.transition/v4')
                    or plan.get('kind') != purpose + '_rotation'
                    or type(predecessors) is not list or len(predecessors) < 2
                    or any(type(item) is not dict for item in predecessors)
                    or type(preparation_digest) is not str or len(preparation_digest) != 64
                    or any(character not in '0123456789abcdef' for character in preparation_digest)
                    or predecessors[-1].get('plan_digest') != preparation_digest):
                raise SystemExit(f'FreshCluster.ProfileMismatch: sealed {purpose} successor lineage is missing.')
    plain_database = manifest['database'] + '_plain'
    cluster, port, password = start_cluster(workdir)
    try:
        credentials = provision(port, password, manifest, plain_database)
        home = write_home(workdir, port, manifest, credentials)
        restore = run_pytest(restore_receipt, 'Fresh-cluster protected-backup recovery and adoption; isolated cluster' + profile,
                             ('tests/test_search_operational_cli.py::test_genuine_adopted_search_cli_seals_saved_activation_and_latest_native_exit' if args.search_cli else
                              'tests/test_payload_operational_cli.py::test_genuine_adopted_payload_cli_seals_saved_activation_and_latest_native_exit' if args.payload_cli else
                              'tests/test_rewrap_operational_cli.py::test_genuine_adopted_rewrap_cli_preserves_binding_and_byte_identity' if args.rewrap_cli else
                              'tests/test_reverse_operational_cli.py::test_genuine_adopted_source_reverse_cli_uses_explicit_binding_and_latest_native_exit' if args.reverse_cli else
                              'tests/test_fresh_boolean_restore.py' if args.integer or args.date else
                              'tests/test_public_slots_restore.py' if args.public_slots else
                              'tests/test_owned_sequences_restore.py' if args.owned_sequences else
                              'tests/test_sqlmodel_searchable_restore.py' if (args.sqlmodel_searchable or args.sqlmodel_direct_search or args.sqlmodel_public_slots or args.sqlmodel_http) else
                              'tests/test_fresh_boolean_restore.py' if args.boolean else
                              'tests/test_smolink_fresh_cluster.py' if args.smolink
                              else 'tests/test_direct_generation.py' if args.direct_generation
                              else 'tests/test_adopted_search.py' if args.adopted_search
                              else 'tests/test_adopted_payload.py' if args.adopted_payload
                              else 'tests/test_adopted_rewrap.py' if args.adopted_rewrap
                              else 'tests/test_restore_lease_fresh.py' if args.restore_lease
                              else 'tests/test_fresh_cluster_restore.py'),
                             {'HOME': str(home), 'CRYPTALIS_FRESH_CLUSTER_DIR': str(workdir),
                              'CRYPTALIS_FRESH_INTEGER_BITS': str(args.integer or 0),
                              'CRYPTALIS_FRESH_DATE': '1' if args.date else '0',
                              'CRYPTALIS_SQLMODEL_DIRECT_SEARCH': '1' if (args.sqlmodel_direct_search or args.sqlmodel_public_slots) else '0',
                              'CRYPTALIS_SQLMODEL_PUBLIC_SLOTS': '1' if (args.sqlmodel_public_slots or args.sqlmodel_http) else '0',
                              'CRYPTALIS_SQLMODEL_HTTP_FRESH': '1' if args.sqlmodel_http else '0',
                              'CRYPTALIS_FRESH_PLAIN_DATABASE': plain_database,
                              'CRYPTALIS_FRESH_PLAINTEXT_ROLE': credentials['plaintext'][0],
                              'CRYPTALIS_FRESH_SOURCE_REWRAP': '1' if args.rewrap else '0',
                              'CRYPTALIS_FRESH_SOURCE_PAYLOAD_ROTATION': '1' if args.payload_rotation else '0',
                              'CRYPTALIS_FRESH_SOURCE_SEARCH_ROTATION': '1' if args.search_rotation else '0'})
    finally:
        stop_cluster(cluster)
    print('workdir', workdir)
    for name, receipt in (('export', export), ('restore', restore)):
        print(name, receipt['counts'], receipt['exit_code'], receipt['fixing_revision'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
