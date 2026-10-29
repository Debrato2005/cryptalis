"""Run online protection E2E checks on an isolated PostgreSQL 16 cluster.

Every test runs through the mandatory wrapper with three freshly loaded private
role URLs. The cluster stops on every exit. Failed probes are never retried.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys

from fresh_cluster_qualification import start_cluster, stop_cluster, provision, write_home


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', type=Path, required=True)
    parser.add_argument('--installed-wheel', type=Path,
                        help='Bind both wrapper phases to this inspected installed wheel.')
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument('--http', action='store_true',
                        help='Run the pinned original HTTP application through online capture and native exit.')
    profiles.add_argument('--http-fresh', action='store_true',
                         help='Recover the online HTTP backup on a new cluster, rotate keys and restore native operation.')
    profiles.add_argument('--tenant-http-fresh', action='store_true',
                         help='Recover authenticated owner-scoped original HTTP CRUD/admin cascades on a fresh cluster.')
    profiles.add_argument('--fresh-scalar', choices=('date', 'uuid', 'boolean', 'int16', 'int32', 'int64'),
                         help='Qualify typed storage, rotations, fresh restore and package-free exit.')
    parser.add_argument('--public-slots', action='store_true', help='Preserve public slots in scalar recovery.')
    parser.add_argument('pytest_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.public_slots and (not args.fresh_scalar or args.fresh_scalar == 'boolean'):
        parser.error('--public-slots requires --fresh-scalar date/uuid/int16/int32/int64')
    if args.fresh_scalar and args.pytest_args:
        parser.error('--fresh-scalar runs its fixed export/restore profile; omit pytest arguments')
    args.workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {'owner_role':'cryptalis_online_owner',
                'runtime_role':'cryptalis_online_runtime', 'database':'cryptalis_online'}
    root = Path(__file__).resolve().parents[1]
    runtime_options = ([] if args.installed_wheel is None else
                       ['--installed-wheel', str(args.installed_wheel.resolve())])
    selected = args.pytest_args
    if selected[:1] == ['--']: selected = selected[1:]
    if not selected:
        selected = (['tests/profile_sqlmodel_http_tenant_application.py','-q'] if args.tenant_http_fresh else
                    ['tests/profile_online_http_application.py','-q'] if args.http or args.http_fresh else
                    ['tests/test_online_protection.py','tests/test_online_recovery.py','tests/test_online_multitable.py','tests/test_online_tenants.py',
                     'tests/test_online_access.py','tests/test_postgres_source_role.py','-q'])
    fresh = args.http_fresh or args.tenant_http_fresh
    backup_variable = ('CRYPTALIS_TENANT_HTTP_BACKUP_DIR' if args.tenant_http_fresh else 'CRYPTALIS_ONLINE_HTTP_BACKUP_DIR')
    report_variable = ('CRYPTALIS_TENANT_HTTP_REPORT' if args.tenant_http_fresh else 'CRYPTALIS_ONLINE_HTTP_REPORT')
    backup = args.workdir/'backup'
    if fresh: backup.mkdir(mode=0o700)
    source = args.workdir/'source' if fresh else args.workdir
    if fresh: source.mkdir(mode=0o700)
    cluster = None
    try:
        cluster,port,password = start_cluster(source)
        credentials = provision(port,password,manifest,'cryptalis_online_native')
        home = write_home(source,port,manifest,credentials,source_database=manifest['database'])
        command = [sys.executable,str(root/'scripts/test_postgres.py'),*runtime_options,'--source-role',
                   '--scope','Isolated PostgreSQL 16 online protection: three authenticated roles',
                   '--receipt',str(source/'receipt.json'),'--',*selected]
        environment = dict(os.environ,CRYPTALIS_TEST_CONFIG_DIR=str(home),CRYPTALIS_ONLINE_RESTORE_DATABASE='cryptalis_online_native')
        if args.http or fresh:
            environment[report_variable] = str(source/'application.json')
        if fresh:
            environment[backup_variable] = str(backup)
        if args.fresh_scalar:
            command = [sys.executable, str(root/'scripts/fresh_cluster_qualification.py'),
                       '--workdir', str(args.workdir/'recovery'), *runtime_options]
            command += (['--integer', args.fresh_scalar[3:]] if args.fresh_scalar.startswith('int')
                        else ['--' + args.fresh_scalar])
            if args.public_slots:
                command.append('--public-slots')
        result = subprocess.run(command,cwd=root,env=environment).returncode
    finally:
        if cluster is not None: stop_cluster(cluster)
    if result or not fresh: return result
    if not (backup/'manifest.json').is_file() or not (backup/'protected.sql').is_file():
        raise SystemExit('Online HTTP export did not produce the required backup artifacts.')
    # The source process is terminal before a distinct cluster receives authority.
    restored = args.workdir/'restored'
    restored.mkdir(mode=0o700)
    manifest = {**manifest,'database':'cryptalis_online_restored'}
    cluster = None
    try:
        cluster,port,password = start_cluster(restored)
        credentials = provision(port,password,manifest,'cryptalis_online_restored_native')
        home = write_home(restored,port,manifest,credentials,source_database=manifest['database'])
        command = [sys.executable,str(root/'scripts/test_postgres.py'),*runtime_options,'--source-role',
                   '--scope','Fresh-cluster online HTTP restore, adopted rotations and native exit: three authenticated roles',
                   '--receipt',str(restored/'receipt.json'),'--',
                   'tests/profile_sqlmodel_http_tenant_restore.py' if args.tenant_http_fresh else 'tests/profile_online_http_restore.py','-q']
        environment = dict(os.environ, CRYPTALIS_TEST_CONFIG_DIR=str(home), **{backup_variable: str(backup),
                           report_variable: str(restored/'application.json')})
        return subprocess.run(command,cwd=root,env=environment).returncode
    finally:
        if cluster is not None: stop_cluster(cluster)


if __name__ == '__main__':
    raise SystemExit(main())
