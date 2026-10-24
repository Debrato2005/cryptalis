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
    parser.add_argument('pytest_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.workdir.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {'owner_role':'cryptalis_online_owner',
                'runtime_role':'cryptalis_online_runtime', 'database':'cryptalis_online'}
    cluster = None
    try:
        cluster,port,password = start_cluster(args.workdir)
        credentials = provision(port,password,manifest,'cryptalis_online_native')
        home = write_home(args.workdir,port,manifest,credentials,source_database=manifest['database'])
        root = Path(__file__).resolve().parents[1]
        selected = args.pytest_args
        if selected[:1] == ['--']: selected = selected[1:]
        if not selected:
            selected = ['tests/test_online_protection.py','tests/test_online_recovery.py','tests/test_online_multitable.py','tests/test_online_access.py',
                        'tests/test_postgres_source_role.py','-q']
        command = [sys.executable,str(root/'scripts/test_postgres.py'),'--source-role',
                   '--scope','Isolated PostgreSQL 16 online protection: three authenticated roles',
                   '--receipt',str(args.workdir/'receipt.json'),'--',*selected]
        return subprocess.run(command,cwd=root,env=dict(os.environ,HOME=str(home),CRYPTALIS_ONLINE_RESTORE_DATABASE='cryptalis_online_native')).returncode
    finally:
        if cluster is not None: stop_cluster(cluster)


if __name__ == '__main__':
    raise SystemExit(main())
