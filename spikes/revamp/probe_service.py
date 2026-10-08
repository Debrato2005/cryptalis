"""Probe only the user-authorized disposable database without exposing its URL."""
import json
import os
from pathlib import Path
import socket

import psycopg
from psycopg.conninfo import conninfo_to_dict

RESULT = Path(__file__).with_name('results') / 'service-probe.json'
EXPECTED = {'host': '127.0.0.1', 'port': '55432', 'dbname': 'cryptalis_test', 'user': 'cryptalis_migrator'}


def emit(result, code):
    RESULT.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    raise SystemExit(code)


def main():
    url = os.environ.get('CRYPTALIS_TEST_DATABASE_URL')
    result = {'status': 'UNKNOWN', 'url_environment_present': bool(url), 'authentication': 'NOT_REACHED',
              'mutations': 'NONE', 'connection_url': 'NEVER_RECORDED'}
    stage = 'create_tcp_socket'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            stage = 'connect_authorized_disposable_endpoint'
            client.connect((EXPECTED['host'], int(EXPECTED['port'])))
    except OSError as exc:
        result.update({'stage': stage, 'errno': exc.errno,
                       'os_error': os.strerror(exc.errno) if exc.errno is not None else 'TIMEOUT'})
        emit(result, 3)
    if not url:
        result.update({'stage': 'configuration', 'reason': 'URL_ENVIRONMENT_NOT_AVAILABLE_TO_EXECUTOR'})
        emit(result, 3)
    try:
        config = conninfo_to_dict(url)
        if any(str(config.get(key)) != value for key, value in EXPECTED.items()):
            result.update({'stage': 'configuration', 'reason': 'TARGET_NOT_AUTHORIZED'})
            emit(result, 2)
        with psycopg.connect(url, **EXPECTED, hostaddr=EXPECTED['host'], connect_timeout=3) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT current_database(),current_user,current_setting('server_version'),rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user")
                row = cursor.fetchone()
                if row[0] != EXPECTED['dbname'] or row[1] != EXPECTED['user'] or any(row[3:]):
                    result.update({'stage': 'identity', 'reason': 'RESTRICTED_TARGET_CONTRACT_FAILED'})
                    emit(result, 2)
                result.update({'status': 'CONNECTED_RESTRICTED_ROLE', 'authentication': 'OBSERVED',
                               'stage': 'identity', 'server_version': row[2], 'non_superuser': True,
                               'no_createdb': True, 'no_createrole': True})
    except Exception as exc:
        # Provider/driver exception text can include connection material.
        result.update({'stage': 'connection_or_identity', 'exception_type': type(exc).__name__,
                       'sqlstate': getattr(exc, 'sqlstate', None), 'reason': 'CONNECTION_FAILURE_DETAILS_WITHHELD'})
        emit(result, 3)
    emit(result, 0)


if __name__ == '__main__':
    main()
