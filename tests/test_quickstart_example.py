"""The published example must complete on the installed library, unedited."""

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict
from sqlalchemy import URL, select

from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyUnavailable, create_root
from cryptalis.project import ProjectError
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_project import STOPPED, protect, restart
from test_migration import application, TENANT

EXAMPLE = Path(__file__).parents[1] / 'examples' / 'quickstart.py'
CONTEXT = KeyContext(uuid4(), uuid4(), 'payload', uuid4(), 1)


def url(variable, schema):
    info = conninfo_to_dict(os.environ[variable])
    return URL.create('postgresql+psycopg', info['user'], info.get('password'), info['host'], int(info['port']),
                      info['dbname'], {'options': f'-csearch_path={schema}'}).render_as_string(hide_password=False)


def test_quickstart_completes_the_lifecycle_across_real_processes(tmp_path):
    if not os.environ.get('CRYPTALIS_TEST_SOURCE_URL'):
        pytest.skip('The example needs a separate native role.')
    schema = 'quickstart_' + uuid4().hex
    owner = os.environ['CRYPTALIS_TEST_DATABASE_URL']
    runtime, native = (conninfo_to_dict(os.environ[name])['user']
                       for name in ('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', 'CRYPTALIS_TEST_SOURCE_URL'))
    with psycopg.connect(owner, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA {schema}')
        connection.execute(f'GRANT USAGE ON SCHEMA {schema} TO "{runtime}", "{native}"')
    environment = {'PATH': os.environ['PATH'], 'HOME': str(tmp_path),
                   'QUICKSTART_OWNER_URL': url('CRYPTALIS_TEST_DATABASE_URL', schema),
                   'QUICKSTART_APP_URL': url('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema),
                   'QUICKSTART_NATIVE_URL': url('CRYPTALIS_TEST_SOURCE_URL', schema)}
    try:
        result = subprocess.run([sys.executable, EXAMPLE, tmp_path / 'state'], env=environment, cwd=tmp_path,
                                capture_output=True, text=True, timeout=300)
        assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
        assert "Undeclared search refuses before SQL: ('Customer.note (storage-only)',)" in result.stdout
        assert 'Native application reads ada@example.com / latest value' in result.stdout
    finally:
        with psycopg.connect(owner, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA {schema} CASCADE')


def test_development_key_file_keeps_custody_across_instances(tmp_path):
    path = tmp_path / 'kek'
    first = DevelopmentKeyProvider(path)
    assert path.stat().st_mode & 0o777 == 0o600
    wrapped = create_root(first, CONTEXT)
    written = path.stat().st_mtime_ns, path.stat().st_ino
    second = DevelopmentKeyProvider(path)
    assert (path.stat().st_mtime_ns, path.stat().st_ino) == written
    assert second.provider_id == first.provider_id
    assert second.unwrap(wrapped, CONTEXT) == first.unwrap(wrapped, CONTEXT)
    assert list(tmp_path.iterdir()) == [path]
    # A different file is a different custody identity, as an ephemeral provider is.
    with pytest.raises(KeyUnavailable):
        DevelopmentKeyProvider(tmp_path / 'other').unwrap(wrapped, CONTEXT)


@pytest.mark.parametrize('damage', ['readable', 'short', 'symlink', 'directory'])
def test_development_key_file_refuses_unsafe_custody(tmp_path, damage):
    path = tmp_path / 'kek'
    DevelopmentKeyProvider(path)
    if damage == 'readable':
        path.chmod(0o640)
    elif damage == 'short':
        path.write_bytes(b'short')
    elif damage == 'symlink':
        target = tmp_path / 'target'
        path.rename(target)
        path.symlink_to(target)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises(KeyUnavailable):
        DevelopmentKeyProvider(path)


def test_unsupported_query_names_declared_fields_without_values(tmp_path):
    provider, secret = DevelopmentKeyProvider(), 'a-secret-search-value'
    with application() as app:
        protect(app, restart(app, provider, tmp_path / 'state'))
        process = restart(app, provider, tmp_path / 'state')
        with process.project.attach(process.runtime)(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation) as refused:
                session.execute(select(process.Customer).where(process.Customer.name.like(secret)))
    assert refused.value.fields == ('Customer.name (equality, IN)',)
    assert 'Customer.name (equality, IN)' in str(refused.value) and secret not in str(refused.value)


def test_decrypt_explains_a_reused_runtime_role(tmp_path):
    with application() as app:
        process = restart(app, DevelopmentKeyProvider(), tmp_path / 'state')
        protect(app, process)
        with pytest.raises(ProjectError, match='DistinctPlaintextRoleRequired'):
            process.project.decrypt(app.owner, plaintext_role=app.role, writers_stopped=STOPPED,
                                    accept_plaintext=True, retained_backups='Synthetic fixture.')
