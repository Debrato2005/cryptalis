"""Development diagnosis uses real dual probes; refusals expose no credentials."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

import psycopg
import pytest


PRIVATE_URLS = tuple(os.environ[name] for name in (
    'CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL'))


def runner(monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'scripts/test_postgres.py'
    spec = importlib.util.spec_from_file_location('_cryptalis_dev_preflight', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in (*module.VARIABLES, module.SOURCE_VARIABLE):
        # The CLI clears inherited values. Restore the outer runner after this test.
        if name in os.environ:
            monkeypatch.setenv(name, os.environ[name])
    monkeypatch.setattr(sys, 'argv', [str(path), '--development-preflight'])
    monkeypatch.setattr(pytest, 'main', lambda *a, **k: pytest.fail('diagnosis invoked pytest'))
    return module


def report(capsys):
    output = capsys.readouterr().out
    assert all(value not in output for value in PRIVATE_URLS)
    assert 'PRIVATE_DIAGNOSTIC_DETAIL' not in output
    return json.loads(output)


@pytest.mark.parametrize('source_present', [False, True])
def test_diagnostics_restore_optional_source_role_for_following_tests(monkeypatch, capsys, source_present):
    name = 'CRYPTALIS_TEST_SOURCE_URL'
    if source_present:
        monkeypatch.setenv(name, 'PUBLIC source-role restoration sentinel')
    else:
        monkeypatch.delenv(name, raising=False)
    with monkeypatch.context() as diagnostic:
        module = runner(diagnostic)
        assert module.main() == 0
        assert report(capsys)['checks']['restricted_roles']['status'] == 'PASS'
    restored = (os.environ.get(name) == 'PUBLIC source-role restoration sentinel'
                if source_present else name not in os.environ)
    assert restored, 'Diagnostics changed the optional source-role state for later tests.'


def test_native_development_prerequisites_do_not_authorize_destructive_tests(monkeypatch, capsys):
    module = runner(monkeypatch)
    assert module.main() == 0
    document = report(capsys)
    assert document['status'] == 'READY_FOR_APPROVED_TESTS'
    for name in ('git_metadata', 'dependencies', 'test_configuration', 'sockets',
                 'postgresql16', 'restricted_roles', 'build_tools'):
        assert document['checks'][name]['status'] == 'PASS'
    assert document['checks']['target_authorization']['status'] == 'UNKNOWN'


@pytest.mark.parametrize('restriction', ['git', 'socket'])
def test_local_restriction_stops_before_database_probe(monkeypatch, capsys, restriction):
    module = runner(monkeypatch)
    def forbidden(*args, **kwargs):
        pytest.fail('local refusal reached a database connection')
    monkeypatch.setattr(psycopg, 'connect', forbidden)
    if restriction == 'git':
        def denied(*args, **kwargs):
            raise OSError(errno.EROFS, 'PRIVATE_DIAGNOSTIC_DETAIL')
        monkeypatch.setattr(tempfile, 'TemporaryFile', denied)
    else:
        def denied(*args, **kwargs):
            raise PermissionError(errno.EPERM, 'PRIVATE_DIAGNOSTIC_DETAIL')
        monkeypatch.setattr(socket, 'socket', denied)
    assert module.main() == 2
    document = report(capsys)
    check = document['checks']['git_metadata' if restriction == 'git' else 'sockets']
    assert check['status'] == 'FAIL'
    assert check['classification'] == 'authorized_alternative'


@pytest.mark.parametrize('fault', ['permissions', 'symlink', 'different_target'])
def test_unsafe_test_configuration_refuses_without_connection(monkeypatch, capsys, tmp_path, fault):
    module = runner(monkeypatch)
    original_home = Path.home()
    for name in module.FILES:
        path = tmp_path / name
        path.write_bytes((original_home / name).read_bytes())
        path.chmod(0o600)
    if fault == 'permissions':
        (tmp_path / module.FILES[0]).chmod(0o640)
    elif fault == 'symlink':
        (tmp_path / module.FILES[0]).unlink()
        (tmp_path / module.FILES[0]).symlink_to(original_home / module.FILES[0])
    else:
        path = tmp_path / module.FILES[1]
        values = module.conninfo_to_dict(path.read_text().strip().replace(
            'postgresql+psycopg://', 'postgresql://', 1))
        values['dbname'] = 'PUBLIC_WRONG_TEST_TARGET'
        path.write_text(module.make_conninfo(**values))
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    # Keep build-tool discovery independent of the temporary private-file HOME.
    monkeypatch.setenv('PATH', str(original_home / '.local/bin') + os.pathsep + os.environ['PATH'])
    monkeypatch.setattr(psycopg, 'connect', lambda *a, **k: pytest.fail('unsafe configuration connected'))
    assert module.main() == 2
    document = report(capsys)
    assert document['checks']['test_configuration']['status'] == 'FAIL'
    assert document['checks']['test_configuration']['classification'] == 'external_prerequisite'


def test_connection_failure_is_classified_without_raw_exception_text(monkeypatch, capsys):
    module = runner(monkeypatch)
    def unavailable(*args, **kwargs):
        raise psycopg.OperationalError('PRIVATE_DIAGNOSTIC_DETAIL')
    monkeypatch.setattr(psycopg, 'connect', unavailable)
    assert module.main() == 2
    document = report(capsys)
    check = document['checks']['postgresql16']
    assert check['status'] == 'FAIL'
    assert check['classification'] == 'external_prerequisite'
    assert document['status'] == 'BLOCKED'


def test_wrong_major_tools_are_not_reported_as_postgresql16(monkeypatch, capsys):
    module = runner(monkeypatch)
    original = subprocess.run
    def version_override(args, **kwargs):
        if args[-1] == '--version':
            return subprocess.CompletedProcess(args, 0, 'tool (PostgreSQL) 15.9\n', '')
        return original(args, **kwargs)
    monkeypatch.setattr(subprocess, 'run', version_override)
    assert module.main() == 0
    document = report(capsys)
    assert document['checks']['fresh_cluster_tools']['status'] == 'UNKNOWN'
    assert document['checks']['postgresql16']['status'] == 'PASS'


def test_runtime_database_create_is_refused(monkeypatch, capsys):
    module = runner(monkeypatch)
    original = module.preflight
    def observe_grant(urls, *, observations):
        result = original(urls, observations=observations)
        if result:
            facts = list(observations[1]['facts'])
            facts[14] = True  # Controlled CREATE observation; no native grant change.
            observations[1]['facts'] = tuple(facts)
        return result
    monkeypatch.setattr(module, 'preflight', observe_grant)
    assert module.main() == 2
    document = report(capsys)
    assert document['checks']['restricted_roles']['status'] == 'FAIL'
