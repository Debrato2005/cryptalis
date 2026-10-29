"""Source-role admission controls for the PostgreSQL wrapper; no database calls."""
import importlib.util
import os
import sys
from types import SimpleNamespace

import pytest


@pytest.fixture(autouse=True)
def preserve_outer_wrapper_admission(monkeypatch):
    # Nested runner calls clear inherited URLs as intended. Keep their effects
    # inside this controlled test so later real PostgreSQL tests retain theirs.
    for name in ('CRYPTALIS_TEST_DATABASE_URL','CRYPTALIS_TEST_RUNTIME_DATABASE_URL','CRYPTALIS_TEST_SOURCE_URL'):
        if name in os.environ:
            monkeypatch.setenv(name,os.environ[name])
        else:
            monkeypatch.delenv(name,raising=False)
    monkeypatch.setitem(sys.modules,'_cryptalis_test_preflight',sys.modules['_cryptalis_test_preflight'])


def load_runner(path):
    spec = importlib.util.spec_from_file_location('_cryptalis_source_role_runner', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('source_role', [False, True])
@pytest.mark.parametrize('configuration', ['explicit', 'home'])
def test_wrapper_loads_only_selected_private_urls_and_clears_inherited_values(
        tmp_path, monkeypatch, capsys, source_role, configuration):
    root = __import__('pathlib').Path(__file__).resolve().parents[1]
    runner = load_runner(root / 'scripts/test_postgres.py')
    if configuration == 'explicit':
        monkeypatch.setenv(runner.CONFIG_DIRECTORY, str(tmp_path))
        monkeypatch.setattr(runner.Path, 'home', classmethod(
            lambda cls: pytest.fail('explicit configuration must not consult HOME')))
    else:
        monkeypatch.delenv(runner.CONFIG_DIRECTORY, raising=False)
        monkeypatch.setattr(runner.Path, 'home', classmethod(lambda cls: tmp_path))
    files = (*runner.FILES, runner.SOURCE_FILE)
    values = ('postgresql://owner@localhost/db', 'postgresql://runtime@localhost/db',
              'postgresql://source@localhost/plain')
    for filename, value in zip(files[:2], values[:2]):
        (tmp_path / filename).write_text(value + '\n')
        (tmp_path / filename).chmod(0o600)
    if source_role:
        (tmp_path / files[2]).write_text(values[2] + '\n')
        (tmp_path / files[2]).chmod(0o600)
    for name in (*runner.VARIABLES, runner.SOURCE_VARIABLE):
        monkeypatch.setenv(name, 'inherited-value')
    monkeypatch.setattr(runner, 'psycopg', SimpleNamespace())
    probed = []
    monkeypatch.setattr(runner, 'preflight', lambda urls: probed.append(urls) or True)
    monkeypatch.setattr(runner, 'source_hashes', lambda: {})
    admitted_env = []
    monkeypatch.setattr('pytest.main', lambda *args, **kwargs: admitted_env.append(dict(os.environ)) or 0)
    monkeypatch.setattr(sys, 'argv', ['test_postgres.py', *(['--source-role'] if source_role else []),
                                      '--', 'controlled-test'])

    assert runner.main() == 0
    expected = values if source_role else values[:2]
    assert probed == [expected]
    selected = runner.VARIABLES + ((runner.SOURCE_VARIABLE,) if source_role else ())
    assert len(admitted_env) == 1
    assert tuple(admitted_env[0][name] for name in selected) == expected
    assert (runner.SOURCE_VARIABLE in admitted_env[0]) is source_role
    output = capsys.readouterr().out
    assert all(value not in output for value in values)


def test_source_role_probe_failure_stops_before_pytest(tmp_path, monkeypatch):
    root = __import__('pathlib').Path(__file__).resolve().parents[1]
    runner = load_runner(root / 'scripts/test_postgres.py')
    monkeypatch.setenv(runner.CONFIG_DIRECTORY, str(tmp_path))
    for filename in (*runner.FILES, runner.SOURCE_FILE):
        (tmp_path / filename).write_text('postgresql://role@localhost/db\n')
        (tmp_path / filename).chmod(0o600)
    monkeypatch.setattr(runner, 'psycopg', SimpleNamespace())
    probes = []
    monkeypatch.setattr(runner, 'preflight', lambda urls: probes.append(urls) or False)
    monkeypatch.setattr(sys, 'argv', ['test_postgres.py', '--source-role'])
    monkeypatch.setattr('pytest.main', lambda *args, **kwargs: pytest.fail('pytest must not run'))

    assert runner.main() == 2
    assert len(probes) == 1 and len(probes[0]) == 3


def test_failed_source_cluster_shutdown_blocks_restored_authority(tmp_path,monkeypatch):
    """A failed stop must prevent the fresh target from starting or adopting."""
    from pathlib import Path
    import subprocess
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root/'scripts'))
    harness = load_runner(root/'scripts/online_qualification.py')
    started = []
    def start(directory):
        started.append(directory)
        return directory/'cluster',54321,'PUBLIC unused fixture password'
    monkeypatch.setattr(harness,'start_cluster',start)
    monkeypatch.setattr(harness,'provision',lambda *args: {})
    monkeypatch.setattr(harness,'write_home',lambda directory,*args,**kwargs: directory)
    def run(command,**kwargs):
        if Path(command[0]).name == 'pg_ctl':
            if kwargs.get('check'):
                raise subprocess.CalledProcessError(1,command)
            return subprocess.CompletedProcess(command,1)
        return subprocess.CompletedProcess(command,0)
    monkeypatch.setattr(subprocess,'run',run)
    monkeypatch.setattr(sys,'argv',['online_qualification.py','--workdir',str(tmp_path/'run'),'--http-fresh'])
    with pytest.raises(subprocess.CalledProcessError):
        harness.main()
    assert started == [tmp_path/'run'/'source']
