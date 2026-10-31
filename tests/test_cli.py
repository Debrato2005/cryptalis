"""The command line, run as a real process: useful output and observable failures."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import pytest

_REPOSITORY_ROOT = Path(__file__).parent.parent
_MANIFEST = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(UUID(int=1)),
    'models': [{'model': 'Customer', 'table_id': str(UUID(int=2)), 'tenancy': {'column': 'tenant_id'}, 'fields': [
        {'name': 'email', 'field_id': str(UUID(int=3)), 'protect': True, 'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']},
        {'name': 'amount', 'field_id': str(UUID(int=4)), 'protect': True, 'queries': ['equality', 'order'], 'accept_leakage': ['equality', 'order']},
        {'name': 'note', 'field_id': str(UUID(int=5)), 'protect': True, 'queries': [], 'accept_leakage': []}]}]}


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cryptalis", *arguments],
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def _manifest(tmp_path):
    path = tmp_path / 'cryptalis.json'
    path.write_text(json.dumps(_MANIFEST))
    return path


def test_manifest_inspect_shows_what_is_protected_and_the_accepted_leakage(tmp_path):
    path = _manifest(tmp_path)
    text = _run_cli('manifest', 'inspect', str(path))
    assert text.returncode == 0 and text.stderr == ''
    assert 'Customer.email: equality, unique' in text.stdout
    assert 'Customer.amount: equality, order' in text.stdout
    assert 'Customer.note: storage only' in text.stdout
    machine = _run_cli('manifest', 'inspect', str(path), '--json')
    assert machine.returncode == 0
    result = json.loads(machine.stdout)
    assert result['scope'] == 'manifest' and result['domain_id'] == str(UUID(int=1))
    assert result['fields'] == [{'model': 'Customer', 'field': 'amount', 'search': ['equality', 'order']},
                                {'model': 'Customer', 'field': 'email', 'search': ['equality', 'unique']},
                                {'model': 'Customer', 'field': 'note', 'search': []}]
    # Reformatting the same declaration keeps its digest.
    path.write_text(json.dumps(_MANIFEST, indent=4))
    assert json.loads(_run_cli('manifest', 'inspect', str(path), '--json').stdout)['digest'] == result['digest']


@pytest.mark.parametrize('content', [
    b'{"schema": "do-not-echo-secret"}',
    b'not json do-not-echo-secret',
    json.dumps({**_MANIFEST, 'schema': 'do-not-echo-secret'}).encode(),
])
def test_invalid_manifest_is_refused_without_echoing_it(tmp_path, content):
    path = tmp_path / 'do-not-echo-path.json'
    path.write_bytes(content)
    result = _run_cli('manifest', 'inspect', str(path), '--json')
    assert result.returncode == 2 and result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert (error['family'], error['code'], error['cause']) == ('Manifest', 'Invalid', 'ManifestInvalid')
    UUID(error['correlation_id'])
    assert 'do-not-echo' not in result.stderr


def test_missing_and_oversized_files_are_refused(tmp_path):
    missing = tmp_path / 'do-not-echo-missing.json'
    result = _run_cli('manifest', 'inspect', str(missing), '--json')
    assert result.returncode == 2 and json.loads(result.stderr)['error']['cause'] == 'ENOENT'
    assert str(missing) not in result.stderr
    oversized = tmp_path / 'oversized.json'
    oversized.write_bytes(b' ' * (16 * 1024 * 1024 + 1))
    result = _run_cli('manifest', 'inspect', str(oversized), '--json')
    assert result.returncode == 2 and result.stdout == ''


def test_unknown_command_is_refused_without_echo():
    result = _run_cli('sensitive-command-token')
    assert result.returncode == 2 and 'sensitive-command-token' not in result.stderr


@pytest.mark.parametrize('machine_json', [False, True])
@pytest.mark.parametrize('destination', ['full', 'closed_pipe'])
def test_failed_stdout_is_an_operational_failure_not_a_success(tmp_path, machine_json, destination):
    if destination == 'full':
        if not Path('/dev/full').exists():
            pytest.skip('The full-device fixture requires /dev/full.')
        sink = open('/dev/full', 'wb', buffering=0)
    else:
        reader, writer = os.pipe()
        os.close(reader)
        sink = os.fdopen(writer, 'wb', buffering=0)
    arguments = ['manifest', 'inspect', str(_manifest(tmp_path))] + (['--json'] if machine_json else [])
    with sink:
        result = subprocess.run([sys.executable, '-m', 'cryptalis', *arguments], cwd=_REPOSITORY_ROOT,
                                stdout=sink, stderr=subprocess.PIPE, text=True, check=False, timeout=10)
    assert result.returncode == 4
    assert 'Traceback' not in result.stderr and 'Exception ignored' not in result.stderr
    if machine_json:
        error = json.loads(result.stderr)['error']
        assert (error['family'], error['code']) == ('CLI', 'OutputUnavailable')
        assert error['cause'] == ('ENOSPC' if destination == 'full' else 'EPIPE')
    else:
        assert 'CLI.OutputUnavailable' in result.stderr


def test_closed_stdout_keeps_the_operational_exit(tmp_path):
    result = subprocess.run(
        [sys.executable, '-c', 'import os, sys; from cryptalis.cli import main; '
         'os.close(sys.stdout.fileno()); raise SystemExit(main(sys.argv[1:]))',
         'manifest', 'inspect', str(_manifest(tmp_path)), '--json'],
        cwd=_REPOSITORY_ROOT, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 4 and result.stdout == ''
    assert json.loads(result.stderr)['error']['cause'] == 'EBADF'
