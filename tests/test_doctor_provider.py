"""Cold-access diagnostics: no cache authority, leaked values or DB effects."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

import cryptalis
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring, create_root
from cryptalis.doctor import check_keys


def keyring():
    provider = DevelopmentKeyProvider()
    context = KeyContext(uuid4(), uuid4(), 'payload', uuid4(), 1)
    policy = KeyPolicy(context.domain_id, context.tenant_id, (create_root(provider, context),), 1)
    return Keyring(policy, {provider.provider_id: provider}), provider


def test_cold_checks_preserve_original_cache_and_do_not_claim_full_health(monkeypatch):
    ring, provider = keyring()
    assert check_keys((ring,))['checks']['cold_key_preparation'] == 'PASS'
    assert not ring._cache
    ring.prepare()
    cache = dict(ring._cache)
    assert check_keys((ring,))['status'] == 'UNKNOWN'
    assert ring._cache == cache
    def unavailable(*args):
        raise RuntimeError('PRIVATE_PROVIDER_EXCEPTION')
    monkeypatch.setattr(provider, 'unwrap', unavailable)
    assert ring.prepare()  # A valid lease remains available to the application.
    report = check_keys((ring,))
    assert report['checks']['cold_key_preparation'] == report['status'] == 'FAIL'
    assert ring._cache == cache
    assert all(value == 'UNKNOWN' for name, value in report['checks'].items()
               if name != 'cold_key_preparation')
    encoded = json.dumps(report)
    assert 'PRIVATE_PROVIDER_EXCEPTION' not in encoded
    assert str(ring.policy.tenant_id) not in encoded


@pytest.mark.parametrize('invalid', [None, [], (None,), 'keys', (None,) * 17])
def test_invalid_finite_input_never_dispatches_partial_provider_work(monkeypatch, invalid):
    ring, provider = keyring()
    monkeypatch.setattr(provider, 'unwrap', lambda *args: pytest.fail('invalid input dispatched'))
    selection = (ring, *invalid) if type(invalid) is tuple else invalid
    report = check_keys(selection)
    assert report['status'] == 'FAIL'
    assert report['items'] == []
    assert report['issues'][0]['code'] == 'Provider.InvalidKeyrings'


def test_empty_input_remains_unknown_and_partial_failure_keeps_all_outcomes(monkeypatch):
    assert check_keys()['checks']['cold_key_preparation'] == 'UNKNOWN'
    first, provider = keyring()
    second, _ = keyring()
    monkeypatch.setattr(provider, 'unwrap', lambda *args: b'short')
    report = check_keys((first, second))
    assert report['items'] == [{'index': 0, 'status': 'FAIL'}, {'index': 1, 'status': 'PASS'}]
    assert report['status'] == 'FAIL'
    assert not first._cache and not second._cache


def test_authentication_failure_keeps_partial_results_unknown_effects_and_caller_leases(monkeypatch):
    from cryptalis.crypto import ProviderAuthenticationUnavailable
    first, _ = keyring()
    second, provider = keyring()
    second.prepare()
    cache = dict(second._cache)
    calls = []
    def unavailable(*args):
        calls.append(True)
        raise ProviderAuthenticationUnavailable() from RuntimeError('PRIVATE_AUTH_DETAIL')
    monkeypatch.setattr(provider, 'unwrap', unavailable)
    report = check_keys((first, second))
    assert report['status'] == report['checks']['cold_key_preparation'] == 'FAIL'
    assert report['effects'] == 'UNKNOWN'
    assert report['items'] == [{'index': 0, 'status': 'PASS'}, {'index': 1, 'status': 'FAIL'}]
    issue, = report['issues']
    assert issue['code'] == 'Provider.AuthenticationUnavailable' and issue['retryable'] is False
    assert 'native token issuance' in issue['remedy']
    assert 'PRIVATE_AUTH_DETAIL' not in json.dumps(report)
    assert len(calls) == 1 and second._cache == cache
    assert second.prepare()  # Diagnosis cannot revoke or refresh the caller's lease.
    assert len(calls) == 1


def invoke(directory, body, *options):
    (directory / 'provider_host.py').write_text(body)
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join((
        str(Path(cryptalis.__file__).resolve().parent.parent), str(directory))))
    return subprocess.run([sys.executable, '-m', 'cryptalis', 'doctor',
        '--provider-context=provider_host:context', '--json', *options],
        # A provider may make two independently bounded 10s HTTPS requests.
        # This process watchdog also covers interpreter/host initialization;
        # it is not a provider latency acceptance target.
        env=environment, capture_output=True, text=True, timeout=45)


@pytest.mark.parametrize('body,code,status', [
    ('def context(): return ()', 'KeyAccessUnavailable', 'UNKNOWN'),
    ('def context(): return (None,)', 'HostContextInvalid', 'FAIL'),
    ('async def context(): return ()', 'HostContextInvalid', 'FAIL'),
    ('async def value(): return ()\ndef context(): return value()', 'HostContextInvalid', 'FAIL'),
    ('def context(): raise RuntimeError("PRIVATE_CONTEXT")', 'HostContextUnavailable', 'UNKNOWN'),
    ('def context(): raise SystemExit("PRIVATE_CONTEXT")', 'HostContextUnavailable', 'UNKNOWN'),
])
def test_cli_context_refusals_are_redacted_and_have_explicit_scope(tmp_path, body, code, status):
    result = invoke(tmp_path, 'print("PRIVATE_CONTEXT")\n' + body)
    assert result.returncode == (2 if code == 'HostContextInvalid' else 4)
    assert result.stdout == ''
    assert 'PRIVATE_CONTEXT' not in result.stderr and 'Warning' not in result.stderr
    report = json.loads(result.stderr)['error']
    assert report['code'] == code and report['status'] == status
    assert report['scope'] == 'cold_provider_access'
    assert report['host_configuration_effects'] == 'UNKNOWN'


@pytest.mark.parametrize('options', [
    ('--database-url-file', 'unused'), ('--host-context', 'unused:factory'),
    ('--pin', 'unused'), ('--restore-binding', 'unused'),
    ('--pre-adoption', 'unused'), ('unused-plan',),
])
def test_cli_mixed_modes_refuse_before_host_import(tmp_path, options):
    marker = tmp_path / 'imported'
    result = invoke(tmp_path, f'from pathlib import Path\nPath({str(marker)!r}).touch()', *options)
    assert result.returncode == 2 and not marker.exists()
    report = json.loads(result.stderr)['error']
    assert report['code'] == 'InvalidArguments'
    assert report['scope'] == 'cold_provider_access'


def test_cli_checks_real_development_wrappers_without_database_or_stream_leaks(tmp_path):
    result = invoke(tmp_path, '''
from uuid import uuid4
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring, create_root
import sys
print('PRIVATE_CONTEXT')
def context():
    p = DevelopmentKeyProvider()
    c = KeyContext(uuid4(), uuid4(), 'payload', uuid4(), 1)
    w = create_root(p, c)
    original = p.unwrap
    def unwrap(*args):
        print('PRIVATE_PROVIDER_OUTPUT', file=sys.stderr)
        return original(*args)
    p.unwrap = unwrap
    return (Keyring(KeyPolicy(c.domain_id, c.tenant_id, (w,), 1), {p.provider_id: p}),)
''')
    assert result.returncode == 0 and result.stderr == ''
    assert 'PRIVATE_' not in result.stdout
    report = json.loads(result.stdout)
    assert report['checks']['cold_key_preparation'] == 'PASS'
    assert report['status'] == 'UNKNOWN' and report['effects'] == 'PROVIDER_ACCESS'
