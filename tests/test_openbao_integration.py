"""Real OpenBao HTTPS/Transit and PostgreSQL; configured isolated services only.

CRYPTALIS_OPENBAO_TEST_CONFIG names a private JSON file containing endpoint,
ca_cert, and admin_token_file (OpenBao initialization JSON). Never use production.
Keys and mounts are retained; tests do not delete or export service key material.
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, insert, select, update

from cryptalis.crypto import (DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring,
    KeyUnavailable, WrappedRoot, create_root, open_text, seal_text)
from cryptalis.crypto.openbao import OpenBaoAppRoleToken, OpenBaoTransitKeyProvider
from test_cf1 import descriptor
from test_application_online import app, tenant_app, exercise_online

CONTEXT = KeyContext(UUID(int=1), UUID(int=4), 'payload', UUID(int=907), 1)
ROOT = bytes(range(32))  # Public test vector; production roots use create_root.


def private_json(path):
    path = Path(path)
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
    return json.loads(path.read_text())


@pytest.fixture(scope='module')
def service():
    path = os.environ.get('CRYPTALIS_OPENBAO_TEST_CONFIG')
    if not path:
        pytest.skip('explicit isolated OpenBao HTTPS test configuration not supplied')
    hvac = pytest.importorskip('hvac')
    config = private_json(path)
    admin = hvac.Client(url=config['endpoint'], verify=config['ca_cert'],
                        token=private_json(config['admin_token_file'])['root_token'],
                        allow_redirects=False, timeout=5)
    assert admin.sys.read_health_status(method='GET')['version'] == '2.7.2'
    mount = 'cryptalis-test-' + uuid4().hex
    admin.sys.enable_secrets_engine('transit', path=mount)
    # No create on encrypt; no key administration, export, backup or token minting.
    policy = '\n'.join(f'path "{mount}/{operation}/*" {{ capabilities = ["{capability}"] }}'
                       for operation, capability in [('keys', 'read'), ('encrypt', 'update'), ('decrypt', 'update')])
    admin.sys.create_or_update_policy(mount, policy)
    token = admin.auth.token.create(policies=[mount], no_default_policy=True, ttl='1h')['auth']['client_token']
    runtime = hvac.Client(url=config['endpoint'], verify=config['ca_cert'], token=token,
                          allow_redirects=False, timeout=5)
    yield SimpleNamespace(admin=admin, runtime=runtime, config=config, mount=mount, token=token, hvac=hvac)
    runtime.session.close()
    admin.session.close()


@pytest.fixture
def live(service):
    name = 'root-' + uuid4().hex
    service.admin.write(f'{service.mount}/keys/{name}', type='aes256-gcm96')
    def make(**changes):
        args = dict(endpoint=service.config['endpoint'], ca_cert=service.config['ca_cert'],
                    token=lambda: service.token, provider_id=UUID(int=908),
                    mount=service.mount, key_name=name, key_version=1, timeout=3)
        args.update(changes)
        return OpenBaoTransitKeyProvider(**args)
    return SimpleNamespace(provider=make(), make=make, name=name, service=service)


def workload_credentials(live, **role_changes):
    s = live.service
    mount = 'cryptalis-approle-' + uuid4().hex
    s.admin.sys.enable_auth_method('approle', path=mount)
    policy = '\n'.join(f'path "{s.mount}/{operation}/{live.name}" {{ capabilities = ["{capability}"] }}'
        for operation, capability in [('keys', 'read'), ('encrypt', 'update'), ('decrypt', 'update')])
    policy += f'\npath "auth/{mount}/role/application" {{ capabilities = ["read"] }}'
    s.admin.sys.create_or_update_policy(mount, policy)
    settings = dict(bind_secret_id=True, secret_id_ttl='10m', secret_id_num_uses=0,
        token_ttl='60s', token_max_ttl='60s', token_explicit_max_ttl='60s',
        token_policies=[mount], token_no_default_policy=True, token_type='service', token_num_uses=0)
    settings.update(role_changes)
    s.admin.auth.approle.create_or_update_approle('application', mount_point=mount, **settings)
    role_id = s.admin.auth.approle.read_role_id('application', mount_point=mount)['data']['role_id']
    def issue():
        return s.admin.auth.approle.generate_secret_id('application', mount_point=mount)['data']['secret_id']
    current = [issue()]
    def make(**changes):
        config = dict(endpoint=s.config['endpoint'], ca_cert=s.config['ca_cert'], role_name='application', role_id=role_id,
            secret_id=lambda: current[0], policies=(mount,), mount=mount, max_token_ttl=60, timeout=3)
        config.update(changes)
        return OpenBaoAppRoleToken(**config)
    return SimpleNamespace(token=make(), make=make, current=current, issue=issue, mount=mount,
                           role_id=role_id, policy=policy)


def audit_records(path):
    path = Path(path)
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
    return [json.loads(line) for line in path.read_text().splitlines()]


def audit_pair(records, path):
    requests = [r for r in records if r['type'] == 'request' and r['request']['path'] == path]
    assert len(requests) == 1, 'ExpectedOneAuditedRequest'
    request, = requests
    responses = [r for r in records if r['type'] == 'response' and r['request']['id'] == request['request']['id']]
    assert len(responses) == 1, 'ExpectedOneMatchingAuditedResponse'
    return request, responses[0]


def test_native_audit_correlates_approle_and_transit_with_verified_hmac(live):
    s = live.service
    if not s.config.get('audit_file'):
        pytest.skip('native audit inspection requires the isolated qualification harness')
    device = s.config['audit_device']
    entry = s.admin.sys.list_enabled_audit_devices()['data'][device + '/']
    assert entry['type'] == 'file'
    assert all(entry['options'][key] == value for key, value in
        [('log_raw', 'false'), ('hmac_accessor', 'true'), ('mode', '0600'), ('format', 'json')])
    workload = workload_credentials(live)
    token = workload.token()
    accessor = s.admin.auth.token.lookup(token)['data']['accessor']
    p = live.make(token=lambda: token)
    wrapper = p.wrap(ROOT, CONTEXT)
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    records = audit_records(s.config['audit_file'])
    login, logged_in = audit_pair(records, f'auth/{workload.mount}/login')
    encrypt, encrypted = audit_pair(records, f'{s.mount}/encrypt/{live.name}')
    decrypt, decrypted = audit_pair(records, f'{s.mount}/decrypt/{live.name}')
    # This native oracle proves the recorded fields correspond to supplied values;
    # merely observing an absent plaintext or an hmac-looking prefix is insufficient.
    def hashed(value):
        return s.admin.sys.calculate_hash(device, value)['data']['hash']
    plaintext = base64.b64encode(ROOT).decode('ascii')
    aad = p._aad(CONTEXT)
    ciphertext = wrapper.sealed.decode('ascii')
    assert login['request']['data']['role_id'] == hashed(workload.role_id)
    assert login['request']['data']['secret_id'] == hashed(workload.current[0])
    assert logged_in['response']['auth']['client_token'] == hashed(token)
    assert logged_in['response']['auth']['accessor'] == hashed(accessor)
    assert encrypt['request']['client_token'] == hashed(token)
    assert encrypt['request']['client_token_accessor'] == hashed(accessor)
    assert encrypt['request']['data']['plaintext'] == hashed(plaintext)
    assert encrypt['request']['data']['associated_data'] == hashed(aad)
    assert encrypted['response']['data']['ciphertext'] == hashed(ciphertext)
    assert decrypt['request']['data']['ciphertext'] == hashed(ciphertext)
    assert decrypt['request']['data']['associated_data'] == hashed(aad)
    assert decrypted['response']['data']['plaintext'] == hashed(plaintext)
    # Paths, operations, policies, time, numeric versions and durations are visible.
    assert encrypt['request']['operation'] == 'update' and encrypt['time']
    assert encrypt['request']['data']['key_version'] == 1
    assert logged_in['response']['auth']['policies'] == [workload.mount]
    assert logged_in['response']['auth']['token_ttl'] == 60
    raw = Path(s.config['audit_file']).read_text()
    if any(secret in raw for secret in (plaintext, aad, ciphertext, token, accessor,
                                        workload.role_id, workload.current[0])):
        raise AssertionError('AuditCleartextLeak')
    runtime = s.hvac.Client(url=s.config['endpoint'], verify=s.config['ca_cert'], token=token,
        allow_redirects=False, timeout=3)
    try:
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.sys.list_enabled_audit_devices()
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.sys.calculate_hash(device, plaintext)
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.sys.disable_audit_device(device)
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.sys.enable_audit_device('file', path='forbidden-audit', options={'file_path':'discard'})
    finally:
        runtime.session.close()
    assert device + '/' in s.admin.sys.list_enabled_audit_devices()['data']


def test_native_audit_reopen_preserves_old_records_and_hash_identity(live):
    s = live.service
    if not s.config.get('audit_file') or not s.config.get('isolated_container'):
        pytest.skip('native audit reopen requires the isolated qualification harness')
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    try:
        from openbao_qualification import docker
    finally:
        sys.path.pop(0)
    device, path = s.config['audit_device'], Path(s.config['audit_file'])
    wrapper = live.provider.wrap(ROOT, CONTEXT)
    ciphertext = wrapper.sealed.decode('ascii')
    expected = s.admin.sys.calculate_hash(device, ciphertext)['data']['hash']
    rotated = path.with_name('audit-before-reopen.jsonl')
    assert not rotated.exists()
    path.rename(rotated)  # Preserve the old file; never delete or truncate audit history.
    docker('kill', '--signal=HUP', s.config['isolated_container'])
    deadline = time.monotonic() + 10
    while not path.exists():
        assert time.monotonic() < deadline, 'AuditReopenUnavailable'
        time.sleep(0.05)
    before = rotated.read_bytes()
    assert live.provider.unwrap(wrapper, CONTEXT) == ROOT
    request, response = audit_pair(audit_records(path), f'{s.mount}/decrypt/{live.name}')
    assert request['request']['data']['ciphertext'] == expected
    assert response['response']['data']['plaintext'] == s.admin.sys.calculate_hash(
        device, base64.b64encode(ROOT).decode('ascii'))['data']['hash']
    assert s.admin.sys.calculate_hash(device, ciphertext)['data']['hash'] == expected
    assert rotated.read_bytes() == before
    audit_pair(audit_records(rotated), f'{s.mount}/encrypt/{live.name}')


def test_real_approle_uses_only_supplied_credentials_and_narrow_policy(live, monkeypatch):
    s = live.service
    workload = workload_credentials(live)
    monkeypatch.setattr(s.hvac.utils, 'get_token_from_env',
                        lambda: pytest.fail('AppRole used ambient token discovery'))
    p = live.make(token=workload.token)
    wrapper = p.wrap(ROOT, CONTEXT)
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    assert asyncio.run(p.unwrap_async(wrapper, CONTEXT)) == ROOT
    runtime = s.hvac.Client(url=s.config['endpoint'], verify=s.config['ca_cert'],
        token=workload.token(), allow_redirects=False, timeout=3)
    try:
        for path, values in [(f'{s.mount}/keys/forbidden', {'type': 'aes256-gcm96'}),
                             (f'{s.mount}/keys/{live.name}/rotate', {})]:
            with pytest.raises(s.hvac.exceptions.Forbidden): runtime.write(path, **values)
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.read(f'{s.mount}/export/encryption-key/{live.name}')
        with pytest.raises(s.hvac.exceptions.Forbidden):
            runtime.auth.approle.generate_secret_id('application', mount_point=workload.mount)
    finally: runtime.session.close()


def test_real_single_use_secret_refuses_replay_and_current_callback_recovers(live):
    from cryptalis.crypto import ProviderAuthenticationUnavailable
    workload = workload_credentials(live, secret_id_num_uses=1)
    p = live.make(token=workload.token)
    wrapper = p.wrap(ROOT, CONTEXT)
    with pytest.raises(ProviderAuthenticationUnavailable) as error: p.unwrap(wrapper, CONTEXT)
    assert error.value.effects == 'UNKNOWN' and error.value.retryable is False
    workload.current[0] = workload.issue()
    assert p.unwrap(wrapper, CONTEXT) == ROOT


@pytest.mark.parametrize('fault', ['wrong_role', 'wrong_secret', 'extra_policy', 'long_lease',
                                 'unbound_secret', 'unbounded_secret', 'unreadable_role'])
def test_real_approle_wrong_authority_and_policy_drift_refuse(live, fault):
    from cryptalis.crypto import ProviderAuthenticationUnavailable
    workload = workload_credentials(live)
    good = live.make(token=workload.token)
    wrapper = good.wrap(ROOT, CONTEXT)
    if fault == 'wrong_role': candidate = workload.make(role_id=str(uuid4()))
    elif fault == 'wrong_secret': candidate = workload.make(secret_id=lambda: str(uuid4()))
    elif fault == 'extra_policy': candidate = workload.make(policies=('different-runtime-policy',))
    elif fault == 'long_lease': candidate = workload.make(max_token_ttl=1)
    else:
        if fault == 'unreadable_role':
            live.service.admin.sys.create_or_update_policy(workload.mount,
                '\n'.join(workload.policy.splitlines()[:-1]))
        else:
            live.service.admin.auth.approle.create_or_update_approle('application',
                mount_point=workload.mount,
                **({'bind_secret_id': False, 'secret_id_bound_cidrs': ['0.0.0.0/0']} if fault == 'unbound_secret'
                   else {'secret_id_ttl': '0s'}))
        native = live.service.hvac.Client(url=live.service.config['endpoint'], token='',
            verify=live.service.config['ca_cert'], allow_redirects=False, timeout=3)
        try:
            observed = native.auth.approle.login(role_id=workload.role_id,
                secret_id=str(uuid4()) if fault == 'unbound_secret' else workload.current[0],
                mount_point=workload.mount, use_token=False)
            assert observed['auth']['token_policies'] == [workload.mount]
        finally: native.session.close()
        candidate = workload.token
    with pytest.raises(ProviderAuthenticationUnavailable) as error:
        live.make(token=candidate).unwrap(wrapper, CONTEXT)
    assert error.value.effects == 'UNKNOWN'
    if fault in ('unbound_secret', 'unbounded_secret', 'unreadable_role'):
        replacement = workload_credentials(live)
        good = live.make(token=replacement.token)
    assert good.unwrap(wrapper, CONTEXT) == ROOT


def test_real_transit_randomized_wrapping_and_cf1_sync_async(live):
    p = live.provider
    one, two = p.wrap(ROOT, CONTEXT), p.wrap(ROOT, CONTEXT)
    assert one.sealed != two.sealed
    assert p.unwrap(one, CONTEXT) == ROOT
    assert asyncio.run(p.unwrap_async(two, CONTEXT)) == ROOT
    keys = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (one,), 1), {p.provider_id: p})
    field, record = descriptor(), UUID(int=5)
    frame = seal_text('café 雪', field, CONTEXT.tenant_id, record, keys.prepare())
    assert open_text(frame, field, CONTEXT.tenant_id, record, asyncio.run(keys.prepare_async())) == 'café 雪'


def test_concurrent_operations_share_no_sdk_session_or_root_state(live):
    p = live.provider
    contexts = [replace(CONTEXT, root_id=uuid4()) for _ in range(8)]
    def round_trip(context):
        wrapper = create_root(p, context)
        return wrapper, p.unwrap(wrapper, context)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(round_trip, contexts))
    assert len({root for _, root in results}) == len(contexts)
    for (wrapper, _), context in zip(results, contexts[1:] + contexts[:1]):
        with pytest.raises(KeyUnavailable):
            p.unwrap(replace(wrapper, context=context), context)


@pytest.mark.parametrize('field,value', [
    ('domain_id', UUID(int=21)), ('tenant_id', UUID(int=22)),
    ('purpose', 'search'), ('root_id', UUID(int=23)), ('generation', 2),
])
def test_service_rejects_each_forged_authenticated_context(live, field, value):
    wrapper = live.provider.wrap(ROOT, CONTEXT)
    changed = replace(CONTEXT, **{field: value})
    with pytest.raises(KeyUnavailable):
        live.provider.unwrap(WrappedRoot(wrapper.provider_id, changed, wrapper.sealed), changed)


def test_wrong_provider_key_ciphertext_and_ca_fail_closed(live):
    p = live.provider
    wrapper = p.wrap(ROOT, CONTEXT)
    other = live.make(provider_id=uuid4())
    with pytest.raises(KeyUnavailable):
        other.unwrap(replace(wrapper, provider_id=other.provider_id), CONTEXT)
    service = live.service
    service.admin.write(f'{service.mount}/keys/other', type='aes256-gcm96')
    with pytest.raises(KeyUnavailable):
        live.make(key_name='other').unwrap(wrapper, CONTEXT)
    changed = wrapper.sealed[:-5] + (b'A' if wrapper.sealed[-5:-4] != b'A' else b'B') + wrapper.sealed[-4:]
    with pytest.raises(KeyUnavailable):
        p.unwrap(replace(wrapper, sealed=changed), CONTEXT)
    with pytest.raises(KeyUnavailable):
        live.make(ca_cert=None).unwrap(wrapper, CONTEXT)


def test_runtime_policy_cannot_create_export_or_administer_keys(live):
    s = live.service
    for path, values in [(f'{s.mount}/keys/forbidden', {'type':'aes256-gcm96'}),
                         (f'{s.mount}/keys/{live.name}/config', {'exportable':True}),
                         (f'{s.mount}/keys/{live.name}/rotate', {}),
                         (f'{s.mount}/encrypt/nonexistent', {'plaintext':'eA=='})]:
        with pytest.raises(s.hvac.exceptions.Forbidden):
            s.runtime.write(path, **values)
    with pytest.raises(s.hvac.exceptions.Forbidden):
        s.runtime.read(f'{s.mount}/export/encryption-key/{live.name}')
    with pytest.raises(s.hvac.exceptions.Forbidden):
        s.runtime.sys.take_raft_snapshot()
    with pytest.raises(s.hvac.exceptions.Forbidden):
        s.runtime.sys.force_restore_raft_snapshot(b'public invalid snapshot')
    with pytest.raises(KeyUnavailable):
        live.make(key_name='missing').wrap(ROOT, CONTEXT)


def test_rotation_rewrap_and_version_revocation_preserve_root(live):
    p, s = live.provider, live.service
    wrapper = p.wrap(ROOT, CONTEXT)
    s.admin.write(f'{s.mount}/keys/{live.name}/rotate')
    successor = live.make(provider_id=uuid4(), key_version=2)
    rewrapped = p.rewrap(wrapper, successor, CONTEXT)
    assert rewrapped.sealed.startswith(b'vault:v2:')
    assert successor.unwrap(rewrapped, CONTEXT) == ROOT
    # Raising encryption minimum must not reject historical decryption.
    s.admin.write(f'{s.mount}/keys/{live.name}/config', min_encryption_version=2)
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    with pytest.raises(KeyUnavailable):
        p.wrap(ROOT, CONTEXT)
    s.admin.write(f'{s.mount}/keys/{live.name}/config', min_decryption_version=2)
    with pytest.raises(KeyUnavailable):
        p.unwrap(wrapper, CONTEXT)
    assert successor.unwrap(rewrapped, CONTEXT) == ROOT
    local = DevelopmentKeyProvider()
    assert local.unwrap(successor.rewrap(rewrapped, local, CONTEXT), CONTEXT) == ROOT


def test_token_revocation_refuses_cold_access_and_renewal_callback_recovers(live):
    s = live.service
    token = s.admin.auth.token.create(policies=[s.mount], no_default_policy=True, ttl='5m')['auth']['client_token']
    current = [token]
    p = live.make(token=lambda: current[0])
    wrapper = p.wrap(ROOT, CONTEXT)
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    s.admin.auth.token.revoke(token)
    with pytest.raises(KeyUnavailable):
        p.unwrap(wrapper, CONTEXT)
    current[0] = s.token
    assert p.unwrap(wrapper, CONTEXT) == ROOT


def test_doctor_observes_revocation_despite_warm_cache_and_cli_recovers(live, tmp_path):
    from cryptalis.doctor import check_keys
    from test_doctor_provider import invoke
    s = live.service
    token = s.admin.auth.token.create(policies=[s.mount], no_default_policy=True, ttl='5m')['auth']['client_token']
    current = [token]
    p = live.make(token=lambda: current[0])
    wrapper = p.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1), {p.provider_id: p})
    ring.prepare()
    cache = dict(ring._cache)
    assert check_keys((ring,))['checks']['cold_key_preparation'] == 'PASS'
    configuration = tmp_path / 'private-provider.json'
    values = dict(endpoint=s.config['endpoint'], ca_cert=s.config['ca_cert'], token=token,
                  mount=s.mount, key_name=live.name, sealed=wrapper.sealed.decode('ascii'))
    configuration.write_text(json.dumps(values))
    configuration.chmod(0o600)
    body = f'''
import json
from pathlib import Path
from uuid import UUID
from cryptalis.crypto import KeyContext, KeyPolicy, Keyring, WrappedRoot
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider
def context():
    config = json.loads(Path({str(configuration)!r}).read_text())
    token, sealed = config.pop('token'), config.pop('sealed')
    p = OpenBaoTransitKeyProvider(**config, token=lambda: token, provider_id=UUID(int=908), key_version=1)
    c = KeyContext(UUID(int=1), UUID(int=4), 'payload', UUID(int=907), 1)
    w = WrappedRoot(p.provider_id, c, sealed.encode('ascii'))
    return (Keyring(KeyPolicy(c.domain_id, c.tenant_id, (w,), 1), {{p.provider_id: p}}),)
'''
    assert invoke(tmp_path, body).returncode == 0
    s.admin.auth.token.revoke(token)
    assert ring.prepare()  # Still inside the application's original bounded lease.
    assert check_keys((ring,))['checks']['cold_key_preparation'] == 'FAIL'
    refused = invoke(tmp_path, body)
    assert refused.returncode == 4 and refused.stdout == ''
    assert json.loads(refused.stderr)['error']['checks']['cold_key_preparation'] == 'FAIL'
    assert token not in refused.stderr and wrapper.sealed.decode('ascii') not in refused.stderr
    current[0] = s.token
    values['token'] = s.token
    configuration.write_text(json.dumps(values))
    assert invoke(tmp_path, body).returncode == 0
    assert check_keys((ring,))['checks']['cold_key_preparation'] == 'PASS'
    assert ring._cache == cache


def test_cancellation_does_not_publish_late_keys(live):
    p = live.provider
    wrapper = create_root(p, CONTEXT)
    started, release = threading.Event(), threading.Event()
    def token():
        started.set()
        assert release.wait(10)
        return live.service.token
    delayed = live.make(token=token)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1), {p.provider_id: delayed})
    async def cancel():
        task = asyncio.create_task(ring.prepare_async())
        try:
            assert await asyncio.to_thread(started.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
    asyncio.run(cancel())  # Waits for the worker's actual service request to finish.
    assert not ring._cache


def test_approle_doctor_and_cli_preserve_uncertain_native_issuance(live, tmp_path):
    from cryptalis.doctor import check_keys
    from test_doctor_provider import invoke
    workload = workload_credentials(live)
    authentication = [workload.token]
    p = live.make(token=lambda: authentication[0]())
    wrapper = create_root(p, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1), {p.provider_id: p})
    ring.prepare()
    original_cache = dict(ring._cache)
    # Native login succeeds, but its 60s lease exceeds this explicitly lower
    # admission ceiling. The library cannot claim no native token was issued.
    authentication[0] = workload.make(max_token_ttl=1)
    report = check_keys((ring,))
    assert report['effects'] == 'UNKNOWN' and report['status'] == 'FAIL'
    assert report['issues'][0]['code'] == 'Provider.AuthenticationUnavailable'
    assert report['issues'][0]['retryable'] is False
    assert ring._cache == original_cache and ring.prepare()
    configuration = tmp_path / 'private-approle.json'
    config = dict(endpoint=live.service.config['endpoint'], ca_cert=live.service.config['ca_cert'],
        mount=workload.mount, role_name='application', role_id=workload.role_id,
        secret_id=workload.current[0], policies=[workload.mount], max_token_ttl=1,
        transit_mount=live.service.mount, key_name=live.name, sealed=wrapper.sealed.decode('ascii'))
    configuration.write_text(json.dumps(config)); configuration.chmod(0o600)
    body = f'''
import json
from pathlib import Path
from uuid import UUID
from cryptalis.crypto import KeyContext, KeyPolicy, Keyring, WrappedRoot
from cryptalis.crypto.openbao import OpenBaoAppRoleToken, OpenBaoTransitKeyProvider
def context():
    config = json.loads(Path({str(configuration)!r}).read_text())
    secret, sealed = config.pop('secret_id'), config.pop('sealed')
    mount, name = config.pop('transit_mount'), config.pop('key_name')
    config['policies'] = tuple(config['policies'])
    auth = OpenBaoAppRoleToken(**config, secret_id=lambda: secret)
    p = OpenBaoTransitKeyProvider(endpoint=config['endpoint'], ca_cert=config['ca_cert'],
        token=auth, mount=mount, key_name=name, key_version=1, provider_id=UUID(int=908))
    c = KeyContext(UUID(int=1), UUID(int=4), 'payload', UUID(int=907), 1)
    w = WrappedRoot(p.provider_id, c, sealed.encode('ascii'))
    return (Keyring(KeyPolicy(c.domain_id, c.tenant_id, (w,), 1), {{p.provider_id: p}}),)
'''
    refused = invoke(tmp_path, body)
    assert refused.returncode == 4 and refused.stdout == ''
    error = json.loads(refused.stderr)['error']
    assert error['code'] == 'KeyAccessUnavailable' and error['effects'] == 'UNKNOWN'
    assert error['issues'][0]['code'] == 'Provider.AuthenticationUnavailable'
    assert error['retryable'] is error['issues'][0]['retryable'] is False
    assert workload.current[0] not in refused.stderr and config['sealed'] not in refused.stderr
    config['max_token_ttl'] = 60
    configuration.write_text(json.dumps(config))
    recovered = invoke(tmp_path, body)
    assert recovered.returncode == 0 and recovered.stderr == ''
    report = json.loads(recovered.stdout)
    assert report['checks']['cold_key_preparation'] == 'PASS' and report['status'] == 'UNKNOWN'
    authentication[0] = workload.token
    assert check_keys((ring,))['checks']['cold_key_preparation'] == 'PASS'
    assert ring._cache == original_cache


def test_isolated_service_outage_expiry_and_sealed_restart_recovery(live):
    s, p = live.service, live.provider
    container = s.config.get('isolated_container')
    if not container:
        pytest.skip('service restart requires the isolated qualification harness')
    # Only the harness-created container, never an arbitrary configured service.
    import re
    import requests
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    try:
        from openbao_qualification import docker, wait_active
    finally:
        sys.path.pop(0)
    assert re.fullmatch(r'cryptalis-bao-[0-9a-f]{32}', container)
    wrapper = p.wrap(ROOT, CONTEXT)
    # The native container stop has a 10s grace period. Use a longer explicit
    # lease so that shutdown time cannot itself consume the intended warm case.
    # Still wait for actual expiry and prove both held and fresh access refuse.
    lease_seconds = 30
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1),
                   {p.provider_id: p}, max_age=lease_seconds)
    field, record = descriptor(), UUID(int=5)
    frame = seal_text('outage value', field, CONTEXT.tenant_id, record, ring.prepare())
    prepared_at = time.monotonic()
    docker('stop', '--time', '10', container)
    try:
        with pytest.raises(KeyUnavailable):
            p.unwrap(wrapper, CONTEXT)
        # Bounded cache availability is explicit; no remote retry or plaintext fallback.
        prepared = ring.prepare()
        assert open_text(frame, field, CONTEXT.tenant_id, record, prepared) == 'outage value'
        time.sleep(max(0, prepared_at + lease_seconds - time.monotonic()) + 0.1)
        with pytest.raises(KeyUnavailable):
            open_text(frame, field, CONTEXT.tenant_id, record, prepared)
        with pytest.raises(KeyUnavailable):
            ring.prepare()
    finally:
        docker('start', container)
        deadline = time.monotonic() + 15
        while True:
            try:
                assert s.admin.sys.is_sealed()
                break
            except s.hvac.exceptions.VaultError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
            except (requests.ConnectionError, requests.Timeout):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        # A sealed server refuses cold decryption; unlock only this retained test service.
        try:
            with pytest.raises(KeyUnavailable):
                p.unwrap(wrapper, CONTEXT)
        finally:
            initialization = private_json(s.config['admin_token_file'])
            s.admin.sys.submit_unseal_key(initialization['keys'][0])
            wait_active(s.admin)
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    assert open_text(frame, field, CONTEXT.tenant_id, record, ring.prepare()) == 'outage value'


def test_independent_snapshot_restores_cold_roots_with_source_fenced(live):
    """Restore only into newly initialized empty test storage; retain all files."""
    import re
    import sys
    from cryptalis.doctor import check_keys
    s, p = live.service, live.provider
    source_container = s.config.get('isolated_container')
    if not source_container:
        pytest.skip('snapshot recovery requires the isolated qualification harness')
    assert re.fullmatch(r'cryptalis-bao-[0-9a-f]{32}', source_container)
    workload = workload_credentials(live)
    p = live.make(token=workload.token)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    try:
        from openbao_qualification import docker, service_files, start_container, wait_available, wait_active, write_private, retire_container
    finally:
        sys.path.pop(0)
    # Keep snapshots and bootstrap secrets outside pytest's temporary cleanup.
    workdir = Path(s.config['admin_token_file']).parent / 'snapshot-recovery'
    workdir.mkdir(mode=0o700, exist_ok=False)
    target_container = 'cryptalis-bao-' + uuid4().hex
    wrapper = create_root(p, CONTEXT)
    policy = KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1)
    field, record = descriptor(), UUID(int=5)
    frame = seal_text('independent provider recovery', field, CONTEXT.tenant_id, record,
                      Keyring(policy, {p.provider_id: p}).prepare())
    audit_hash = s.admin.sys.calculate_hash(s.config['audit_device'], wrapper.sealed.decode('ascii'))['data']['hash']
    with s.admin.sys.take_raft_snapshot() as response:
        chunks, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            assert size <= 16 * 1024 * 1024
            chunks.append(chunk)
        snapshot = b''.join(chunks)
    assert snapshot
    write_private(workdir / 'source.snap', snapshot)
    # This key must remain absent after point-in-time recovery.
    s.admin.write(f'{s.mount}/keys/after-snapshot', type='aes256-gcm96')
    service_files(workdir)
    created = source_stopped = target_stopped = False
    client = None
    try:
        endpoint = start_container(workdir, target_container)
        created = True
        write_private(workdir / 'container-name', target_container.encode())
        assert endpoint != s.config['endpoint']
        client = s.hvac.Client(url=endpoint, verify=str(workdir / 'ca.pem'), allow_redirects=False, timeout=30)
        assert not wait_available(client)
        initialized = client.sys.initialize(secret_shares=1, secret_threshold=1)
        write_private(workdir / 'bootstrap-initialization.json', json.dumps(initialized).encode())
        client.sys.submit_unseal_key(initialized['keys'][0])
        wait_active(client)
        client.token = initialized['root_token']
        assert s.mount + '/' not in client.sys.list_mounted_secrets_engines()
        recovered = live.make(endpoint=endpoint, ca_cert=str(workdir / 'ca.pem'),
            token=workload.make(endpoint=endpoint, ca_cert=str(workdir / 'ca.pem')))
        with pytest.raises(KeyUnavailable):
            recovered.unwrap(wrapper, CONTEXT)
        # Default restore refuses a different seal; malformed force input also refuses.
        with pytest.raises(s.hvac.exceptions.VaultError):
            client.sys.restore_raft_snapshot(snapshot)
        with pytest.raises(s.hvac.exceptions.VaultError):
            client.sys.force_restore_raft_snapshot(b'public invalid snapshot')
        assert not client.sys.is_sealed()
        docker('stop', '--time', '10', source_container)
        source_stopped = True
        assert docker('inspect', '--format', '{{.State.Running}}', source_container) == 'false'
        source_audit = Path(s.config['audit_file']).read_bytes()
        with pytest.raises(KeyUnavailable):
            p.unwrap(wrapper, CONTEXT)
        # Force is confined to this proven-empty disposable target, never an existing service.
        client.sys.force_restore_raft_snapshot(snapshot)
        deadline = time.monotonic() + 30
        while not client.sys.is_sealed():
            assert time.monotonic() < deadline, 'restored service did not seal'
            time.sleep(0.1)
        with pytest.raises(KeyUnavailable):
            recovered.unwrap(wrapper, CONTEXT)
        source_initialization = private_json(s.config['admin_token_file'])
        client.sys.submit_unseal_key(source_initialization['keys'][0])
        wait_active(client)
        client.token = source_initialization['root_token']
        assert client.read(f'{s.mount}/keys/after-snapshot') is None
        # The original auth endpoint is still fenced; it cannot silently supply
        # credentials for the independently restored authority.
        with pytest.raises(KeyUnavailable):
            live.make(endpoint=endpoint, ca_cert=str(workdir / 'ca.pem'),
                      token=workload.token).unwrap(wrapper, CONTEXT)
        cold = Keyring(policy, {p.provider_id: recovered})
        assert check_keys((cold,))['checks']['cold_key_preparation'] == 'PASS'
        assert not cold._cache
        assert open_text(frame, field, CONTEXT.tenant_id, record, cold.prepare()) == 'independent provider recovery'
        assert docker('inspect', '--format', '{{.State.Running}}', source_container) == 'false'
        assert Path(s.config['audit_file']).read_bytes() == source_audit
        assert client.sys.calculate_hash(s.config['audit_device'], wrapper.sealed.decode('ascii'))['data']['hash'] == audit_hash
        target_records = audit_records(workdir / 'audit.jsonl')
        requests = [r for r in target_records if r['type'] == 'request'
                    and r['request']['path'] == f'{s.mount}/decrypt/{live.name}']
        assert len(requests) == 2  # Cold Doctor and the application's fresh preparation.
        for request in requests:
            assert request['request']['data']['ciphertext'] == audit_hash
            assert len([r for r in target_records if r['type'] == 'response'
                        and r['request']['id'] == request['request']['id']]) == 1
    finally:
        try:
            if client is not None:
                client.session.close()
        finally:
            if created:
                docker('stop', '--time', '15', target_container)
                import hashlib
                retained = {p: hashlib.sha256(p.read_bytes()).digest()
                            for p in workdir.rglob('*') if p.is_file()}
                retire_container(workdir, target_container)
                assert docker('ps', '-a', '--filter', 'name=' + target_container, '--format', '{{.Names}}') == ''
                assert all(p.is_file() and hashlib.sha256(p.read_bytes()).digest() == digest
                           for p, digest in retained.items())
                assert (workdir / 'container.log').stat().st_mode & 0o777 == 0o600
                assert (workdir / 'container.log').stat().st_size > 0
                target_stopped = True
            # Never restart source authority if target shutdown failed.
            if source_stopped and target_stopped:
                docker('start', source_container)
                assert wait_available(s.admin)
                s.admin.sys.submit_unseal_key(private_json(s.config['admin_token_file'])['keys'][0])
                wait_active(s.admin)
    assert p.unwrap(wrapper, CONTEXT)


@pytest.mark.parametrize('labelled', [False, True])
def test_real_provider_protect_search_edit_and_verified_plaintext_exit(live, monkeypatch, labelled):
    from sqlalchemy import and_, not_
    live.provider = live.make(token=workload_credentials(live).token)
    import test_migration as fixture
    import test_deprotection as reverse
    from cryptalis.sqlalchemy import attach
    from cryptalis import deprotection

    p, policies = live.provider, {}
    def keys(tenant):
        if tenant not in policies:
            wrappers = tuple(create_root(p, KeyContext(fixture.DOMAIN, tenant, purpose, uuid4(), 1))
                             for purpose in ('payload', 'search'))
            policies[tenant] = KeyPolicy(fixture.DOMAIN, tenant, wrappers, 1, 1)
        return Keyring(policies[tenant], {p.provider_id: p})
    monkeypatch.setattr(fixture, 'keys', keys)
    monkeypatch.setattr(reverse, 'keys', keys)
    with fixture.application() as app:
        fixture.run(app)
        fixture.publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=fixture.TENANT) as session:
            assert list(session.scalars(select(app.Customer.id).where(app.Customer.name.in_(['exact', 'é']))))
            row = session.get(app.Customer, UUID(int=101))
            row.name = 'live provider edit'
            session.commit()
            assert session.scalar(select(app.Customer.id).where(app.Customer.name == 'live provider edit')) == row.id
            returned = session.execute(update(app.Customer).where(app.Customer.id == row.id,
                app.Customer.tenant_id == fixture.TENANT).values(name='live provider returning').returning(
                    app.Customer.name.label('display_name') if labelled else app.Customer.name),
                execution_options={'synchronize_session': False})
            assert returned.scalar_one() == 'live provider returning'
            session.commit()
            deleted = session.execute(delete(app.Customer).where(app.Customer.id == UUID(int=102),
                app.Customer.tenant_id == fixture.TENANT).returning(app.Customer.name.label('display_name') if labelled else app.Customer.name),
                execution_options={'synchronize_session': False})
            assert deleted.scalar_one() == app.source[UUID(int=102)][1]
            session.commit()
            inserted = session.execute(insert(app.Customer).returning(
                app.Customer.name.label('display_name') if labelled else app.Customer.name),
                [dict(id=UUID(int=10000), tenant_id=fixture.TENANT, name='live provider insert')])
            assert inserted.scalar_one() == 'live provider insert'
            session.commit()
            counted = session.execute(update(app.Customer).where(app.Customer.id == UUID(int=10000),
                app.Customer.tenant_id == fixture.TENANT).values(name='live provider counted update'),
                execution_options={'synchronize_session': False})
            assert counted.rowcount == 1 and counted.returns_rows is False
            session.commit()
            negated = not_(and_(app.Customer.name != 'live provider counted update',
                               app.Customer.name.is_not(None)))
            assert set(session.scalars(select(app.Customer.id).where(negated))) == {
                UUID(int=100), UUID(int=10000)}
        expected = dict(app.source)
        expected[UUID(int=101)] = (fixture.TENANT, 'live provider returning')
        expected[UUID(int=10000)] = (fixture.TENANT, 'live provider counted update')
        del expected[UUID(int=102)]
        bodies = fixture.frames(app, True)
        assert bodies[UUID(int=100)] is None
        assert all(value is None or b'live provider returning' not in value for value in bodies.values())
        plan = reverse.proposal(app)
        assert reverse.reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        assert reverse.native_rows(app) == expected
        consent, pin = reverse.consent(plan, 'PLAINTEXT_ACTIVATING')
        assert deprotection.apply(plan, app.owner, keys=keys, pin=pin, approval=app.approval,
                                 consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = deprotection.RemovalApproval(plan.target_id, plan.operation_id, plan.digest,
                    'local native application verification', 'synthetic fixture has no retained backups', True)
        assert deprotection.remove(plan, app.owner, pin=replace(pin, phase='REMOVING'),
                    approval=app.approval, removal=removal, consent=consent).phase == 'REMOVED'
        assert reverse.native_rows(app) == expected


@pytest.mark.parametrize('search', [True, False])
def test_real_approle_modification_search_and_current_value_removal(live, monkeypatch, search):
    import test_migration as fixture
    from test_modification_storage import storage_change
    from test_application_modification import configured_change
    from test_deprotection import app_pin, native_rows
    from test_payload_rotation_execution import operation_pin
    from test_search_retained_readers import remove_current

    provider, policies = live.make(token=workload_credentials(live).token), {}
    def resolve(tenant):
        if tenant not in policies:
            wrappers = tuple(create_root(provider, KeyContext(fixture.DOMAIN, tenant, purpose, uuid4(), 1))
                             for purpose in ('payload', 'search'))
            policies[tenant] = KeyPolicy(fixture.DOMAIN, tenant, wrappers, 1, 1)
        return Keyring(policies[tenant], {provider.provider_id: provider})
    monkeypatch.setattr(fixture, 'keys', resolve)
    with fixture.application(unique=False, queries=[] if search else ['equality']) as app:
        configured = configured_change(app) if search else storage_change(app)
        fixture.run(app); fixture.publish(app)
        proposal = configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=resolve,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=2)
        deployment = proposal, operation_pin(proposal)
        assert configured.prepare_modification(app.owner, deployment=deployment, keys=resolve,
            approval=app.approval).phase == 'BACKFILLED'
        successor = configured.seal_modification(app.owner, deployment=deployment, keys=resolve,
            approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        configured.switch_modification(app.owner, proposal=proposal,
            deployment=(successor, app_pin(successor, 'PREPARED')), keys=resolve, approval=app.approval)
        configured.apply(app.owner, deployment=(successor, app_pin(successor, 'ACTIVATING')),
            keys=resolve, approval=app.approval, until='ACTIVE')
        app.plan, app.pin = successor, app_pin(successor, 'ACTIVE')
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=resolve)
        with factory(tenant_id=fixture.TENANT) as session:
            assert session.get(app.Customer, UUID(int=102)).name == '雪😀'
            if search:
                assert session.scalar(select(app.Customer.id).where(app.Customer.name == '雪😀')) == UUID(int=102)
            session.get(app.Customer, UUID(int=101)).name = 'latest provider-backed profile edit'
            session.commit()
        remove_current(app, resolve)
        expected = dict(app.source)
        expected[UUID(int=101)] = fixture.TENANT, 'latest provider-backed profile edit'
        assert native_rows(app) == expected


def test_real_approle_three_rotations_and_current_value_removal(live, monkeypatch):
    import test_migration as fixture
    from test_application_config import config
    from test_application_rotation import exercise_rotations

    p, policies = live.make(token=workload_credentials(live).token), {}
    def resolve(tenant):
        if tenant not in policies:
            wrappers = tuple(create_root(p, KeyContext(fixture.DOMAIN, tenant, purpose, uuid4(), 1))
                             for purpose in ('payload', 'search'))
            policies[tenant] = KeyPolicy(fixture.DOMAIN, tenant, wrappers, 1, 1)
        return Keyring(policies[tenant], {p.provider_id: p})
    monkeypatch.setattr(fixture, 'keys', resolve)
    with fixture.application() as app:
        configured = config(app)
        fixture.run(app); fixture.publish(app)
        # A new native wrapping version is real custody evolution; retain v1 for
        # recovery and bind v2 to a separately configured logical provider.
        live.service.admin.write(f'{live.service.mount}/keys/{live.name}/rotate')
        destination = live.make(token=p._token, provider_id=uuid4(), key_version=2)
        exercise_rotations(app, configured, resolve, destination)


def test_real_approle_online_capture_tenant_publication_and_removal(live, tenant_app):
    p = live.make(token=workload_credentials(live).token)
    domain = UUID(tenant_app.tenant_plan.document['lock']['domain_id'])
    rings = {}
    def resolve(tenant):
        if tenant not in rings:
            wrappers = tuple(create_root(p, KeyContext(domain, tenant, purpose, uuid4(), 1))
                             for purpose in ('payload', 'search'))
            rings[tenant] = Keyring(KeyPolicy(domain, tenant, wrappers, 1, 1), {p.provider_id: p})
        return rings[tenant]
    exercise_online(tenant_app, resolve)


def test_real_approle_lifecycle_authentication_failure_preserves_state_and_resumes(live, tmp_path, monkeypatch, capsys):
    import test_migration as fixture
    from cryptalis import migration as m
    from test_operational_cli import host, inputs, invoke
    from test_provider_authentication_lifecycle import authentication_error
    workload = workload_credentials(live)
    authentication, calls, policies = [workload.token], [], {}
    def token():
        calls.append(True)
        return authentication[0]()
    p = live.make(token=token)
    def resolve(tenant):
        if tenant not in policies:
            wrappers = tuple(create_root(p, KeyContext(fixture.DOMAIN, tenant, purpose, uuid4(), 1))
                             for purpose in ('payload', 'search'))
            policies[tenant] = KeyPolicy(fixture.DOMAIN, tenant, wrappers, 1, 1)
        return Keyring(policies[tenant], {p.provider_id: p})
    monkeypatch.setattr(fixture, 'keys', resolve)
    with fixture.application() as app:
        fixture.run(app, until='EXPANDED')
        path, _ = inputs(app, tmp_path)
        reference, _, observed = host(app, monkeypatch, resolver=resolve)
        authentication[0] = workload.make(max_token_ttl=1)
        calls.clear()
        result = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        authentication_error(result, effects='INSPECT_JOURNAL')
        assert len(calls) == 1 and observed['dispose'] == 1
        if workload.current[0] in result[2]:
            raise AssertionError('SecretIDExposure')
        state = m.status(app.plan, app.owner, pin=app.pin)
        assert state.phase == 'EXPANDED' and state.committed_rows == 0
        authentication[0] = workload.token
        code, output, error = invoke(capsys, 'apply', str(path), '--host-context', reference, '--json')
        assert code == 0 and error == '' and json.loads(output)['phase'] == 'PENDING'
        fixture.publish(app)
        assert m.status(app.plan, app.owner, pin=app.pin).phase == 'ACTIVE'
