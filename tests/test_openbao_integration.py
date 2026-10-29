"""Real OpenBao HTTPS/Transit and PostgreSQL; configured isolated services only.

CRYPTALIS_OPENBAO_TEST_CONFIG names a private JSON file containing endpoint,
ca_cert, and admin_token_file (OpenBao initialization JSON). Never use production.
Keys and mounts are retained; tests do not delete or export service key material.
"""
import asyncio
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
from sqlalchemy import select

from cryptalis.crypto import (DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring,
    KeyUnavailable, WrappedRoot, create_root, open_text, seal_text)
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider
from test_cf1 import descriptor

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
        from openbao_qualification import docker
    finally:
        sys.path.pop(0)
    assert re.fullmatch(r'cryptalis-bao-[0-9a-f]{32}', container)
    wrapper = p.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1),
                   {p.provider_id: p}, max_age=5)
    field, record = descriptor(), UUID(int=5)
    frame = seal_text('outage value', field, CONTEXT.tenant_id, record, ring.prepare())
    docker('stop', '--time', '10', container)
    try:
        with pytest.raises(KeyUnavailable):
            p.unwrap(wrapper, CONTEXT)
        # Bounded cache availability is explicit; no remote retry or plaintext fallback.
        prepared = ring.prepare()
        assert open_text(frame, field, CONTEXT.tenant_id, record, prepared) == 'outage value'
        time.sleep(5.1)
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
    assert p.unwrap(wrapper, CONTEXT) == ROOT
    assert open_text(frame, field, CONTEXT.tenant_id, record, ring.prepare()) == 'outage value'


def test_real_provider_protect_search_edit_and_verified_plaintext_exit(live, monkeypatch):
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
        expected = dict(app.source)
        expected[UUID(int=101)] = (fixture.TENANT, 'live provider edit')
        bodies = fixture.frames(app, True)
        assert bodies[UUID(int=100)] is None
        assert all(value is None or b'live provider edit' not in value for value in bodies.values())
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
