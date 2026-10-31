"""Opt-in native hvac/OpenBao 2.7.2 service; no production custody claim."""

import asyncio
import base64
from dataclasses import replace
import importlib.metadata
import os
import socket
import subprocess
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

hvac = pytest.importorskip("hvac", reason="explicit OpenBao profile requires native hvac 2.4.0")
import requests
from sqlalchemy import select

from cryptalis.crypto import KeyContext, KeyPolicy, Keyring, KeyUnavailable, WrappedRoot, create_root
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider
from cryptalis.sqlalchemy import attach
from test_openbao_transit import CONTEXT, ROOT


@pytest.fixture(scope="module")
def service(tmp_path_factory):
    binary = os.environ.get("CRYPTALIS_OPENBAO_TEST_BINARY")
    if not binary:
        pytest.skip("set CRYPTALIS_OPENBAO_TEST_BINARY to the verified OpenBao 2.7.2 binary")
    assert importlib.metadata.version("hvac") == "2.4.0"
    version = subprocess.run([binary, "version"], check=True, capture_output=True, text=True)
    assert version.stdout.startswith("OpenBao v2.7.2 ")
    directory = tmp_path_factory.mktemp("openbao-service")
    directory.chmod(0o700)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    token = uuid4().hex
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("BAO_", "VAULT_"))}
    environment["BAO_DEV_ROOT_TOKEN_ID"] = token
    sessions = []
    def client(credential):
        session = requests.Session()
        session.trust_env = False
        sessions.append(session)
        return hvac.Client(url=url, token=credential, timeout=2,
                           allow_redirects=False, session=session)
    with (directory / "private-service.log").open("wb") as log:
        process = subprocess.Popen(
            [binary, "server", "-dev", "-dev-no-store-token",
             f"-dev-listen-address=127.0.0.1:{port}"], env=environment,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            admin = client(token)
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    pytest.fail("local OpenBao exited before readiness; inspect private service log")
                try:
                    if admin.sys.is_initialized() and not admin.sys.is_sealed():
                        break
                except requests.exceptions.ConnectionError:
                    pass
                if time.monotonic() >= deadline:
                    pytest.fail("local OpenBao readiness deadline exceeded")
                time.sleep(0.05)
            admin.sys.enable_secrets_engine("transit", path="cryptalis-test")
            yield SimpleNamespace(admin=admin, transit=admin.secrets.transit, client=client,
                                  mount="cryptalis-test", directory=directory)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            for session in sessions:
                session.close()


@pytest.fixture
def native(service):
    name = "roots-" + uuid4().hex
    service.transit.create_key(
        name=name, mount_point=service.mount, key_type="aes256-gcm96",
        derived=False, convergent_encryption=False, exportable=False,
        allow_plaintext_backup=False,
    )
    provider = OpenBaoTransitKeyProvider(service.transit, provider_id=uuid4(),
        mount_point=service.mount, key_name=name, key_version=1)
    return SimpleNamespace(provider=provider, name=name, service=service)


@pytest.mark.parametrize("field,value", [
    ("domain_id", uuid4()), ("tenant_id", uuid4()), ("purpose", "search"),
    ("root_id", uuid4()), ("generation", 2),
])
def test_native_aead_rejects_relabelled_root_context(native, field, value):
    bao = native.provider
    first, second = bao.wrap(ROOT, CONTEXT), bao.wrap(ROOT, CONTEXT)
    assert first.sealed != second.sealed
    assert bao.unwrap(first, CONTEXT) == ROOT
    changed = replace(CONTEXT, **{field: value})
    with pytest.raises(KeyUnavailable):
        bao.unwrap(WrappedRoot(bao.provider_id, changed, first.sealed), changed)
    body = bytearray(base64.b64decode(first.sealed.split(b":", 2)[2]))
    body[-1] ^= 1
    damaged = b"vault:v1:" + base64.b64encode(body)
    with pytest.raises(KeyUnavailable):
        bao.unwrap(replace(first, sealed=damaged), CONTEXT)


def test_native_rotation_does_not_silently_select_latest_and_rewrap_preserves_root(native):
    bao, service = native.provider, native.service
    wrapper = bao.wrap(ROOT, CONTEXT)
    service.transit.rotate_key(name=native.name, mount_point=service.mount)
    assert bao.wrap(ROOT, CONTEXT).sealed.startswith(b"vault:v1:")
    target = OpenBaoTransitKeyProvider(service.transit, provider_id=uuid4(),
        mount_point=service.mount, key_name=native.name, key_version=2)
    moved = bao.rewrap(wrapper, target, CONTEXT)
    assert moved.sealed.startswith(b"vault:v2:")
    assert target.unwrap(moved, CONTEXT) == ROOT
    assert bao.unwrap(wrapper, CONTEXT) == ROOT
    # Relabelling the public provider identity cannot select another KEK version.
    with pytest.raises(KeyUnavailable):
        target.unwrap(replace(wrapper, provider_id=target.provider_id), CONTEXT)


def test_native_least_privilege_token_revocation_and_host_recovery(native):
    service = native.service
    policy = "cryptalis-test-" + uuid4().hex
    service.admin.sys.create_or_update_policy(policy, f'''
        path "{service.mount}/keys/{native.name}" {{ capabilities = ["read"] }}
        path "{service.mount}/encrypt/{native.name}" {{ capabilities = ["update"] }}
        path "{service.mount}/decrypt/{native.name}" {{ capabilities = ["update"] }}
    ''')
    def credential():
        return service.admin.auth.token.create(policies=[policy], no_default_policy=True,
            ttl="60s", renewable=False)["auth"]["client_token"]
    token = credential()
    client = service.client(token)
    bao = OpenBaoTransitKeyProvider(client.secrets.transit,
        provider_id=native.provider.provider_id, mount_point=service.mount,
        key_name=native.name, key_version=1)
    wrapped = bao.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapped,), 1),
                   {bao.provider_id: bao})
    ring.prepare()
    service.admin.auth.token.revoke(token)
    with pytest.raises(KeyUnavailable):
        bao.unwrap(wrapped, CONTEXT)
    client.token = credential()
    assert bao.unwrap(wrapped, CONTEXT) == ROOT
    with pytest.raises(hvac.exceptions.Forbidden):
        client.secrets.transit.rotate_key(name=native.name, mount_point=service.mount)


def test_native_async_cancelled_reply_does_not_publish_late_material(native):
    bao = native.provider
    wrapped = bao.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapped,), 1),
                   {bao.provider_id: bao})
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = bao._transit.decrypt_data
    def delayed(**kwargs):
        try:
            result = original(**kwargs)
            entered.set()
            assert release.wait(5)
            return result
        finally:
            finished.set()
    bao._transit.decrypt_data = delayed
    async def scenario():
        task = asyncio.create_task(ring.prepare_async())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        def unavailable(**kwargs):
            raise RuntimeError("service reply unavailable")
        bao._transit.decrypt_data = unavailable
        with pytest.raises(KeyUnavailable):
            await ring.prepare_async()
    try:
        asyncio.run(scenario())
    finally:
        bao._transit.decrypt_data = original
        release.set()
    ring.prepare()


def test_native_provider_protects_searches_modifies_and_removes_current_values(native, monkeypatch):
    import test_migration as migration
    import test_deprotection as reverse
    bao = native.provider
    rings = {}
    def resolve(tenant):
        if tenant not in rings:
            contexts = [KeyContext(migration.DOMAIN, tenant, purpose, uuid4(), 1)
                        for purpose in ("payload", "search")]
            wrappers = tuple(create_root(bao, context) for context in contexts)
            rings[tenant] = Keyring(KeyPolicy(migration.DOMAIN, tenant, wrappers, 1, 1),
                                    {bao.provider_id: bao})
        return rings[tenant]
    monkeypatch.setattr(migration, "keys", resolve)
    monkeypatch.setattr(reverse, "keys", resolve)
    with migration.application() as app:
        assert migration.run(app).phase == "PENDING"
        migration.publish(app)
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=resolve,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=migration.TENANT) as session:
            assert {r.id: (r.tenant_id, r.name) for r in session.scalars(select(app.Customer))} == app.source
            row = session.get(app.Customer, next(iter(app.source)))
            row.name = "private OpenBao current edit 雪"
            identity = row.id
            session.commit()
            assert session.scalar(select(app.Customer.name).where(
                app.Customer.name == "private OpenBao current edit 雪")) == "private OpenBao current edit 雪"
        expected = dict(app.source)
        expected[identity] = (migration.TENANT, "private OpenBao current edit 雪")
        proposal = reverse.proposal(app)
        assert reverse.reverse(app, proposal, key_resolver=resolve).phase == "PLAINTEXT_PENDING"
        consent, pin = reverse.consent(proposal, "PLAINTEXT_ACTIVATING")
        assert reverse.d.apply(proposal, app.owner, keys=resolve, pin=pin,
            approval=app.approval, consent=consent,
            until="PLAINTEXT_ACTIVE").phase == "PLAINTEXT_ACTIVE"
        assert reverse.native_rows(app) == expected
        removal = reverse.d.RemovalApproval(proposal.target_id, proposal.operation_id,
            proposal.digest, "native current-value workload passed", "synthetic recovery evidence", True)
        assert reverse.d.remove(proposal, app.owner, pin=replace(pin, phase="REMOVING"),
            approval=app.approval, removal=removal, consent=consent).phase == "REMOVED"
        assert reverse.d.check_removed(proposal, app.owner,
            pin=replace(pin, phase="REMOVED")) is None
        assert reverse.native_rows(app) == expected
        with app.owner.connect() as connection:
            assert connection.exec_driver_sql(
                f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
                (identity,)).scalar_one() == "private OpenBao current edit 雪"
