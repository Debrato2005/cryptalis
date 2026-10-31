"""Opaque Transit protocol controls; live service evidence is a separate profile."""

import asyncio
import base64
import gc
import traceback
import warnings
from contextlib import contextmanager
from dataclasses import replace
from uuid import UUID

import pytest

from cryptalis.crypto import (
    DevelopmentKeyProvider, InvalidContext, KeyContext, KeyPolicy, Keyring,
    KeyUnavailable, WrappedRoot, open_text, seal_text,
)
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider
from test_cf1 import descriptor


PROVIDER = UUID(int=901)
CONTEXT = KeyContext(UUID(int=1), UUID(int=4), "payload", UUID(int=906), 1)
ROOT = bytes(range(32))
SECRET = "private-service-diagnostic-token-root"


class TransitDouble:
    def __init__(self):
        self.calls = []
        self.values = {}
        self.metadata = {
            "name": "roots", "type": "aes256-gcm96", "derived": False,
            "exportable": False, "allow_plaintext_backup": False,
            "deletion_allowed": False, "keys": {"1": 1, "2": 2},
            "supports_encryption": True, "supports_decryption": True,
            "imported_key": False, "latest_version": 2,
            "min_decryption_version": 1, "min_encryption_version": 0,
        }

    def read(self, path):
        mount, _, name = path.rsplit("/", 2)
        return self.read_key(name=name, mount_point=mount)

    def write(self, path, **request):
        mount, operation, name = path.rsplit("/", 2)
        method = self.encrypt_data if operation == "encrypt" else self.decrypt_data
        return method(name=name, mount_point=mount, **request)

    def read_key(self, **request):
        self.calls.append(("read", request))
        return {"data": dict(self.metadata)}

    def encrypt_data(self, **request):
        self.calls.append(("encrypt", request))
        # Opaque handle, not invented cryptography.
        handle = f"vault:v{request['key_version']}:" + base64.b64encode(
            str(len(self.values)).encode()).decode()
        self.values[handle] = dict(request)
        return {"data": {"ciphertext": handle, "key_version": request["key_version"]}}

    def decrypt_data(self, **request):
        self.calls.append(("decrypt", request))
        original = self.values[request["ciphertext"]]
        if any(original[key] != request[key]
               for key in ("name", "mount_point", "associated_data")):
            raise RuntimeError(SECRET)
        return {"data": {"plaintext": original["plaintext"]}}


def provider(client=None, **kwargs):
    # Exercise the canonical provider's protocol using an opaque service double.
    # Real endpoint/authentication behavior belongs to the native SDK profiles.
    client = client or TransitDouble()
    bao = OpenBaoTransitKeyProvider(
        endpoint="https://bao.example.invalid", token=lambda: "synthetic-token",
        provider_id=PROVIDER, mount="transit", key_name="roots", key_version=1, **kwargs,
    )
    @contextmanager
    def supplied():
        yield client
    bao._client = supplied
    return bao


def test_exact_context_randomized_service_contract_and_cf1_round_trip():
    client = TransitDouble()
    bao = provider(client)
    wrapper = bao.wrap(ROOT, CONTEXT)
    request = client.calls[1][1]
    assert client.calls[0] == ("read", {"name": "roots", "mount_point": "transit"})
    assert set(request) == {"name", "mount_point", "key_version", "plaintext", "associated_data"}
    assert request["key_version"] == 1
    assert base64.b64decode(request["plaintext"], validate=True) == ROOT
    assert b"CF1/openbao-transit-wrap/v1" in base64.b64decode(request["associated_data"])
    keys = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1),
                   {PROVIDER: bao}).prepare()
    field, record = descriptor(), UUID(int=5)
    frame = seal_text("café 雪", field, CONTEXT.tenant_id, record, keys)
    assert open_text(frame, field, CONTEXT.tenant_id, record, keys) == "café 雪"
    assert client.calls[-1][1] == {
        "name": "roots", "mount_point": "transit", "ciphertext": wrapper.sealed.decode(),
        "associated_data": request["associated_data"],
    }


@pytest.mark.parametrize("changes", [
    {"domain_id": UUID(int=21)}, {"tenant_id": UUID(int=0)}, {"purpose": "search"},
    {"root_id": UUID(int=22)}, {"generation": 2},
])
def test_relabelled_context_is_authenticated_by_service(changes):
    bao = provider()
    wrapper = bao.wrap(ROOT, CONTEXT)
    changed = replace(CONTEXT, **changes)
    with pytest.raises(KeyUnavailable) as caught:
        bao.unwrap(WrappedRoot(PROVIDER, changed, wrapper.sealed), changed)
    assert SECRET not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("field,value", [
    ("key_name", "../roots"), ("key_name", "roots/other"),
    ("mount", "https://host/transit"), ("mount", "transit/../auth"),
    ("key_version", 0), ("key_version", True), ("key_version", 2**31),
    ("provider_id", UUID(int=0)),
])
def test_invalid_authority_never_dispatches(field, value):
    client = TransitDouble()
    arguments = dict(endpoint="https://bao.example.invalid", token=lambda: "synthetic-token",
        provider_id=PROVIDER, mount="transit", key_name="roots", key_version=1)
    arguments[field] = value
    with pytest.raises(InvalidContext):
        OpenBaoTransitKeyProvider(**arguments)
    assert client.calls == []


@pytest.mark.parametrize("field,value", [
    ("type", "aes128-gcm96"), ("name", "other"), ("derived", True),
    ("exportable", True), ("allow_plaintext_backup", True),
    ("deletion_allowed", True), ("supports_encryption", False),
    ("supports_decryption", False), ("keys", {"2": 2}), ("derived", 0),
])
def test_unsafe_or_wrong_metadata_never_dispatches_crypto(field, value):
    client = TransitDouble()
    client.metadata[field] = value
    with pytest.raises(KeyUnavailable):
        provider(client).wrap(ROOT, CONTEXT)
    assert [kind for kind, _ in client.calls] == ["read"]


@pytest.mark.parametrize("sealed", [
    b"vault:v2:YQ==", b"vault:v0:YQ==", b"vault:v01:YQ==", b"vault:v1:!!!",
    b"vault:v1:", b"vault:v1:YQ==\n", b"x" * 8193, b"\xff",
])
def test_foreign_or_malformed_ciphertext_refuses_before_dispatch(sealed):
    client = TransitDouble()
    with pytest.raises(KeyUnavailable):
        provider(client).unwrap(WrappedRoot(PROVIDER, CONTEXT, sealed), CONTEXT)
    assert client.calls == []


def test_wrong_provider_and_context_refuse_before_dispatch():
    client = TransitDouble()
    bao = provider(client)
    wrapper = bao.wrap(ROOT, CONTEXT)
    client.calls.clear()
    for wrong in (replace(wrapper, provider_id=UUID(int=3)),
                  replace(wrapper, context=replace(CONTEXT, generation=2))):
        with pytest.raises(KeyUnavailable):
            bao.unwrap(wrong, CONTEXT)
    assert client.calls == []


@pytest.mark.parametrize("field,value", [
    ("domain_id", "not-uuid"), ("purpose", "other"), ("generation", True),
])
def test_altered_context_and_invalid_root_refuse_before_dispatch(field, value):
    client = TransitDouble()
    context = replace(CONTEXT)
    object.__setattr__(context, field, value)
    bao = provider(client)
    with pytest.raises(InvalidContext):
        bao.wrap(ROOT, context)
    with pytest.raises(InvalidContext):
        bao.wrap(ROOT[:-1], CONTEXT)
    assert client.calls == []


@pytest.mark.parametrize("operation", ["read_key", "encrypt_data", "decrypt_data"])
def test_service_errors_are_redacted_without_retry(operation):
    client = TransitDouble()
    bao = provider(client)
    wrapper = bao.wrap(ROOT, CONTEXT)
    def fail(**kwargs):
        raise RuntimeError(SECRET)
    setattr(client, operation, fail)
    with pytest.raises(KeyUnavailable) as caught:
        if operation == "encrypt_data":
            bao.wrap(ROOT, CONTEXT)
        else:
            bao.unwrap(wrapper, CONTEXT)
    assert SECRET not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("value", [None, {}, {"data": {}}, {"data": {"plaintext": "!!!"}},
    {"data": {"plaintext": base64.b64encode(ROOT[:-1]).decode()}},
    {"data": {"plaintext": base64.b64encode(ROOT).decode() + "\n"}},
])
def test_malformed_decrypt_response_cannot_release_material(value):
    client = TransitDouble()
    bao = provider(client)
    wrapper = bao.wrap(ROOT, CONTEXT)
    client.decrypt_data = lambda **kwargs: value
    with pytest.raises(KeyUnavailable):
        bao.unwrap(wrapper, CONTEXT)


def test_async_and_cross_provider_rewrap_preserve_exact_root():
    bao = provider()
    wrapper = bao.wrap(ROOT, CONTEXT)
    assert asyncio.run(bao.unwrap_async(wrapper, CONTEXT)) == ROOT
    development = DevelopmentKeyProvider()
    moved = bao.rewrap(wrapper, development, CONTEXT)
    assert development.unwrap(moved, CONTEXT) == ROOT
    restored = development.rewrap(moved, bao, CONTEXT)
    assert bao.unwrap(restored, CONTEXT) == ROOT


def test_inherited_provider_refuses_before_dispatch(monkeypatch):
    client = TransitDouble()
    bao = provider(client)
    monkeypatch.setattr("cryptalis.crypto.openbao.os.getpid", lambda: -1)
    with pytest.raises(KeyUnavailable):
        bao.wrap(ROOT, CONTEXT)
    assert client.calls == []


def test_async_authentication_callback_refuses_before_use():
    async def asynchronous(**kwargs):
        pytest.fail("constructor called asynchronous authentication")
    with pytest.raises(InvalidContext):
        OpenBaoTransitKeyProvider(endpoint="https://bao.example.invalid", token=asynchronous,
            provider_id=PROVIDER, key_name="roots", key_version=1)


@pytest.mark.parametrize("operation", ["read_key", "encrypt_data", "decrypt_data"])
def test_accidental_coroutine_response_is_closed_and_retry_recovers(operation):
    client = TransitDouble()
    bao = provider(client)
    wrapper = bao.wrap(ROOT, CONTEXT)
    original = getattr(client, operation)
    async def accidental():
        return {"private": SECRET}
    setattr(client, operation, lambda **kwargs: accidental())
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always", RuntimeWarning)
        with pytest.raises(KeyUnavailable) as caught:
            if operation == "encrypt_data":
                bao.wrap(ROOT, CONTEXT)
            else:
                bao.unwrap(wrapper, CONTEXT)
        gc.collect()
    assert not [warning for warning in observed if "never awaited" in str(warning.message)]
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    setattr(client, operation, original)
    assert bao.unwrap(wrapper, CONTEXT) == ROOT


@pytest.mark.parametrize("value", [None, "vault:v2:YQ==", "vault:v1:!!!", "vault:v1:",
                                    "vault:v1:YQ==\n", "x" * 8193])
def test_wrong_or_malformed_wrap_response_cannot_create_wrapper(value):
    client = TransitDouble()
    client.encrypt_data = lambda **kwargs: {"data": {"ciphertext": value}}
    with pytest.raises(KeyUnavailable):
        provider(client).wrap(ROOT, CONTEXT)
