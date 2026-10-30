"""Actual Google SDK/protobuf, local protocol transport, real PostgreSQL.

The transport stores opaque test handles, not simulated KMS cryptography. These
checks cannot qualify Google custody, IAM, TLS, version revocation or deletion.
"""
import asyncio
from dataclasses import replace
import os
import threading
import traceback
from uuid import UUID

import pytest

kms = pytest.importorskip('google.cloud.kms_v1')
crc = pytest.importorskip('google_crc32c')
from google.auth.credentials import AnonymousCredentials
from google.cloud.kms_v1.services.key_management_service.transports.base import KeyManagementServiceTransport

from cryptalis.crypto import DevelopmentKeyProvider, InvalidContext, KeyContext, KeyPolicy, Keyring, KeyUnavailable, WrappedRoot
from cryptalis.crypto.google_kms import GoogleKmsKeyProvider
from test_cf1 import descriptor

PROVIDER = UUID(int=950)
KEY = 'projects/cryptalis-test/locations/global/keyRings/fixture/cryptoKeys/root'
VERSION = KEY + '/cryptoKeyVersions/1'
CONTEXT = KeyContext(UUID(int=1), UUID(int=4), 'payload', UUID(int=951), 1)
ROOT = bytes(range(32))
SECRET = 'PRIVATE Google SDK credential/root diagnostic'


class ProtocolTransport(KeyManagementServiceTransport):
    """Runs the real SDK request conversion without credentials or network access."""
    def __init__(self, level=kms.ProtectionLevel.SOFTWARE):
        super().__init__(credentials=AnonymousCredentials())
        self._wrapped_methods = {self.encrypt: self.encrypt, self.decrypt: self.decrypt}
        self.calls, self.values = [], {}
        self.level, self.offline, self.mutate = level, False, lambda operation, response: response
        self.started = self.release = None

    def encrypt(self, request, *, retry, timeout, metadata):
        assert type(request) is kms.EncryptRequest
        self.calls.append(('encrypt', request, retry, timeout))
        if self.offline: raise RuntimeError(SECRET)
        assert request.plaintext_crc32c == crc.value(request.plaintext)
        assert request.additional_authenticated_data_crc32c == crc.value(request.additional_authenticated_data)
        sealed = b'opaque-google-sdk-handle-' + str(len(self.values)).encode()
        self.values[sealed] = (request.name.rsplit('/cryptoKeyVersions/', 1)[0],
                              request.additional_authenticated_data, request.plaintext)
        return self.mutate('encrypt', kms.EncryptResponse(name=request.name, ciphertext=sealed,
            ciphertext_crc32c=crc.value(sealed), verified_plaintext_crc32c=True,
            verified_additional_authenticated_data_crc32c=True, protection_level=self.level))

    def decrypt(self, request, *, retry, timeout, metadata):
        assert type(request) is kms.DecryptRequest
        self.calls.append(('decrypt', request, retry, timeout))
        if self.started is not None:
            self.started.set()
            if not self.release.wait(5): raise RuntimeError(SECRET)
        if self.offline: raise RuntimeError(SECRET)
        assert request.ciphertext_crc32c == crc.value(request.ciphertext)
        assert request.additional_authenticated_data_crc32c == crc.value(request.additional_authenticated_data)
        name, aad, root = self.values[request.ciphertext]
        if name != request.name or aad != request.additional_authenticated_data: raise RuntimeError(SECRET)
        return self.mutate('decrypt', kms.DecryptResponse(plaintext=root,
            plaintext_crc32c=crc.value(root), protection_level=self.level))

    def close(self):
        pass


def provider(transport=None, **kwargs):
    transport = transport or ProtocolTransport()
    return GoogleKmsKeyProvider(kms.KeyManagementServiceClient(transport=transport),
        provider_id=kwargs.pop('provider_id', PROVIDER), key_version=kwargs.pop('key_version', VERSION), **kwargs)


def redacted(error):
    assert SECRET in ''.join(traceback.format_exception(RuntimeError(SECRET)))
    rendered = ''.join(traceback.format_exception(error))
    assert SECRET not in rendered and str(ROOT) not in rendered
    assert error.code == 'KeyUnavailable'


@pytest.mark.parametrize('level', ['SOFTWARE', 'HSM'])
def test_real_sdk_checksums_context_and_cf1_keyring(level):
    from cryptalis.crypto import open_text, seal_text
    transport = ProtocolTransport(kms.ProtectionLevel[level])
    service = provider(transport, protection_level=level, timeout=3)
    wrapped = service.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapped,), 1), {PROVIDER: service}).prepare()
    field, record = descriptor(), UUID(int=5)
    frame = seal_text('café 雪', field, CONTEXT.tenant_id, record, ring)
    assert open_text(frame, field, CONTEXT.tenant_id, record, ring) == 'café 雪'
    assert len(transport.calls) == 2
    encrypt, decrypt = transport.calls
    assert encrypt[1].name == VERSION and decrypt[1].name == KEY
    assert encrypt[1].additional_authenticated_data == decrypt[1].additional_authenticated_data
    assert all(call[2] is None and call[3] == 3 for call in transport.calls)
    assert str(ROOT) not in repr(service) + repr(wrapped)


@pytest.mark.parametrize('version', [KEY, VERSION + '\n', VERSION + '/suffix', VERSION.replace('/1', '/0'),
    VERSION.replace('/1', '/01'), VERSION.replace('cryptalis-test', '..'), 'https://cloudkms.googleapis.com/' + VERSION])
def test_invalid_or_ambiguous_resource_never_dispatches(version):
    transport = ProtocolTransport()
    with pytest.raises(InvalidContext): provider(transport, key_version=version)
    assert not transport.calls


@pytest.mark.parametrize('option,value', [('timeout', True), ('timeout', 0), ('timeout', float('inf')),
    ('timeout', 61), ('protection_level', 'EXTERNAL'), ('provider_id', UUID(int=0))])
def test_invalid_authority_and_deadlines_refuse(option, value):
    transport = ProtocolTransport()
    with pytest.raises(InvalidContext): provider(transport, **{option: value})
    assert not transport.calls


@pytest.mark.parametrize('field,value', [('domain_id', UUID(int=21)), ('tenant_id', UUID(int=22)),
    ('purpose', 'search'), ('root_id', UUID(int=23)), ('generation', 2)])
def test_context_relabelling_is_rejected_by_aad(field, value):
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT)
    changed = replace(CONTEXT, **{field: value})
    with pytest.raises(KeyUnavailable) as error:
        service.unwrap(WrappedRoot(PROVIDER, changed, wrapped.sealed), changed)
    assert len(transport.calls) == 2
    redacted(error.value)


@pytest.mark.parametrize('change', ['provider', 'key', 'version', 'level'])
def test_wrapper_cannot_reselect_provider_key_version_or_level(change):
    transport = ProtocolTransport(); source = provider(transport)
    wrapped = source.wrap(ROOT, CONTEXT)
    overrides = {'provider': dict(provider_id=UUID(int=953)),
        'key': dict(key_version=VERSION.replace('/root/', '/other/')),
        'version': dict(key_version=KEY + '/cryptoKeyVersions/2'),
        'level': dict(protection_level='HSM')}[change]
    other = provider(transport, **overrides)
    if change == 'provider':
        with pytest.raises(KeyUnavailable): other.unwrap(wrapped, CONTEXT)
        assert len(transport.calls) == 1
        wrapped = WrappedRoot(other.provider_id, CONTEXT, wrapped.sealed)
    with pytest.raises(KeyUnavailable) as error: other.unwrap(wrapped, CONTEXT)
    redacted(error.value)


@pytest.mark.parametrize('operation,fault', [('encrypt', 'name'), ('encrypt', 'checksum'),
    ('encrypt', 'missing_checksum'), ('encrypt', 'plaintext_flag'), ('encrypt', 'aad_flag'),
    ('encrypt', 'level'), ('encrypt', 'empty'), ('encrypt', 'oversized'),
    ('decrypt', 'checksum'), ('decrypt', 'missing_checksum'), ('decrypt', 'level'),
    ('decrypt', 'short'), ('decrypt', 'long')])
def test_unverified_sdk_results_release_no_material(operation, fault):
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT)
    def mutate(kind, response):
        if kind != operation: return response
        value = 'ciphertext' if kind == 'encrypt' else 'plaintext'
        checksum = value + '_crc32c'
        if fault == 'name': response.name = KEY + '/cryptoKeyVersions/2'
        elif fault == 'checksum': setattr(response, checksum, getattr(response, checksum) ^ 1)
        elif fault == 'missing_checksum': delattr(response, checksum)
        elif fault == 'plaintext_flag': response.verified_plaintext_crc32c = False
        elif fault == 'aad_flag': response.verified_additional_authenticated_data_crc32c = False
        elif fault == 'level': response.protection_level = kms.ProtectionLevel.HSM
        else:
            body = {'empty': b'', 'oversized': b'x' * 65537, 'short': ROOT[:-1], 'long': ROOT + b'x'}[fault]
            setattr(response, value, body); setattr(response, checksum, crc.value(body))
        return response
    transport.mutate = mutate
    with pytest.raises(KeyUnavailable) as error:
        if operation == 'encrypt': service.wrap(ROOT, CONTEXT)
        else: service.unwrap(wrapped, CONTEXT)
    redacted(error.value)


def test_outage_is_typed_redacted_and_never_retried():
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT); transport.offline = True
    for action in (lambda: service.wrap(ROOT, CONTEXT), lambda: service.unwrap(wrapped, CONTEXT)):
        before = len(transport.calls)
        with pytest.raises(KeyUnavailable) as error: action()
        assert len(transport.calls) == before + 1
        redacted(error.value)


def test_async_client_is_refused():
    class AsyncClient:
        async def encrypt(self, **kwargs): raise AssertionError
        async def decrypt(self, **kwargs): raise AssertionError
    with pytest.raises(InvalidContext):
        GoogleKmsKeyProvider(AsyncClient(), provider_id=PROVIDER, key_version=VERSION)


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires an actual POSIX child process')
def test_actual_child_cannot_dispatch_with_inherited_provider():
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT)
    pid = os.fork()
    if pid == 0:
        try:
            service.unwrap(wrapped, CONTEXT)
        except KeyUnavailable:
            os._exit(0)
        except BaseException:
            os._exit(2)
        os._exit(1)
    assert os.waitpid(pid, 0)[1] == 0
    assert len(transport.calls) == 1


@pytest.mark.parametrize('target', ['development', 'google'])
def test_verified_cross_provider_rewrap_and_wrong_root_refusal(target):
    service = provider(); wrapped = service.wrap(ROOT, CONTEXT)
    destination = (DevelopmentKeyProvider() if target == 'development' else
                   provider(provider_id=UUID(int=954), key_version=KEY + '/cryptoKeyVersions/2'))
    result = service.rewrap(wrapped, destination, CONTEXT)
    assert destination.unwrap(result, CONTEXT) == ROOT
    original = destination.unwrap
    destination.unwrap = lambda *args: b'x' * 32
    with pytest.raises(KeyUnavailable): service.rewrap(wrapped, destination, CONTEXT)
    destination.unwrap = original


def test_rewrap_preserves_unknown_authentication_effects_without_raw_cause():
    from cryptalis.crypto import ProviderAuthenticationUnavailable
    service = provider(); wrapped = service.wrap(ROOT, CONTEXT)
    destination = DevelopmentKeyProvider()
    def failed(*args): raise ProviderAuthenticationUnavailable() from RuntimeError(SECRET)
    destination.wrap = failed
    with pytest.raises(ProviderAuthenticationUnavailable) as error:
        service.rewrap(wrapped, destination, CONTEXT)
    assert error.value.effects == 'UNKNOWN' and error.value.retryable is False
    assert SECRET not in ''.join(traceback.format_exception(error.value))


def test_async_cancel_discards_late_sdk_result_and_requires_fresh_preparation():
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapped,), 1), {PROVIDER: service})
    transport.started, transport.release = threading.Event(), threading.Event()
    async def exercise():
        task = asyncio.create_task(ring.prepare_async())
        assert await asyncio.to_thread(transport.started.wait, 5)
        task.cancel()
        try:
            with pytest.raises(asyncio.CancelledError): await task
        finally: transport.release.set()
    asyncio.run(exercise())
    transport.started = transport.release = None
    transport.offline = True
    # A canceled unwrap must not populate the cache: cold access still dispatches.
    with pytest.raises(KeyUnavailable): ring.prepare()
    transport.offline = False
    prepared = asyncio.run(ring.prepare_async())
    from cryptalis.crypto import seal_text, open_text
    frame = seal_text('x', descriptor(), CONTEXT.tenant_id, UUID(int=5), prepared)
    assert open_text(frame, descriptor(), CONTEXT.tenant_id, UUID(int=5), prepared) == 'x'
    assert len(transport.calls) == 4


@pytest.mark.parametrize('root,context', [(ROOT[:-1], CONTEXT), (bytearray(ROOT), CONTEXT), (ROOT, None)])
def test_invalid_root_or_context_never_dispatches(root, context):
    transport = ProtocolTransport(); service = provider(transport)
    with pytest.raises(InvalidContext): service.wrap(root, context)
    assert not transport.calls


@pytest.mark.parametrize('operation', ['wrap', 'unwrap'])
def test_sync_client_coroutine_result_is_closed_and_redacted(operation):
    import gc
    import warnings
    transport = ProtocolTransport(); service = provider(transport)
    wrapped = service.wrap(ROOT, CONTEXT)
    async def unexpected(): raise RuntimeError(SECRET)
    transport.mutate = lambda *args: unexpected()
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter('always', RuntimeWarning)
        with pytest.raises(KeyUnavailable) as error:
            if operation == 'wrap': service.wrap(ROOT, CONTEXT)
            else: service.unwrap(wrapped, CONTEXT)
        redacted(error.value)
        gc.collect()
    assert observed == []


def test_real_postgres_lifecycle_with_sdk_transport_and_current_value_removal():
    from sqlalchemy import select
    from test_application_config import config, authority
    from test_deprotection import consent, d, least_privilege_role, native_rows
    from test_migration import application, DOMAIN, TENANT
    transport = ProtocolTransport(); service = provider(transport)
    wrappers = tuple(service.wrap(bytes([index]) * 32,
        KeyContext(DOMAIN, TENANT, purpose, UUID(int=960 + index), 1))
        for index, purpose in enumerate(('payload', 'search'), 1))
    ring = Keyring(KeyPolicy(DOMAIN, TENANT, wrappers, 1, 1), {PROVIDER: service})
    def resolve(tenant):
        assert tenant == TENANT
        return ring
    with application() as app:
        configured = config(app)
        app.plan = configured.plan(app.owner, **authority(app, resolve))
        app.pin = replace(app.pin, operation_id=app.plan.operation_id, plan_digest=app.plan.digest)
        configured.apply(app.owner, deployment=(app.plan, app.pin), keys=resolve, approval=app.approval)
        app.pin = replace(app.pin, phase='ACTIVATING')
        configured.apply(app.owner, deployment=(app.plan, app.pin), keys=resolve, approval=app.approval, until='ACTIVE')
        app.pin = replace(app.pin, phase='ACTIVE')
        factory = configured.attach(app.runtime, deployment=(app.plan, app.pin), keys=resolve)
        with factory(tenant_id=TENANT) as session:
            assert {row.id: (row.tenant_id, row.name) for row in session.scalars(select(app.Customer))} == app.source
            session.get(app.Customer, UUID(int=101)).name = 'current SDK-protected edit'; session.commit()
            assert session.scalars(select(app.Customer.id).where(app.Customer.tenant_id == TENANT,
                app.Customer.name == 'current SDK-protected edit')).one() == UUID(int=101)
        reverse = configured.plan_deprotection(app.owner, deployment=(app.plan, app.pin), keys=resolve,
            plaintext_runtime_role=least_privilege_role(app), backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=700, wal_bytes_per_row=700)
        exposure, pin = consent(reverse)
        configured.decrypt_back(app.owner, deployment=(reverse, pin), keys=resolve, approval=app.approval, consent=exposure)
        configured.decrypt_back(app.owner, deployment=(reverse, replace(pin, phase='PLAINTEXT_ACTIVATING')),
            keys=resolve, approval=app.approval, consent=exposure, until='PLAINTEXT_ACTIVE')
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'native public fixture current values', 'public fixture custody retained', True)
        configured.remove(app.owner, deployment=(reverse, replace(pin, phase='REMOVING')),
            approval=app.approval, consent=exposure, removal=removal)
        expected = dict(app.source); expected[UUID(int=101)] = (TENANT, 'current SDK-protected edit')
        assert native_rows(app) == expected
