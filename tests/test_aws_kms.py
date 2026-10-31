"""SDK-shaped test double boundary, not botocore, IAM or live AWS evidence."""

import asyncio
import gc
import os
import threading
import traceback
import warnings
from dataclasses import replace
from uuid import UUID

import pytest

from cryptalis.crypto import (
    DevelopmentKeyProvider, InvalidContext, KeyContext, KeyPolicy, Keyring,
    KeyUnavailable, WrappedRoot, create_root, open_text, seal_text,
)
from cryptalis.crypto.aws_kms import AwsKmsKeyProvider
from test_cf1 import descriptor


PROVIDER = UUID(int=901)
ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
OTHER_ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ac"
CONTEXT = KeyContext(UUID(int=1), UUID(int=4), "payload", UUID(int=906), 1)
ROOT = bytes(range(32))
SECRET = "INJECTED raw credential/plaintext/root diagnostic"


class KmsProtocolDouble:
    """Opaque handles model service context matching; no fake cryptography."""

    def __init__(self):
        self.calls = []
        self.values = {}
        self.offline = False

    def encrypt(self, **request):
        self.calls.append(("encrypt", request))
        if self.offline:
            raise RuntimeError(SECRET)
        handle = b"opaque-sdk-protocol-handle-" + str(len(self.values)).encode()
        self.values[handle] = (request["KeyId"], dict(request["EncryptionContext"]),
                               request["Plaintext"])
        return {"KeyId": request["KeyId"], "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextBlob": handle}

    def decrypt(self, **request):
        self.calls.append(("decrypt", request))
        if self.offline:
            raise RuntimeError(SECRET)
        key, context, root = self.values[request["CiphertextBlob"]]
        if (key, context) != (request["KeyId"], request["EncryptionContext"]):
            raise RuntimeError(SECRET)
        return {"KeyId": key, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT", "Plaintext": root}


def provider(client=None, **kwargs):
    return AwsKmsKeyProvider(client or KmsProtocolDouble(), provider_id=PROVIDER,
                             key_arn=ARN, **kwargs)


def assert_redacted(error):
    assert SECRET in "".join(traceback.format_exception(RuntimeError(SECRET)))
    rendered = "".join(traceback.format_exception(error))
    assert SECRET not in rendered
    assert str(ROOT) not in rendered
    assert error.code == "KeyUnavailable"
    assert error.operation_id


def test_exact_sdk_requests_and_keyring_cf1_round_trip():
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    expected = {
        "cryptalis:format": "CF1/aws-kms-wrap/v1",
        "cryptalis:provider": str(PROVIDER),
        "cryptalis:domain": str(CONTEXT.domain_id),
        "cryptalis:tenant": str(CONTEXT.tenant_id),
        "cryptalis:purpose": "payload",
        "cryptalis:root": str(CONTEXT.root_id),
        "cryptalis:generation": "1",
    }
    assert client.calls == [("encrypt", {"KeyId": ARN, "Plaintext": ROOT,
                "EncryptionContext": expected, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})]
    policy = KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1)
    keys = Keyring(policy, {PROVIDER: kms}).prepare()
    assert client.calls[-1] == ("decrypt", {"KeyId": ARN, "CiphertextBlob": wrapper.sealed,
                "EncryptionContext": expected, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
    field, record = descriptor(), UUID(int=5)
    frame = seal_text("café 雪", field, CONTEXT.tenant_id, record, keys)
    assert open_text(frame, field, CONTEXT.tenant_id, record, keys) == "café 雪"
    assert len(client.calls) == 2
    assert ROOT.hex() not in repr(kms)
    assert str(ROOT) not in repr(wrapper)


@pytest.mark.parametrize("key_arn", [
    "alias/application", "arn:aws:kms:us-east-1:111122223333:alias/application",
    "1234abcd-12ab-34cd-56ef-1234567890ab", ARN + "\n", ARN + "/suffix", " " + ARN,
])
def test_aliases_or_ambiguous_key_identifiers_refuse_before_dispatch(key_arn):
    client = KmsProtocolDouble()
    with pytest.raises(InvalidContext):
        AwsKmsKeyProvider(client, provider_id=PROVIDER, key_arn=key_arn)
    assert client.calls == []


def test_multiregion_key_and_nil_tenant_are_exact_public_metadata():
    client = KmsProtocolDouble()
    arn = "arn:aws-us-gov:kms:us-gov-west-1:111122223333:key/mrk-" + "a" * 32
    kms = AwsKmsKeyProvider(client, provider_id=PROVIDER, key_arn=arn)
    context = replace(CONTEXT, tenant_id=UUID(int=0), generation=0xFFFFFFFF)
    wrapper = create_root(kms, context)
    assert len(kms.unwrap(wrapper, context)) == 32
    assert client.calls[-1][1]["EncryptionContext"]["cryptalis:tenant"] == str(UUID(int=0))
    assert client.calls[-1][1]["EncryptionContext"]["cryptalis:generation"] == "4294967295"


@pytest.mark.parametrize("field,value", [
    ("domain_id", UUID(int=21)), ("tenant_id", UUID(int=22)),
    ("purpose", "search"), ("root_id", UUID(int=23)), ("generation", 2),
])
def test_relabelled_wrapper_cannot_change_authenticated_context(field, value):
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    changed = replace(CONTEXT, **{field: value})
    forged = WrappedRoot(PROVIDER, changed, wrapper.sealed)
    with pytest.raises(KeyUnavailable) as caught:
        kms.unwrap(forged, changed)
    assert client.calls[-1][0] == "decrypt"
    assert_redacted(caught.value)


def test_relabelled_provider_fails_service_context_and_foreign_wrapper_never_dispatches():
    client = KmsProtocolDouble()
    source = provider(client)
    wrapper = source.wrap(ROOT, CONTEXT)
    other = AwsKmsKeyProvider(client, provider_id=UUID(int=902), key_arn=ARN)
    with pytest.raises(KeyUnavailable):
        other.unwrap(wrapper, CONTEXT)
    assert len(client.calls) == 1
    relabelled = WrappedRoot(other.provider_id, CONTEXT, wrapper.sealed)
    with pytest.raises(KeyUnavailable) as caught:
        other.unwrap(relabelled, CONTEXT)
    assert len(client.calls) == 2
    assert_redacted(caught.value)


def test_ciphertext_cannot_select_a_different_key_under_the_same_provider_uuid():
    client = KmsProtocolDouble()
    wrapper = provider(client).wrap(ROOT, CONTEXT)
    other_key = AwsKmsKeyProvider(client, provider_id=PROVIDER, key_arn=OTHER_ARN)
    with pytest.raises(KeyUnavailable) as caught:
        other_key.unwrap(wrapper, CONTEXT)
    assert client.calls[-1][1]["KeyId"] == OTHER_ARN
    assert_redacted(caught.value)


@pytest.mark.parametrize("root,context", [
    (b"x" * 31, CONTEXT), (bytearray(ROOT), CONTEXT), (ROOT, None),
])
def test_invalid_root_or_context_never_dispatches(root, context):
    client = KmsProtocolDouble()
    with pytest.raises(InvalidContext):
        provider(client).wrap(root, context)
    assert client.calls == []


@pytest.mark.parametrize("operation,kind", [
    ("encrypt", "coroutine"), ("decrypt", "callable"), ("encrypt", "async_generator"),
])
def test_async_sdk_methods_refuse_before_use_without_coroutine_warnings(operation, kind):
    async def coroutine(**request):
        raise AssertionError("async SDK operation must not run")

    class AsyncCallable:
        async def __call__(self, **request):
            raise AssertionError("async SDK operation must not run")

    async def async_generator(**request):
        yield {}

    client = KmsProtocolDouble()
    setattr(client, operation, {"coroutine": coroutine, "callable": AsyncCallable(),
                               "async_generator": async_generator}[kind])
    refused_at_construction = False
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always", RuntimeWarning)
        try:
            kms = provider(client)
        except InvalidContext:
            refused_at_construction = True
        else:
            # Exercise the old late failure so RED records the coroutine warning,
            # rather than merely inspecting the constructor's implementation.
            with pytest.raises(KeyUnavailable):
                if operation == "encrypt":
                    kms.wrap(ROOT, CONTEXT)
                else:
                    kms.unwrap(WrappedRoot(PROVIDER, CONTEXT, b"opaque"), CONTEXT)
        gc.collect()
    assert refused_at_construction, (
        "async SDK accepted until use; warning categories: "
        + repr([warning.category.__name__ for warning in emitted]))
    assert emitted == []
    assert client.calls == []


def test_altered_frozen_context_and_mismatched_wrapper_never_dispatch():
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    changed = replace(CONTEXT)
    object.__setattr__(changed, "purpose", "credential=" + SECRET)
    with pytest.raises(InvalidContext):
        kms.wrap(ROOT, changed)
    with pytest.raises(KeyUnavailable):
        kms.unwrap(wrapper, changed)
    with pytest.raises(KeyUnavailable):
        kms.unwrap(wrapper, replace(CONTEXT, generation=2))
    assert len(client.calls) == 1


@pytest.mark.parametrize("operation,field,value", [
    ("wrap", "KeyId", OTHER_ARN), ("unwrap", "KeyId", OTHER_ARN),
    ("wrap", "EncryptionAlgorithm", "RSAES_OAEP_SHA_256"),
    ("unwrap", "EncryptionAlgorithm", None),
    ("wrap", "CiphertextBlob", b""), ("wrap", "CiphertextBlob", b"x" * 6145),
    ("wrap", "CiphertextBlob", "base64-data"),
    ("unwrap", "Plaintext", b"x" * 31), ("unwrap", "Plaintext", b"x" * 33),
    ("unwrap", "Plaintext", bytearray(ROOT)),
])
def test_malformed_or_wrong_identity_response_never_releases_material(operation, field, value):
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    response = {"KeyId": ARN, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "CiphertextBlob": b"ciphertext", "Plaintext": ROOT}
    response[field] = value
    setattr(client, "encrypt" if operation == "wrap" else "decrypt", lambda **kw: response)
    with pytest.raises(KeyUnavailable) as caught:
        kms.wrap(ROOT, CONTEXT) if operation == "wrap" else kms.unwrap(wrapper, CONTEXT)
    assert_redacted(caught.value)


@pytest.mark.parametrize("operation", ["wrap", "unwrap"])
@pytest.mark.parametrize("already_closed", [False, True])
def test_coroutine_return_is_redacted_closed_and_healthy_sdk_retry_works(operation, already_closed):
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    method = "encrypt" if operation == "wrap" else "decrypt"
    original, calls, entered = getattr(client, method), [], []

    async def invalid_response():
        entered.append(True)
        raise AssertionError(SECRET)

    def unexpected(**request):
        calls.append(True)
        result = invalid_response()
        if already_closed:
            result.close()
        return result

    setattr(client, method, unexpected)
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always", RuntimeWarning)
        try:
            with pytest.raises(KeyUnavailable) as caught:
                kms.wrap(ROOT, CONTEXT) if operation == "wrap" else kms.unwrap(wrapper, CONTEXT)
            assert_redacted(caught.value)
            del caught
            gc.collect()
        finally:
            setattr(client, method, original)
    assert calls == [True]
    assert entered == []
    assert kms.unwrap(kms.wrap(ROOT, CONTEXT), CONTEXT) == ROOT
    assert emitted == []


@pytest.mark.parametrize("operation", ["wrap", "unwrap", "unwrap_async"])
def test_sdk_exception_is_redacted_without_adapter_retry(operation):
    client = KmsProtocolDouble()
    kms = provider(client)
    wrapper = kms.wrap(ROOT, CONTEXT)
    client.offline = True
    with pytest.raises(KeyUnavailable) as caught:
        if operation == "wrap":
            kms.wrap(ROOT, CONTEXT)
        elif operation == "unwrap":
            kms.unwrap(wrapper, CONTEXT)
        else:
            asyncio.run(kms.unwrap_async(wrapper, CONTEXT))
    assert len(client.calls) == 2
    assert_redacted(caught.value)


def test_base_exception_remains_observable():
    class Stop(BaseException):
        pass
    client = KmsProtocolDouble()
    kms = provider(client)
    def stop(**kw):
        raise Stop()
    client.encrypt = stop
    with pytest.raises(Stop):
        kms.wrap(ROOT, CONTEXT)


def test_rewrap_preserves_root_and_context_with_existing_provider_protocol():
    source, target = provider(), DevelopmentKeyProvider()
    wrapped = source.wrap(ROOT, CONTEXT)
    replacement = source.rewrap(wrapped, target, CONTEXT)
    assert replacement.context == CONTEXT
    assert target.unwrap(replacement, CONTEXT) == ROOT
    back = target.rewrap(replacement, source, CONTEXT)
    assert source.unwrap(back, CONTEXT) == ROOT


@pytest.mark.parametrize("fault", [
    "wrong_root", "short_material", "long_material", "mutable_material",
    "unwrap_outage", "identity_drift",
])
@pytest.mark.parametrize("source_factory", [provider, DevelopmentKeyProvider],
                         ids=["aws-sdk", "development"])
def test_rewrap_requires_exact_root_recovery_before_returning_target_custody(fault, source_factory):
    source = source_factory()
    wrapped = source.wrap(ROOT, CONTEXT)

    class Target(DevelopmentKeyProvider):
        def wrap(self, root, context):
            if fault == "wrong_root":
                root = b"x" * 32
            return super().wrap(root, context)

        def unwrap(self, wrapper, context):
            root = super().unwrap(wrapper, context)
            if fault == "short_material":
                return root[:-1]
            if fault == "long_material":
                return root + b"x"
            if fault == "mutable_material":
                return bytearray(root)
            if fault == "unwrap_outage":
                raise RuntimeError(SECRET)
            if fault == "identity_drift":
                self.provider_id = UUID(int=903)
            return root

    with pytest.raises(KeyUnavailable) as caught:
        source.rewrap(wrapped, Target(), CONTEXT)
    assert_redacted(caught.value)
    assert source.unwrap(wrapped, CONTEXT) == ROOT
    healthy = DevelopmentKeyProvider()
    replacement = source.rewrap(wrapped, healthy, CONTEXT)
    assert replacement.context == CONTEXT
    assert healthy.unwrap(replacement, CONTEXT) == ROOT


@pytest.mark.parametrize("source_factory", [provider, DevelopmentKeyProvider],
                         ids=["aws-sdk", "development"])
def test_rewrap_target_recovery_interruption_propagates_and_source_remains_usable(source_factory):
    source = source_factory()
    wrapped = source.wrap(ROOT, CONTEXT)

    class Target(DevelopmentKeyProvider):
        def unwrap(self, wrapper, context):
            raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        source.rewrap(wrapped, Target(), CONTEXT)
    assert source.unwrap(wrapped, CONTEXT) == ROOT


def test_cancelled_thread_result_does_not_warm_keyring():
    async def scenario():
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        client = KmsProtocolDouble()
        kms = provider(client)
        wrapper = kms.wrap(ROOT, CONTEXT)
        decrypt = client.decrypt
        def delayed(**kw):
            entered.set()
            try:
                assert release.wait(5), "test did not release SDK thread"
                return decrypt(**kw)
            finally:
                finished.set()
        client.decrypt = delayed
        ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1),
                       {PROVIDER: kms})
        task = asyncio.create_task(ring.prepare_async())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            # The event loop remains available while the SDK call blocks.
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            release.set()
        assert await asyncio.to_thread(finished.wait, 5)
        client.offline = True
        with pytest.raises(KeyUnavailable):
            await ring.prepare_async()
        client.offline = False
        keys = await ring.prepare_async()
        field, record = descriptor(), UUID(int=5)
        assert open_text(seal_text("fresh", field, CONTEXT.tenant_id, record, keys),
                         field, CONTEXT.tenant_id, record, keys) == "fresh"
    asyncio.run(scenario())


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires the POSIX fork boundary")
def test_inherited_provider_refuses_before_sdk_use_and_fresh_child_provider_works():
    kms = provider()
    wrapper = kms.wrap(ROOT, CONTEXT)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            for call in (lambda: kms.wrap(ROOT, CONTEXT),
                         lambda: kms.unwrap(wrapper, CONTEXT),
                         lambda: asyncio.run(kms.unwrap_async(wrapper, CONTEXT))):
                try:
                    call()
                except KeyUnavailable:
                    continue
                os._exit(2)
            fresh = provider()
            assert fresh.unwrap(fresh.wrap(ROOT, CONTEXT), CONTEXT) == ROOT
            os.write(write_fd, b"refused inherited; fresh works")
            os._exit(0)
        except BaseException:
            os._exit(3)
    os.close(write_fd)
    result = os.read(read_fd, 100)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert result == b"refused inherited; fresh works"
