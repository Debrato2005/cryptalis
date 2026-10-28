"""Explicit optional boto3/botocore compatibility profile; no live AWS calls."""

import asyncio
import base64
import json
import threading
import traceback
from uuid import UUID

import pytest

boto3 = pytest.importorskip("boto3", reason="Explicit profile requires an isolated boto3 SDK installation")
import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError
from botocore.stub import Stubber

from cryptalis.crypto import DevelopmentKeyProvider, KeyPolicy, Keyring, KeyUnavailable, WrappedRoot
from cryptalis.crypto.aws_kms import AwsKmsKeyProvider
from test_aws_kms import ARN, CONTEXT, OTHER_ARN, PROVIDER, ROOT, SECRET


ENCRYPTION_CONTEXT = {
    "cryptalis:format": "CF1/aws-kms-wrap/v1",
    "cryptalis:provider": str(PROVIDER),
    "cryptalis:domain": str(CONTEXT.domain_id),
    "cryptalis:tenant": str(CONTEXT.tenant_id),
    "cryptalis:purpose": "payload",
    "cryptalis:root": str(CONTEXT.root_id),
    "cryptalis:generation": "1",
}
CIPHERTEXT = b"synthetic-opaque-sdk-response"


def request(field, value):
    return {"KeyId": ARN, field: value, "EncryptionContext": dict(ENCRYPTION_CONTEXT),
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}


def response(field, value):
    return {"KeyId": ARN, field: value, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"}


@pytest.fixture
def sdk(monkeypatch):
    # Explicit synthetic credentials bypass credential resolution and IMDS.
    def deny_credential_discovery(*args, **kwargs):
        raise AssertionError("SDK profile attempted credential discovery")
    monkeypatch.setattr(botocore.session.Session, "get_credentials", deny_credential_discovery)
    client = boto3.session.Session().client(
        "kms", aws_access_key_id="synthetic-access-key",
        aws_secret_access_key="synthetic-secret-key", region_name="us-east-1",
        endpoint_url="https://kms.example.invalid",
        config=Config(connect_timeout=1, read_timeout=1,
                      retries={"total_max_attempts": 1}),
    )
    sent = []
    def deny_transport(request, **kwargs):
        sent.append(request)
        raise AssertionError("SDK profile attempted network transport")
    monkeypatch.setattr(client._endpoint.http_session, "send", deny_transport)
    with pytest.raises(AssertionError, match="attempted network"):
        client._endpoint.http_session.send(None)
    sent.clear()
    stubber = Stubber(client)
    with stubber:
        yield client, stubber, AwsKmsKeyProvider(client, provider_id=PROVIDER, key_arn=ARN)
        stubber.assert_no_pending_responses()
    client.close()
    assert sent == []


def test_sdk_serializes_exact_encrypt_and_decrypt_context_before_stubbed_response(sdk):
    client, stubber, provider = sdk
    serialized = []
    def observe(model, params, **kwargs):
        serialized.append((model.name, json.loads(params["body"])))
    # Stubber short-circuits this public event at first priority. Register the
    # observer before reactivation so the real serializer output is observed.
    stubber.deactivate()
    client.meta.events.register_first("before-call.*.*", observe)
    stubber.activate()
    stubber.add_response("encrypt", response("CiphertextBlob", CIPHERTEXT), request("Plaintext", ROOT))
    stubber.add_response("decrypt", response("Plaintext", ROOT), request("CiphertextBlob", CIPHERTEXT))
    wrapper = provider.wrap(ROOT, CONTEXT)
    assert provider.unwrap(wrapper, CONTEXT) == ROOT
    assert serialized == [
        ("Encrypt", request("Plaintext", base64.b64encode(ROOT).decode("ascii"))),
        ("Decrypt", request("CiphertextBlob", base64.b64encode(CIPHERTEXT).decode("ascii"))),
    ]


@pytest.mark.parametrize("operation,error_code", [
    ("encrypt", "AccessDeniedException"), ("decrypt", "InvalidCiphertextException"),
    ("decrypt", "DisabledException"), ("decrypt", "ThrottlingException"),
])
def test_actual_sdk_client_errors_are_typed_redacted_and_not_retried(sdk, operation, error_code):
    client, stubber, provider = sdk
    dispatches = []
    def observe(model, **kwargs):
        dispatches.append(model.name)
    client.meta.events.register("before-parameter-build.kms", observe)
    field, value = ("Plaintext", ROOT) if operation == "encrypt" else ("CiphertextBlob", CIPHERTEXT)
    expected = request(field, value)
    stubber.add_client_error(operation, service_error_code=error_code, service_message=SECRET,
                            http_status_code=400, expected_params=expected)
    # Positive control: the real SDK exception formatter exposes the supplied message.
    control = ClientError({"Error": {"Code": error_code, "Message": SECRET}}, operation)
    assert SECRET in "".join(traceback.format_exception(control))
    with pytest.raises(KeyUnavailable) as caught:
        if operation == "encrypt":
            provider.wrap(ROOT, CONTEXT)
        else:
            provider.unwrap(WrappedRoot(PROVIDER, CONTEXT, CIPHERTEXT), CONTEXT)
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert caught.value.operation_id
    assert dispatches == [operation.capitalize()]


@pytest.mark.parametrize("changes", [
    {"KeyId": OTHER_ARN}, {"EncryptionAlgorithm": "RSAES_OAEP_SHA_256"},
    {"Plaintext": b"short"}, {"Plaintext": b"x" * 33}, {"Plaintext": None},
])
def test_sdk_model_valid_response_still_requires_exact_adapter_material(sdk, changes):
    _, stubber, provider = sdk
    reply = response("Plaintext", ROOT)
    reply.update(changes)
    if reply["Plaintext"] is None:
        del reply["Plaintext"]
    # Stubber validates provided output fields against the real KMS service model.
    stubber.add_response("decrypt", reply, request("CiphertextBlob", CIPHERTEXT))
    with pytest.raises(KeyUnavailable):
        provider.unwrap(WrappedRoot(PROVIDER, CONTEXT, CIPHERTEXT), CONTEXT)


def test_real_sdk_model_rejects_wrong_output_type_before_use(sdk):
    _, stubber, _ = sdk
    with pytest.raises(ParamValidationError):
        stubber.add_response("decrypt", response("Plaintext", 42))


@pytest.mark.parametrize("source_kind", ["aws-sdk", "development"])
@pytest.mark.parametrize("recovery", [
    "exact_root", "wrong_root", "short_material", "wrong_key", "disabled",
])
def test_direct_rewrap_requires_actual_sdk_target_recovery(sdk, source_kind, recovery):
    client, stubber, target = sdk
    source_id = UUID(int=902)
    source_context = dict(ENCRYPTION_CONTEXT, **{"cryptalis:provider": str(source_id)})
    source_request = {
        "KeyId": OTHER_ARN, "CiphertextBlob": b"source-opaque-wrapper",
        "EncryptionContext": source_context, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
    }
    source_response = dict(response("Plaintext", ROOT), KeyId=OTHER_ARN)
    if source_kind == "aws-sdk":
        source = AwsKmsKeyProvider(client, provider_id=source_id, key_arn=OTHER_ARN)
        original = WrappedRoot(source_id, CONTEXT, b"source-opaque-wrapper")
        stubber.add_response("decrypt", source_response, source_request)
    else:
        source = DevelopmentKeyProvider()
        original = source.wrap(ROOT, CONTEXT)

    stubber.add_response("encrypt", response("CiphertextBlob", CIPHERTEXT), request("Plaintext", ROOT))
    if recovery == "disabled":
        stubber.add_client_error("decrypt", service_error_code="DisabledException",
                                service_message=SECRET, http_status_code=400,
                                expected_params=request("CiphertextBlob", CIPHERTEXT))
    else:
        recovered = {"exact_root": ROOT, "wrong_root": b"x" * 32,
                     "short_material": b"short", "wrong_key": ROOT}[recovery]
        reply = response("Plaintext", recovered)
        if recovery == "wrong_key":
            reply["KeyId"] = OTHER_ARN
        stubber.add_response("decrypt", reply, request("CiphertextBlob", CIPHERTEXT))

    if recovery == "exact_root":
        replacement = source.rewrap(original, target, CONTEXT)
        assert replacement == WrappedRoot(PROVIDER, CONTEXT, CIPHERTEXT)
    else:
        with pytest.raises(KeyUnavailable) as caught:
            source.rewrap(original, target, CONTEXT)
        assert SECRET not in "".join(traceback.format_exception(caught.value))
        assert caught.value.operation_id

    # A failed recovery never retires source custody. A healthy retry uses the
    # original source root/context and must perform a new target recovery proof.
    if source_kind == "aws-sdk":
        stubber.add_response("decrypt", source_response, source_request)
    assert source.unwrap(original, CONTEXT) == ROOT
    if source_kind == "aws-sdk":
        stubber.add_response("decrypt", source_response, source_request)
    stubber.add_response("encrypt", response("CiphertextBlob", CIPHERTEXT), request("Plaintext", ROOT))
    stubber.add_response("decrypt", response("Plaintext", ROOT), request("CiphertextBlob", CIPHERTEXT))
    replacement = source.rewrap(original, target, CONTEXT)
    stubber.add_response("decrypt", response("Plaintext", ROOT), request("CiphertextBlob", CIPHERTEXT))
    assert target.unwrap(replacement, CONTEXT) == ROOT


def test_real_sdk_blocking_call_cancellation_does_not_publish_keyring_material(sdk):
    client, stubber, provider = sdk
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    original = client.decrypt
    def delayed(**kwargs):
        entered.set()
        try:
            assert release.wait(5), "test did not release the SDK call"
            return original(**kwargs)
        finally:
            completed.set()
    client.decrypt = delayed
    expected = request("CiphertextBlob", CIPHERTEXT)
    stubber.add_response("decrypt", response("Plaintext", ROOT), expected)
    stubber.add_client_error("decrypt", service_error_code="DisabledException",
                            service_message=SECRET, expected_params=expected)
    stubber.add_response("decrypt", response("Plaintext", ROOT), expected)
    wrapper = WrappedRoot(PROVIDER, CONTEXT, CIPHERTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1),
                   {PROVIDER: provider})
    async def scenario():
        pending = asyncio.create_task(ring.prepare_async())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        finally:
            release.set()
        assert await asyncio.to_thread(completed.wait, 5)
        with pytest.raises(KeyUnavailable):
            await ring.prepare_async()
        assert await ring.prepare_async()
    asyncio.run(scenario())
