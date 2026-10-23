"""Optional AWS KMS bridge for a caller-supplied synchronous boto3 KMS client.

The host owns SDK installation, credentials, endpoint, timeouts and bounded
retries. This module performs no discovery, retry or key administration.
Encryption context is public metadata and can appear in AWS CloudTrail.
An async cancellation cannot stop an already dispatched blocking SDK call.
Python bytes do not provide a verified root-zeroization guarantee.
"""

import asyncio
import os
import re
from uuid import UUID

from .keys import InvalidContext, KeyContext, KeyProvider, KeyUnavailable, WrappedRoot


_KEY_ARN = re.compile(
    r"arn:[a-z0-9-]+:kms:[a-z0-9-]+:[0-9]{12}:key/"
    r"(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})"
)


class AwsKmsKeyProvider:
    """Pin one provider UUID and one full key ARN, with exact wrapping context.

    Supply a configured, synchronous boto3 KMS client. No live AWS custody,
    workload identity, IAM, retry or deletion qualification follows from this
    adapter. Construct a fresh client and provider after fork.
    """

    def __init__(self, client, *, provider_id: UUID, key_arn: str):
        if (type(provider_id) is not UUID or provider_id.int == 0
                or type(key_arn) is not str or _KEY_ARN.fullmatch(key_arn) is None):
            raise InvalidContext()
        try:
            if not callable(client.encrypt) or not callable(client.decrypt):
                raise InvalidContext()
        except Exception:
            raise InvalidContext() from None
        self._client = client
        self._provider_id = provider_id
        self._key_arn = key_arn
        self._pid = os.getpid()

    @property
    def provider_id(self):
        return self._provider_id

    @property
    def key_arn(self):
        return self._key_arn

    def _check(self):
        if self._pid != os.getpid():
            raise KeyUnavailable()

    def _context(self, context):
        if (type(context) is not KeyContext
                or any(type(value) is not UUID for value in (
                    context.domain_id, context.tenant_id, context.root_id))
                or type(context.purpose) is not str):
            raise InvalidContext()
        # Revalidate before dispatch even if a frozen object was altered.
        KeyContext(context.domain_id, context.tenant_id, context.purpose,
                   context.root_id, context.generation)
        return {
            "cryptalis:format": "CF1/aws-kms-wrap/v1",
            "cryptalis:provider": str(self.provider_id),
            "cryptalis:domain": str(context.domain_id),
            "cryptalis:tenant": str(context.tenant_id),
            "cryptalis:purpose": context.purpose,
            "cryptalis:root": str(context.root_id),
            "cryptalis:generation": str(context.generation),
        }

    def _response(self, response, field, minimum, maximum):
        if (type(response) is not dict
                or type(response.get("KeyId")) is not str
                or response["KeyId"] != self.key_arn
                or type(response.get("EncryptionAlgorithm")) is not str
                or response["EncryptionAlgorithm"] != "SYMMETRIC_DEFAULT"):
            raise KeyUnavailable()
        value = response.get(field)
        if type(value) is not bytes or not minimum <= len(value) <= maximum:
            raise KeyUnavailable()
        return value

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot:
        self._check()
        if type(root) is not bytes or len(root) != 32:
            raise InvalidContext()
        encryption_context = self._context(context)
        try:
            response = self._client.encrypt(
                KeyId=self.key_arn, Plaintext=root,
                EncryptionContext=encryption_context,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
            )
            sealed = self._response(response, "CiphertextBlob", 1, 6144)
            return WrappedRoot(self.provider_id, context, sealed)
        except Exception:
            raise KeyUnavailable() from None

    def unwrap(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        try:
            encryption_context = self._context(context)
            if (type(wrapper) is not WrappedRoot
                    or wrapper.provider_id != self.provider_id
                    or wrapper.context != context or type(wrapper.sealed) is not bytes
                    or not 1 <= len(wrapper.sealed) <= 6144):
                raise KeyUnavailable()
            response = self._client.decrypt(
                KeyId=self.key_arn, CiphertextBlob=wrapper.sealed,
                EncryptionContext=encryption_context,
                EncryptionAlgorithm="SYMMETRIC_DEFAULT",
            )
            return self._response(response, "Plaintext", 32, 32)
        except Exception:
            raise KeyUnavailable() from None

    async def unwrap_async(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        # Cancellation propagates; no late thread result enters Keyring's cache.
        return await asyncio.to_thread(self.unwrap, wrapper, context)

    def rewrap(self, wrapper: WrappedRoot, new_provider: KeyProvider,
               context: KeyContext) -> WrappedRoot:
        root = self.unwrap(wrapper, context)
        try:
            identity = new_provider.provider_id
            if type(identity) is not UUID or identity.int == 0:
                raise KeyUnavailable()
            result = new_provider.wrap(root, context)
            if (type(result) is not WrappedRoot or result.context != context
                    or result.provider_id != identity
                    or new_provider.provider_id != identity):
                raise KeyUnavailable()
            return result
        except Exception:
            raise KeyUnavailable() from None
