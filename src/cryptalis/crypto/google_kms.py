"""Optional Google Cloud KMS bridge for a host-owned synchronous SDK client.

Install ``cryptalis[gcp]``. The host owns credentials, authenticated TLS transport
and client lifetime. No key creation, discovery, retry, rotation or deletion is
performed here. The service chooses the decrypting version inside the pinned
CryptoKey; its decrypt response does not identify that version. Complete wrapper
context, including the configured encryption version, is authenticated as AAD.
"""

import asyncio
from hmac import compare_digest
import inspect
import math
import os
import re
from types import CoroutineType
from uuid import UUID

from .keys import (InvalidContext, KeyContext, KeyProvider, KeyUnavailable,
                   ProviderAuthenticationUnavailable, WrappedRoot, tuple_bytes)


_VERSION = re.compile(
    r"projects/[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}/locations/[a-z][a-z0-9-]{0,62}"
    r"/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}"
    r"/cryptoKeyVersions/[1-9][0-9]{0,9}"
)


class GoogleKmsKeyProvider:
    """Pin one provider UUID, encryption version and SOFTWARE/HSM protection level.

    CRC32C detects transport corruption, not malicious forgery. KMS authenticates
    AAD and wrapped material. No plaintext checksum is retained. Keyring owns root
    caching and leases. Construct a fresh client/provider after fork. Cancellation
    cannot stop an already dispatched blocking SDK call; late results are not cached.
    Python bytes do not provide a verified zeroization guarantee.
    """

    def __init__(self, client, *, provider_id: UUID, key_version: str,
                 protection_level: str = 'SOFTWARE', timeout: float = 10):
        try:
            if (type(provider_id) is not UUID or provider_id.int == 0
                    or type(key_version) is not str or _VERSION.fullmatch(key_version) is None
                    or type(protection_level) is not str or protection_level not in ('SOFTWARE', 'HSM')
                    or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60):
                raise InvalidContext()
            for operation in (client.encrypt, client.decrypt):
                if (not callable(operation) or any(
                        inspect.iscoroutinefunction(candidate) or inspect.isasyncgenfunction(candidate)
                        for candidate in (operation, getattr(operation, '__call__', None)))):
                    raise InvalidContext()
        except Exception:
            raise InvalidContext() from None
        try:
            import google_crc32c
            from google.cloud import kms_v1
        except Exception:
            raise KeyUnavailable() from None
        self._client = client
        self._provider_id = provider_id
        self._version = key_version
        self._key = key_version.rsplit('/cryptoKeyVersions/', 1)[0]
        self._level = kms_v1.ProtectionLevel[protection_level]
        self._encrypt_response = kms_v1.EncryptResponse
        self._decrypt_response = kms_v1.DecryptResponse
        self._checksum = google_crc32c.value
        self._timeout = timeout
        self._pid = os.getpid()

    @property
    def provider_id(self):
        return self._provider_id

    @property
    def key_version(self):
        return self._version

    def _check(self):
        if self._pid != os.getpid():
            raise KeyUnavailable()

    def _aad(self, context):
        if (type(context) is not KeyContext
                or any(type(value) is not UUID for value in
                       (context.domain_id, context.tenant_id, context.root_id))
                or type(context.purpose) is not str):
            raise InvalidContext()
        KeyContext(context.domain_id, context.tenant_id, context.purpose,
                   context.root_id, context.generation)
        return tuple_bytes(b'CF1/google-kms-wrap/v1', self.provider_id.bytes,
            self.key_version.encode('ascii'), self._level.name.encode('ascii'), context.domain_id.bytes,
            context.tenant_id.bytes, context.purpose.encode('ascii'), context.root_id.bytes,
            context.generation.to_bytes(4, 'big'))

    def _response(self, response, expected_type, field, minimum, maximum):
        if type(response) is CoroutineType:
            response.close()
        if type(response) is not expected_type or response.protection_level != self._level:
            raise KeyUnavailable()
        value = getattr(response, field)
        checksum = field + '_crc32c'
        if (type(value) is not bytes or not minimum <= len(value) <= maximum
                or checksum not in response or getattr(response, checksum) != self._checksum(value)):
            raise KeyUnavailable()
        return value

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot:
        self._check()
        if type(root) is not bytes or len(root) != 32:
            raise InvalidContext()
        aad = self._aad(context)
        try:
            response = self._client.encrypt(request=dict(name=self.key_version, plaintext=root,
                additional_authenticated_data=aad, plaintext_crc32c=self._checksum(root),
                additional_authenticated_data_crc32c=self._checksum(aad)),
                retry=None, timeout=self._timeout)
            sealed = self._response(response, self._encrypt_response, 'ciphertext', 1, 65536)
            if (response.name != self.key_version or response.verified_plaintext_crc32c is not True
                    or response.verified_additional_authenticated_data_crc32c is not True):
                raise KeyUnavailable()
            return WrappedRoot(self.provider_id, context, sealed)
        except Exception:
            raise KeyUnavailable() from None

    def unwrap(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        try:
            aad = self._aad(context)
            if (type(wrapper) is not WrappedRoot or wrapper.provider_id != self.provider_id
                    or wrapper.context != context or type(wrapper.sealed) is not bytes
                    or not 1 <= len(wrapper.sealed) <= 65536):
                raise KeyUnavailable()
            response = self._client.decrypt(request=dict(name=self._key, ciphertext=wrapper.sealed,
                additional_authenticated_data=aad, ciphertext_crc32c=self._checksum(wrapper.sealed),
                additional_authenticated_data_crc32c=self._checksum(aad)),
                retry=None, timeout=self._timeout)
            return self._response(response, self._decrypt_response, 'plaintext', 32, 32)
        except Exception:
            raise KeyUnavailable() from None

    async def unwrap_async(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
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
                    or result.provider_id != identity or new_provider.provider_id != identity):
                raise KeyUnavailable()
            recovered = new_provider.unwrap(result, context)
            if (type(recovered) is not bytes or len(recovered) != 32
                    or not compare_digest(root, recovered) or new_provider.provider_id != identity):
                raise KeyUnavailable()
            return result
        except ProviderAuthenticationUnavailable:
            raise ProviderAuthenticationUnavailable() from None
        except Exception:
            raise KeyUnavailable() from None
