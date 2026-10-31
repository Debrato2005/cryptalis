"""Optional OpenBao Transit bridge for a caller-supplied synchronous SDK.

Supply ``hvac.Client(...).secrets.transit``. The host owns endpoint trust,
credentials, namespaces, timeouts and bounded SDK retries. This bridge neither
discovers credentials nor administers keys. Construct fresh clients after fork.
"""

import asyncio
import base64
import inspect
import os
import re
from types import CoroutineType
from uuid import UUID

from .keys import InvalidContext, KeyContext, KeyProvider, KeyUnavailable, WrappedRoot, tuple_bytes


_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"


class OpenBaoTransitKeyProvider:
    """Pin a provider UUID, mount, non-derived AES-256-GCM key and version.

    The trusted host must assign a distinct UUID to each configured authority
    and key version. A Transit name is not an immutable key identifier; service
    administration and authenticated endpoint configuration remain host duties.
    Python bytes provide no verified zeroization guarantee.
    """

    def __init__(self, transit, *, provider_id: UUID, mount_point: str,
                 key_name: str, key_version: int):
        if (type(provider_id) is not UUID or provider_id.int == 0
                or type(mount_point) is not str or len(mount_point) > 255
                or re.fullmatch(rf"{_SEGMENT}(?:/{_SEGMENT})*", mount_point) is None
                or type(key_name) is not str or re.fullmatch(_SEGMENT, key_name) is None
                or type(key_version) is not int or not 1 <= key_version <= 0x7FFFFFFF):
            raise InvalidContext()
        try:
            for operation in (transit.read_key, transit.encrypt_data, transit.decrypt_data):
                if (not callable(operation)
                        or any(inspect.iscoroutinefunction(candidate)
                               or inspect.isasyncgenfunction(candidate)
                               for candidate in (operation, getattr(operation, "__call__", None)))):
                    raise InvalidContext()
        except Exception:
            raise InvalidContext() from None
        self._transit = transit
        self._provider_id = provider_id
        self._mount = mount_point
        self._name = key_name
        self._version = key_version
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
                or any(type(value) is not UUID for value in (
                    context.domain_id, context.tenant_id, context.root_id))
                or type(context.purpose) is not str):
            raise InvalidContext()
        KeyContext(context.domain_id, context.tenant_id, context.purpose,
                   context.root_id, context.generation)
        return base64.b64encode(tuple_bytes(
            b"CF1/openbao-transit-wrap/v1", self.provider_id.bytes,
            self._mount.encode("ascii"), self._name.encode("ascii"),
            self._version.to_bytes(4, "big"), context.domain_id.bytes,
            context.tenant_id.bytes, context.purpose.encode("ascii"),
            context.root_id.bytes, context.generation.to_bytes(4, "big"),
        )).decode("ascii")

    @staticmethod
    def _data(response):
        if type(response) is CoroutineType:
            response.close()
        if type(response) is not dict or type(response.get("data")) is not dict:
            raise KeyUnavailable()
        return response["data"]

    def _metadata(self):
        data = self._data(self._transit.read_key(name=self._name, mount_point=self._mount))
        if (type(data.get("name")) is not str or data["name"] != self._name
                or type(data.get("type")) is not str or data["type"] != "aes256-gcm96"
                or any(data.get(flag) is not False for flag in (
                    "derived", "exportable", "allow_plaintext_backup", "deletion_allowed"))
                or any(data.get(flag) is not True for flag in (
                    "supports_encryption", "supports_decryption"))
                or type(data.get("keys")) is not dict or str(self._version) not in data["keys"]):
            raise KeyUnavailable()
        # Non-derived keys cannot enable convergent encryption. The service,
        # rather than this adapter, generates a fresh nonce for every wrap.

    def _ciphertext(self, value):
        if type(value) is not str or not 1 <= len(value) <= 8192:
            raise KeyUnavailable()
        prefix = f"vault:v{self._version}:"
        if not value.startswith(prefix):
            raise KeyUnavailable()
        encoded = value[len(prefix):]
        opaque = base64.b64decode(encoded, validate=True)
        if not opaque or base64.b64encode(opaque).decode("ascii") != encoded:
            raise KeyUnavailable()
        return value.encode("ascii")

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot:
        self._check()
        if type(root) is not bytes or len(root) != 32:
            raise InvalidContext()
        aad = self._aad(context)
        try:
            self._metadata()
            response = self._transit.encrypt_data(
                name=self._name, mount_point=self._mount, key_version=self._version,
                plaintext=base64.b64encode(root).decode("ascii"), associated_data=aad,
            )
            sealed = self._ciphertext(self._data(response).get("ciphertext"))
            return WrappedRoot(self.provider_id, context, sealed)
        except Exception:
            raise KeyUnavailable() from None

    def unwrap(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        try:
            aad = self._aad(context)
            if (type(wrapper) is not WrappedRoot or wrapper.provider_id != self.provider_id
                    or wrapper.context != context or type(wrapper.sealed) is not bytes
                    or not 1 <= len(wrapper.sealed) <= 8192):
                raise KeyUnavailable()
            ciphertext = wrapper.sealed.decode("ascii")
            self._ciphertext(ciphertext)
            self._metadata()
            data = self._data(self._transit.decrypt_data(
                name=self._name, mount_point=self._mount,
                ciphertext=ciphertext, associated_data=aad,
            ))
            encoded = data.get("plaintext")
            if type(encoded) is not str or len(encoded) != 44:
                raise KeyUnavailable()
            root = base64.b64decode(encoded, validate=True)
            if len(root) != 32 or base64.b64encode(root).decode("ascii") != encoded:
                raise KeyUnavailable()
            return root
        except Exception:
            raise KeyUnavailable() from None

    async def unwrap_async(self, wrapper: WrappedRoot, context: KeyContext) -> bytes:
        self._check()
        # Cancellation rejects publication, but cannot stop dispatched SDK I/O.
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
            return result
        except Exception:
            raise KeyUnavailable() from None
