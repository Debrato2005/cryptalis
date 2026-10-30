"""Optional OpenBao Transit envelope provider using the maintained hvac client.

Install ``cryptalis[openbao]``. The host supplies renewable authentication through
a token callback; the provider never creates keys, rotates them or grants access.
Transit authenticates the complete root context. CF1 data encryption is unchanged.
The service, host credentials and CA configuration are trusted boundaries.
"""

import asyncio
import base64
from contextlib import contextmanager
from hmac import compare_digest
import inspect
import math
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import UUID

from .keys import (InvalidContext, KeyContext, KeyProvider, KeyUnavailable,
                   ProviderAuthenticationUnavailable, WrappedRoot, tuple_bytes)


_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


def _https_endpoint(endpoint, ca_cert, timeout):
    try:
        parsed = urlsplit(endpoint)
        if (type(endpoint) is not str or parsed.scheme != 'https' or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                or any(c in endpoint for c in ('\\', '%'))
                or any(ord(c) < 33 or ord(c) > 126 for c in endpoint)
                or parsed.port is not None and not 1 <= parsed.port <= 65535
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 60
                or ca_cert is not None and (type(ca_cert) is not str
                    or not Path(ca_cert).is_absolute() or not Path(ca_cert).is_file())):
            raise InvalidContext()
    except Exception:
        raise InvalidContext() from None
    return endpoint.rstrip('/')


class OpenBaoAppRoleToken:
    """Acquire a fresh short-lived service token using explicit workload credentials.

    Supply this callable as Transit provider ``token``. ``secret_id`` supplies the
    current SecretID; it is never invoked during construction. Expected policies
    and the maximum issued TTL are host authority. No token is cached, renewed or
    automatically retried. Failed login/validation may already have issued a token.
    The issued token must be able to read its exact role configuration. Current
    SecretID binding and finite role SecretID TTL are verified before release;
    delivery, prior SecretID retirement and policy contents remain host duties.
    """

    def __init__(self, *, endpoint: str, role_name: str, role_id: str, secret_id,
                 policies: tuple[str, ...], mount: str = 'approle',
                 max_token_ttl: int = 300, ca_cert: str | None = None, timeout: float = 10):
        self._endpoint = _https_endpoint(endpoint, ca_cert, timeout)
        try:
            if (type(role_name) is not str or not _SEGMENT.fullmatch(role_name)
                    or type(role_id) is not str or not 1 <= len(role_id) <= 4096
                    or any(ord(c) < 33 or ord(c) > 126 for c in role_id)
                    or not callable(secret_id) or any(inspect.iscoroutinefunction(candidate)
                        or inspect.isasyncgenfunction(candidate)
                        for candidate in (secret_id, getattr(secret_id, '__call__', None)))
                    or type(policies) is not tuple or not 1 <= len(policies) <= 64
                    or any(type(policy) is not str or not _SEGMENT.fullmatch(policy) for policy in policies)
                    or len(set(policies)) != len(policies) or 'root' in policies
                    or type(mount) is not str or not 1 <= len(mount) <= 512
                    or not all(_SEGMENT.fullmatch(part) for part in mount.split('/'))
                    or type(max_token_ttl) is not int or not 1 <= max_token_ttl <= 3600):
                raise InvalidContext()
        except Exception:
            raise InvalidContext() from None
        self._role_name, self._role_id = role_name, role_id
        self._secret_id, self._policies = secret_id, set(policies)
        self._mount, self._max_token_ttl = mount, max_token_ttl
        self._ca_cert, self._timeout, self._pid = ca_cert, timeout, os.getpid()

    def __call__(self):
        if self._pid != os.getpid():
            raise ProviderAuthenticationUnavailable()
        try:
            secret = self._secret_id()
            if inspect.iscoroutine(secret): secret.close()
            if (type(secret) is not str or not 1 <= len(secret) <= 4096
                    or any(ord(c) < 33 or ord(c) > 126 for c in secret)):
                raise ProviderAuthenticationUnavailable()
            import hvac
            # An empty explicit token suppresses hvac's ambient VAULT_TOKEN and
            # token-file lookup. Login uses only the supplied AppRole credentials.
            client = hvac.Client(url=self._endpoint, token='', verify=self._ca_cert or True,
                                 allow_redirects=False, timeout=self._timeout)
            try:
                response = client.auth.approle.login(role_id=self._role_id, secret_id=secret,
                    mount_point=self._mount, use_token=False)
                if (type(response) is not dict or response.get('warnings') or response.get('errors')
                        or type(response.get('auth')) is not dict):
                    raise ProviderAuthenticationUnavailable()
                auth = response['auth']
                token, policies = auth.get('client_token'), auth.get('token_policies')
                if (type(token) is not str or not 1 <= len(token) <= 4096
                        or any(ord(c) < 33 or ord(c) > 126 for c in token)
                        or type(policies) is not list or any(type(p) is not str for p in policies)
                        or len(policies) != len(self._policies) or set(policies) != self._policies
                        or auth.get('identity_policies') not in (None, [])
                        or type(auth.get('metadata')) is not dict
                        or auth['metadata'].get('role_name') != self._role_name
                        or auth.get('token_type') != 'service'
                        or type(auth.get('lease_duration')) is not int
                        or not 1 <= auth['lease_duration'] <= self._max_token_ttl
                        or type(auth.get('num_uses')) is not int or auth['num_uses'] != 0):
                    raise ProviderAuthenticationUnavailable()
                if 'policies' in auth and (type(auth['policies']) is not list
                        or any(type(p) is not str for p in auth['policies'])
                        or len(auth['policies']) != len(self._policies)
                        or set(auth['policies']) != self._policies):
                    raise ProviderAuthenticationUnavailable()
                client.token = token
                role = client.auth.approle.read_role(role_name=self._role_name, mount_point=self._mount)
                if (type(role) is not dict or role.get('warnings') or role.get('errors')
                        or type(role.get('data')) is not dict):
                    raise ProviderAuthenticationUnavailable()
                data = role['data']
                if (data.get('bind_secret_id') is not True
                        or type(data.get('secret_id_ttl')) is not int or data['secret_id_ttl'] <= 0
                        or data.get('token_type') != 'service'
                        or type(data.get('token_policies')) is not list
                        or any(type(p) is not str for p in data['token_policies'])
                        or len(data['token_policies']) != len(self._policies)
                        or set(data['token_policies']) != self._policies):
                    raise ProviderAuthenticationUnavailable()
                return token
            finally:
                client.session.close()
        except Exception:
            raise ProviderAuthenticationUnavailable() from None


class OpenBaoTransitKeyProvider:
    """Pin a logical provider, Transit mount, existing AES-256 key and version.

    ``token`` is a synchronous callable returning a current least-privilege token.
    HTTPS certificate/hostname verification is mandatory. ``ca_cert`` optionally
    names a private CA bundle. Each operation owns its SDK session; no session or
    plaintext key survives in this provider. Keyring owns bounded root caching.
    Timeouts bound individual SDK network waits, not token acquisition or a total
    operation deadline. Cancellation cannot stop an already dispatched SDK call.
    """

    def __init__(self, *, endpoint: str, token, provider_id: UUID,
                 key_name: str, key_version: int, mount: str = "transit",
                 ca_cert: str | None = None, timeout: float = 10):
        normalized_endpoint = _https_endpoint(endpoint, ca_cert, timeout)
        try:
            if (type(provider_id) is not UUID or provider_id.int == 0
                    or type(key_name) is not str or not _SEGMENT.fullmatch(key_name)
                    or type(mount) is not str or not 1 <= len(mount) <= 512
                    or not all(_SEGMENT.fullmatch(part) for part in mount.split("/"))
                    or type(key_version) is not int or not 1 <= key_version <= 0x7fffffff
                    or not callable(token)
                    or any(inspect.iscoroutinefunction(candidate) or inspect.isasyncgenfunction(candidate)
                               for candidate in (token, getattr(token, "__call__", None)))):
                raise InvalidContext()
        except Exception:
            raise InvalidContext() from None
        self._endpoint = normalized_endpoint
        self._token = token
        self._provider_id = provider_id
        self._key_name = key_name
        self._key_version = key_version
        self._mount = mount
        self._ca_cert = ca_cert
        self._timeout = timeout
        self._pid = os.getpid()

    @property
    def provider_id(self):
        return self._provider_id

    def _check(self):
        if self._pid != os.getpid():
            raise KeyUnavailable()

    def _aad(self, context):
        if type(context) is not KeyContext:
            raise InvalidContext()
        KeyContext(context.domain_id, context.tenant_id, context.purpose,
                   context.root_id, context.generation)
        return base64.b64encode(tuple_bytes(
            b"CF1/openbao-transit-wrap/v1", self.provider_id.bytes,
            self._mount.encode("ascii"), self._key_name.encode("ascii"),
            self._key_version.to_bytes(4, "big"), context.domain_id.bytes,
            context.tenant_id.bytes, context.purpose.encode("ascii"),
            context.root_id.bytes, context.generation.to_bytes(4, "big"),
        )).decode("ascii")

    @contextmanager
    def _client(self):
        import hvac  # Optional dependency; construction/import performs no network work.

        token = self._token()
        if inspect.iscoroutine(token):
            token.close()
        if (type(token) is not str or not 1 <= len(token) <= 4096
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise KeyUnavailable()
        client = hvac.Client(url=self._endpoint, token=token,
                             verify=self._ca_cert or True, timeout=self._timeout,
                             allow_redirects=False)
        try:
            yield client
        finally:
            client.session.close()

    @staticmethod
    def _data(response):
        if (type(response) is not dict or type(response.get("data")) is not dict
                or response.get("errors") or response.get("warnings")):
            raise KeyUnavailable()
        return response["data"]

    def _inspect_key(self, client, *, encrypt):
        data = self._data(client.read(f"{self._mount}/keys/{self._key_name}"))
        if (data.get("name") != self._key_name or data.get("type") != "aes256-gcm96"
                or any(data.get(flag) is not False for flag in (
                    "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "imported_key"))
                or any(data.get(flag) is not True for flag in ("supports_encryption", "supports_decryption"))
                or type(data.get("keys")) is not dict or str(self._key_version) not in data["keys"]
                or type(data.get("latest_version")) is not int
                or data["latest_version"] < self._key_version
                or type(data.get("min_decryption_version")) is not int
                or not 1 <= data["min_decryption_version"] <= self._key_version
                or encrypt and (type(data.get("min_encryption_version")) is not int
                    or not 0 <= data["min_encryption_version"] <= self._key_version)):
            raise KeyUnavailable()

    def _ciphertext(self, value):
        prefix = f"vault:v{self._key_version}:"
        if type(value) is not str or not len(prefix) < len(value) <= 8192 or not value.startswith(prefix):
            raise KeyUnavailable()
        encoded = value[len(prefix):]
        decoded = base64.b64decode(encoded, validate=True)
        if not decoded or base64.b64encode(decoded).decode("ascii") != encoded:
            raise KeyUnavailable()
        return value

    def wrap(self, root: bytes, context: KeyContext) -> WrappedRoot:
        self._check()
        if type(root) is not bytes or len(root) != 32:
            raise InvalidContext()
        aad = self._aad(context)
        try:
            with self._client() as client:
                self._inspect_key(client, encrypt=True)
                data = self._data(client.write(f"{self._mount}/encrypt/{self._key_name}",
                    plaintext=base64.b64encode(root).decode("ascii"),
                    associated_data=aad, key_version=self._key_version))
                sealed = self._ciphertext(data.get("ciphertext")).encode("ascii")
                if type(data.get("key_version")) is not int or data["key_version"] != self._key_version:
                    raise KeyUnavailable()
                return WrappedRoot(self.provider_id, context, sealed)
        except ProviderAuthenticationUnavailable:
            raise ProviderAuthenticationUnavailable() from None
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
            ciphertext = self._ciphertext(wrapper.sealed.decode("ascii"))
            with self._client() as client:
                self._inspect_key(client, encrypt=False)
                data = self._data(client.write(f"{self._mount}/decrypt/{self._key_name}",
                    ciphertext=ciphertext, associated_data=aad))
                encoded = data.get("plaintext")
                if type(encoded) is not str or len(encoded) != 44:
                    raise KeyUnavailable()
                root = base64.b64decode(encoded, validate=True)
                if len(root) != 32 or base64.b64encode(root).decode("ascii") != encoded:
                    raise KeyUnavailable()
                return root
        except ProviderAuthenticationUnavailable:
            raise ProviderAuthenticationUnavailable() from None
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
