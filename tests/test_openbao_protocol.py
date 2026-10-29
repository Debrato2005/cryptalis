"""Malformed SDK responses and local refusal boundaries; no service custody claim."""
import asyncio
import base64
import os
import sys
import traceback
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis.crypto import InvalidContext, KeyContext, KeyUnavailable, WrappedRoot
from cryptalis.crypto.openbao import OpenBaoTransitKeyProvider

CONTEXT = KeyContext(UUID(int=1), UUID(int=4), 'payload', UUID(int=907), 1)
ROOT = bytes(range(32))
PROVIDER = UUID(int=908)
SECRET = 'INJECTED PRIVATE PROVIDER DETAIL'


def provider(**changes):
    args = dict(endpoint='https://bao.example.invalid', token=lambda: 'synthetic-token',
                provider_id=PROVIDER, key_name='application', key_version=1)
    args.update(changes)
    return OpenBaoTransitKeyProvider(**args)


@pytest.mark.parametrize('changes', [
    {'endpoint': 'http://localhost:8200'}, {'endpoint': 'https://user:pass@host'},
    {'endpoint': 'https://host/prefix'}, {'endpoint': 'https://host?token=secret'},
    {'endpoint': 'https://host/#fragment'}, {'endpoint': 'https://host\\evil'},
    {'endpoint': ' https://host'}, {'endpoint': 'https://host:99999'},
    {'mount': '../transit'}, {'key_name': 'x/../../keys'}, {'key_name': 'x%2fy'},
    {'key_version': 0}, {'key_version': True}, {'timeout': float('nan')},
    {'ca_cert': False}, {'token': 'literal-token'}, {'provider_id': UUID(int=0)},
])
def test_unsafe_configuration_never_invokes_authentication(changes):
    def forbidden():
        pytest.fail('constructor invoked authentication')
    with pytest.raises(InvalidContext):
        provider(**dict({'token': forbidden}, **changes))


def test_async_token_callback_and_inherited_provider_refuse_before_dispatch(monkeypatch):
    async def token():
        return 'synthetic-token'
    with pytest.raises(InvalidContext):
        provider(token=token)
    p = provider(token=lambda: pytest.fail('forked provider invoked authentication'))
    monkeypatch.setattr(os, 'getpid', lambda: -1)
    with pytest.raises(KeyUnavailable):
        p.wrap(ROOT, CONTEXT)
    with pytest.raises(KeyUnavailable):
        asyncio.run(p.unwrap_async(WrappedRoot(PROVIDER, CONTEXT, b'x'), CONTEXT))


@pytest.mark.parametrize('fault', [
    'exception', 'redirect', 'missing', 'wrong-key', 'exportable', 'backup', 'derived',
    'delete', 'imported', 'algorithm', 'revoked', 'version', 'malformed', 'plaintext',
])
def test_failed_or_ambiguous_service_responses_are_redacted_and_never_accepted(monkeypatch, fault):
    calls, closed = [], []
    sealed = 'vault:v1:' + base64.b64encode(b'opaque test handle').decode()
    class Client:
        def __init__(self, **config):
            assert config['verify'] is True and config['allow_redirects'] is False
            assert 0 < config['timeout'] <= 60
            self.session = SimpleNamespace(close=lambda: closed.append(True))
        def read(self, path):
            calls.append('read')
            if fault == 'exception':
                raise RuntimeError(SECRET)
            if fault == 'redirect':
                return SimpleNamespace(status_code=307)
            data = dict(name='application', type='aes256-gcm96', derived=False,
                exportable=False, allow_plaintext_backup=False, deletion_allowed=False,
                imported_key=False, supports_encryption=True, supports_decryption=True,
                keys={'1': 1}, latest_version=1, min_decryption_version=1, min_encryption_version=0)
            changes = {'wrong-key': ('name', 'other'), 'exportable': ('exportable', True),
                'backup': ('allow_plaintext_backup', True), 'derived': ('derived', True),
                'delete': ('deletion_allowed', True), 'imported': ('imported_key', True),
                'algorithm': ('type', 'rsa-2048'), 'revoked': ('min_decryption_version', 2)}
            if fault in changes:
                key, value = changes[fault]; data[key] = value
            if fault == 'missing':
                del data['derived']
            return {'data': data}
        def write(self, path, **request):
            calls.append('write')
            if fault == 'plaintext':
                return {'data': {'plaintext': base64.b64encode(b'x' * 31).decode()}}
            return {'data': {'ciphertext': sealed if fault != 'malformed' else 'vault:v1:!!!',
                             'key_version': 2 if fault == 'version' else 1}}
    monkeypatch.setitem(sys.modules, 'hvac', SimpleNamespace(Client=Client))
    p = provider()
    with pytest.raises(KeyUnavailable) as caught:
        if fault == 'plaintext':
            p.unwrap(WrappedRoot(PROVIDER, CONTEXT, sealed.encode()), CONTEXT)
        else:
            p.wrap(ROOT, CONTEXT)
    assert closed == [True]
    if fault not in ('version', 'malformed', 'plaintext'):
        assert calls == ['read']
    assert SECRET in ''.join(traceback.format_exception(RuntimeError(SECRET)))
    rendered = ''.join(traceback.format_exception(caught.value))
    assert SECRET not in rendered and 'synthetic-token' not in rendered and repr(ROOT) not in rendered


def test_authentication_failure_is_safe_and_does_not_construct_sdk(monkeypatch):
    def token():
        raise RuntimeError(SECRET)
    monkeypatch.setitem(sys.modules, 'hvac', SimpleNamespace(
        Client=lambda **kw: pytest.fail('authentication failure reached SDK')))
    with pytest.raises(KeyUnavailable) as caught:
        provider(token=token).wrap(ROOT, CONTEXT)
    assert SECRET not in ''.join(traceback.format_exception(caught.value))
