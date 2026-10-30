"""AppRole parser, non-dispatch and failure visibility; real service checks are separate."""
import asyncio
import os
import sys
import traceback
from types import SimpleNamespace
from uuid import UUID

import pytest

from cryptalis.crypto import (DevelopmentKeyProvider, InvalidContext, KeyPolicy, Keyring,
    ProviderAuthenticationUnavailable, WrappedRoot, create_root)
from cryptalis.crypto.openbao import OpenBaoAppRoleToken
from test_openbao_protocol import CONTEXT, ROOT, SECRET, provider


def token(**changes):
    values = dict(endpoint='https://bao.example.invalid', role_name='application', role_id='public-role-id',
        secret_id=lambda: 'public-fixture-secret-id', policies=('cryptalis-runtime',))
    values.update(changes)
    return OpenBaoAppRoleToken(**values)


def response():
    return {'auth': dict(client_token='public-fixture-token', token_policies=['cryptalis-runtime'],
        policies=['cryptalis-runtime'], lease_duration=60, token_type='service', num_uses=0,
        metadata={'role_name': 'application'})}


def client(monkeypatch, result):
    calls, closed = [], []
    class Client:
        def __init__(self, **config):
            assert config['token'] == ''  # hvac must not discover ambient credentials.
            assert config['verify'] is True and config['allow_redirects'] is False
            self.session = SimpleNamespace(close=lambda: closed.append(True))
            self.auth = SimpleNamespace(approle=SimpleNamespace(login=self.login, read_role=self.read_role))
        def login(self, **request):
            assert request['use_token'] is False
            calls.append(request)
            if isinstance(result, Exception): raise result
            return result
        def read_role(self, **request):
            assert request == {'role_name': 'application', 'mount_point': 'approle'}
            return {'data': dict(bind_secret_id=True, secret_id_ttl=600,
                                 token_type='service', token_policies=['cryptalis-runtime'])}
    monkeypatch.setitem(sys.modules, 'hvac', SimpleNamespace(Client=Client))
    return calls, closed


@pytest.mark.parametrize('change', [dict(endpoint='http://localhost:8200'), dict(endpoint='https://u:p@host'),
    dict(endpoint='https://host/path'), dict(endpoint='https://host?token=x'), dict(role_id=''),
    dict(role_id='line\nbreak'), dict(policies=()), dict(policies=['runtime']), dict(policies=('root',)),
    dict(policies=('runtime', 'runtime')), dict(mount='../approle'), dict(secret_id='literal'),
    dict(max_token_ttl=True), dict(max_token_ttl=3601), dict(timeout=float('nan'))])
def test_invalid_authentication_configuration_never_reads_credentials(change):
    def forbidden(): pytest.fail('constructor read credentials')
    with pytest.raises(InvalidContext): token(**dict({'secret_id': forbidden}, **change))


def test_each_call_uses_current_secret_and_owns_its_sdk_session(monkeypatch):
    calls, closed = client(monkeypatch, response())
    current = ['first-public-secret']
    auth = token(secret_id=lambda: current[0])
    assert not calls
    assert auth() == 'public-fixture-token'
    current[0] = 'second-public-secret'
    assert auth() == 'public-fixture-token'
    assert [call['secret_id'] for call in calls] == ['first-public-secret', 'second-public-secret']
    assert all(call['role_id'] == 'public-role-id' and call['mount_point'] == 'approle' for call in calls)
    assert len(closed) == 2


@pytest.mark.parametrize('fault', ['exception', 'missing_auth', 'warnings', 'token', 'policies',
    'effective_policies', 'identity_policies', 'type', 'ttl_zero', 'ttl_bool', 'ttl_long', 'uses'])
def test_ambiguous_or_overprivileged_login_never_releases_token(monkeypatch, fault):
    result = response()
    if fault == 'exception': result = RuntimeError(SECRET)
    elif fault == 'missing_auth': result.pop('auth')
    elif fault == 'warnings': result['warnings'] = [SECRET]
    else:
        name, value = {'token': ('client_token', SECRET + '\n'),
            'policies': ('token_policies', ['root']), 'effective_policies': ('policies', ['unexpected']),
            'identity_policies': ('identity_policies', ['unexpected']), 'type': ('token_type', 'batch'),
            'ttl_zero': ('lease_duration', 0), 'ttl_bool': ('lease_duration', True),
            'ttl_long': ('lease_duration', 301), 'uses': ('num_uses', 1)}[fault]
        result['auth'][name] = value
    calls, closed = client(monkeypatch, result)
    with pytest.raises(ProviderAuthenticationUnavailable) as error: token()()
    rendered = ''.join(traceback.format_exception(error.value))
    assert SECRET in ''.join(traceback.format_exception(RuntimeError(SECRET)))
    assert SECRET not in rendered
    assert error.value.effects == 'UNKNOWN' and error.value.retryable is False
    assert len(calls) == len(closed) == 1


@pytest.mark.parametrize('operation', ['wrap', 'create', 'unwrap', 'prepare', 'prepare_async', 'rewrap'])
def test_authentication_failure_visibility_survives_provider_and_keyring(monkeypatch, operation):
    calls, closed = client(monkeypatch, RuntimeError(SECRET))
    p = provider(token=token())
    wrapper = WrappedRoot(p.provider_id, CONTEXT, b'vault:v1:eA==')
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapper,), 1), {p.provider_id: p})
    local = DevelopmentKeyProvider(); local_wrapper = local.wrap(ROOT, CONTEXT)
    actions = {'wrap': lambda: p.wrap(ROOT, CONTEXT), 'create': lambda: create_root(p, CONTEXT),
        'unwrap': lambda: p.unwrap(wrapper, CONTEXT), 'prepare': ring.prepare,
        'prepare_async': lambda: asyncio.run(ring.prepare_async()),
        'rewrap': lambda: local.rewrap(local_wrapper, p, CONTEXT)}
    with pytest.raises(ProviderAuthenticationUnavailable) as error: actions[operation]()
    assert error.value.effects == 'UNKNOWN' and error.value.retryable is False
    assert SECRET not in ''.join(traceback.format_exception(error.value))
    assert len(calls) == len(closed) == 1


def test_async_secret_callback_refuses_without_invocation():
    async def secret(): pytest.fail('async credential callback ran')
    with pytest.raises(InvalidContext): token(secret_id=secret)


@pytest.mark.skipif(not hasattr(os, 'fork'), reason='requires actual POSIX fork')
def test_inherited_authenticator_refuses_before_secret_or_network():
    auth = token(secret_id=lambda: pytest.fail('inherited authenticator read a secret'))
    pid = os.fork()
    if pid == 0:
        try: auth()
        except ProviderAuthenticationUnavailable: os._exit(0)
        except BaseException: os._exit(2)
        os._exit(1)
    assert os.waitpid(pid, 0)[1] == 0
