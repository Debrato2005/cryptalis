"""Opt-in unchanged async Smolink journey with local native SDK responses.

This profile supplies no live AWS, IAM, workload identity or custody evidence.
The existing application helper owns HTTP, Redis and package-free removal.
"""

import importlib.metadata
import json
import os
from pathlib import Path
import threading
import traceback
from types import SimpleNamespace
from uuid import UUID

import pytest

pytest.importorskip('boto3', reason='explicit profile requires the isolated native SDK cell')

from sqlalchemy import event

from cryptalis.crypto import AuthenticationFailed, KeyContext, KeyPolicy, Keyring, KeyUnavailable
import cryptalis.crypto.keys as key_module
from profile_aws_kms_sdk import sdk
from test_aws_kms import ARN, PROVIDER, ROOT, SECRET
import test_smolink_application as application


CONTEXT = KeyContext(application.DOMAIN, application.TABLE, 'payload', UUID(int=2904), 1)
WRAPPER = b'PUBLIC opaque Stubber async application wrapper'
ALIAS = 'kms-async-recovery'
DESTINATION = 'https://example.invalid/kms-async?marker=private-destination'


def request(field, value):
    return {'KeyId': ARN, field: value, 'EncryptionAlgorithm': 'SYMMETRIC_DEFAULT',
        'EncryptionContext': {'cryptalis:format': 'CF1/aws-kms-wrap/v1',
            'cryptalis:provider': str(PROVIDER), 'cryptalis:domain': str(CONTEXT.domain_id),
            'cryptalis:tenant': str(CONTEXT.tenant_id), 'cryptalis:purpose': CONTEXT.purpose,
            'cryptalis:root': str(CONTEXT.root_id), 'cryptalis:generation': '1'}}


def response(field, value):
    return {'KeyId': ARN, field: value, 'EncryptionAlgorithm': 'SYMMETRIC_DEFAULT'}


def test_original_async_smolink_kms_failures_recover_and_exit(tmp_path, monkeypatch, sdk):
    if not os.environ.get('CRYPTALIS_SMOLINK_CHECKOUT'):
        pytest.skip('set CRYPTALIS_SMOLINK_CHECKOUT to the pinned application checkout')
    assert not os.environ.get('CRYPTALIS_SMOLINK_FRESH_EXPORT'), 'profile exercises current-data exit'
    client, stubber, provider = sdk
    clock = [100.0]
    monkeypatch.setattr(key_module, 'time', SimpleNamespace(
        monotonic=lambda: clock[0], monotonic_ns=lambda: int(clock[0] * 1_000_000_000)))
    calls = []
    client.meta.events.register('before-parameter-build.kms',
        lambda model, **kwargs: calls.append((model.name, threading.get_ident())))
    stubber.add_response('encrypt', response('CiphertextBlob', WRAPPER), request('Plaintext', ROOT))
    wrapped = provider.wrap(ROOT, CONTEXT)
    ring = Keyring(KeyPolicy(CONTEXT.domain_id, CONTEXT.tenant_id, (wrapped,), 1),
                   {provider.provider_id: provider}, max_age=10)

    def queue_root(root=ROOT):
        stubber.add_response('decrypt', response('Plaintext', root), request('CiphertextBlob', WRAPPER))

    def resolve(tenant):
        assert tenant == CONTEXT.tenant_id
        return ring

    queue_root()
    monkeypatch.setattr(application, 'keys', resolve)
    native_attach = application.attach
    steps = []
    async_dispatches = []

    async def with_failure_controls(mapping, engine, *, lock, keys, deployment=None):
        factory = await native_attach(mapping, engine, lock=lock, keys=keys, deployment=deployment)
        from app.api.v1.endpoints.urls import generator
        from app.repositories.url_repository import get_url_by_short_code
        from app.services.url_service import create_short_url
        loop_thread, first_async_call = threading.get_ident(), len(calls)
        schema = deployment[0].document['journal_schema']
        probe = application.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
        statements, parameters = [], []
        def capture(connection, cursor, statement, values, context, many):
            statements.append(statement)
            parameters.append(repr(values))
        event.listen(engine.sync_engine, 'before_cursor_execute', capture)
        try:
            with probe.connect() as connection:
                original = bytes(connection.exec_driver_sql(
                    'SELECT destination FROM urls WHERE short_code=%s', ('native-baseline',)).scalar_one())
            assert original.startswith(b'CF1\0')
            clock[0] += 10
            stubber.add_client_error('decrypt', service_error_code='DisabledException',
                service_message=SECRET, http_status_code=400,
                expected_params=request('CiphertextBlob', WRAPPER))
            before = len(statements)
            async with factory(tenant_id=application.TABLE, expire_on_commit=False) as session:
                with pytest.raises(KeyUnavailable) as outage:
                    await create_short_url(session, DESTINATION, ALIAS, None, None, generator)
                assert SECRET not in ''.join(traceback.format_exception(outage.value))
                assert len(statements) == before
                await session.rollback()
                with probe.connect() as connection:
                    assert connection.exec_driver_sql('SELECT count(*) FROM urls WHERE short_code=%s',
                        (ALIAS,)).scalar_one() == 0
                queue_root()
                recovered = await create_short_url(session, DESTINATION, ALIAS, None, None, generator)
                await session.commit()
                await session.refresh(recovered)
                assert recovered.destination == DESTINATION
                assert await get_url_by_short_code(session, ALIAS) is recovered
                await session.delete(recovered)
                await session.commit()
                assert await get_url_by_short_code(session, ALIAS) is None
            steps.append('exact-expiry SDK outage refused before SQL; async rollback and original service retry passed')

            clock[0] += 10
            queue_root()
            async with factory(tenant_id=application.TABLE) as session:
                baseline = await get_url_by_short_code(session, 'native-baseline')
                expected = 'https://example.invalid/edited-native-baseline?marker=latest-private-destination'
                assert baseline is not None and baseline.destination == expected
            steps.append('healthy exact-expiry async SDK preparation and original repository read passed')

            clock[0] += 10
            queue_root(bytes(reversed(ROOT)))
            async with factory(tenant_id=application.TABLE) as session:
                with pytest.raises(AuthenticationFailed):
                    await get_url_by_short_code(session, 'native-baseline')
                await session.rollback()
                clock[0] += 10
                queue_root()
                assert (await get_url_by_short_code(session, 'native-baseline')).destination == expected
            steps.append('SDK-valid wrong root failed authentication; async rollback and healthy expiry recovery passed')

            damaged = original[:-1] + bytes((original[-1] ^ 1,))
            # Restore the public fixture ciphertext even if a read or assertion fails.
            try:
                with probe.begin() as connection:
                    connection.exec_driver_sql('UPDATE urls SET destination=%s WHERE short_code=%s',
                                              (damaged, 'native-baseline'))
                async with factory(tenant_id=application.TABLE) as session:
                    with pytest.raises(AuthenticationFailed):
                        await get_url_by_short_code(session, 'native-baseline')
                    await session.rollback()
            finally:
                with probe.begin() as connection:
                    connection.exec_driver_sql('UPDATE urls SET destination=%s WHERE short_code=%s',
                                              (original, 'native-baseline'))
            async with factory(tenant_id=application.TABLE) as session:
                assert (await get_url_by_short_code(session, 'native-baseline')).destination == expected
            with probe.connect() as connection:
                assert bytes(connection.exec_driver_sql('SELECT destination FROM urls WHERE short_code=%s',
                    ('native-baseline',)).scalar_one()) == original
                assert connection.exec_driver_sql('SELECT count(*) FROM urls WHERE short_code=%s',
                    (ALIAS,)).scalar_one() == 0
            assert 'private-destination' not in ''.join(parameters)
            steps.append('corrupted tag refused; fixture ciphertext restored in finally; async repository recovered')
            observed = calls[first_async_call:]
            assert len(observed) == 5 and all(name == 'Decrypt' and thread != loop_thread
                                            for name, thread in observed)
            async_dispatches.extend(name for name, _ in observed)
        finally:
            event.remove(engine.sync_engine, 'before_cursor_execute', capture)
            probe.dispose()
        return factory

    monkeypatch.setattr(application, 'attach', with_failure_controls)
    application.test_pinned_smolink_url_router_protects_and_restarts_without_cryptalis(tmp_path, monkeypatch)
    operations = [name for name, _ in calls]
    assert operations == ['Encrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt']
    assert len(steps) == 4 and len(async_dispatches) == 5
    evidence = os.environ.get('CRYPTALIS_AWS_KMS_SMOLINK_RECEIPT')
    if evidence:
        with Path(evidence).open('x') as stream:
            json.dump({'application_revision': application.REVISION,
                'protected_field': 'Url.destination', 'app_source_changes': [],
                'provider': 'existing AwsKmsKeyProvider through Keyring.prepare_async and native async attachment',
                'transport': 'native boto3/botocore Stubber local responses; synthetic credentials; no AWS network',
                'tripwires': 'existing SDK fixture denies credential discovery and HTTP send; positive transport refusal control',
                'steps': steps, 'sdk_operations': operations,
                'async_sdk_dispatches': async_dispatches, 'async_sdk_dispatch_off_event_loop_thread': True,
                'lifecycle': 'original native/protected URL HTTP and async repository CRUD, Redis rate limiting, latest-data decrypt-back/removal and fresh import-denied package-free restart passed',
                'rotation': 'not exercised by this profile; no new rotation claim',
                'runtime': {name: importlib.metadata.version(name) for name in (
                    'boto3', 'botocore', 'fastapi', 'SQLAlchemy', 'psycopg', 'cryptography', 'greenlet')},
                'custody': 'NO live AWS/IAM/workload identity or independent security qualification',
                'gates': 'all seven UNKNOWN'}, stream, indent=2)
            stream.write('\n')
