"""Opt-in real app/PostgreSQL workflow with native SDK local Stubber transport.

This is not live AWS, IAM, workload identity, or production custody evidence.
Reuse the pinned application journey and its original model/query code.
"""

import importlib.metadata
import json
import os
from pathlib import Path
import traceback
from types import SimpleNamespace
from uuid import UUID

import pytest

pytest.importorskip('boto3', reason='explicit profile requires the isolated native SDK cell')
sqlmodel = pytest.importorskip('sqlmodel', reason='explicit profile requires SQLModel 0.0.48')
pytestmark = pytest.mark.skipif(sqlmodel.__version__ != '0.0.48', reason='exact SQLModel profile')

from sqlalchemy import event

from cryptalis.crypto import AuthenticationFailed, KeyContext, KeyPolicy, Keyring, KeyUnavailable
import cryptalis.crypto.keys as key_module
import cryptalis.sqlmodel as bridge
from profile_aws_kms_sdk import sdk
from test_aws_kms import ARN, PROVIDER, ROOT, SECRET
import test_sqlmodel_application as application


CONTEXT = KeyContext(application.DOMAIN, application.TABLE, 'payload', UUID(int=2903), 1)
WRAPPER = b'PUBLIC opaque Stubber application wrapper'


def request(field, value):
    return {'KeyId': ARN, field: value, 'EncryptionAlgorithm': 'SYMMETRIC_DEFAULT',
        'EncryptionContext': {'cryptalis:format': 'CF1/aws-kms-wrap/v1',
            'cryptalis:provider': str(PROVIDER), 'cryptalis:domain': str(CONTEXT.domain_id),
            'cryptalis:tenant': str(CONTEXT.tenant_id), 'cryptalis:purpose': CONTEXT.purpose,
            'cryptalis:root': str(CONTEXT.root_id), 'cryptalis:generation': '1'}}


def response(field, value):
    return {'KeyId': ARN, field: value, 'EncryptionAlgorithm': 'SYMMETRIC_DEFAULT'}


def test_original_application_kms_expiry_outage_wrong_root_corruption_and_exit(
        tmp_path, monkeypatch, sdk):
    if not os.environ.get('CRYPTALIS_SQLMODEL_APP_SOURCE'):
        pytest.skip('set CRYPTALIS_SQLMODEL_APP_SOURCE to the pinned official snapshot')
    client, stubber, provider = sdk
    clock = [100.0]
    monkeypatch.setattr(key_module, 'time', SimpleNamespace(
        monotonic=lambda: clock[0], monotonic_ns=lambda: int(clock[0] * 1_000_000_000)))
    calls = []
    client.meta.events.register('before-parameter-build.kms',
                               lambda model, **kwargs: calls.append(model.name))
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
    native_attach = bridge.attach
    steps = []

    def with_failure_controls(mapping, engine, *, lock, keys, deployment=None):
        factory = native_attach(mapping, engine, lock=lock, keys=keys, deployment=deployment)
        from app import crud
        from app.models import UserCreate
        schema = deployment[0].document['journal_schema']
        probe = application.native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
        statements, parameters = [], []
        def capture(connection, cursor, statement, values, context, many):
            statements.append(statement)
            parameters.append(repr(values))
        event.listen(engine, 'before_cursor_execute', capture)
        try:
            with probe.connect() as connection:
                original = bytes(connection.exec_driver_sql(
                    'SELECT full_name FROM "user" WHERE email=%s', ('native@example.com',)).scalar_one())
            assert original.startswith(b'CF1\0')
            # The lease expires exactly at its deadline. The real SDK converts
            # the queued service response to ClientError; the adapter redacts it.
            clock[0] += 10
            stubber.add_client_error('decrypt', service_error_code='DisabledException',
                service_message=SECRET, http_status_code=400,
                expected_params=request('CiphertextBlob', WRAPPER))
            before = len(statements)
            with factory(tenant_id=application.TABLE, expire_on_commit=False) as session:
                with pytest.raises(KeyUnavailable) as outage:
                    crud.create_user(session=session, user_create=UserCreate(
                        email='kms-recovery@example.com', password='PUBLIC disposable password 2026',
                        full_name='private-kms-recovery'))
                assert SECRET not in ''.join(traceback.format_exception(outage.value))
                assert len(statements) == before
                session.rollback()
                with probe.connect() as connection:
                    assert connection.exec_driver_sql('SELECT count(*) FROM "user" WHERE email=%s',
                        ('kms-recovery@example.com',)).scalar_one() == 0
                queue_root()
                recovered = crud.create_user(session=session, user_create=UserCreate(
                    email='kms-recovery@example.com', password='PUBLIC disposable password 2026',
                    full_name='private-kms-recovery'))
                assert crud.get_user_by_email(session=session, email='kms-recovery@example.com') is recovered
                session.delete(recovered)
                session.commit()
                assert crud.get_user_by_email(session=session, email='kms-recovery@example.com') is None
            steps.append('expired SDK outage refused before SQL; rollback and original CRUD retry passed')

            clock[0] += 10
            queue_root()
            with factory(tenant_id=application.TABLE) as session:
                baseline = crud.get_user_by_email(session=session, email='native@example.com')
                assert baseline is not None and baseline.full_name == 'private-name-updated-native-雪😀'
            steps.append('exact-expiry healthy SDK preparation and original app read passed')

            clock[0] += 10
            queue_root(bytes(reversed(ROOT)))
            with factory(tenant_id=application.TABLE) as session:
                with pytest.raises(AuthenticationFailed):
                    crud.get_user_by_email(session=session, email='native@example.com')
                session.rollback()
                clock[0] += 10
                queue_root()
                assert crud.get_user_by_email(session=session, email='native@example.com').full_name == baseline.full_name
            steps.append('SDK-valid wrong root failed authentication; rollback and healthy expiry recovery passed')

            damaged = original[:-1] + bytes((original[-1] ^ 1,))
            # Always restore the known fixture ciphertext, including on an
            # unexpected assertion or read failure. No journal is rewritten.
            try:
                with probe.begin() as connection:
                    connection.exec_driver_sql('UPDATE "user" SET full_name=%s WHERE email=%s',
                                              (damaged, 'native@example.com'))
                with factory(tenant_id=application.TABLE) as session:
                    with pytest.raises(AuthenticationFailed):
                        crud.get_user_by_email(session=session, email='native@example.com')
                    session.rollback()
            finally:
                with probe.begin() as connection:
                    connection.exec_driver_sql('UPDATE "user" SET full_name=%s WHERE email=%s',
                                              (original, 'native@example.com'))
            with factory(tenant_id=application.TABLE) as session:
                assert crud.get_user_by_email(session=session, email='native@example.com').full_name == baseline.full_name
            with probe.connect() as connection:
                assert bytes(connection.exec_driver_sql('SELECT full_name FROM "user" WHERE email=%s',
                    ('native@example.com',)).scalar_one()) == original
                assert connection.exec_driver_sql('SELECT count(*) FROM "user" WHERE email=%s',
                    ('kms-recovery@example.com',)).scalar_one() == 0
            assert 'private-kms-recovery' not in ''.join(parameters)
            steps.append('corrupted tag refused; original ciphertext restored in finally; original app recovered')
        finally:
            event.remove(engine, 'before_cursor_execute', capture)
            probe.dispose()
        return factory

    monkeypatch.setattr(bridge, 'attach', with_failure_controls)
    application.test_unchanged_template_user_crud_protects_and_restarts_without_cryptalis(tmp_path, monkeypatch)
    assert calls == ['Encrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt', 'Decrypt']
    assert len(steps) == 4
    evidence = os.environ.get('CRYPTALIS_AWS_KMS_APP_RECEIPT')
    if evidence:
        with Path(evidence).open('x') as stream:
            json.dump({'application_revision': application.REVISION, 'application_release': '0.10.0',
                'protected_field': 'User.full_name', 'app_source_changes': [],
                'provider': 'existing AwsKmsKeyProvider with native boto3/botocore Stubber',
                'transport': 'local deterministic SDK responses; synthetic credentials; no network',
                'tripwires': 'existing sdk fixture denies credential discovery and HTTP send; positive transport refusal control',
                'steps': steps, 'sdk_operations': calls,
                'lifecycle': 'original native/protected CRUD, decrypt-back/removal and fresh import-denied package-free restart passed',
                'rotation': 'not exercised by this application profile; no new rotation claim',
                'runtime': {name: importlib.metadata.version(name) for name in (
                    'boto3', 'botocore', 'sqlmodel', 'SQLAlchemy', 'psycopg', 'cryptography', 'greenlet')},
                'custody': 'NO live AWS/IAM/workload identity or independent security qualification',
                'gates': 'all seven UNKNOWN'}, stream, indent=2)
            stream.write('\n')
