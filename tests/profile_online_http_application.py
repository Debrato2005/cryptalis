"""Online protection through the unchanged, pinned SQLModel HTTP application.

This opt-in profile uses the source runtime role for original application CRUD,
the target runtime role for protected CRUD, and owner-only DDL for transitions.
It is a local disposable PostgreSQL profile; it does not qualify deployment,
external custody, or the seven admission gates.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import threading
from uuid import UUID, uuid4

import pytest

pytest.importorskip('sqlmodel', reason='optional pinned SQLModel HTTP application profile')
pytest.importorskip('fastapi', reason='optional pinned original FastAPI HTTP profile')

from sqlmodel import Session, select
from sqlalchemy import event
from sqlalchemy.exc import DBAPIError

from cryptalis import deprotection as d
from cryptalis import migration as m
from cryptalis import online
from cryptalis.doctor import preflight
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlmodel import attach
from profile_sqlmodel_public_slots_application import public_slots
from profile_sqlmodel_searchable_application import native_catalog, search_controls
from test_migration import DOMAIN, keys
from test_sqlmodel_application import native_engine, settings, TABLE, FIELD


SOURCE = json.loads((Path(__file__).parent / 'fixtures/sqlmodel_http_source.json').read_text())


def _online_pin(plan, phase):
    return m.DeploymentPin(plan.target_id, plan.operation_id, plan.digest, phase)


def _mapped_rows(factory, mapping):
    """Read every mapped application table through the supplied runtime path."""
    result = {}
    with factory() as session:
        for mapper in sorted(mapping.mappers, key=lambda item: item.local_table.name):
            model = mapper.class_
            rows = session.exec(select(model).order_by(*mapper.primary_key)).all()
            result[mapper.local_table.name] = [
                tuple(getattr(row, column.key) for column in mapper.column_attrs) for row in rows]
    return result


def _native_rows(owner,mapping):
    result = {}
    with owner.connect() as c:
        quote = c.dialect.identifier_preparer.quote_identifier
        for mapper in sorted(mapping.mappers,key=lambda item:item.local_table.name):
            names = ','.join(quote(prop.columns[0].name) for prop in mapper.column_attrs)
            order = ','.join(quote(col.name) for col in mapper.primary_key)
            result[mapper.local_table.name] = [tuple(row) for row in c.exec_driver_sql(
                f'SELECT {names} FROM {quote(mapper.local_table.name)} ORDER BY {order}')]
    return result


def test_pinned_http_application_moves_online_to_protected_and_back(tmp_path, monkeypatch):
    source_root = os.environ.get('CRYPTALIS_SQLMODEL_HTTP_SOURCE')
    required = ('CRYPTALIS_TEST_DATABASE_URL', 'CRYPTALIS_TEST_RUNTIME_DATABASE_URL',
                'CRYPTALIS_TEST_SOURCE_URL')
    if not source_root or any(not os.environ.get(name) for name in required):
        pytest.skip('set the pinned SQLModel snapshot and all three PostgreSQL profile URLs')
    assert sys.version_info >= (3, 13), 'qualification snapshot requires Python 3.13'
    assert not any(name == 'app' or name.startswith('app.') for name in sys.modules)

    copied = tmp_path / 'original'
    hashes = {}
    for relative, expected in SOURCE['files'].items():
        raw = (Path(source_root) / relative).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        hashes[relative] = hashlib.sha256(raw).hexdigest()
    assert len(hashes) == 26

    monkeypatch.syspath_prepend(str(copied / 'backend'))
    isolated_cwd = tmp_path / 'empty' / 'cwd'
    isolated_cwd.mkdir(parents=True)
    monkeypatch.chdir(isolated_cwd)
    settings(monkeypatch)
    for name, value in dict(ENVIRONMENT='local', SMTP_HOST='', SMTP_USER='', SMTP_PASSWORD='',
            EMAILS_FROM_EMAIL='', SENTRY_DSN='', FRONTEND_HOST='http://localhost:5173').items():
        monkeypatch.setenv(name, value)

    schema = 'sqlmodel_http_online_' + uuid4().hex
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    target = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
    source = native_engine('CRYPTALIS_TEST_SOURCE_URL', schema)
    mapping = original_engine = None
    schema_created = False
    source_connection = None
    try:
        from app.models import SQLModel, User
        from app.main import app as api
        from app.core.db import engine as original_engine
        mapping = User._sa_registry
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        schema_created = True
        SQLModel.metadata.create_all(owner)
        with owner.connect() as connection:
            owner_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with target.connect() as connection:
            target_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with source.connect() as connection:
            source_role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        assert len({owner_role, target_role, source_role}) == 3

        user_table = User.__table__.name
        quote = owner.dialect.identifier_preparer.quote
        with owner.begin() as connection:
            connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            for role in (source_role, target_role):
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {quote(role)}')
            tables = list(SQLModel.metadata.tables.values())
            for table in tables:
                qualified = f'"{schema}".{quote(table.name)}'
                connection.exec_driver_sql(
                    f'GRANT SELECT,INSERT,UPDATE,DELETE ON {qualified} TO {quote(source_role)}')
                if table.name != user_table:
                    connection.exec_driver_sql(
                        f'GRANT SELECT,INSERT,UPDATE,DELETE ON {qualified} TO {quote(target_role)}')

        baseline_catalog = native_catalog(owner)
        baseline_slots = public_slots(owner)
        inventory = WriterInventory(True, (Writer(TABLE, 'pinned original HTTP app', 'sqlalchemy',
            evidence='unchanged pinned HTTP routes and request-session dependency using the source runtime role'),))
        email_field = UUID(int=1903)
        declaration = {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'User', 'table_id': str(TABLE), 'tenancy': {'single_tenant': True},
                'fields': [
                    {'name': 'full_name', 'field_id': str(FIELD), 'protect': True,
                     'queries': [], 'accept_leakage': []},
                    {'name': 'email', 'field_id': str(email_field), 'protect': True,
                     'queries': ['equality', 'unique'],
                     'accept_leakage': ['equality', 'unique']}]}]}
        reviews = (SearchReview(email_field, False,
            'Fixture-only opaque UUID128 email identities; equality, frequency, query and uniqueness leakage '
            'is accepted for disposable public values. Arbitrary production email admission remains UNKNOWN.'),)

        with target.connect() as connection, pytest.raises(DBAPIError) as denied:
            connection.exec_driver_sql(f'SELECT id FROM "{schema}"."{user_table}"').all()
        assert getattr(denied.value.orig, 'sqlstate', None) == '42501'

        from sqlmodel_http_workload import workflow as http_workflow
        from sqlmodel_http_mail_workload import workflow as mail_workflow
        samples = {}
        def collect(state):
            if state.is_select:
                cache = state.statement._generate_cache_key()
                samples[cache.key if cache is not None else id(state.statement)] = state.statement
        event.listen(Session, 'do_orm_execute', collect)
        try:
            native = http_workflow(api, lambda: Session(source))
        finally:
            event.remove(Session, 'do_orm_execute', collect)
        assert native['is_active'] is True
        assert samples, 'native HTTP request sessions must provide actual SELECT structures'
        report = preflight(json.dumps(declaration).encode(), mapping, owner,
            writers=inventory, search_reviews=reviews, queries=tuple(samples.values()))
        assert report['checks']['query_samples'] == 'PASS'
        assert report['checks']['query_routes'] == 'UNKNOWN'
        assert report['status'] == 'UNKNOWN' and report['effects'] == 'NONE'
        native_mail = mail_workflow(api, lambda: Session(source), native, monkeypatch)
        assert native_mail['smtp_messages'] == 4

        proposal = online.plan(json.dumps(declaration).encode(), mapping, owner,
            source_role=source_role, layout='preserve-public-slots/v1', writers=inventory,
            search_reviews=reviews, keys=keys, runtime_role=target_role, target_id=uuid4(),
            max_rows=1, max_bytes=4096, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        capture_pin = _online_pin(proposal, 'PREPARED')
        capture_approval = online.OnlineApproval(
            'The owner is the only DDL writer; the native source role uses the transactional capture trigger.',
            True, 3600)
        assert online.apply(proposal, owner, keys=keys, pin=capture_pin,
            approval=capture_approval, max_chunks=0).phase == 'CAPTURING'
        entered,release = threading.Event(),threading.Event()
        def held_keys(tenant):
            entered.set()
            assert release.wait(15), 'HTTP overlap did not release the locked batch'
            return keys(tenant)
        from fastapi.testclient import TestClient
        from app.api.deps import get_db
        def request_session():
            with Session(source) as session: yield session
        previous = api.dependency_overrides.copy()
        api.dependency_overrides[get_db] = request_session
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                batch = pool.submit(online.apply,proposal,owner,keys=held_keys,pin=capture_pin,
                                    approval=capture_approval,max_chunks=1)
                try:
                    assert entered.wait(5)
                    with TestClient(api) as client:
                        response = client.post('/api/v1/users/signup',json={
                            'email':uuid4().hex+'@example.com',
                            'password':'PUBLIC concurrent signup password 2026',
                            'full_name':'PUBLIC signup while backfill holds a row lock'})
                        assert response.status_code == 200
                        assert not batch.done(), 'the native HTTP write must commit during the live batch'
                finally:
                    release.set()
                assert batch.result(timeout=15).committed_rows == 1
        finally:
            api.dependency_overrides.clear()
            api.dependency_overrides.update(previous)

        # The original routes continue to use source credentials while capture is live.
        captured_http = http_workflow(api, lambda: Session(source), retained=native)
        captured_mail = mail_workflow(api, lambda: Session(source), captured_http, monkeypatch)
        assert captured_http['is_active'] is True and captured_mail['smtp_messages'] == native_mail['smtp_messages']
        # Force committed native changes below the first backfill identity,
        # including a NULL and a delete/reinsert of the same UUID.
        from app.models import User, UserCreate
        low_identity, replaced_identity = UUID(int=1), UUID(int=2)
        with Session(source, expire_on_commit=False) as session:
            existing = session.get(User, UUID(native['id']))
            existing.full_name = None
            session.add(existing)
            inserted = User.model_validate(UserCreate(email=uuid4().hex + '@example.com',
                password='PUBLIC online capture fixture 2026', full_name='PUBLIC below-cursor'),
                update={'id': low_identity, 'hashed_password': 'PUBLIC fixture hash'})
            replaced = User.model_validate(UserCreate(email=uuid4().hex + '@example.com',
                password='PUBLIC online capture fixture 2026'),
                update={'id': replaced_identity, 'hashed_password': 'PUBLIC fixture hash'})
            session.add_all((inserted, replaced))
            session.commit()
            session.delete(session.get(User, replaced_identity))
            session.commit()
            reinserted = User.model_validate(UserCreate(email=uuid4().hex + '@example.com',
                password='PUBLIC online capture fixture 2026', full_name=None),
                update={'id': replaced_identity, 'hashed_password': 'PUBLIC fixture hash'})
            session.add(reinserted)
            session.commit()
            assert session.get(User, low_identity).full_name is not None
            assert session.get(User, replaced_identity).full_name is None
        native_current = _mapped_rows(lambda: Session(source), mapping)
        with target.connect() as connection, pytest.raises(DBAPIError) as still_denied:
            connection.exec_driver_sql(f'SELECT id FROM "{schema}"."{user_table}"').all()
        assert getattr(still_denied.value.orig, 'sqlstate', None) == '42501'

        source_connection = source.connect()
        source_connection.exec_driver_sql('SELECT 1')
        source_connection.commit()
        fenced = online.apply(proposal, owner, keys=keys, pin=capture_pin,
            approval=capture_approval, max_chunks=1, fence=True)
        assert fenced.phase == 'FENCED'
        assert source_connection.exec_driver_sql(
            f'SELECT id FROM "{schema}"."{user_table}" LIMIT 1').first() is not None
        with pytest.raises(DBAPIError) as existing_source_write_denied:
            source_connection.exec_driver_sql(f'UPDATE "{schema}"."{user_table}" SET full_name=%s WHERE id=%s',
                ('PUBLIC blocked by fence', native['id']))
        assert getattr(existing_source_write_denied.value.orig, 'sqlstate', None) in ('42501', '55000')
        source_connection.rollback()
        with source.connect() as fresh_source, pytest.raises(DBAPIError) as fresh_source_write_denied:
            fresh_source.exec_driver_sql(
                f'UPDATE "{schema}"."{user_table}" SET full_name=%s WHERE id=%s',
                ('PUBLIC blocked after fence', native['id']))
        assert getattr(fresh_source_write_denied.value.orig, 'sqlstate', None) in ('42501', '55000')
        online.apply(proposal, owner, keys=keys, pin=capture_pin,
            approval=capture_approval, max_chunks=100)
        sealed = online.seal(proposal, owner, keys=keys, pin=capture_pin, approval=capture_approval)
        successor_path = tmp_path / 'activation.json'
        successor_path.write_bytes(sealed.artifact)
        retained_successor = m.MigrationPlan(successor_path.read_bytes())
        assert retained_successor.artifact == sealed.artifact
        successor = online.switch(proposal, owner, successor=retained_successor, keys=keys,
            pin=capture_pin, approval=capture_approval)
        assert successor.artifact == sealed.artifact
        assert m.apply(successor, owner, keys=keys, pin=_online_pin(successor, 'ACTIVATING'),
            approval=m.MaintenanceApproval(capture_approval.owner_writer_exclusion, 3600),
            until='ACTIVE').phase == 'ACTIVE'
        active = _online_pin(successor, 'ACTIVE')

        with pytest.raises(DBAPIError) as existing_source_denied:
            source_connection.exec_driver_sql(f'SELECT id FROM "{schema}"."{user_table}"').all()
        assert getattr(existing_source_denied.value.orig, 'sqlstate', None) == '42501'
        source_connection.rollback()
        with pytest.raises(DBAPIError) as existing_source_write_revoked:
            source_connection.exec_driver_sql(f'UPDATE "{schema}"."{user_table}" SET full_name=%s WHERE id=%s',
                ('PUBLIC revoked after switch', native['id']))
        assert getattr(existing_source_write_revoked.value.orig, 'sqlstate', None) == '42501'
        source_connection.rollback()
        with source.connect() as fresh_source, pytest.raises(DBAPIError) as fresh_source_denied:
            fresh_source.exec_driver_sql(f'SELECT id FROM "{schema}"."{user_table}"').all()
        assert getattr(fresh_source_denied.value.orig, 'sqlstate', None) == '42501'
        fresh_source_write = source.connect()
        try:
            with pytest.raises(DBAPIError) as fresh_write_revoked:
                fresh_source_write.exec_driver_sql(
                    f'UPDATE "{schema}"."{user_table}" SET full_name=%s WHERE id=%s',
                    ('PUBLIC revoked after switch', native['id']))
            assert getattr(fresh_write_revoked.value.orig, 'sqlstate', None) == '42501'
        finally:
            fresh_source_write.close()

        attached = attach(mapping, target, lock=successor.lock_bytes, keys=keys,
            deployment=(successor, active))
        protected_factory = lambda: attached(tenant_id=TABLE, expire_on_commit=False)
        assert _mapped_rows(protected_factory, mapping) == native_current
        protected = http_workflow(api, protected_factory, retained=captured_http)
        assert protected['is_active'] is True
        protected, protected_search = search_controls(protected_factory, protected)
        assert protected_search['unique_sqlstate'] == '23505'
        assert protected_search['latest_email_edit'] is True
        protected_mail = mail_workflow(api, protected_factory, protected, monkeypatch)
        assert protected_mail['smtp_messages'] == 4
        latest_rows = _mapped_rows(protected_factory,mapping)

        with owner.connect() as connection:
            email_values = connection.exec_driver_sql(
                f'SELECT email,full_name,is_active FROM "{user_table}"').all()
            assert email_values
            assert all(bytes(email).startswith(b'CF1\0') for email, _, _ in email_values)
            assert all(name is None or bytes(name).startswith(b'CF1\0') for _, name, _ in email_values)
            assert all(type(value) is bool for _, _, value in email_values)

        reverse = d.plan(successor, owner, source_pin=active, keys=keys,
            plaintext_runtime_role=source_role, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
        reverse_approval = m.MaintenanceApproval(
            'Original application writers pause during decrypt-back; only the owner performs maintenance.', 3600)
        consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
            'Disposable public HTTP fixtures; no historical protected backup is retained.')
        assert d.apply(reverse, owner, keys=keys, pin=_online_pin(reverse, 'PREPARED'),
            approval=reverse_approval, consent=consent, until='PLAINTEXT_PENDING').phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse, owner, keys=keys, pin=_online_pin(reverse, 'PLAINTEXT_ACTIVATING'),
            approval=reverse_approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        target_probe = native_engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', schema)
        try:
            with target_probe.connect() as connection, pytest.raises(DBAPIError) as target_revoked:
                connection.exec_driver_sql(f'SELECT id FROM "{schema}"."{user_table}"').all()
            assert getattr(target_revoked.value.orig, 'sqlstate', None) == '42501'
        finally:
            target_probe.dispose()
        removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
            'Unchanged original HTTP app reads the current native rows as the source role.',
            'No historical protected backup retained.', True)
        assert d.remove(reverse, owner, pin=_online_pin(reverse, 'REMOVING'), approval=reverse_approval,
            removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse, owner, pin=_online_pin(reverse, 'REMOVED')) is None
        assert native_catalog(owner) == baseline_catalog
        assert public_slots(owner, baseline_slots) == baseline_slots
        assert _native_rows(owner,mapping) == latest_rows

        package_free = None
        with monkeypatch.context() as source_env:
            source_env.setenv('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', os.environ['CRYPTALIS_TEST_SOURCE_URL'])
            from sqlmodel_http_package_free import run as package_free_http
            package_free = package_free_http(copied, schema, protected)
        assert package_free['native_http'] == 'passed'
        assert hashes == {relative: hashlib.sha256((copied / relative).read_bytes()).hexdigest()
                          for relative in hashes}

        receipt = os.environ.get('CRYPTALIS_ONLINE_HTTP_REPORT')
        if receipt:
            with Path(receipt).open('x', encoding='utf-8') as stream:
                json.dump({'application_revision': SOURCE['revision'],
                    'application_source_sha256': hashes, 'source_edits': [],
                    'protected_fields': ['User.email', 'User.full_name'],
                    'native_boolean': 'unprotected native control',
                    'layout': 'preserve-public-slots/v1',
                    'query_sample_count': len(samples), 'query_samples': 'PASS',
                    'query_routes': 'UNKNOWN', 'native_http': native['controls'],
                    'concurrent_http_signup_during_locked_backfill':'PASS',
                    'capturing_http': captured_http['controls'],
                    'protected_http': protected['controls'], 'protected_search_controls': protected_search,
                    'protected_local_smtp': protected_mail,
                    'native_local_smtp':native_mail,'capturing_local_smtp':captured_mail,
                    'latest_all_table_rows_equal_after_reverse':True,
                    'package_free_native_exit': package_free,
                    'mail_boundary': 'local SMTP only; no external mail service',
                    'qualification': 'local PostgreSQL 16 profile; all seven gates remain UNKNOWN'},
                    stream, indent=2)
                stream.write('\n')
    finally:
        if source_connection is not None:
            source_connection.close()
        source.dispose()
        target.dispose()
        if original_engine is not None:
            original_engine.dispose()
        if schema_created:
            with owner.begin() as connection:
                connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        if mapping is not None:
            mapping.dispose()
            mapping.metadata.clear()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
