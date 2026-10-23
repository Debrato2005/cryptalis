"""Opt-in adoption of pinned, unchanged Smolink source through the URL router.

Run through scripts/test_postgres.py with CRYPTALIS_SMOLINK_CHECKOUT set.
The interpreter must supply Smolink's Python 3.13 dependencies and Cryptalis.
No application checkout, settings file, or installed package is modified.
"""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import traceback
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import cryptalis.deprotection as d
import cryptalis.migration as m
from cryptalis.manifest.compiler import Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, keys
from smolink_workload import PUBLIC_SECRET, USER_ID, workflow, restart_without_cryptalis


REVISION = '498d24bae999ed53ad85e1c1f1a09ea7fa151aa4'
TABLE, FIELD = UUID(int=901), UUID(int=902)


def declaration():
    return {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [{'model': 'Url', 'table_id': str(TABLE), 'tenancy': {'single_tenant': True},
                        'fields': [{'name': 'destination', 'field_id': str(FIELD), 'protect': True,
                                    'queries': [], 'accept_leakage': []}]}]}


def snapshot(checkout, directory):
    archive = subprocess.run(['git', '-C', str(checkout), 'archive', REVISION, 'backend/app'],
                             check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(directory, filter='data')
    backend = directory / 'backend'
    hashes = {str(p.relative_to(backend)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(backend.rglob('*.py'))}
    assert hashes and (backend / 'app/main.py').is_file()
    return backend, hashes


@contextmanager
def redis_server(directory):
    socket = directory / 'redis.sock'
    process = subprocess.Popen(['redis-server', '--port', '0', '--unixsocket', str(socket),
                                '--unixsocketperm', '700', '--save', '', '--appendonly', 'no'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert socket.exists() and process.poll() is None, 'disposable Redis did not start'
        yield 'unix://' + str(socket)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)


def settings(monkeypatch, redis_url):
    values = dict(DATABASE_URL='postgresql+psycopg://unused.invalid/unused', REDIS_URL=redis_url,
                  JWT_SECRET=PUBLIC_SECRET, IP_HASH_SECRET=PUBLIC_SECRET, TOKEN_HASH_SECRET=PUBLIC_SECRET,
                  PUBLIC_BASE_URL='https://short.example.invalid', APP_PUBLIC_URL='https://app.example.invalid',
                  JWT_ISSUER='smolink-test', JWT_AUDIENCE='smolink-test', ACCESS_TOKEN_TTL_SECONDS='300',
                  REFRESH_TOKEN_TTL_SECONDS='600', EMAIL_FROM='test@example.invalid', RESEND_API_KEY='unused',
                  GOOGLE_CLIENT_ID='unused', GOOGLE_CLIENT_SECRET='unused',
                  GOOGLE_REDIRECT_URI='https://app.example.invalid/callback')
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def native_engine(variable, schema):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
                         creator=lambda: psycopg.connect(os.environ[variable], options='-csearch_path=' + schema))




def test_pinned_smolink_url_router_protects_and_restarts_without_cryptalis(tmp_path, monkeypatch):
    checkout = os.environ.get('CRYPTALIS_SMOLINK_CHECKOUT')
    if not checkout:
        pytest.skip('opt-in pinned external Smolink application; set CRYPTALIS_SMOLINK_CHECKOUT')
    assert sys.version_info >= (3, 13), 'Smolink requires Python 3.13 or later'
    assert not any(n == 'app' or n.startswith('app.') for n in sys.modules), 'application modules already loaded'
    backend, hashes = snapshot(checkout, tmp_path)
    monkeypatch.syspath_prepend(str(backend))
    monkeypatch.chdir(tmp_path)  # BaseSettings must not load a checkout's .env.
    export_dir = os.environ.get('CRYPTALIS_SMOLINK_FRESH_EXPORT')
    schema = 'smolink_adoption_' + uuid4().hex
    owner = native_engine('CRYPTALIS_TEST_DATABASE_URL', schema)
    runtime = None
    try:
        with redis_server(tmp_path) as redis_url:
            settings(monkeypatch, redis_url)
            from app.main import app as api
            from app.core.redis import get_redis_client
            from app.db.base import Base
            from app.models.user import User
            from app.models.url import Url
            with owner.begin() as connection:
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            Base.metadata.create_all(owner)
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(
                    os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], options='-csearch_path=' + schema))
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
                role = connection.execute('SELECT current_user').fetchone()[0]
            with owner.begin() as connection:
                connection.execute(User.__table__.insert().values(id=USER_ID, email='owner@example.invalid',
                    password_hash=None, email_verified_at=datetime.now(timezone.utc)))
                q = connection.dialect.identifier_preparer.quote
                connection.exec_driver_sql(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO {q(role)}')
                connection.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}" TO {q(role)}')

            async def lifecycle():
                plain = async_sessionmaker(runtime, expire_on_commit=False)
                baseline = await workflow(api, plain, 'native-baseline')
                # Real Redis rate limiting remains active across the router calls.
                await get_redis_client().flushdb()
                from cryptalis.doctor import preflight
                inventory = WriterInventory(True, (Writer(TABLE, 'pinned Smolink URL router', 'sqlalchemy',
                    evidence='single disposable process; original URL service and repository'),))
                report = preflight(json.dumps(declaration()).encode(), Base.registry, owner, writers=inventory)
                assert report['checks']['manifest_schema'] == 'PASS'
                assert report['status'] == report['checks']['provider_keys'] == 'UNKNOWN'
                assert report['effects'] == 'NONE'
                if export_dir:
                    from smolink_fresh_cluster import export_plain
                    export_plain(owner, schema, Path(export_dir))
                proposal = m.plan(json.dumps(declaration()).encode(), Base.registry, owner,
                    writers=inventory,
                    keys=keys, runtime_role=role, target_id=uuid4(), backfill_rows_per_second=1000,
                    verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
                pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
                approval = m.MaintenanceApproval('disposable Smolink stopped; only test owner and runtime exist', 3600)
                if export_dir:
                    from smolink_fresh_cluster import interrupt_and_resume
                    interrupt_and_resume(proposal, owner, pin, approval, Path(export_dir))
                assert m.apply(proposal, owner, keys=keys, pin=pin, approval=approval).phase == 'PENDING'
                assert m.apply(proposal, owner, keys=keys, pin=replace(pin, phase='ACTIVATING'),
                               approval=approval, until='ACTIVE').phase == 'ACTIVE'
                pin = replace(pin, phase='ACTIVE')
                current_keys = keys
                if export_dir:
                    from smolink_fresh_cluster import rotate
                    proposal, pin, current_keys = rotate(proposal, owner, pin, approval, Path(export_dir))
                attached = await attach(Base.registry, runtime, lock=proposal.lock_bytes, keys=current_keys,
                                        deployment=(proposal, pin))
                protected = lambda: attached(tenant_id=TABLE, expire_on_commit=False)
                cursor_parameters = []
                def capture(connection, cursor, statement, parameters, context, many):
                    cursor_parameters.append(repr(parameters))
                event.listen(runtime.sync_engine, 'before_cursor_execute', capture)
                try:
                    current = await workflow(api, protected, 'protected-live', retained=baseline)
                finally:
                    event.remove(runtime.sync_engine, 'before_cursor_execute', capture)
                assert 'private-destination' not in ''.join(cursor_parameters)
                with owner.connect() as connection:
                    rows = connection.exec_driver_sql('SELECT destination FROM urls').scalars().all()
                    assert rows and all(bytes(value).startswith(bytes.fromhex('43463100')) for value in rows)
                if export_dir:
                    from smolink_fresh_cluster import export_protected
                    assert hashes == {str(p.relative_to(backend)): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(backend.rglob('*.py'))}
                    export_protected(owner, schema, proposal, pin, current, baseline, hashes, Path(export_dir))
                    return current
                plaintext_role = least_privilege_role(SimpleNamespace(owner=owner, role=role))
                reverse = d.plan(proposal, owner, source_pin=pin, keys=keys,
                    plaintext_runtime_role=plaintext_role, backfill_rows_per_second=1000,
                    verify_rows_per_second=1000, temporary_bytes_per_row=3000, wal_bytes_per_row=6000)
                consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                              'public disposable test values; no protected backup retained')
                def reverse_pin(phase):
                    return m.DeploymentPin(reverse.target_id, reverse.operation_id, reverse.digest, phase)
                assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PREPARED'), approval=approval,
                               consent=consent).phase == 'PLAINTEXT_PENDING'
                assert d.apply(reverse, owner, keys=keys, pin=reverse_pin('PLAINTEXT_ACTIVATING'),
                    approval=approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
                removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
                    'original URL router and repository restart with Cryptalis imports denied',
                    'public disposable values; no historical backup', True)
                assert d.remove(reverse, owner, pin=reverse_pin('REMOVING'), approval=approval,
                                removal=removal, consent=consent).phase == 'REMOVED'
                assert d.check_removed(reverse, owner, pin=reverse_pin('REMOVED')) is None
                with owner.connect() as connection:
                    assert connection.exec_driver_sql('SELECT destination FROM urls WHERE id=%s',
                                                     (current['id'],)).scalar_one() == current['destination']
                    assert connection.exec_driver_sql("SELECT character_maximum_length FROM information_schema.columns "
                        "WHERE table_schema=%s AND table_name='urls' AND column_name='destination'",
                        (schema,)).scalar_one() == 2048
                await get_redis_client().flushdb()
                return current

            async def checked_lifecycle():
                try:
                    return await lifecycle()
                finally:
                    await get_redis_client().aclose()
                    await runtime.dispose()

            try:
                current = asyncio.run(checked_lifecycle())
            except Exception as error:
                # Keep diagnostic locations and SQLSTATE, never driver messages,
                # SQL text, parameters, or credentials from the external process.
                failure = {'exception': type(error).__name__,
                           'sqlstate': getattr(getattr(error, 'orig', error), 'sqlstate', None),
                           'unadapted_sealed_parameter': "cannot adapt type '_Sealed'" in str(getattr(error, 'orig', '')),
                           'frames': [(Path(f.filename).name, f.lineno, f.name)
                                      for f in traceback.extract_tb(error.__traceback__)]}
                (tmp_path / 'safe-failure.json').write_text(json.dumps(failure))
                raise
            if export_dir:
                return
            restart_without_cryptalis(backend, schema, current)
            assert hashes == {str(p.relative_to(backend)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in sorted(backend.rglob('*.py'))}
            for name, module in tuple(sys.modules.items()):
                if name == 'app' or name.startswith('app.'):
                    origin = getattr(module, '__file__', None)
                    if origin:
                        assert Path(origin).is_relative_to(backend), 'application module outside pinned snapshot'
            evidence = os.environ.get('CRYPTALIS_SMOLINK_RECEIPT')
            if evidence:
                with Path(evidence).open('x') as stream:
                    json.dump({'application_revision': REVISION, 'application_source_sha256': hashes,
                        'application_source_files_changed': [], 'model_changes': [], 'query_changes': [],
                        'protected_fields': ['Url.destination'], 'profile': 'storage-only; explicit single tenant',
                        'full_app_startup': 'original app imported; URL endpoint exercised; auth endpoints not qualified',
                        'url_router': 'native/protected/package-free HTTP creation and repository/ORM CRUD passed',
                        'redis': 'real disposable server; original rate-limit dependency',
                        'runtime': {name: importlib.metadata.version(name) for name in (
                            'fastapi', 'SQLAlchemy', 'greenlet', 'psycopg', 'cryptography')},
                        'python': sys.version.split()[0], 'psycopg_impl': psycopg.pq.__impl__,
                        'gates': 'all seven UNKNOWN'}, stream, indent=2)
                    stream.write('\n')
    finally:
        if runtime is not None:
            asyncio.run(runtime.dispose())
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        for name in tuple(sys.modules):
            if name == 'app' or name.startswith('app.'):
                del sys.modules[name]
