"""One manifest and one provider through the whole lifecycle on real PostgreSQL."""
import asyncio
import json
import os
import stat
from contextlib import contextmanager
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, Index, MetaData, Table, Text, Uuid, event, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry, sessionmaker

from cryptalis import Project
from cryptalis.crypto import AuthenticationFailed, DevelopmentKeyProvider, KeyUnavailable
from cryptalis.migration import DeploymentPin, MigrationPlan, TransitionFailure
from cryptalis.project import ProjectError
from cryptalis.sqlalchemy import PolicyMismatch, UnsupportedProtectedOperation, attach
from test_deprotection import least_privilege_role, native_rows
from test_migration import application, engine, frames, TENANT
from test_online_protection import app as online_app  # noqa: F401  (pytest fixture)

STOPPED = 'Deploy job stopped the API and workers; the attached application is the only writer.'
REVIEWED = 'Names are not enumerable; equality and frequency leakage are accepted.'
_processes = []  # A real process keeps its model classes; the registry holds them weakly.


@pytest.fixture(autouse=True)
def _end_simulated_processes():
    yield
    while _processes:
        _processes.pop().runtime.dispose()


def manifest_of(app, **field_changes):
    declaration = json.loads(json.dumps(app.plan.document['lock']['declaration']))
    declaration['models'][0]['fields'][0].update(field_changes)
    return json.dumps(declaration).encode()


def restart(app, provider, state, *, manifest=None, indexed=True, **options):
    """Build what a fresh process builds: mapping, model class, engine and Project."""
    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    if indexed:
        Index('native_name', table.c.tenant_id, table.c.name, unique=True)
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    project = Project(manifest or manifest_of(app), mapping, provider=provider, state_dir=state, **options)
    process = SimpleNamespace(project=project, Customer=Customer, runtime=engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL'))
    _processes.append(process)
    return process


def protect(app, process):
    return process.project.protect(app.owner, runtime_role=app.role, writers_stopped=STOPPED,
                                   search_reviewed=REVIEWED, chunk_size=2)


def read_all(app, process):
    sessions = process.project.attach(process.runtime)
    with sessions(tenant_id=TENANT) as session:
        return {row.id: (row.tenant_id, row.name) for row in session.scalars(select(process.Customer))}


def stored(app):
    return frames(app, True)


def test_complete_journey_needs_only_manifest_provider_and_state(tmp_path):
    state = tmp_path / 'state'
    provider = DevelopmentKeyProvider()
    with application() as app:
        process = restart(app, provider, state)
        assert process.project.status(app.owner) is None
        report = process.project.doctor(app.owner)
        assert report['checks']['manifest_schema'] == 'PASS' and report['status'] == 'UNKNOWN'
        with pytest.raises(ProjectError, match='NotProtected'):
            process.project.attach(process.runtime)
        for missing in ({'writers_stopped': ' '}, {'writers_stopped': None}):
            with pytest.raises(ProjectError, match='StatementRequired'):
                process.project.protect(app.owner, runtime_role=app.role, search_reviewed=REVIEWED, **missing)
        with pytest.raises(ProjectError, match='StatementRequired'):
            process.project.protect(app.owner, runtime_role=app.role, writers_stopped=STOPPED)
        assert not (state / 'state.json').exists()

        assert protect(app, process).phase == 'ACTIVE'
        assert protect(app, process).phase == 'ACTIVE'  # Repeating is harmless.
        assert process.project.status(app.owner).phase == 'ACTIVE'

        # An independent connection sees authenticated frames, never plaintext.
        original = stored(app)
        assert all(value is None or value[:3] == b'CF1' for value in original.values())
        assert not any(value and b'user-' in value for value in original.values())
        # State holds wrapped roots and plans only, readable by the owner alone.
        raw = (state / 'state.json').read_bytes()
        assert stat.S_IMODE((state / 'state.json').stat().st_mode) == 0o600
        assert b'trailing ' not in raw

        # A fresh process needs only the same inputs.
        process = restart(app, provider, state)
        sessions = process.project.attach(process.runtime)
        with sessions(tenant_id=TENANT) as session:
            assert {r.id: (r.tenant_id, r.name) for r in session.scalars(select(process.Customer))} == app.source
            session.get(process.Customer, UUID(int=101)).name = 'latest edit'
            session.commit()
            found = select(process.Customer.id).where(process.Customer.name == 'latest edit')
            assert session.scalar(found) == UUID(int=101)
            session.add(process.Customer(id=uuid4(), tenant_id=TENANT, name='latest edit'))
            with pytest.raises(IntegrityError) as duplicate:
                session.commit()
            assert duplicate.value.orig.sqlstate == '23505'
            session.rollback()
        with pytest.raises(PolicyMismatch):
            sessions(tenant_id=uuid4())
        expected = dict(app.source)
        expected[UUID(int=101)] = TENANT, 'latest edit'

        process = restart(app, provider, state)
        report = process.project.doctor(process.runtime)
        assert report['deployment'] == 'PASS' and report['status'] == 'UNKNOWN'
        assert report['keys'][0]['checks']['cold_key_preparation'] == 'PASS'

        before = stored(app)
        restart(app, provider, state).project.rotate(app.owner, 'payload', writers_stopped=STOPPED)
        after = stored(app)
        for identity, frame in after.items():
            if frame is not None:
                assert int.from_bytes(frame[6:10], 'big') == 2 and frame[10:46] == before[identity][10:46]
        assert read_all(app, restart(app, provider, state)) == expected

        restart(app, provider, state).project.rotate(app.owner, 'search', writers_stopped=STOPPED)
        rotated = stored(app)
        for identity, frame in rotated.items():
            if frame is not None:
                assert int.from_bytes(frame[10:14], 'big') == 2 and frame[14:46] != after[identity][14:46]
        process = restart(app, provider, state)
        sessions = process.project.attach(process.runtime)
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(process.Customer.id).where(process.Customer.name == 'latest edit')) == UUID(int=101)

        new_provider = DevelopmentKeyProvider()
        restart(app, provider, state).project.rotate(app.owner, 'wrapping', writers_stopped=STOPPED, provider=new_provider)
        assert stored(app) == rotated  # Rewrap changes custody, not stored bytes.
        with pytest.raises(KeyUnavailable):  # The former provider alone no longer opens it.
            read_all(app, restart(app, provider, state))
        assert read_all(app, restart(app, new_provider, state)) == expected

        async def asynchronous():
            process = restart(app, new_provider, state)
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                sessions = await process.project.attach(runtime)
                async with sessions(tenant_id=TENANT) as session:
                    return (await session.get(process.Customer, UUID(int=101))).name
            finally:
                await runtime.dispose()
        assert asyncio.run(asynchronous()) == 'latest edit'

        process = restart(app, new_provider, state)
        exit_inputs = dict(plaintext_role=least_privilege_role(app), writers_stopped=STOPPED,
                           retained_backups='Encrypted backups stay readable through the retained state and provider.')
        with pytest.raises(ProjectError, match='PlaintextNotAccepted'):
            process.project.decrypt(app.owner, accept_plaintext=False, **exit_inputs)
        with pytest.raises(ProjectError, match='NotDecrypted'):
            process.project.remove(app.owner, writers_stopped=STOPPED, application_verified='n/a', old_workers_stopped=True)
        assert process.project.decrypt(app.owner, accept_plaintext=True, **exit_inputs).phase == 'PLAINTEXT_ACTIVE'
        assert native_rows(app) == expected
        with pytest.raises(ProjectError, match='Decrypted'):
            (lambda p: p.project.attach(p.runtime))(restart(app, new_provider, state))
        assert process.project.status(app.owner).phase == 'PLAINTEXT_ACTIVE'

        removed = restart(app, new_provider, state).project.remove(
            app.owner, writers_stopped=STOPPED, old_workers_stopped=True,
            application_verified='Native application passed its own CRUD checks.')
        assert removed.phase == 'REMOVED'
        assert native_rows(app) == expected


class Crash(BaseException):
    """Like process death: executors must not convert it into a typed failure."""


@contextmanager
def crash_at_save(position, moment):
    """Fail the Nth state save, either before it is durable or just after."""
    real, count = Project._save, [0]
    def save(self, document):
        count[0] += 1
        if count[0] == position + 1 and moment == 'before':
            raise Crash()
        real(self, document)
        if count[0] == position + 1:
            raise Crash()
    Project._save = save
    try:
        yield
    finally:
        Project._save = real


@pytest.mark.parametrize('moment', ['before', 'after'])
@pytest.mark.parametrize('position', [0, 1, 2, 3])
def test_protect_resumes_from_every_state_save(tmp_path, position, moment):
    provider = DevelopmentKeyProvider()
    with application() as app:
        with crash_at_save(position, moment), pytest.raises(Crash):
            protect(app, restart(app, provider, tmp_path))
        assert protect(app, restart(app, provider, tmp_path)).phase == 'ACTIVE'
        assert read_all(app, restart(app, provider, tmp_path)) == app.source


@pytest.mark.parametrize('moment', ['before', 'after'])
@pytest.mark.parametrize('purpose,position', [
    ('payload', 0), ('payload', 1), ('payload', 2), ('payload', 3),
    ('search', 1), ('search', 2),
    ('wrapping', 0), ('wrapping', 1), ('wrapping', 2)])
def test_rotation_resumes_from_every_state_save(tmp_path, purpose, position, moment):
    provider, target = DevelopmentKeyProvider(), DevelopmentKeyProvider()
    options = {'provider': target} if purpose == 'wrapping' else {}
    finish = target if purpose == 'wrapping' else provider
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        with crash_at_save(position, moment), pytest.raises(Crash):
            restart(app, provider, tmp_path).project.rotate(app.owner, purpose, writers_stopped=STOPPED, **options)
        restart(app, provider, tmp_path).project.rotate(app.owner, purpose, writers_stopped=STOPPED, **options)
        assert read_all(app, restart(app, finish, tmp_path)) == app.source


@pytest.mark.parametrize('moment', ['before', 'after'])
@pytest.mark.parametrize('position', [0, 1, 2])
def test_decrypt_resumes_from_every_state_save(tmp_path, position, moment):
    provider = DevelopmentKeyProvider()
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        inputs = dict(plaintext_role=least_privilege_role(app), writers_stopped=STOPPED, accept_plaintext=True,
                      retained_backups='No backups were taken of this disposable fixture.')
        with crash_at_save(position, moment), pytest.raises(Crash):
            restart(app, provider, tmp_path).project.decrypt(app.owner, **inputs)
        assert restart(app, provider, tmp_path).project.decrypt(app.owner, **inputs).phase == 'PLAINTEXT_ACTIVE'
        assert native_rows(app) == app.source


def _changed_search(app):
    return manifest_of(app, queries=['equality'], accept_leakage=['equality'])


def _process_for(app, op, provider, tmp_path):
    return restart(app, provider, tmp_path, indexed=op != 'modify',
                   **({'manifest': _changed_search(app)} if op == 'modify' else {}))


def _start_change(app, provider, tmp_path, op, target):
    """Return the call that starts or resumes one lifecycle operation."""
    project = _process_for(app, op, provider, tmp_path).project
    if op == 'wrapping':
        return lambda: project.rotate(app.owner, op, writers_stopped=STOPPED, provider=target)
    if op == 'modify':
        return lambda: project.modify(app.owner, writers_stopped=STOPPED, search_reviewed=REVIEWED)
    if op == 'tenant':
        return lambda: project.add_tenant(app.owner, UUID(int=7777), writers_stopped=STOPPED)
    if op == 'decrypt':
        return lambda: project.decrypt(app.owner, plaintext_role=least_privilege_role(app), writers_stopped=STOPPED,
            accept_plaintext=True, retained_backups='No backups were taken of this disposable fixture.')
    return lambda: project.rotate(app.owner, op, writers_stopped=STOPPED)


def _fixture_for(op):
    return application(unique=False, queries=[]) if op == 'modify' else application()


def _protect_for(app, op, provider, tmp_path):
    restart(app, provider, tmp_path, indexed=op != 'modify').project.protect(
        app.owner, runtime_role=app.role, writers_stopped=STOPPED,
        **({} if op == 'modify' else {'search_reviewed': REVIEWED}), chunk_size=2)


@pytest.mark.parametrize('moment', ['before', 'after'])
@pytest.mark.parametrize('op,position', [('modify', 0), ('modify', 1), ('modify', 2), ('modify', 3),
                                         ('tenant', 0), ('tenant', 1), ('tenant', 2)])
def test_modify_and_tenant_resume_from_every_state_save(tmp_path, op, position, moment):
    provider = DevelopmentKeyProvider()
    with _fixture_for(op) as app:
        _protect_for(app, op, provider, tmp_path)
        with crash_at_save(position, moment), pytest.raises(Crash):
            _start_change(app, provider, tmp_path, op, None)()
        assert _start_change(app, provider, tmp_path, op, None)().phase == 'ACTIVE'
        assert read_all(app, _process_for(app, op, provider, tmp_path)) == app.source


@pytest.mark.parametrize('moment', ['before', 'after'])
def test_remove_resumes_after_its_state_save(tmp_path, moment):
    provider = DevelopmentKeyProvider()
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        _start_change(app, provider, tmp_path, 'decrypt', None)()
        inputs = dict(writers_stopped=STOPPED, old_workers_stopped=True,
                      application_verified='Native application passed its own CRUD checks.')
        with crash_at_save(0, moment), pytest.raises(Crash):
            restart(app, provider, tmp_path).project.remove(app.owner, **inputs)
        assert restart(app, provider, tmp_path).project.remove(app.owner, **inputs).phase == 'REMOVED'
        assert restart(app, provider, tmp_path).project.remove(app.owner, **inputs).phase == 'REMOVED'
        assert restart(app, provider, tmp_path).project.status(app.owner).phase == 'REMOVED'
        assert native_rows(app) == app.source


ALL_CHANGES = ['payload', 'search', 'wrapping', 'modify', 'tenant', 'decrypt']


def _pending(tmp_path):
    return json.loads((tmp_path / 'state.json').read_bytes())['pending']


@pytest.mark.parametrize('op', ALL_CHANGES)
def test_status_reports_every_step_of_an_unfinished_operation(tmp_path, op):
    provider, target = DevelopmentKeyProvider(), DevelopmentKeyProvider()
    with _fixture_for(op) as app:
        _protect_for(app, op, provider, tmp_path)
        steps = 0
        while True:  # Stop right after each save, so every recorded step is observed.
            with crash_at_save(0, 'after'), pytest.raises(Crash):
                _start_change(app, provider, tmp_path, op, target)()
            pending = _pending(tmp_path)
            if pending is None:
                break
            steps += 1
            assert pending['op'] == op
            assert _process_for(app, op, provider, tmp_path).project.status(app.owner).phase
        assert steps >= 2


@pytest.mark.parametrize('op', ALL_CHANGES)
def test_abort_cancels_an_operation_that_has_not_switched(tmp_path, op):
    provider, target = DevelopmentKeyProvider(), DevelopmentKeyProvider()
    with _fixture_for(op) as app:
        _protect_for(app, op, provider, tmp_path)
        before = stored(app)
        with crash_at_save(0, 'after'), pytest.raises(Crash):
            _start_change(app, provider, tmp_path, op, target)()
        _process_for(app, op, provider, tmp_path).project.abort(app.owner, writers_stopped=STOPPED)
        assert _pending(tmp_path) is None
        assert stored(app) == before
        assert read_all(app, restart(app, provider, tmp_path, indexed=op != 'modify')) == app.source


def test_completed_switch_cannot_be_aborted(tmp_path):
    provider = DevelopmentKeyProvider()
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        with crash_at_save(2, 'after'), pytest.raises(Crash):  # Switched; awaiting activation.
            restart(app, provider, tmp_path).project.rotate(app.owner, 'payload', writers_stopped=STOPPED)
        with pytest.raises(TransitionFailure):
            restart(app, provider, tmp_path).project.abort(app.owner, writers_stopped=STOPPED)
        restart(app, provider, tmp_path).project.rotate(app.owner, 'payload', writers_stopped=STOPPED)
        assert read_all(app, restart(app, provider, tmp_path)) == app.source


def test_unsafe_state_and_mismatched_inputs_refuse(tmp_path):
    provider = DevelopmentKeyProvider()
    with application() as app:
        process = restart(app, provider, tmp_path)
        protect(app, process)
        changed = manifest_of(app, queries=['equality'], accept_leakage=['equality'])
        with pytest.raises(ProjectError, match='ManifestChanged'):
            (lambda p: p.project.attach(p.runtime))(restart(app, provider, tmp_path, manifest=changed))
        with pytest.raises(KeyUnavailable):
            read_all(app, restart(app, DevelopmentKeyProvider(), tmp_path))
        with pytest.raises(ProjectError, match='InvalidRotation'):
            process.project.rotate(app.owner, 'everything', writers_stopped=STOPPED)
        with pytest.raises(ProjectError, match='ProviderRequired'):
            process.project.rotate(app.owner, 'wrapping', writers_stopped=STOPPED)
        with pytest.raises(ProjectError, match='NothingToAbort'):
            process.project.abort(app.owner, writers_stopped=STOPPED)
        # The active source cannot adopt itself as a restored copy.
        with pytest.raises(TransitionFailure, match='restore_source_is_current'):
            process.project.recover(app.owner, host='operator', quarantine='isolated network', source_fenced=True)
        state = tmp_path / 'state.json'
        state.chmod(0o666)
        with pytest.raises(ProjectError, match='StateNotPrivate'):
            process.project.status(app.owner)
        state.chmod(0o600)
        document = json.loads(state.read_bytes())
        recorded_plan = document['plan']
        malformed = json.loads(recorded_plan)
        malformed['unexpected_authority'] = True
        document['plan'] = json.dumps(malformed, sort_keys=True, separators=(',', ':'))
        state.write_text(json.dumps(document))

        def forbidden(*args, **kwargs):
            pytest.fail('invalid saved plan reached the database')

        event.listen(app.owner, 'engine_connect', forbidden)
        try:
            with pytest.raises(TransitionFailure, match='invalid_plan'):
                process.project.status(app.owner)
        finally:
            event.remove(app.owner, 'engine_connect', forbidden)
        document['plan'] = recorded_plan
        document['format'] = 'something-else'
        state.write_text(json.dumps(document))
        with pytest.raises(ProjectError, match='StateUnreadable'):
            process.project.status(app.owner)


def test_abort_cancels_unfinished_work_and_other_operations_wait(tmp_path):
    provider = DevelopmentKeyProvider()
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        before = stored(app)
        with crash_at_save(0, 'after'), pytest.raises(Crash):
            restart(app, provider, tmp_path).project.rotate(app.owner, 'payload', writers_stopped=STOPPED)
        process = restart(app, provider, tmp_path)
        with pytest.raises(ProjectError, match='OperationInProgress'):
            process.project.attach(process.runtime)
        with pytest.raises(ProjectError, match='OperationInProgress'):
            process.project.rotate(app.owner, 'search', writers_stopped=STOPPED)
        process.project.abort(app.owner, writers_stopped=STOPPED)
        assert stored(app) == before
        assert read_all(app, restart(app, provider, tmp_path)) == app.source


def test_changed_manifest_enables_search_on_protected_field(tmp_path):
    provider = DevelopmentKeyProvider()
    with application(unique=False, queries=[]) as app:
        process = restart(app, provider, tmp_path, indexed=False)
        process.project.protect(app.owner, runtime_role=app.role, writers_stopped=STOPPED, chunk_size=2)
        changed = manifest_of(app, queries=['equality'], accept_leakage=['equality'])
        process = restart(app, provider, tmp_path, manifest=changed, indexed=False)
        with pytest.raises(ProjectError, match='StatementRequired'):
            process.project.modify(app.owner, writers_stopped=STOPPED)
        assert process.project.modify(app.owner, writers_stopped=STOPPED, search_reviewed=REVIEWED).phase == 'ACTIVE'
        process = restart(app, provider, tmp_path, manifest=changed, indexed=False)
        sessions = process.project.attach(process.runtime)
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(process.Customer.id).where(process.Customer.name == 'exact')) == UUID(int=105)


def test_new_tenant_gets_its_own_keys(tmp_path):
    provider = DevelopmentKeyProvider()
    tenant = uuid4()
    with application() as app:
        protect(app, restart(app, provider, tmp_path))
        assert restart(app, provider, tmp_path).project.add_tenant(
            app.owner, tenant, writers_stopped=STOPPED).phase == 'ACTIVE'
        process = restart(app, provider, tmp_path)
        sessions = process.project.attach(process.runtime)
        with sessions(tenant_id=tenant) as session:
            session.add(process.Customer(id=UUID(int=9000), tenant_id=tenant, name='exact'))
            session.commit()
            assert session.scalars(select(process.Customer.name).where(process.Customer.tenant_id == tenant)).all() == ['exact']
        with sessions(tenant_id=TENANT) as session:
            assert session.scalars(select(process.Customer.name).where(
                process.Customer.tenant_id == TENANT, process.Customer.name == 'exact')).all() == ['exact']
        document = json.loads((tmp_path / 'state.json').read_bytes())
        roots = {w['root'] for entry in document['keys'].values() for w in entry['wrappers']}
        assert len(document['keys']) == 2 and len(roots) == 4
        # The enlarged deployment still rotates and exits like any other.
        restart(app, provider, tmp_path).project.rotate(app.owner, 'payload', writers_stopped=STOPPED)
        restart(app, provider, tmp_path).project.rotate(app.owner, 'wrapping', writers_stopped=STOPPED,
                                                        provider=(moved := DevelopmentKeyProvider()))
        assert restart(app, moved, tmp_path).project.decrypt(
            app.owner, plaintext_role=least_privilege_role(app), writers_stopped=STOPPED, accept_plaintext=True,
            retained_backups='No backups were taken of this disposable fixture.').phase == 'PLAINTEXT_ACTIVE'
        assert native_rows(app) == {**app.source, UUID(int=9000): (tenant, 'exact')}


def test_online_protection_keeps_native_writes_until_the_fence(tmp_path, online_app, monkeypatch):
    app = online_app
    from cryptalis import online
    provider = DevelopmentKeyProvider()
    declaration = json.dumps(app.plan.document['lock']['declaration']).encode()
    real, calls = online._chunk, [0]
    def chunk(*args, **kwargs):
        calls[0] += 1
        if calls[0] == 2:  # Between committed chunks, while capture is running.
            with app.source_factory() as session:
                session.get(app.Customer, UUID(int=20)).body = 'written during capture'
                session.commit()
        return real(*args, **kwargs)
    monkeypatch.setattr(online, '_chunk', chunk)
    project = Project(declaration, app.mapping, provider=provider, state_dir=tmp_path)
    with pytest.raises(ProjectError, match='PlaintextCaptureNotAccepted'):
        project.protect_online(app.owner, runtime_role=app.target_role, source_role=app.source_role,
                               writers_excluded=STOPPED, search_reviewed=REVIEWED, accept_plaintext_capture=False)
    assert project.protect_online(app.owner, runtime_role=app.target_role, source_role=app.source_role,
                                  writers_excluded=STOPPED, search_reviewed=REVIEWED,
                                  accept_plaintext_capture=True).phase == 'ACTIVE'
    assert calls[0] >= 2
    with app.source.connect() as connection, pytest.raises(DBAPIError):
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=label')

    mapping = registry(metadata=MetaData(schema=app.schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('body', Text(collation='C')), Column('label', app.table.c.label.type))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    sessions = Project(declaration, mapping, provider=provider, state_dir=tmp_path).attach(app.target)
    table_id = UUID(app.plan.document['lock']['models'][0]['table_id'])
    with sessions(tenant_id=table_id) as session:
        assert session.get(Customer, UUID(int=20)).body == 'written during capture'
        assert session.get(Customer, UUID(int=10)).body == 'body-10'
        assert session.scalar(select(Customer.id).where(Customer.body == 'body-30')) == UUID(int=30)


@pytest.mark.parametrize('position', [0, 1, 2, 3, 4])
def test_online_protection_resumes_from_every_state_save(tmp_path, online_app, position):
    app = online_app
    provider = DevelopmentKeyProvider()
    declaration = json.dumps(app.plan.document['lock']['declaration']).encode()
    def start():
        return Project(declaration, app.mapping, provider=provider, state_dir=tmp_path).protect_online(
            app.owner, runtime_role=app.target_role, source_role=app.source_role, writers_excluded=STOPPED,
            search_reviewed=REVIEWED, accept_plaintext_capture=True)
    with crash_at_save(position, 'after'), pytest.raises(Crash):
        start()
    observed = Project(declaration, app.mapping, provider=provider, state_dir=tmp_path).status(app.owner)
    assert observed is None if position == 0 else observed.phase  # The first save holds only keys.
    assert start().phase == 'ACTIVE'


def test_online_abort_restores_native_writers(tmp_path, online_app):
    app = online_app
    declaration = json.dumps(app.plan.document['lock']['declaration']).encode()
    project = Project(declaration, app.mapping, provider=DevelopmentKeyProvider(), state_dir=tmp_path)
    with crash_at_save(1, 'after'), pytest.raises(Crash):  # Sealed and retained; not switched.
        project.protect_online(app.owner, runtime_role=app.target_role, source_role=app.source_role,
                               writers_excluded=STOPPED, search_reviewed=REVIEWED, accept_plaintext_capture=True)
    project.abort(app.owner, writers_stopped=STOPPED)
    assert _pending(tmp_path) is None
    with app.source_factory() as session:
        session.get(app.Customer, UUID(int=20)).body = 'native writes work again'
        session.commit()


def _two_table_app():
    """Two protected single-tenant tables and one tenant-column table, as one process maps them."""
    mapping = registry(metadata=MetaData(schema='cryptalis_two_' + uuid4().hex))
    def model(name, *columns):
        table = Table(name, mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False), *columns)
        cls = type(name.title(), (), {})
        mapping.map_imperatively(cls, table)
        return cls
    return SimpleNamespace(mapping=mapping,
        Account=model('account', Column('secret', Text(collation='C'))),
        Setting=model('setting', Column('secret', Text(collation='C'))),
        Note=model('note', Column('tenant_id', Uuid, nullable=False), Column('secret', Text(collation='C'))))


_ACCOUNT, _SETTING, _NOTE = UUID(int=7001), UUID(int=7002), UUID(int=7003)


def _two_table_manifest(*, tenant_table=False):
    field = lambda number: {'name': 'secret', 'field_id': str(UUID(int=number)), 'protect': True,
                            'queries': [], 'accept_leakage': []}
    models = [{'model': 'Account', 'table_id': str(_ACCOUNT), 'tenancy': {'single_tenant': True}, 'fields': [field(7101)]},
              {'model': 'Setting', 'table_id': str(_SETTING), 'tenancy': {'single_tenant': True}, 'fields': [field(7102)]}]
    if tenant_table:
        models.append({'model': 'Note', 'table_id': str(_NOTE), 'tenancy': {'column': 'tenant_id'}, 'fields': [field(7103)]})
    return json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(UUID(int=7000)),
                       'models': models}).encode()


@contextmanager
def _two_tables(*, tenant_table=False):
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    app = _two_table_app()
    schema = app.mapping.metadata.schema
    with runtime.connect() as connection:
        role = connection.exec_driver_sql('SELECT current_user').scalar_one()
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        app.mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}" TO "{role}"')
        with sessionmaker(owner)() as session:
            session.add_all([app.Account(id=UUID(int=1), secret='account-one'), app.Setting(id=UUID(int=2), secret='setting-two')])
            if tenant_table:
                session.add(app.Note(id=UUID(int=3), tenant_id=TENANT, secret='note-three'))
            session.commit()
        yield app, owner, runtime, role
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


def test_one_session_spans_every_single_tenant_table(tmp_path):
    with _two_tables() as (app, owner, runtime, role):
        project = Project(_two_table_manifest(), app.mapping, provider=DevelopmentKeyProvider(), state_dir=tmp_path)
        project.protect(owner, runtime_role=role, writers_stopped=STOPPED)
        sessions = project.attach(runtime)
        with sessions() as session:  # A non-multi-tenant application names no tenant.
            account, setting = session.get(app.Account, UUID(int=1)), session.get(app.Setting, UUID(int=2))
            assert (account.secret, setting.secret) == ('account-one', 'setting-two')
            account.secret, setting.secret = 'account-edit', 'setting-edit'
            session.add(app.Account(id=UUID(int=11), secret='account-new'))
            session.commit()
            assert session.scalars(select(app.Account.secret).order_by(app.Account.id)).all() == ['account-edit', 'account-new']
            session.add(app.Setting(id=UUID(int=1), secret='setting-one'))
            session.commit()
            pairs = session.execute(select(app.Account.secret, app.Setting.secret).join(
                app.Setting, app.Account.id == app.Setting.id)).all()
            assert [tuple(row) for row in pairs] == [('account-edit', 'setting-one')]
            session.delete(session.get(app.Account, UUID(int=11)))
            session.commit()
            assert session.get(app.Account, UUID(int=11)) is None
        document = json.loads((tmp_path / 'state.json').read_bytes())
        assert set(document['keys']) == {str(_ACCOUNT), str(_SETTING)}  # Each table keeps its own keys.


def test_tenant_session_also_reaches_shared_tables_but_needs_a_tenant_for_its_own(tmp_path):
    with _two_tables(tenant_table=True) as (app, owner, runtime, role):
        project = Project(_two_table_manifest(tenant_table=True), app.mapping,
                          provider=DevelopmentKeyProvider(), state_dir=tmp_path)
        project.protect(owner, runtime_role=role, writers_stopped=STOPPED)
        sessions = project.attach(runtime)
        with sessions(tenant_id=TENANT) as session:
            note, setting = session.get(app.Note, UUID(int=3)), session.get(app.Setting, UUID(int=2))
            assert (note.secret, setting.secret) == ('note-three', 'setting-two')
            note.secret, setting.secret = 'note-edit', 'setting-edit'
            session.commit()
            assert session.scalar(select(app.Note.secret)) == 'note-edit'
        with sessions() as session:
            assert session.get(app.Setting, UUID(int=2)).secret == 'setting-edit'
            with pytest.raises(UnsupportedProtectedOperation):  # No tenant, no tenant-scoped data.
                session.scalar(select(app.Note.secret))
        with sessions(tenant_id=TENANT) as session:
            other = app.Note(id=UUID(int=4), tenant_id=uuid4(), secret='wrong tenant')
            session.add(other)
            with pytest.raises(AuthenticationFailed):  # The tenant check still applies.
                session.commit()
            session.rollback()


def test_session_without_a_tenant_refuses_when_nothing_is_single_tenant(tmp_path):
    provider = DevelopmentKeyProvider()
    with application() as app:
        process = restart(app, provider, tmp_path)
        protect(app, process)
        sessions = process.project.attach(process.runtime)
        with pytest.raises(PolicyMismatch):
            sessions()


def test_unknown_tenant_refuses_before_any_shared_key_lookup(tmp_path):
    with _two_tables(tenant_table=True) as (app, owner, runtime, role):
        project = Project(_two_table_manifest(tenant_table=True), app.mapping,
                          provider=DevelopmentKeyProvider(), state_dir=tmp_path)
        project.protect(owner, runtime_role=role, writers_stopped=STOPPED)
        plan = MigrationPlan(json.loads((tmp_path / 'state.json').read_bytes())['plan'].encode())
        pin = DeploymentPin(plan.target_id, plan.operation_id, plan.digest, 'ACTIVE')
        resolutions = []

        def observe(scope):
            resolutions.append(scope)
            raise KeyUnavailable()

        monitored = attach(app.mapping, runtime, lock=plan.lock_bytes, keys=observe, deployment=(plan, pin))
        with pytest.raises(PolicyMismatch):
            monitored(tenant_id=uuid4())
        assert resolutions == []
        with pytest.raises(KeyUnavailable):
            monitored(tenant_id=TENANT)
        assert resolutions == [TENANT]
