"""ON CONFLICT and INSERT .values(...) against a native PostgreSQL oracle."""

import asyncio
from contextlib import contextmanager
import json
import os
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Column, DateTime, MetaData, Table, Text, Uuid, bindparam, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session, registry

from cryptalis import Project
from cryptalis.crypto import AuthenticationFailed, DevelopmentKeyProvider
from cryptalis.sqlalchemy import UnsupportedProtectedOperation
from test_migration import engine, TENANT
from test_project import REVIEWED, STOPPED

ONE, TWO, THREE = UUID(int=1), UUID(int=2), UUID(int=3)
COUNTED = {'preserve_rowcount': True}  # INSERT reports its real count only on request, natively too.
OTHER_TENANT = UUID(int=9001)
ACCOUNT, NOTE = UUID(int=8001), UUID(int=8002)


def field(number, name, queries):
    return {'name': name, 'field_id': str(UUID(int=number)), 'protect': True, 'queries': queries,
            'accept_leakage': queries}


MANIFEST = json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(UUID(int=8000)), 'models': [
    {'model': 'Account', 'table_id': str(ACCOUNT), 'tenancy': {'single_tenant': True},
     'fields': [field(8101, 'email', ['equality', 'unique']), field(8102, 'note', [])]},
    {'model': 'Note', 'table_id': str(NOTE), 'tenancy': {'column': 'tenant_id'}, 'fields': [field(8103, 'body', [])]},
]}).encode()


def mapped(schema):
    mapping = registry(metadata=MetaData(schema=schema))
    account = Table('account', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                    Column('email', Text(collation='C'), nullable=False, unique=True), Column('note', Text),
                    Column('plan', Text), Column('touched', DateTime(timezone=True)),
                    Column('created', DateTime(timezone=True), server_default=func.now(), nullable=False))
    note = Table('note', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                 Column('tenant_id', Uuid, nullable=False), Column('body', Text))

    class Account:
        pass

    class Note:
        pass
    mapping.map_imperatively(Account, account)
    mapping.map_imperatively(Note, note)
    return mapping, Account, Note


@contextmanager
def twins(tmp_path, *, attached=True):
    """The same schema twice: protected through Cryptalis, and left native as the oracle."""
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    oracle = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')  # Attachment guards `runtime` against native sessions.
    protected, native = 'upsert_' + uuid4().hex, 'upsert_native_' + uuid4().hex
    mapping, Account, Note = mapped(protected)
    native_mapping, NativeAccount, NativeNote = mapped(native)
    with runtime.connect() as connection:
        role = connection.exec_driver_sql('SELECT current_user').scalar_one()
    try:
        with owner.begin() as connection:
            for schema in (protected, native):
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
                connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        mapping.metadata.create_all(owner)
        native_mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            for schema in (protected, native):
                connection.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}" TO "{role}"')
        for model, note in ((Account, Note), (NativeAccount, NativeNote)):
            with Session(owner) as session:
                session.add(model(id=ONE, email='one@example.com', note='first', plan='free'))
                session.add(note(id=ONE, tenant_id=OTHER_TENANT, body='theirs'))
                session.add(note(id=TWO, tenant_id=TENANT, body='ours'))
                session.commit()
        project = Project(MANIFEST, mapping, provider=DevelopmentKeyProvider(), state_dir=tmp_path / 'state')
        project.protect(owner, runtime_role=role, writers_stopped=STOPPED, search_reviewed=REVIEWED)
        sessions = project.attach(runtime) if attached else project
        yield sessions, Account, Note, oracle, NativeAccount, NativeNote, owner, protected
    finally:
        runtime.dispose()
        oracle.dispose()
        with owner.begin() as connection:
            for schema in (protected, native):
                connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()


def rows(session, model):
    return session.execute(select(model.id, model.email, model.note, model.plan).order_by(model.id)).all()


def same_as_native(sessions, Account, runtime, NativeAccount, build):
    """Run one statement on both sides and require native results and final rows."""
    outcomes = []
    for model, factory in ((NativeAccount, lambda: Session(runtime)), (Account, lambda: sessions(tenant_id=TENANT))):
        with factory() as session:
            try:
                count = session.execute(build(model), execution_options=COUNTED).rowcount
                session.commit()
                outcome = ('ok', count)
            except IntegrityError as failure:
                session.rollback()
                outcome = ('refused', failure.orig.sqlstate)
            outcomes.append((outcome, rows(session, model)))
    assert outcomes[0] == outcomes[1]
    return outcomes[1][1]


def test_values_insert_matches_native(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        stored = same_as_native(sessions, Account, runtime, NativeAccount, lambda model: insert(model).values(
            id=TWO, email='two@example.com', note=None, plan='pro'))
        assert stored[1][1:] == ('two@example.com', None, 'pro')
        stored = same_as_native(sessions, Account, runtime, NativeAccount, lambda model: insert(model).values([
            {'id': THREE, 'email': 'three@example.com', 'note': 'n3', 'plan': 'free'},
            {'id': UUID(int=4), 'email': 'four@example.com', 'note': 'n4', 'plan': 'free'}]))
        assert [row[1] for row in stored] == ['one@example.com', 'two@example.com', 'three@example.com', 'four@example.com']


@pytest.mark.parametrize('target', [None, ['id'], ['email']])
def test_do_nothing_matches_native(tmp_path, target):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        conflict_id = ONE if target != ['email'] else TWO
        conflict_email = 'one@example.com' if target != ['id'] else 'new@example.com'
        conflicting = lambda model: pg_insert(model).values(
            id=conflict_id, email=conflict_email, note='ignored', plan='ignored').on_conflict_do_nothing(index_elements=target)
        assert same_as_native(sessions, Account, runtime, NativeAccount, conflicting)[0][1:] == ('one@example.com', 'first', 'free')
        fresh = lambda model: pg_insert(model).values(
            id=THREE, email='three@example.com', note='new', plan='pro').on_conflict_do_nothing(index_elements=target)
        assert len(same_as_native(sessions, Account, runtime, NativeAccount, fresh)) == 2


def test_do_update_on_the_primary_key_matches_native_and_stays_searchable(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        def upsert(model):
            statement = pg_insert(model).values(id=ONE, email='changed@example.com', note='second', plan='pro')
            return statement.on_conflict_do_update(index_elements=[model.id], set_={
                'email': statement.excluded.email, 'note': statement.excluded.note, 'plan': statement.excluded.plan})
        stored = same_as_native(sessions, Account, runtime, NativeAccount, upsert)
        assert stored[0][1:] == ('changed@example.com', 'second', 'pro')
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(Account.id).where(Account.email == 'changed@example.com')) == ONE
            assert session.scalar(select(Account.id).where(Account.email == 'one@example.com')) is None
            assert session.get(Account, ONE).note == 'second'


def test_do_update_keeps_native_errors_and_public_expressions(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        add = lambda model: insert(model).values(id=TWO, email='two@example.com', note='n', plan='p')
        same_as_native(sessions, Account, runtime, NativeAccount, add)

        def taken(model):
            statement = pg_insert(model).values(id=ONE, email='two@example.com')
            return statement.on_conflict_do_update(index_elements=['id'], set_={'email': statement.excluded.email})
        same_as_native(sessions, Account, runtime, NativeAccount, taken)

        def touched(model):
            statement = pg_insert(model).values(id=ONE, email='one@example.com', note='later')
            return statement.on_conflict_do_update(index_elements=['id'], set_={
                'note': statement.excluded.note, 'touched': func.now()})
        same_as_native(sessions, Account, runtime, NativeAccount, touched)
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(Account.touched).where(Account.id == ONE)) is not None


def refused(model):
    statement = pg_insert(model).values(id=ONE, email='one@example.com', note='x')
    excluded = statement.excluded
    return {
        'unique target would move a frame to another record': statement.on_conflict_do_update(
            index_elements=['email'], set_={'note': excluded.note}),
        'storage-only target': statement.on_conflict_do_nothing(index_elements=['note']),
        'literal for a protected column': statement.on_conflict_do_update(index_elements=['id'], set_={'note': 'plain'}),
        'another column\'s frame': statement.on_conflict_do_update(index_elements=['id'], set_={'note': excluded.email}),
        'protected value into a public column': statement.on_conflict_do_update(index_elements=['id'], set_={'plan': excluded.note}),
        'bind in a public expression': statement.on_conflict_do_update(index_elements=['id'], set_={'plan': 'pro'}),
        'row condition': statement.on_conflict_do_update(index_elements=['id'], set_={'note': excluded.note},
                                                         where=model.plan == 'free'),
        'named constraint': statement.on_conflict_do_update(constraint='account_pkey', set_={'note': excluded.note}),
        'partial index': statement.on_conflict_do_nothing(index_elements=['id'], index_where=model.plan == 'free'),
        'primary key assignment': statement.on_conflict_do_update(index_elements=['id'], set_={'id': excluded.id}),
        'returning': statement.on_conflict_do_nothing().returning(model.id),
    }


@pytest.mark.parametrize('case', list(refused(mapped('probe')[1])))
def test_unsafe_conflicts_refuse_before_the_driver(tmp_path, case):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        with sessions(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(refused(Account)[case])
            assert rows(session, Account)[0][1:] == ('one@example.com', 'first', 'free')


def test_tenant_tables_cannot_overwrite_another_tenants_row(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, NativeNote, owner, schema):
        with sessions(tenant_id=TENANT) as session:
            statement = pg_insert(Note).values(id=ONE, tenant_id=TENANT, body='mine')
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(statement.on_conflict_do_update(index_elements=['id'], set_={'body': statement.excluded.body}))
            session.rollback()
            assert session.execute(statement.on_conflict_do_nothing(), execution_options=COUNTED).rowcount == 0
            assert session.execute(pg_insert(Note).values(id=TWO, tenant_id=TENANT, body='other').on_conflict_do_nothing(),
                                   execution_options=COUNTED).rowcount == 0
            session.commit()
        with sessions(tenant_id=OTHER_TENANT) as session:
            assert session.get(Note, ONE).body == 'theirs'
        with sessions(tenant_id=TENANT) as session:
            assert session.get(Note, TWO).body == 'ours'


def test_values_and_upserts_store_only_authenticated_frames(tmp_path):
    """An attached read would decrypt, so inspect bytes through an independent connection."""
    with twins(tmp_path) as (sessions, Account, Note, _, _, _, owner, schema):
        with sessions(tenant_id=TENANT) as session:
            session.execute(insert(Account).values(id=TWO, email='plain-two@example.com', note='plain-note-two'))
            session.execute(insert(Account).values([{'id': THREE, 'email': 'plain-three@example.com', 'note': 'plain-note-three'}]))
            statement = pg_insert(Account).values(id=ONE, email='plain-one@example.com', note='plain-note-one')
            session.execute(statement.on_conflict_do_update(index_elements=['id'], set_={
                'email': statement.excluded.email, 'note': statement.excluded.note}))
            session.commit()
        with owner.connect() as connection:
            stored = connection.exec_driver_sql(f'SELECT id, email, note FROM "{schema}".account ORDER BY id').all()
        assert [row[0] for row in stored] == [ONE, TWO, THREE]
        for row in stored:
            for value in (bytes(row[1]), bytes(row[2])):
                assert value.startswith(b'CF1') and b'plain' not in value and b'example.com' not in value


def test_a_public_server_default_still_applies(tmp_path):
    with twins(tmp_path) as (sessions, Account, *_):
        with sessions(tenant_id=TENANT) as session:
            session.execute(insert(Account).values(id=TWO, email='two@example.com'))
            session.execute(insert(Account), [{'id': THREE, 'email': 'three@example.com'}])
            session.commit()
            assert None not in session.scalars(select(Account.created)).all()


def test_a_values_key_outside_the_table_is_a_typed_refusal(tmp_path):
    with twins(tmp_path) as (sessions, Account, *_):
        with sessions(tenant_id=TENANT) as session, pytest.raises(UnsupportedProtectedOperation):
            session.execute(insert(Account).values(id=TWO, email='two@example.com', unknown='x'))


def test_a_values_bind_without_a_value_is_not_stored_as_null(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, oracle, NativeAccount, *_):
        unset = lambda model: insert(model).values(id=TWO, email='two@example.com', note=bindparam('later'))
        with Session(oracle) as session, pytest.raises(Exception, match='later'):
            session.execute(unset(NativeAccount))  # Native SQLAlchemy refuses too.
        with sessions(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(unset(Account))
            assert len(rows(session, Account)) == 1


def test_a_values_insert_keeps_its_explicit_tenant_check(tmp_path):
    with twins(tmp_path) as (sessions, Account, Note, runtime, NativeAccount, _, _, _):
        with sessions(tenant_id=TENANT) as session, pytest.raises(AuthenticationFailed):
            session.execute(insert(Note).values(id=THREE, tenant_id=OTHER_TENANT, body='wrong tenant'))


def test_async_upsert_seals_and_stays_searchable(tmp_path):
    with twins(tmp_path, attached=False) as (project, Account, *_):
        async def journey():
            runtime = create_async_engine('postgresql+psycopg://', hide_parameters=True, async_creator=lambda:
                                          psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            try:
                sessions = await project.attach(runtime)
                async with sessions(tenant_id=TENANT) as session:
                    statement = pg_insert(Account).values(id=ONE, email='async@example.com', note='async')
                    updated = await session.execute(statement.on_conflict_do_update(index_elements=['id'], set_={
                        'email': statement.excluded.email, 'note': statement.excluded.note}), execution_options=COUNTED)
                    assert updated.rowcount == 1
                    await session.execute(insert(Account).values(id=TWO, email='two@example.com'))
                    await session.commit()
                async with sessions(tenant_id=TENANT) as session:
                    found = await session.scalar(select(Account).where(Account.email == 'async@example.com'))
                    assert (found.id, found.note) == (ONE, 'async')
                    assert await session.scalar(select(Account.id).where(Account.email == 'two@example.com')) == TWO
            finally:
                await runtime.dispose()
        asyncio.run(journey())
