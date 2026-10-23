"""Native owner-role oracle for one mapped tenant-and-record DELETE, no RETURNING."""
from uuid import UUID

import pytest
from sqlalchemy import BigInteger, delete, event, inspect, select
from sqlalchemy.exc import DBAPIError, PendingRollbackError, ResourceClosedError
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import ObjectDeletedError

from test_bulk_insert_native import assert_aborted
from test_sqlalchemy_adapter import app as native_app, db, TENANT, OTHER


def identities(app):
    return (-(2**63), 0, 2**63-1) if isinstance(app.Customer.__table__.c.id.type, BigInteger) else (
        UUID(int=0), UUID(int=1), UUID(int=2))


def seed(app, *, referenced=False):
    ids = identities(app)
    with Session(app.engine) as session:
        session.add_all(app.Customer(id=identity, tenant_id=OTHER if index == 2 else TENANT,
            name='native-' + str(index), note='public native value', secret=None, rank=index)
            for index, identity in enumerate(ids))
        session.flush()
        if referenced:
            session.add(app.Article(id=UUID(int=900), customer_id=ids[0], title='native foreign key'))
        session.commit()
    return ids


def statement(app, identity):
    return delete(app.Customer).where(app.Customer.tenant_id == TENANT, app.Customer.id == identity)


def execute(session, app, identity):
    return session.execute(statement(app, identity), execution_options={'synchronize_session': False})


def stored(app):
    with app.engine.connect() as connection:
        return connection.execute(select(app.Customer.__table__).order_by(app.Customer.id)).all()


@pytest.mark.parametrize('native_app', [{}, {'bigint': True}], indirect=True, ids=['uuid', 'int64'])
def test_native_scoped_delete_rowcounts_closed_rows_and_transactional_visibility(native_app):
    app = native_app
    ids = seed(app)
    before = stored(app)
    missing = -7 if type(ids[0]) is int else UUID(int=999)
    with Session(app.engine) as session:
        for identity, count in ((ids[0], 1), (ids[0], 0), (missing, 0), (ids[2], 0)):
            result = execute(session, app, identity)
            assert result.rowcount == count and result.returns_rows is False
            with pytest.raises(ResourceClosedError):
                result.all()
        assert len(session.identity_map) == 0
        assert session.scalar(select(app.Customer.id).where(app.Customer.id == ids[0])) is None
        assert stored(app) == before
        session.rollback()
        assert stored(app) == before
        assert execute(session, app, ids[0]).rowcount == 1
        session.commit()
    assert stored(app) == before[1:]


@pytest.mark.parametrize('native_app', [{}, {'bigint': True}], indirect=True, ids=['uuid', 'int64'])
def test_native_false_synchronization_keeps_loaded_identity_until_explicit_expiry(native_app):
    app = native_app
    identity = seed(app)[0]
    with Session(app.engine, expire_on_commit=False) as session:
        loaded = session.get(app.Customer, identity)
        assert execute(session, app, identity).rowcount == 1
        assert inspect(loaded).persistent and not inspect(loaded).deleted
        assert session.get(app.Customer, identity) is loaded
        session.commit()
        assert loaded.name == 'native-0' and session.get(app.Customer, identity) is loaded
        session.expire(loaded)
        with pytest.raises(ObjectDeletedError):
            _ = loaded.name
    with Session(app.engine) as session:
        assert session.get(app.Customer, identity) is None


@pytest.mark.parametrize('native_app', [{}, {'bigint': True}], indirect=True, ids=['uuid', 'int64'])
def test_native_delete_autoflushes_pending_insert_and_rollback_restores_original(native_app):
    app = native_app
    seed(app)
    before, commands = stored(app), []
    identity = 123456 if type(identities(app)[0]) is int else UUID(int=123456)

    def observe(connection, cursor, sql, parameters, context, executemany):
        command = sql.lstrip().split()[0].upper()
        if command in ('INSERT', 'DELETE'):
            commands.append(command)

    event.listen(app.engine, 'before_cursor_execute', observe)
    try:
        with Session(app.engine) as session:
            pending = app.Customer(id=identity, tenant_id=TENANT, name='pending native', rank=7)
            session.add(pending)
            assert execute(session, app, identity).rowcount == 1
            assert commands == ['INSERT', 'DELETE']
            assert inspect(pending).persistent
            assert session.scalar(select(app.Customer.id).where(app.Customer.id == identity)) is None
            session.rollback()
    finally:
        event.remove(app.engine, 'before_cursor_execute', observe)
    assert stored(app) == before


@pytest.mark.parametrize('native_app', [{}, {'bigint': True}], indirect=True, ids=['uuid', 'int64'])
def test_native_foreign_key_failure_aborts_then_savepoint_rollback_preserves_outer_work(native_app):
    app = native_app
    identity = seed(app, referenced=True)[0]
    before = stored(app)
    outer_id = 123456 if type(identity) is int else UUID(int=123456)
    with Session(app.engine) as session:
        with pytest.raises(DBAPIError) as failed:
            execute(session, app, identity)
        assert failed.value.orig.sqlstate == '23503'
        assert_aborted(session)
        session.rollback()
        assert stored(app) == before
        session.add(app.Customer(id=outer_id, tenant_id=TENANT, name='outer native', rank=9))
        session.flush()
        savepoint = session.begin_nested()
        with pytest.raises(DBAPIError) as nested:
            execute(session, app, identity)
        assert nested.value.orig.sqlstate == '23503'
        assert_aborted(session)
        savepoint.rollback()
        assert session.scalar(select(app.Customer.name).where(app.Customer.id == outer_id)) == 'outer native'
        assert session.execute(delete(app.Article).where(app.Article.id == UUID(int=900)),
                               execution_options={'synchronize_session': False}).rowcount == 1
        assert execute(session, app, identity).rowcount == 1
        session.commit()
    with Session(app.engine) as session:
        assert session.get(app.Customer, identity) is None
        assert session.get(app.Customer, outer_id).name == 'outer native'
        assert session.scalar(select(app.Article.id)) is None


def test_native_autoflush_unique_failure_precedes_delete_and_requires_session_rollback(native_app):
    app = native_app
    identity = seed(app)[0]
    before, deletes = stored(app), []

    def observe(connection, cursor, sql, parameters, context, executemany):
        if sql.lstrip().upper().startswith('DELETE '):
            deletes.append(True)

    event.listen(app.engine, 'before_cursor_execute', observe)
    try:
        with Session(app.engine) as session:
            session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT, name='native-0', rank=9))
            with pytest.raises(DBAPIError) as failed:
                execute(session, app, identity)
            assert failed.value.orig.sqlstate == '23505'
            assert session.is_active is False and deletes == []
            with pytest.raises(PendingRollbackError):
                session.scalar(select(1))
            assert stored(app) == before
            session.rollback()
            assert execute(session, app, identity).rowcount == 1
            session.rollback()
    finally:
        event.remove(app.engine, 'before_cursor_execute', observe)
    assert stored(app) == before
