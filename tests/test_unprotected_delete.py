"""Finite unprotected mapped DELETE retains native ORM and transaction behavior."""
import asyncio
import os
from types import MethodType
from uuid import uuid4

import psycopg
import pytest
from sqlalchemy import MetaData, Table, Uuid, bindparam, delete, event, func, inspect, or_, select
from sqlalchemy.exc import ResourceClosedError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import operators
from sqlalchemy.sql.dml import Delete
from sqlalchemy.sql.elements import BinaryExpression, BindParameter

from cryptalis.crypto import CryptoFailure
from cryptalis.sqlalchemy import attach
from test_driver_event_boundary import raw_calls
from test_sqlalchemy_adapter import app as adapter_app, db, factory, TENANT


def rows(app):
    identities = [uuid4() for _ in range(4)]
    parents = [app.Customer(id=identity, tenant_id=TENANT, name='public-' + str(identity),
        note='protected parent', secret='parent secret', rank=index)
        for index, identity in enumerate(identities[:2])]
    children = [app.Article(id=identity, customer=parents[index], title='public child')
                for index, identity in enumerate(identities[2:])]
    return parents, children


def cleanup_statement(app, owner):
    # Same mapped-table and UUID-literal filter as the unchanged users.py route.
    return delete(app.Article).where(app.Article.customer_id == owner)


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('synchronization', ['default', 'evaluate', False])
def test_plain_delete_native_synchronization_rowcount_rollback_and_commit(adapter_app, protected, synchronization):
    app = adapter_app
    sessions = factory(app, protected)
    parents, children = rows(app)
    owner, removed, retained = parents[0].id, children[0].id, children[1].id
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    options = {} if synchronization == 'default' else {'synchronize_session': synchronization}
    with sessions(tenant_id=TENANT) as session:
        loaded = session.get(app.Article, removed)
        parent = session.get(app.Customer, owner)
        parent.note = 'autoflushed parent'
        statement = cleanup_statement(app, owner).where(app.Article.title == 'public child')
        result = session.execute(statement, execution_options=options)
        assert result.rowcount == 1 and result.returns_rows is False
        with pytest.raises(ResourceClosedError):
            result.all()
        assert inspect(loaded).deleted is (synchronization is not False)
        if synchronization is False:
            assert session.get(app.Article, removed) is loaded
        else:
            assert session.get(app.Article, removed) is None
        session.rollback()
        assert inspect(loaded).persistent
        assert session.get(app.Article, removed) is loaded
        assert parent.note == 'protected parent'
        assert session.execute(statement, execution_options=options).rowcount == 1
        session.commit()
    with sessions(tenant_id=TENANT) as session:
        assert session.get(app.Article, removed) is None
        assert session.get(app.Article, retained).title == 'public child'
        assert session.get(app.Customer, owner).note == 'protected parent'
        assert session.execute(cleanup_statement(app, owner)).rowcount == 0
        session.rollback()


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
def test_plain_cleanup_then_protected_parent_flush_delete_matches_original_route(adapter_app, protected):
    app = adapter_app
    sessions = factory(app, protected)
    parents, children = rows(app)
    victim, survivor, retained = parents[0].id, parents[1].id, children[1].id
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    with sessions(tenant_id=TENANT) as session:
        user = session.get(app.Customer, victim)
        assert session.execute(cleanup_statement(app, victim)).rowcount == 1
        session.delete(user)
        session.commit()
    with sessions(tenant_id=TENANT) as session:
        assert session.get(app.Customer, victim) is None
        assert session.get(app.Customer, survivor).note == 'protected parent'
        assert session.scalars(select(app.Article.id)).all() == [retained]


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
def test_async_plain_delete_keeps_default_synchronization_rollback_and_parent_cleanup(adapter_app, protected):
    app = adapter_app
    if protected:
        app.switch()
    async def scenario():
        engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']))
        try:
            sessions = (await attach(app.mapping, engine, lock=app.plan.lock_bytes,
                                    keys=app.rings.__getitem__) if protected else async_sessionmaker(engine))
            create = lambda: sessions(tenant_id=TENANT) if protected else sessions()
            parents, children = rows(app)
            owner, removed, retained = parents[0].id, children[0].id, children[1].id
            async with create() as session:
                session.add_all(parents + children)
                await session.commit()
            async with create() as session:
                loaded = await session.get(app.Article, removed)
                result = await session.execute(cleanup_statement(app, owner))
                assert result.rowcount == 1 and result.returns_rows is False and inspect(loaded).deleted
                await session.rollback()
                assert await session.get(app.Article, removed) is loaded
                assert (await session.execute(cleanup_statement(app, owner),
                    execution_options={'synchronize_session': 'evaluate'})).rowcount == 1
                await session.delete(await session.get(app.Customer, owner))
                await session.commit()
            async with create() as session:
                assert await session.get(app.Customer, owner) is None
                assert (await session.get(app.Article, retained)).title == 'public child'
        finally:
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize('fault', ['whole_table', 'or', 'subquery', 'function', 'protected_reference',
    'returning', 'external_params', 'fetch', 'callable', 'custom_delete', 'custom_binary', 'custom_bind'])
def test_plain_delete_unadmitted_shapes_refuse_before_driver(adapter_app, fault, monkeypatch):
    app = adapter_app
    sessions = factory(app, True)
    identity = uuid4()
    statement, parameters, options = cleanup_statement(app, identity), None, {}
    if fault == 'whole_table': statement = delete(app.Article)
    elif fault == 'or': statement = delete(app.Article).where(or_(app.Article.customer_id == identity, app.Article.title == 'public'))
    elif fault == 'subquery': statement = delete(app.Article).where(app.Article.customer_id.in_(select(app.Customer.id)))
    elif fault == 'function': statement = delete(app.Article).where(func.lower(app.Article.title) == 'public')
    elif fault == 'protected_reference': statement = delete(app.Article).where(app.Article.customer_id == app.Customer.id)
    elif fault == 'returning': statement = statement.returning(app.Customer.note)
    elif fault == 'external_params': parameters = {'public_extra': identity}
    elif fault == 'fetch': options = {'synchronize_session': 'fetch'}
    elif fault == 'callable': statement = delete(app.Article).where(app.Article.customer_id == bindparam('owner', callable_=lambda: identity, type_=Uuid()))
    elif fault == 'custom_delete':
        class CustomDelete(Delete): pass
        statement = CustomDelete(app.Article).where(app.Article.customer_id == identity)
    elif fault == 'custom_binary':
        class CustomBinary(BinaryExpression): pass
        statement = delete(app.Article).where(CustomBinary(app.Article.customer_id,
            bindparam('owner', identity, type_=Uuid()), operators.eq))
    else:
        class CustomBind(BindParameter): pass
        statement = delete(app.Article).where(app.Article.customer_id == CustomBind('owner', identity, type_=Uuid()))
    with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
        with sessions(tenant_id=TENANT) as session:
            with pytest.raises(CryptoFailure):
                session.execute(statement, parameters, execution_options=options)
            session.rollback()
        assert sent == []


@pytest.mark.parametrize('lineage', ['same_table', 'separate_metadata'])
def test_plain_mapper_cannot_target_protected_physical_table(adapter_app, lineage, monkeypatch):
    app = adapter_app
    table = app.Customer.__table__
    if lineage == 'separate_metadata':
        table = table.to_metadata(MetaData(schema=app.schema))
    class Alternate: pass
    app.mapping.map_imperatively(Alternate, table)
    sessions = factory(app, True)
    statement = delete(Alternate).where(Alternate.id == uuid4())
    with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
        with sessions(tenant_id=TENANT) as session:
            with pytest.raises(CryptoFailure):
                session.execute(statement)
            session.rollback()
        assert sent == []


@pytest.mark.parametrize('fault', ['statement', 'compiled_and_sent'])
def test_plain_delete_cannot_retarget_after_original_admission(adapter_app, fault, monkeypatch):
    app = adapter_app
    sessions = factory(app, True)
    original, changed = uuid4(), uuid4()
    def replace(connection, statement, multiparams, params, options):
        if isinstance(statement, Delete):
            statement = cleanup_statement(app, changed)
        return statement, multiparams, params
    def rewrite(connection, cursor, sql, parameters, context, many):
        if sql.lstrip().upper().startswith('DELETE '):
            key = next(key for key, value in parameters.items() if value == original)
            parameters[key] = changed
            context.compiled_parameters[0][key] = changed
        return sql, parameters
    name, callback = ('before_execute', replace) if fault == 'statement' else ('before_cursor_execute', rewrite)
    event.listen(app.engine, name, callback, retval=True)
    try:
        with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with sessions(tenant_id=TENANT) as session:
                with pytest.raises(CryptoFailure):
                    session.execute(cleanup_statement(app, original))
                session.rollback()
            assert sent == []
    finally:
        event.remove(app.engine, name, callback)


@pytest.mark.parametrize('fault', ['column_name', 'processor', 'annotated_name', 'annotated_table', 'column_table',
    'target_name', 'target_schema', 'column_quote'])
def test_resolver_cannot_change_plain_delete_physical_predicate_or_type(adapter_app, fault, monkeypatch):
    app = adapter_app
    app.switch()
    column = app.Article.__table__.c.customer_id
    original_name, original_processor, original_table = column.name, column.type.bind_processor, column.table
    original_quote = original_name.quote
    alternate = original_table.alias('alternate_owner')
    armed, changed = [False], []
    def resolve(tenant):
        if armed[0] and not changed:
            changed.append(fault)
            if fault == 'column_name':
                column.name = 'id'
            elif fault == 'annotated_name':
                statement.whereclause.left.name = 'id'
            elif fault == 'annotated_table':
                statement.whereclause.left.table = alternate
            elif fault == 'column_table':
                column.table = alternate
            elif fault == 'target_name':
                statement.table.name = 'alternate_child'
            elif fault == 'target_schema':
                statement.table.schema = 'alternate_schema'
            elif fault == 'column_quote':
                column.name.quote = True
            else:
                column.type.bind_processor = MethodType(lambda self, dialect: lambda value: uuid4(), column.type)
            if fault in ('annotated_name', 'annotated_table', 'column_table', 'target_name', 'target_schema', 'column_quote'):
                assert str(statement.compile(dialect=app.engine.dialect)) != original_sql
        return app.rings[tenant]
    sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
    parents, children = rows(app)
    owner, child = parents[0].id, children[0].id
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    statement = (delete(app.Article).where(column == owner) if fault == 'column_table'
                 else cleanup_statement(app, owner))
    original_sql = str(statement.compile(dialect=app.engine.dialect))
    original_left_name, original_left_table = statement.whereclause.left.name, statement.whereclause.left.table
    original_target_name, original_target_schema = statement.table.name, statement.table.schema
    with raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
        with sessions(tenant_id=TENANT) as session:
            armed[0] = True
            try:
                with pytest.raises(CryptoFailure):
                    session.execute(statement)
                assert changed == [fault] and sent == []
            finally:
                armed[0] = False
                column.name = original_name
                column.name.quote = original_quote
                column.table = original_table
                statement.whereclause.left.name = original_left_name
                statement.whereclause.left.table = original_left_table
                statement.table.name = original_target_name
                statement.table.schema = original_target_schema
                if fault == 'processor':
                    del column.type.bind_processor
                assert column.type.bind_processor == original_processor
                session.rollback()
            assert session.get(app.Article, child) is not None
            assert session.execute(cleanup_statement(app, owner)).rowcount == 1
            session.rollback()
