"""Public mapped DELETE RETURNING preserves native results and transaction effects."""
import asyncio
from collections import Counter
import os
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import Text, Uuid, delete, event, func, inspect, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import aliased, selectinload
from sqlalchemy.sql.elements import quoted_name

from cryptalis.crypto import CryptoFailure, Keyring
from cryptalis.sqlalchemy import attach
from test_driver_event_boundary import raw_calls
from test_sqlalchemy_adapter import app as adapter_app, db, factory, TENANT
from test_unprotected_delete import cleanup_statement, rows


def fixture_rows(app):
    parents, children = rows(app)
    null_child = app.Article(id=uuid4(), customer=parents[0], title=None)
    children.append(null_child)
    return parents, children


def outputs(app, kind):
    if kind == 'scalar':
        return (app.Article.title,)
    if kind == 'tuple':
        return app.Article.id, app.Article.title
    return app.Article.id.label('record_id'), app.Article.title.label(quoted_name('select', True))


def check_result(result, columns, kind, expected):
    assert tuple(result.keys()) == tuple(column.key for column in columns)
    if kind == 'scalar':
        assert Counter(result.scalars().all()) == Counter(expected.values())
        return
    returned = result.all()
    assert {row[0]: row[1] for row in returned} == expected
    assert len(returned) == len(expected)
    for row in returned:
        assert type(row[0]) is UUID and (row[1] is None or type(row[1]) is str)
        for index, column in enumerate(columns):
            assert row._mapping[column] == row[index]
            assert row._mapping[column.key] == row[index]


def options(synchronization):
    return {} if synchronization == 'default' else {'synchronize_session': synchronization}


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('bridge', ['sqlalchemy', 'sqlmodel'])
def test_public_returning_native_outputs_synchronization_autoflush_and_transactions(adapter_app, protected, bridge):
    app = adapter_app
    if bridge == 'sqlmodel':
        from sqlmodel import Session
        from cryptalis.sqlmodel import attach as selected
        if protected:
            app.switch()
            sessions = selected(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
        else:
            sessions = lambda *, tenant_id: Session(app.engine)
    else:
        sessions = factory(app, protected)
    parents, children = fixture_rows(app)
    owner, removed, retained, null_child = parents[0].id, children[0].id, children[1].id, children[2].id
    expected = {removed: 'public child', null_child: None}
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    # Native compilation can reuse the first structurally equivalent label's
    # lookup identity. Reuse caller objects as well as their output names.
    projections = {kind: outputs(app, kind) for kind in ('scalar', 'tuple', 'labels')}
    for synchronization in ('default', 'auto', 'evaluate', False):
        for kind in ('scalar', 'tuple', 'labels'):
            columns = projections[kind]
            statement = cleanup_statement(app, owner).returning(*columns)
            with sessions(tenant_id=TENANT) as session:
                execute = session.exec if bridge == 'sqlmodel' else session.execute
                loaded = session.get(app.Article, removed)
                parent = session.get(app.Customer, owner)
                nested = session.begin_nested()
                parent.note = 'autoflushed by public returning'
                result = execute(statement, execution_options=options(synchronization))
                check_result(result, columns, kind, expected)
                assert inspect(loaded).deleted is (synchronization is not False)
                assert session.scalar(select(app.Customer.note).where(app.Customer.id == owner)) == 'autoflushed by public returning'
                nested.rollback()
                assert inspect(loaded).persistent
                assert session.get(app.Article, removed) is loaded
                assert parent.note == 'protected parent'
                missing = cleanup_statement(app, owner).where(app.Article.title == 'no such title').returning(*columns)
                assert execute(missing, execution_options=options(synchronization)).all() == []
                session.rollback()
    columns = projections['labels']
    with sessions(tenant_id=TENANT) as session:
        execute = session.exec if bridge == 'sqlmodel' else session.execute
        check_result(execute(cleanup_statement(app, owner).returning(*columns),
            execution_options={'synchronize_session': False}), columns, 'labels', expected)
        session.commit()
    with sessions(tenant_id=TENANT) as session:
        execute = session.exec if bridge == 'sqlmodel' else session.execute
        assert session.get(app.Article, removed) is None and session.get(app.Article, null_child) is None
        assert session.get(app.Article, retained).title == 'public child'
        assert session.get(app.Customer, owner).note == 'protected parent'
        assert execute(cleanup_statement(app, owner).returning(app.Article.title)).all() == []
        session.rollback()


@pytest.mark.parametrize('protected', [False, True], ids=['native', 'attached'])
@pytest.mark.parametrize('bridge', ['sqlalchemy', 'sqlmodel'])
def test_async_public_returning_native_results_savepoint_and_commit(adapter_app, protected, bridge):
    app = adapter_app
    if protected:
        app.switch()

    async def scenario():
        selected = attach
        from sqlalchemy.ext.asyncio import AsyncSession
        if bridge == 'sqlmodel':
            from sqlmodel.ext.asyncio.session import AsyncSession
            from cryptalis.sqlmodel import attach as selected
        engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']))
        try:
            sessions = (await selected(app.mapping, engine, lock=app.plan.lock_bytes,
                keys=app.rings.__getitem__) if protected else async_sessionmaker(engine, class_=AsyncSession))
            create = lambda: sessions(tenant_id=TENANT) if protected else sessions()
            parents, children = fixture_rows(app)
            owner, removed, retained, null_child = parents[0].id, children[0].id, children[1].id, children[2].id
            expected = {removed: 'public child', null_child: None}
            async with create() as session:
                session.add_all(parents + children)
                await session.commit()
            projections = {kind: outputs(app, kind) for kind in ('scalar', 'tuple', 'labels')}
            for synchronization in ('default', 'evaluate', False):
                for kind in ('scalar', 'tuple', 'labels'):
                    columns = projections[kind]
                    statement = cleanup_statement(app, owner).returning(*columns)
                    async with create() as session:
                        execute = session.exec if bridge == 'sqlmodel' else session.execute
                        loaded = await session.get(app.Article, removed)
                        parent = await session.get(app.Customer, owner)
                        nested = await session.begin_nested()
                        parent.note = 'async autoflush by public returning'
                        result = await execute(statement, execution_options=options(synchronization))
                        check_result(result, columns, kind, expected)
                        assert inspect(loaded).deleted is (synchronization is not False)
                        assert await session.scalar(select(app.Customer.note).where(app.Customer.id == owner)) == 'async autoflush by public returning'
                        await nested.rollback()
                        assert inspect(loaded).persistent
                        assert await session.get(app.Article, removed) is loaded
                        await session.refresh(parent)
                        assert parent.note == 'protected parent'
                        assert (await execute(cleanup_statement(app, uuid4()).returning(*columns),
                            execution_options=options(synchronization))).all() == []
                        await session.rollback()
            columns = projections['labels']
            async with create() as session:
                execute = session.exec if bridge == 'sqlmodel' else session.execute
                check_result(await execute(cleanup_statement(app, owner).returning(*columns),
                    execution_options={'synchronize_session': False}), columns, 'labels', expected)
                await session.commit()
            async with create() as session:
                execute = session.exec if bridge == 'sqlmodel' else session.execute
                assert await session.get(app.Article, removed) is None
                assert await session.get(app.Article, null_child) is None
                assert (await session.get(app.Article, retained)).title == 'public child'
                assert (await session.get(app.Customer, owner)).note == 'protected parent'
                assert (await execute(cleanup_statement(app, owner).returning(app.Article.title))).all() == []
                await session.rollback()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize('fault', ['entity', 'computed', 'alias', 'core', 'external', 'fetch', 'loader',
    'anonymous_label', 'unquoted_label', 'label_dispatch', 'label_type'])
def test_public_returning_unadmitted_shapes_refuse_before_driver(adapter_app, fault, monkeypatch):
    app = adapter_app
    sessions = factory(app, True)
    identity = uuid4()
    statement = cleanup_statement(app, identity).returning(app.Article.title)
    parameters, execution = None, {}
    if fault == 'entity':
        statement = cleanup_statement(app, identity).returning(app.Article)
    elif fault == 'computed':
        statement = cleanup_statement(app, identity).returning(func.upper(app.Article.title))
    elif fault == 'alias':
        statement = cleanup_statement(app, identity).returning(aliased(app.Article).title)
    elif fault == 'core':
        statement = delete(app.Article.__table__).where(app.Article.id == identity).returning(app.Article.title)
    elif fault == 'external':
        parameters = {'extra': identity}
    elif fault == 'fetch':
        execution = {'synchronize_session': 'fetch'}
    elif fault == 'loader':
        statement = statement.options(selectinload(app.Article.customer))
    elif fault == 'unquoted_label':
        statement = cleanup_statement(app, identity).returning(app.Article.title.label(quoted_name('title, 1', False)))
    elif fault in ('label_dispatch', 'label_type'):
        label = app.Article.title.label('visible_title')
        if fault == 'label_dispatch':
            label._compiler_dispatch = lambda *args, **kwargs: 'public_custom_label'
        else:
            label.type = Text()
        statement = cleanup_statement(app, identity).returning(label)
    else:
        statement = cleanup_statement(app, identity).returning(app.Article.title.label(None))
    with sessions(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
        with pytest.raises(CryptoFailure):
            session.execute(statement, parameters, execution_options=execution)
        session.rollback()
        assert sent == []


@pytest.mark.parametrize('fault', ['projection', 'column_name', 'column_type', 'label_name'])
def test_provider_cannot_change_captured_public_returning(adapter_app, fault, monkeypatch):
    app = adapter_app
    app.switch()
    armed, changed = [], []
    column = app.Article.__table__.c.title
    original_name, original_type = column.name, column.type
    label = app.Article.title.label(quoted_name('visible_title', None))

    def resolve(tenant):
        if armed:
            armed.clear()
            changed.append(fault)
            if fault == 'projection':
                statement._returning = cleanup_statement(app, owner).returning(app.Article.customer_id)._returning
            elif fault == 'column_name':
                column.name = 'customer_id'
            elif fault == 'column_type':
                column.type = Uuid()
            else:
                label.name.quote = True
        return app.rings[tenant]

    sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=resolve)
    parents, children = rows(app)
    owner, child = parents[0].id, children[0].id
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    statement = cleanup_statement(app, owner).returning(label if fault == 'label_name' else app.Article.title)
    original_returning = statement._returning
    with sessions(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
        armed.append(True)
        try:
            with pytest.raises(CryptoFailure):
                session.execute(statement)
            assert changed == [fault] and armed == sent == []
        finally:
            column.name, column.type = original_name, original_type
            label.name.quote = None
            statement._returning = original_returning
            session.rollback()
        assert session.get(app.Article, child).title == 'public child'
        assert session.execute(cleanup_statement(app, owner).returning(app.Article.title)).scalars().all() == ['public child']
        session.rollback()


@pytest.mark.parametrize('bridge', ['sqlalchemy', 'sqlmodel'])
def test_awaited_provider_cannot_change_public_returning_before_async_driver(adapter_app, bridge, monkeypatch):
    app = adapter_app
    app.switch()

    async def scenario():
        selected = attach
        if bridge == 'sqlmodel':
            from cryptalis.sqlmodel import attach as selected
        entered, release = asyncio.Event(), asyncio.Event()
        armed, changed = [], []

        class AwaitedProvider:
            provider_id = app.provider.provider_id

            def unwrap(self, wrapper, context):
                raise AssertionError('Async execution must await provider preparation')

            async def unwrap_async(self, wrapper, context):
                if armed:
                    armed.clear()
                    entered.set()
                    await release.wait()
                return app.provider.unwrap(wrapper, context)

        provider = AwaitedProvider()

        def resolve(tenant):
            # Keep setup from warming away this operation's awaited boundary.
            return Keyring(app.rings[tenant].policy, {provider.provider_id: provider})

        engine = create_async_engine('postgresql+psycopg://', hide_parameters=True,
            async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']))
        task = None
        try:
            sessions = await selected(app.mapping, engine, lock=app.plan.lock_bytes, keys=resolve)
            parents, children = rows(app)
            owner, child = parents[0].id, children[0].id
            async with sessions(tenant_id=TENANT) as session:
                session.add_all(parents + children)
                await session.commit()
            statement = cleanup_statement(app, owner).returning(app.Article.title)
            original_returning = statement._returning
            async with sessions(tenant_id=TENANT) as session:
                execute = session.exec if bridge == 'sqlmodel' else session.execute
                with raw_calls(monkeypatch, app.schema, 'DELETE', asynchronous=True) as sent:
                    armed.append(True)
                    task = asyncio.create_task(execute(statement))
                    try:
                        await asyncio.wait_for(entered.wait(), timeout=5)
                        statement._returning = cleanup_statement(app, owner).returning(app.Article.customer_id)._returning
                        changed.append(True)
                        release.set()
                        with pytest.raises(CryptoFailure):
                            await task
                        assert changed == [True] and armed == sent == []
                    finally:
                        statement._returning = original_returning
                        release.set()
                        if not task.done():
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
                        await session.rollback()
                assert (await session.get(app.Article, child)).title == 'public child'
                assert (await execute(statement)).scalars().all() == ['public child']
                await session.rollback()
        finally:
            release.set()
            await engine.dispose()

    asyncio.run(scenario())


def test_late_compiled_public_returning_replacement_refuses_before_driver(adapter_app, monkeypatch):
    app = adapter_app
    sessions = factory(app, True)
    parents, children = rows(app)
    owner, child = parents[0].id, children[0].id
    with sessions(tenant_id=TENANT) as session:
        session.add_all(parents + children)
        session.commit()
    changed = []

    def replace(connection, cursor, sql, parameters, context, many):
        if sql.lstrip().upper().startswith('DELETE '):
            context.compiled.statement = cleanup_statement(app, owner).returning(app.Article.customer_id)
            changed.append(True)
        return sql, parameters

    event.listen(app.engine, 'before_cursor_execute', replace, retval=True)
    try:
        with sessions(tenant_id=TENANT) as session, raw_calls(monkeypatch, app.schema, 'DELETE') as sent:
            with pytest.raises(CryptoFailure):
                session.execute(cleanup_statement(app, owner).returning(app.Article.title))
            assert changed == [True] and sent == []
            session.rollback()
    finally:
        event.remove(app.engine, 'before_cursor_execute', replace)
    with sessions(tenant_id=TENANT) as session:
        assert session.get(app.Article, child).title == 'public child'
        assert session.execute(cleanup_statement(app, owner).returning(app.Article.title)).scalars().all() == ['public child']
        session.rollback()
