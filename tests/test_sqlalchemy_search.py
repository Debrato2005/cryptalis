"""Slice 4: native SQLAlchemy/PostgreSQL and real attacks are the oracles."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
import time
from threading import Barrier
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy import (Column, Index, Integer, MetaData, Table, Text, Uuid,
                        and_, bindparam, create_engine, event, func, literal,
                        not_, or_, select, text)
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import aliased, registry, sessionmaker
from sqlalchemy.types import TypeDecorator

from cryptalis.crypto import (AuthenticationFailed, DevelopmentKeyProvider, InvalidText, KeyUnavailable,
                              KeyContext, KeyPolicy, Keyring, create_root)
from cryptalis.manifest.compiler import (PlanningRejected, SearchReview, Writer,
                                        WriterInventory, compile_protection)
from cryptalis.manifest.parser import ManifestInvalid
from cryptalis.sqlalchemy import attach, PolicyMismatch, UnsupportedProtectedOperation


DOMAIN, TABLE_ID, FIELD_ID, TENANT, OTHER = (UUID(int=i) for i in range(101, 106))
OTHER_FIELD_ID = UUID(int=106)
EQ_INDEX = "_cryptalis_" + FIELD_ID.hex + "_eq"
FRAME_CHECK = "_cryptalis_" + FIELD_ID.hex + "_frame"
FRAME_SQL = (
    "name IS NULL OR (pg_catalog.octet_length(name) BETWEEN 74 AND 16777290 "
    "AND pg_catalog.substring(name, 1, 6) = pg_catalog.decode('434631000101', 'hex') "
    "AND pg_catalog.substring(name, 7, 4) <> pg_catalog.decode('00000000', 'hex') "
    "AND pg_catalog.substring(name, 11, 4) <> pg_catalog.decode('00000000', 'hex'))"
)


def _engine(variable):
    return create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                         creator=lambda: psycopg.connect(os.environ[variable]))


def _declaration(unique, single_tenant, two_fields=False):
    queries = ["equality", "unique"] if unique else ["equality"]
    fields = [{"name": "name", "field_id": str(FIELD_ID), "protect": True,
               "queries": queries, "accept_leakage": queries}]
    if two_fields:
        fields.append({"name": "other_name", "field_id": str(OTHER_FIELD_ID), "protect": True,
                       "queries": ["equality"], "accept_leakage": ["equality"]})
    return {"schema": "cryptalis.protection/v1", "profile": "cf1", "domain_id": str(DOMAIN),
            "models": [{"model": "Customer", "table_id": str(TABLE_ID),
                        "tenancy": {"single_tenant": True} if single_tenant else {"column": "tenant_id"},
                        "fields": fields}]}


@contextmanager
def search_application(protected=True, unique=False, single_tenant=False, *, attach_now=True, two_fields=False):
    """Disposable owner setup; all ORM application traffic uses the runtime role.

    Physical setup is a test fixture, not a product migration or lifecycle API.
    The compiler inspects an empty native schema before its test-only switch.
    """
    for variable in ("CRYPTALIS_TEST_DATABASE_URL", "CRYPTALIS_TEST_RUNTIME_DATABASE_URL"):
        if not os.environ.get(variable):
            pytest.fail("Both authorized PostgreSQL credentials are required")
    owner, runtime = _engine("CRYPTALIS_TEST_DATABASE_URL"), _engine("CRYPTALIS_TEST_RUNTIME_DATABASE_URL")
    schema = "cryptalis_search_" + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    columns = [Column("id", Uuid, primary_key=True, autoincrement=False)]
    if not single_tenant:
        columns.append(Column("tenant_id", Uuid, nullable=False))
    fields = [Column("name", Text(collation="C"))]
    if two_fields:
        fields.append(Column("other_name", Text(collation="C")))
    customer = Table("customer", mapping.metadata, *columns, *fields,
                     Column("label", Text), Column("rank", Integer))
    native_index = Index("name_native", *([customer.c.name] if not unique or single_tenant
                                         else [customer.c.tenant_id, customer.c.name]), unique=unique)
    other_index = Index("other_name_native", customer.c.other_name) if two_fields else None
    Index("rank_native", customer.c.rank)
    Index("label_native", customer.c.label)
    class Customer:
        pass
    mapping.map_imperatively(Customer, customer)
    try:
        with owner.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        mapping.metadata.create_all(owner)
        declaration = _declaration(unique, single_tenant, two_fields)
        writers = WriterInventory(True, (Writer(TABLE_ID, "app", "sqlalchemy", evidence="test-owned application"),))
        reviews = tuple(SearchReview(UUID(field["field_id"]), False, "synthetic unbounded account labels; host review")
                        for field in declaration["models"][0]["fields"])
        plan = compile_protection(json.dumps(declaration).encode(), mapping, owner,
                                  writers=writers, search_reviews=reviews)
        provider, rings = DevelopmentKeyProvider(), {}
        for tenant in (TENANT, OTHER, TABLE_ID):
            roots = tuple(create_root(provider, KeyContext(DOMAIN, tenant, purpose, uuid4(), 1))
                          for purpose in ("payload", "search"))
            rings[tenant] = Keyring(KeyPolicy(DOMAIN, tenant, roots, 1, 1), {provider.provider_id: provider})
        if protected:
            native_index.drop(owner)
            if other_index is not None:
                other_index.drop(owner)
            with owner.begin() as connection:
                for field in declaration["models"][0]["fields"]:
                    name, prefix = field["name"], "_cryptalis_" + UUID(field["field_id"]).hex
                    connection.execute(text(f'ALTER TABLE "{schema}".customer ALTER COLUMN {name} TYPE pg_catalog.bytea USING NULL::pg_catalog.bytea'))
                    scope = "" if single_tenant else "tenant_id, "
                    unique_sql = "UNIQUE " if "unique" in field["queries"] else ""
                    connection.execute(text(f'CREATE {unique_sql}INDEX "{prefix}_eq" ON "{schema}".customer ({scope}pg_catalog.substring({name}, 15, 32))'))
                    check = FRAME_SQL.replace("name", name)
                    connection.execute(text(f'ALTER TABLE "{schema}".customer ADD CONSTRAINT "{prefix}_frame" CHECK ({check})'))
        with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as connection:
            assert connection.execute("select 1").fetchone() == (1,)
            assert int(connection.execute("show server_version_num").fetchone()[0]) // 10000 == 16
            role = connection.execute("select current_user").fetchone()[0]
            assert connection.execute("select not rolsuper and not rolcreatedb and not rolcreaterole and not rolbypassrls from pg_roles where rolname=current_user").fetchone() == (True,)
        with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as connection:
            connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC, {}").format(sql.Identifier(schema), sql.Identifier(role)))
            connection.execute(sql.SQL("REVOKE ALL ON TABLE {}.customer FROM PUBLIC, {}").format(sql.Identifier(schema), sql.Identifier(role)))
            connection.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
            connection.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {}.customer TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        native = sessionmaker(runtime)
        sessions = (attach(mapping, runtime, lock=plan.lock_bytes, keys=rings.__getitem__)
                    if protected and attach_now else lambda *, tenant_id: native())
        yield SimpleNamespace(engine=runtime, owner_engine=owner, schema=schema, mapping=mapping,
                              Customer=Customer, plan=plan, declaration=declaration, rings=rings,
                              provider=provider, keys=rings.__getitem__, sessions=sessions,
                              writers=writers, reviews=reviews, protected=protected,
                              name_index_name=EQ_INDEX if protected else "name_native",
                              single_tenant=single_tenant, tenant=TABLE_ID if single_tenant else TENANT)
    finally:
        runtime.dispose()
        with owner.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        owner.dispose()
        mapping.dispose()


def _row(app, value, rank, tenant=None):
    attributes = dict(id=uuid4(), name=value, rank=rank, label=f"label-{rank}")
    if not app.single_tenant:
        attributes["tenant_id"] = tenant or app.tenant
    return app.Customer(**attributes)


def _scope(app, model=None):
    return literal(True) if app.single_tenant else (model or app.Customer).tenant_id == app.tenant


async def _async_factory(app):
    engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                 async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
    if app.protected:
        sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.keys)
    else:
        native = async_sessionmaker(engine)
        sessions = lambda *, tenant_id: native()
    return engine, sessions


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("single_tenant", [False, True])
def test_query_membership_bind_types_aliases_and_sql_null_truth(protected, mode, single_tenant):
    """The identical statements/values run on native text and protected bytea."""
    with search_application(protected, single_tenant=single_tenant, attach_now=mode == "sync") as app:
        Customer = app.Customer
        values = [None, "", "é", "e\u0301", "account-12345", "account-54321"]
        def private_binds(connection, cursor, statement, parameters, context, many):
            if not protected:
                return
            def leaves(value):
                if isinstance(value, dict):
                    for part in value.values():
                        yield from leaves(part)
                elif isinstance(value, (list, tuple)):
                    for part in value:
                        yield from leaves(part)
                else:
                    yield value
            secrets = {value for value in values if value}
            assert not any(type(value) is str and value in secrets for value in leaves(parameters))
        def cases(model):
            return [(model.name == "", {}, [1]),
                    (literal("é", Text()) == model.name, {}, [2]),
                    (model.name == bindparam("value", type_=Text()), {"value": "account-12345"}, [4]),
                    (bindparam("value", type_=Text()) == model.name, {"value": "e\u0301"}, [3]),
                    (model.name.in_(bindparam("values", expanding=True, type_=Text())), {"values": ["é", None]}, [2]),
                    (model.name.in_([]), {}, []), (model.name.in_([None]), {}, []),
                    (model.name.in_([None, "", "account-54321"]), {}, [1, 5]),
                    (model.name == None, {}, [0]),
                    (and_(model.name.in_(["é", "e\u0301"]), model.rank > 2), {}, [3]),
                    (or_(model.name == "é", model.name == "account-54321"), {}, [2, 5])]
        def statements():
            for model in (Customer, aliased(Customer)):
                for predicate, parameters, expected in cases(model):
                    yield select(model.rank).where(_scope(app, model), predicate).order_by(model.rank), parameters, expected
            yield select(Customer.name.in_([None, "é"])).where(_scope(app)).order_by(Customer.rank), {}, [None, None, True, None, None, None]
            yield select(Customer.name.in_([])).where(_scope(app)).order_by(Customer.rank), {}, [False] * 6
            yield select((Customer.name == "é").label("matches")).where(_scope(app)).order_by(Customer.rank), {}, [None, False, True, False, False, False]
            # Reuse one late-bound statement with different values. SQLAlchemy's
            # statement cache must not retain another query's term.
            statement = select(Customer.rank).where(_scope(app), Customer.name == bindparam("value", type_=Text()))
            for value, expected in (("é", [2]), ("", [1]), ("e\u0301", [3]), ("absent", []), (None, []), ("é", [2])):
                yield statement, {"value": value}, expected
        if mode == "sync":
            event.listen(app.engine, "before_cursor_execute", private_binds)
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all([_row(app, value, rank) for rank, value in enumerate(values)])
                session.commit()
                for case, (statement, parameters, expected) in enumerate(statements()):
                    try:
                        assert session.scalars(statement, parameters).all() == expected
                    except UnsupportedProtectedOperation:
                        pytest.fail(f"Supported native query {case} was refused")
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                event.listen(engine.sync_engine, "before_cursor_execute", private_binds)
                try:
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add_all([_row(app, value, rank) for rank, value in enumerate(values)])
                        await session.commit()
                        for statement, parameters, expected in statements():
                            assert (await session.scalars(statement, parameters)).all() == expected
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_query_tenant_terms_are_isolated_and_wrong_scope_cannot_read(mode):
    with search_application(attach_now=mode == "sync") as app:
        Customer = app.Customer
        identities = {}
        statement = select(Customer).where(Customer.tenant_id == bindparam("tenant"), Customer.name == bindparam("value", type_=Text()))
        def assert_result(rows, tenant):
            assert [row.id for row in rows] == [identities[tenant]]
        if mode == "sync":
            for tenant in (TENANT, OTHER):
                with app.sessions(tenant_id=tenant) as session:
                    row = _row(app, "identical cross tenant", 1, tenant)
                    identities[tenant] = row.id
                    session.add(row)
                    session.commit()
            for tenant in (TENANT, OTHER, TENANT):
                with app.sessions(tenant_id=tenant) as session:
                    assert_result(session.scalars(statement, {"tenant": tenant, "value": "identical cross tenant"}).all(), tenant)
                    try:
                        assert session.scalars(statement, {"tenant": OTHER if tenant == TENANT else TENANT, "value": "identical cross tenant"}).all() == []
                    except (PolicyMismatch, UnsupportedProtectedOperation, AuthenticationFailed):
                        pass
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    for tenant in (TENANT, OTHER):
                        async with sessions(tenant_id=tenant) as session:
                            row = _row(app, "identical cross tenant", 1, tenant)
                            identities[tenant] = row.id
                            session.add(row)
                            await session.commit()
                    for tenant in (TENANT, OTHER, TENANT):
                        async with sessions(tenant_id=tenant) as session:
                            assert_result((await session.scalars(statement, {"tenant": tenant, "value": "identical cross tenant"})).all(), tenant)
                            try:
                                assert (await session.scalars(statement, {"tenant": OTHER if tenant == TENANT else TENANT, "value": "identical cross tenant"})).all() == []
                            except (PolicyMismatch, UnsupportedProtectedOperation, AuthenticationFailed):
                                pass
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("single_tenant", [False, True])
def test_native_unique_insert_race_nulls_and_atomic_rollback(protected, mode, single_tenant):
    """A native unique index, not a preflight SELECT, chooses one race winner."""
    with search_application(protected, unique=True, single_tenant=single_tenant, attach_now=mode == "sync") as app:
        Customer = app.Customer
        if mode == "sync":
            barrier = Barrier(2)
            def insert_competitor(rank):
                with app.sessions(tenant_id=app.tenant) as session:
                    session.add(_row(app, "competing account", rank))
                    barrier.wait(timeout=10)
                    try:
                        session.commit()
                        return "committed"
                    except IntegrityError as error:
                        assert error.orig.sqlstate == "23505"
                        session.rollback()
                        return "duplicate"
            with ThreadPoolExecutor(2) as pool:
                outcomes = list(pool.map(insert_competitor, (0, 1)))
            assert sorted(outcomes) == ["committed", "duplicate"]
            with app.sessions(tenant_id=app.tenant) as session:
                session.add_all([_row(app, None, 2), _row(app, None, 3), _row(app, "another account", 4)])
                session.commit()
                other = session.scalar(select(Customer).where(_scope(app), Customer.name == "another account"))
                other.name = "competing account"
                with pytest.raises(IntegrityError) as caught:
                    session.commit()
                assert caught.value.orig.sqlstate == "23505"
                session.rollback()
                assert session.scalar(select(Customer.name).where(Customer.id == other.id)) == "another account"
                other.name = "after rollback"
                session.commit()
                assert session.scalar(select(Customer.rank).where(_scope(app), Customer.name == "after rollback")) == 4
                assert session.scalar(select(Customer.rank).where(_scope(app), Customer.name == "another account")) is None
            if not single_tenant:
                with app.sessions(tenant_id=OTHER) as session:
                    session.add(_row(app, "competing account", 5, OTHER))
                    session.commit()
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                ready, count = asyncio.Event(), 0
                async def competitor(rank):
                    nonlocal count
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add(_row(app, "competing account", rank))
                        count += 1
                        if count == 2:
                            ready.set()
                        await asyncio.wait_for(ready.wait(), 10)
                        try:
                            await session.commit()
                            return "committed"
                        except IntegrityError as error:
                            assert error.orig.sqlstate == "23505"
                            await session.rollback()
                            return "duplicate"
                try:
                    assert sorted(await asyncio.gather(competitor(0), competitor(1))) == ["committed", "duplicate"]
                    async with sessions(tenant_id=app.tenant) as session:
                        session.add_all([_row(app, None, 2), _row(app, None, 3), _row(app, "another account", 4)])
                        await session.commit()
                        other = await session.scalar(select(Customer).where(_scope(app), Customer.name == "another account"))
                        identity = other.id
                        other.name = "competing account"
                        with pytest.raises(IntegrityError) as caught:
                            await session.commit()
                        assert caught.value.orig.sqlstate == "23505"
                        await session.rollback()
                        assert await session.scalar(select(Customer.name).where(Customer.id == identity)) == "another account"
                        other = await session.get(Customer, identity)
                        other.name = "after rollback"
                        await session.commit()
                        assert await session.scalar(select(Customer.rank).where(_scope(app), Customer.name == "after rollback")) == 4
                        assert await session.scalar(select(Customer.rank).where(_scope(app), Customer.name == "another account")) is None
                    if not single_tenant:
                        async with sessions(tenant_id=OTHER) as session:
                            session.add(_row(app, "competing account", 5, OTHER))
                            await session.commit()
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


def test_search_leakage_and_low_domain_require_host_admission():
    """The compiler must reject known small domains and absent leakage consent."""
    with search_application(False) as app:
        with pytest.raises(PlanningRejected) as unknown:
            compile_protection(json.dumps(app.declaration).encode(), app.mapping, app.owner_engine,
                               writers=app.writers, search_reviews=())
        assert "search_domain_unknown" in {issue.code for issue in unknown.value.issues}
        with pytest.raises(PlanningRejected) as caught:
            compile_protection(json.dumps(app.declaration).encode(), app.mapping, app.owner_engine,
                               writers=app.writers, search_reviews=(SearchReview(FIELD_ID, True, "boolean-like population"),))
        assert "small_search_domain" in {issue.code for issue in caught.value.issues}
        declaration = json.loads(json.dumps(app.declaration))
        declaration["models"][0]["fields"][0]["accept_leakage"] = []
        with pytest.raises(ManifestInvalid):
            compile_protection(json.dumps(declaration).encode(), app.mapping, app.owner_engine,
                               writers=app.writers, search_reviews=app.reviews)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_unsupported_search_grammar_never_reaches_driver(mode):
    # Construct hostile statements while columns still have their native Text
    # type. Their lineage remains protected after attachment mutates the type.
    with search_application(attach_now=False) as app:
        C, alias = app.Customer, aliased(app.Customer)
        independent = Table("customer", MetaData(schema=app.schema), Column("id", Uuid),
                            Column("tenant_id", Uuid), Column("name", Text(collation="C")))
        statements = [select(C).where(C.name != "x"), select(C).where(C.name.is_not(None)), select(C).where(C.name.not_in(["x"])),
                      select(C).where(not_(C.name.in_(["x"]))), select(C).where(C.name > "x"),
                      select(C).where(C.name.like("x%")), select(C).where(C.name.ilike("x%")),
                      select(C).where(C.name.startswith("x")), select(C).where(C.name.contains("x")),
                      select(C).where(C.name == C.label), select(C).where(C.name == alias.name),
                      select(C).join(alias, C.name == alias.name), select(C.name).distinct(),
                      select(C).join(alias, C.name == "x"), select(C).join(alias, C.name.in_(["x"])),
                      select(C).join(alias, C.name.is_(None)),
                      select(C).join(alias, and_(C.id == alias.id, C.name == "x")),
                      select(C).join(alias, or_(C.id == alias.id, C.name.in_(["x"]))),
                      select(func.count(C.name)), select(func.min(C.name)), select(C).order_by(C.name),
                      select(C.name, func.count()).group_by(C.name),
                      select(C).where(func.lower(C.name) == "x"),
                      select(C).where(C.name.in_(select(alias.name))),
                      select(C).where(C.id.in_(select(alias.id).order_by(alias.name.desc()))),
                      select((C.name != "x").label("not_equal")),
                      select(select(C.name).subquery().c.name),
                      select(C).where(C.id.in_(select(alias.id).where(alias.name.like("x%"))))]
        for spoof in (independent.alias("spoof"), independent.alias("first").alias("chained")):
            statements.extend([select(spoof.c.name), select(spoof.c.id).where(spoof.c.name == "x"),
                               select(spoof.c.id).where(spoof.c.name.in_(["x"]))])
        cte = select(C.id, C.name).cte("protected_cte")
        statements.extend([select(cte.c.name), select(cte.c.id).where(cte.c.name == "x"),
                           select(cte.c.id).where(cte.c.name.in_(["x"]))])
        wrapped = select(C.id, C.name).subquery("protected_subquery").alias("wrapped_subquery")
        statements.extend([select(wrapped.c.name), select(wrapped.c.id).where(wrapped.c.name == "x"),
                           select(wrapped.c.id).where(wrapped.c.name.in_(["x"]))])
        shared_predicate = C.name == "x"
        statements.extend([select(C).join(alias, shared_predicate).where(and_(shared_predicate, C.rank > 0)),
                           select(C).join(alias, shared_predicate).where(or_(shared_predicate, C.rank > 0)),
                           select(C).join(alias, C.name).where(C.name),
                           select(C).where(and_(C.name, C.rank > 0))])
        observed = []
        if mode == "sync":
            app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
            with app.sessions(tenant_id=TENANT) as session:
                for index, statement in enumerate(statements):
                    before = len(observed)
                    try:
                        session.execute(statement)
                    except UnsupportedProtectedOperation:
                        pass
                    else:
                        pytest.fail(f"Unsupported query {index} reached the driver")
                    assert len(observed) == before, str(statement)
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        for index, statement in enumerate(statements):
                            before = len(observed)
                            try:
                                await session.execute(statement)
                            except UnsupportedProtectedOperation:
                                pass
                            else:
                                pytest.fail(f"Unsupported query {index} reached the driver")
                            assert len(observed) == before, str(statement)
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


def test_term_tampering_fails_on_point_read_but_writer_can_hide_membership():
    """AEAD detects altered headers on read; it cannot authenticate absent rows."""
    with search_application() as app:
        with app.sessions(tenant_id=TENANT) as session:
            row = _row(app, "authenticated account", 1)
            identity = row.id
            session.add(row)
            session.commit()
        # The restricted CRUD principal can reconnect without the attachment.
        # PostgreSQL privileges do not enforce honest equality-term contents.
        with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as connection:
            connection.execute(sql.SQL("UPDATE {}.customer SET name=pg_catalog.set_byte(name, 14, pg_catalog.get_byte(name,14) # 1) WHERE id=%s").format(sql.Identifier(app.schema)), (identity,))
        with app.sessions(tenant_id=TENANT) as session:
            assert session.scalars(select(app.Customer).where(_scope(app), app.Customer.name == "authenticated account")).all() == []
            with pytest.raises(AuthenticationFailed):
                session.get(app.Customer, identity)


@pytest.mark.parametrize("damage", ["missing_index", "wrong_expression", "partial_index", "missing_check", "weak_check", "wrong_unique", "not_valid_check", "missing_tenant_key", "wrong_opclass"])
def test_attachment_rejects_malformed_physical_search_contract(damage):
    with search_application(unique=True, attach_now=False) as app:
        with app.owner_engine.begin() as connection:
            if damage in ("missing_index", "wrong_expression", "partial_index", "wrong_unique", "missing_tenant_key", "wrong_opclass"):
                connection.execute(text(f'DROP INDEX "{app.schema}"."{EQ_INDEX}"'))
                if damage != "missing_index":
                    expression = "pg_catalog.substring(name, 14, 32)" if damage == "wrong_expression" else "pg_catalog.substring(name, 15, 32)"
                    partial = " WHERE name IS NOT NULL" if damage == "partial_index" else ""
                    unique = "" if damage == "wrong_unique" else "UNIQUE "
                    tenant = "" if damage == "missing_tenant_key" else "tenant_id, "
                    method = "hash" if damage == "wrong_opclass" else "btree"
                    if damage == "wrong_opclass":
                        # PG hash bytea_ops is not the admitted btree bytea_ops.
                        # Hash indexes are nonunique and cannot enforce this contract.
                        tenant, unique = "", ""
                    connection.execute(text(f'CREATE {unique}INDEX "{EQ_INDEX}" ON "{app.schema}".customer USING {method} ({tenant}{expression}){partial}'))
            else:
                connection.execute(text(f'ALTER TABLE "{app.schema}".customer DROP CONSTRAINT "{FRAME_CHECK}"'))
                if damage == "weak_check":
                    connection.execute(text(f'ALTER TABLE "{app.schema}".customer ADD CONSTRAINT "{FRAME_CHECK}" CHECK (name IS NULL OR pg_catalog.octet_length(name) >= 74)'))
                elif damage == "not_valid_check":
                    connection.execute(text(f'ALTER TABLE "{app.schema}".customer ADD CONSTRAINT "{FRAME_CHECK}" CHECK ({FRAME_SQL}) NOT VALID'))
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)


def test_attachment_catalog_check_rejects_search_path_function_shadowing():
    """An attacker-owned function must not deparse as the admitted builtin."""
    with search_application(unique=True, attach_now=False) as app:
        with app.owner_engine.begin() as connection:
            connection.execute(text(f'''CREATE FUNCTION "{app.schema}"."substring"(bytea, integer, integer)
                RETURNS bytea LANGUAGE SQL IMMUTABLE AS
                'SELECT pg_catalog.substring($1, CASE WHEN $2 = 15 THEN 16 ELSE $2 END, $3)' '''))
            connection.execute(text(f'DROP INDEX "{app.schema}"."{EQ_INDEX}"'))
            connection.execute(text(f'CREATE UNIQUE INDEX "{EQ_INDEX}" ON "{app.schema}".customer (tenant_id, "{app.schema}"."substring"(name, 15, 32))'))
            connection.execute(text(f'ALTER TABLE "{app.schema}".customer DROP CONSTRAINT "{FRAME_CHECK}"'))
            shadow_check = FRAME_SQL.replace("pg_catalog.substring", f'"{app.schema}"."substring"')
            connection.execute(text(f'ALTER TABLE "{app.schema}".customer ADD CONSTRAINT "{FRAME_CHECK}" CHECK ({shadow_check})'))
        event.listen(app.engine, "connect", lambda db, record: db.execute(f'SET search_path = "{app.schema}", pg_catalog'))
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)


def test_duplicate_backfill_fails_native_unique_index_creation():
    """Real PostgreSQL rejects duplicate equality terms before admission."""
    with search_application() as app:
        with app.sessions(tenant_id=TENANT) as session:
            session.add_all([_row(app, "duplicate target account", i) for i in (1, 2)])
            session.commit()
        with pytest.raises(IntegrityError) as caught:
            with app.owner_engine.begin() as connection:
                connection.execute(text(f'CREATE UNIQUE INDEX duplicate_target ON "{app.schema}".customer (tenant_id, pg_catalog.substring(name, 15, 32))'))
        assert caught.value.orig.sqlstate == "23505"


def test_postgresql_frame_check_refuses_malformed_reconnecting_runtime_writes():
    """The native CHECK enforces public framing, not ciphertext authenticity."""
    header = bytes.fromhex("4346310001010000000100000001")
    plausible = header + bytes(60)
    malformed = [b"", plausible[:73], b"XX" + plausible[2:],
                 plausible[:6] + bytes(4) + plausible[10:],
                 plausible[:10] + bytes(4) + plausible[14:]]
    with search_application() as app:
        statement = sql.SQL("INSERT INTO {}.customer (id, tenant_id, name, rank) VALUES (%s,%s,%s,1)").format(sql.Identifier(app.schema))
        for body in malformed:
            with pytest.raises(psycopg.errors.CheckViolation) as caught:
                with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as connection:
                    connection.execute(statement, (uuid4(), TENANT, body))
            assert caught.value.sqlstate == "23514"
        identity = uuid4()
        with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as connection:
            connection.execute(statement, (identity, TENANT, plausible))
        with app.sessions(tenant_id=TENANT) as session:
            with pytest.raises(AuthenticationFailed):
                session.get(app.Customer, identity)


@pytest.mark.parametrize("replacement", ["generation", "root"])
@pytest.mark.parametrize("operation", ["query", "insert"])
def test_search_root_policy_change_refused_before_query_or_uniqueness_write(replacement, operation):
    """An unannounced root change must not hide matches or bypass uniqueness."""
    with search_application(unique=True) as app:
        with app.sessions(tenant_id=TENANT) as session:
            session.add(_row(app, "existing unique account", 1))
            session.commit()
        old = app.rings[TENANT].policy
        payload = next(root for root in old.wrappers if root.context.purpose == "payload")
        generation = 2 if replacement == "generation" else 1
        search = create_root(app.provider, KeyContext(DOMAIN, TENANT, "search", uuid4(), generation))
        app.rings[TENANT] = Keyring(KeyPolicy(DOMAIN, TENANT, (payload, search), 1, generation),
                                   {app.provider.provider_id: app.provider})
        observed = []
        event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
        with pytest.raises(PolicyMismatch):
            with app.sessions(tenant_id=TENANT) as session:
                if operation == "query":
                    session.scalars(select(app.Customer).where(_scope(app), app.Customer.name == "existing unique account")).all()
                else:
                    session.add(_row(app, "existing unique account", 2))
                    session.commit()
        assert observed == [], "A changed search authority reached PostgreSQL"
        with app.owner_engine.connect() as connection:
            assert connection.execute(text(f'SELECT count(*) FROM "{app.schema}".customer')).scalar_one() == 1


def test_mixed_search_generations_refused_before_first_application_operation():
    """Without reindex/rotation admission there is only one searchable namespace."""
    with search_application(unique=True) as app:
        old = app.rings[TENANT].policy
        extra = create_root(app.provider, KeyContext(DOMAIN, TENANT, "search", uuid4(), 2))
        app.rings[TENANT] = Keyring(KeyPolicy(DOMAIN, TENANT, (*old.wrappers, extra), 1, 1),
                                   {app.provider.provider_id: app.provider})
        with pytest.raises(PolicyMismatch):
            with app.sessions(tenant_id=TENANT) as session:
                session.add(_row(app, "new unique account", 1))
                session.commit()
        with app.owner_engine.connect() as connection:
            assert connection.execute(text(f'SELECT count(*) FROM "{app.schema}".customer')).scalar_one() == 0


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_shared_user_bind_names_do_not_cross_protected_and_plain_fields(protected, mode):
    """Native bind identity is preserved while each protected use gets a term."""
    with search_application(protected, attach_now=mode == "sync") as app:
        C = app.Customer
        value = "shared bind account"
        row = _row(app, value, 1)
        row.label = value
        name_eq = C.name == bindparam("v", type_=Text())
        label_eq = C.label == bindparam("v", type_=Text())
        name_in = C.name.in_(bindparam("values", expanding=True, type_=Text()))
        label_in = C.label.in_(bindparam("values", expanding=True, type_=Text()))
        cases = [(and_(name_eq, label_eq), {"v": value}),
                 (and_(label_eq, name_eq), {"v": value}),
                 (and_(name_in, label_in), {"values": [value, "absent"]}),
                 (and_(label_in, name_in), {"values": [value, "absent"]})]
        if mode == "sync":
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                for predicate, parameters in cases:
                    assert session.scalars(select(C.rank).where(_scope(app), predicate), parameters).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        for predicate, parameters in cases:
                            assert (await session.scalars(select(C.rank).where(_scope(app), predicate), parameters)).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_invalid_search_text_and_utf8_size_bound_refused_before_driver(mode):
    """The published CF1 text bound applies to query inputs as well as writes."""
    invalid = [123, b"binary account", "NUL\x00account", "\ud800", "x" * (16 * 1024 * 1024 + 1), "😀" * (4 * 1024 * 1024 + 1)]
    with search_application(attach_now=mode == "sync") as app:
        C = app.Customer
        cases = [(select(C.rank).where(_scope(app), C.name == bindparam("value", type_=Text())), "value", lambda value: value),
                 (select(C.rank).where(_scope(app), C.name.in_(bindparam("values", expanding=True, type_=Text()))), "values", lambda value: [value])]
        observed = []
        def check_failure(caught):
            assert isinstance(caught.value.orig if isinstance(caught.value, StatementError) else caught.value, InvalidText)
            diagnostic = str(caught.value)
            assert "NUL\x00account" not in diagnostic and "NUL\\x00account" not in diagnostic
            assert "binary account" not in diagnostic
        if mode == "sync":
            event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
            with app.sessions(tenant_id=TENANT) as session:
                for statement, key, prepare in cases:
                    for value in invalid:
                        before = len(observed)
                        with pytest.raises((InvalidText, StatementError)) as caught:
                            session.execute(statement, {key: prepare(value)})
                        check_failure(caught)
                        assert len(observed) == before
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        for statement, key, prepare in cases:
                            for value in invalid:
                                before = len(observed)
                                with pytest.raises((InvalidText, StatementError)) as caught:
                                    await session.execute(statement, {key: prepare(value)})
                                check_failure(caught)
                                assert len(observed) == before
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_two_protected_fields_sharing_bind_keep_independent_field_terms(protected, mode):
    """Identical values and bind names must still use each field's own key domain."""
    with search_application(protected, attach_now=mode == "sync", two_fields=True) as app:
        C, value = app.Customer, "same value across independent fields"
        row = _row(app, value, 1)
        row.other_name = value
        first_eq = C.name == bindparam("v", type_=Text())
        second_eq = C.other_name == bindparam("v", type_=Text())
        first_in = C.name.in_(bindparam("values", expanding=True, type_=Text()))
        second_in = C.other_name.in_(bindparam("values", expanding=True, type_=Text()))
        cases = [(and_(first_eq, second_eq), {"v": value}),
                 (and_(second_eq, first_eq), {"v": value}),
                 (and_(first_in, second_in), {"values": [value, "absent"]}),
                 (and_(second_in, first_in), {"values": [value, "absent"]})]
        if mode == "sync":
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                for predicate, parameters in cases:
                    assert session.scalars(select(C.rank).where(_scope(app), predicate), parameters).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        for predicate, parameters in cases:
                            assert (await session.scalars(select(C.rank).where(_scope(app), predicate), parameters)).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
        if protected:
            with app.owner_engine.connect() as connection:
                terms = connection.execute(text(f'SELECT pg_catalog.substring(name, 15, 32), pg_catalog.substring(other_name, 15, 32) FROM "{app.schema}".customer')).one()
            assert all(type(term) is bytes and len(term) == 32 for term in terms)
            assert terms[0] != terms[1], "The two distinct field identities reused a search domain"


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_native_alias_and_cte_controls_do_not_admit_forged_protected_columns(protected, mode):
    """Native PostgreSQL reads these shapes; protected grammar rejects origins."""
    with search_application(protected, attach_now=False) as app:
        value, row = "alias origin account", _row(app, "alias origin account", 1)
        identity = row.id
        independent = Table("customer", MetaData(schema=app.schema), Column("id", Uuid),
                            Column("tenant_id", Uuid), Column("name", Text(collation="C")))
        sources = [independent.alias("spoof"), independent.alias("first").alias("chained"),
                   select(app.Customer.id, app.Customer.name).cte("protected_cte"),
                   select(app.Customer.id, app.Customer.name).subquery("protected_subquery").alias("wrapped_subquery")]
        statements = []
        for source in sources:
            statements.extend([(select(source.c.name), [value]),
                               (select(source.c.id).where(source.c.name == value), [identity]),
                               (select(source.c.id).where(source.c.name.in_([value, "absent"])), [identity])])
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                for statement, expected in statements:
                    if protected:
                        before = len(observed)
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(statement)
                        assert len(observed) == before
                    else:
                        assert session.scalars(statement).all() == expected
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        for statement, expected in statements:
                            if protected:
                                before = len(observed)
                                with pytest.raises(UnsupportedProtectedOperation):
                                    await session.execute(statement)
                                assert len(observed) == before
                            else:
                                assert (await session.scalars(statement)).all() == expected
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_host_bind_codec_has_native_oracle_and_is_refused_for_protected_search(protected, mode):
    """Silently replacing a custom host bind codec changes native membership."""
    class CasefoldText(TypeDecorator):
        impl = Text
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return None if value is None else value.casefold()

    with search_application(protected, attach_now=False) as app:
        row = _row(app, "matching account", 1)
        statement = select(app.Customer.rank).where(_scope(app), app.Customer.name == bindparam("value", type_=CasefoldText()))
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                if protected:
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(statement, {"value": "MATCHING ACCOUNT"})
                    assert observed == []
                else:
                    assert session.scalars(statement, {"value": "MATCHING ACCOUNT"}).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        if protected:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(statement, {"value": "MATCHING ACCOUNT"})
                            assert observed == []
                        else:
                            assert (await session.scalars(statement, {"value": "MATCHING ACCOUNT"})).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_shared_callable_bind_keeps_native_single_evaluation_or_refuses(protected, mode):
    """Host callables are evaluated once by native SQLAlchemy, never by refusal."""
    calls = []
    def bind_value():
        calls.append(True)
        return "matching account"
    with search_application(protected, attach_now=False) as app:
        C, row = app.Customer, _row(app, "matching account", 1)
        row.label = "matching account"
        shared = bindparam("same", callable_=bind_value, type_=Text())
        statement = select(C.rank).where(_scope(app), C.name == shared, C.label == shared)
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                if protected:
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(statement)
                    assert observed == [] and calls == []
                else:
                    assert session.scalars(statement).all() == [1]
                    assert len(calls) == 1
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        if protected:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(statement)
                            assert observed == [] and calls == []
                        else:
                            assert (await session.scalars(statement)).all() == [1]
                            assert len(calls) == 1
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_conflicting_shared_bind_defaults_need_explicit_protected_value(protected, mode):
    """Native compiler resolves duplicate names; explicit parameters remove ambiguity."""
    with search_application(protected, attach_now=False) as app:
        C, row = app.Customer, _row(app, "matching account", 1)
        row.label = "matching account"
        first = bindparam("same", value="wrong value", type_=Text())
        second = bindparam("same", value="matching account", type_=Text())
        statement = select(C.rank).where(_scope(app), C.name == first, C.label == second)
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                if protected:
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(statement)
                    assert observed == []
                else:
                    assert session.scalars(statement).all() == [1]
                assert session.scalars(statement, {"same": "matching account"}).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        if protected:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(statement)
                            assert observed == []
                        else:
                            assert (await session.scalars(statement)).all() == [1]
                        assert (await session.scalars(statement, {"same": "matching account"})).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_custom_plain_bind_codec_shared_with_search_has_native_control(protected, mode):
    """A plain-field codec on the same bind name can alter protected membership."""
    class CasefoldText(TypeDecorator):
        impl = Text
        cache_ok = True

        def process_bind_param(self, value, dialect):
            return None if value is None else value.casefold()

    with search_application(protected, attach_now=False) as app:
        C, row = app.Customer, _row(app, "matching account", 1)
        row.label = "matching account"
        statement = select(C.rank).where(_scope(app), C.name == bindparam("same", type_=Text()),
                                         C.label == bindparam("same", type_=CasefoldText()))
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                if protected:
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(statement, {"same": "MATCHING ACCOUNT"})
                    assert observed == []
                else:
                    assert session.scalars(statement, {"same": "MATCHING ACCOUNT"}).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        if protected:
                            with pytest.raises(UnsupportedProtectedOperation):
                                await session.execute(statement, {"same": "MATCHING ACCOUNT"})
                            assert observed == []
                        else:
                            assert (await session.scalars(statement, {"same": "MATCHING ACCOUNT"})).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_unique_user_binds_require_public_parameters_and_keep_default_semantics(protected, mode):
    """Compiled parameter aliases are native API, outside protected admission."""
    with search_application(protected, attach_now=False) as app:
        C, row = app.Customer, _row(app, "matching account", 1)
        overridden = select(C.rank).where(_scope(app), C.name == bindparam("v", value="wrong value", unique=True, type_=Text()))
        required = select(C.rank).where(_scope(app), C.name == bindparam("v", unique=True, type_=Text()))
        default = select(C.rank).where(_scope(app), C.name == bindparam("v", value="matching account", unique=True, type_=Text()))
        observed = []
        if mode == "sync":
            if protected:
                app.sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.keys)
            with app.sessions(tenant_id=TENANT) as session:
                session.add(row)
                session.commit()
                event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
                for statement in (overridden, required):
                    if protected:
                        before = len(observed)
                        with pytest.raises(UnsupportedProtectedOperation):
                            session.execute(statement, {"v_1": "matching account"})
                        assert len(observed) == before
                    else:
                        assert session.scalars(statement, {"v_1": "matching account"}).all() == [1]
                assert session.scalars(default).all() == [1]
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(row)
                        await session.commit()
                        event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                        for statement in (overridden, required):
                            if protected:
                                before = len(observed)
                                with pytest.raises(UnsupportedProtectedOperation):
                                    await session.execute(statement, {"v_1": "matching account"})
                                assert len(observed) == before
                            else:
                                assert (await session.scalars(statement, {"v_1": "matching account"})).all() == [1]
                        assert (await session.scalars(default)).all() == [1]
                finally:
                    await engine.dispose()
            asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_expired_prepared_keys_abort_write_and_fresh_session_recovers(mode):
    """Real elapsed lease expiry must leave PostgreSQL unchanged, then recover."""
    class DelayedKeys(Keyring):
        def prepare(self):
            prepared = super().prepare()
            time.sleep(.05)
            return prepared

        async def prepare_async(self):
            prepared = await super().prepare_async()
            await asyncio.sleep(.05)
            return prepared

    with search_application(attach_now=mode == "sync") as app:
        healthy = app.rings[TENANT]
        app.rings[TENANT] = DelayedKeys(healthy.policy, {app.provider.provider_id: app.provider}, max_age=.02)
        observed, row_id = [], uuid4()
        if mode == "sync":
            event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
            with app.sessions(tenant_id=TENANT) as session:
                session.add(app.Customer(id=row_id, tenant_id=TENANT, name="recovering account", rank=1))
                with pytest.raises(KeyUnavailable):
                    session.commit()
                session.rollback()
            assert observed == []
            with app.owner_engine.connect() as connection:
                assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == 0
            app.rings[TENANT] = healthy
            with app.sessions(tenant_id=TENANT) as session:
                session.add(app.Customer(id=row_id, tenant_id=TENANT, name="recovering account", rank=1))
                session.commit()
                assert session.scalar(select(app.Customer.id).where(app.Customer.name == "recovering account")) == row_id
        else:
            async def scenario():
                engine, sessions = await _async_factory(app)
                event.listen(engine.sync_engine, "before_cursor_execute", lambda *args: observed.append(True))
                try:
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(app.Customer(id=row_id, tenant_id=TENANT, name="recovering account", rank=1))
                        with pytest.raises(KeyUnavailable):
                            await session.commit()
                        await session.rollback()
                    assert observed == []
                    with app.owner_engine.connect() as connection:
                        assert connection.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one() == 0
                    app.rings[TENANT] = healthy
                    async with sessions(tenant_id=TENANT) as session:
                        session.add(app.Customer(id=row_id, tenant_id=TENANT, name="recovering account", rank=1))
                        await session.commit()
                        assert await session.scalar(select(app.Customer.id).where(app.Customer.name == "recovering account")) == row_id
                finally:
                    await engine.dispose()
            asyncio.run(scenario())
