"""Native PostgreSQL/SQLAlchemy behavior is the oracle for attached workflows."""

import asyncio
import json
import os
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
import pytest
from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table, Text, Uuid, event, select, text, func, insert, update
from sqlalchemy import bindparam, create_engine, inspect, literal, literal_column, type_coerce
from sqlalchemy import BigInteger, and_, or_, tuple_, cast
from sqlalchemy.sql.elements import Grouping
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, aliased, joinedload, registry, relationship, selectinload, sessionmaker

from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring, create_root, AuthenticationFailed, KeyUnavailable
from cryptalis.manifest.compiler import Writer, WriterInventory, compile_protection
from cryptalis.sqlalchemy import attach, PolicyMismatch, UnsupportedProtectedOperation


DOMAIN, TABLE_ID, NOTE, SECRET, TENANT, OTHER = (UUID(int=i) for i in range(1, 7))


@pytest.fixture(scope="module")
def db():
    if not os.environ.get("CRYPTALIS_TEST_DATABASE_URL"):
        pytest.skip("Authorized real PostgreSQL is required")
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], connect_timeout=5) as c:
        assert c.execute("select 1").fetchone() == (1,)
        assert int(c.execute("show server_version_num").fetchone()[0]) // 10000 == 16
        assert c.execute("select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname=current_user").fetchone() == (True,)
    return True


@pytest.fixture
def app(db, request):
    options = getattr(request, "param", {})
    schema = "cryptalis_adapter_" + uuid4().hex
    engine = create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
    mapping = registry(metadata=MetaData(schema=schema))
    customer = Table("customer", mapping.metadata,
                     Column("id", BigInteger if options.get("bigint") else Uuid, primary_key=True,
                            autoincrement=False, default=uuid4 if options.get("client_default") else None),
                     Column("tenant_id", Uuid, nullable=False),
                     Column("name", Text, nullable=False, unique=True), Column("note", Text),
                     Column("secret", Text), Column("rank", Integer, nullable=False))
    article = Table("article", mapping.metadata, Column("id", Uuid, primary_key=True),
                    Column("customer_id", BigInteger if options.get("bigint") else Uuid, ForeignKey(customer.c.id)), Column("title", Text))
    class Customer:
        pass
    class Article:
        pass
    mapping.map_imperatively(Customer, customer, properties={"articles": relationship(Article, back_populates="customer")})
    mapping.map_imperatively(Article, article, properties={"customer": relationship(Customer, back_populates="articles")})
    with engine.begin() as c:
        c.execute(text(f'CREATE SCHEMA "{schema}"'))
    def cleanup():
        engine.dispose()
        with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as c:
            c.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        mapping.dispose()
    request.addfinalizer(cleanup)
    mapping.metadata.create_all(engine)
    declaration = {"schema": "cryptalis.protection/v1", "profile": "cf1", "domain_id": str(DOMAIN),
                   "models": [{"model": "Customer", "table_id": str(TABLE_ID), "tenancy": {"column": "tenant_id"},
                               "fields": [{"name": name, "field_id": str(identity), "protect": True,
                                           "queries": [], "accept_leakage": []}
                                          for name, identity in (("note", NOTE), ("secret", SECRET))]}]}
    if options.get("single_tenant"):
        declaration["models"][0]["tenancy"] = {"single_tenant": True}
    plan = compile_protection(json.dumps(declaration).encode(), mapping, engine,
                              writers=WriterInventory(True, (Writer(TABLE_ID, "app", "sqlalchemy", evidence="test-owned application"),)))
    provider = DevelopmentKeyProvider()
    rings = {}
    for tenant in (TENANT, OTHER, TABLE_ID):
        context = KeyContext(DOMAIN, tenant, "payload", uuid4(), 1)
        rings[tenant] = Keyring(KeyPolicy(DOMAIN, tenant, (create_root(provider, context),), 1),
                               {provider.provider_id: provider})
    state = SimpleNamespace(schema=schema, engine=engine, mapping=mapping, Customer=Customer, declaration=declaration,
                            Article=Article, plan=plan, rings=rings, provider=provider)
    def switch():
        # Test setup only: no application data, no product transition executor.
        with engine.begin() as c:
            for name in ("note", "secret"):
                c.execute(text(f'ALTER TABLE "{schema}".customer ALTER COLUMN {name} TYPE pg_catalog.bytea USING NULL::pg_catalog.bytea'))
    state.switch = switch
    yield state


def factory(app, protected):
    if protected:
        app.switch()
        return attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
    native = sessionmaker(app.engine)
    return lambda *, tenant_id: native()


@pytest.mark.parametrize("protected", [False, True])
def test_native_state_flush_refresh_merge_autoflush_and_rollback(app, protected):
    sessions, Customer = factory(app, protected), app.Customer
    identity = uuid4()
    with sessions(tenant_id=TENANT) as s:
        row = Customer(id=identity, tenant_id=TENANT, name="original", note="café", secret="", rank=1)
        s.add(row)
        assert type(row.note) is str
        s.flush()
        assert row.note == "café" and row.secret == ""
        assert not inspect(row).attrs.note.history.has_changes()
        assert s.get(Customer, identity) is row
        row.note = "cafe\u0301"
        assert inspect(row).attrs.note.history.has_changes()
        assert s.scalar(select(Customer.note).where(Customer.id == identity)) == "cafe\u0301"
        s.commit()
        assert row.note == "cafe\u0301"
        s.expire(row, ["note"])
        assert row.note == "cafe\u0301"
        s.refresh(row)
        assert row.secret == ""
        s.expunge(row)
    row.note = "detached"
    with sessions(tenant_id=TENANT) as s:
        merged = s.merge(row)
        assert merged is not row and merged.note == "detached"
        s.flush()
        s.rollback()
        assert s.get(Customer, identity).note == "cafe\u0301"


@pytest.mark.parametrize("protected", [False, True])
def test_native_entities_scalars_aliases_outerjoins_relationships_and_streaming(app, protected):
    sessions, Customer, Article = factory(app, protected), app.Customer, app.Article
    identities = [uuid4() for _ in range(6)]
    values = [None, "", "雪😀", "exact", "e\u0301", "é"]
    with sessions(tenant_id=TENANT) as s:
        for i, value in enumerate(values):
            row = Customer(id=identities[i], tenant_id=TENANT, name=f"person-{i}", note=value, secret="same", rank=i)
            row.articles = [Article(id=uuid4(), title="one"), Article(id=uuid4(), title="two")]
            s.add(row)
        s.add(Article(id=uuid4(), title="orphan"))
        s.commit()
    with sessions(tenant_id=TENANT) as s:
        stmt = select(Customer).order_by(Customer.rank)
        rows = s.scalars(stmt).all()
        assert [row.note for row in rows] == values
        assert s.scalars(stmt).all()[0] is rows[0]
        assert s.execute(select(Customer.note.label("renamed"), Customer.rank).order_by(Customer.rank)).keys() == ["renamed", "rank"]
        assert s.execute(select(Customer.note, Customer.secret).order_by(Customer.rank)).all() == [(v, "same") for v in values]
        alias = aliased(Customer)
        assert s.scalars(select(alias.note).order_by(alias.rank)).all() == values
        assert s.scalars(select(alias).order_by(alias.rank)).all()[0] is rows[0]
        orphan = s.execute(select(Article.title, alias.note).outerjoin(alias, Article.customer_id == alias.id).where(Article.title == "orphan")).one()
        assert tuple(orphan) == ("orphan", None)
        assert s.scalars(stmt.options(selectinload(Customer.articles))).all()[0].articles[0].customer is rows[0]
        joined = s.execute(stmt.options(joinedload(Customer.articles)))
        from sqlalchemy.exc import InvalidRequestError
        with pytest.raises(InvalidRequestError):
            joined.all()
        assert len(s.execute(stmt.options(joinedload(Customer.articles))).unique().scalars().all()) == 6
        batches = list(s.scalars(stmt.execution_options(yield_per=2)).partitions())
        assert [len(batch) for batch in batches] == [2, 2, 2]
        assert [x.note for batch in batches for x in batch] == values


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("projection", ["entity", "scalar"])
def test_interleaved_tenants_keep_current_context_on_reused_statements(app, protected, projection):
    """Verify that tenant context cannot leak across reused statements."""
    sessions, Customer = factory(app, protected), app.Customer
    identities = {tenant: [uuid4(), uuid4()] for tenant in (TENANT, OTHER)}
    values = {TENANT: ["tenant-one é", "tenant-one e\u0301"], OTHER: ["tenant-two 雪", "tenant-two 😀"]}
    for tenant in (TENANT, OTHER):
        with sessions(tenant_id=tenant) as session:
            session.add_all([Customer(id=identity, tenant_id=tenant, name=f"{tenant}-{index}",
                                      note=value, secret="", rank=index)
                             for index, (identity, value) in enumerate(zip(identities[tenant], values[tenant]))])
            session.commit()
    selected = Customer if projection == "entity" else Customer.note
    statement = select(selected).where(Customer.id == bindparam("point"), Customer.tenant_id == bindparam("scope"))
    native_statement = select(Customer.name).where(Customer.id == bindparam("point"))
    native_cache_hits = []
    def observe_cache(connection, cursor, sql_text, parameters, context, many):
        if context.compiled is not None and hasattr(context.compiled.statement, "selected_columns"):
            columns = list(context.compiled.statement.selected_columns)
            if len(columns) == 1 and columns[0].shares_lineage(inspect(Customer).local_table.c.name):
                native_cache_hits.append(context.cache_hit.name)
    event.listen(app.engine, "after_cursor_execute", observe_cache)
    with sessions(tenant_id=TENANT) as first, sessions(tenant_id=OTHER) as second:
        by_tenant = {TENANT: first, OTHER: second}
        for tenant, index in ((TENANT, 0), (OTHER, 0), (TENANT, 1), (OTHER, 1), (TENANT, 0), (OTHER, 0)):
            session = by_tenant[tenant]
            result = session.scalar(statement, {"point": identities[tenant][index], "scope": tenant})
            value = result.note if projection == "entity" else result
            assert type(value) is str and value == values[tenant][index]
            assert session.scalar(native_statement, {"point": identities[tenant][index]}) == f"{tenant}-{index}"
        for tenant in (TENANT, OTHER):
            row = by_tenant[tenant].get(Customer, identities[tenant][0])
            row.note = values[tenant][0] + " changed"
        for tenant in (OTHER, TENANT):
            result = by_tenant[tenant].scalar(statement, {"point": identities[tenant][0], "scope": tenant})
            assert (result.note if projection == "entity" else result) == values[tenant][0] + " changed"
        first.rollback()
        second.rollback()
        for tenant in (OTHER, TENANT):
            result = by_tenant[tenant].scalar(statement, {"point": identities[tenant][0], "scope": tenant})
            assert (result.note if projection == "entity" else result) == values[tenant][0]
    assert "CACHE_HIT" in native_cache_hits


def test_protected_plaintext_never_crosses_driver_boundary_and_failures_release_none(app):
    sessions, Customer = factory(app, True), app.Customer
    identity, other_identity = uuid4(), uuid4()
    observed = []
    event.listen(app.engine, "before_cursor_execute", lambda c, cur, st, p, ctx, many: observed.append(p))
    with sessions(tenant_id=TENANT) as s:
        s.add(Customer(id=identity, tenant_id=TENANT, name="visible", note="protected-marker", secret="second-marker", rank=1))
        s.add(Customer(id=other_identity, tenant_id=TENANT, name="other-visible", note="other-protected-marker", secret="", rank=2))
        s.commit()
        row = s.get(Customer, identity)
        row.note = "updated-marker"
        s.commit()
    serialized = repr(observed)
    assert "visible" in serialized  # Positive control: collector sees actual binds.
    for secret in ("protected-marker", "other-protected-marker", "second-marker", "updated-marker"):
        assert secret not in serialized
    with sessions(tenant_id=OTHER) as s:
        with pytest.raises(AuthenticationFailed):
            s.get(Customer, identity)  # Valid frame, wrong expected tenant.
    def substitute_point(connection, statement, multiparams, params, options):
        return select(Customer).where(Customer.id == other_identity), [], {}
    event.listen(app.engine, "before_execute", substitute_point, retval=True)
    try:
        with sessions(tenant_id=TENANT) as s:
            with pytest.raises(AuthenticationFailed):
                s.get(Customer, identity)  # Real SQL returns a different valid row.
    finally:
        event.remove(app.engine, "before_execute", substitute_point)
    with sessions(tenant_id=TENANT) as s:
        assert s.get(Customer, identity).note == "updated-marker"
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as c:
        payload = c.execute(sql.SQL("select note from {}.customer where id=%s").format(sql.Identifier(app.schema)), (identity,)).fetchone()[0]
        assert bytes(payload).startswith(b"CF1\0")
        c.execute(sql.SQL("update {}.customer set note=%s where id=%s").format(sql.Identifier(app.schema)), (payload, other_identity))
    with sessions(tenant_id=TENANT) as s:
        with pytest.raises(AuthenticationFailed):
            s.get(Customer, other_identity)  # Valid frame relocated to another row.
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as c:
        altered = bytearray(payload)
        altered[-1] ^= 1
        c.execute(sql.SQL("update {}.customer set note=%s where id=%s").format(sql.Identifier(app.schema)), (bytes(altered), identity))
    with sessions(tenant_id=TENANT) as s:
        with pytest.raises(AuthenticationFailed):
            s.get(Customer, identity)


_POINT_FORMS = ("bound", "grouped", "nested_and", "reversed", "literal", "late",
                "late_override", "single_in", "late_in", "multi_in", "callable", "callable_override", "tuple_eq",
                "tuple_in", "or", "cast", "text", "literal_sql", "unique_override",
                "unique_default", "conflicting_defaults", "conflicting_override")
_REFUSED_POINT_FORMS = {"callable", "tuple_eq", "tuple_in", "or", "cast", "text",
                        "literal_sql", "unique_override", "conflicting_defaults"}


def _point_predicate(Customer, identity, mode, calls):
    params = {}
    bound = bindparam("point", identity, type_=Uuid())
    predicate = Customer.id == bound
    if mode == "grouped":
        predicate = Grouping(predicate)
    elif mode == "nested_and":
        predicate = Grouping(and_(Grouping(predicate), Grouping(and_(Customer.rank >= 0, Customer.name != "absent"))))
    elif mode == "reversed":
        predicate = bound == Customer.id
    elif mode == "literal":
        predicate = Customer.id == literal(identity, Uuid())
    elif mode in ("late", "late_override"):
        predicate = Customer.id == bindparam("point", uuid4(), type_=Uuid()) if mode == "late_override" else Customer.id == bindparam("point", type_=Uuid())
        params = {"point": identity}
    elif mode == "single_in":
        predicate = Customer.id.in_([identity])
    elif mode == "late_in":
        predicate = Customer.id.in_(bindparam("points", expanding=True, type_=Uuid()))
        params = {"points": [identity]}
    elif mode == "multi_in":
        predicate = Customer.id.in_([identity, uuid4(), None])
    elif mode in ("callable", "callable_override"):
        def value():
            calls.append(True)
            return identity
        predicate = Customer.id == bindparam("point", callable_=value, type_=Uuid())
        if mode == "callable_override":
            params = {"point": identity}
    elif mode == "tuple_eq":
        predicate = tuple_(Customer.id) == tuple_(literal(identity, Uuid()))
    elif mode == "tuple_in":
        predicate = tuple_(Customer.id).in_([(identity,)])
    elif mode == "or":
        predicate = or_(predicate, Customer.name == "absent")
    elif mode == "cast":
        predicate = cast(Customer.id, Uuid()) == identity
    elif mode == "text":
        predicate = text("id = :point").bindparams(bound)
    elif mode == "literal_sql":
        predicate = Customer.id == literal_column("'" + str(identity) + "'::uuid")
    elif mode == "unique_override":
        predicate = Customer.id == bindparam("point", uuid4(), unique=True, type_=Uuid())
        params = {"point_1": identity}
    elif mode == "unique_default":
        predicate = Customer.id == bindparam("point", identity, unique=True, type_=Uuid())
    elif mode in ("conflicting_defaults", "conflicting_override"):
        predicate = and_(predicate, Customer.id == bindparam("point", uuid4(), type_=Uuid()))
        if mode == "conflicting_override":
            params = {"point": identity}
    return predicate, params


@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
@pytest.mark.parametrize("projection", ["entity", "scalar"])
@pytest.mark.parametrize("first_form", ["grouped", "callable"])
def test_requested_row_variants_use_native_oracle_and_reject_substituted_rows(app, asynchronous, projection, first_form):
    """Native SQL identifies a requested row; a different valid frame must never pass."""
    Customer = app.Customer
    identity, other = uuid4(), uuid4()
    selected = Customer if projection == "entity" else Customer.note
    # Independent native SQLAlchemy engine remains outside attachment guards.
    oracle = create_engine("postgresql+psycopg://", hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
    def substitute(connection, statement, multiparams, params, options):
        return select(selected).where(Customer.id == other), [], {}
    def cases():
        for mode in (first_form, *(form for form in _POINT_FORMS if form != first_form)):
            calls = []
            predicate, params = _point_predicate(Customer, identity, mode, calls)
            with Session(oracle) as native:
                # Isolate each expression's bind semantics. A native cached
                # non-callable template can otherwise omit a later callable.
                expected = native.scalar(select(Customer.name).where(predicate), params,
                                         execution_options={"compiled_cache": None})
            # Duplicate named defaults use the compiler's final definition.
            assert expected == (None if mode == "conflicting_defaults" else "requested"), mode
            assert len(calls) == (1 if mode == "callable" else 0)
            calls.clear()
            yield mode, select(selected).where(predicate), params, calls
    def check(session, engine):
        observed = []
        event.listen(engine, "before_cursor_execute", lambda *args: observed.append(True))
        for mode, statement, params, calls in cases():
            before = len(observed)
            if mode in _REFUSED_POINT_FORMS:
                with pytest.raises(UnsupportedProtectedOperation):
                    session.scalar(statement, params)
                assert len(observed) == before, mode + " reached SQL"
                assert not calls, "Admission evaluated a host callable"
                continue
            value = session.scalar(statement, params)
            assert (value.note if projection == "entity" else value) == "requested payload"
            session.expunge_all()
            event.listen(engine, "before_execute", substitute, retval=True)
            try:
                with pytest.raises(AuthenticationFailed):
                    session.scalar(statement, params)
            finally:
                event.remove(engine, "before_execute", substitute)
    def seed(session):
        session.add_all([Customer(id=identity, tenant_id=TENANT, name="requested", note="requested payload", secret="", rank=1),
                         Customer(id=other, tenant_id=TENANT, name="substituted", note="different valid payload", secret="", rank=2)])
    if not asynchronous:
        sessions = factory(app, True)
        try:
            with sessions(tenant_id=TENANT) as session:
                seed(session)
                session.commit()
            with sessions(tenant_id=TENANT) as session:
                check(session, app.engine)
        finally:
            oracle.dispose()
        return
    app.switch()
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        try:
            sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            async with sessions(tenant_id=TENANT) as session:
                seed(session)
                await session.commit()
            async with sessions(tenant_id=TENANT) as session:
                await session.run_sync(lambda sync: check(sync, engine.sync_engine))
        finally:
            await engine.dispose()
            oracle.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("form", ["having", "join_on"])
@pytest.mark.parametrize("projection", ["entity", "scalar"])
def test_requested_identity_outside_where_cannot_skip_admission(app, form, projection):
    sessions, Customer, Article = factory(app, True), app.Customer, app.Article
    identity, other = uuid4(), uuid4()
    with sessions(tenant_id=TENANT) as session:
        session.add_all([Customer(id=identity, tenant_id=TENANT, name="requested", note="requested payload", secret="", rank=1),
                         Customer(id=other, tenant_id=TENANT, name="other", note="other valid payload", secret="", rank=2),
                         Article(id=uuid4(), customer_id=identity, title="requested article")])
        session.commit()
    def statement(selected):
        point = Customer.id == bindparam("point", identity, type_=Uuid())
        if form == "having":
            return select(selected).group_by(Customer.id).having(point)
        return select(selected).join(Article, and_(Article.customer_id == Customer.id, point))
    oracle = create_engine("postgresql+psycopg://", hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
    try:
        with Session(oracle) as native:
            assert native.scalar(statement(Customer.name)) == "requested"
    finally:
        oracle.dispose()
    observed = []
    event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
    selected = Customer if projection == "entity" else Customer.note
    def substitute(connection, statement, multiparams, params, options):
        return select(selected).where(Customer.id == other), [], {}
    event.listen(app.engine, "before_execute", substitute, retval=True)
    try:
        with sessions(tenant_id=TENANT) as session:
            with pytest.raises(UnsupportedProtectedOperation):
                session.scalar(statement(selected))
        assert not observed, "Unadmitted identity constraint reached SQL"
    finally:
        event.remove(app.engine, "before_execute", substitute)


@pytest.mark.parametrize("form", ["or", "cast", "range"])
def test_plain_projection_keeps_native_primary_key_predicates(app, form):
    sessions, Customer = factory(app, True), app.Customer
    identity = uuid4()
    with sessions(tenant_id=TENANT) as session:
        session.add(Customer(id=identity, tenant_id=TENANT, name="native plain value", note="private", secret="", rank=1))
        session.commit()
    predicates = {"or": or_(Customer.id == identity, Customer.rank == -1),
                  "cast": cast(Customer.id, Uuid()) == identity,
                  "range": Customer.id >= identity}
    statement = select(Customer.name).where(predicates[form])
    oracle = create_engine("postgresql+psycopg://", hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
    try:
        with Session(oracle) as native:
            expected = native.scalars(statement).all()
        with sessions(tenant_id=TENANT) as session:
            assert session.scalars(statement).all() == expected == ["native plain value"]
    finally:
        oracle.dispose()


def test_unprepared_opaque_computed_nested_ddl_and_raw_driver_paths_reject(app):
    sessions, Customer = factory(app, True), app.Customer
    observed = []
    event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
    denied = [text("SELECT 1"), insert(Customer).values(id=uuid4(), tenant_id=TENANT, name="unsafe", note="private", rank=1),
              update(Customer).values(note=func.lower("private")), select(func.lower(Customer.note)),
              select(Customer).where(Customer.note == "private"), select(Customer).order_by(Customer.note),
              select(Customer).where(Customer.rank.in_(select(func.length(Customer.note)))),
              select(Customer).distinct(), select(Customer.note).distinct(),
              select(Customer.note).group_by(Customer.note), select(func.count(Customer.note.distinct())),
              select(Customer.note.label("protected_value")).order_by("protected_value"),
              select(literal_column("1")), select(type_coerce(Customer.note, Text))]
    with sessions(tenant_id=TENANT) as s:
        for statement in denied:
            before = len(observed)
            with pytest.raises(UnsupportedProtectedOperation):
                s.execute(statement)
            assert len(observed) == before, "Unsupported query reached the driver"
        assert s.scalar(select(literal(1))) == 1
        assert s.scalar(select(func.count()).select_from(Customer)) == 0
        with pytest.raises(PolicyMismatch):
            s.execute(select(Customer), execution_options={"schema_translate_map": {app.schema: app.schema}})
        with pytest.raises(UnsupportedProtectedOperation):
            s.execute(text("CREATE TABLE forbidden(id int)"), execution_options={"cryptalis_admitted": True})
        with pytest.raises(UnsupportedProtectedOperation):
            s.connection().exec_driver_sql("SELECT 1")
        raw = s.connection().connection
        for handle in (raw.dbapi_connection, raw.driver_connection):
            with pytest.raises(UnsupportedProtectedOperation):
                handle.cursor().execute("SELECT 1")
            with pytest.raises(UnsupportedProtectedOperation):
                handle.pgconn
            with pytest.raises(UnsupportedProtectedOperation):
                handle.cursor().copy("COPY anything FROM STDIN")
    app.engine.dispose()
    with sessions(tenant_id=TENANT) as s:
        with pytest.raises(UnsupportedProtectedOperation):
            s.connection().connection.driver_connection.cursor().execute("SELECT 1")


def test_failed_flush_missing_identity_changed_tenant_and_context_cleanup(app):
    sessions, Customer = factory(app, True), app.Customer
    with sessions(tenant_id=TENANT) as s:
        row = Customer(tenant_id=TENANT, name="missing", note="x", rank=1)
        s.add(row)
        with pytest.raises(UnsupportedProtectedOperation):
            s.flush()
        s.rollback()
        s.add(Customer(id=uuid4(), tenant_id=OTHER, name="wrong tenant", note="x", rank=1))
        with pytest.raises(AuthenticationFailed):
            s.flush()
        s.rollback()
        first = Customer(id=uuid4(), tenant_id=TENANT, name="duplicate", note="first", rank=1)
        s.add(first)
        s.commit()
        s.add(Customer(id=uuid4(), tenant_id=TENANT, name="duplicate", note="second", rank=2))
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            s.flush()
        s.rollback()
        assert s.get(Customer, first.id).note == "first"
        first.id = uuid4()
        with pytest.raises(UnsupportedProtectedOperation):
            s.flush()


def test_changed_mapping_is_rejected_before_driver_execution(app):
    """Verify that changed storage or context mappings cannot reuse admission."""
    sessions = factory(app, True)
    table = inspect(app.Customer).local_table
    observed = []
    event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
    for target, attribute, replacement in ((table.c.note, "type", Text()),
                                           (table.c.id, "type", Integer()),
                                           (table.c.note, "nullable", False),
                                           (table.c.id, "primary_key", False),
                                           (table, "schema", "changed_target")):
        original = getattr(target, attribute)
        try:
            setattr(target, attribute, replacement)
            before = len(observed)
            with sessions(tenant_id=TENANT) as session:
                with pytest.raises(PolicyMismatch):
                    session.scalars(select(app.Customer)).all()
            assert len(observed) == before
        finally:
            setattr(target, attribute, original)
    with sessions(tenant_id=TENANT) as session:
        assert session.scalars(select(app.Customer)).all() == []


@pytest.mark.parametrize("change", ["translation", "record_mapping", "primary_key_mapping", "tenant_nullability", "field_nullability", "server_key_default"])
def test_attachment_matches_native_context_catalog_and_pinned_target(app, change):
    app.switch()
    engine = app.engine
    table = inspect(app.Customer).local_table
    if change == "translation":
        engine = engine.execution_options(schema_translate_map={app.schema: app.schema})
    elif change == "record_mapping":
        table.c.id.type = BigInteger()
    elif change == "primary_key_mapping":
        inspect(app.Customer).primary_key = (table.c.name,)
    else:
        alteration = {"tenant_nullability": "ALTER COLUMN tenant_id DROP NOT NULL",
                      "field_nullability": "ALTER COLUMN note SET NOT NULL",
                      "server_key_default": "ALTER COLUMN id SET DEFAULT pg_catalog.gen_random_uuid()"}[change]
        with engine.begin() as connection:
            connection.execute(text(f'ALTER TABLE "{app.schema}".customer {alteration}'))
    with pytest.raises(PolicyMismatch):
        attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_async_native_workflow_and_task_isolation(app, protected):
    if protected:
        app.switch()
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        try:
            if protected:
                sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = async_sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            async def write_read(tenant, value):
                async with sessions(tenant_id=tenant) as s:
                    identity = uuid4()
                    row = app.Customer(id=identity, tenant_id=tenant, name=value, note=value, secret="", rank=1)
                    s.add(row)
                    await s.flush()
                    assert row.note == value
                    await s.commit()
                    await s.refresh(row)
                    assert row.note == value
                    s.expire(row, ["note"])
                    await s.refresh(row, ["note"])
                    assert await s.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == value
                    row.note = value + " updated"
                    assert await s.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == value + " updated"
                    await s.rollback()
            await asyncio.gather(write_read(TENANT, "tenant-one"), write_read(OTHER, "tenant-two"))
            if protected:
                async with sessions(tenant_id=TENANT) as s:
                    with pytest.raises(UnsupportedProtectedOperation):
                        connection = await s.connection()
                        await connection.exec_driver_sql("SELECT 1")
                    connection = await s.connection()
                    raw = await connection.get_raw_connection()
                    for handle in (raw.dbapi_connection, raw.driver_connection):
                        with pytest.raises(UnsupportedProtectedOperation):
                            handle.pgconn
        finally:
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("projection", ["entity", "scalar"])
def test_async_interleaved_tenants_keep_current_context_on_reused_statements(app, protected, projection):
    """The async oracle uses the same statement and changing tenant/point binds."""
    if protected:
        app.switch()
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        identities = {tenant: [uuid4(), uuid4()] for tenant in (TENANT, OTHER)}
        values = {TENANT: ["one é", "one e\u0301"], OTHER: ["two 雪", "two 😀"]}
        try:
            if protected:
                sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = async_sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            for tenant in (TENANT, OTHER):
                async with sessions(tenant_id=tenant) as session:
                    session.add_all([app.Customer(id=record, tenant_id=tenant, name=f"{tenant}-{index}",
                                                  note=value, secret="", rank=index)
                                     for index, (record, value) in enumerate(zip(identities[tenant], values[tenant]))])
                    await session.commit()
            selected = app.Customer if projection == "entity" else app.Customer.note
            statement = select(selected).where(app.Customer.id == bindparam("point"), app.Customer.tenant_id == bindparam("scope"))
            async with sessions(tenant_id=TENANT) as first, sessions(tenant_id=OTHER) as second:
                by_tenant = {TENANT: first, OTHER: second}
                for tenant, index in ((TENANT, 0), (OTHER, 0), (TENANT, 1), (OTHER, 1), (TENANT, 0), (OTHER, 0)):
                    result = await by_tenant[tenant].scalar(statement, {"point": identities[tenant][index], "scope": tenant})
                    value = result.note if projection == "entity" else result
                    assert type(value) is str and value == values[tenant][index]
                for tenant in (TENANT, OTHER):
                    row = await by_tenant[tenant].get(app.Customer, identities[tenant][0])
                    row.note = values[tenant][0] + " changed"
                for tenant in (OTHER, TENANT):
                    result = await by_tenant[tenant].scalar(statement, {"point": identities[tenant][0], "scope": tenant})
                    assert (result.note if projection == "entity" else result) == values[tenant][0] + " changed"
                await first.rollback()
                await second.rollback()
                for tenant in (OTHER, TENANT):
                    result = await by_tenant[tenant].scalar(statement, {"point": identities[tenant][0], "scope": tenant})
                    assert (result.note if projection == "entity" else result) == values[tenant][0]
        finally:
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_async_alias_streaming_preserves_native_partitions(app, protected):
    if protected:
        app.switch()
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        try:
            if protected:
                sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = async_sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            values = [None, "", "雪", "😀", "é", "e\u0301"]
            async with sessions(tenant_id=TENANT) as session:
                session.add_all([app.Customer(id=uuid4(), tenant_id=TENANT, name=f"stream-{i}", note=v, secret="", rank=i)
                                 for i, v in enumerate(values)])
                await session.commit()
            async with sessions(tenant_id=TENANT) as session:
                alias = aliased(app.Customer)
                result = await session.stream_scalars(select(alias.note).order_by(alias.rank).execution_options(yield_per=2))
                batches = [batch async for batch in result.partitions()]
                assert [len(batch) for batch in batches] == [2, 2, 2]
                assert [value for batch in batches for value in batch] == values
                await result.close()
        finally:
            await engine.dispose()
    asyncio.run(scenario())


def test_async_cancellation_during_key_preparation_has_no_database_effect(app):
    """A local awaited-provider boundary injects cancellation before SQL."""
    app.switch()
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        provider = app.provider
        class AwaitedProvider:
            provider_id = provider.provider_id

            def unwrap(self, wrapper, context):
                raise AssertionError("The async adapter must not call synchronous provider preparation")

            async def unwrap_async(self, wrapper, context):
                entered.set()
                await release.wait()
                return provider.unwrap(wrapper, context)

        awaited = AwaitedProvider()
        ring = Keyring(app.rings[TENANT].policy, {awaited.provider_id: awaited})
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        task = None
        try:
            sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=ring)
            async with sessions(tenant_id=TENANT) as session:
                identity = uuid4()
                session.add(app.Customer(id=identity, tenant_id=TENANT, name="awaited provider", note="pending", rank=1))
                task = asyncio.create_task(session.flush())
                await asyncio.wait_for(entered.wait(), timeout=5)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                await session.rollback()
                with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as observer:
                    assert observer.execute(sql.SQL("SELECT count(*) FROM {}.customer").format(sql.Identifier(app.schema))).fetchone() == (0,)
                release.set()
                session.add(app.Customer(id=identity, tenant_id=TENANT, name="fresh after cancellation", note="fresh", rank=1))
                await session.commit()
                assert await session.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == "fresh"
        finally:
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_async_database_cancellation_preserves_rollback_and_recovery(app, protected, caplog):
    """Observe PostgreSQL executing the query before cancellation; compare native behavior."""
    if protected:
        app.switch()

    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        task = None
        try:
            if protected:
                sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = async_sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            identity = uuid4()
            async with sessions(tenant_id=TENANT) as session:
                session.add(app.Customer(id=identity, tenant_id=TENANT, name="canceled", note="pending", rank=1))
                await session.flush()
                pid = await session.scalar(select(func.pg_backend_pid()))
                task = asyncio.create_task(session.scalar(select(func.pg_sleep(30))))
                async with await psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], autocommit=True) as observer:
                    async with asyncio.timeout(5):
                        while True:
                            cursor = await observer.execute("select wait_event from pg_stat_activity where pid=%s", (pid,))
                            if await cursor.fetchone() == ("PgSleep",):
                                break
                            await asyncio.sleep(0.01)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=5)
                await session.rollback()
                assert await session.get(app.Customer, identity) is None
            async with sessions(tenant_id=OTHER) as session:
                session.add(app.Customer(id=identity, tenant_id=OTHER, name="recovered", note="fresh tenant context", rank=2))
                await session.commit()
                assert await session.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == "fresh tenant context"
            assert not [record for record in caplog.records if record.levelno >= 40], "Cancellation or cleanup logged an error"
        finally:
            if task is not None and not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
def test_expired_context_survives_plaintext_only_update_and_delete(app, protected, asynchronous):
    """Native commit expiration must not prevent ordinary ORM updates/deletes."""
    identity = uuid4()
    if not asynchronous:
        sessions = factory(app, protected)
        with sessions(tenant_id=TENANT) as session:
            row = app.Customer(id=identity, tenant_id=TENANT, name="expired", note="preserved", rank=1)
            session.add(row)
            session.commit()
            assert inspect(row).expired_attributes
            row.rank = 2
            session.commit()
            assert session.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == "preserved"
            assert session.scalar(select(app.Customer.rank).where(app.Customer.id == identity)) == 2
            session.expire(row)
            session.delete(row)
            session.commit()
            assert session.get(app.Customer, identity) is None
        return
    if protected:
        app.switch()
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
        try:
            if protected:
                sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = async_sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            async with sessions(tenant_id=TENANT) as session:
                row = app.Customer(id=identity, tenant_id=TENANT, name="expired", note="preserved", rank=1)
                session.add(row)
                await session.commit()
                assert inspect(row).expired_attributes
                row.rank = 2
                await session.commit()
                assert await session.scalar(select(app.Customer.note).where(app.Customer.id == identity)) == "preserved"
                assert await session.scalar(select(app.Customer.rank).where(app.Customer.id == identity)) == 2
                session.expire(row)
                await session.delete(row)
                await session.commit()
                assert await session.get(app.Customer, identity) is None
        finally:
            await engine.dispose()
    asyncio.run(scenario())


@pytest.mark.parametrize("app", [{"single_tenant": True, "bigint": True}], indirect=True)
@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_single_tenant_bigint_alias_outer_join_preserves_native_null(app, protected):
    sessions = factory(app, protected)
    with sessions(tenant_id=TABLE_ID) as session:
        session.add(app.Customer(id=2**40, tenant_id=TENANT, name="bigint", note="雪", rank=1))
        session.add(app.Article(id=uuid4(), title="orphan"))
        session.commit()
        alias = aliased(app.Customer)
        assert session.scalar(select(alias.note).where(alias.id == 2**40)) == "雪"
        row = session.execute(select(app.Article.title, alias.note).outerjoin(alias, app.Article.customer_id == alias.id)).one()
        assert tuple(row) == ("orphan", None)


@pytest.mark.parametrize("app", [{"client_default": True}], indirect=True)
@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_application_assigned_identity_with_python_default_mapping(app, protected):
    """A Python default is not a server-generated ID; use an explicit app ID."""
    sessions = factory(app, protected)
    identity = uuid4()
    with sessions(tenant_id=TENANT) as session:
        session.add(app.Customer(id=identity, tenant_id=TENANT, name="assigned", note="value", rank=1))
        session.commit()
        assert session.get(app.Customer, identity).note == "value"


def test_attachment_rejects_existing_native_connections_before_pool_replacement(app):
    """An existing engine connection cannot outlive installation unguarded."""
    app.switch()
    with app.engine.connect() as existing:
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
        assert existing.scalar(select(literal(1))) == 1
    sessions = attach(app.mapping, app.engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
    with sessions(tenant_id=TENANT) as session:
        assert session.scalar(select(literal(1))) == 1


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
def test_same_named_tables_in_distinct_schemas_keep_separate_row_context(app, protected):
    """Physical schema is part of the row address, including batched writes."""
    other_schema = "cryptalis_adapter_" + uuid4().hex
    other_table_id, other_field_id = uuid4(), uuid4()
    other_table = Table("customer", app.mapping.metadata,
                        Column("id", Uuid, primary_key=True), Column("tenant_id", Uuid, nullable=False),
                        Column("note", Text), schema=other_schema)
    class OtherCustomer:
        pass
    app.mapping.map_imperatively(OtherCustomer, other_table)
    with app.engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{other_schema}"'))
    try:
        other_table.create(app.engine)
        declaration = json.loads(json.dumps(app.declaration))
        declaration["models"].append({"model": "OtherCustomer", "table_id": str(other_table_id),
            "tenancy": {"column": "tenant_id"}, "fields": [{"name": "note", "field_id": str(other_field_id),
            "protect": True, "queries": [], "accept_leakage": []}]})
        app.plan = compile_protection(json.dumps(declaration).encode(), app.mapping, app.engine,
            writers=WriterInventory(True, tuple(Writer(table_id, "app", "sqlalchemy", evidence="test-owned application")
                                                for table_id in (TABLE_ID, other_table_id))))
        if protected:
            with app.engine.begin() as connection:
                connection.execute(text(f'ALTER TABLE "{other_schema}".customer ALTER COLUMN note TYPE pg_catalog.bytea USING NULL::pg_catalog.bytea'))
        sessions = factory(app, protected)
        identity = uuid4()
        with sessions(tenant_id=TENANT) as session:
            first = app.Customer(id=identity, tenant_id=TENANT, name="schema-one", note="first schema", rank=1)
            second = OtherCustomer(id=identity, tenant_id=TENANT, note="second schema")
            session.add_all([first, second])
            session.commit()
            assert session.get(app.Customer, identity).note == "first schema"
            assert session.get(OtherCustomer, identity).note == "second schema"
            first.note, second.note = "first updated", "second updated"
            session.commit()
            assert session.get(app.Customer, identity).note == "first updated"
            assert session.get(OtherCustomer, identity).note == "second updated"
    finally:
        app.engine.dispose()
        with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(other_schema)))


def test_ambiguous_columns_and_alternate_target_mapping_reject_before_driver(app):
    """Protected storage must be read through its validated column lineage."""
    from sqlalchemy import column
    sessions = factory(app, True)
    original = inspect(app.Customer).local_table
    alternate = Table("customer", MetaData(), Column("note", Text), schema=app.schema)
    observed = []
    event.listen(app.engine, "before_cursor_execute", lambda *args: observed.append(True))
    with sessions(tenant_id=TENANT) as session:
        for statement in (select(column("note", Text)).select_from(original), select(alternate.c.note)):
            before = len(observed)
            with pytest.raises(UnsupportedProtectedOperation):
                session.execute(statement)
            assert len(observed) == before, "An unvalidated column reached the driver"


@pytest.fixture
def runtime_access(app):
    """Grant customer CRUD and the relationship lookup required for deletion."""
    if not os.environ.get("CRYPTALIS_TEST_RUNTIME_DATABASE_URL"):
        pytest.skip("Separate restricted runtime credentials are required")
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as owner, \
            psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as runtime:
        assert runtime.execute("select 1").fetchone() == (1,)
        assert int(runtime.execute("show server_version_num").fetchone()[0]) // 10000 == 16
        assert (owner.info.host, owner.info.port, owner.info.dbname) == (runtime.info.host, runtime.info.port, runtime.info.dbname)
        owner_role = owner.execute("select current_user").fetchone()[0]
        runtime_role = runtime.execute("select current_user").fetchone()[0]
        assert owner_role != runtime_role
        assert runtime.execute("select not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication and not rolbypassrls from pg_roles where rolname=current_user").fetchone() == (True,)
        assert runtime.execute("select pg_has_role(current_user, %s, 'USAGE'), pg_has_role(current_user, %s, 'SET')", (owner_role, owner_role)).fetchone() == (False, False)
        schema, role = sql.Identifier(app.schema), sql.Identifier(runtime_role)
        owner.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC, {}").format(schema, role))
        owner.execute(sql.SQL("REVOKE ALL ON TABLE {}.customer, {}.article FROM PUBLIC, {}").format(schema, schema, role))
        owner.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(schema, role))
        owner.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {}.customer TO {}").format(schema, role))
        owner.execute(sql.SQL("GRANT SELECT ON TABLE {}.article TO {}").format(schema, role))
        owner.commit()
        target = app.schema + ".customer"
        assert runtime.execute("select has_schema_privilege(current_user, %s, 'USAGE'), has_schema_privilege(current_user, %s, 'CREATE')", (app.schema, app.schema)).fetchone() == (True, False)
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            assert runtime.execute("select has_table_privilege(current_user, %s, %s)", (target, privilege)).fetchone() == (privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"),)
            assert runtime.execute("select has_table_privilege(current_user, %s, %s)", (target, privilege + " WITH GRANT OPTION")).fetchone() == (False,)
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            assert runtime.execute("select has_table_privilege(current_user, %s, %s)", (app.schema + ".article", privilege)).fetchone() == (privilege == "SELECT",)
            assert runtime.execute("select has_table_privilege(current_user, %s, %s)", (app.schema + ".article", privilege + " WITH GRANT OPTION")).fetchone() == (False,)
        assert runtime.execute("select nspowner = (select oid from pg_roles where rolname=%s) from pg_namespace where nspname=%s", (owner_role, app.schema)).fetchone() == (True,)
        assert runtime.execute("select relowner = (select oid from pg_roles where rolname=%s) from pg_class where oid=%s::regclass", (owner_role, target)).fetchone() == (True,)
    return owner_role, runtime_role


@pytest.mark.parametrize("protected", [False, True], ids=["native", "attached"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_restricted_runtime_crud_matches_native_application(app, runtime_access, protected, mode):
    """The same runtime principal and application values exercise both paths."""
    if protected:
        app.switch()
    identities = [uuid4() for _ in range(3)]
    values = [None, "", "runtime é e\u0301 雪😀"]
    Customer = app.Customer
    observed = []
    def observe(connection, cursor, statement, parameters, context, many):
        observed.append(parameters)
    def rows():
        return [Customer(id=identity, tenant_id=TENANT, name=f"runtime-visible-{index}",
                         note=value, secret="runtime-private", rank=index)
                for index, (identity, value) in enumerate(zip(identities, values))]
    def storage():
        # Independent connection observes committed storage, not ORM state.
        with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as connection:
            stored = connection.execute(sql.SQL("select note, secret from {}.customer order by rank").format(sql.Identifier(app.schema))).fetchall()
        if protected:
            assert stored[0][0] is None
            for note, secret in stored:
                for payload in (note, secret):
                    if payload is not None:
                        assert bytes(payload).startswith(b"CF1\0") and b"runtime-private" not in bytes(payload)
            assert "runtime-visible-0" in repr(observed)
            assert "runtime-private" not in repr(observed) and values[2] not in repr(observed)
        else:
            assert stored == [(value, "runtime-private") for value in values]
    statement = select(Customer.note).order_by(Customer.rank)
    if mode == "sync":
        engine = create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                               creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
        try:
            if protected:
                sessions = attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            else:
                native = sessionmaker(engine)
                sessions = lambda *, tenant_id: native()
            event.listen(engine, "before_cursor_execute", observe)
            with sessions(tenant_id=TENANT) as session:
                session.add_all(rows())
                session.commit()
                assert session.scalars(statement).all() == values
            storage()
            with sessions(tenant_id=TENANT) as session:
                row = session.get(Customer, identities[2])
                assert type(row.note) is str and row.note == values[2]
                row.note = "updated runtime"
                session.commit()
                session.refresh(row)
                assert row.note == "updated runtime"
                row.note = "must roll back"
                session.flush()
                session.rollback()
                assert session.get(Customer, identities[2]).note == "updated runtime"
                if protected:
                    before = len(observed)
                    with pytest.raises(UnsupportedProtectedOperation):
                        session.execute(text(f'ALTER TABLE "{app.schema}".customer ADD COLUMN forbidden int'))
                    assert len(observed) == before
                for identity in identities:
                    session.delete(session.get(Customer, identity))
                session.commit()
            with sessions(tenant_id=TENANT) as session:
                assert session.scalars(select(Customer)).all() == []
        finally:
            engine.dispose()
    else:
        async def scenario():
            engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                         async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
            try:
                if protected:
                    sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
                else:
                    native = async_sessionmaker(engine)
                    sessions = lambda *, tenant_id: native()
                event.listen(engine.sync_engine, "before_cursor_execute", observe)
                async with sessions(tenant_id=TENANT) as session:
                    session.add_all(rows())
                    await session.commit()
                    assert (await session.scalars(statement)).all() == values
                storage()
                async with sessions(tenant_id=TENANT) as session:
                    row = await session.get(Customer, identities[2])
                    assert type(row.note) is str and row.note == values[2]
                    row.note = "updated runtime"
                    await session.commit()
                    await session.refresh(row)
                    assert row.note == "updated runtime"
                    row.note = "must roll back"
                    await session.flush()
                    await session.rollback()
                    assert (await session.get(Customer, identities[2])).note == "updated runtime"
                    if protected:
                        before = len(observed)
                        with pytest.raises(UnsupportedProtectedOperation):
                            await session.execute(text(f'ALTER TABLE "{app.schema}".customer ADD COLUMN forbidden int'))
                        assert len(observed) == before
                    for identity in identities:
                        await session.delete(await session.get(Customer, identity))
                    await session.commit()
                async with sessions(tenant_id=TENANT) as session:
                    assert (await session.scalars(select(Customer))).all() == []
            finally:
                await engine.dispose()
        asyncio.run(scenario())
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as connection:
        assert connection.execute(sql.SQL("select count(*) from {}.customer").format(sql.Identifier(app.schema))).fetchone() == (0,)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_postgresql_refuses_runtime_ddl_and_ownership_without_attachment(app, runtime_access, mode):
    """Actual SQLSTATE 42501 is the oracle; Python guards cannot supply it."""
    app.switch()
    owner_role, runtime_role = runtime_access
    schema = sql.Identifier(app.schema)
    denied = [
        sql.SQL("CREATE TABLE {}.forbidden(id int)").format(schema),
        sql.SQL("ALTER TABLE {}.customer ADD COLUMN forbidden int").format(schema),
        sql.SQL("CREATE INDEX forbidden ON {}.customer(rank)").format(schema),
        sql.SQL("TRUNCATE TABLE {}.customer").format(schema),
        sql.SQL("DROP TABLE {}.customer").format(schema),
        sql.SQL("ALTER TABLE {}.customer OWNER TO {}").format(schema, sql.Identifier(runtime_role)),
        sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(schema, sql.Identifier(runtime_role)),
        sql.SQL("DROP SCHEMA {} CASCADE").format(schema),
        sql.SQL("SET ROLE {}").format(sql.Identifier(owner_role)),
    ]
    if mode == "sync":
        with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"], autocommit=True) as connection:
            for statement in denied:
                with pytest.raises(psycopg.errors.InsufficientPrivilege) as refused:
                    with connection.transaction():
                        connection.execute(statement)
                assert refused.value.sqlstate == "42501"
                assert connection.execute("select 1").fetchone() == (1,)
    else:
        async def scenario():
            async with await psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"], autocommit=True) as connection:
                for statement in denied:
                    with pytest.raises(psycopg.errors.InsufficientPrivilege) as refused:
                        async with connection.transaction():
                            await connection.execute(statement)
                    assert refused.value.sqlstate == "42501"
                    assert await (await connection.execute("select 1")).fetchone() == (1,)
        asyncio.run(scenario())
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]) as connection:
        assert connection.execute("select nspowner = (select oid from pg_roles where rolname=%s) from pg_namespace where nspname=%s", (owner_role, app.schema)).fetchone() == (True,)
        assert connection.execute("select relowner = (select oid from pg_roles where rolname=%s) from pg_class where oid=%s::regclass", (owner_role, app.schema + ".customer")).fetchone() == (True,)
        assert connection.execute("select to_regclass(%s)", (app.schema + ".forbidden",)).fetchone() == (None,)
        assert "forbidden" not in [column["name"] for column in inspect(app.engine).get_columns("customer", schema=app.schema)]


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_independent_runtime_writer_can_tamper_replay_null_and_delete(app, runtime_access, mode):
    """Security-doc attack cases expose the limit of ordinary CRUD privileges."""
    app.switch()
    identity = uuid4()
    target = sql.SQL("{}.customer").format(sql.Identifier(app.schema))
    def capture():
        with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as writer:
            return bytes(writer.execute(sql.SQL("SELECT note FROM {} WHERE id=%s").format(target), (identity,)).fetchone()[0])
    def attacks(original):
        current = capture()
        assert current != original
        tampered = current[:-1] + bytes([current[-1] ^ 1])
        for attack, replacement, expected in (("tamper", tampered, None), ("replay", original, "original"),
                                               ("null", None, None), ("delete", None, None)):
            # Each independent connection authenticates again with the runtime URL.
            with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as writer:
                statement = (sql.SQL("DELETE FROM {} WHERE id=%s").format(target) if attack == "delete" else
                             sql.SQL("UPDATE {} SET note=%s WHERE id=%s").format(target))
                parameters = (identity,) if attack == "delete" else (replacement, identity)
                assert writer.execute(statement, parameters).rowcount == 1
            with psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]) as observer:
                stored = observer.execute(sql.SQL("SELECT note FROM {} WHERE id=%s").format(target), (identity,)).fetchone()
                assert stored == (None if attack == "delete" else (replacement,))
            yield attack, expected
    async def scenario():
        engine = create_async_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                                     async_creator=lambda: psycopg.AsyncConnection.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
        try:
            sessions = await attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            async with sessions(tenant_id=TENANT) as session:
                session.add(app.Customer(id=identity, tenant_id=TENANT, name="bypass", note="original", rank=1))
                await session.commit()
            original = capture()
            async with sessions(tenant_id=TENANT) as session:
                row = await session.get(app.Customer, identity)
                row.note = "current"
                await session.commit()
                await session.refresh(row)
                assert row.note == "current"
            for attack, expected in attacks(original):
                async with sessions(tenant_id=TENANT) as session:
                    if attack == "tamper":
                        with pytest.raises(AuthenticationFailed):
                            await session.get(app.Customer, identity)
                    else:
                        row = await session.get(app.Customer, identity)
                        if attack == "delete":
                            assert row is None
                        else:
                            assert row.note == expected
        finally:
            await engine.dispose()
    if mode == "async":
        asyncio.run(scenario())
    else:
        engine = create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                               creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_RUNTIME_DATABASE_URL"]))
        try:
            sessions = attach(app.mapping, engine, lock=app.plan.lock_bytes, keys=app.rings.__getitem__)
            with sessions(tenant_id=TENANT) as session:
                session.add(app.Customer(id=identity, tenant_id=TENANT, name="bypass", note="original", rank=1))
                session.commit()
            original = capture()
            with sessions(tenant_id=TENANT) as session:
                row = session.get(app.Customer, identity)
                row.note = "current"
                session.commit()
                assert row.note == "current"
            for attack, expected in attacks(original):
                with sessions(tenant_id=TENANT) as session:
                    if attack == "tamper":
                        with pytest.raises(AuthenticationFailed):
                            session.get(app.Customer, identity)
                    else:
                        row = session.get(app.Customer, identity)
                        if attack == "delete":
                            assert row is None
                        else:
                            assert row.note == expected
        finally:
            engine.dispose()
