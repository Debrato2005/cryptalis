"""Isolated public-hook experiment. SQLite evidence is not PostgreSQL evidence."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from sqlalchemy import (
    BigInteger, Column, LargeBinary, String, case, cast, create_engine,
    event, func, inspect, select, text, type_coerce, update,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.sql import operators, visitors
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.sql.selectable import FromClause, Select
from sqlalchemy.types import TypeDecorator


KEY = bytes(range(32))  # Public lab key for synthetic values only.
SEARCH_KEY = bytes(range(31, -1, -1))
FIELD = b"revamp/field-email/tenant-fixture/"
RESULTS = Path(__file__).with_name("results")


class UnsupportedProtectedOperation(ValueError):
    pass


class PreparedText(str):
    """The ordinary string remains visible to application code."""
    def __new__(cls, value, identity):
        obj = super().__new__(cls, value)
        obj.identity = identity
        return obj


def token(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise UnsupportedProtectedOperation("Exact text required")
    return hmac.digest(SEARCH_KEY, FIELD + str(value).encode(), "sha256")


def protect(identity, value, field=FIELD):
    term = token(value)
    nonce = os.urandom(12)
    header = term + nonce
    aad = field + struct.pack(">q", identity) + header
    return header + AESGCMSIV(KEY).encrypt(nonce, str(value).encode(), aad)


def reveal(identity, frame, field=FIELD):
    if len(frame) < 60:
        raise UnsupportedProtectedOperation("Malformed protected frame")
    header = frame[:44]
    value = AESGCMSIV(KEY).decrypt(
        frame[32:44], frame[44:], field + struct.pack(">q", identity) + header,
    ).decode()
    if not hmac.compare_digest(frame[:32], token(value)):
        raise UnsupportedProtectedOperation("Search representation mismatch")
    return value


class ContextualRead(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, field=FIELD):
        self.field = field
        super().__init__()

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "postgresql":
            return reveal(struct.unpack(">q", value[:8])[0], value[8:], self.field)
        identity, encoded = value.split(":", 1)
        return reveal(int(identity), bytes.fromhex(encoded), self.field)


class ProtectedText(TypeDecorator):
    impl = LargeBinary
    cache_ok = False

    def __init__(self, field=FIELD):
        self.field = field
        super().__init__()

    class comparator_factory(TypeDecorator.Comparator):
        def operate(self, op, *other, **kw):
            if op in (operators.is_, operators.is_not):
                if other != (None,):
                    raise UnsupportedProtectedOperation("Only NULL presence is supported")
                return op(type_coerce(self.expr, LargeBinary), None)
            eq_expr = func.substr(type_coerce(self.expr, LargeBinary), 1, 32)
            if op in (operators.eq, operators.ne):
                value = other[0]
                if value is None:
                    return self.operate(operators.is_ if op == operators.eq else operators.is_not, None)
                if hasattr(value, "__clause_element__"):
                    return op(eq_expr, func.substr(type_coerce(value, LargeBinary), 1, 32))
                return op(eq_expr, token(value))
            if op in (operators.in_op, operators.not_in_op):
                return op(eq_expr, [token(v) for v in other[0]])
            raise UnsupportedProtectedOperation("Query capability is unavailable")

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, PreparedText):
            raise UnsupportedProtectedOperation("A protected ORM write needs row context")
        return protect(value.identity, value, self.field)

    def column_expression(self, colexpr):
        # Only public expression APIs. Aliases must retain the companion identity.
        identity = colexpr.table.c.id
        if getattr(self, "pg", False):
            read = func.int8send(identity).op("||")(type_coerce(colexpr, LargeBinary))
        else:
            read = cast(identity, String) + ":" + func.hex(type_coerce(colexpr, LargeBinary))
        return type_coerce(case((type_coerce(colexpr, LargeBinary).is_(None), None), else_=read), ContextualRead(self.field))


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "account"
    id = Column(BigInteger, primary_key=True)
    email = Column(String)


class User(Base):
    __tablename__ = "user"
    id = Column(BigInteger, primary_key=True)
    email = Column(String)
    name = Column(String)


def attach(engine):
    """Local candidate: replace type before any statement compilation or instance."""
    for model in (User, Account):
        field = FIELD + (b"logical-user-email" if model is User else b"logical-account-email")
        model.__table__.c.email.type = ProtectedText(field)

    @event.listens_for(Session, "before_flush")
    def prepare(session, flush_context, instances):
        for obj in session.new | session.dirty:
            if not isinstance(obj, (User, Account)):
                continue
            state = inspect(obj)
            if state.persistent and state.attrs.id.history.has_changes():
                raise UnsupportedProtectedOperation("Record identity must remain stable")
            if state.persistent and not state.attrs.email.history.has_changes():
                continue
            value = obj.email
            if value is not None:
                if obj.id is None:
                    raise UnsupportedProtectedOperation("Identity preparation is required")
                obj.email = PreparedText(value, obj.id)

    @event.listens_for(Session, "do_orm_execute")
    def validate(state):
        stmt = state.statement
        if isinstance(stmt, TextClause) or state.is_update or state.is_insert:
            raise UnsupportedProtectedOperation("Use the protected instance write path")
        for node in visitors.iterate(stmt):
            if getattr(node, "__visit_name__", None) == "function" and node.name in ("lower", "upper", "sum", "avg", "min", "max"):
                if any(isinstance(n.type, ProtectedText) for n in visitors.iterate(node) if hasattr(n, "type")):
                    raise UnsupportedProtectedOperation("Protected function is unavailable")
        if isinstance(stmt, Select):
            allowed_projection = []
            for description in stmt.column_descriptions:
                expression = description["expr"]
                if isinstance(expression, type):
                    continue
                allowed_projection.append(expression.__clause_element__() if hasattr(expression, "__clause_element__") else expression)
            where_nodes = list(visitors.iterate(stmt.whereclause)) if stmt.whereclause is not None else []
            relation_nodes = [n for relation in stmt.get_final_froms() for n in visitors.iterate(relation)]
            for child in stmt.get_children():
                if isinstance(child, FromClause) or any(child is n for n in where_nodes + relation_nodes):
                    continue
                match = next((i for i, selected in enumerate(allowed_projection) if child.compare(selected)), None)
                if match is not None:
                    allowed_projection.pop(match)
                    continue
                if any(isinstance(n.type, ProtectedText) for n in visitors.iterate(child) if hasattr(n, "type")):
                    raise UnsupportedProtectedOperation("Protected clause is unavailable")
            compiler = engine.dialect.statement_compiler(engine.dialect, stmt)
            # Public compiler rendering exposes DISTINCT without private Select flags.
            if compiler.get_select_precolumns(stmt) and any(isinstance(c.type, ProtectedText) for c in stmt.selected_columns):
                raise UnsupportedProtectedOperation("Protected DISTINCT needs explicit token projection")


def main():
    engine = create_engine("sqlite://", hide_parameters=True)
    attach(engine)
    Base.metadata.create_all(engine)
    observed = []

    @event.listens_for(engine, "before_cursor_execute")
    def observe(conn, cursor, statement, parameters, context, many):
        observed.append((statement, parameters))

    outcomes = {}
    def check(name, fn):
        fn()
        outcomes[name] = "PASS"

    with Session(engine) as session:
        session.add_all([User(id=1, email="alice@example.test", name="Alice"), User(id=2, email=None, name="Null"), Account(id=10, email="alice@example.test"), Account(id=1, email="account-only@example.test")])
        session.commit()
        check("instance_write_plaintext_absent", lambda: assert_true(all("alice@example.test" not in repr(p) for _, p in observed)))
        check("normal_read_and_expiry", lambda: assert_true(session.get(User, 1).email == "alice@example.test"))
        check("same_id_distinct_field_read", lambda: assert_true(session.get(Account, 1).email == "account-only@example.test"))
        check("scalar_projection_context", lambda: assert_true(session.scalar(select(User.email).where(User.id == 1)) == "alice@example.test"))
        check("equal", lambda: assert_true([u.id for u in session.scalars(select(User).where(User.email == "alice@example.test"))] == [1]))
        check("membership", lambda: assert_true([u.id for u in session.scalars(select(User).where(User.email.in_([None, "alice@example.test"]))) ] == [1]))
        check("empty_membership", lambda: assert_true(list(session.scalars(select(User).where(User.email.in_([])))) == []))
        check("null", lambda: assert_true([u.id for u in session.scalars(select(User).where(User.email == None))] == [2]))
        check("negative_null_semantics", lambda: assert_true(list(session.scalars(select(User).where(User.email.not_in([None, "absent"])))) == []))
        check("shared_domain_join", lambda: assert_true(session.execute(select(User.id, Account.id).join(Account, User.email == Account.email)).all() == [(1, 10)]))
        user = session.get(User, 1)
        user.email = "changed@example.test"
        with session.no_autoflush:
            check("dirty_entity_native_history", lambda: assert_true(session.get(User, 1).email == "changed@example.test"))
            check("dirty_scalar_stored_value", lambda: assert_true(session.scalar(select(User.email).where(User.id == 1)) == "alice@example.test"))
        session.refresh(user)
        check("refresh_discards_pending", lambda: assert_true(user.email == "alice@example.test"))
        user.email = "autoflush@example.test"
        check("native_autoflush", lambda: assert_true(session.scalar(select(User.email).where(User.id == 1)) == "autoflush@example.test"))
        session.rollback()
        check("rollback_and_expiry", lambda: assert_true(user.email == "alice@example.test"))
        detached = User(id=1, email="merged@example.test", name="Alice")
        merged = session.merge(detached)
        session.commit()
        check("native_merge", lambda: assert_true(merged.email == "merged@example.test"))
        for name, fn in {
            "unsupported_range": lambda: User.email > "a",
            "unsupported_prefix": lambda: User.email.startswith("a"),
            "unsupported_bulk": lambda: session.execute(update(User).values(email="raw@example.test")),
            "unsupported_text": lambda: session.execute(text("SELECT email FROM user")),
            "unsupported_sort": lambda: session.execute(select(User).order_by(User.email)),
            "unsupported_function": lambda: session.execute(select(func.lower(User.email))),
            "unsupported_distinct": lambda: session.execute(select(User.email).distinct()),
            "unsupported_grouping": lambda: session.execute(select(User.email).group_by(User.email)),
        }.items():
            try:
                fn()
            except UnsupportedProtectedOperation:
                outcomes[name] = "PASS"
            else:
                raise AssertionError(name)
    with engine.connect() as conn:
        raw = conn.exec_driver_sql('SELECT email FROM user WHERE id=1').scalar()
        assert isinstance(raw, bytes)
        tampered = raw[:-1] + bytes([raw[-1] ^ 1])
        for name, identity, frame in (("tamper_rejected", 1, tampered), ("relocation_rejected", 9, raw)):
            try:
                reveal(identity, frame, User.__table__.c.email.type.field)
            except InvalidTag:
                outcomes[name] = "PASS"
            else:
                raise AssertionError(name)
        try:
            conn.execute(User.__table__.insert().values(id=20, email="bypass@example.test"))
        except StatementError as exc:
            assert isinstance(exc.orig, UnsupportedProtectedOperation)
            outcomes["typed_core_plaintext_bind_rejected"] = "PASS"
        else:
            raise AssertionError("Core bypass")
        conn.exec_driver_sql('UPDATE account SET email=? WHERE id=1', (raw,))
        try:
            with Session(conn) as probe:
                probe.scalar(select(Account.email).where(Account.id == 1))
        except InvalidTag:
            outcomes["same_id_cross_field_transplant_rejected"] = "PASS"
        else:
            raise AssertionError("Cross-field transplant accepted")
        # Deliberate negative control: a raw driver can store arbitrary bytes.
        conn.exec_driver_sql('INSERT INTO user(id,email,name) VALUES (30,?,?)', (b"plaintext-bypass", "Bypass"))
        outcomes["raw_driver_bypass"] = "FAIL_REQUIRES_SCHEMA_AND_ROLE_GUARDS"
        conn.rollback()
    User.__table__.c.email.type.pg = True
    pg_sql = str(select(User.email).where(User.email == "probe").compile(dialect=postgresql.dialect()))
    assert "int8send" in pg_sql and "substr" in pg_sql
    RESULTS.mkdir(exist_ok=True)
    result = {"cell": "SQLite/public SQLAlchemy hooks only", "outcomes": outcomes,
              "postgresql_sql": pg_sql, "live_postgres": "BLOCKED_SOCKET_SANDBOX",
              "limits": ["One synthetic tenant and text codec", "No async, concurrent uniqueness or provider calls", "Public clause rejection grammar needs complete differential tests", "PreparedText changes the exact Python type", "No universal driver interception"]}
    (RESULTS / "adapter.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": sum(x == "PASS" for x in outcomes.values()), "negative_control": outcomes["raw_driver_bypass"]}))


def assert_true(condition):
    assert condition


if __name__ == "__main__":
    main()
