"""SQLite parameter-preparation alternative. It is not a complete adapter."""
import json
from pathlib import Path

from sqlalchemy import BigInteger, Column, String, create_engine, event, inspect, select
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BinaryExpression, BindParameter

from run_adapter import ProtectedText, UnsupportedProtectedOperation, protect


class PreparedFrame(bytes):
    pass


class NativeText(ProtectedText):
    cache_ok = False

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, PreparedFrame):
            raise UnsupportedProtectedOperation("Prepared row parameters required")
        return bytes(value)


class Base(DeclarativeBase):
    pass


class Contact(Base):
    __tablename__ = "contact"
    id = Column(BigInteger, primary_key=True)
    email = Column(String)
    name = Column(String)


def main():
    engine = create_engine("sqlite://", hide_parameters=True)
    Contact.__table__.c.email.type = NativeText()
    Base.metadata.create_all(engine)
    outcomes = {}
    observed = []

    def check(name, value):
        assert value, name
        outcomes[name] = "PASS"

    @event.listens_for(Session, "before_flush")
    def prepare(session, context, instances):
        connection = session.connection()
        session.info["revamp_connections"] = [connection]
        prepared = {}
        for obj in session.new | session.dirty:
            if not isinstance(obj, Contact):
                continue
            state = inspect(obj)
            if state.persistent and state.attrs.id.history.has_changes():
                raise UnsupportedProtectedOperation("Stable record identity required")
            if state.persistent and not state.attrs.email.history.has_changes():
                continue
            if obj.id is None:
                raise UnsupportedProtectedOperation("Prepared identity required")
            if obj.email is not None and type(obj.email) is not str:
                raise UnsupportedProtectedOperation("Original exact text type required")
            prepared[obj.id] = (obj.email, None if obj.email is None else PreparedFrame(protect(obj.id, obj.email)))
        connection.info["revamp_rows"] = prepared

    def clear(session, *args):
        for connection in session.info.pop("revamp_connections", []):
            if not connection.closed:
                connection.info.pop("revamp_rows", None)

    event.listen(Session, "after_flush_postexec", clear)
    event.listen(Session, "after_soft_rollback", clear)

    @event.listens_for(engine, "before_execute", retval=True)
    def bind_rows(connection, statement, multiparams, params, options):
        if not (getattr(statement, "is_insert", False) or getattr(statement, "is_update", False)):
            return statement, multiparams, params
        if getattr(statement, "table", None) is not Contact.__table__:
            return statement, multiparams, params
        prepared = connection.info.get("revamp_rows", {})
        if not prepared:
            raise UnsupportedProtectedOperation("Only the prepared instance path is admitted")
        rows = list(multiparams) if multiparams else [params]
        changed = []
        for parameters in rows:
            row = dict(parameters)
            identity = row.get("id")
            if identity is None and getattr(statement, "is_update", False):
                for node in visitors.iterate(statement.whereclause):
                    if isinstance(node, BinaryExpression) and node.left.compare(Contact.__table__.c.id) and isinstance(node.right, BindParameter):
                        identity = row.get(node.right.key)
            if identity not in prepared:
                raise UnsupportedProtectedOperation("Row context is unavailable")
            if "email" in row:
                original, sealed = prepared[identity]
                if row["email"] != original:
                    raise UnsupportedProtectedOperation("Prepared row changed")
                row["email"] = sealed
            changed.append(row)
        return (statement, changed, {}) if multiparams else (statement, [], changed[0])

    @event.listens_for(engine, "before_cursor_execute")
    def observe(connection, cursor, statement, parameters, context, many):
        observed.append(repr(parameters))

    with Session(engine) as session:
        alice = Contact(id=1, email="same@example.test", name="Alice")
        bob = Contact(id=2, email="same@example.test", name="Bob")
        session.add_all([alice, bob, Contact(id=3, email=None, name="Null")])
        session.flush()
        check("exact_type_after_flush", type(alice.email) is str and type(bob.email) is str)
        check("history_after_flush", not inspect(alice).attrs.email.history.has_changes())
        check("duplicate_values_distinct_row_context", session.scalars(select(Contact.email).order_by(Contact.id)).all() == ["same@example.test", "same@example.test", None])
        check("prepared_context_cleared", "revamp_rows" not in session.connection().info)
        check("no_plaintext_wire_bind", all("same@example.test" not in entry for entry in observed))
        alice.email = "changed@example.test"
        session.flush()
        check("exact_type_after_update", type(alice.email) is str)
        check("updated_scalar", session.scalar(select(Contact.email).where(Contact.id == 1)) == "changed@example.test")
        session.commit()
        alice.email = "rollback@example.test"
        session.flush()
        session.rollback()
        check("rollback_native_value", alice.email == "changed@example.test" and type(alice.email) is str)
        session.refresh(alice)
        check("refresh_native_value", type(alice.email) is str)
        session.expire(alice)
        check("expiry_native_value", alice.email == "changed@example.test" and type(alice.email) is str)
        merged = session.merge(Contact(id=1, email="merged@example.test", name="Alice"))
        session.flush()
        check("merge_native_value", type(merged.email) is str and session.scalar(select(Contact.email).where(Contact.id == 1)) == "merged@example.test")
        bob.email = "autoflush@example.test"
        check("autoflush_native_value", session.scalar(select(Contact.email).where(Contact.id == 2)) == "autoflush@example.test" and type(bob.email) is str)
        session.rollback()
    with engine.connect() as connection:
        try:
            connection.execute(Contact.__table__.insert(), {"id": 9, "email": "raw@example.test"})
        except UnsupportedProtectedOperation:
            outcomes["unprepared_core_rejected"] = "PASS"
        else:
            raise AssertionError("Unprepared Core write accepted")
    result = {"cell": "SQLite public before_flush/before_execute parameter alternative", "outcomes": outcomes,
              "ordinary_python_type_preserved": True,
              "limits": ["Not a complete clause/raw/COPY guard", "No PG driver or async evidence", "Explicit bigint IDs and one field/tenant only", "Generated identities, multi-table flushes, cascades and parameter shapes unqualified", "Reuses the old lab frame, not CF1"]}
    Path(__file__).with_name("results").joinpath("native-types.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps({"passed": len(outcomes), "type": "str"}))


if __name__ == "__main__":
    main()
