"""An ordinary application fixture with no Cryptalis attachment or protected types."""
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

import psycopg
from sqlalchemy import (
    DateTime, ForeignKey, Identity, Integer, MetaData, Numeric, String,
    UniqueConstraint, create_engine, func, inspect, insert, select, text, update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, selectinload
from sqlalchemy.pool import NullPool
from sqlalchemy.schema import CreateSchema, DropSchema

import probe_service

RESULTS = Path(__file__).with_name("results")
APP_SCHEMA = "revamp_plain_app"


class Base(DeclarativeBase):
    metadata = MetaData(schema=APP_SCHEMA)


class Account(Base):
    __tablename__ = "account"
    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    customers: Mapped[list["Customer"]] = relationship(back_populates="account", cascade="all, delete-orphan")


class Customer(Base):
    __tablename__ = "customer"
    __table_args__ = (UniqueConstraint("account_id", "email"),)
    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey(Account.id))
    email: Mapped[str | None] = mapped_column(String)
    display_name: Mapped[str] = mapped_column(String)
    age: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    account: Mapped[Account] = relationship(back_populates="customers")
    invoices: Mapped[list["Invoice"]] = relationship(back_populates="customer", cascade="all, delete-orphan")


class Invoice(Base):
    __tablename__ = "invoice"
    id: Mapped[int] = mapped_column(Integer, Identity(), primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey(Customer.id))
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    customer: Mapped[Customer] = relationship(back_populates="invoices")


def active_customers(account_id):
    return select(Customer).where(Customer.account_id == account_id, Customer.deleted_at.is_(None))


def lookup_email(account_id, email):
    return active_customers(account_id).where(Customer.email == email)


def lookup_emails(account_id, emails):
    return active_customers(account_id).where(Customer.email.in_(emails)).order_by(Customer.id)


def browse_customers(account_id, minimum_age, prefix, offset=0, limit=2):
    return active_customers(account_id).where(
        Customer.age >= minimum_age, Customer.display_name.startswith(prefix, autoescape=True),
    ).order_by(Customer.age, Customer.id).offset(offset).limit(limit)


def invoice_export(account_id):
    return select(Customer.email, Invoice.amount).join(Invoice.customer).where(
        Customer.account_id == account_id, Customer.deleted_at.is_(None),
    ).order_by(Invoice.id)


def names(session, statement):
    return [customer.display_name for customer in session.scalars(statement)]


def exercise(engine, outcomes):
    Base.metadata.create_all(engine)

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        outcomes[name] = "PASS"

    with Session(engine) as session:
        alpha, beta = Account(name="alpha"), Account(name="beta")
        session.add_all([alpha, beta])
        session.flush()
        alpha_id, beta_id = alpha.id, beta.id
        alpha.customers = [
            Customer(email="alice@example.test", display_name="Deb", age=19),
            Customer(email="bob@example.test", display_name="Debrato", age=30),
            Customer(email=None, display_name="Null", age=None),
            Customer(email=None, display_name="a%b", age=40),
            Customer(email="gone@example.test", display_name="Gone", age=45, deleted_at=datetime.now(timezone.utc)),
        ]
        beta.customers = [Customer(email="alice@example.test", display_name="Other", age=30)]
        alice = alpha.customers[0]
        alice.invoices = [Invoice(amount=Decimal("12.50")), Invoice(amount=Decimal("7.25"))]
        alpha.customers[1].invoices = [Invoice(amount=Decimal("20.00"))]
        session.commit()
        customer_id = alice.id
        check("generated_identity_and_default", type(customer_id) is int and alice.created_at is not None)
        check("equality_and_tenant_scope", names(session, lookup_email(alpha_id, "alice@example.test")) == ["Deb"])
        check("membership", names(session, lookup_emails(alpha_id, ["bob@example.test", "alice@example.test"])) == ["Deb", "Debrato"])
        check("empty_membership", names(session, lookup_emails(alpha_id, [])) == [])
        check("mixed_null_membership", names(session, lookup_emails(alpha_id, [None, "alice@example.test"])) == ["Deb"])
        check("null_presence", names(session, active_customers(alpha_id).where(Customer.email.is_(None)).order_by(Customer.id)) == ["Null", "a%b"])
        check("not_in_null_unknown", names(session, active_customers(alpha_id).where(Customer.email.not_in([None, "alice@example.test"]))) == [])
        check("soft_delete_scope", names(session, lookup_email(alpha_id, "gone@example.test")) == [])
        check("range_prefix_order_page", names(session, browse_customers(alpha_id, 18, "Deb", 1, 1)) == ["Debrato"])
        check("literal_wildcard_prefix", names(session, browse_customers(alpha_id, 18, "a%", 0, 5)) == ["a%b"])
        check("bounded_range", names(session, active_customers(alpha_id).where(Customer.age.between(18, 20))) == ["Deb"])
        check("null_order", names(session, active_customers(alpha_id).order_by(Customer.age.asc().nulls_last(), Customer.id)) == ["Deb", "Debrato", "a%b", "Null"])
        check("join_and_decimal", session.execute(invoice_export(alpha_id)).all() == [
            ("alice@example.test", Decimal("12.50")), ("alice@example.test", Decimal("7.25")), ("bob@example.test", Decimal("20.00")),
        ])
        loaded = session.scalars(active_customers(alpha_id).options(selectinload(Customer.invoices)).order_by(Customer.id)).all()
        check("relationship_loading", [len(customer.invoices) for customer in loaded] == [2, 1, 0, 0])
        check("native_aggregates", session.execute(select(func.count(Customer.email), func.count(func.distinct(Customer.email))).where(Customer.account_id == alpha_id)).one() == (3, 3))
        check("decimal_sum", session.scalar(select(func.sum(Invoice.amount))) == Decimal("39.75"))
        with session.begin_nested():
            session.add(Customer(account_id=beta_id, email="new@example.test", display_name="Beta", age=22))
            session.flush()
        check("cross_tenant_duplicate_allowed", names(session, lookup_email(beta_id, "alice@example.test")) == ["Other"])
        try:
            with session.begin_nested():
                session.add(Customer(account_id=alpha_id, email="alice@example.test", display_name="Duplicate", age=1))
                session.flush()
        except IntegrityError:
            outcomes["scoped_uniqueness"] = "PASS"
        else:
            raise AssertionError("scoped_uniqueness")
        customer = session.get(Customer, customer_id)
        check("exact_python_type", type(customer.email) is str)
        customer.email = "edited@example.test"
        check("autoflush", session.scalar(lookup_email(alpha_id, "edited@example.test")) is customer)
        check("native_history", not inspect(customer).attrs.email.history.has_changes())
        session.rollback()
        check("rollback_expiry", customer.email == "alice@example.test")
        customer.email = "discarded@example.test"
        session.refresh(customer)
        check("refresh", customer.email == "alice@example.test")
        session.expunge(customer)
        customer.email = "merged@example.test"
        merged = session.merge(customer)
        session.commit()
        check("merge", merged.email == "merged@example.test")
        session.execute(insert(Customer), [dict(account_id=beta_id, email="bulk@example.test", display_name="Bulk", age=50)])
        check("bulk_insert", names(session, lookup_email(beta_id, "bulk@example.test")) == ["Bulk"])
        session.execute(update(Customer).where(Customer.email == "bulk@example.test").values(display_name="Bulk updated"))
        session.commit()
        check("bulk_update", names(session, lookup_email(beta_id, "bulk@example.test")) == ["Bulk updated"])
    with engine.begin() as connection:
        schema = engine.get_execution_options()["schema_translate_map"][APP_SCHEMA]
        qualified = "customer" if schema is None else '"' + schema + '".customer'
        connection.execute(text("UPDATE " + qualified + " SET display_name=:value WHERE id=:identity"), {"value": "Raw edited", "identity": customer_id})
    with Session(engine) as background:
        check("raw_writer", background.get(Customer, customer_id).display_name == "Raw edited")
        background.get(Customer, customer_id).display_name = "Background edited"
        background.commit()
    with Session(engine) as session:
        check("background_session", session.get(Customer, customer_id).display_name == "Background edited")
        customer = session.get(Customer, customer_id)
        invoice_ids = [invoice.id for invoice in customer.invoices]
        session.delete(customer)
        session.commit()
        check("delete_cascade", session.get(Customer, customer_id) is None and not session.scalars(select(Invoice.id).where(Invoice.id.in_(invoice_ids))).all())
    return outcomes


def main():
    RESULTS.mkdir(exist_ok=True)
    offline = sys.argv[1:] == ["--sqlite-baseline-only"]
    if sys.argv[1:] and not offline:
        raise SystemExit("Use --sqlite-baseline-only or no arguments for the authorized service")
    result = {"status": "UNKNOWN", "protected_retrofit": "NOT_IMPLEMENTED", "async_copy_concurrency": "NOT_TESTED",
              "adoption_change_counts": "UNKNOWN", "connection_url": "NEVER_RECORDED"}
    outcomes = {}
    result["outcomes"] = outcomes
    result["source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    receipt = RESULTS / ("plain-app-sqlite.json" if offline else "plain-app-service.json")
    if not offline:
        try:
            probe_service.main()
        except SystemExit as stopped:
            if stopped.code != 0:
                result.update({"stage": "authorized_service_probe", "mutations": "NONE"})
                receipt.write_text(json.dumps(result, indent=2) + "\n")
                raise
    schema = None if offline else "revamp_plain_app_" + uuid.uuid4().hex
    engine = None
    schema_created = False
    try:
        if offline:
            engine = create_engine("sqlite://", hide_parameters=True)
        else:
            def connect():
                connection = psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], **probe_service.EXPECTED,
                                             hostaddr=probe_service.EXPECTED["host"], connect_timeout=3)
                try:
                    row = connection.execute("SELECT current_database(),current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
                    if row[:2] != (probe_service.EXPECTED["dbname"], probe_service.EXPECTED["user"]) or any(row[2:]):
                        raise ValueError("RESTRICTED_ROLE_REQUIRED")
                    connection.commit()
                    return connection
                except Exception:
                    connection.close()
                    raise
            engine = create_engine("postgresql+psycopg://", creator=connect, hide_parameters=True, poolclass=NullPool)
            with engine.begin() as connection:
                connection.execute(CreateSchema(schema))
            schema_created = True
        engine = engine.execution_options(schema_translate_map={APP_SCHEMA: schema})
        exercise(engine, outcomes)
        result.update({"status": "PASS_PLAINTEXT_BASELINE_ONLY", "cell": "SQLite" if offline else "authorized PostgreSQL service",
                       "outcomes": outcomes, "schema": schema, "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "limits": ["No attachment or protected application comparison", "SQLite does not qualify PostgreSQL semantics"] if offline else ["No protected retrofit", "No async/COPY/concurrent-writer baseline"]})
    except Exception as failure:
        result.update({"status": "FAIL", "exception_type": type(failure).__name__, "details": "WITHHELD"})
        if isinstance(failure, AssertionError) and len(failure.args) == 1 and re.fullmatch(r"[a-z_]+", str(failure.args[0])):
            result["failed_check"] = failure.args[0]
    finally:
        if engine is not None:
            if schema_created:
                try:
                    with engine.begin() as connection:
                        connection.execute(DropSchema(schema, cascade=True))
                    result["cleanup"] = "OWN_SCHEMA_DROPPED"
                except Exception as failure:
                    result.update({"status": "FAIL", "cleanup": "FAILED", "cleanup_exception_type": type(failure).__name__, "schema": schema})
            engine.dispose()
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "passed": len(result.get("outcomes", {}))}))
    raise SystemExit(0 if result["status"] == "PASS_PLAINTEXT_BASELINE_ONLY" else 1)


if __name__ == "__main__":
    main()
