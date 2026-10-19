"""An ordinary accounts/customers/notes application.

This module imports no Cryptalis component. A host may create the schema,
seed it, attach a protective engine, or leave the application alone.
Protected deployment is a host decision; application code stays unchanged.
"""
import argparse
import json
import os
import sys
from uuid import UUID

import psycopg
from sqlalchemy import ForeignKey, Index, MetaData, Text, Uuid, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

if os.environ.get('CRYPTALIS_FORBIDDEN'):
    class BlockCryptalis:
        def find_spec(self, name, path=None, target=None):
            if name == 'cryptalis' or name.startswith('cryptalis.'):
                raise RuntimeError('Cryptalis import is forbidden in this process')

    sys.meta_path.insert(0, BlockCryptalis())

SCHEMA = os.environ.get('APP_SCHEMA', 'independent_app')


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA)


class Account(Base):
    __tablename__ = 'account'
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, autoincrement=False)
    tenant_id: Mapped[UUID] = mapped_column(Uuid)
    display_name: Mapped[str] = mapped_column(Text(collation='C'))
    customers: Mapped[list['Customer']] = relationship(back_populates='account')


class Customer(Base):
    __tablename__ = 'customer'
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, autoincrement=False)
    tenant_id: Mapped[UUID] = mapped_column(Uuid)
    account_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('account.id', name='customer_account_fk'))
    name: Mapped[str] = mapped_column(Text(collation='C'))
    note: Mapped[str | None] = mapped_column(Text)
    account: Mapped[Account] = relationship(back_populates='customers')
    __table_args__ = (Index('customer_name_unique', 'tenant_id', 'name', unique=True),)


class Note(Base):
    __tablename__ = 'note'
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, autoincrement=False)
    tenant_id: Mapped[UUID] = mapped_column(Uuid)
    account_id: Mapped[UUID] = mapped_column(Uuid, ForeignKey('account.id', name='note_account_fk'))
    body: Mapped[str | None] = mapped_column(Text(collation='C'))


def engine(url):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
                         creator=lambda: psycopg.connect(url))


def simple_sessions(engine):
    return lambda tenant_id=None: Session(engine)


def init(engine):
    Base.metadata.create_all(engine)


def seed(sessions, tenants):
    for tenant, data in tenants.items():
        with sessions(tenant_id=UUID(tenant)) as session:
            session.add_all(Account(tenant_id=UUID(tenant), **row) for row in data.get('accounts', ()))
            session.flush()
            session.add_all(Customer(tenant_id=UUID(tenant), **row) for row in data.get('customers', ()))
            session.add_all(Note(tenant_id=UUID(tenant), **row) for row in data.get('notes', ()))
            session.commit()


def read(sessions, tenant):
    with sessions(tenant_id=UUID(tenant)) as session:
        return {str(row.id): {'name': row.name, 'note': row.note, 'account': str(row.account_id)}
                for row in session.scalars(select(Customer).where(Customer.tenant_id == UUID(tenant)))}


def read_accounts(sessions, tenant):
    with sessions(tenant_id=UUID(tenant)) as session:
        return {str(row.id): row.display_name for row in session.scalars(
            select(Account).where(Account.tenant_id == UUID(tenant)))}


def read_notes(sessions, tenant):
    with sessions(tenant_id=UUID(tenant)) as session:
        return {str(row.id): row.body for row in session.scalars(
            select(Note).where(Note.tenant_id == UUID(tenant)))}


def search(sessions, tenant, name):
    with sessions(tenant_id=UUID(tenant)) as session:
        return sorted(str(row.id) for row in session.scalars(
            select(Customer).where(Customer.tenant_id == UUID(tenant), Customer.name == name)))


def edit_customer(sessions, tenant, customer_id, name):
    with sessions(tenant_id=UUID(tenant)) as session:
        session.get(Customer, UUID(customer_id)).name = name
        session.commit()


def edit_account(sessions, tenant, account_id, display_name):
    with sessions(tenant_id=UUID(tenant)) as session:
        session.get(Account, UUID(account_id)).display_name = display_name
        session.commit()


def add_customer(sessions, tenant, customer_id, account_id, name, note=None):
    with sessions(tenant_id=UUID(tenant)) as session:
        session.add(Customer(id=UUID(customer_id), tenant_id=UUID(tenant),
                             account_id=UUID(account_id), name=name, note=note))
        session.commit()


def add_note(sessions, tenant, note_id, account_id, body=None):
    with sessions(tenant_id=UUID(tenant)) as session:
        session.add(Note(id=UUID(note_id), tenant_id=UUID(tenant),
                         account_id=UUID(account_id), body=body))
        session.commit()


def delete_customer(sessions, tenant, customer_id):
    with sessions(tenant_id=UUID(tenant)) as session:
        session.delete(session.get(Customer, UUID(customer_id)))
        session.commit()


COMMANDS = {'read': read, 'read_accounts': read_accounts, 'read_notes': read_notes,
            'search': search, 'edit_customer': edit_customer, 'edit_account': edit_account,
            'add_customer': add_customer, 'add_note': add_note, 'delete_customer': delete_customer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'crud') + tuple(COMMANDS))
    parser.add_argument('payload', nargs='?')
    args = parser.parse_args()
    application = engine(os.environ['APP_DATABASE_URL'])
    sessions = simple_sessions(application)
    if args.command == 'init':
        init(application)
        print(json.dumps({'ok': True}))
        return 0
    if args.command == 'crud':
        script = json.loads(args.payload)
        tenant = script['tenant']
        for operation in script['ops']:
            arguments = dict(operation)
            COMMANDS[arguments.pop('function')](sessions, tenant=tenant, **arguments)
        print(json.dumps({'customers': read(sessions, tenant), 'notes': read_notes(sessions, tenant),
                          'accounts': read_accounts(sessions, tenant)}, sort_keys=True))
        return 0
    print(json.dumps(COMMANDS[args.command](sessions, **json.loads(args.payload)), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
