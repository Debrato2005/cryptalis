"""Protect a table in an existing application, then remove Cryptalis again.

This runs the whole lifecycle on a disposable PostgreSQL 16 database. Every step
runs in its own process, as a deployment would, because workers restart after a
lifecycle change. Run it after creating three roles and one empty database:

    CREATE ROLE shop_owner  LOGIN PASSWORD '...';  -- owns the schema, runs migrations
    CREATE ROLE shop_app    LOGIN PASSWORD '...';  -- the application while protected
    CREATE ROLE shop_native LOGIN PASSWORD '...';  -- the application after removal
    CREATE DATABASE shop OWNER shop_owner;

    export QUICKSTART_OWNER_URL=postgresql+psycopg://shop_owner:...@localhost/shop
    export QUICKSTART_APP_URL=postgresql+psycopg://shop_app:...@localhost/shop
    export QUICKSTART_NATIVE_URL=postgresql+psycopg://shop_native:...@localhost/shop
    python quickstart.py ./quickstart-state

DevelopmentKeyProvider is for synthetic data. A real deployment passes an external
KeyProvider such as OpenBao or a cloud KMS; nothing else below changes.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import String, create_engine, make_url, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

OWNER_URL = os.environ['QUICKSTART_OWNER_URL']
APP_URL = os.environ['QUICKSTART_APP_URL']
NATIVE_URL = os.environ['QUICKSTART_NATIVE_URL']
ADA = UUID('00000000-0000-0000-0000-00000000000a')
WRITERS_STOPPED = 'This script is the only writer and runs one step at a time.'


# The application's ordinary model. Protecting it changes nothing here.
class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = 'quickstart_customers'
    id: Mapped[UUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    note: Mapped[str | None]


MANIFEST = json.dumps({
    'schema': 'cryptalis.protection/v1',
    'profile': 'cf1',
    'domain_id': '10000000-0000-0000-0000-000000000001',
    'models': [{
        'model': 'Customer',
        'table_id': '20000000-0000-0000-0000-000000000001',
        'tenancy': {'single_tenant': True},
        'fields': [
            # Searchable: a database dump reveals which rows share an email.
            {'name': 'email', 'field_id': '30000000-0000-0000-0000-000000000001', 'protect': True,
             'queries': ['unique'], 'accept_leakage': ['equality', 'unique']},
            # Storage-only: no search, nothing revealed except length and NULL.
            {'name': 'note', 'field_id': '30000000-0000-0000-0000-000000000002', 'protect': True,
             'queries': [], 'accept_leakage': []},
        ],
    }],
}).encode()


def owner_engine():
    return create_engine(OWNER_URL)


def app_engine():
    # Attachment refuses an engine that could log protected parameters.
    return create_engine(APP_URL, hide_parameters=True)


def project(state, key_file='key'):
    from cryptalis import Project
    from cryptalis.crypto import DevelopmentKeyProvider
    return Project(MANIFEST, Base.registry, provider=DevelopmentKeyProvider(state / key_file), state_dir=state / 'cryptalis')


def native_application(state):
    """Existing data in an existing application, before Cryptalis."""
    owner = owner_engine()
    Base.metadata.create_all(owner)
    with owner.begin() as connection:
        for url in (APP_URL, NATIVE_URL):
            role = make_url(url).username
            connection.execute(text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {Customer.__table__.name} TO "{role}"'))
    with Session(owner) as session:
        session.add(Customer(id=ADA, email='ada@example.com', note='first customer'))
        session.commit()
    print('Native application wrote one customer.')


def protect(state):
    """Check compatibility, then encrypt existing rows. Writers are stopped."""
    owner = owner_engine()
    print('Doctor found', project(state).doctor(owner)['issues'] or 'no issues.')
    progress = project(state).protect(owner, runtime_role=make_url(APP_URL).username, writers_stopped=WRITERS_STOPPED,
                                      search_reviewed='Emails are not enumerable.')
    print(f'Protected {progress.committed_rows} row: {progress.phase}.')


def application(state):
    """The same model and queries, through project.attach."""
    from sqlalchemy.exc import IntegrityError
    from cryptalis.sqlalchemy import UnsupportedProtectedOperation
    sessions = project(state).attach(app_engine())
    with sessions() as session:
        session.add(Customer(id=uuid4(), email=f'{uuid4()}@example.com'))
        ada = session.scalar(select(Customer).where(Customer.email == 'ada@example.com'))
        ada.note = 'edited while protected'
        session.commit()
        print('Search by email found:', ada.email, '/', ada.note)
        print('IN found:', session.scalars(select(Customer.email).where(Customer.email.in_(['ada@example.com']))).all())

        session.add(Customer(id=uuid4(), email='ada@example.com'))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            print('Uniqueness still holds without PostgreSQL seeing the email.')

        try:
            session.scalars(select(Customer).where(Customer.note == 'x'))
        except UnsupportedProtectedOperation as failure:
            print('Undeclared search refuses before SQL:', failure.fields)
    with owner_engine().connect() as connection:
        stored = bytes(connection.scalar(select(text('email')).select_from(Customer.__table__).limit(1)))
    print('PostgreSQL stores', len(stored), 'authenticated bytes, starting', stored[:8].hex())
    assert b'@example.com' not in stored


def rotate(state):
    """Three separate operations, each in its own process in a real deployment."""
    owner = owner_engine()
    for purpose in ('payload', 'search'):
        print(f'Rotated {purpose} key:', project(state).rotate(owner, purpose, writers_stopped=WRITERS_STOPPED).phase)


def rotate_wrapping(state):
    """Move the same data keys under a new provider; stored bytes do not change."""
    from cryptalis.crypto import DevelopmentKeyProvider
    new_provider = DevelopmentKeyProvider(state / 'new-key')
    progress = project(state).rotate(owner_engine(), 'wrapping', provider=new_provider, writers_stopped=WRITERS_STOPPED)
    print('Rewrapped under a new provider:', progress.phase)


def application_after_rotation(state):
    with project(state, 'new-key').attach(app_engine())() as session:
        ada = session.get(Customer, ADA)
        ada.note = 'latest value'
        session.commit()
        print('Rotated data still reads:', ada.email)


def remove(state):
    """Decrypt the latest values, then drop everything Cryptalis generated."""
    owner, operator = owner_engine(), project(state, 'new-key')
    operator.decrypt(owner, plaintext_role=make_url(NATIVE_URL).username, writers_stopped=WRITERS_STOPPED,
                     accept_plaintext=True, retained_backups='Disposable database: no backups exist.')
    progress = operator.remove(owner, writers_stopped=WRITERS_STOPPED, old_workers_stopped=True,
                               application_verified='The next step restarts without Cryptalis.')
    print('Removed:', progress.phase)


def application_without_cryptalis(state):
    """Cryptalis cannot be imported here, as if it were uninstalled."""
    sys.modules['cryptalis'] = None
    with Session(create_engine(NATIVE_URL)) as session:
        ada = session.scalar(select(Customer).where(Customer.email == 'ada@example.com'))
        print('Native application reads', ada.email, '/', ada.note)
        assert ada.note == 'latest value'


STEPS = (native_application, protect, application, rotate, application, rotate_wrapping,
         application_after_rotation, remove, application_without_cryptalis)

if __name__ == '__main__':
    state = Path(sys.argv[1]).resolve()
    if len(sys.argv) > 2:
        globals()[sys.argv[2]](state)
    else:
        state.mkdir(mode=0o700)
        (state / 'cryptalis').mkdir(mode=0o700)  # Holds wrapped keys. Back it up, away from database backups.
        for step in STEPS:
            print(f'--- {step.__name__}', flush=True)
            subprocess.run([sys.executable, __file__, state, step.__name__], check=True)
