"""CRUD through unchanged official template modules; no Cryptalis import."""

from uuid import UUID

from sqlmodel import select

from app import crud
from app.models import User, UserCreate, UserUpdate


def workflow(factory, phase, retained=None):
    with factory() as session:
        if retained is not None:
            old = crud.get_user_by_email(session=session, email=retained['email'])
            assert old is not None and str(old.id) == retained['id']
            assert old.full_name == retained['full_name']
            if 'is_active' in retained:
                assert old.is_active is retained['is_active']
        email = phase + '@example.com'
        row = crud.create_user(session=session, user_create=UserCreate(
            email=email, password='PUBLIC disposable password 2026', full_name='private-name-' + phase))
        assert type(row.id) is UUID and row.created_at is not None
        assert row.hashed_password != 'PUBLIC disposable password 2026'
        assert crud.get_user_by_email(session=session, email=email) is row
        assert session.exec(select(User.full_name).where(User.id == row.id)).one() == row.full_name
        assert tuple(session.exec(select(User.id, User.full_name).where(User.id == row.id)).one()) == (row.id, row.full_name)
        crud.update_user(session=session, db_user=row, user_in=UserUpdate(full_name=None))
        assert row.full_name is None
        name = 'private-name-updated-' + phase + '-雪😀'
        crud.update_user(session=session, db_user=row, user_in=UserUpdate(full_name=name))
        assert row.full_name == name
        assert session.exec(select(User).where(User.email == email)).one() is row
        removed = crud.create_user(session=session, user_create=UserCreate(
            email='deleted-' + email, password='PUBLIC disposable password 2026', full_name='delete me'))
        session.delete(removed)
        session.commit()
        assert crud.get_user_by_email(session=session, email='deleted-' + email) is None
        return {'id': str(row.id), 'email': email, 'full_name': name}


def boolean_controls(factory, retained, phase):
    with factory() as session:
        row = crud.get_user_by_email(session=session, email=retained['email'])
        assert row is not None
        created = crud.create_user(session=session, user_create=UserCreate(
            email='boolean-default-' + phase + '@example.com',
            password='PUBLIC disposable password 2026'))
        assert created.is_active is True
        assert session.exec(select(User.is_active).where(User.id == created.id)).one() is True
        crud.update_user(session=session, db_user=created, user_in=UserUpdate(is_active=False))
        session.refresh(created)
        assert created.is_active is False
        session.delete(created)
        session.commit()
        crud.update_user(session=session, db_user=row, user_in=UserUpdate(is_active=True))
        session.refresh(row)
        assert row.is_active is True
        crud.update_user(session=session, db_user=row, user_in=UserUpdate(is_active=False))
        session.refresh(row)
        assert row.is_active is False
        assert tuple(session.exec(select(User.id, User.is_active).where(User.id == row.id)).one()) == (row.id, False)
        return dict(retained, is_active=False)
