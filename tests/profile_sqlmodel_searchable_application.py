"""Opt-in encrypted email query journey on pinned unchanged SQLModel CRUD.

Search review is limited to public opaque UUID fixture identities. Arbitrary
production email domains and multi-tenant application behavior remain UNKNOWN.
"""
from test_sqlmodel_application import run_application


def test_original_template_email_search_and_latest_value_exit(tmp_path, monkeypatch):
    run_application(tmp_path, monkeypatch, searchable_email=True)



def native_catalog(owner):
    with owner.connect() as c:
        return {'columns': c.exec_driver_sql(
            "SELECT column_name,data_type,character_maximum_length,is_nullable "
            "FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='user' "
            "ORDER BY column_name").all(),
            'indexes': c.exec_driver_sql("SELECT indexname,indexdef FROM pg_catalog.pg_indexes "
                "WHERE schemaname=current_schema() AND tablename='user' ORDER BY indexname").all(),
            'constraints': c.exec_driver_sql("SELECT conname,pg_catalog.pg_get_constraintdef(oid) "
                "FROM pg_catalog.pg_constraint WHERE conrelid='\"user\"'::regclass ORDER BY conname").all()}


def search_controls(factory, retained):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from uuid import UUID, uuid4
    import pytest
    from sqlalchemy.exc import IntegrityError, PendingRollbackError
    from sqlmodel import select
    from app import crud
    from app.models import User, UserCreate, UserUpdate
    with factory() as session:
        row = crud.get_user_by_email(session=session, email=retained['email'])
        assert str(row.id) == retained['id']
        assert session.exec(select(User.id).where(User.email.in_([retained['email'], None]))).all() == [row.id]
        assert session.exec(select(User.id).where(User.email.in_([]))).all() == []
        assert session.exec(select(User.id).where(User.email.is_(None))).all() == []
        unicode_email = '雪.' + uuid4().hex + '@example.com'
        unicode_row = crud.create_user(session=session, user_create=UserCreate(email=unicode_email,
            password='PUBLIC disposable password 2026', full_name='Unicode email fixture'))
        assert crud.get_user_by_email(session=session, email=unicode_email).id == unicode_row.id
        assert set(session.exec(select(User.id).where(User.email.in_([unicode_email, retained['email'], None]))).all()) == {row.id, unicode_row.id}
        session.delete(unicode_row)
        session.commit()
        with pytest.raises(IntegrityError) as caught:
            crud.create_user(session=session, user_create=UserCreate(email=retained['email'],
                password='PUBLIC disposable password 2026', full_name='duplicate fixture'))
        assert caught.value.orig.sqlstate == '23505' and not session.is_active
        with pytest.raises(PendingRollbackError):
            crud.get_user_by_email(session=session, email=retained['email'])
        session.rollback()
        row = crud.get_user_by_email(session=session, email=retained['email'])
        latest = uuid4().hex + '@example.com'
        crud.update_user(session=session, db_user=row, user_in=UserUpdate(email=latest))
        assert crud.get_user_by_email(session=session, email=retained['email']) is None
        assert crud.get_user_by_email(session=session, email=latest).id == UUID(retained['id'])
        retained = dict(retained, email=latest)
    # PostgreSQL's existing unique index arbitrates two real transactions.
    email = uuid4().hex + '@example.com'
    ready = Barrier(2)
    def competitor(_):
        with factory() as session:
            value = User.model_validate(UserCreate(email=email, password='PUBLIC disposable password 2026'),
                                        update={'hashed_password': 'PUBLIC fixture only'})
            session.add(value)
            ready.wait(timeout=10)
            try:
                session.commit()
                return 'committed', value.id
            except IntegrityError as conflict:
                assert conflict.orig.sqlstate == '23505'
                session.rollback()
                assert crud.get_user_by_email(session=session, email=email) is not None
                return '23505', None
    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(competitor, (0, 1)))
    assert sorted(status for status, _ in outcomes) == ['23505', 'committed']
    winner = next(identity for status, identity in outcomes if status == 'committed')
    code = '23505'
    with factory() as session:
        value = crud.get_user_by_email(session=session, email=email)
        assert value.id == winner
        session.delete(value)
        session.commit()
    return retained, {'equality': True, 'IN': True, 'empty_IN': True, 'NULL': 'no NULL email; IN NULL ignored',
                      'Unicode': True, 'unique_sqlstate': '23505', 'rollback': True,
                      'concurrent_unique_sqlstate': code, 'latest_email_edit': True}
