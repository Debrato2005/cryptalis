"""Native scoped dictionary UPDATE oracle; no protected implementation assumed."""
from contextlib import contextmanager
from copy import deepcopy
import json
from uuid import UUID

import pytest
from sqlalchemy import event, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError, PendingRollbackError, ResourceClosedError
from sqlalchemy.orm import Session

from test_bulk_insert_native import assert_aborted, native_application, stored
from test_migration import TENANT


FOREIGN, MISSING, OTHER = UUID(int=9000), UUID(int=9001), UUID(int=999)


def changes(identity, **values):
    return dict(id=UUID(int=identity), **values)


def execute(session, app, rows):
    return session.execute(update(app.Customer).where(app.Customer.tenant_id == TENANT),
                           rows, execution_options={'synchronize_session': False})


def snapshot(app):
    with app.owner.connect() as connection:
        return stored(app, connection)


def by_id(rows):
    return {row[0]: tuple(row[1:]) for row in rows}


def empty_result(result):
    # ORM bulk UPDATE returns native null_result(), unlike INSERT CursorResult.
    assert list(result.keys()) == []
    assert result.all() == []
    result.close()
    with pytest.raises(ResourceClosedError):
        result.all()


def add_foreign(app):
    with Session(app.runtime) as session:
        session.add(app.Customer(id=FOREIGN, tenant_id=OTHER, name='else', label='foreign'))
        session.commit()


@contextmanager
def observations(app):
    attempted, completed = [], []

    def before(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('UPDATE '):
            attempted.append({'groups': [sorted(group) for group in context.compiled_parameters],
                              'executemany': executemany})

    def after(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('UPDATE '):
            rowcount = cursor.rowcount
            visible = connection.execute(select(app.table).order_by(app.table.c.id)).all()
            completed.append({'rowcount': rowcount,
                              'visible': [(row.id.int, row.tenant_id.int, row.name, row.label)
                                          for row in visible]})

    event.listen(app.runtime, 'before_cursor_execute', before)
    event.listen(app.runtime, 'after_cursor_execute', after)
    try:
        yield attempted, completed
    finally:
        event.remove(app.runtime, 'before_cursor_execute', before)
        event.remove(app.runtime, 'after_cursor_execute', after)


def record(record_property, label, value):
    encoded = json.dumps(value, ensure_ascii=False)
    record_property(label, encoded)
    print(label + ': ' + encoded)


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_native_scoped_update_partial_null_and_identity_map(varchar, record_property):
    with native_application(varchar) as app:
        rows = [changes(100, name='e\u0301😀界'), changes(101, label='label only'), changes(102, name=None)]
        original, before = deepcopy(rows), by_id(snapshot(app))
        with observations(app) as observed:
            with Session(app.runtime) as session:
                loaded = session.get(app.Customer, UUID(int=100))
                assert loaded.name is None
                empty_result(execute(session, app, rows))
                assert loaded.name is None and len(session.identity_map) == 1
                session.refresh(loaded)
                assert loaded.name == 'e\u0301😀界'
                actual = by_id(session.execute(select(app.table)).all())
                assert actual[UUID(int=100)] == (TENANT, 'e\u0301😀界', before[UUID(int=100)][2])
                assert actual[UUID(int=101)] == (TENANT, '', 'label only')
                assert actual[UUID(int=102)] == (TENANT, None, before[UUID(int=102)][2])
                session.commit()
        assert rows == original and by_id(snapshot(app)) == actual
        record(record_property, 'native_update_batches', observed)


@pytest.mark.parametrize('heterogeneous', [False, True], ids=['same-group', 'heterogeneous'])
def test_native_repeated_ids_apply_each_occurrence_in_order(heterogeneous, record_property):
    with native_application(False) as app:
        rows = ([changes(100, name='first', label='first group'), changes(101, name='middle'),
                 changes(100, name='last')] if heterogeneous else
                [changes(100, name='first'), changes(100, name='last')])
        original, before = deepcopy(rows), snapshot(app)
        with observations(app) as observed:
            with Session(app.runtime) as session:
                empty_result(execute(session, app, rows))
                assert session.scalar(select(app.Customer.name).where(app.Customer.id == UUID(int=100))) == 'last'
                assert len(session.identity_map) == 0
                session.rollback()
        assert rows == original and snapshot(app) == before
        attempted, completed = observed
        assert sum(item['rowcount'] for item in completed) == len(rows)
        assert len(attempted) == (2 if heterogeneous else 1)
        record(record_property, 'native_repeated_id_updates', observed)


def test_native_missing_and_foreign_ids_match_zero_without_stale_error(record_property):
    with native_application(False) as app:
        add_foreign(app)
        before = by_id(snapshot(app))
        rows = [changes(100, label='own update'), {'id': MISSING, 'name': 'missing'},
                {'id': FOREIGN, 'name': 'other update'}]
        original = deepcopy(rows)
        with observations(app) as observed:
            with Session(app.runtime) as session:
                empty_result(execute(session, app, rows))
                actual = by_id(session.execute(select(app.table)).all())
                assert actual[FOREIGN] == before[FOREIGN] and MISSING not in actual
                assert actual[UUID(int=100)] == (TENANT, None, 'own update')
                session.commit()
        assert rows == original and by_id(snapshot(app)) == actual
        assert sum(item['rowcount'] for item in observed[1]) == 1
        record(record_property, 'native_zero_match_updates', observed)


def test_native_autoflush_success_precedes_scoped_update(record_property):
    with native_application(False) as app:
        before = snapshot(app)
        with observations(app) as observed:
            with Session(app.runtime) as session:
                loaded = session.get(app.Customer, UUID(int=101))
                loaded.label = 'autoflush first'
                empty_result(execute(session, app, [changes(100, name='bulk next')]))
                assert session.scalar(select(app.Customer.label).where(
                    app.Customer.id == UUID(int=101))) == 'autoflush first'
                assert session.scalar(select(app.Customer.name).where(
                    app.Customer.id == UUID(int=100))) == 'bulk next'
                session.rollback()
        assert snapshot(app) == before and len(observed[1]) == 2
        first = {row[0]: row[2:] for row in observed[1][0]['visible']}
        assert first[100][0] is None and first[101][1] == 'autoflush first'
        record(record_property, 'native_autoflush_update_order', observed)


def test_native_pending_autoflush_constraint_precedes_matching_varchar_error(record_property):
    with native_application(True) as app:
        rows, before = [changes(101, name='abcde')], snapshot(app)
        original = deepcopy(rows)
        with observations(app) as observed:
            with Session(app.runtime) as session:
                session.add(app.Customer(id=UUID(int=100), tenant_id=TENANT, name='good'))
                with pytest.raises(IntegrityError) as failed:
                    execute(session, app, rows)
                assert failed.value.orig.sqlstate == '23505' and session.is_active is False
                with pytest.raises(PendingRollbackError):
                    session.execute(select(app.Customer.id))
                session.rollback()
        assert observed == ([], []) and rows == original and snapshot(app) == before
        record(record_property, 'native_pending_autoflush_sqlstate', '23505')


@pytest.mark.parametrize('fault', ['unique', 'length'])
def test_native_savepoint_failure_rolls_back_inner_prefix_and_preserves_outer(fault, record_property):
    with native_application(True) as app:
        before = by_id(snapshot(app))
        rows = [changes(101, name='good', label='inner prefix'),
                changes(102, name='good' if fault == 'unique' else 'abcde')]
        original = deepcopy(rows)
        with Session(app.runtime) as session:
            empty_result(execute(session, app, [changes(100, label='outer')]))
            savepoint = session.begin_nested()
            with observations(app) as observed:
                with pytest.raises(DBAPIError) as failed:
                    execute(session, app, rows)
                assert failed.value.orig.sqlstate == ('23505' if fault == 'unique' else '22001')
                assert_aborted(session)
            assert len(observed[1]) == 1
            prefix = {row[0]: row[2:] for row in observed[1][0]['visible']}
            assert prefix[101] == ('good', 'inner prefix')
            savepoint.rollback()
            current = by_id(session.execute(select(app.table)).all())
            assert current[UUID(int=100)] == (TENANT, None, 'outer')
            assert current[UUID(int=101)] == before[UUID(int=101)]
            assert current[UUID(int=102)] == before[UUID(int=102)]
            empty_result(execute(session, app, [changes(101, name='done')]))
            session.commit()
        actual = by_id(snapshot(app))
        assert actual[UUID(int=100)][2] == 'outer' and actual[UUID(int=101)][1] == 'done'
        assert rows == original
        record(record_property, 'native_failed_update_savepoint_prefix', observed)


@pytest.mark.parametrize('length_first', [False, True], ids=['unique-first', 'length-first'])
def test_native_update_constraint_order_precedes_later_failure(length_first, record_property):
    with native_application(True) as app:
        with Session(app.runtime) as session:
            empty_result(execute(session, app, [changes(100, name='base'), changes(101, name='held')]))
            session.commit()
        before = snapshot(app)
        conflict, length = changes(100, name='held', label='conflict'), changes(102, name='abcde')
        rows = [length, conflict] if length_first else [conflict, length]
        original = deepcopy(rows)
        with Session(app.runtime) as session:
            with pytest.raises(DBAPIError) as failed:
                execute(session, app, rows)
            assert failed.value.orig.sqlstate == ('22001' if length_first else '23505')
            assert_aborted(session)
            session.rollback()
        assert rows == original and snapshot(app) == before
        record(record_property, 'native_update_first_failure_sqlstate', failed.value.orig.sqlstate)


def test_native_varchar_assignment_observes_matching_missing_and_foreign_rows(record_property):
    with native_application(True) as app:
        add_foreign(app)
        before, outcomes = snapshot(app), {}
        for label, identity in [('matching', UUID(int=100)), ('missing', MISSING), ('foreign', FOREIGN)]:
            rows, outcome = [{'id': identity, 'name': 'abcde'}], {}
            original = deepcopy(rows)
            with observations(app) as observed:
                with Session(app.runtime) as session:
                    try:
                        empty_result(execute(session, app, rows))
                    except DBAPIError as failed:
                        outcome['sqlstate'] = failed.orig.sqlstate
                        assert failed.orig.sqlstate == '22001'
                        assert_aborted(session)
                    else:
                        outcome['sqlstate'] = None
                        assert label != 'matching'
                        assert sum(item['rowcount'] for item in observed[1]) == 0
                    session.rollback()
            assert rows == original and snapshot(app) == before
            outcome['attempted_groups'] = observed[0]
            outcome['matched_rows'] = sum(item['rowcount'] for item in observed[1])
            outcomes[label] = outcome
        assert outcomes['matching']['sqlstate'] == '22001'
        # Zero-match evaluation is an observation, not an INSERT-carrier rule.
        record(record_property, 'native_varchar_update_match_dependence', outcomes)
