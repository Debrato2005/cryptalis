"""Native PostgreSQL oracle for mapped dictionary inserts without RETURNING."""
from copy import deepcopy
import json
from uuid import UUID

import pytest
from sqlalchemy import String, event, insert, literal, select, text
from sqlalchemy.exc import DBAPIError, ResourceClosedError
from sqlalchemy.orm import Session

from test_migration import application, TENANT


def native_application(varchar):
    # The first three existing fixture values fit VARCHAR(4).
    return application(rows=3, value_type=String(4, collation='C') if varchar else None)


def row(identity, name, **extra):
    return dict(id=UUID(int=identity), tenant_id=TENANT, name=name, **extra)


def stored(app, connection):
    table = app.table
    return connection.execute(select(table.c.id, table.c.tenant_id, table.c.name,
                                     table.c.label).order_by(table.c.id)).all()


def assert_aborted(session):
    # execute() errors leave the SQLAlchemy Session active while PostgreSQL
    # refuses more statements until transaction/savepoint rollback.
    assert session.is_active is True
    with pytest.raises(DBAPIError) as blocked:
        session.execute(select(literal(1)))
    assert blocked.value.orig.sqlstate == '25P02'


def observe_prefix(app, attempted, visible):
    def before(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('INSERT '):
            attempted.append([sorted(values) for values in context.compiled_parameters])

    def after(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('INSERT '):
            visible.append(tuple(connection.execute(select(app.table.c.id).where(
                app.table.c.id >= UUID(int=1000)).order_by(app.table.c.id)).scalars()))

    event.listen(app.runtime, 'before_cursor_execute', before)
    event.listen(app.runtime, 'after_cursor_execute', after)
    return before, after


def stop_observing(app, listeners):
    event.remove(app.runtime, 'before_cursor_execute', listeners[0])
    event.remove(app.runtime, 'after_cursor_execute', listeners[1])


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_native_bulk_insert_preserves_values_inputs_and_empty_identity_map(varchar, record_property):
    with native_application(varchar) as app:
        rows = [row(1000, 'e\u0301😀界', label='unicode'),
                row(1001, None, label=None),
                {'id': UUID(int=1002), 'tenant_id': TENANT, 'label': 'omitted name'},
                row(1003, 'abcd   ', label='space overflow'),
                row(1004, 'x '), row(1005, 'new', label=None)]
        original = deepcopy(rows)
        attempted, visible = [], []
        listeners = observe_prefix(app, attempted, visible)
        try:
            with Session(app.runtime) as session:
                result = session.execute(insert(app.Customer), rows)
                with pytest.raises(ResourceClosedError):
                    result.all()
                assert len(session.identity_map) == 0
                expected = [(entry['id'], TENANT,
                             'abcd' if varchar and entry.get('name') == 'abcd   ' else entry.get('name'),
                             entry.get('label')) for entry in rows]
                actual = session.execute(select(app.table).where(
                    app.table.c.id >= UUID(int=1000)).order_by(app.table.c.id)).all()
                assert actual == expected
                assert len(session.identity_map) == 0
                session.commit()
            assert rows == original
        finally:
            stop_observing(app, listeners)
        record_property('native_insert_parameter_groups', json.dumps(attempted))
        record_property('native_successful_insert_prefixes', json.dumps(
            [[str(identity) for identity in prefix] for prefix in visible]))
        assert attempted and visible[-1] == tuple(entry['id'] for entry in rows)
        with app.owner.connect() as connection:
            assert len(stored(app, connection)) == 3 + len(rows)


@pytest.mark.parametrize('varchar,fault', [
    (False, 'duplicate_id'), (False, 'unique_name'),
    (True, 'duplicate_id'), (True, 'unique_name'), (True, 'length'),
], ids=['text-id', 'text-unique', 'varchar-id', 'varchar-unique', 'varchar-length'])
def test_native_late_bulk_failure_aborts_the_transaction_until_rollback(varchar, fault, record_property):
    with native_application(varchar) as app:
        first = row(1000, 'good', label='prefix')
        second = row(1000 if fault == 'duplicate_id' else 1001,
                     'good' if fault == 'unique_name' else 'abcde' if fault == 'length' else 'next')
        rows, attempted, visible = [first, second], [], []
        original = deepcopy(rows)
        with app.owner.connect() as connection:
            baseline = stored(app, connection)
        listeners = observe_prefix(app, attempted, visible)
        try:
            with Session(app.runtime) as session:
                with pytest.raises(DBAPIError) as failure:
                    session.execute(insert(app.Customer), rows)
                assert failure.value.orig.sqlstate == ('22001' if fault == 'length' else '23505')
                assert len(session.identity_map) == 0 and rows == original
                assert_aborted(session)
                # A different session never sees the uncommitted prefix.
                with app.owner.connect() as connection:
                    assert stored(app, connection) == baseline
                session.rollback()
                assert stored(app, session) == baseline
                assert len(attempted) == 2 and visible == [(UUID(int=1000),)]
                session.execute(insert(app.Customer), [row(1009, 'redo', label='after rollback')])
                session.commit()
        finally:
            stop_observing(app, listeners)
        record_property('native_failure_sqlstate', failure.value.orig.sqlstate)
        record_property('native_insert_parameter_groups', json.dumps(attempted))
        record_property('native_prefix_before_failed_statement', str(visible[0][0]))
        with app.owner.connect() as connection:
            final = stored(app, connection)
        assert final == baseline + [(UUID(int=1009), TENANT, 'redo', 'after rollback')]
        assert rows == original


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_native_bulk_savepoint_rollback_keeps_outer_work_and_allows_recovery(varchar, record_property):
    with native_application(varchar) as app:
        outer = row(1000, 'keep', label='outer transaction')
        rows = [row(1001, 'dupe', label='savepoint prefix'), row(1002, 'dupe')]
        original = deepcopy(rows)
        attempted, visible = [], []
        with app.owner.connect() as connection:
            baseline = stored(app, connection)
        listeners = observe_prefix(app, attempted, visible)
        try:
            with Session(app.runtime) as session:
                session.execute(insert(app.Customer), [outer])
                savepoint = session.begin_nested()
                with pytest.raises(DBAPIError) as failure:
                    session.execute(insert(app.Customer), rows)
                assert failure.value.orig.sqlstate == '23505'
                assert_aborted(session)
                savepoint.rollback()
                assert stored(app, session) == baseline + [
                    (UUID(int=1000), TENANT, 'keep', 'outer transaction')]
                assert len(session.identity_map) == 0
                assert visible == [(UUID(int=1000),), (UUID(int=1000), UUID(int=1001))]
                session.execute(insert(app.Customer), [row(1003, 'done', label='after savepoint')])
                session.commit()
        finally:
            stop_observing(app, listeners)
        record_property('native_savepoint_insert_parameter_groups', json.dumps(attempted))
        with app.owner.connect() as connection:
            final = stored(app, connection)
        assert final == baseline + [(UUID(int=1000), TENANT, 'keep', 'outer transaction'),
                                    (UUID(int=1003), TENANT, 'done', 'after savepoint')]
        assert rows == original


def test_native_fixed_varchar_coercion_failure_preserves_transaction_and_savepoint_rules():
    with native_application(False) as app:
        probe = text("SELECT pg_catalog.varchar('xx'::varchar,5,false)")
        with Session(app.runtime) as session:
            with pytest.raises(DBAPIError) as failed:
                session.execute(probe)
            assert failed.value.orig.sqlstate == '22001'
            assert_aborted(session)
            session.rollback()
            assert session.scalar(select(1)) == 1
            session.execute(insert(app.Customer), [row(1000, 'keep', label='outside savepoint')])
            savepoint = session.begin_nested()
            with pytest.raises(DBAPIError) as nested:
                session.execute(probe)
            assert nested.value.orig.sqlstate == '22001'
            assert_aborted(session)
            savepoint.rollback()
            assert session.scalar(select(app.Customer.name).where(
                app.Customer.id == UUID(int=1000))) == 'keep'
            session.commit()
