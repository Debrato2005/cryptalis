"""Native VARCHAR UPDATE observations under custom and generic server plans."""
from copy import deepcopy
from uuid import UUID

import pytest
from sqlalchemy import event
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from test_bulk_insert_native import assert_aborted, native_application
from test_bulk_update_native import (
    FOREIGN, MISSING, add_foreign, changes, empty_result, execute,
    observations, record, snapshot,
)


def prepared_updates(session, schema):
    return [dict(statement=row[0], generic=row[1], custom=row[2]) for row in
            session.connection().exec_driver_sql(
                "SELECT statement, generic_plans, custom_plans FROM pg_prepared_statements "
                "WHERE statement LIKE %s ORDER BY name", (f'UPDATE {schema}.customer%',)).all()]


def attempt(session, app, rows):
    original = deepcopy(rows)
    savepoint = session.begin_nested()
    prior_plans = prepared_updates(session, app.schema)
    with observations(app) as observed:
        try:
            empty_result(execute(session, app, rows))
        except DBAPIError as failed:
            outcome = {'sqlstate': failed.orig.sqlstate}
            assert failed.orig.sqlstate == '22001'
            assert session.is_active is True
            assert_aborted(session)
        else:
            outcome = {'sqlstate': None, 'prepared_after_success': prepared_updates(session, app.schema)}
        outcome['prepared_before'] = prior_plans
        outcome['completed_rowcounts'] = [entry['rowcount'] for entry in observed[1]]
        outcome['attempted'] = observed[0]
    savepoint.rollback()
    assert rows == original
    return outcome


@pytest.mark.parametrize('mode', ['force_custom_plan', 'force_generic_plan'])
@pytest.mark.parametrize('shape', ['single', 'same_group', 'heterogeneous'])
def test_native_varchar_failure_depends_on_server_plan_and_matches(mode, shape, record_property):
    with native_application(True) as app:
        add_foreign(app)
        before = snapshot(app)
        sent, outcomes = [], []

        def rendered(connection, cursor, statement, parameters, context, executemany):
            if statement.lstrip().upper().startswith('UPDATE '):
                entry = {'sql': statement, 'executemany': executemany}
                if entry not in sent:
                    sent.append(entry)

        event.listen(app.runtime, 'before_cursor_execute', rendered)
        try:
            with Session(app.runtime) as session:
                driver = session.connection().connection.driver_connection
                driver.prepare_threshold = 0
                session.connection().exec_driver_sql(f'SET LOCAL plan_cache_mode = {mode}')
                for label, identity in [('matching', UUID(int=100)), ('missing', MISSING), ('foreign', FOREIGN)]:
                    for repeat in range(2):
                        rows = [{'id': identity, 'name': 'abcde'}]
                        if shape != 'single':
                            rows.insert(0, changes(101, name='good', **(
                                {'label': 'public prefix'} if shape == 'heterogeneous' else {})))
                        outcome = attempt(session, app, rows)
                        outcomes.append(dict(target=label, repeat=repeat, **outcome))
                session.rollback()
        finally:
            event.remove(app.runtime, 'before_cursor_execute', rendered)
        assert snapshot(app) == before
        record(record_property, 'varchar_update_plan_observations', {
            'mode': mode, 'prepare_threshold': 0, 'shape': shape,
            'sent': sent, 'outcomes': outcomes,
        })
        for outcome in outcomes:
            expected_error = mode == 'force_custom_plan' or outcome['target'] == 'matching'
            assert outcome['sqlstate'] == ('22001' if expected_error else None)
            if not expected_error:
                assert sum(outcome['completed_rowcounts']) == (0 if shape == 'single' else 1)
        assert sent
        if mode == 'force_generic_plan':
            prepared = [entry for outcome in outcomes for entry in outcome.get('prepared_after_success', ())]
            assert prepared
            assert sum(entry['generic'] for entry in prepared) > 0
            assert sum(entry['custom'] for entry in prepared) == 0


def test_native_varchar_auto_plan_before_and_after_repeated_valid_updates(record_property):
    with native_application(True) as app:
        add_foreign(app)
        before, outcomes = snapshot(app), []
        with Session(app.runtime) as session:
            driver = session.connection().connection.driver_connection
            threshold = driver.prepare_threshold
            session.connection().exec_driver_sql('SET LOCAL plan_cache_mode = auto')
            for phase in ('cold', 'warm'):
                for label, identity in [('matching', UUID(int=100)), ('missing', MISSING), ('foreign', FOREIGN)]:
                    if phase == 'warm':
                        for _ in range(12):
                            empty_result(execute(session, app, [changes(101, name='good')]))
                    outcome = attempt(session, app, [{'id': identity, 'name': 'abcde'}])
                    outcomes.append(dict(phase=phase, target=label, **outcome))
            session.rollback()
        assert snapshot(app) == before
        record(record_property, 'varchar_update_auto_plan_observations', {
            'mode': 'auto', 'prepare_threshold': threshold, 'outcomes': outcomes,
        })
        assert threshold == 5
        assert all(outcome['sqlstate'] == '22001' for outcome in outcomes if outcome['phase'] == 'cold')
        for outcome in outcomes:
            if outcome['phase'] == 'warm':
                assert outcome['sqlstate'] == ('22001' if outcome['target'] == 'matching' else None)
