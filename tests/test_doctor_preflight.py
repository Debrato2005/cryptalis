"""Pre-adoption reports retain uncertainty and safe native failure evidence."""
import json
import re

import pytest
from sqlalchemy import event

from cryptalis.doctor import preflight
from test_protection_compiler import app, engine, declaration, inventory, reviews, snapshot


def observe(app, manifest=None):
    database, mapping, _, _ = app
    return preflight(json.dumps(declaration() if manifest is None else manifest).encode(),
                     mapping, database, writers=inventory(), search_reviews=reviews())


def test_schema_pass_is_not_overall_health_or_permission_to_read_application_rows(app):
    database, _, _, schema = app
    before = snapshot(app)
    statements = []

    def capture(connection, cursor, statement, parameters, context, many):
        statements.append(statement)
        assert connection.get_execution_options()['postgresql_readonly'] is True
        assert not re.search(r'\bFROM\s+(?:"?' + re.escape(schema) + r'"?\.)?"?customer\b',
                             statement, re.IGNORECASE)

    event.listen(database, 'before_cursor_execute', capture)
    try:
        report = observe(app)
    finally:
        event.remove(database, 'before_cursor_execute', capture)
    assert statements
    assert report['status'] == 'UNKNOWN' and report['effects'] == 'NONE'
    assert report['checks']['manifest_schema'] == 'PASS' and report['issues'] == []
    assert {value for name, value in report['checks'].items() if name != 'manifest_schema'} == {'UNKNOWN'}
    assert snapshot(app) == before


def test_native_schema_refusal_has_actionable_issues_without_applying_changes(app):
    database, _, _, schema = app
    with database.begin() as connection:
        connection.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN tenant_id DROP NOT NULL')
    before = snapshot(app)
    report = observe(app)
    assert report['status'] == report['checks']['manifest_schema'] == 'FAIL'
    assert report['issues'] and all(issue['code'] and issue['location'] and issue['remedy']
                                    for issue in report['issues'])
    assert {value for name, value in report['checks'].items() if name != 'manifest_schema'} == {'UNKNOWN'}
    assert snapshot(app) == before


def test_native_inspection_error_is_unknown_redacted_and_recovers_on_retry(app):
    database, _, _, _ = app
    before = snapshot(app)

    def interrupt(connection, cursor, statement, parameters, context, many):
        if 'SELECT t.oid, t.relkind' in statement:
            connection.exec_driver_sql("SELECT 1/0 /* PRIVATE_DOCTOR_INSPECTION */")

    event.listen(database, 'before_cursor_execute', interrupt)
    try:
        report = observe(app)
    finally:
        event.remove(database, 'before_cursor_execute', interrupt)
    assert report['status'] == report['checks']['manifest_schema'] == 'UNKNOWN'
    assert report['sqlstate'] == '22012' and report['issues'][0]['remedy']
    assert 'PRIVATE_DOCTOR_INSPECTION' not in json.dumps(report)
    assert snapshot(app) == before
    assert observe(app)['checks']['manifest_schema'] == 'PASS'


def test_invalid_manifest_refuses_before_database_access(app, monkeypatch):
    database, _, _, _ = app

    def unavailable():
        pytest.fail('invalid manifest attempted database access')

    monkeypatch.setattr(database, 'connect', unavailable)
    report = observe(app, {'schema': 'private-invalid-declaration'})
    assert report['status'] == report['checks']['manifest_schema'] == 'FAIL'
    assert report['issues'][0]['code'] == 'Manifest.Invalid'
    assert 'private-invalid-declaration' not in json.dumps(report)
