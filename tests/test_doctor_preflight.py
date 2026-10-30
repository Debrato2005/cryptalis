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


def test_supplied_select_shapes_use_runtime_admission_without_keys_rows_or_mapping_changes(app, monkeypatch):
    from sqlalchemy import select
    from sqlalchemy.orm import aliased
    from cryptalis.sqlalchemy import _Attachment
    database, mapping, Customer, schema = app
    before, original_type = snapshot(app), Customer.email.type
    def forbidden(*args, **kwargs):
        pytest.fail('query preflight accessed runtime activation or keys')
    for method in ('activate', 'validate', '_ring'):
        monkeypatch.setattr(_Attachment, method, forbidden)
    def readonly(connection, cursor, statement, parameters, context, many):
        assert connection.get_execution_options()['postgresql_readonly'] is True
        assert not re.search(r'\bFROM\s+(?:"?' + re.escape(schema) + r'"?\.)?"?customer\b',
                             statement, re.IGNORECASE)
    other = aliased(Customer)
    queries = (select(Customer), select(other.email).where(other.email.in_(['PRIVATE_QUERY_VALUE', None])),
               select(Customer.id).where(Customer.email.is_(None)))
    event.listen(database, 'before_cursor_execute', readonly)
    try:
        report = preflight(json.dumps(declaration()).encode(), mapping, database,
                           writers=inventory(), search_reviews=reviews(), queries=queries)
    finally:
        event.remove(database, 'before_cursor_execute', readonly)
    assert report['checks']['query_samples'] == 'PASS' and report['checks']['query_routes'] == 'UNKNOWN'
    assert report['status'] == 'UNKNOWN' and report['query_samples']['execution'] == 'NOT_PERFORMED'
    assert [item['status'] for item in report['query_samples']['items']] == ['STRUCTURE_ADMITTED'] * 3
    assert 'PRIVATE_QUERY_VALUE' not in json.dumps(report)
    assert Customer.email.type is original_type and snapshot(app) == before


def test_known_query_incompatibility_is_actionable_without_disclosing_sql_or_values(app):
    from sqlalchemy import select, text, update
    database, mapping, Customer, _ = app
    before = snapshot(app)
    queries = (select(Customer.id), select(Customer).where(Customer.email.ilike('PRIVATE_PATTERN')),
               text('PRIVATE_SQL'), update(Customer).values(email='PRIVATE_UPDATE'))
    report = preflight(json.dumps(declaration()).encode(), mapping, database,
                       writers=inventory(), search_reviews=reviews(), queries=queries)
    assert report['status'] == report['checks']['query_routes'] == 'FAIL'
    assert report['checks']['manifest_schema'] == 'PASS'
    assert [item['status'] for item in report['query_samples']['items']] == ['STRUCTURE_ADMITTED', 'FAIL', 'FAIL', 'FAIL']
    assert len(report['issues']) == 3 and all(issue['remedy'] for issue in report['issues'])
    assert 'PRIVATE_' not in json.dumps(report) and snapshot(app) == before


@pytest.mark.parametrize('queries', [None, [], (None,) * 129])
def test_invalid_query_sample_container_refuses_before_database_access(app, monkeypatch, queries):
    database, mapping, _, _ = app
    def forbidden():
        pytest.fail('invalid query samples attempted database access')
    monkeypatch.setattr(database, 'connect', forbidden)
    report = preflight(json.dumps(declaration()).encode(), mapping, database,
                       writers=inventory(), search_reviews=reviews(), queries=queries)
    assert report['status'] == report['checks']['query_routes'] == 'FAIL'
    assert report['issues'][0]['code'] == 'Query.InvalidSamples'


def test_query_inspection_failure_stays_unknown_and_redacted(app, monkeypatch):
    from sqlalchemy import select
    from cryptalis.sqlalchemy import _Attachment
    database, mapping, Customer, _ = app
    def unavailable(*args, **kwargs):
        raise RuntimeError('PRIVATE_QUERY_INSPECTION')
    monkeypatch.setattr(_Attachment, 'admit', unavailable)
    report = preflight(json.dumps(declaration()).encode(), mapping, database,
                       writers=inventory(), search_reviews=reviews(), queries=(select(Customer),))
    assert report['status'] == report['checks']['query_routes'] == report['checks']['query_samples'] == 'UNKNOWN'
    assert report['checks']['manifest_schema'] == 'PASS'
    assert report['issues'][0]['code'] == 'Query.InspectionUnavailable'
    assert 'PRIVATE_' not in json.dumps(report)


def test_mapped_insert_samples_use_runtime_structure_checks_without_rows_keys_or_type_changes(app, monkeypatch):
    from sqlalchemy import insert, select
    from cryptalis.sqlalchemy import _Attachment
    database, mapping, Customer, schema = app
    before, original_type = snapshot(app), Customer.email.type
    def forbidden(*args, **kwargs):
        pytest.fail('INSERT diagnosis attempted attachment or key resolution')
    for method in ('activate', 'validate', '_ring'):
        monkeypatch.setattr(_Attachment, method, forbidden)
    def readonly(connection, cursor, statement, parameters, context, many):
        assert connection.get_execution_options()['postgresql_readonly'] is True
        assert not re.search(r'\bFROM\s+(?:"?' + re.escape(schema) + r'"?\.)?"?customer\b',
                             statement, re.IGNORECASE)
    queries = (insert(Customer), insert(Customer).returning(Customer.id, Customer.email),
               insert(Customer).returning(Customer), select(Customer.id))
    event.listen(database, 'before_cursor_execute', readonly)
    try:
        report = preflight(json.dumps(declaration()).encode(), mapping, database,
                           writers=inventory(), search_reviews=reviews(), queries=queries)
    finally:
        event.remove(database, 'before_cursor_execute', readonly)
    assert report['checks']['query_samples'] == 'PASS'
    assert report['status'] == report['checks']['query_routes'] == 'UNKNOWN'
    assert report['checks']['provider_keys'] == report['checks']['writer_exclusion'] == 'UNKNOWN'
    assert report['query_samples']['scope'] == 'supplied_statement_structures'
    assert report['query_samples']['execution'] == 'NOT_PERFORMED'
    assert [item['status'] for item in report['query_samples']['items']] == ['STRUCTURE_ADMITTED'] * 4
    assert [item['parameters'] for item in report['query_samples']['items'][:3]] == ['NOT_INSPECTED'] * 3
    assert Customer.email.type is original_type and snapshot(app) == before


@pytest.mark.parametrize('shape', ['core', 'values', 'defaults', 'expression', 'alias', 'loader'])
def test_unadmitted_insert_samples_fail_safely_without_sql_or_value_disclosure(app, shape):
    from sqlalchemy import func, insert
    from sqlalchemy.orm import aliased, load_only
    database, mapping, Customer, _ = app
    before = snapshot(app)
    samples = {
        'core': insert(Customer.__table__),
        'values': insert(Customer).values(email='PRIVATE_INSERT_VALUE'),
        'defaults': insert(Customer).return_defaults(),
        'expression': insert(Customer).returning(func.lower(Customer.email)),
        'alias': insert(Customer).returning(aliased(Customer)),
        'loader': insert(Customer).returning(Customer).options(load_only(Customer.email)),
    }
    report = preflight(json.dumps(declaration()).encode(), mapping, database,
                       writers=inventory(), search_reviews=reviews(), queries=(samples[shape],))
    assert report['status'] == report['checks']['query_samples'] == 'FAIL'
    assert report['issues'][0]['code'] == 'Query.UnsupportedStructure'
    assert report['query_samples']['items'][0]['parameters'] == 'NOT_INSPECTED'
    assert 'PRIVATE_' not in json.dumps(report)
    assert snapshot(app) == before
