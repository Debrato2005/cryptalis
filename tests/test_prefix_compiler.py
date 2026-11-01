"""Prefix planning refusals preserve a real native application and its schema."""
from datetime import date
from decimal import Decimal

import pytest

from sqlalchemy import Boolean, Date, Integer, Numeric

from cryptalis.manifest.compiler import PlanningRejected
from cryptalis.manifest.parser import ManifestInvalid
from test_protection_compiler import (
    app, engine, compile_app, declaration, reviews, snapshot,
)

pytestmark = pytest.mark.prefix_qualification


def prefix_declaration():
    document = declaration(queries=('equality', 'prefix', 'unique'))
    field = document['models'][0]['fields'][0]
    field['accept_leakage'] = list(field['queries'])
    field['prefix_lengths'] = {'min': 1, 'max': 16}
    return document


def native_state(app):
    database, _, _, schema = app
    with database.connect() as connection:
        relations = connection.exec_driver_sql('''
            SELECT c.relname, c.relkind::text FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s ORDER BY c.relname
        ''', (schema,)).all()
        routines = connection.exec_driver_sql('''
            SELECT p.proname, p.prokind::text,
                   pg_catalog.pg_get_function_identity_arguments(p.oid)
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=%s ORDER BY p.proname, p.oid
        ''', (schema,)).all()
    return snapshot(app), relations, routines


def refused_without_effects(app, document, error_type, code=None, **options):
    before = native_state(app)
    with pytest.raises(error_type) as failure:
        compile_app(app, document, **options)
    if code is not None:
        assert code in {issue.code for issue in failure.value.issues}
        assert failure.value.effects == 'NONE'
        assert all(issue.remedy for issue in failure.value.issues)
    assert native_state(app) == before


@pytest.mark.parametrize('dtype,native_type,value', [
    (Numeric(8, 2), 'numeric(8,2)', Decimal('1.20')),
    (Boolean(), 'boolean', True),
    (Integer(), 'integer', 7),
    (Date(), 'date', date(2026, 11, 1)),
])
def test_prefix_nontext_source_refuses_with_typed_planning_error(app, dtype, native_type, value):
    database, _, Customer, schema = app
    with database.begin() as connection:
        # Existing Unicode addresses are deliberately replaced under native
        # application ownership before changing the source column's type.
        connection.exec_driver_sql(f'UPDATE "{schema}".customer SET email=NULL')
        connection.exec_driver_sql(f'ALTER TABLE "{schema}".customer ALTER COLUMN email '
                                   f'TYPE {native_type} USING NULL::{native_type}')
        connection.exec_driver_sql(f'UPDATE "{schema}".customer SET email=%s WHERE id='
                                   f'(SELECT id FROM "{schema}".customer ORDER BY id LIMIT 1)', (value,))
    Customer.__table__.c.email.type = dtype
    refused_without_effects(app, prefix_declaration(), PlanningRejected, 'unsupported_query')


@pytest.mark.parametrize('bounds', [None, {'min': 0, 'max': 16}, {'min': 3, 'max': 2},
                                    {'min': 1, 'max': 257}, {'min': True, 'max': 16}])
def test_prefix_missing_or_unbounded_lengths_refuse_before_source_effects(app, bounds):
    document = prefix_declaration()
    field = document['models'][0]['fields'][0]
    if bounds is None:
        del field['prefix_lengths']
    else:
        field['prefix_lengths'] = bounds
    refused_without_effects(app, document, ManifestInvalid)


@pytest.mark.parametrize('mutation', ['missing_acceptance', 'bounds_without_prefix', 'prefix_and_order'])
def test_prefix_inconsistent_intent_refuses_without_touching_native_data(app, mutation):
    document = prefix_declaration()
    field = document['models'][0]['fields'][0]
    if mutation == 'missing_acceptance':
        field['accept_leakage'].remove('prefix')
    elif mutation == 'bounds_without_prefix':
        field['queries'].remove('prefix')
        field['accept_leakage'].remove('prefix')
    else:
        field['queries'].append('order')
        field['accept_leakage'].append('order')
    refused_without_effects(app, document, ManifestInvalid)


@pytest.mark.parametrize('search_reviews,code', [((), 'search_domain_unknown'),
                                              (reviews(small=True), 'small_search_domain')])
def test_prefix_missing_or_small_domain_review_refuses_without_effects(app, search_reviews, code):
    refused_without_effects(app, prefix_declaration(), PlanningRejected, code,
                           search_reviews=search_reviews)


@pytest.mark.parametrize('shape,code', [
    ('partial', 'unsupported_index'), ('expression', 'unsupported_index'),
    ('include', 'unsupported_index'), ('unscoped_unique', 'unsupported_uniqueness'),
    ('undeclared_prefix', 'unsupported_index'),
])
def test_unsupported_native_pattern_index_is_preserved_on_refusal(app, shape, code):
    database, _, _, schema = app
    table = f'"{schema}".customer'
    definitions = {
        'partial': f'CREATE INDEX native_prefix ON {table} (email text_pattern_ops) WHERE email IS NOT NULL',
        'expression': f'CREATE INDEX native_prefix ON {table} (lower(email) text_pattern_ops)',
        'include': f'CREATE INDEX native_prefix ON {table} (email text_pattern_ops) INCLUDE(note)',
        'unscoped_unique': f'CREATE UNIQUE INDEX native_prefix ON {table} (email text_pattern_ops)',
        'undeclared_prefix': f'CREATE INDEX native_prefix ON {table} (email text_pattern_ops)',
    }
    with database.begin() as connection:
        connection.exec_driver_sql(definitions[shape])
    document = declaration() if shape == 'undeclared_prefix' else prefix_declaration()
    refused_without_effects(app, document, PlanningRejected, code)
