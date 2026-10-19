"""End-to-end independent application adoption, decrypt-back, and package-free exit.

The application module imports no Cryptalis component. A host creates the
schema, protects it, attaches the same registries at runtime, then reverses,
removes, and restarts the application in a fresh process with Cryptalis
imports blocked.
"""
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from sqlalchemy import text

import cryptalis.deprotection as d
import cryptalis.migration as m
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.sqlalchemy import attach
from test_deprotection import least_privilege_role
from test_migration import DOMAIN, engine, keys

ACCOUNT_FIELD, CUSTOMER_FIELD, NOTE_FIELD = (UUID(int=i) for i in range(701, 704))
ACCOUNT_TABLE, CUSTOMER_TABLE, NOTE_TABLE = (UUID(int=i) for i in range(711, 714))
TENANT_A, TENANT_B = UUID(int=721), UUID(int=722)
ACCOUNT_A1, ACCOUNT_A2, ACCOUNT_B = UUID(int=731), UUID(int=732), UUID(int=733)
CUSTOMERS = {name: UUID(int=740 + index) for index, name in enumerate(
    ('plain', 'empty', 'unicode', 'decomposed', 'composed', 'trailing'), start=1)}
NEW_CUSTOMER, CHILD_CUSTOMER = UUID(int=747), UUID(int=748)
NOTE_1, NOTE_2, CHILD_NOTE = UUID(int=751), UUID(int=752), UUID(int=753)


def seed_payload():
    return {
        str(TENANT_A): {
            'accounts': [{'id': ACCOUNT_A1, 'display_name': 'Alpha account'},
                         {'id': ACCOUNT_A2, 'display_name': 'B\u00e9ta \u96ea'}],
            'customers': [
                {'id': CUSTOMERS['plain'], 'account_id': ACCOUNT_A1, 'name': 'plain', 'note': 'n1'},
                {'id': CUSTOMERS['empty'], 'account_id': ACCOUNT_A1, 'name': '', 'note': None},
                {'id': CUSTOMERS['unicode'], 'account_id': ACCOUNT_A1, 'name': '\u96ea\U0001f600', 'note': 'n3'},
                {'id': CUSTOMERS['decomposed'], 'account_id': ACCOUNT_A1, 'name': 'e\u0301', 'note': None},
                {'id': CUSTOMERS['composed'], 'account_id': ACCOUNT_A2, 'name': '\u00e9', 'note': 'n5'},
                {'id': CUSTOMERS['trailing'], 'account_id': ACCOUNT_A2, 'name': 'trailing ', 'note': 'n6'},
            ]},
        str(TENANT_B): {'accounts': [{'id': ACCOUNT_B, 'display_name': 'Gamma'}],
                        'customers': [], 'notes': []},
    }


def declaration():
    return {'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(DOMAIN),
            'models': [
                {'model': 'Account', 'table_id': str(ACCOUNT_TABLE), 'tenancy': {'column': 'tenant_id'},
                 'fields': [{'name': 'display_name', 'field_id': str(ACCOUNT_FIELD), 'protect': True,
                             'queries': ['equality'], 'accept_leakage': ['equality']}]},
                {'model': 'Customer', 'table_id': str(CUSTOMER_TABLE), 'tenancy': {'column': 'tenant_id'},
                 'fields': [{'name': 'name', 'field_id': str(CUSTOMER_FIELD), 'protect': True,
                             'queries': ['equality', 'unique'], 'accept_leakage': ['equality', 'unique']}]},
                {'model': 'Note', 'table_id': str(NOTE_TABLE), 'tenancy': {'column': 'tenant_id'},
                 'fields': [{'name': 'body', 'field_id': str(NOTE_FIELD), 'protect': True,
                             'queries': ['equality'], 'accept_leakage': ['equality']}]}]}


def expected_customers():
    return {str(CUSTOMERS['plain']): {'name': 'child edited', 'note': 'n1', 'account': str(ACCOUNT_A1)},
            str(CUSTOMERS['unicode']): {'name': '\u96ea\U0001f600', 'note': 'n3', 'account': str(ACCOUNT_A1)},
            str(CUSTOMERS['decomposed']): {'name': 'edited under protection', 'note': None, 'account': str(ACCOUNT_A1)},
            str(CUSTOMERS['trailing']): {'name': 'trailing ', 'note': 'n6', 'account': str(ACCOUNT_A2)},
            str(NEW_CUSTOMER): {'name': 'added \u96ea', 'note': None, 'account': str(ACCOUNT_A1)},
            str(CHILD_CUSTOMER): {'name': 'child \u96ea', 'note': None, 'account': str(ACCOUNT_A1)}}


def expected_notes():
    return {str(NOTE_1): None, str(NOTE_2): 'note \u96ea', str(CHILD_NOTE): None}


def expected_accounts():
    return {str(ACCOUNT_A1): 'child renamed', str(ACCOUNT_A2): 'B\u00e9ta \u96ea'}


def plain_sql_read(connection, schema):
    with psycopg.connect(connection) as c:
        customers = c.execute(
            f'SELECT id, name, note, account_id FROM "{schema}".customer ORDER BY id').fetchall()
        notes = c.execute(f'SELECT id, body FROM "{schema}".note ORDER BY id').fetchall()
        accounts = c.execute(f'SELECT id, display_name FROM "{schema}".account ORDER BY id').fetchall()
    return ({str(identity): {'name': name, 'note': note, 'account': str(account)}
             for identity, name, note, account in customers},
            {str(identity): body for identity, body in notes},
            {str(identity): display for identity, display in accounts})


def package_free_run(schema, database_url, script):
    environment = dict(os.environ, CRYPTALIS_FORBIDDEN='1', APP_SCHEMA=schema,
                       APP_DATABASE_URL=database_url, PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, str(Path(__file__).with_name('independent_app.py')),
                           'crud', json.dumps(script)],
                          env=environment, capture_output=True, text=True, timeout=120)


def test_independent_application_adopts_reverses_and_restarts_package_free():
    schema = 'independent_app_' + uuid4().hex
    os.environ['APP_SCHEMA'] = schema
    sys.modules.pop('independent_app', None)
    app = importlib.import_module('independent_app')
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
        role = c.execute('SELECT current_user').fetchone()[0]
    try:
        with owner.begin() as c:
            c.execute(text(f'CREATE SCHEMA "{schema}"'))
        app.init(owner)
        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as c:
            c.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(
                sql.Identifier(schema), sql.Identifier(role)))
            for table in ('account', 'customer', 'note'):
                c.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON {}.{} TO {}').format(
                    sql.Identifier(schema), sql.Identifier(table), sql.Identifier(role)))
        app.seed(app.simple_sessions(owner), seed_payload())
        baseline = plain_sql_read(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], schema)
        assert baseline[0][str(CUSTOMERS['unicode'])]['name'] == '\u96ea\U0001f600'

        writers = WriterInventory(True, tuple(
            Writer(table, 'independent application', 'sqlalchemy', evidence='owned independent application')
            for table in (ACCOUNT_TABLE, CUSTOMER_TABLE, NOTE_TABLE)))
        reviews = tuple(SearchReview(field, False, 'independent application exact text')
                        for field in (ACCOUNT_FIELD, CUSTOMER_FIELD, NOTE_FIELD))
        protection = m.plan(json.dumps(declaration()).encode(), app.Base.registry, owner,
                            writers=writers, search_reviews=reviews, keys=keys, runtime_role=role,
                            target_id=uuid4(), backfill_rows_per_second=1000,
                            verify_rows_per_second=1000, temporary_bytes_per_row=700,
                            wal_bytes_per_row=2000)
        pin = m.DeploymentPin(protection.target_id, protection.operation_id, protection.digest, 'PREPARED')
        approval = m.MaintenanceApproval(
            'test operator stopped inventoried workers and excluded owner writers', 3600)
        m.apply(protection, owner, keys=keys, pin=pin, approval=approval)
        m.apply(protection, owner, keys=keys, pin=replace(pin, phase='ACTIVATING'),
                approval=approval, until='ACTIVE')
        pin = replace(pin, phase='ACTIVE')
        sessions = attach(app.Base.registry, runtime, lock=protection.lock_bytes, keys=keys,
                          deployment=(protection, pin))
        assert app.read(sessions, str(TENANT_A)) == {str(identity): {'name': value, 'note': note,
                                                                     'account': str(account)}
            for identity, value, note, account in [
                (CUSTOMERS['plain'], 'plain', 'n1', ACCOUNT_A1),
                (CUSTOMERS['empty'], '', None, ACCOUNT_A1),
                (CUSTOMERS['unicode'], '\u96ea\U0001f600', 'n3', ACCOUNT_A1),
                (CUSTOMERS['decomposed'], 'e\u0301', None, ACCOUNT_A1),
                (CUSTOMERS['composed'], '\u00e9', 'n5', ACCOUNT_A2),
                (CUSTOMERS['trailing'], 'trailing ', 'n6', ACCOUNT_A2)]}
        assert app.search(sessions, str(TENANT_A), '\u96ea\U0001f600') == [str(CUSTOMERS['unicode'])]
        assert app.search(sessions, str(TENANT_A), 'trailing ') == [str(CUSTOMERS['trailing'])]
        assert app.search(sessions, str(TENANT_A), 'trailing') == []

        app.edit_customer(sessions, str(TENANT_A), str(CUSTOMERS['decomposed']), 'edited under protection')
        app.edit_account(sessions, str(TENANT_A), str(ACCOUNT_A1), 'renamed under protection')
        app.add_customer(sessions, str(TENANT_A), str(NEW_CUSTOMER), str(ACCOUNT_A1), 'added \u96ea')
        app.delete_customer(sessions, str(TENANT_A), str(CUSTOMERS['composed']))
        app.add_note(sessions, str(TENANT_A), str(NOTE_1), str(ACCOUNT_A1))
        app.add_note(sessions, str(TENANT_A), str(NOTE_2), str(ACCOUNT_A2), 'note \u96ea')
        assert app.read_notes(sessions, str(TENANT_A)) == {str(NOTE_1): None, str(NOTE_2): 'note \u96ea'}
        assert app.read(sessions, str(TENANT_B)) == {}

        plaintext_role = least_privilege_role(SimpleNamespace(owner=owner, role=role))
        reverse_plan = d.plan(protection, owner, source_pin=pin, keys=keys,
                              plaintext_runtime_role=plaintext_role,
                              backfill_rows_per_second=1000, verify_rows_per_second=1000,
                              temporary_bytes_per_row=700, wal_bytes_per_row=700)
        consent = d.PlaintextApproval(reverse_plan.target_id, reverse_plan.operation_id,
                                      reverse_plan.digest, True, 'synthetic public backup recovery evidence')

        def reverse_pin(phase):
            return m.DeploymentPin(reverse_plan.target_id, reverse_plan.operation_id, reverse_plan.digest, phase)

        assert d.apply(reverse_plan, owner, keys=keys, pin=reverse_pin('PREPARED'),
                       approval=approval, consent=consent, until='PLAINTEXT_PENDING').phase == 'PLAINTEXT_PENDING'
        assert d.apply(reverse_plan, owner, keys=keys, pin=reverse_pin('PLAINTEXT_ACTIVATING'),
                       approval=approval, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        removal = d.RemovalApproval(reverse_plan.target_id, reverse_plan.operation_id, reverse_plan.digest,
                                    'synthetic package-free workload run', 'synthetic backup recovery', True)
        assert d.remove(reverse_plan, owner, pin=reverse_pin('REMOVING'), approval=approval,
                        removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(reverse_plan, owner, pin=reverse_pin('REMOVED')) is None

        with owner.connect() as c:
            for model in protection.document['lock']['models']:
                assert d._metadata_diff(model['source_schema'], m._facts(c, model)) == []
        observed = plain_sql_read(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], schema)
        assert observed[0] == {str(NEW_CUSTOMER): {'name': 'added \u96ea', 'note': None,
                                                   'account': str(ACCOUNT_A1)},
                               str(CUSTOMERS['plain']): {'name': 'plain', 'note': 'n1',
                                                         'account': str(ACCOUNT_A1)},
                               str(CUSTOMERS['empty']): {'name': '', 'note': None,
                                                         'account': str(ACCOUNT_A1)},
                               str(CUSTOMERS['unicode']): {'name': '\u96ea\U0001f600', 'note': 'n3',
                                                           'account': str(ACCOUNT_A1)},
                               str(CUSTOMERS['decomposed']): {'name': 'edited under protection',
                                                              'note': None, 'account': str(ACCOUNT_A1)},
                               str(CUSTOMERS['trailing']): {'name': 'trailing ', 'note': 'n6',
                                                            'account': str(ACCOUNT_A2)}}
        script = {'tenant': str(TENANT_A), 'ops': [
            {'function': 'edit_customer', 'customer_id': str(CUSTOMERS['plain']), 'name': 'child edited'},
            {'function': 'edit_account', 'account_id': str(ACCOUNT_A1), 'display_name': 'child renamed'},
            {'function': 'add_customer', 'customer_id': str(CHILD_CUSTOMER), 'account_id': str(ACCOUNT_A1),
             'name': 'child \u96ea'},
            {'function': 'delete_customer', 'customer_id': str(CUSTOMERS['empty'])},
            {'function': 'add_note', 'note_id': str(CHILD_NOTE), 'account_id': str(ACCOUNT_A2)}]}
        child = package_free_run(schema, os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], script)
        assert child.returncode == 0, 'package-free application run failed'
        assert 'cryptalis' not in (child.stdout + child.stderr).lower()
        assert json.loads(child.stdout) == {'customers': expected_customers(), 'notes': expected_notes(),
                                            'accounts': expected_accounts()}
        final = plain_sql_read(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], schema)
        assert final == (expected_customers(), expected_notes(),
                         dict(expected_accounts(), **{str(ACCOUNT_B): 'Gamma'}))
    finally:
        runtime.dispose()
        with owner.begin() as c:
            c.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        owner.dispose()
        app.Base.registry.dispose()
