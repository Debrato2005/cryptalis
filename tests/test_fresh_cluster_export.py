"""Export a protected fixture schema for fresh-cluster recovery qualification.

This module runs against the primary test cluster. It writes a plaintext
pre-protection dump, a protected dump after real attached edits, and a
manifest of expected values and retained artifacts. It never writes
credentials.
"""
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import String

from cryptalis import migration as m, rotation as r
from cryptalis.sqlalchemy import attach
from test_deprotection import catalog_metadata, column_acl
from test_migration import application, frames, keys, publish, run, TENANT, FIELD_ID
from rewrap_worker import target_keys

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py', allow_module_level=True)

EDITED_ID, ADDED_ID, DELETED_ID = UUID(int=101), UUID(int=999), UUID(int=106)


def source_metadata_fixture(connection, schema, role):
    table = f'"{schema}".customer'
    frame = '_cryptalis_' + FIELD_ID.hex + '_frame'
    connection.exec_driver_sql(f'CREATE TABLE "{schema}".z_frame_reference '
                               f'(customer_id uuid CONSTRAINT "{frame}" REFERENCES {table}(id))')
    connection.exec_driver_sql(f"COMMENT ON TABLE {table} IS 'table comment'")
    connection.exec_driver_sql(f"COMMENT ON COLUMN {table}.label IS 'plain column comment'")
    connection.exec_driver_sql(f"COMMENT ON COLUMN {table}.name IS 'protected column comment'")
    quoted_role = connection.dialect.identifier_preparer.quote(role)
    connection.exec_driver_sql(f'GRANT SELECT (name) ON {table} TO {quoted_role} WITH GRANT OPTION')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STATISTICS 500')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET STORAGE EXTERNAL')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET COMPRESSION pglz')
    connection.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN name SET (n_distinct=10)')
    connection.exec_driver_sql(f"COMMENT ON CONSTRAINT customer_pkey ON {table} IS 'primary key comment'")
    connection.exec_driver_sql(f"COMMENT ON INDEX \"{schema}\".native_name IS 'index comment'")
    connection.exec_driver_sql(f'ALTER INDEX "{schema}".native_name SET (fillfactor=70)')
    connection.exec_driver_sql(f'CREATE STATISTICS "{schema}".name_stats (ndistinct, dependencies) '
                               f'ON name, label FROM {table}')
    connection.exec_driver_sql(f'ALTER STATISTICS "{schema}".name_stats SET STATISTICS 700')
    connection.exec_driver_sql(f"COMMENT ON STATISTICS \"{schema}\".name_stats IS 'protected statistics comment'")


def assert_source_metadata(app, role):
    """Native catalog oracle, independent of compiler capture/restore helpers."""
    table, columns, index, constraint, statistics = catalog_metadata(app)
    assert table == 'table comment'
    assert columns['label'][0] == 'plain column comment'
    comment, target, storage, _, compression, options = columns['name']
    assert (comment, target, storage, compression, options) == (
        'protected column comment', 500, 'e', 'p', '{n_distinct=10}')
    assert column_acl(app, 'name') == {(role, 'SELECT', True)}
    assert index == ('{fillfactor=70}', 'index comment')
    assert constraint == 'primary key comment'
    assert statistics[:3] == (['d', 'f'], 700, 'protected statistics comment')
    assert sorted(statistics[3]) == ['label', 'name']


def environment(variable, database=None):
    parsed = psycopg.conninfo.conninfo_to_dict(os.environ[variable])
    return dict(os.environ, PGHOST=parsed.get('host', ''),
                PGPORT=parsed.get('port', '5432'), PGUSER=parsed['user'],
                PGPASSWORD=parsed['password'], PGDATABASE=database or parsed['dbname'])


def dump(path, schema, environment_values):
    with path.open('wb') as stream:
        result = subprocess.run(['pg_dump', '--schema=' + schema],
                                env=environment_values, stdout=stream, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'pg_dump failed (diagnostics withheld)'


def attached_edits(app):
    sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                      deployment=(app.plan, app.pin))
    with sessions(tenant_id=TENANT) as session:
        session.get(app.Customer, EDITED_ID).name = 'edited while protected'
        session.commit()
        session.add(app.Customer(id=ADDED_ID, tenant_id=TENANT,
                                 name='added while protected', label='fresh'))
        session.commit()
        session.delete(session.get(app.Customer, DELETED_ID))
        session.commit()


def test_export_fresh_cluster_source():
    workdir = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    varchar = os.environ.get('CRYPTALIS_FRESH_SOURCE_VARCHAR') == '1'
    rewrapped = os.environ.get('CRYPTALIS_FRESH_SOURCE_REWRAP') == '1'
    with application(setup=source_metadata_fixture,
                     value_type=String(64, collation='C') if varchar else None) as app:
        assert_source_metadata(app, app.role)
        parsed = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app)
        publish(app)
        attached_edits(app)
        if rewrapped:
            before = frames(app, True)
            proposal = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin,
                                     keys=keys, target_keys=target_keys,
                                     verify_rows_per_second=1000)
            successor = proposal.activation_plan
            pin = m.DeploymentPin(successor.target_id, successor.operation_id, successor.digest, 'PREPARED')
            assert r.apply_rewrap(proposal, app.owner, keys=keys, target_keys=target_keys,
                                   pin=pin, approval=app.approval).phase == 'PENDING'
            app.plan, app.pin = successor, replace(pin, phase='ACTIVATING')
            assert m.apply(app.plan, app.owner, keys=target_keys, pin=app.pin,
                           approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
            app.pin = replace(app.pin, phase='ACTIVE')
            assert frames(app, True) == before
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        model = app.plan.document['lock']['models'][0]
        field = model['fields'][0]
        expected = {str(identity): [str(tenant), value] for identity, (tenant, value) in app.source.items()}
        expected[str(EDITED_ID)] = [str(TENANT), 'edited while protected']
        expected[str(ADDED_ID)] = [str(TENANT), 'added while protected']
        del expected[str(DELETED_ID)]
        manifest = {
            'rewrapped': rewrapped,
            'native_type': 'varchar' if varchar else 'text', 'native_limit': 64 if varchar else None,
            'database': parsed['dbname'], 'owner_role': parsed['user'], 'runtime_role': runtime['user'],
            'schema': app.schema, 'column': field['column'], 'field_id': field['field_id'],
            'descriptor': field['descriptor'], 'descriptor_digest': field['descriptor_digest'],
            'tenant_id': str(TENANT), 'expected': expected,
            'source': {str(identity): [str(tenant), value] for identity, (tenant, value) in app.source.items()},
            'deleted_id': str(DELETED_ID), 'added_id': str(ADDED_ID),
            'plan': base64.b64encode(app.plan.artifact).decode('ascii'),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase},
            'target': app.plan.document['target'], 'journal_schema': app.plan.document['journal_schema'],
        }
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
