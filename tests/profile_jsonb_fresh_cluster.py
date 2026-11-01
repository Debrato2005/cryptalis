"""Actual fresh-cluster JSONB adoption retains exact native current wire bytes."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import ColumnDefault, JSON, select
from sqlalchemy.orm import Session

from cryptalis import migration as m, restore as recovery
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_keys, remove_date, rotate_all
from test_jsonb_lifecycle import (document_wire, encoded_wire, jsonb_application, native_restart,
                                 native_wire, protected_wire)
from test_jsonb_storage import LATEST, current_edits, mapping_for, values
from test_jsonb_defaults import DEFAULT, native_default_restart
from test_migration import engine, keys, publish, run, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --jsonb', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump


def test_export_jsonb_backup_after_three_rotations_and_current_edits():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
    default = deepcopy(DEFAULT) if os.environ.get('CRYPTALIS_FRESH_JSONB_DEFAULTS') == '1' else None
    with jsonb_application(public_slots=public_slots, value_default=default) as app:
        from test_public_slots import slots
        original_slots = [list(row) for row in slots(app)[1]] if public_slots else None
        source_wire = native_wire(app)
        with Session(app.runtime) as session:
            current_edits(session, app.Customer)
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.flush()
            expected_wire = native_wire(app, connection=session.connection())
            expected_values = json.loads(json.dumps(values(session, app.Customer), default=str))
            session.rollback()
        dump(directory / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        assert protected_wire(app, keys) == source_wire
        rotate_all(app)
        assert protected_wire(app, date_keys) == source_wire
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            current_edits(session, app.Customer)
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.commit()
            assert json.loads(json.dumps(values(session, app.Customer), default=str)) == expected_values
        assert protected_wire(app, date_keys) == expected_wire
        dump(directory / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': 'jsonb-storage', 'application_default': default,
            'none_as_null': False, 'public_slots': public_slots, 'source_public_slots': original_slots,
            'database': owner['dbname'], 'owner_role': owner['user'], 'runtime_role': runtime['user'],
            'schema': app.schema, 'source_wire': encoded_wire(source_wire),
            'expected_wire': encoded_wire(expected_wire), 'expected_values': expected_values,
            'plan': base64.b64encode(app.plan.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
    (directory / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def test_restore_jsonb_authentication_current_edits_native_wire_and_package_free_exit():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'jsonb-storage' and manifest['none_as_null'] is False
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        rows = {identity: (sql_null, None if body is None else bytes(body))
                for identity, sql_null, body in connection.execute(
                    f'SELECT id,name IS NULL,pg_catalog.jsonb_send(name) FROM "{schema}".customer')}
        assert encoded_wire(rows) == manifest['source_wire']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    raw = manifest['pin']
    pin = m.DeploymentPin(UUID(raw['target_id']), UUID(raw['operation_id']), raw['plan_digest'], raw['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, table, Customer = mapping_for(schema, False)
    if manifest['application_default'] is not None:
        table.c.name.default = ColumnDefault(manifest['application_default'])
    approval = m.MaintenanceApproval('Source schema dropped; isolated restored target excludes all writers.', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt lossless JSONB protected backup',
                                     'source export is terminal and restored target is quarantined', True)
    app = SimpleNamespace(owner=owner, schema=schema, plan=source, pin=pin, approval=approval)
    try:
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            identity, frame = connection.exec_driver_sql(
                f'SELECT id,name FROM "{schema}".customer WHERE name IS NOT NULL ORDER BY id LIMIT 1').one()
            frame = bytes(frame)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                                      (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with pytest.raises(m.TransitionFailure) as tampered:
            recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        assert tampered.value.code == 'restored_frame_verification_failed'
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, identity))
        binding = recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        assert encoded_wire(protected_wire(app, date_keys)) == manifest['expected_wire']
        factory = attach(mapping, runtime, lock=source.lock_bytes, keys=date_keys, deployment=(source, pin, binding))
        edited = {'restored': [deepcopy(LATEST), '雪', None, 1e20]}
        with factory(tenant_id=TENANT) as session:
            assert json.loads(json.dumps(values(session, Customer), default=str)) == manifest['expected_values']
            assert session.scalar(select(Customer.id).where(Customer.label == 'label-100')) == UUID(int=100)
            session.get(Customer, UUID(int=910)).name = edited
            session.delete(session.get(Customer, UUID(int=101)))
            session.add(Customer(id=UUID(int=999), tenant_id=TENANT, name=JSON.NULL, label='restored current'))
            if manifest['application_default'] is not None:
                session.add(Customer(id=UUID(int=998), tenant_id=TENANT, label='restored omitted default'))
            session.commit()
            session.refresh(session.get(Customer, UUID(int=910)))
        expected = {UUID(identity): (sql_null, None if body is None else bytes.fromhex(body))
                    for identity, (sql_null, body) in manifest['expected_wire'].items()}
        with owner.connect() as connection:
            expected[UUID(int=910)] = document_wire(connection, edited)
            expected[UUID(int=999)] = document_wire(connection, None)
            if manifest['application_default'] is not None:
                expected[UUID(int=998)] = document_wire(connection, manifest['application_default'])
        del expected[UUID(int=101)]
        assert protected_wire(app, date_keys) == expected
        remove_date(app, restore=binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
        assert native_wire(app) == expected
        if manifest['public_slots']:
            from test_public_slots import slots
            assert [list(row) for row in slots(app)[1]] == manifest['source_public_slots']
        native_restart(schema, expected, directory=directory)
        if manifest['application_default'] is not None:
            native_default_restart(app, expected, none_as_null=False)
        (directory / 'jsonb-journey-receipt.json').write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'profile': 'JSONB exact native wire, three rotations, fresh PostgreSQL16 adoption, current-value removal',
            'none_as_null': False, 'public_slots': manifest['public_slots'],
            'literal_client_default': manifest['application_default'] is not None,
            'tampered_frame': 'refused before adoption', 'native_wire': 'exact jsonb_send bytes preserved',
            'package_free_restart': 'passed', 'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
