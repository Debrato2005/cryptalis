"""Genuine fresh-cluster DATE adoption authenticates before current-data exit."""
import base64
from datetime import date
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Column, Date, MetaData, Table, Text, Uuid, select
from sqlalchemy.orm import registry

from cryptalis import migration as m, restore as recovery
from cryptalis.sqlalchemy import attach
from test_date_lifecycle import date_application, date_keys, native_restart, remove_date, rotate_all
from test_migration import engine, frames, publish, run, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --date', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump


def wire(values):
    return {str(key): value.isoformat() if value is not None else None for key, value in values.items()}


def test_export_date_backup_after_rotations():
    workdir = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
    with date_application(public_slots=public_slots) as app:
        source_slots = None
        if public_slots:
            from test_public_slots import slots
            source_slots = [list(row) for row in slots(app)[1]]
        source = {identity: value for identity, (_, value) in app.source.items()}
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        rotate_all(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = date.max
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT))
            session.commit()
        expected = dict(source)
        expected[UUID(int=101)] = date.max
        expected[UUID(int=999)] = date.min
        del expected[UUID(int=106)]
        assert all(value is None or len(value) == 46 for value in frames(app, True).values())
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': 'date-storage', 'application_default': date.min.isoformat(),
            'public_slots': public_slots, 'source_public_slots': source_slots,
            'database': owner['dbname'], 'owner_role': owner['user'], 'runtime_role': runtime['user'],
            'schema': app.schema, 'source': wire(source), 'expected': wire(expected),
            'plan': base64.b64encode(app.plan.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')


def test_restore_date_authentication_explicit_adoption_latest_exit():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'date-storage'
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        assert wire(dict(connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall())) == manifest['source']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    raw = manifest['pin']
    pin = m.DeploymentPin(UUID(raw['target_id']), UUID(raw['operation_id']), raw['plan_digest'], raw['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
        Column('tenant_id', Uuid, nullable=False), Column('name', Date, default=date.min), Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    approval = m.MaintenanceApproval('source schema removed; isolated fresh target excludes all writers', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt DATE protected backup',
                                     'source schema dropped and target quarantined', True)
    try:
        with pytest.raises(m.TransitionFailure): m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            identity, frame = connection.exec_driver_sql(
                f'SELECT id,name FROM "{schema}".customer WHERE name IS NOT NULL ORDER BY id LIMIT 1').one()
            frame = bytes(frame)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                                      (frame[:-1] + bytes([frame[-1] ^ 1]), identity))
        with pytest.raises(m.TransitionFailure):
            recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, identity))
        binding = recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=date_keys, deployment=(source, pin, binding))
        with sessions(tenant_id=TENANT) as session:
            actual = {row.id: row.name for row in session.scalars(select(Customer))}
            assert wire(actual) == manifest['expected']
            assert all(value is None or type(value) is date for value in actual.values())
            session.get(Customer, UUID(int=999)).name = date(2026, 10, 27)
            session.commit()
        actual[UUID(int=999)] = date(2026, 10, 27)
        app = SimpleNamespace(owner=owner, plan=source, pin=pin, approval=approval)
        remove_date(app, restore=binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
        if manifest['public_slots']:
            with owner.connect() as connection:
                slots = connection.exec_driver_sql('SELECT attname,attnum FROM pg_catalog.pg_attribute '
                    'WHERE attrelid=pg_catalog.to_regclass(%s) AND attnum>0 AND NOT attisdropped ORDER BY attnum',
                    (f'"{schema}".customer',)).all()
            assert [list(row) for row in slots] == manifest['source_public_slots']
        native_restart(schema, actual, directory=directory)
        (directory / 'date-journey-receipt.json').write_text(json.dumps({
            'source_plan_digest': source.digest, 'restore_adoption_id': binding.document['adoption_id'],
            'profile': 'DATE storage, three rotations, fresh PostgreSQL16 adoption, latest-value removal',
            'tampered_frame': 'refused before adoption', 'package_free_restart': 'passed',
            'gates': 'all seven UNKNOWN'}, indent=2) + '\n')
    finally:
        runtime.dispose(); owner.dispose(); mapping.dispose()
