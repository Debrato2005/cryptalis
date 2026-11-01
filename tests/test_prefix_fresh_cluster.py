"""Exact-prefix backup adoption keeps native pattern indexes and latest committed data."""
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import psycopg
import pytest

from sqlalchemy import select
from sqlalchemy.orm import Session

from cryptalis import migration as m, restore as recovery
from test_date_lifecycle import date_keys, remove_date, rotate_all
from test_deprotection import app_pin
from test_migration import publish, run, TENANT
from test_prefix_lifecycle import attached_prefix, native_indexes, native_restart, prefix_application
from test_prefix_search import WRITE, observe

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --prefix', allow_module_level=True)

from test_fresh_cluster_export import dump, environment
from test_fresh_boolean_restore import restore_dump

pytestmark = pytest.mark.prefix_qualification


def wire(values):
    return {str(identity): value for identity, value in values.items()}


def answers(session, model):
    return json.loads(json.dumps(observe(session, model), default=str))


def test_export_prefix_backup_after_rotations_and_current_edits():
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
    with prefix_application(public_slots=public_slots) as app:
        with app.owner.connect() as connection:
            indexes = native_indexes(connection, app.schema)
            slots = [list(row) for row in connection.exec_driver_sql(
                'SELECT attname,attnum FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass(%s) '
                'AND attnum>0 AND NOT attisdropped ORDER BY attnum', (f'"{app.schema}".customer',))]
        with Session(app.runtime) as session:
            original = {row.id: row.name for row in session.scalars(select(app.Customer))}
            original_answers = answers(session, app.Customer)
            session.get(app.Customer, UUID(int=102)).name = WRITE
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT, name='fresh_%prefix'))
            session.flush()
            expected = {row.id: row.name for row in session.scalars(select(app.Customer))}
            expected_answers = answers(session, app.Customer)
            session.rollback()
        dump(directory / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app); rotate_all(app)
        with attached_prefix(app, resolver=date_keys) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert answers(session, Customer) == original_answers
                session.get(Customer, UUID(int=102)).name = WRITE
                session.delete(session.get(Customer, UUID(int=106)))
                session.add(Customer(id=UUID(int=999), tenant_id=TENANT, name='fresh_%prefix'))
                session.commit()
                assert answers(session, Customer) == expected_answers
        dump(directory / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = dict(application_profile='text-prefix', public_slots=public_slots,
            source_public_slots=slots if public_slots else None, native_pattern_indexes=indexes,
            database=owner['dbname'], owner_role=owner['user'], runtime_role=runtime['user'], schema=app.schema,
            source=wire(original), expected=wire(expected), expected_answers=expected_answers,
            plan=base64.b64encode(app.plan.artifact).decode(), pin=dict(target_id=str(app.pin.target_id),
                operation_id=str(app.pin.operation_id), plan_digest=app.pin.plan_digest, phase=app.pin.phase))
    (directory / 'restore-manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')


def test_restore_prefix_authentication_pattern_indexes_latest_native_and_package_free_exit():
    from test_migration import engine
    directory = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    manifest = json.loads((directory / 'restore-manifest.json').read_text())
    assert manifest['application_profile'] == 'text-prefix'
    schema = manifest['schema']
    restore_dump(directory / 'plain.sql', os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE'])
    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                         dbname=os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']) as connection:
        assert wire(dict(connection.execute(f'SELECT id,name FROM "{schema}".customer').fetchall())) == manifest['source']
    restore_dump(directory / 'protected.sql')
    source = m.MigrationPlan(base64.b64decode(manifest['plan'], validate=True))
    pin = app_pin(source, 'ACTIVE')
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    maintenance = m.MaintenanceApproval('Source schema removed; isolated fresh target excludes all writers.', 3600)
    intent = recovery.RestoreApproval('qualification host', 'adopt exact prefix protected backup',
                                     'source schema dropped and fresh target quarantined', True)
    app = SimpleNamespace(schema=schema, owner=owner, plan=source, pin=pin, approval=maintenance)
    try:
        with pytest.raises(m.TransitionFailure):
            m.check_deployment(source, owner, pin=pin)
        with owner.connect() as connection:
            frame = bytes(connection.exec_driver_sql(f'SELECT name FROM "{schema}".customer WHERE id=%s',
                                                      (UUID(int=102),)).scalar_one())
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s',
                                      (frame[:-1] + bytes([frame[-1] ^ 1]), UUID(int=102)))
        with pytest.raises(m.TransitionFailure):
            recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{schema}".customer SET name=%s WHERE id=%s', (frame, UUID(int=102)))
        binding = recovery.plan(source, owner, pin=pin, keys=date_keys, approval=intent)
        with attached_prefix(app, resolver=date_keys, restore=binding) as (Customer, factory):
            with factory(tenant_id=TENANT) as session:
                assert answers(session, Customer) == manifest['expected_answers']
                current = {row.id: row.name for row in session.scalars(select(Customer))}
                assert wire(current) == manifest['expected']
                session.get(Customer, UUID(int=999)).name = 'after_restore_%prefix' + (' current' * 12)
                session.commit()
                assert session.scalar(select(Customer.id).where(Customer.tenant_id == TENANT,
                    Customer.name.startswith('after_restore_', autoescape=True))) == UUID(int=999)
                current[UUID(int=999)] = session.get(Customer, UUID(int=999)).name
        remove_date(app, restore=binding, plaintext_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'])
        with owner.connect() as connection:
            assert [list(row) for row in native_indexes(connection, schema)] == manifest['native_pattern_indexes']
            if manifest['public_slots']:
                slots = [list(row) for row in connection.exec_driver_sql('SELECT attname,attnum '
                    'FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass(%s) '
                    'AND attnum>0 AND NOT attisdropped ORDER BY attnum', (f'"{schema}".customer',))]
                assert slots == manifest['source_public_slots']
        native_restart(schema, current, directory)
        (directory / 'prefix-journey-receipt.json').write_text(json.dumps(dict(
            source_plan_digest=source.digest, restore_adoption_id=binding.document['adoption_id'],
            profile='exact text prefixes, three rotations, native pattern indexes, fresh PostgreSQL16 adoption and latest removal',
            tampered_frame='refused before adoption', native_pattern_indexes='restored',
            package_free_restart='passed', gates='all seven UNKNOWN'), sort_keys=True) + '\n')
    finally:
        owner.dispose()
