"""DATE values survive every rotation and latest-data native removal."""
from datetime import date
from contextlib import contextmanager
import json
import os
import subprocess
import sys
from uuid import UUID

import pytest
from sqlalchemy import Date, select

from cryptalis import deprotection as d, migration as m, rotation as r
from cryptalis.sqlalchemy import attach
from test_deprotection import app_pin, consent, least_privilege_role
from test_migration import application, frames, keys, publish, run, TENANT, TABLE_ID
from test_date_storage import VALUES
from rewrap_worker import target_keys as rewrapped_keys
from payload_rotation_worker import rotated_keys
from search_rotation_worker import target_keys as searched_keys


def date_keys(tenant):
    return searched_keys(tenant, source=rotated_keys)


@contextmanager
def date_application(*, public_slots=False):
    """Retain storage-only DATE alongside independently declared searchable text."""
    from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory, _canonical
    label_id = UUID(int=1211)
    def setup(connection, schema, role):
        connection.exec_driver_sql(f'CREATE INDEX native_label ON "{schema}".customer (label)')
    with application(value_type=Date(), queries=[], protected_values=VALUES,
                     value_default=date.min, setup=setup) as app:
        # ORM INSERT applies the native client default to None; create SQL NULL
        # through a subsequent native UPDATE so both values enter migration.
        with app.runtime.begin() as connection:
            for identity, (_, value) in app.source.items():
                if value is None:
                    connection.execute(app.table.update().where(app.table.c.id == identity).values(name=None))
        declaration = app.plan.document['lock']['declaration']
        declaration['models'][0]['fields'].append({'name': 'label', 'field_id': str(label_id),
            'protect': True, 'queries': ['equality'], 'accept_leakage': ['equality']})
        app.plan = m.plan(_canonical(declaration), app.mapping, app.owner,
            layout='preserve-public-slots/v1' if public_slots else None,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='public DATE/text fixture'),)),
            search_reviews=(SearchReview(label_id, False, 'synthetic distinct public labels'),), keys=keys,
            runtime_role=app.role, target_id=app.plan.target_id, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
        app.pin = app_pin(app.plan, 'PREPARED')
        yield app


def rotate_all(app):
    before = frames(app, True)
    root = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin,
        keys=keys, target_keys=rewrapped_keys, verify_rows_per_second=1000)
    assert r.apply_rewrap(root, app.owner, keys=keys, target_keys=rewrapped_keys,
        pin=app_pin(root.activation_plan, 'PREPARED'), approval=app.approval).phase == 'PENDING'
    assert m.apply(root.activation_plan, app.owner, keys=rewrapped_keys,
        pin=app_pin(root.activation_plan, 'ACTIVATING'), approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
    app.plan, app.pin = root.activation_plan, app_pin(root.activation_plan, 'ACTIVE')
    assert frames(app, True) == before
    source_keys = rewrapped_keys
    for purpose, target_keys in (('payload', rotated_keys), ('search', date_keys)):
        source, pin = app.plan, app.pin
        before = frames(app, True)
        preparation = getattr(r, 'plan_' + purpose + '_rotation')(
            source, app.owner, source_pin=pin, keys=source_keys, target_keys=target_keys,
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=2)
        operation_pin = m.DeploymentPin(source.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
        apply = getattr(r, 'apply_' + purpose + '_rotation')
        paused = apply(preparation, app.owner, keys=source_keys, target_keys=target_keys,
            pin=operation_pin, approval=app.approval, max_chunks=1)
        assert paused.phase == 'EXPANDED' and paused.committed_chunks == 1
        assert frames(app, True) == before
        assert apply(type(preparation)(preparation.artifact), app.owner, keys=source_keys,
            target_keys=target_keys, pin=operation_pin, approval=app.approval).phase == 'BACKFILLED'
        activation = getattr(r, 'seal_' + purpose + '_rotation')(
            preparation, app.owner, keys=source_keys, target_keys=target_keys,
            pin=operation_pin, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert getattr(r, 'switch_' + purpose + '_rotation')(
            preparation, activation, app.owner, keys=source_keys, target_keys=target_keys,
            pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=target_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        after = frames(app, True)
        if purpose == 'search':
            assert after == before
        else:
            assert all(after[key] != value if value is not None else after[key] is None
                       for key, value in before.items())
        with pytest.raises(m.TransitionFailure): m.check_deployment(source, app.owner, pin=pin)
        source_keys = target_keys


def remove_date(app, *, restore=None, plaintext_role=None):
    proposal = d.plan(app.plan, app.owner, source_pin=app.pin, keys=date_keys, restore=restore,
        plaintext_runtime_role=plaintext_role or least_privilege_role(app),
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048)
    pure, pin = consent(proposal)
    assert d.apply(proposal, app.owner, keys=date_keys, pin=pin, approval=app.approval,
        consent=pure, until='BACKFILLED', chunk_size=2).phase == 'BACKFILLED'
    assert d.apply(type(proposal)(proposal.artifact), app.owner, keys=date_keys, pin=pin,
        approval=app.approval, consent=pure).phase == 'PLAINTEXT_PENDING'
    assert d.apply(proposal, app.owner, keys=date_keys, pin=app_pin(proposal, 'PLAINTEXT_ACTIVATING'),
        approval=app.approval, consent=pure, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
        'native DATE current-value restart', 'public disposable DATE fixtures', True)
    assert d.remove(proposal, app.owner, pin=app_pin(proposal, 'REMOVING'), approval=app.approval,
                    removal=removal, consent=pure).phase == 'REMOVED'
    d.check_removed(proposal, app.owner, pin=app_pin(proposal, 'REMOVED'))


def native_restart(schema, expected, *, directory='/tmp'):
    child = subprocess.run([sys.executable, '-B', '-I', '-c', '''
import importlib.abc, json, os, sys
from datetime import date
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis import denied after removal')
sys.meta_path.insert(0, Deny())
import psycopg
from psycopg import sql
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as connection:
    rows = connection.execute(sql.SQL('SELECT id,name FROM {}.customer').format(
        sql.Identifier(os.environ['DATE_SCHEMA']))).fetchall()
    assert all(value is None or type(value) is date for _, value in rows)
    assert {str(key): value.isoformat() if value is not None else None for key, value in rows} == json.loads(os.environ['DATE_EXPECTED'])
    actual = connection.execute('SELECT a.atttypid::regtype::text FROM pg_catalog.pg_attribute a '
        'WHERE a.attrelid=pg_catalog.to_regclass(%s) AND a.attname=%s',
        ('"' + os.environ['DATE_SCHEMA'] + '".customer', 'name')).fetchone()[0]
    assert actual == 'date'
    connection.execute(sql.SQL('UPDATE {}.customer SET name=%s WHERE id=(SELECT min(id::text)::uuid FROM {}.customer)').format(
        sql.Identifier(os.environ['DATE_SCHEMA']), sql.Identifier(os.environ['DATE_SCHEMA'])), (date(2001, 1, 1),))
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print('native DATE package-free restart passed')
'''], env=dict(os.environ, DATE_SCHEMA=schema, DATE_EXPECTED=json.dumps({str(key):
        value.isoformat() if value is not None else None for key, value in expected.items()})),
        cwd=directory, capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'native DATE restart failed; diagnostics withheld'
    assert child.stdout.strip() == 'native DATE package-free restart passed'


@pytest.mark.parametrize('public_slots', [False, True])
def test_date_both_layouts_all_rotations_resume_latest_data_and_native_restart(public_slots):
    with date_application(public_slots=public_slots) as app:
        if public_slots:
            from test_public_slots import slots
            original_slots = slots(app)
        run(app); publish(app)
        rotate_all(app)
        expected = {identity: value for identity, (_, value) in app.source.items()}
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=date_keys,
                          deployment=(app.plan, app.pin))
        with sessions(tenant_id=TENANT) as session:
            assert {row.id: row.name for row in session.scalars(select(app.Customer))} == expected
            assert session.scalar(select(app.Customer.name).where(app.Customer.label == 'label-100')) == date.min
            row = session.get(app.Customer, UUID(int=101))
            row.name = date.max
            session.commit()
            session.refresh(row)
            assert type(row.name) is date and row.name == date.max
        expected[UUID(int=101)] = date.max
        remove_date(app)
        if public_slots:
            assert slots(app) == original_slots
        native_restart(app.schema, expected)
