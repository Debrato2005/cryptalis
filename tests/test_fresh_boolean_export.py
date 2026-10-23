"""Export public Boolean values after interrupted payload rotation and a latest edit."""
import base64
import json
import os
from pathlib import Path
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import Boolean

from cryptalis import migration as m, rotation as r
from cryptalis.sqlalchemy import attach
from payload_rotation_worker import target_keys
from test_deprotection import app_pin
from test_migration import application, frames, keys, publish, run, TENANT

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py --boolean', allow_module_level=True)

from test_fresh_cluster_export import dump, environment


def test_export_boolean_storage_after_payload_rotation():
    workdir = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
    with application(rows=7, value_type=Boolean(), queries=[], protected_values=(False, True, None)) as app:
        source = {str(key): value for key, (_, value) in app.source.items()}
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        preparation = r.plan_payload_rotation(app.plan, app.owner, source_pin=app.pin,
            keys=keys, target_keys=target_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
            max_batch_rows=3)
        operation_pin = m.DeploymentPin(app.plan.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
        paused = r.apply_payload_rotation(preparation, app.owner, keys=keys, target_keys=target_keys,
            pin=operation_pin, approval=app.approval, max_chunks=1)
        assert paused.phase == 'EXPANDED' and paused.committed_chunks == 1
        assert r.apply_payload_rotation(type(preparation)(preparation.artifact), app.owner,
            keys=keys, target_keys=target_keys, pin=operation_pin, approval=app.approval).phase == 'BACKFILLED'
        activation = r.seal_payload_rotation(preparation, app.owner, keys=keys, target_keys=target_keys,
            pin=operation_pin, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert r.switch_payload_rotation(preparation, activation, app.owner, keys=keys,
            target_keys=target_keys, pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=target_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        sessions = attach(app.mapping, app.runtime, lock=activation.lock_bytes, keys=target_keys,
                          deployment=(activation, app.pin))
        with sessions(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = False
            session.delete(session.get(app.Customer, UUID(int=106)))
            session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT, name=True))
            session.commit()
        expected = dict(source)
        expected[str(UUID(int=101))] = False
        expected[str(UUID(int=999))] = True
        del expected[str(UUID(int=106))]
        assert all(value is None or len(value) == 43 for value in frames(app, True).values())
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': 'boolean-storage', 'database': owner['dbname'],
            'owner_role': owner['user'], 'runtime_role': runtime['user'], 'schema': app.schema,
            'source': source, 'expected': expected, 'plan': base64.b64encode(activation.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
