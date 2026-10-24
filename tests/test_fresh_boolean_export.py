"""Export public Boolean values after interrupted payload rotation and a latest edit."""
import base64
import json
import os
from pathlib import Path
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import BigInteger, Boolean, Integer, SmallInteger

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
    bits = int(os.environ.get('CRYPTALIS_FRESH_INTEGER_BITS', '0'))
    dtype = {0: Boolean, 16: SmallInteger, 32: Integer, 64: BigInteger}[bits]
    lower, upper = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if bits else (0, 1)
    profile = 'integer-' + str(bits) if bits else 'boolean-storage'
    default_raw = os.environ.get('CRYPTALIS_FRESH_INTEGER_DEFAULT', '')
    default = int(default_raw) if default_raw else None
    assert default is None or bits in (16, 32, 64)
    values = (lower, upper, None, -1, 0, 1, 17) if bits else (False, True, None)
    if default is not None:
        values = (lower, upper, -1, 0, 1, 17, 29)
    with application(rows=7, value_type=dtype(), queries=[], protected_values=values, value_default=default) as app:
        source_public_slots = None
        public_slots = os.environ.get('CRYPTALIS_FRESH_PUBLIC_SLOTS') == '1'
        if public_slots:
            from test_public_slots import select_layout, slots
            source_public_slots = [list(row) for row in slots(app)[1]]
            select_layout(app)
        source = {str(key): value for key, (_, value) in app.source.items()}
        dump(workdir / 'plain.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        run(app); publish(app)
        source_keys, reader_keys = keys, target_keys
        if default is not None:
            from rewrap_worker import target_keys as rewrapped_keys
            from payload_rotation_worker import rotated_keys
            before_rewrap = frames(app, True)
            root = r.plan_rewrap(app.plan, app.owner, source_pin=app.pin,
                keys=keys, target_keys=rewrapped_keys, verify_rows_per_second=1000)
            assert r.apply_rewrap(root, app.owner, keys=keys, target_keys=rewrapped_keys,
                pin=app_pin(root.activation_plan, 'PREPARED'), approval=app.approval).phase == 'PENDING'
            assert m.apply(root.activation_plan, app.owner, keys=rewrapped_keys,
                pin=app_pin(root.activation_plan, 'ACTIVATING'), approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
            assert frames(app, True) == before_rewrap
            app.plan, app.pin = root.activation_plan, app_pin(root.activation_plan, 'ACTIVE')
            source_keys, reader_keys = rewrapped_keys, rotated_keys
        preparation = r.plan_payload_rotation(app.plan, app.owner, source_pin=app.pin,
            keys=source_keys, target_keys=reader_keys, backfill_rows_per_second=1000,
            verify_rows_per_second=1000, temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
            max_batch_rows=3)
        operation_pin = m.DeploymentPin(app.plan.target_id, preparation.operation_id, preparation.digest, 'PREPARED')
        paused = r.apply_payload_rotation(preparation, app.owner, keys=source_keys, target_keys=reader_keys,
            pin=operation_pin, approval=app.approval, max_chunks=1)
        assert paused.phase == 'EXPANDED' and paused.committed_chunks == 1
        assert r.apply_payload_rotation(type(preparation)(preparation.artifact), app.owner,
            keys=source_keys, target_keys=reader_keys, pin=operation_pin, approval=app.approval).phase == 'BACKFILLED'
        activation = r.seal_payload_rotation(preparation, app.owner, keys=source_keys, target_keys=reader_keys,
            pin=operation_pin, approval=app.approval, copy_rows_per_second=1000, copy_wal_bytes_per_row=2048)
        assert r.switch_payload_rotation(preparation, activation, app.owner, keys=source_keys,
            target_keys=reader_keys, pin=app_pin(activation, 'PREPARED'), approval=app.approval).phase == 'PENDING'
        assert m.apply(activation, app.owner, keys=reader_keys, pin=app_pin(activation, 'ACTIVATING'),
            approval=app.approval, until='ACTIVE').phase == 'ACTIVE'
        app.plan, app.pin = activation, app_pin(activation, 'ACTIVE')
        sessions = attach(app.mapping, app.runtime, lock=activation.lock_bytes, keys=reader_keys,
                          deployment=(activation, app.pin))
        with sessions(tenant_id=TENANT) as session:
            session.get(app.Customer, UUID(int=101)).name = lower + 17 if bits else False
            session.delete(session.get(app.Customer, UUID(int=106)))
            if default is not None:
                session.get(app.Customer, UUID(int=102)).name = None
                session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT))
            else:
                session.add(app.Customer(id=UUID(int=999), tenant_id=TENANT, name=upper - 17 if bits else True))
            session.commit()
        expected = dict(source)
        expected[str(UUID(int=101))] = lower + 17 if bits else False
        expected[str(UUID(int=999))] = default if default is not None else upper - 17 if bits else True
        if default is not None:
            expected[str(UUID(int=102))] = None
        del expected[str(UUID(int=106))]
        assert all(value is None or len(value) == (42 + bits // 8 if bits else 43) for value in frames(app, True).values())
        dump(workdir / 'protected.sql', app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
        owner = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        runtime = psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'])
        manifest = {'application_profile': profile, 'integer_bits': bits,
            'application_default': None if default is None else str(default), 'root_rewrapped': default is not None,
            'public_slots': public_slots, 'source_public_slots': source_public_slots, 'database': owner['dbname'],
            'owner_role': owner['user'], 'runtime_role': runtime['user'], 'schema': app.schema,
            'source': source, 'expected': expected, 'plan': base64.b64encode(activation.artifact).decode(),
            'pin': {'target_id': str(app.pin.target_id), 'operation_id': str(app.pin.operation_id),
                    'plan_digest': app.pin.plan_digest, 'phase': app.pin.phase}}
    (workdir / 'restore-manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
