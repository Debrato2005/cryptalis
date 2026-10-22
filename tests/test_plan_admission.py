"""Malformed host artifacts fail at input admission, before database inspection."""
from dataclasses import asdict, replace
from hashlib import sha256
import json

import pytest

from cryptalis.manifest.compiler import _canonical
from test_cli import _run_cli
from test_deprotection import app_pin, d, proposal
from test_migration import application, publish, run
from test_status_cli import arguments, inputs


@pytest.mark.parametrize('damage', ['empty_lock', 'empty_models', 'malformed_columns',
    'empty_estimates', 'missing_pause', 'bool_pause', 'string_pause'])
def test_protection_plan_rejects_invalid_nested_inputs(damage):
    with application() as app:
        document = app.plan.document
        if damage == 'empty_lock':
            document['lock'] = {}
        elif damage == 'empty_models':
            document['lock']['models'] = []
        elif damage == 'malformed_columns':
            document['lock']['models'][0]['source_schema']['columns'] = None
        elif damage == 'empty_estimates':
            document['estimates'] = {}
        elif damage == 'missing_pause':
            document['estimates'].pop('writer_pause_seconds_estimate')
        elif damage == 'bool_pause':
            document['estimates']['writer_pause_seconds_estimate'] = True
        else:
            document['estimates']['writer_pause_seconds_estimate'] = 'PRIVATE_PLAN_INPUT'
        with pytest.raises(app.m.TransitionFailure, match='invalid_plan'):
            app.m.MigrationPlan(_canonical(document))


def test_valid_host_plans_reload_without_changing_their_bytes_or_status():
    with application() as app:
        restored = app.m.MigrationPlan(app.plan.artifact)
        assert restored.artifact == app.plan.artifact
        assert app.m.status(restored, app.owner, pin=app.pin).phase == 'PREPARED'
        run(app)
        publish(app)
        plan = proposal(app)
        restored_reverse = d.DeprotectionPlan(plan.artifact)
        assert restored_reverse.artifact == plan.artifact
        assert d.status(restored_reverse, app.owner, pin=app_pin(plan, 'PREPARED')).phase == 'PREPARED'


@pytest.mark.parametrize('version', ['cryptalis.lock/v1', 'cryptalis.lock/v2'])
def test_legacy_protection_plan_without_measured_rates_remains_inspectable(version):
    with application() as app:
        original = app.plan.artifact
        document = app.plan.document
        document['lock']['schema'] = version
        if version == 'cryptalis.lock/v1':
            for model in document['lock']['models']:
                model.pop('source_metadata')
        document['estimates'].pop('backfill_rows_per_second')
        document['estimates'].pop('verify_rows_per_second')
        raw = _canonical(document)
        restored = app.m.MigrationPlan(raw)
        assert restored.artifact == raw
        assert 'measured rates unavailable in this historical artifact' in str(restored)
        pin = replace(app.pin, plan_digest=restored.digest)
        assert app.m.status(restored, app.owner, pin=pin).phase == 'PREPARED'
        assert app.plan.artifact == original


@pytest.mark.parametrize('location', ['lock', 'model', 'field'])
def test_protection_plan_rejects_unknown_compiler_members(location):
    with application() as app:
        document = app.plan.document
        target = document['lock']
        if location in ('model', 'field'):
            target = target['models'][0]
        if location == 'field':
            target = target['fields'][0]
        target['PRIVATE_PLAN_INPUT'] = True
        with pytest.raises(app.m.TransitionFailure, match='invalid_plan'):
            app.m.MigrationPlan(_canonical(document))


@pytest.mark.parametrize('damage', ['list', 'null', 'null_entry', 'list_entry', 'missing_columns'])
def test_reverse_plan_rejects_invalid_active_schema_inputs(damage):
    with application() as app:
        run(app)
        publish(app)
        document = proposal(app).document
        table_id = document['lock']['models'][0]['table_id']
        if damage == 'list':
            document['active_schemas'] = [table_id]
        elif damage == 'null':
            document['active_schemas'] = None
        elif damage == 'null_entry':
            document['active_schemas'][table_id] = None
        elif damage == 'list_entry':
            document['active_schemas'][table_id] = []
        else:
            document['active_schemas'][table_id].pop('columns')
        with pytest.raises(app.m.TransitionFailure, match='invalid_reverse_plan'):
            d.DeprotectionPlan(_canonical(document))


@pytest.mark.parametrize('damage', ['empty_estimates', 'nullable_integer', 'attnum_boolean'])
def test_reverse_plan_rejects_invalid_estimate_and_catalog_scalars(damage):
    with application() as app:
        run(app)
        publish(app)
        document = proposal(app).document
        table_id = document['lock']['models'][0]['table_id']
        if damage == 'empty_estimates':
            document['estimates'] = {}
        else:
            column = document['active_schemas'][table_id]['columns'][0]
            if damage == 'nullable_integer':
                column['nullable'] = 1
            else:
                column['attnum'] = True
        with pytest.raises(app.m.TransitionFailure, match='invalid_reverse_plan'):
            d.DeprotectionPlan(_canonical(document))


def test_empty_host_model_inventory_cannot_report_active_metadata_success():
    with application() as app:
        run(app)
        publish(app)
        document = app.plan.document
        document['lock']['models'] = []
        changed_journal = False
        try:
            with pytest.raises(app.m.TransitionFailure, match='invalid_plan'):
                malformed = app.m.MigrationPlan(_canonical(document))
                pin = replace(app.pin, plan_digest=malformed.digest)
                with app.owner.begin() as c:
                    c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal '
                                      'SET plan_digest=%s WHERE operation_id=%s',
                                      (malformed.digest, malformed.operation_id))
                changed_journal = True
                assert app.m.status(malformed, app.owner, pin=pin).runtime_metadata_matches
        finally:
            if changed_journal:
                with app.owner.begin() as c:
                    c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal '
                                      'SET plan_digest=%s WHERE operation_id=%s',
                                      (app.plan.digest, app.plan.operation_id))


@pytest.mark.parametrize('direction', ['protect', 'reverse'])
def test_cli_rejects_nested_plan_damage_before_connection(tmp_path, direction):
    with application() as app:
        if direction == 'protect':
            document = app.plan.document
            document['lock'] = {}
            pin = app.pin
        else:
            run(app)
            publish(app)
            plan = proposal(app)
            document = plan.document
            document['active_schemas'] = list(document['active_schemas'])
            pin = app_pin(plan, 'PREPARED')
        paths = inputs(app, tmp_path)
        raw = _canonical(document)
        paths['plan'].write_bytes(raw)
        pin = replace(pin, plan_digest=sha256(raw).hexdigest())
        paths['pin'].write_text(json.dumps(asdict(pin), default=str))
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_PLAN_INPUT')
        result = _run_cli(*arguments(paths))
        assert result.returncode == 2, result.stderr
        assert not result.stdout
        error = json.loads(result.stderr)['error']
        assert (error['family'], error['code'], error['stage']) == ('Transition', 'InvalidInput', 'inputs')
        assert 'PRIVATE_PLAN_INPUT' not in result.stderr and 'Traceback' not in result.stderr
