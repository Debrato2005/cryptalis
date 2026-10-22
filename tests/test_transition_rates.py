"""Measured fractional throughput survives artifact reload and real transitions."""
import json
import math

import pytest

from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from cryptalis.manifest.parser import ManifestInvalid, decode_manifest_json
from test_migration import application, keys, publish, run, TABLE_ID, FIELD_ID
from test_deprotection import d, least_privilege_role, reverse


@pytest.mark.parametrize('rates', [(1000, 1000), (1000.0, 1000.0), (0.5, 2.25)])
def test_measured_rates_round_trip_through_protection_and_reverse(rates):
    with application() as app:
        declaration = json.loads(app.plan.lock_bytes)['declaration']
        app.plan = app.m.plan(json.dumps(declaration).encode(), app.mapping, app.owner,
            writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy', evidence='synthetic app'),)),
            search_reviews=(SearchReview(FIELD_ID, False, 'synthetic labels'),), keys=keys,
            runtime_role=app.role, target_id=app.plan.target_id,
            backfill_rows_per_second=rates[0], verify_rows_per_second=rates[1],
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        app.plan = app.m.MigrationPlan(app.plan.artifact)
        costs = app.plan.document['estimates']
        assert costs['backfill_rows_per_second'] == rates[0]
        assert costs['verify_rows_per_second'] == rates[1]
        assert costs['writer_pause_seconds_estimate'] == math.ceil(7 / rates[0] + 7 / rates[1])
        assert 'rows/s' in str(app.plan)
        app.pin = app.m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
        run(app)
        publish(app)
        planned = d.plan(app.plan, app.owner, source_pin=app.pin, keys=keys,
            plaintext_runtime_role=least_privilege_role(app),
            backfill_rows_per_second=0.75, verify_rows_per_second=3.5,
            temporary_bytes_per_row=700, wal_bytes_per_row=700)
        planned = d.DeprotectionPlan(planned.artifact)
        assert planned.source.artifact == app.plan.artifact
        assert planned.document['estimates']['writer_pause_seconds_estimate'] == 12
        assert reverse(app, planned).phase == 'PLAINTEXT_PENDING'
        with app.owner.connect() as c:
            actual = {row[0]: (row[1], row[2]) for row in c.exec_driver_sql(
                f'SELECT id, tenant_id, name FROM "{app.schema}".customer')}
        assert actual == app.source


@pytest.mark.parametrize('location', ['counter', 'target', 'lock'])
def test_fractional_numbers_remain_refused_outside_observed_rates(location):
    with application() as app:
        document = app.plan.document
        if location == 'counter':
            document['estimates']['rows'] = 7.0
        elif location == 'target':
            document['target'][3] = 5432.0
        else:
            document['lock']['domain_id'] = 1.5
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        with pytest.raises(app.m.TransitionFailure, match='invalid_plan'):
            app.m.MigrationPlan(raw)


@pytest.mark.parametrize('rate', ['0.0', '-0.5', 'NaN', 'Infinity', '1e309'])
def test_invalid_observed_rate_artifacts_fail_safely(rate):
    with application() as app:
        document = app.plan.document
        document['estimates']['backfill_rows_per_second'] = 'RATE_TOKEN'
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        raw = raw.replace('"RATE_TOKEN"', rate).encode()
        with pytest.raises(app.m.TransitionFailure, match='invalid_plan'):
            app.m.MigrationPlan(raw)


def test_manifest_rate_names_do_not_admit_fractional_manifest_numbers():
    with pytest.raises(ManifestInvalid):
        decode_manifest_json(b'{"estimates":{"backfill_rows_per_second":1.5}}')
