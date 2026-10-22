"""Paused schema facts remain bound to the host plan after journal forgery."""
import json

import pytest
from sqlalchemy import String

from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import application, keys, publish, run
from test_paused_guard_contract import snapshot


def native_setup(damage, direction):
    def setup(c, schema, role):
        if damage == 'source_constraint':
            c.exec_driver_sql(f'CREATE TABLE "{schema}".child '
                              f'(parent uuid CONSTRAINT recorded_parent REFERENCES "{schema}".customer(id))')
        elif damage == 'source_index' and direction == 'reverse':
            c.exec_driver_sql(f'CREATE INDEX recorded_label ON "{schema}".customer(label)')
    return setup


def forge_schema(app, plan, damage, direction):
    model = plan.document['lock']['models'][0]
    field = model['fields'][0]
    staging = field['payload_column'] if direction == 'protect' else d._staging(field)
    protected = staging if direction == 'protect' else field['column']
    table = f'"{app.schema}".customer'
    frame = field['payload_column'] + '_frame'
    index = field['payload_column'] + '_eq'
    with app.owner.begin() as c:
        guard = app.m._guard_facts(c, plan, model)
        if damage == 'extra_column':
            c.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN unplanned_plaintext text')
        elif damage == 'unprotected_type':
            c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN label TYPE varchar(63)')
        elif damage == 'unprotected_check':
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT unplanned_label CHECK (label IS NOT NULL)')
        elif damage == 'shadow_type':
            c.exec_driver_sql(f'CREATE DOMAIN "{app.schema}".unplanned_payload AS bytea')
            c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN "{staging}" '
                              f'TYPE "{app.schema}".unplanned_payload USING "{staging}"::"{app.schema}".unplanned_payload')
        elif damage in ('staging_type', 'staging_typmod'):
            c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN "{staging}" TYPE varchar(63)')
        elif damage in ('shadow_nullable', 'staging_nullable'):
            c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN "{staging}" SET NOT NULL')
        elif damage in ('shadow_default', 'staging_default'):
            default = "pg_catalog.decode('00','hex')" if direction == 'protect' else "'unplanned default'"
            c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN "{staging}" SET DEFAULT {default}')
        elif damage == 'staging_check':
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT unplanned_staging '
                              f'CHECK ("{staging}" IS NULL OR pg_catalog.char_length("{staging}") >= 0)')
        elif damage == 'source_constraint':
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".child ALTER CONSTRAINT recorded_parent '
                              'DEFERRABLE INITIALLY DEFERRED')
        elif damage == 'source_index':
            native_index = 'native_name' if direction == 'protect' else 'recorded_label'
            c.exec_driver_sql(f'DROP INDEX "{app.schema}"."{native_index}"')
        elif damage in ('frame_check', 'protected_frame'):
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "{frame}"')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{frame}" '
                              f'CHECK ("{protected}" IS NULL OR pg_catalog.octet_length("{protected}") > 0)')
        else:
            c.exec_driver_sql(f'DROP INDEX "{app.schema}"."{index}"')
            unique = '' if damage == 'index_uniqueness' else 'UNIQUE '
            length = 31 if damage in ('index_expression', 'protected_index_expression') else 32
            order = 'DESC' if damage == 'index_order' else 'ASC'
            c.exec_driver_sql(f'CREATE {unique}INDEX "{index}" ON {table} '
                              f'USING btree (tenant_id, (pg_catalog.substring("{protected}",15,{length})) {order})')
        assert app.m._guard_facts(c, plan, model) == guard
        journal = app.m._journal(c, plan)
        state = c.exec_driver_sql(f'SELECT state FROM {journal} WHERE operation_id=%s',
                                  (plan.operation_id,)).scalar_one()
        state['models'][model['table_id']]['schema'] = app.m._facts(c, model)
        c.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                          (json.dumps(state), plan.operation_id))


@pytest.mark.parametrize('phase,damage,route', [
    ('EXPANDED', 'extra_column', 'status'),
    ('EXPANDED', 'unprotected_type', 'resume'),
    ('BACKFILLED', 'unprotected_check', 'verify'),
    ('EXPANDED', 'shadow_type', 'status'),
    ('EXPANDED', 'shadow_nullable', 'resume'),
    ('BACKFILLED', 'shadow_default', 'abort'),
    ('BACKFILLED', 'source_constraint', 'verify'),
    ('EXPANDED', 'source_index', 'status'),
    ('EXPANDED', 'frame_check', 'abort'),
    ('BACKFILLED', 'index_expression', 'verify'),
    ('EXPANDED', 'index_uniqueness', 'resume'),
    ('BACKFILLED', 'index_order', 'status'),
])
def test_protection_paused_schema_cannot_be_redefined_by_its_journal(phase, damage, route):
    rows = 0 if damage == 'shadow_nullable' else 7
    with application(rows=rows, setup=native_setup(damage, 'protect')) as app:
        assert run(app, phase).phase == phase
        forge_schema(app, app.plan, damage, 'protect')
        before = snapshot(app, app.plan)
        try:
            with pytest.raises(app.m.TransitionFailure):
                if route == 'status':
                    app.m.status(app.plan, app.owner, pin=app.pin)
                elif route == 'resume':
                    run(app, 'BACKFILLED')
                elif route == 'verify':
                    app.m.verify(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
                else:
                    app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
        finally:
            assert snapshot(app, app.plan) == before


@pytest.mark.parametrize('phase,damage,route', [
    ('EXPANDED', 'extra_column', 'status'),
    ('EXPANDED', 'unprotected_type', 'resume'),
    ('BACKFILLED', 'unprotected_check', 'verify'),
    ('EXPANDED', 'staging_type', 'status'),
    ('EXPANDED', 'staging_nullable', 'resume'),
    ('BACKFILLED', 'staging_default', 'abort'),
    ('BACKFILLED', 'source_constraint', 'verify'),
    ('EXPANDED', 'source_index', 'status'),
    ('BACKFILLED', 'protected_frame', 'verify'),
    ('EXPANDED', 'staging_check', 'abort'),
    ('EXPANDED', 'staging_typmod', 'resume'),
    ('BACKFILLED', 'protected_index_expression', 'status'),
])
def test_reverse_paused_schema_cannot_be_redefined_by_its_journal(phase, damage, route):
    rows = 0 if damage == 'staging_nullable' else 7
    value_type = String(64, collation='C') if damage == 'staging_typmod' else None
    with application(rows=rows, setup=native_setup(damage, 'reverse'), value_type=value_type) as app:
        run(app)
        publish(app)
        plan = proposal(app)
        assert reverse(app, plan, until=phase).phase == phase
        forge_schema(app, plan, damage, 'reverse')
        before = snapshot(app, plan)
        try:
            with pytest.raises(app.m.TransitionFailure):
                if route == 'status':
                    d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
                elif route == 'resume':
                    reverse(app, plan, until='BACKFILLED')
                elif route == 'verify':
                    reverse(app, plan, until='VERIFIED')
                else:
                    d.abort(plan, app.owner, pin=app_pin(plan, 'PREPARED'), approval=app.approval,
                            consent=consent(plan)[0])
        finally:
            assert snapshot(app, plan) == before
