"""A forged journal cannot redefine the host's protected schema contract."""
from dataclasses import replace
import json

import pytest

from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_deprotection import proposal
from test_migration import application, keys, publish, run


def forge_snapshot(c, app):
    state = c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal WHERE operation_id=%s',
                             (app.plan.operation_id,)).scalar_one()
    model = app.plan.document['lock']['models'][0]
    state['models'][model['table_id']]['active_schema'] = app.m._facts(c, model)
    state['models'][model['table_id']]['guard'] = app.m._guard_facts(c, app.plan, model)
    c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb WHERE operation_id=%s',
                      (json.dumps(state), app.plan.operation_id))


@pytest.mark.parametrize('route', ['status', 'deployment', 'attachment', 'reverse_plan'])
@pytest.mark.parametrize('drift', ['extra_column', 'unprotected_type', 'unprotected_check',
                                  'frame_check', 'index_expression', 'index_order', 'index_uniqueness'])
def test_active_host_contract_rejects_schema_and_journal_changed_together(route, drift):
    with application() as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            table = f'"{app.schema}".customer'
            field = app.plan.document['lock']['models'][0]['fields'][0]
            index = field['payload_column'] + '_eq'
            constraint = field['payload_column'] + '_frame'
            ddl = {
                'extra_column': f'ALTER TABLE {table} ADD COLUMN unplanned_plaintext text',
                'unprotected_type': f'ALTER TABLE {table} ALTER COLUMN label TYPE bytea USING convert_to(label,\'UTF8\')',
                'unprotected_check': f'ALTER TABLE {table} ADD CONSTRAINT unplanned_rule CHECK (label IS NOT NULL)',
            }.get(drift)
            if ddl:
                c.exec_driver_sql(ddl)
            elif drift == 'frame_check':
                c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "{constraint}"')
                c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{constraint}" CHECK (name IS NULL OR octet_length(name)>0)')
            else:
                c.exec_driver_sql(f'DROP INDEX "{app.schema}"."{index}"')
                expression = 'pg_catalog.substring(name,15,31)' if drift == 'index_expression' else 'pg_catalog.substring(name,15,32)'
                order = 'DESC' if drift == 'index_order' else 'ASC'
                unique = '' if drift == 'index_uniqueness' else 'UNIQUE '
                c.exec_driver_sql(f'CREATE {unique}INDEX "{index}" ON {table} USING btree (tenant_id, ({expression}) {order})')
            forge_snapshot(c, app)
        with pytest.raises(PolicyMismatch if route == 'attachment' else app.m.TransitionFailure):
            if route == 'status':
                app.m.status(app.plan, app.owner, pin=app.pin)
            elif route == 'deployment':
                app.m.check_deployment(app.plan, app.owner, pin=app.pin)
            elif route == 'attachment':
                attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                       deployment=(app.plan, app.pin))
            else:
                proposal(app)


@pytest.mark.parametrize('route', ['status', 'activation'])
@pytest.mark.parametrize('drift', ['extra_column', 'guard_body', 'guard_disabled', 'extra_trigger'])
def test_pending_schema_cannot_be_redefined_before_publication(route, drift):
    with application() as app:
        run(app)
        with app.owner.begin() as c:
            model = app.plan.document['lock']['models'][0]
            trigger, function = app.m._guard_names(app.plan, model)
            table = f'"{app.schema}".customer'
            if drift == 'extra_column':
                c.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN unplanned_plaintext text')
            elif drift == 'guard_body':
                c.exec_driver_sql(f'CREATE OR REPLACE FUNCTION "{app.schema}"."{function}"() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS \'BEGIN RETURN NULL; END\'')
            elif drift == 'guard_disabled':
                c.exec_driver_sql(f'ALTER TABLE {table} DISABLE TRIGGER "{trigger}"')
            else:
                c.exec_driver_sql(f'CREATE TRIGGER extra_callback BEFORE INSERT ON {table} FOR EACH STATEMENT EXECUTE FUNCTION "{app.schema}"."{function}"()')
            forge_snapshot(c, app)
        with pytest.raises(app.m.TransitionFailure):
            if route == 'status':
                app.m.status(app.plan, app.owner, pin=app.pin)
            else:
                run(app, 'ACTIVE', pin=replace(app.pin, phase='ACTIVATING'))


def test_storage_only_frame_contract_rejects_forged_matching_journal():
    with application(unique=False, queries=[]) as app:
        run(app)
        publish(app)
        with app.owner.begin() as c:
            field = app.plan.document['lock']['models'][0]['fields'][0]
            constraint = field['payload_column'] + '_frame'
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DROP CONSTRAINT "{constraint}"')
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD CONSTRAINT "{constraint}" CHECK (name IS NULL OR octet_length(name)>0)')
            forge_snapshot(c, app)
        with pytest.raises(app.m.TransitionFailure, match='active_schema_mismatch'):
            app.m.status(app.plan, app.owner, pin=app.pin)


def test_native_constraints_with_equal_names_on_distinct_tables_remain_bound():
    def setup(c, schema, role):
        table = f'"{schema}".customer'
        for name in ('a_child', 'z_child'):
            c.exec_driver_sql(f'CREATE TABLE "{schema}".{name} (parent uuid CONSTRAINT same_name REFERENCES {table}(id))')
    with application(setup=setup) as app:
        run(app)
        publish(app)
        assert app.m.status(app.plan, app.owner, pin=app.pin).runtime_metadata_matches
        with app.owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE "{app.schema}".a_child ALTER CONSTRAINT same_name DEFERRABLE INITIALLY DEFERRED')
            forge_snapshot(c, app)
        with pytest.raises(app.m.TransitionFailure, match='active_schema_mismatch'):
            app.m.status(app.plan, app.owner, pin=app.pin)
