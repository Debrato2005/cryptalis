"""A matching database snapshot cannot authorize an ineffective writer fence."""
import json
from uuid import UUID

import pytest
from sqlalchemy.exc import DBAPIError

from test_deprotection import app_pin, consent, d, proposal, reverse
from test_migration import application, keys, publish, run


def runtime_label_update(app, *, denied):
    with app.runtime.connect() as c:
        transaction = c.begin()
        try:
            statement = f'UPDATE "{app.schema}".customer SET label=%s WHERE id=%s'
            values = ('forged guard allowed this write', UUID(int=101))
            if denied:
                with pytest.raises(DBAPIError) as failure:
                    c.exec_driver_sql(statement, values)
                assert failure.value.orig.sqlstate == '55000'
            else:
                assert c.exec_driver_sql(statement, values).rowcount == 1
        finally:
            transaction.rollback()


def forge_guard(app, plan, damage):
    model = plan.document['lock']['models'][0]
    _, function = app.m._guard_names(plan, model)
    target = f'"{app.schema}"."{function}"'
    with app.owner.begin() as c:
        if damage == 'body':
            c.exec_driver_sql(f'CREATE OR REPLACE FUNCTION {target}() RETURNS trigger '
                              "LANGUAGE plpgsql SET search_path=pg_catalog AS 'BEGIN RETURN NULL; END'")
        else:
            c.exec_driver_sql(f'ALTER FUNCTION {target}() SECURITY DEFINER')
        journal = app.m._journal(c, plan)
        state = c.exec_driver_sql(f'SELECT state FROM {journal} WHERE operation_id=%s',
                                  (plan.operation_id,)).scalar_one()
        observed = state['models'][model['table_id']]
        schema = 'plaintext_schema' if state['phase'] == 'PLAINTEXT_PENDING' else 'schema'
        assert app.m._facts(c, model) == observed[schema]
        observed['guard'] = app.m._guard_facts(c, plan, model)
        assert observed['guard'][0] == 'A'
        c.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                          (json.dumps(state), plan.operation_id))


def snapshot(app, plan):
    model = plan.document['lock']['models'][0]
    with app.owner.connect() as c:
        return {
            'journal': c.exec_driver_sql(
                f'SELECT state FROM {app.m._journal(c, plan)} WHERE operation_id=%s',
                (plan.operation_id,)).scalar_one(),
            'catalog': app.m._facts(c, model),
            'guard': app.m._guard_facts(c, plan, model),
            'rows': c.exec_driver_sql(f'SELECT * FROM "{app.schema}".customer ORDER BY id').all(),
        }


def prove_bypass_and_snapshot(app, plan, damage):
    with app.owner.connect() as c:
        original_label = c.exec_driver_sql(f'SELECT label FROM "{app.schema}".customer WHERE id=%s',
                                           (UUID(int=101),)).scalar_one()
    runtime_label_update(app, denied=True)
    forge_guard(app, plan, damage)
    runtime_label_update(app, denied=False)
    before = snapshot(app, plan)
    assert next(row.label for row in before['rows'] if row.id == UUID(int=101)) == original_label
    return before


@pytest.mark.parametrize('damage', ['body', 'security_definer'])
@pytest.mark.parametrize('direction', ['protect', 'reverse'])
def test_first_backfill_chunk_requires_the_host_guard_contract(damage, direction):
    with application() as app:
        if direction == 'protect':
            plan = app.plan
            assert run(app, 'EXPANDED').phase == 'EXPANDED'
        else:
            run(app)
            publish(app)
            plan = proposal(app)
            assert reverse(app, plan, until='EXPANDED').phase == 'EXPANDED'
        before = prove_bypass_and_snapshot(app, plan, damage)
        assert before['journal']['phase'] == 'EXPANDED'
        assert all(model['rows'] == model['chunks'] == 0 for model in before['journal']['models'].values())
        try:
            with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
                if direction == 'protect':
                    run(app, 'BACKFILLED')
                else:
                    reverse(app, plan, until='BACKFILLED')
        finally:
            assert snapshot(app, plan) == before


@pytest.mark.parametrize('damage', ['body', 'security_definer'])
@pytest.mark.parametrize('route', ['status', 'verify', 'resume', 'abort'])
def test_protection_paused_guard_cannot_be_authorized_by_its_journal(damage, route):
    with application() as app:
        assert run(app, 'BACKFILLED').phase == 'BACKFILLED'
        before = prove_bypass_and_snapshot(app, app.plan, damage)
        try:
            with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
                if route == 'status':
                    app.m.status(app.plan, app.owner, pin=app.pin)
                elif route == 'verify':
                    app.m.verify(app.plan, app.owner, keys=keys, pin=app.pin, approval=app.approval)
                elif route == 'resume':
                    run(app)
                else:
                    app.m.abort(app.plan, app.owner, pin=app.pin, approval=app.approval)
        finally:
            assert snapshot(app, app.plan) == before


@pytest.mark.parametrize('damage', ['body', 'security_definer'])
@pytest.mark.parametrize('route', ['status', 'resume', 'abort'])
def test_reverse_paused_guard_cannot_be_authorized_by_its_journal(damage, route):
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        assert reverse(app, plan, until='BACKFILLED').phase == 'BACKFILLED'
        before = prove_bypass_and_snapshot(app, plan, damage)
        try:
            with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
                if route == 'status':
                    d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
                elif route == 'resume':
                    reverse(app, plan)
                else:
                    d.abort(plan, app.owner, pin=app_pin(plan, 'PREPARED'), approval=app.approval,
                            consent=consent(plan)[0])
        finally:
            assert snapshot(app, plan) == before


@pytest.mark.parametrize('damage', ['body', 'security_definer'])
@pytest.mark.parametrize('route', ['status', 'publication'])
def test_plaintext_publication_requires_the_host_guard_contract(damage, route):
    with application() as app:
        run(app)
        publish(app)
        plan = proposal(app)
        assert reverse(app, plan).phase == 'PLAINTEXT_PENDING'
        before = prove_bypass_and_snapshot(app, plan, damage)
        try:
            with pytest.raises(app.m.TransitionFailure, match='writer_fence_changed'):
                if route == 'status':
                    d.status(plan, app.owner, pin=app_pin(plan, 'PREPARED'))
                else:
                    reverse(app, plan, until='PLAINTEXT_ACTIVE', phase='PLAINTEXT_ACTIVATING')
        finally:
            assert snapshot(app, plan) == before
