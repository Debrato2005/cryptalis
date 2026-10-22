"""Native reverse privilege drift, host-phase selection and removal retries."""
import json
from uuid import UUID
from types import SimpleNamespace

import pytest

from cryptalis import migration as m
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows, proposal, reverse
from test_migration import application, keys, publish, run
from test_runtime_boundary import privilege_change


def snapshot(app):
    with app.owner.connect() as c:
        return (c.exec_driver_sql(f'SELECT * FROM "{app.schema}".customer ORDER BY id').all(),
                c.exec_driver_sql(f'SELECT * FROM "{app.schema}"."{m.JOURNAL}" ORDER BY operation_id').all())


def target_grant(app, plan, fault):
    quote=app.owner.dialect.identifier_preparer.quote_identifier
    role=quote(plan.document['plaintext_runtime_role'])
    scope=(f'UPDATE (state) ON "{app.schema}"."{m.JOURNAL}"' if fault=='journal_column_update'
           else f'CREATE ON SCHEMA "{app.schema}"')
    return f'GRANT {scope} TO {role}',f'REVOKE {scope} FROM {role}'


def removal(plan):
    return d.RemovalApproval(plan.target_id,plan.operation_id,plan.digest,
        'synthetic native application check','synthetic retained recovery check',True)


@pytest.mark.parametrize('phase',['PREPARED','EXPANDED','BACKFILLED','VERIFIED','PLAINTEXT_PENDING'])
@pytest.mark.parametrize('fault',['journal_column_update','schema_create'])
def test_reverse_rechecks_source_role_before_staging_or_resume(phase,fault):
    with application() as app:
        run(app);publish(app)
        plan=proposal(app)
        if phase!='PREPARED':
            assert reverse(app,plan,until=phase).phase==phase
        before=snapshot(app)
        grant,revoke=privilege_change(app,fault)
        called=[]
        def forbidden(tenant):
            called.append(tenant)
            raise AssertionError('unsafe reverse cannot reach keys')
        try:
            with app.owner.begin() as c:c.exec_driver_sql(grant)
            with pytest.raises(m.TransitionFailure,match='unsafe_runtime_role'):
                reverse(app,plan,phase=phase,key_resolver=forbidden)
            assert called==[] and snapshot(app)==before
        finally:
            with app.owner.begin() as c:c.exec_driver_sql(revoke)


@pytest.mark.parametrize('phase',['PLAINTEXT_ACTIVATING','PLAINTEXT_ACTIVE','REMOVING'])
@pytest.mark.parametrize('fault',['journal_column_update','schema_create'])
def test_plaintext_publication_and_retirement_recheck_selected_role(phase,fault):
    with application() as app:
        run(app);publish(app)
        plan=proposal(app)
        reverse(app,plan)
        pure,pin=consent(plan,'PLAINTEXT_ACTIVATING')
        if phase!='PLAINTEXT_ACTIVATING':
            assert d.apply(plan,app.owner,keys=keys,pin=pin,approval=app.approval,
                consent=pure,until='PLAINTEXT_ACTIVE').phase=='PLAINTEXT_ACTIVE'
        before=snapshot(app)
        grant,revoke=target_grant(app,plan,fault)
        try:
            with app.owner.begin() as c:c.exec_driver_sql(grant)
            with pytest.raises(m.TransitionFailure,match='unsafe_plaintext_runtime_role'):
                if phase=='REMOVING':
                    d.remove(plan,app.owner,pin=app_pin(plan,phase),approval=app.approval,
                        consent=pure,removal=removal(plan))
                else:
                    d.apply(plan,app.owner,keys=keys,pin=app_pin(plan,phase),approval=app.approval,
                        consent=pure,until='PLAINTEXT_ACTIVE')
            assert snapshot(app)==before
        finally:
            with app.owner.begin() as c:c.exec_driver_sql(revoke)


def test_forged_plaintext_journal_cannot_select_the_checked_runtime():
    with application() as app:
        run(app);publish(app)
        plan=proposal(app)
        reverse(app,plan,until='EXPANDED')
        grant,revoke=privilege_change(app,'journal_column_update')
        with app.owner.begin() as c:
            c.exec_driver_sql(grant)
            original=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"."{m.JOURNAL}" '
                'WHERE operation_id=%s',(plan.operation_id,)).scalar_one()
            forged={**original,'phase':'PLAINTEXT_PENDING'}
            c.exec_driver_sql(f'UPDATE "{app.schema}"."{m.JOURNAL}" SET state=%s::jsonb '
                'WHERE operation_id=%s',(json.dumps(forged),plan.operation_id))
        before=snapshot(app)
        try:
            with pytest.raises(m.TransitionFailure,match='unsafe_runtime_role'):
                reverse(app,plan,phase='PREPARED')
            assert snapshot(app)==before
        finally:
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}"."{m.JOURNAL}" SET state=%s::jsonb '
                    'WHERE operation_id=%s',(json.dumps(original),plan.operation_id))
                c.exec_driver_sql(revoke)


def test_removed_retry_does_not_reinstate_retired_runtime_boundaries():
    with application() as app:
        run(app);publish(app)
        plan=proposal(app)
        reverse(app,plan)
        pure,pin=consent(plan,'PLAINTEXT_ACTIVATING')
        old_grant,old_revoke=privilege_change(app,'schema_create')
        new_grant,new_revoke=target_grant(app,plan,'schema_create')
        try:
            with app.owner.begin() as c:c.exec_driver_sql(old_grant)
            assert d.apply(plan,app.owner,keys=keys,pin=pin,approval=app.approval,
                consent=pure,until='PLAINTEXT_ACTIVE').phase=='PLAINTEXT_ACTIVE'
            assert d.remove(plan,app.owner,pin=app_pin(plan,'REMOVING'),approval=app.approval,
                consent=pure,removal=removal(plan)).phase=='REMOVED'
            with app.owner.begin() as c:
                c.exec_driver_sql(new_grant)
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                    ('native edit after removal',UUID(int=101)))
            removed=app_pin(plan,'REMOVED')
            assert d.remove(plan,app.owner,pin=removed,approval=app.approval,
                consent=pure,removal=removal(plan)).phase=='REMOVED'
            assert d.check_removed(plan,app.owner,pin=removed) is None
            assert d.status(plan,app.owner,pin=removed).phase=='REMOVED'
            assert native_rows(app)[UUID(int=101)][1]=='native edit after removal'
        finally:
            with app.owner.begin() as c:
                c.exec_driver_sql(old_revoke)
                c.exec_driver_sql(new_revoke)


@pytest.mark.parametrize('fault',['journal_column_update','schema_create'])
def test_reverse_plan_refuses_unsafe_plaintext_role_before_keys(fault):
    with application() as app:
        run(app);publish(app)
        role=least_privilege_role(app)
        grant,revoke=target_grant(app,SimpleNamespace(document={'plaintext_runtime_role':role}),fault)
        called=[]
        def forbidden(tenant):
            called.append(tenant)
            raise AssertionError('unsafe plaintext planning cannot reach keys')
        before=snapshot(app)
        try:
            with app.owner.begin() as c:c.exec_driver_sql(grant)
            with pytest.raises(m.TransitionFailure,match='unsafe_plaintext_runtime_role'):
                d.plan(app.plan,app.owner,source_pin=app.pin,keys=forbidden,
                    plaintext_runtime_role=role,backfill_rows_per_second=1000,
                    verify_rows_per_second=1000,temporary_bytes_per_row=700,wal_bytes_per_row=700)
            assert called==[] and snapshot(app)==before
        finally:
            with app.owner.begin() as c:c.exec_driver_sql(revoke)
