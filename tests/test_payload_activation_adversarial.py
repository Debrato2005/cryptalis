"""Sealed artifact admission, late metadata drift and mixed rotation lineage."""
from dataclasses import replace
import hashlib
import json
import time
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from payload_rotation_worker import target_keys
from test_deprotection import app_pin, consent, d, least_privilege_role, native_rows, reverse
from test_migration import application, keys, publish, run, DOMAIN, TABLE_ID, FIELD_ID, TENANT
from test_migration_multitable import multiple_tables, OTHER_TABLE, OTHER_FIELD
from test_payload_rotation_execution import operation_pin, plan, stage
from test_payload_rotation_cutover import seal, switch
from test_rewrap_plan import _snapshot


def prepared(app):
    run(app);publish(app)
    p=plan(app,target_keys)
    stage(app,p,target_keys)
    return p,seal(app,p)


@pytest.mark.parametrize('fault',['unknown_operation','public_acl','counter_boolean','scope','negative_metrics'])
def test_late_publication_metadata_failure_precedes_provider_work(fault):
    with application(rows=1 if fault=='counter_boolean' else 7) as app:
        p,a=prepared(app)
        switch(app,p,a)
        with app.owner.begin() as c:
            if fault=='unknown_operation':
                c.exec_driver_sql(f'INSERT INTO "{app.schema}"."_cryptalis_journal" VALUES (%s,%s,%s::jsonb)',
                                  (uuid4(),'0'*64,json.dumps({'phase':'ACTIVE'})))
            elif fault=='public_acl':c.exec_driver_sql(f'GRANT SELECT (name) ON "{app.schema}".customer TO PUBLIC')
            else:
                state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"."_cryptalis_journal" WHERE operation_id=%s',
                                        (a.operation_id,)).scalar_one()
                item=next(iter(state['models'].values()))
                if fault=='counter_boolean':item['rows']=True
                if fault=='scope':item['scope']['membership']='0'*64
                if fault=='negative_metrics':state['cutover_measurements']['copy_wall_ns']=-1
                c.exec_driver_sql(f'UPDATE "{app.schema}"."_cryptalis_journal" SET state=%s::jsonb WHERE operation_id=%s',
                                  (json.dumps(state),a.operation_id))
        before=_snapshot(app)
        called=[]
        def unavailable(tenant):
            called.append(tenant)
            raise RuntimeError('should never call provider before metadata refusal')
        with pytest.raises(m.TransitionFailure):
            m.apply(a,app.owner,keys=unavailable,pin=app_pin(a,'ACTIVATING'),approval=app.approval,until='ACTIVE')
        assert called==[] and _snapshot(app)==before


@pytest.mark.parametrize('fault',['scope_boolean','scope_duplicate','scope_missing','byte_boolean','extra_cost',
                                 'wrong_preparation_digest','copy_nan'])
def test_malformed_sealed_authority_is_refused_before_database_execution(fault):
    with application(rows=1) as app:
        p,a=prepared(app)
        doc=a.document
        if fault=='scope_boolean':doc['scopes'][0]['estimated_rows']=True
        if fault=='scope_duplicate':doc['scopes']*=2
        if fault=='scope_missing':doc['scopes']=[]
        if fault=='byte_boolean':doc['payload_batch_limits']['max_bytes']=True
        if fault=='extra_cost':doc['estimates']['unplanned']=1
        if fault=='wrong_preparation_digest':doc['payload_rotation_plan_digest']='0'*64
        if fault=='copy_nan':doc['estimates']['copy_rows_per_second']=float('nan')
        before=_snapshot(app)
        raw=json.dumps(doc,sort_keys=True,separators=(',',':')).encode() if fault=='copy_nan' else m._canonical(doc)
        with pytest.raises(m.TransitionFailure,match='invalid_plan'):
            m.MigrationPlan(raw)
        assert _snapshot(app)==before
        with pytest.raises(m.TransitionFailure,match='payload_rotation_executor_required'):
            m.apply(a,None,keys=None,pin=app_pin(a,'PREPARED'),approval=app.approval)


def test_native_model_order_different_from_uuid_order_survives_seal_reload_and_binding():
    with multiple_tables() as app:
        declaration=app.plan.document['lock']['declaration']
        first,second=declaration['models']
        first['table_id'],second['table_id']=second['table_id'],first['table_id']
        app.plan=m.plan(json.dumps(declaration).encode(),app.mapping,app.owner,
            writers=WriterInventory(True,tuple(Writer(t,'app','sqlalchemy',evidence='reversed UUID model ordering')
                                              for t in (TABLE_ID,OTHER_TABLE))),
            search_reviews=tuple(SearchReview(f,False,'synthetic unbounded names') for f in (FIELD_ID,OTHER_FIELD)),
            keys=keys,runtime_role=app.role,target_id=app.plan.target_id,
            backfill_rows_per_second=1000,verify_rows_per_second=1000,temporary_bytes_per_row=700,wal_bytes_per_row=2000)
        app.pin=app_pin(app.plan,'PREPARED')
        ids=[model['table_id'] for model in app.plan.document['lock']['models']]
        assert ids!=sorted(ids)
        p,a=prepared(app)
        a=m.MigrationPlan(a.artifact)
        assert switch(app,p,a).phase=='PENDING'
        assert m.apply(a,app.owner,keys=target_keys,pin=app_pin(a,'ACTIVATING'),
                       approval=app.approval,until='ACTIVE').phase=='ACTIVE'


def test_payload_rewrap_payload_chain_keeps_latest_values_through_complete_removal():
    from test_rewrap_execution import proposal as rewrap_plan, apply as rewrap, activate, target_factory
    with application() as app:
        run(app);publish(app)
        p=plan(app,target_keys);stage(app,p,target_keys)
        a=r.seal_payload_rotation(p,app.owner,keys=keys,target_keys=target_keys,pin=operation_pin(p),
            approval=app.approval,copy_rows_per_second=1000.5,copy_wal_bytes_per_row=2048)
        switch(app,p,a)
        m.apply(a,app.owner,keys=target_keys,pin=app_pin(a,'ACTIVATING'),approval=app.approval,until='ACTIVE')
        app.plan,app.pin=a,app_pin(a,'ACTIVE')
        custody,current,provider=rewrap_plan(app,target_keys)
        rewrap(app,custody,current,target_keys);activate(app,custody,current)
        added=DevelopmentKeyProvider()
        context=KeyContext(DOMAIN,TENANT,'payload',uuid4(),3)
        wrapper=added.wrap(hashlib.sha256(b'PUBLIC INDEPENDENT GENERATION THREE ROOT').digest(),context)
        next_keys=Keyring(replace(current.policy,wrappers=current.policy.wrappers+(wrapper,),payload_generation=3),
                         {provider.provider_id:provider,added.provider_id:added})
        p=plan(app,next_keys,current)
        assert r.apply_payload_rotation(p,app.owner,keys=current,target_keys=next_keys,
                                         pin=operation_pin(p),approval=app.approval).phase=='BACKFILLED'
        a=r.seal_payload_rotation(p,app.owner,keys=current,target_keys=next_keys,pin=operation_pin(p),
            approval=app.approval,copy_rows_per_second=1000,copy_wal_bytes_per_row=2048)
        assert r.switch_payload_rotation(p,a,app.owner,keys=current,target_keys=next_keys,
            pin=app_pin(a,'PREPARED'),approval=app.approval).phase=='PENDING'
        assert m.apply(a,app.owner,keys=next_keys,pin=app_pin(a,'ACTIVATING'),
                       approval=app.approval,until='ACTIVE').phase=='ACTIVE'
        app.plan,app.pin=a,app_pin(a,'ACTIVE')
        assert len(a.document['predecessors'])==5
        mapping,Customer,sessions=target_factory(app,next_keys)
        try:
            with sessions(tenant_id=TENANT) as session:
                session.get(Customer,UUID(int=101)).name='latest after payload rewrap payload'
                session.commit()
                assert session.scalar(select(Customer.name).where(Customer.id==UUID(int=101)))=='latest after payload rewrap payload'
            app.source[UUID(int=101)]=(TENANT,'latest after payload rewrap payload')
        finally:mapping.dispose()
        reverse_plan=d.plan(a,app.owner,source_pin=app.pin,keys=next_keys,
            plaintext_runtime_role=least_privilege_role(app),backfill_rows_per_second=1000,
            verify_rows_per_second=1000,temporary_bytes_per_row=700,wal_bytes_per_row=700)
        assert reverse(app,reverse_plan,key_resolver=next_keys).phase=='PLAINTEXT_PENDING'
        pure,_=consent(reverse_plan)
        assert d.apply(reverse_plan,app.owner,keys=next_keys,pin=app_pin(reverse_plan,'PLAINTEXT_ACTIVATING'),
                       approval=app.approval,consent=pure,until='PLAINTEXT_ACTIVE').phase=='PLAINTEXT_ACTIVE'
        removal=d.RemovalApproval(reverse_plan.target_id,reverse_plan.operation_id,reverse_plan.digest,
            'current native workload after three transitions','retained public generation roots',True)
        assert d.remove(reverse_plan,app.owner,pin=app_pin(reverse_plan,'REMOVING'),
            approval=app.approval,removal=removal,consent=pure).phase=='REMOVED'
        assert native_rows(app)==app.source


def test_native_copy_metrics_fit_independent_wall_and_cluster_wal_observations(tmp_path):
    with application() as app:
        p,a=prepared(app)
        with app.owner.connect() as c:
            before=c.exec_driver_sql('SELECT pg_catalog.pg_current_wal_insert_lsn()::text').scalar_one()
        started=time.perf_counter_ns()
        assert switch(app,p,a).phase=='PENDING'
        outside_ns=time.perf_counter_ns()-started
        with app.owner.connect() as c:
            outer_wal=c.exec_driver_sql('SELECT pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_insert_lsn(),'
                                       '%s::pg_catalog.pg_lsn)::bigint',(before,)).scalar_one()
            measurements=c.exec_driver_sql(f'SELECT state FROM "{app.schema}".'
                                            '"_cryptalis_journal" WHERE operation_id=%s',(a.operation_id,)).scalar_one()['cutover_measurements']
        assert 0<measurements['copy_wall_ns']<=outside_ns
        assert 0<measurements['copy_wal_bytes_cluster_delta']<=outer_wal
        assert all(type(value) is int for value in measurements.values())
        (tmp_path/'copy-measurements.json').write_text(json.dumps({
            'format':'cryptalis.payload-copy-observation/v1','rows':len(app.source),
            'recorded_copy':measurements,'outer_call_wall_ns':outside_ns,
            'outer_call_wal_bytes_cluster_delta':outer_wal,
            'limits':'Synthetic seven-row local fixture. WAL is cluster-wide. No scale or capacity claim.'},indent=2)+'\n')
