"""Real encrypted-shadow progress, paired verification and source-preserving exit."""
from dataclasses import replace
import json
from uuid import UUID

import pytest
from sqlalchemy import String, select
from sqlalchemy.exc import DBAPIError

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import Keyring
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.sqlalchemy import attach
from test_migration import application, frames, keys, publish, run, TENANT, PROVIDER, PublicFixtureProvider
from test_payload_rotation_plan import plan, target_factory
from test_rewrap_plan import _snapshot
from test_rewrap_abort import index_identity


def operation_pin(proposal,phase='PREPARED'):
    return m.DeploymentPin(proposal.source.target_id,proposal.operation_id,proposal.digest,phase)


def stage(app,proposal,target,**options):
    return r.apply_payload_rotation(proposal,app.owner,keys=keys,target_keys=target,
        pin=operation_pin(proposal),approval=app.approval,**options)


def staged_frames(app,proposal):
    model=proposal.source.document['lock']['models'][0]
    # Native SQL reads only the operation's declared bytea shadows.
    with app.owner.connect() as c:
        names=','.join(m._quote(c,f['payload_column']+'_rotation') for f in model['fields'])
        return {row[0]:tuple(None if value is None else bytes(value) for value in row[1:])
                for row in c.exec_driver_sql(f'SELECT id,{names} FROM "{app.schema}".customer ORDER BY id')}


def snapshot(app,proposal):
    return _snapshot(app),staged_frames(app,proposal)


@pytest.mark.parametrize('varchar',[False,True])
def test_committed_shadow_prefix_resumes_without_resealing_or_changing_public_frames(varchar):
    with application(value_type=String(64,collation='C') if varchar else None) as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        original,index_before=frames(app,True),index_identity(app)
        first=stage(app,proposal,target,max_chunks=1)
        assert first.phase=='EXPANDED' and first.committed_rows==3 and first.committed_chunks==1
        prefix=staged_frames(app,proposal)
        assert frames(app,True)==original and index_identity(app)==index_before
        with pytest.raises(m.TransitionFailure,match='active_schema_mismatch'):
            m.check_deployment(app.plan,app.owner,pin=app.pin)
        with app.runtime.connect() as c:
            with pytest.raises(DBAPIError) as blocked:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=%s',('paused',))
            assert blocked.value.orig.sqlstate=='55000'
        result=stage(app,proposal,target)
        assert result.phase=='BACKFILLED' and result.committed_rows==len(original)
        complete=staged_frames(app,proposal)
        for identity in (UUID(int=100),UUID(int=101),UUID(int=102)):assert complete[identity]==prefix[identity]
        field=app.plan.document['lock']['models'][0]['fields'][0]
        descriptor=FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest'])
        for identity,values in complete.items():
            frame=values[0]
            assert open_text(frame,descriptor,TENANT,identity,target(TENANT).prepare())==app.source[identity][1]
            if frame is not None:
                assert int.from_bytes(frame[6:10],'big')==2
                assert frame[10:46]==original[identity][10:46]
        before=snapshot(app,proposal)
        assert stage(app,r.PayloadRotationPlan(proposal.artifact),target).phase=='BACKFILLED'
        assert snapshot(app,proposal)==before
        observed=r.status_payload_rotation(proposal,app.owner,pin=operation_pin(proposal))
        assert observed.phase=='BACKFILLED' and observed.verification=='NOT_PERFORMED'
        assert observed.runtime_metadata_matches is False
        assert frames(app,True)==original and index_identity(app)==index_before


def test_target_outage_preserves_prefix_and_source_only_cancellation_restores_writers():
    with application() as app:
        run(app);publish(app)
        target,provider=target_factory()
        proposal=plan(app,target)
        original=frames(app,True)
        stage(app,proposal,target,max_chunks=1)
        before=snapshot(app,proposal)
        class Outage:
            provider_id=provider.provider_id
            def unwrap(self,*args):raise RuntimeError('PRIVATE PAYLOAD CHUNK OUTAGE')
        def unavailable(tenant):
            return Keyring(target(tenant).policy,{PROVIDER:PublicFixtureProvider(),provider.provider_id:Outage()})
        with pytest.raises(m.TransitionFailure) as caught:stage(app,proposal,unavailable)
        assert 'PRIVATE PAYLOAD CHUNK OUTAGE' not in str(caught.value)
        assert snapshot(app,proposal)==before
        result=r.abort_payload_rotation(proposal,app.owner,keys=keys,source_pin=app.pin,approval=app.approval)
        assert result.phase=='ABORTED' and frames(app,True)==original
        assert m.status(app.plan,app.owner,pin=app.pin).phase=='ACTIVE'
        observed=r.status_payload_rotation(proposal,app.owner,pin=operation_pin(proposal))
        assert observed.phase=='ABORTED' and observed.verification=='NOT_PERFORMED'
        sessions=attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
        with sessions(tenant_id=TENANT) as s:
            s.get(app.Customer,UUID(int=101)).name='latest edit after canceled payload preparation'
            s.commit()
        before=_snapshot(app)
        assert r.abort_payload_rotation(proposal,app.owner,keys=keys,source_pin=app.pin,
                                         approval=app.approval).phase=='ABORTED'
        assert _snapshot(app)==before
        with sessions(tenant_id=TENANT) as s:
            assert s.scalar(select(app.Customer.id).where(
                app.Customer.name=='latest edit after canceled payload preparation'))==UUID(int=101)
        with pytest.raises(m.TransitionFailure,match='operation_aborted'):stage(app,proposal,target)


@pytest.mark.parametrize('fault',['copied_source','changed_target','forged_phase','cursor_rollback',
    'source_state','guard','schema','pin','approval','target_policy'])
def test_tampering_or_wrong_authority_refuses_without_changing_committed_progress(fault):
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        stage(app,proposal,target,max_chunks=1)
        model=app.plan.document['lock']['models'][0]
        shadow=model['fields'][0]['payload_column']+'_rotation'
        with app.owner.begin() as c:
            if fault=='copied_source':
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{shadow}"=name WHERE id=%s',(UUID(int=101),))
            if fault=='changed_target':
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{shadow}"=pg_catalog.set_byte("{shadow}",'
                    f'octet_length("{shadow}")-1,pg_catalog.get_byte("{shadow}",octet_length("{shadow}")-1) # 1) '
                    'WHERE id=%s',(UUID(int=101),))
            if fault in ('forged_phase','cursor_rollback'):
                state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"."_cryptalis_journal" '
                                        'WHERE operation_id=%s',(proposal.operation_id,)).scalar_one()
                progress=state['models'][model['table_id']]
                if fault=='forged_phase':
                    state['phase']='BACKFILLED';progress.update(rows=7,chunks=3,cursor=str(UUID(int=106)))
                else:progress.update(rows=0,chunks=0,cursor=None)
                c.exec_driver_sql(f'UPDATE "{app.schema}"."_cryptalis_journal" SET state=%s::jsonb '
                                  'WHERE operation_id=%s',(json.dumps(state),proposal.operation_id))
            if fault=='source_state':
                c.exec_driver_sql(f'UPDATE "{app.schema}"."_cryptalis_journal" SET state=state || %s::jsonb '
                                  'WHERE operation_id=%s',(json.dumps({'unplanned':True}),app.plan.operation_id))
            if fault=='guard':
                trigger='_cryptalis_'+proposal.operation_id.hex+'_pause'
                c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER "{trigger}"')
            if fault=='schema':c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ADD COLUMN unplanned text')
        before=snapshot(app,proposal)
        pin=operation_pin(proposal)
        if fault=='pin':pin=replace(pin,plan_digest='0'*64)
        approval=app.approval if fault!='approval' else m.MaintenanceApproval('',0)
        supplied=target if fault!='target_policy' else keys
        with pytest.raises(m.TransitionFailure):
            r.apply_payload_rotation(proposal,app.owner,keys=keys,target_keys=supplied,
                                     pin=pin,approval=approval)
        assert snapshot(app,proposal)==before


def test_multitable_multitenant_shadows_preserve_all_fields_and_cancel_together():
    from test_migration_multitable import multiple_tables, other_frames, assert_independent_values, assert_no_guards
    with multiple_tables() as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        original=(frames(app,True),other_frames(app,True),other_frames(app,True,True))
        assert stage(app,proposal,target,max_chunks=1).committed_rows==3
        complete=stage(app,proposal,target)
        assert complete.phase=='BACKFILLED' and complete.committed_rows==18
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT count(*),count(DISTINCT g.tgrelid),count(DISTINCT g.tgfoid) '
                'FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class t ON t.oid=g.tgrelid '
                'JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace '
                'WHERE n.nspname=%s AND NOT g.tgisinternal',(app.schema,)).one()==(2,2,1)
            for model in proposal.source.document['lock']['models']:
                columns=','.join(m._quote(c,f['payload_column']+'_rotation') for f in model['fields'])
                for row in c.exec_driver_sql(f'SELECT id,tenant_id,{columns} FROM {m._table(c,model)} ORDER BY id'):
                    expected=app.source if model['table']=='customer' else app.other_source
                    for index,field in enumerate(model['fields']):
                        value=app.notes[row[0]] if field['column']=='note' else expected[row[0]][1]
                        frame=None if row[index+2] is None else bytes(row[index+2])
                        descriptor=FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest'])
                        assert open_text(frame,descriptor,row[1],row[0],target(row[1]).prepare())==value
                        if frame is not None:assert int.from_bytes(frame[6:10],'big')==2
        assert (frames(app,True),other_frames(app,True),other_frames(app,True,True))==original
        assert_independent_values(app)
        assert r.abort_payload_rotation(proposal,app.owner,keys=keys,source_pin=app.pin,
                                         approval=app.approval).phase=='ABORTED'
        assert_no_guards(app)
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None
        assert_independent_values(app)


@pytest.mark.parametrize('stage_first',[False,True])
def test_source_authority_cancels_preparation_before_or_after_full_backfill(stage_first):
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        original=frames(app,True)
        if stage_first:assert stage(app,proposal,target).phase=='BACKFILLED'
        assert r.abort_payload_rotation(proposal,app.owner,keys=keys,source_pin=app.pin,
                                         approval=app.approval).phase=='ABORTED'
        assert frames(app,True)==original
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None
        before=_snapshot(app)
        with pytest.raises(m.TransitionFailure,match='operation_aborted'):stage(app,proposal,target)
        assert _snapshot(app)==before


@pytest.mark.parametrize('option',[{'max_chunks':0},{'max_chunks':True},{'until':'ACTIVE'}])
def test_invalid_execution_bounds_fail_before_connection(option):
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        # No usable engine: validation must precede native execution and key work.
        with pytest.raises(m.TransitionFailure,match='invalid_payload_apply_bound'):
            r.apply_payload_rotation(proposal,None,keys=None,target_keys=None,pin=operation_pin(proposal),
                                     approval=app.approval,**option)


def test_source_edit_after_planning_refuses_before_creating_staging():
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        proposal=plan(app,target)
        sessions=attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
        with sessions(tenant_id=TENANT) as s:
            s.get(app.Customer,UUID(int=101)).name='ordinary latest source edit'
            s.commit()
        before=_snapshot(app)
        with pytest.raises(m.TransitionFailure,match='payload_source_changed'):stage(app,proposal,target)
        assert _snapshot(app)==before
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None


def test_payload_preparation_after_rewrap_keeps_reciprocal_ancestor_chain():
    import hashlib
    from uuid import uuid4
    from cryptalis.crypto import DevelopmentKeyProvider, KeyContext
    from test_migration import DOMAIN
    from test_rewrap_execution import proposal as rewrap_plan, apply as rewrap, activate
    with application() as app:
        run(app);publish(app)
        custody,source,provider=rewrap_plan(app)
        rewrap(app,custody,source);activate(app,custody,source)
        new_provider=DevelopmentKeyProvider()
        context=KeyContext(DOMAIN,TENANT,'payload',uuid4(),2)
        policy=replace(source.policy,wrappers=source.policy.wrappers+(
            new_provider.wrap(hashlib.sha256(b'PUBLIC REWRAPPED PAYLOAD TARGET').digest(),context),),payload_generation=2)
        target=Keyring(policy,{provider.provider_id:provider,new_provider.provider_id:new_provider})
        proposal=plan(app,target,source)
        original=frames(app,True)
        result=r.apply_payload_rotation(proposal,app.owner,keys=source,target_keys=target,
                                       pin=operation_pin(proposal),approval=app.approval)
        assert result.phase=='BACKFILLED'
        assert frames(app,True)==original
        assert r.abort_payload_rotation(proposal,app.owner,keys=source,source_pin=app.pin,
                                         approval=app.approval).phase=='ABORTED'
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None
        assert len(app.plan.document['predecessors'])==1
