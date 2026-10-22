"""Native read-only payload-rotation admission and aggregate scan bounds."""
from dataclasses import replace
import hashlib
import json
from uuid import UUID, uuid4

import pytest
from sqlalchemy import String, event, select

from cryptalis import migration as m, rotation as r
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, Keyring, WrappedRoot
from cryptalis.crypto._payload_rotation import prepare_payload_rotation_batch
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.sqlalchemy import attach
from test_migration import (application, frames, keys, publish, run, DOMAIN, TENANT,
                            PROVIDER, PublicFixtureProvider)
from test_rewrap_plan import _historical, _snapshot


def target_factory(source=keys, change=None):
    provider, cache = DevelopmentKeyProvider(), {}
    def target(tenant):
        if tenant not in cache:
            old = source(tenant)
            generation = max(w.context.generation for w in old.policy.wrappers
                             if w.context.purpose == 'payload') + 1
            context = KeyContext(DOMAIN, tenant, 'payload', uuid4(), generation)
            root = hashlib.sha256(b'PUBLIC PAYLOAD ROTATION ROOT' + tenant.bytes).digest()
            policy = replace(old.policy, wrappers=old.policy.wrappers + (provider.wrap(root, context),),
                             payload_generation=generation)
            if change is not None: policy = change(policy, old, provider)
            cache[tenant] = Keyring(policy, {PROVIDER:PublicFixtureProvider(), provider.provider_id:provider})
        return cache[tenant]
    return target, provider


def plan(app, target, source=keys, **kwargs):
    options = dict(source_pin=app.pin, keys=source, target_keys=target,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048,
        max_batch_rows=3, max_batch_bytes=64*1024*1024)
    options.update(kwargs)
    return r.plan_payload_rotation(app.plan, app.owner, **options)


@pytest.mark.parametrize('varchar',[False,True])
def test_native_payload_plan_retains_source_authority_and_drives_real_inactive_transform(varchar):
    with application(value_type=String(64,collation='C') if varchar else None) as app:
        run(app); publish(app)
        target, _ = target_factory()
        before = _snapshot(app)
        proposal = plan(app, target)
        assert _snapshot(app) == before
        assert r.PayloadRotationPlan(proposal.artifact).artifact == proposal.artifact
        document = proposal.document
        assert proposal.operation_id != app.plan.operation_id
        assert UUID(document['successor_operation_id']) not in (proposal.operation_id, app.plan.operation_id)
        assert document['kind'] == 'payload_rotation'
        assert document['source_plan'] == app.plan.document
        assert document['batch_limits'] == {'max_rows':3,'max_bytes':64*1024*1024}
        assert all(word not in str(proposal).lower() for word in ('active deployment', 'production-ready'))
        field = app.plan.document['lock']['models'][0]['fields'][0]
        descriptor = FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest'])
        raw = frames(app, True)
        rows = tuple(raw.items())
        transformed = prepare_payload_rotation_batch(rows, descriptor,TENANT,
            source=keys(TENANT).prepare(),target=target(TENANT).prepare())
        for identity, frame in transformed:
            assert open_text(frame,descriptor,TENANT,identity,target(TENANT).prepare()) == app.source[identity][1]
            if frame is not None:
                assert frame != raw[identity]
                assert frame[10:46] == raw[identity][10:46]
        assert _snapshot(app) == before
        observed = next(iter(document['models'].values()))
        frame_bytes = sum(len(frame) for frame in raw.values() if frame is not None)
        logical = [32+(0 if frame is None else 3*len(frame)-74) for frame in raw.values()]
        assert observed['frame_bytes'] == frame_bytes
        assert observed['logical_bytes'] == sum(logical)
        assert observed['largest_row_logical_bytes'] == max(logical)
        costs = document['estimates']
        assert costs['source_frame_bytes'] == costs['staging_payload_bytes'] == frame_bytes
        assert costs['writer_pause_seconds_estimate'] == 1
        assert costs['required_verify_passes'] == 3
        assert costs['temporary_bytes_estimate'] == len(raw)*1024
        assert costs['wal_bytes_estimate'] == len(raw)*2048
        assert m.check_deployment(app.plan,app.owner,pin=app.pin) is None


@pytest.mark.parametrize('fault', ['missing_retained', 'rewrapped_retained', 'search_generation',
                                 'same_generation', 'old_generation', 'extra_root', 'unchanged'])
def test_payload_plan_rejects_policy_changes_outside_one_new_payload_root(fault):
    def change(policy, old, provider):
        if fault == 'unchanged': return old.policy
        added = policy.wrappers[-1]
        if fault == 'missing_retained':
            return replace(policy,wrappers=tuple(w for w in policy.wrappers
                if w.context.purpose != 'payload' or w.context.generation == policy.payload_generation))
        if fault == 'rewrapped_retained':
            first=old.policy.wrappers[0]
            new=provider.wrap(PublicFixtureProvider().unwrap(first,first.context),first.context)
            return replace(policy,wrappers=(new,)+policy.wrappers[1:])
        if fault == 'same_generation': return replace(policy,payload_generation=old.policy.payload_generation)
        if fault == 'old_generation':
            # A genuinely retained later reader makes the new unused generation stale.
            context=replace(added.context,generation=2)
            wrapper=provider.wrap(hashlib.sha256(b'PUBLIC UNUSED ROOT').digest(),context)
            return replace(policy,wrappers=old.policy.wrappers+(wrapper,),payload_generation=2)
        if fault == 'extra_root':
            context=replace(added.context,root_id=uuid4(),generation=added.context.generation+1)
            wrapper=provider.wrap(hashlib.sha256(b'PUBLIC EXTRA ROOT').digest(),context)
            return replace(policy,wrappers=policy.wrappers+(wrapper,))
        return replace(policy,search_generation=None)
    source = _historical if fault == 'old_generation' else keys
    with application() as app:
        if source is _historical:
            app.plan = m.MigrationPlan(m._canonical({**app.plan.document,
                'key_policies':{str(TENANT):m._policy(source(TENANT))}}))
            app.pin = m.DeploymentPin(app.plan.target_id,app.plan.operation_id,app.plan.digest,'PREPARED')
        run(app,key_resolver=source)
        m.apply(app.plan,app.owner,keys=source,pin=replace(app.pin,phase='ACTIVATING'),
                approval=app.approval,until='ACTIVE')
        app.pin=replace(app.pin,phase='ACTIVE')
        target,_ = target_factory(source,change)
        before=_snapshot(app)
        with pytest.raises(m.TransitionFailure): plan(app,target,source)
        assert _snapshot(app)==before


def test_snapshot_scan_bounds_total_fields_before_frame_retrieval():
    with application(rows=3) as app:
        run(app);publish(app)
        target,_=target_factory()
        before=_snapshot(app)
        row_sizes=[32+(0 if f is None else 3*len(f)-74) for f in frames(app,True).values()]
        smallest=max(row_sizes)
        observed=[]
        def inspect_rows(conn,cursor,statement,parameters,context,executemany):
            if statement.startswith('SELECT "id","tenant_id","name"'):
                observed.append(parameters[-1])
        event.listen(app.owner,'before_cursor_execute',inspect_rows)
        try:
            proposal=plan(app,target,max_batch_bytes=smallest)
            assert proposal.document['models']
        finally: event.remove(app.owner,'before_cursor_execute',inspect_rows)
        assert observed and max(observed)==1
        with pytest.raises(m.TransitionFailure,match='payload_row_exceeds_byte_budget'):
            plan(app,target,max_batch_bytes=smallest-1)
        assert _snapshot(app)==before


@pytest.mark.parametrize('fault', ['bool_pause','float_passes','bool_rows','bool_zero_bytes',
    'bool_model_rows','duplicate_ids','source_alias','missing_target_context','dropped_reader',
    'changed_context','bad_membership','model_total','row_larger_than_batch','extra_cost'])
def test_malformed_payload_artifact_is_refused_with_safe_typed_error(fault):
    with application(rows=1) as app:
        run(app);publish(app)
        target,_=target_factory()
        document=plan(app,target).document
        observed=next(iter(document['models'].values()))
        policy=next(iter(document['key_policies'].values()))
        if fault=='bool_pause':document['estimates']['writer_pause_seconds_estimate']=True
        if fault=='float_passes':document['estimates']['required_verify_passes']=3.0
        if fault=='bool_rows':document['estimates']['rows']=True
        if fault=='bool_zero_bytes':document['estimates']['source_frame_bytes']=False
        if fault=='bool_model_rows':observed['rows']=True
        if fault=='duplicate_ids':document['successor_operation_id']=document['operation_id']
        if fault=='source_alias':document['operation_id']=str(app.plan.operation_id)
        if fault=='missing_target_context':policy['target_contexts'].pop()
        if fault=='dropped_reader':policy['target_contexts'].pop(0)
        if fault=='changed_context':policy['target_contexts'][0]['domain_id']=str(uuid4())
        if fault=='bad_membership':observed['membership']='0'*63
        if fault=='model_total':observed['rows']+=1
        if fault=='row_larger_than_batch':document['batch_limits']['max_bytes']=1
        if fault=='extra_cost':document['estimates']['unreviewed']=1
        with pytest.raises(m.TransitionFailure,match='invalid_payload_rotation_plan'):
            r.PayloadRotationPlan(m._canonical(document))


@pytest.mark.parametrize('missing', [False,True])
def test_historical_roots_and_deleted_tenants_remain_required(missing):
    with application() as app:
        app.plan=m.MigrationPlan(m._canonical({**app.plan.document,
            'key_policies':{str(TENANT):m._policy(_historical(TENANT))}}))
        app.pin=replace(app.pin,plan_digest=app.plan.digest)
        run(app,key_resolver=_historical);publish(app)
        with app.owner.begin() as c:c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer')
        target,_=target_factory(_historical)
        if missing:
            target=lambda tenant:None
        before=_snapshot(app)
        if missing:
            with pytest.raises(m.TransitionFailure,match='missing_target_key_policy'):
                plan(app,target,_historical)
        else:
            proposal=plan(app,target,_historical)
            policy=proposal.document['key_policies'][str(TENANT)]
            assert policy['source_payload_generation']==1 and policy['target_payload_generation']==4
            assert len(policy['source_contexts'])==3 and len(policy['target_contexts'])==4
            assert next(iter(proposal.document['models'].values()))['rows']==0
        assert _snapshot(app)==before


def test_multi_field_tenant_scan_enforces_one_aggregate_logical_budget():
    from test_migration_multitable import multiple_tables,other_frames,OTHER_TENANT
    with multiple_tables() as app:
        run(app);publish(app)
        target,_=target_factory()
        before=frames(app,True),other_frames(app,True),other_frames(app,True,True)
        proposal=plan(app,target)
        assert set(proposal.document['key_policies'])=={str(TENANT),str(OTHER_TENANT)}
        per_field_max=0
        for model in app.plan.document['lock']['models']:
            with app.owner.connect() as c:
                rows=m._stream(c,model)
            for row in rows:
                for index,field in enumerate(model['fields']):
                    frame=row[2+index]
                    per_field_max=max(per_field_max,32+(0 if frame is None else
                        3*len(frame)-(74 if field['queries'] else 42)))
        other_reads=[]
        def observe(conn,cursor,statement,parameters,context,executemany):
            if statement.startswith('SELECT "id","tenant_id","name","note"'):other_reads.append(statement)
        event.listen(app.owner,'before_cursor_execute',observe)
        try:
            with pytest.raises(m.TransitionFailure,match='payload_row_exceeds_byte_budget'):
                plan(app,target,max_batch_bytes=per_field_max)
        finally:event.remove(app.owner,'before_cursor_execute',observe)
        assert other_reads==[]
        assert (frames(app,True),other_frames(app,True),other_frames(app,True,True))==before


@pytest.mark.parametrize('name,value', [('max_batch_rows',True),('max_batch_bytes',False),
    ('max_batch_rows',5001),('max_batch_bytes',2**30+1),('backfill_rows_per_second',float('inf')),
    ('verify_rows_per_second',10**400),('temporary_bytes_per_row',True),('wal_bytes_per_row',0)])
def test_invalid_measurements_and_limits_refuse_before_connection(name,value):
    with application() as app:
        target,_=target_factory()
        with pytest.raises(m.TransitionFailure) as caught:
            r.plan_payload_rotation(app.plan,None,source_pin=replace(app.pin,phase='ACTIVE'),
                keys=keys,target_keys=target,**{**dict(backfill_rows_per_second=1000,
                verify_rows_per_second=1000,temporary_bytes_per_row=1024,wal_bytes_per_row=2048),name:value})
        expected=('invalid_payload_batch_bound' if name.startswith('max_batch') else
            'missing_measured_rates' if name.endswith('per_second') else 'missing_measured_storage_or_wal_costs')
        assert caught.value.code==expected


def test_planning_preserves_snapshot_during_committed_frame_edit():
    from cryptalis.crypto.cf1 import seal_text
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        before=plan(app,target)
        field=app.plan.document['lock']['models'][0]['fields'][0]
        descriptor=FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest'])
        body=seal_text('committed during payload planning',descriptor,TENANT,UUID(int=101),keys(TENANT).prepare())
        settings=[]
        def observe(connection,cursor,statement,parameters,context,executemany):
            if statement.startswith('SET TRANSACTION ISOLATION LEVEL'):
                with cursor.connection.cursor() as probe:
                    probe.execute('SHOW transaction_read_only');readonly=probe.fetchone()[0]
                    probe.execute('SHOW transaction_isolation');settings.append((readonly,probe.fetchone()[0]))
        def concurrent(tenant):
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',(body,UUID(int=101)))
            return target(tenant)
        event.listen(app.owner,'after_cursor_execute',observe)
        try:during=plan(app,concurrent)
        finally:event.remove(app.owner,'after_cursor_execute',observe)
        after=plan(app,target)
        assert settings==[('on','repeatable read')]
        assert before.document['models']==during.document['models']
        assert before.document['models']!=after.document['models']


def test_expired_keys_during_connection_cleanup_cannot_return_a_completed_plan(monkeypatch):
    import time
    from types import SimpleNamespace
    import cryptalis.crypto.keys as crypto_keys
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        before=_snapshot(app)
        clock=[time.monotonic()]
        monkeypatch.setattr(crypto_keys,'time',SimpleNamespace(
            monotonic=lambda:clock[0],monotonic_ns=time.monotonic_ns))
        class Connection:
            def __init__(self,native):self.native=native
            def __getattr__(self,name):return getattr(self.native,name)
            def close(self):
                self.native.close()
                clock[0]+=301
        class Engine:
            def connect(self):return Connection(app.owner.connect())
        with pytest.raises(m.TransitionFailure) as caught:
            r.plan_payload_rotation(app.plan,Engine(),source_pin=app.pin,keys=keys,target_keys=target,
                backfill_rows_per_second=1000,verify_rows_per_second=1000,
                temporary_bytes_per_row=1024,wal_bytes_per_row=2048)
        assert caught.value.code=='KeyUnavailable'
        assert _snapshot(app)==before


def test_source_application_edits_membership_and_values_after_read_only_planning():
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        before=plan(app,target)
        sessions=attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
        with sessions(tenant_id=TENANT) as session:
            session.get(app.Customer,UUID(int=101)).name='edited after payload planning'
            session.delete(session.get(app.Customer,UUID(int=102)))
            session.add(app.Customer(id=UUID(int=900),tenant_id=TENANT,name='new current value'))
            session.commit()
        after=plan(app,target)
        a,b=next(iter(before.document['models'].values())),next(iter(after.document['models'].values()))
        assert a['rows']==b['rows'] and a['membership']!=b['membership'] and a['frames']!=b['frames']
        with sessions(tenant_id=TENANT) as session:
            assert session.scalar(select(app.Customer.id).where(
                app.Customer.name=='edited after payload planning'))==UUID(int=101)
            assert session.get(app.Customer,UUID(int=102)) is None
        # A preparation artifact cannot enter the application publication executor.
        preparation_pin=m.DeploymentPin(after.source.target_id,after.operation_id,after.digest,'ACTIVATING')
        with pytest.raises(m.TransitionFailure,match='external_policy_mismatch'):
            m.apply(after,None,keys=target,pin=preparation_pin,approval=app.approval,until='ACTIVE')


@pytest.mark.parametrize('fault',['retained_material','new_root_alias','target_outage','source_frame','unknown_journal'])
def test_key_data_and_inventory_refusals_preserve_current_source(fault):
    import traceback
    with application() as app:
        run(app);publish(app)
        target,provider=target_factory()
        supplied=target(TENANT)
        if fault=='retained_material':
            class WrongRoot(PublicFixtureProvider):
                def unwrap(self,wrapper,context):return hashlib.sha256(('PUBLIC WRONG '+str(context)).encode()).digest()
            target=lambda tenant:Keyring(supplied.policy,{PROVIDER:WrongRoot(),provider.provider_id:provider})
        if fault=='new_root_alias':
            old=keys(TENANT).policy.wrappers[0]
            alias=provider.wrap(PublicFixtureProvider().unwrap(old,old.context),supplied.policy.wrappers[-1].context)
            policy=replace(supplied.policy,wrappers=supplied.policy.wrappers[:-1]+(alias,))
            target=lambda tenant:Keyring(policy,{PROVIDER:PublicFixtureProvider(),provider.provider_id:provider})
        if fault=='target_outage':
            def target(tenant):raise RuntimeError('PRIVATE PAYLOAD PROVIDER DETAIL')
        if fault=='source_frame':
            with app.owner.begin() as c:
                c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=pg_catalog.set_byte(name,'
                    'octet_length(name)-1,pg_catalog.get_byte(name,octet_length(name)-1) # 1) WHERE id=%s',
                    (UUID(int=101),))
        calls=[]
        if fault=='unknown_journal':
            with app.owner.begin() as c:
                c.exec_driver_sql(f'INSERT INTO "{app.schema}"."_cryptalis_journal" VALUES (%s,%s,%s::jsonb)',
                                  (uuid4(),'0'*64,json.dumps({'phase':'ACTIVE'})))
            def target(tenant):calls.append(tenant);return supplied
        before=_snapshot(app)
        with pytest.raises(m.TransitionFailure) as caught:plan(app,target)
        assert 'PRIVATE PAYLOAD PROVIDER DETAIL' not in ''.join(traceback.format_exception(caught.value))
        assert _snapshot(app)==before
        if fault=='unknown_journal':assert calls==[]


def test_random_identity_failure_cannot_return_a_completed_plan(monkeypatch):
    import traceback
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        target(TENANT)
        before=_snapshot(app)
        def unavailable():raise OSError('PRIVATE PAYLOAD RANDOM DETAIL')
        monkeypatch.setattr(r,'uuid4',unavailable)
        with pytest.raises(m.TransitionFailure) as caught:plan(app,target)
        assert caught.value.code=='operation_failed_requires_inspection'
        assert 'PRIVATE PAYLOAD RANDOM DETAIL' not in ''.join(traceback.format_exception(caught.value))
        assert _snapshot(app)==before


@pytest.mark.parametrize('cost',['pause','storage'])
def test_unrepresentable_measured_cost_is_a_typed_refusal(cost):
    with application() as app:
        run(app);publish(app)
        target,_=target_factory()
        before=_snapshot(app)
        options=({'verify_rows_per_second':1e-320} if cost=='pause' else {'wal_bytes_per_row':2**53-1})
        with pytest.raises(m.TransitionFailure) as caught:plan(app,target,**options)
        assert caught.value.code==('unrepresentable_pause_estimate' if cost=='pause'
                                   else 'unrepresentable_payload_cost_estimate')
        assert _snapshot(app)==before
