"""Host-sealed payload activation and atomic public-frame cutover.

P pins the original source. A pins actual target ciphertext, before source
replacement. The database journal cannot supply either artifact's authority.
"""
import json
import time
from uuid import UUID

from cryptalis import migration as m, rotation as r
from cryptalis import _payload_transition as s


_BASE = ('format','kind','operation_id','target_id','target','runtime_role',
         'journal_schema','lock','source_lock_digest','key_policies','scopes','estimates')


def _costs(p,copy,copy_wal):
    costs=p.document['estimates']
    return m._payload_activation_estimates(costs['rows'],costs['backfill_rows_per_second'],
                                          costs['verify_rows_per_second'],copy,copy_wal)


def _activation(p,observations,copy,copy_wal):
    source=p.source
    source_document=source.document
    document={key:source_document[key] for key in _BASE}
    ancestors=source_document.get('predecessors',[])+[
        {'operation_id':str(source.operation_id),'plan_digest':source.digest},
        {'operation_id':str(p.operation_id),'plan_digest':p.digest}]
    document.update(format='cryptalis.transition/v3',kind='payload_rotation',
        operation_id=p.document['successor_operation_id'],predecessors=ancestors,
        key_policies={tenant:item['target'] for tenant,item in p.document['key_policies'].items()},
        scopes=[{'table_id':model['table_id'],'estimated_rows':observations[model['table_id']]['rows']}
                for model in source_document['lock']['models']],
        estimates=_costs(p,copy,copy_wal),payload_rotation_plan_digest=p.digest,
        payload_rotation_observations=observations,payload_batch_limits=p.document['batch_limits'])
    return m.MigrationPlan(m._canonical(document))


def _binding(p,a):
    if type(p) is not r.PayloadRotationPlan or type(a) is not m.MigrationPlan:
        raise m.TransitionFailure('payload_activation_binding_mismatch')
    d=a.document
    try:
        if d['kind']!='payload_rotation':raise ValueError
        observed=d['payload_rotation_observations']
        for table,item in p.document['models'].items():
            if (observed[table]['rows'],observed[table]['membership'])!=(item['rows'],item['membership']):
                raise ValueError
        expected=_activation(p,observed,d['estimates']['copy_rows_per_second'],
                             d['estimates']['copy_wal_bytes_per_row'])
        if expected.artifact!=a.artifact:raise ValueError
    except (KeyError,ValueError,TypeError,m.TransitionFailure):
        raise m.TransitionFailure('payload_activation_binding_mismatch',p.operation_id) from None


def _leases(prepared,operation):
    try:
        for material in prepared.values():
            for wrapper in material.policy.wrappers:
                c=wrapper.context
                material._resolve(c.domain_id,c.tenant_id,c.purpose,c.generation)
    except Exception as exc:
        raise m._safe_failure(exc,operation,()) from None


def verify_target(c,a,keys):
    """Authenticate current exact-generation bytes against immutable host A."""
    _pending_inventory(c,a)
    prepared={UUID(tenant):m._ring(keys,UUID(tenant),a).prepare() for tenant in a.document['key_policies']}
    observed=r._observe_active(c,a,keys,prepared=prepared,batch_limits=a.document['payload_batch_limits'])
    observed={table:{key:item[key] for key in ('rows','membership','frames')} for table,item in observed.items()}
    if observed!=a.document['payload_rotation_observations']:
        raise m.TransitionFailure('payload_activation_target_changed',a.operation_id)
    return prepared


def seal(p,engine,*,keys,target_keys,pin,approval,copy_rows_per_second,copy_wal_bytes_per_row):
    s._pin(p,pin)
    _costs(p,copy_rows_per_second,copy_wal_bytes_per_row)
    op=s._operation(p)
    with m._maintenance_executor(op,engine,approval) as c:
        with c.begin():
            m._lock_tables(c,op,verification=True)
            state=s._state(c,p,op,pin)
            if state is None or state['phase']!='BACKFILLED':
                raise m.TransitionFailure('payload_sealing_requires_backfilled',p.operation_id)
            s._inspect(c,p,op,state)
            prepared=s._prepare(p,keys,target_keys)
            s._observe_source(c,p,keys,{t:pair[0] for t,pair in prepared.items()})
            observed=s._verify_prefix(c,p,state,prepared)
            a=_activation(p,observed,copy_rows_per_second,copy_wal_bytes_per_row)
    _leases({t:pair[0] for t,pair in prepared.items()},p.operation_id)
    _leases({t:pair[1] for t,pair in prepared.items()},p.operation_id)
    return a


def _copy(c,p,a):
    start=c.exec_driver_sql('SELECT pg_catalog.pg_current_wal_insert_lsn()::text').scalar_one()
    started=time.perf_counter_ns()
    for model in p.source.document['lock']['models']:
        assignments=','.join(m._quote(c,f['column'])+'='+m._quote(c,s._shadow(f)) for f in model['fields'])
        copied=c.exec_driver_sql(f'UPDATE {m._table(c,model)} SET '+assignments)
        if copied.rowcount!=a.document['payload_rotation_observations'][model['table_id']]['rows']:
            raise m.TransitionFailure('payload_copy_membership_changed',a.operation_id)
    elapsed=time.perf_counter_ns()-started
    wal=c.exec_driver_sql('SELECT pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_insert_lsn(),'
                         '%s::pg_catalog.pg_lsn)::bigint',(start,)).scalar_one()
    if elapsed<0 or wal<0:raise m.TransitionFailure('payload_copy_measurement_failed',a.operation_id)
    return {'copy_wall_ns':elapsed,'copy_wal_bytes_cluster_delta':wal}


def _switch(c,p,a,state,observed):
    op=s._operation(p)
    m._lock_tables(c,a)
    metrics=_copy(c,p,a)
    for model in p.source.document['lock']['models']:
        for field in model['fields']:
            c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} DROP COLUMN {m._quote(c,s._shadow(field))}')
    m._drop_guards(c,op)
    m._install_guards(c,a)
    models={}
    for model in a.document['lock']['models']:
        item=observed[model['table_id']]
        models[model['table_id']]=dict(rows=item['rows'],chunks=state['models'][model['table_id']]['chunks'],
            scope={'count':item['rows'],'membership':item['membership']},
            active_schema=m._facts(c,model),guard=m._check_guard(c,a,model))
    pending=dict(phase='PENDING',models=models,payload_rotation_plan_digest=p.digest,cutover_measurements=metrics)
    source=p.source
    source_pin=m.DeploymentPin(source.target_id,source.operation_id,source.digest,'ACTIVE')
    source_state=m._state(c,source,source_pin)
    source_state.update(phase='SUPERSEDED',superseded_by={'operation_id':str(p.operation_id),'plan_digest':p.digest})
    m._save(c,source,source_state)
    state.update(phase='SUPERSEDED',superseded_by={'operation_id':str(a.operation_id),'plan_digest':a.digest})
    m._save(c,op,state)
    c.exec_driver_sql(f'INSERT INTO {m._journal(c,a)} VALUES (%s,%s,%s::jsonb)',
                      (a.operation_id,a.digest,json.dumps(pending)))
    m._state(c,a,m.DeploymentPin(a.target_id,a.operation_id,a.digest,'PREPARED'))
    m._active_schema(c,a,pending)
    return pending


def _pending_inventory(c,a):
    ancestors=m._check_predecessors(c,a)
    for identity,digest,state in c.exec_driver_sql(
            f'SELECT operation_id,plan_digest,state FROM {m._journal(c,a)}'):
        if identity in ancestors or identity==a.operation_id:continue
        if type(state) is not dict or state.get('phase')!='ABORTED':
            raise m.TransitionFailure('unreviewed_journal_operations',a.operation_id)
    for model in a.document['lock']['models']:
        owner=c.exec_driver_sql('SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class '
                               'WHERE oid=pg_catalog.to_regclass(%s)',(m._table(c,model),)).scalar_one()
        if owner!=a.document['target'][-1]:
            raise m.TransitionFailure('maintenance_requires_table_owner',a.operation_id)
        m._refuse_unrecorded_metadata(c,a,model)


def switch(p,a,engine,*,keys,target_keys,pin,approval):
    _binding(p,a)
    m._admit(a,pin)
    if pin.phase not in ('PREPARED','PENDING'):
        raise m.TransitionFailure('payload_switch_requires_prepared_or_pending_pin',a.operation_id)
    with m._executor(a,engine,pin,approval) as c:
        with c.begin():
            m._lock_tables(c,a,verification=True)
            row=c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,a)} WHERE operation_id=%s',
                                  (a.operation_id,)).one_or_none()
            if row is not None:
                state=m._state(c,a,pin)
                m._active_schema(c,a,state)
            else:
                if pin.phase!='PREPARED':raise m.TransitionFailure('missing_payload_activation',a.operation_id)
                op=s._operation(p)
                state=s._state(c,p,op)
                if state is None or state['phase']!='BACKFILLED':
                    raise m.TransitionFailure('payload_switch_requires_backfilled',a.operation_id)
                s._inspect(c,p,op,state)
                prepared=s._prepare(p,keys,target_keys)
                s._observe_source(c,p,keys,{t:pair[0] for t,pair in prepared.items()})
                observed=s._verify_prefix(c,p,state,prepared)
                if observed!=a.document['payload_rotation_observations']:
                    raise m.TransitionFailure('payload_activation_target_changed',a.operation_id)
                state=_switch(c,p,a,state,observed)
            target=verify_target(c,a,target_keys)
            _leases(target,a.operation_id)
            result=m._progress(a,state)
    _leases(target,a.operation_id)
    return result
