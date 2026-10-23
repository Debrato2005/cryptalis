"""Encrypted generation preparation owned by rotation, without publication authority.

P remains immutable. The source public columns and original journal stay intact.
BACKFILLED is a paired data check at this invocation, not a sealed activation
artifact. Source/target observations for publication require later host sealing.
"""
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from uuid import UUID

from cryptalis import migration as m, rotation as r
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.crypto._payload_rotation import prepare_payload_rotation_batch
from cryptalis.crypto._search_rotation import prepare_search_rotation_batch


PHASES = ('PREPARED','EXPANDED','BACKFILLED')


def _pin(p,pin):
    if (type(p) not in (r.PayloadRotationPlan,r.SearchRotationPlan) or type(pin) is not m.DeploymentPin
            or (pin.target_id,pin.operation_id,pin.plan_digest) != (p.source.target_id,p.operation_id,p.digest)
            or pin.phase not in PHASES):
        raise m.TransitionFailure(getattr(p,'purpose','rotation')+'_operation_pin_mismatch')


def _operation(p):
    # SQL helpers need the validated source lock/target plus P's real identity
    # and cost. This private context is never a MigrationPlan or deployment.
    source=p.source
    document=source.document
    document.update(operation_id=str(p.operation_id),estimates=p.document['estimates'])
    return SimpleNamespace(operation_id=p.operation_id,digest=p.digest,
                           lock_bytes=source.lock_bytes,document=document)


def _shadow(field):
    return field['payload_column']+'_rotation'


def _cursor(model,value):
    if value is None:return None
    if model['record']['codec']=='uuid16/v1':return r._uuid(value,nonzero=False)
    parsed=int(value)
    if type(value) is not str or str(parsed)!=value or not -(2**63)<=parsed<2**63:raise ValueError
    return parsed


def _source_current(c,p,op,*,own):
    source=p.source
    row=c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,op)} WHERE operation_id=%s',
                          (source.operation_id,)).one_or_none()
    if (row is None or row[0]!=source.digest
            or m._hash(row[1])!=p.document['journal_state_digest']):
        raise m.TransitionFailure(f'{p.purpose}_source_state_changed',p.operation_id)
    from cryptalis.deprotection import _inventory
    _inventory(c,source,source,own=own)
    for model in source.document['lock']['models']:
        owner=c.exec_driver_sql('SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class '
                               'WHERE oid=pg_catalog.to_regclass(%s)',(m._table(c,model),)).scalar_one()
        if owner!=source.document['target'][-1]:
            raise m.TransitionFailure('maintenance_requires_table_owner',p.operation_id)
        m._refuse_unrecorded_metadata(c,source,model)


def _state(c,p,op,pin=None):
    row=c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,op)} WHERE operation_id=%s',
                          (p.operation_id,)).one_or_none()
    if row is None:
        if pin is not None and pin.phase!='PREPARED':
            raise m.TransitionFailure(f'missing_{p.purpose}_operation',p.operation_id)
        _source_current(c,p,op,own=None)
        return None
    if row[0]!=p.digest:raise m.TransitionFailure('journal_identity_mismatch',p.operation_id)
    state=row[1]
    if type(state) is dict and state.get('phase')=='SUPERSEDED':
        raise m.TransitionFailure(f'{p.purpose}_preparation_superseded',p.operation_id)
    source=p.source
    try:
        if (type(state) is not dict or state.get('phase') not in ('EXPANDED','BACKFILLED','ABORTED')
                or set(state)!=({'phase','models','source_operation_id','source_plan_digest'} |
                    ({'aborted_to'} if state['phase']=='ABORTED' else set()))
                or state['source_operation_id']!=str(source.operation_id) or state['source_plan_digest']!=source.digest
                or set(state['models'])!=set(p.document['models'])):raise ValueError
        if state['phase']=='ABORTED' and state['aborted_to']!={
                'operation_id':str(source.operation_id),'plan_digest':source.digest}:raise ValueError
        for model in source.document['lock']['models']:
            progress=state['models'][model['table_id']]
            if set(progress)!={'cursor','rows','chunks','guard'}:raise ValueError
            r._counter(progress['rows']);r._counter(progress['chunks'])
            if (progress['rows']>p.document['models'][model['table_id']]['rows']
                    or progress['chunks']>progress['rows']
                    or bool(progress['rows'])!=bool(progress['chunks'])
                    or (progress['cursor'] is None)!=(progress['rows']==0)):raise ValueError
            _cursor(model,progress['cursor'])
            if state['phase']=='BACKFILLED' and progress['rows']!=p.document['models'][model['table_id']]['rows']:
                raise ValueError
        if pin is not None and state['phase']!='ABORTED' and PHASES.index(pin.phase)>PHASES.index(state['phase']):
            raise ValueError
    except (ValueError,KeyError,TypeError,AttributeError):
        raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id) from None
    # Own rows are skipped by inventory only AFTER their exact identity and
    # source linkage pass the checks above.
    _source_current(c,p,op,own=p.operation_id)
    return state


def _inspect(c,p,op,state):
    for model in p.source.document['lock']['models']:
        guard=m._check_guard(c,op,model)
        if guard!=state['models'][model['table_id']]['guard']:
            raise m.TransitionFailure('writer_fence_changed',p.operation_id)
        facts=m._facts(c,model)
        columns={column['name']:column for column in facts['columns']}
        for field in model['fields']:
            shadow=_shadow(field)
            actual=columns.get(shadow)
            original=columns.get(field['column'])
            if actual is None or original is None:
                raise m.TransitionFailure(f'{p.purpose}_staging_schema_changed',p.operation_id)
            expected={**original,'name':shadow,'nullable':True,'attnum':actual['attnum']}
            if actual!=expected:raise m.TransitionFailure(f'{p.purpose}_staging_schema_changed',p.operation_id)
            facts['columns'].remove(actual)
        facts['relation']['user_triggers']=False
        if m._hash(facts)!=p.document['models'][model['table_id']]['schema']:
            raise m.TransitionFailure(f'{p.purpose}_staging_schema_changed',p.operation_id)
        m._protected_contract(c,p.source,model,facts)


def _prepare(p,keys,target_keys):
    policies,prepared=r._prepare_generation(p.source,keys,target_keys,p.purpose)
    if policies!=p.document['key_policies']:
        raise m.TransitionFailure(f'{p.purpose}_rotation_policy_changed',p.operation_id)
    return prepared


def _observe_source(c,p,keys,prepared=None):
    if prepared is None:
        prepared={UUID(tenant):m._ring(keys,UUID(tenant),p.source).prepare()
                  for tenant in p.source.document['key_policies']}
    observed=r._observe_active(c,p.source,keys,prepared=prepared,batch_limits=p.document['batch_limits'])
    expected={table:{key:value for key,value in item.items() if key!='schema'}
              for table,item in p.document['models'].items()}
    if observed!=expected:raise m.TransitionFailure(f'{p.purpose}_source_changed',p.operation_id)
    return prepared


def _new_state(p):
    return dict(phase='EXPANDED',source_operation_id=str(p.source.operation_id),source_plan_digest=p.source.digest,
                models={table:dict(cursor=None,rows=0,chunks=0,guard=None) for table in p.document['models']})


def _expand(c,p,op,keys,prepared):
    m._check_connection(p.source,c,m.DeploymentPin(p.source.target_id,p.source.operation_id,p.source.digest,'ACTIVE'))
    for model in p.source.document['lock']['models']:
        if m._hash(m._facts(c,model))!=p.document['models'][model['table_id']]['schema']:
            raise m.TransitionFailure(f'{p.purpose}_source_changed',p.operation_id)
    _observe_source(c,p,keys,{t:pair[0] for t,pair in prepared.items()})
    m._lock_tables(c,op)
    m._install_guards(c,op)
    state=_new_state(p)
    for model in p.source.document['lock']['models']:
        for field in model['fields']:
            c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} ADD COLUMN {m._quote(c,_shadow(field))} bytea')
        state['models'][model['table_id']]['guard']=m._check_guard(c,op,model)
    c.exec_driver_sql(f'INSERT INTO {m._journal(c,op)} VALUES (%s,%s,%s::jsonb)',
                      (p.operation_id,p.digest,json.dumps(state)))
    _inspect(c,p,op,state)
    return state


def _progress_check(c,p,model,progress):
    record=m._quote(c,model['record']['column'])
    cursor=_cursor(model,progress['cursor'])
    prefix=f' WHERE {record}<=%s' if cursor is not None else ' WHERE false'
    params=(cursor,) if cursor is not None else ()
    count=c.exec_driver_sql(f'SELECT count(*) FROM {m._table(c,model)}'+prefix,params).scalar_one()
    if count!=progress['rows']:raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id)
    conditions=[]
    for field in model['fields']:
        old,new=m._quote(c,field['column']),m._quote(c,_shadow(field))
        conditions.append(f'(({old} IS NULL) <> ({new} IS NULL) OR '
            f'coalesce(pg_catalog.octet_length({old}),0)<>coalesce(pg_catalog.octet_length({new}),0))')
    invalid=c.exec_driver_sql(f'SELECT EXISTS(SELECT 1 FROM {m._table(c,model)}'+prefix+
        ' AND ('+' OR '.join(conditions)+'))',params).scalar_one()
    suffix=f'{record}>%s AND ' if cursor is not None else ''
    beyond=c.exec_driver_sql(f'SELECT EXISTS(SELECT 1 FROM {m._table(c,model)} WHERE '+suffix+
        '('+' OR '.join(m._quote(c,_shadow(f))+' IS NOT NULL' for f in model['fields'])+'))',params).scalar_one()
    if invalid or beyond:raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id)


def _generation(frame,field,material,p):
    if frame is not None and (int.from_bytes(frame[6:10],'big')!=material.policy.payload_generation
            or int.from_bytes(frame[10:14],'big')!=(material.policy.search_generation if field['queries'] else 0)):
        raise m.TransitionFailure('generation_mismatch',p.operation_id)


def _verify_prefix(c,p,state,prepared):
    """Authenticate exactly the committed prefix without retaining two raw/decoded pairs.

    Release each raw source reference before decoding the target. Its replacement
    plaintext is shorter than that frame. The second decoded value fits in the
    released frame slot within P's three-frame logical budget. Driver/Python
    object overhead remains excluded, as it is in the planning contract.
    """
    observations={}
    for model in p.source.document['lock']['models']:
        progress=state['models'][model['table_id']]
        _progress_check(c,p,model,progress)
        paired=deepcopy(model)
        for field in paired['fields']:field['payload_column']=_shadow(field)
        descriptors=[FieldDescriptor.from_compiled(f['descriptor'],f['descriptor_digest']) for f in model['fields']]
        remaining,after=progress['rows'],None
        membership,frames=hashlib.sha256(),hashlib.sha256()
        while remaining:
            limits={**p.document['batch_limits'],'max_rows':min(p.document['batch_limits']['max_rows'],remaining)}
            rows=r._payload_stream(c,paired,after,limits,payloads=True)
            if not rows:raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id)
            rows.reverse()
            while rows:
                row=rows.pop()
                record=row[0]
                scoped='column' in model['tenancy']
                tenant=row[1] if scoped else UUID(model['table_id'])
                source,target=prepared[tenant]
                offset=2 if scoped else 1
                pairs=[(None if row[offset+2*i] is None else bytes(row[offset+2*i]),
                        None if row[offset+2*i+1] is None else bytes(row[offset+2*i+1]))
                       for i in range(len(descriptors))]
                row=None
                hashes=[]
                for index,field in enumerate(model['fields']):
                    old,new=pairs[index]
                    pairs[index]=None
                    _generation(old,field,source,p);_generation(new,field,target,p)
                    header=None if old is None else (old[:6]+old[10:46 if field['queries'] else 14]
                        if p.purpose=='payload' else old[:10])
                    storage=None if old is None or p.purpose=='payload' or field['queries'] else hashlib.sha256(old).digest()
                    value=open_text(old,descriptors[index],tenant,record,source)
                    old=None
                    actual=open_text(new,descriptors[index],tenant,record,target)
                    if (type(value)!=type(actual) or value!=actual or
                            (new is not None and header!=(new[:6]+new[10:46 if field['queries'] else 14]
                                if p.purpose=='payload' else new[:10]))
                            or (storage is not None and storage!=hashlib.sha256(new).digest())):
                        raise m.TransitionFailure(f'{p.purpose}_value_verification_failed',p.operation_id)
                    hashes.append(None if new is None else hashlib.sha256(new).hexdigest())
                    value=actual=new=None
                identity=[str(record),str(tenant)]
                membership.update(m._canonical(identity));frames.update(m._canonical(identity+[hashes]))
                after=str(record);remaining-=1
        if after!=progress['cursor']:raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id)
        observations[model['table_id']]=dict(rows=progress['rows'],membership=membership.hexdigest(),frames=frames.hexdigest())
    for pair in prepared.values():(r._same_payload_roots if p.purpose=='payload' else r._same_search_roots)(*pair)
    return observations


def _chunk(c,p,op,state,prepared):
    for model in p.source.document['lock']['models']:
        progress=state['models'][model['table_id']]
        rows=r._payload_stream(c,model,progress['cursor'],p.document['batch_limits'])
        if not rows:continue
        record=m._quote(c,model['record']['column'])
        lower=_cursor(model,progress['cursor'])
        bounds=(f'{record}>%s AND ' if lower is not None else '')+f'{record}<=%s'
        params=((lower,) if lower is not None else ())+(rows[-1][0],)
        populated=c.exec_driver_sql(f'SELECT EXISTS(SELECT 1 FROM {m._table(c,model)} WHERE '+bounds+
            ' AND ('+' OR '.join(m._quote(c,_shadow(f))+' IS NOT NULL' for f in model['fields'])+'))',params).scalar_one()
        if populated:raise m.TransitionFailure(f'{p.purpose}_progress_changed',p.operation_id)
        scoped='column' in model['tenancy']
        offset=2 if scoped else 1
        output={row[0]:[] for row in rows}
        for index,field in enumerate(model['fields']):
            descriptor=FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest'])
            groups={}
            for row in rows:
                tenant=row[1] if scoped else UUID(model['table_id'])
                raw=row[offset+index]
                groups.setdefault(tenant,[]).append((row[0],None if raw is None else bytes(raw)))
            for tenant,group in groups.items():
                transform=prepare_payload_rotation_batch if p.purpose=='payload' else prepare_search_rotation_batch
                for identity,frame in transform(tuple(group),descriptor,tenant,
                        source=prepared[tenant][0],target=prepared[tenant][1],
                        max_rows=p.document['batch_limits']['max_rows'],max_bytes=p.document['batch_limits']['max_bytes']):
                    output[identity].append(frame)
        statement=f'UPDATE {m._table(c,model)} SET '+','.join(
            m._quote(c,_shadow(f))+'=%s' for f in model['fields'])+f' WHERE {record}=%s'
        result=c.exec_driver_sql(statement,[tuple(output[row[0]])+(row[0],) for row in rows])
        if result.rowcount!=len(rows):raise m.TransitionFailure(f'{p.purpose}_chunk_membership_changed',p.operation_id)
        for pair in prepared.values():(r._same_payload_roots if p.purpose=='payload' else r._same_search_roots)(*pair)
        progress.update(cursor=str(rows[-1][0]),rows=progress['rows']+len(rows),chunks=progress['chunks']+1)
        m._save(c,op,state)
        return True
    return False


def apply(p,engine,*,keys,target_keys,pin,approval,until,max_chunks):
    _pin(p,pin)
    if until not in ('EXPANDED','BACKFILLED') or (max_chunks is not None and (type(max_chunks) is not int or max_chunks<1)):
        raise m.TransitionFailure('invalid_payload_apply_bound',p.operation_id)
    op=_operation(p)
    with m._maintenance_executor(op,engine,approval) as c:
        with c.begin():
            m._lock_tables(c,op,verification=True)
            state=_state(c,p,op,pin)
            if state is not None and state['phase']=='ABORTED':
                raise m.TransitionFailure('operation_aborted',p.operation_id)
            prepared=_prepare(p,keys,target_keys)
            if state is None:state=_expand(c,p,op,keys,prepared)
            else:
                _inspect(c,p,op,state)
                _observe_source(c,p,keys,{t:pair[0] for t,pair in prepared.items()})
                _verify_prefix(c,p,state,prepared)
        chunks=0
        if until=='BACKFILLED':
            while state['phase']!='BACKFILLED':
                with c.begin():
                    m._lock_tables(c,op,verification=True)
                    state=_state(c,p,op,pin);_inspect(c,p,op,state)
                    prepared=_prepare(p,keys,target_keys)
                    if not _chunk(c,p,op,state,prepared):
                        _observe_source(c,p,keys,{t:pair[0] for t,pair in prepared.items()})
                        _verify_prefix(c,p,state,prepared)
                        state['phase']='BACKFILLED';m._save(c,op,state)
                chunks+=1
                if max_chunks is not None and chunks>=max_chunks:break
        result=m._progress(op,state)
    try:
        for pair in prepared.values():(r._same_payload_roots if p.purpose=='payload' else r._same_search_roots)(*pair)
    except Exception as exc:
        raise m._safe_failure(exc,p.operation_id,()) from None
    return result


def status(p,engine,*,pin):
    _pin(p,pin)
    op=_operation(p)
    source=p.source
    with m._connection(engine,p.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        if m._target(c)[:-1]!=source.document['target'][:-1]:
            raise m.TransitionFailure('wrong_database_target',p.operation_id)
        m._runtime_safety(c,source.document['runtime_role'],source.document['target'][-1],
                          source.document['lock']['models'],journal=m._journal(c,op),operation_id=p.operation_id)
        state=_state(c,p,op,pin)
        if state is None or state['phase']=='ABORTED':
            m._check_connection(source,c,m.DeploymentPin(source.target_id,source.operation_id,source.digest,'ACTIVE'))
        else:_inspect(c,p,op,state)
        progress=m.Progress(p.operation_id,'PREPARED',0,0,'') if state is None else m._progress(op,state)
        return m.TransitionStatus(p.operation_id,progress.phase,pin.phase,progress.committed_rows,
            progress.committed_chunks,False,'NOT_PERFORMED',
            'Recorded preparation progress only. Keep writers stopped until cancellation or sealed publication.')


def abort(p,engine,*,keys,source_pin,approval):
    if type(p) not in (r.PayloadRotationPlan,r.SearchRotationPlan):raise m.TransitionFailure('invalid_rotation_plan')
    source=p.source
    m._admit(source,source_pin)
    if source_pin.phase!='ACTIVE':raise m.TransitionFailure('source_pin_must_be_active',p.operation_id)
    op=_operation(p)
    with m._maintenance_executor(op,engine,approval) as c:
        with c.begin():
            m._lock_tables(c,op,verification=True)
            state=_state(c,p,op)
            if state is not None and state['phase']=='ABORTED':
                m._check_connection(source,c,source_pin)
            else:
                if state is not None:_inspect(c,p,op,state)
                _observe_source(c,p,keys)
                if state is None:
                    m._check_connection(source,c,source_pin)
                    state=_new_state(p)
                else:
                    m._lock_tables(c,op)
                    for model in source.document['lock']['models']:
                        for field in model['fields']:
                            c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} DROP COLUMN {m._quote(c,_shadow(field))}')
                    m._drop_guards(c,op)
                    m._check_connection(source,c,source_pin)
                state.update(phase='ABORTED',aborted_to={'operation_id':str(source.operation_id),'plan_digest':source.digest})
                exists=c.exec_driver_sql(f'SELECT 1 FROM {m._journal(c,op)} WHERE operation_id=%s',
                                         (p.operation_id,)).one_or_none()
                if exists:m._save(c,op,state)
                else:c.exec_driver_sql(f'INSERT INTO {m._journal(c,op)} VALUES (%s,%s,%s::jsonb)',
                                      (p.operation_id,p.digest,json.dumps(state)))
        return m._progress(op,state)
