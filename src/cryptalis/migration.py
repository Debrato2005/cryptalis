"""Bounded PostgreSQL maintenance transitions. Research prototype.

The host authenticates the plan, target, writer exclusion, and deployment pin.
A database journal is progress evidence, never authority after restore. No
production provider or publication procedure is supplied by this module.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
import time
from uuid import UUID, uuid4
from psycopg import sql

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from cryptalis.crypto.cf1 import FieldDescriptor, seal_text, open_text
from cryptalis.crypto.keys import CryptoFailure, Keyring
from cryptalis.manifest.compiler import compile_protection, _schema_facts, _canonical, _previous_lock
from cryptalis.manifest.parser import decode_manifest_json

JOURNAL = '_cryptalis_journal'
PHASES = ('PREPARED', 'EXPANDED', 'BACKFILLED', 'VERIFIED', 'PENDING', 'ACTIVE')


class TransitionFailure(RuntimeError):
    """Safe, actionable failure; durable progress requires current inspection."""
    effects = 'INSPECT_JOURNAL'
    retry = 'after_inspection'
    def __init__(self, code, operation_id=None, sqlstate=None, *, cleanup_errors=()):
        self.code, self.operation_id, self.sqlstate = code, operation_id, sqlstate
        self.cleanup_errors = tuple(cleanup_errors)
        cleanup = ''.join(f' cleanup={stage}:{cause}:{state or "UNKNOWN"};'
                          for stage,cause,state in self.cleanup_errors)
        super().__init__(f'{code}; operation={operation_id or "unstarted"}; SQLSTATE={sqlstate or "UNKNOWN"}. '
                         'Keep writers stopped. Inspect this operation and the external current policy before resume.' + cleanup)


@dataclass(frozen=True)
class DeploymentPin:
    """Host-authenticated current artifact, stored OUTSIDE database snapshots."""
    target_id: UUID
    operation_id: UUID
    plan_digest: str
    phase: str


@dataclass(frozen=True)
class MaintenanceApproval:
    writer_exclusion: str
    approved_pause_seconds: float


@dataclass(frozen=True)
class MigrationPlan:
    artifact: bytes
    def __post_init__(self):
        doc = decode_manifest_json(self.artifact)
        if (doc.get('format') != 'cryptalis.transition/v1' or _canonical(doc) != self.artifact
                or doc.get('kind') != 'protect'):
            raise TransitionFailure('invalid_plan')
        for name in ('operation_id', 'target_id'):
            if UUID(doc[name]).int == 0: raise TransitionFailure('invalid_plan')
    def __str__(self):
        costs = self.document['estimates']
        rates = (f'backfill {costs["backfill_rows_per_second"]:g} rows/s; '
                 f'verify {costs["verify_rows_per_second"]:g} rows/s'
                 if 'backfill_rows_per_second' in costs and 'verify_rows_per_second' in costs
                 else 'measured rates unavailable in this historical artifact')
        return (f'Estimated writer pause: {costs["writer_pause_seconds_estimate"]} s '
                f'for {costs["rows"]} rows ({rates}). '
                'Uninterrupted backfill and one final verification; a verification checkpoint or retry adds another pass. '
                + costs['limits'])
    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def target_id(self): return UUID(self.document['target_id'])
    @property
    def operation_id(self): return UUID(self.document['operation_id'])
    @property
    def lock_bytes(self): return _canonical(self.document['lock'])


@dataclass(frozen=True)
class Progress:
    operation_id: UUID
    phase: str
    committed_rows: int
    committed_chunks: int
    remedy: str


def _hash(value): return hashlib.sha256(_canonical(value)).hexdigest()


def _quote(c, name): return c.dialect.identifier_preparer.quote_identifier(name)


def _table(c, model): return _quote(c, model['schema']) + '.' + _quote(c, model['table'])


def _journal(c, p): return _quote(c, p.document['journal_schema']) + '.' + _quote(c, JOURNAL)


def _facts(c, model):
    facts = _schema_facts(c, model['schema'], model['table'])
    if facts is None: raise TransitionFailure('missing_table')
    facts.pop('_relation_names')
    for item in facts['constraints'] + facts['indexes']: item.pop('definition')
    return facts


def _target(c):
    return list(c.exec_driver_sql('SELECT current_database(), (SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database()), inet_server_addr()::text, inet_server_port(), current_user').one())


def _policy(ring):
    if not isinstance(ring, Keyring): raise TransitionFailure('missing_key_policy')
    p = ring.policy
    return _hash({'domain':str(p.domain_id),'tenant':str(p.tenant_id), 'payload':p.payload_generation,
        'search':p.search_generation, 'wrappers':[{'provider':str(w.provider_id), 'context':{
            'domain':str(w.context.domain_id),'tenant':str(w.context.tenant_id),'purpose':w.context.purpose,
            'root':str(w.context.root_id),'generation':w.context.generation},
            'wrapper':hashlib.sha256(w.sealed).hexdigest()} for w in p.wrappers]})


def _ring(keys, tenant, p):
    ring = keys(tenant) if callable(keys) else keys
    if (not isinstance(ring, Keyring) or ring.policy.tenant_id != tenant or
            str(ring.policy.domain_id) != p.document['lock']['domain_id'] or
            _policy(ring) != p.document['key_policies'].get(str(tenant))):
        raise TransitionFailure('key_policy_changed', p.operation_id)
    return ring


def plan(manifest, mapping, engine, *, writers, search_reviews=(), keys, runtime_role,
         target_id, backfill_rows_per_second, verify_rows_per_second,
         temporary_bytes_per_row=None, wal_bytes_per_row=None):
    """Read-only compiler admission plus target, keys, scope, and cost estimates.

    Rates and per-row costs are explicit host observations/estimates, not
    qualified budgets or upper bounds. Measure representative staging data.
    """
    if not isinstance(target_id, UUID) or not target_id.int or not isinstance(runtime_role,str) or not runtime_role:
        raise TransitionFailure('invalid_target_or_runtime_role')
    rates = (backfill_rows_per_second, verify_rows_per_second)
    if any(type(r) not in (int,float) or not math.isfinite(r) or r <= 0 for r in rates):
        raise TransitionFailure('missing_measured_rates')
    proposal = compile_protection(manifest, mapping, engine, writers=writers, search_reviews=search_reviews)
    if any(type(cost) is not int or not 1<=cost<2**53 for cost in (temporary_bytes_per_row,wal_bytes_per_row)):
        raise TransitionFailure('missing_measured_storage_or_wal_costs')
    lock = json.loads(proposal.lock_bytes)
    policies, scopes, rows, plaintext_bytes = {}, [], 0, 0
    with _connection(engine) as c:
        target = _target(c)
        role = c.exec_driver_sql('SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, pg_catalog.pg_has_role(rolname,current_user,\'MEMBER\') FROM pg_catalog.pg_roles WHERE rolname=%s',(runtime_role,)).one_or_none()
        if role is None or any(role) or runtime_role == target[-1]: raise TransitionFailure('unsafe_runtime_role')
        for model in lock['models']:
            if _facts(c,model) != model['source_schema']: raise TransitionFailure('stale_plan_schema')
            ownership=c.exec_driver_sql('SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass(%s)',(_table(c,model),)).scalar_one()
            if ownership != target[-1]: raise TransitionFailure('maintenance_requires_table_owner')
            tenant = _quote(c,model['tenancy']['column']) if 'column' in model['tenancy'] else None
            tenants=c.exec_driver_sql(f'SELECT DISTINCT {tenant} FROM {_table(c,model)}').scalars().all() if tenant else [UUID(model['table_id'])]
            for t in tenants:
                ring=keys(t) if callable(keys) else keys
                if ring.policy.domain_id != UUID(lock['domain_id']) or ring.policy.tenant_id != t:
                    raise TransitionFailure('missing_key_policy')
                if any(f['queries'] for f in model['fields']) and ring.policy.search_generation is None:
                    raise TransitionFailure('missing_search_policy')
                policies[str(t)] = _policy(ring)
            count=c.exec_driver_sql(f'SELECT count(*) FROM {_table(c,model)}').scalar_one()
            size=c.exec_driver_sql(f'SELECT coalesce(sum('+'+'.join(f'coalesce(octet_length({_quote(c,f["column"])}),0)' for f in model['fields'])+f'),0) FROM {_table(c,model)}').scalar_one()
            scopes.append({'table_id':model['table_id'],'estimated_rows':count})
            rows+=count; plaintext_bytes+=size
        schema=lock['models'][0]['schema']
        if c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_quote(c,schema)+'.'+_quote(c,JOURNAL),)).scalar_one() is not None:
            raise TransitionFailure('existing_transition_requires_inspection')
    estimates={'rows':rows,'plaintext_bytes':plaintext_bytes,'temporary_bytes_estimate':rows*temporary_bytes_per_row,
        'wal_bytes_estimate':rows*wal_bytes_per_row,'provider_unwraps_per_cold_preparation':sum(len((keys(UUID(t)) if callable(keys) else keys).policy.wrappers) for t in policies),
        'backfill_seconds_estimate':math.ceil(rows/rates[0]), 'verify_seconds_estimate':math.ceil(rows/rates[1]),
        'backfill_rows_per_second':rates[0], 'verify_rows_per_second':rates[1],
        'writer_pause_seconds_estimate':math.ceil(rows/rates[0]+rows/rates[1]),
        'checkpoint_extra_verify_seconds_estimate':math.ceil(rows/rates[1]),
        'cost_basis':'Host-supplied per-row staging observations/estimates; not bounds or qualification.',
        'limits':'Host rate estimates exclude lock drain, DDL, index build, publication delay and capacity guarantees.'}
    return MigrationPlan(_canonical({'format':'cryptalis.transition/v1','kind':'protect','operation_id':str(uuid4()),
        'target_id':str(target_id),'target':target,'runtime_role':runtime_role,'journal_schema':schema,
        'lock':lock,'source_lock_digest':proposal.source_lock_digest,'key_policies':policies,'scopes':scopes,'estimates':estimates}))


def _admit(p,pin):
    if (not isinstance(p,MigrationPlan) or not isinstance(pin,DeploymentPin) or
        (pin.target_id,pin.operation_id,pin.plan_digest) != (p.target_id,p.operation_id,p.digest) or
        pin.phase not in PHASES + ('ACTIVATING',)):
        raise TransitionFailure('external_policy_mismatch',p.operation_id if isinstance(p,MigrationPlan) else None)


def _approve_maintenance(p,approval):
    if not isinstance(approval,MaintenanceApproval):
        raise TransitionFailure('maintenance_approval_required',p.operation_id)
    if (not isinstance(approval.writer_exclusion,str) or not approval.writer_exclusion.strip() or
            type(approval.approved_pause_seconds) not in (int,float) or not math.isfinite(approval.approved_pause_seconds) or
            approval.approved_pause_seconds < p.document['estimates']['writer_pause_seconds_estimate']):
        raise TransitionFailure('writer_exclusion_or_pause_not_approved',p.operation_id)


def _safe_failure(exc,operation_id,cleanup_errors):
    if isinstance(exc,TransitionFailure):
        return TransitionFailure(exc.code,exc.operation_id or operation_id,exc.sqlstate,
                                 cleanup_errors=exc.cleanup_errors + tuple(cleanup_errors))
    if isinstance(exc,SQLAlchemyError):
        return TransitionFailure('database_effect_requires_inspection',operation_id,
                                 getattr(getattr(exc,'orig',None),'sqlstate',None),cleanup_errors=cleanup_errors)
    if isinstance(exc,CryptoFailure):
        return TransitionFailure(exc.code,operation_id,cleanup_errors=cleanup_errors)
    return TransitionFailure('operation_failed_requires_inspection',operation_id,cleanup_errors=cleanup_errors)


@contextmanager
def _connection(engine,operation_id=None,*,exclusive=False):
    """Sanitize acquisition and operation errors; report every cleanup failure.

    Exclusive executors invalidate their physical session so session advisory
    locks cannot return to a pool. Read-only callers close their own connection.
    """
    c=None; driver=None; primary=None; cleanup_errors=[]
    try:
        c=engine.connect()
        if exclusive: driver=c.connection.driver_connection
        yield c
    except BaseException as exc:
        primary=exc
    finally:
        if c is not None:
            for stage in (('rollback','invalidate','close') if exclusive else ('close',)):
                try:
                    getattr(c,stage)()
                except Exception as exc:
                    cleanup_errors.append((stage,type(exc).__name__,getattr(getattr(exc,'orig',None),'sqlstate',None)))
                    if stage=='invalidate' and driver is not None:
                        # Even a failed SQLAlchemy invalidation must not leave
                        # a session advisory lock on a reusable connection.
                        try: driver.close()
                        except Exception as fallback:
                            cleanup_errors.append(('driver_close',type(fallback).__name__,getattr(fallback,'sqlstate',None)))
    if primary is not None:
        if isinstance(primary,Exception):
            raise _safe_failure(primary,operation_id,cleanup_errors) from None
        if cleanup_errors: primary.add_note(f'Cryptalis cleanup failures: {cleanup_errors!r}')
        raise primary
    if cleanup_errors:
        raise TransitionFailure('connection_cleanup_requires_inspection',operation_id,cleanup_errors=cleanup_errors) from None


@contextmanager
def _executor(p,engine,pin,approval):
    _admit(p,pin)
    _approve_maintenance(p,approval)
    try:
        _previous_lock(p.lock_bytes,p.document['lock'],engine)
    except ValueError:
        raise TransitionFailure('invalid_compiler_lock',p.operation_id) from None
    lock=int.from_bytes(hashlib.sha256(_canonical([(m['schema'],m['table']) for m in p.document['lock']['models']])).digest()[:8],'big',signed=True)
    with _connection(engine,p.operation_id,exclusive=True) as c:
        if _target(c) != p.document['target']: raise TransitionFailure('wrong_database_target',p.operation_id)
        c.exec_driver_sql("SET lock_timeout = '5s'")
        c.exec_driver_sql('SET synchronous_commit = on')
        acquired=c.exec_driver_sql('SELECT pg_catalog.pg_try_advisory_lock(%s)',(lock,)).scalar_one()
        c.commit()
        if not acquired: raise TransitionFailure('executor_already_running',p.operation_id)
        yield c


def _state(c,p,pin,*,allow_aborted=False):
    exists=c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_journal(c,p),)).scalar_one()
    if exists is None:
        if pin.phase != 'PREPARED': raise TransitionFailure('restored_or_missing_transition',p.operation_id)
        return None
    row=c.exec_driver_sql(f'SELECT plan_digest, state FROM {_journal(c,p)} WHERE operation_id=%s',(p.operation_id,)).one_or_none()
    if row is None or row[0] != p.digest: raise TransitionFailure('journal_identity_mismatch',p.operation_id)
    state=row[1]
    if state['phase']=='ABORTED':
        if allow_aborted and pin.phase=='PREPARED': return state
        raise TransitionFailure('operation_aborted',p.operation_id)
    required='PENDING' if pin.phase=='ACTIVATING' else pin.phase
    if state['phase'] not in PHASES or PHASES.index(state['phase']) < PHASES.index(required):
        raise TransitionFailure('restored_state_behind_external_pin',p.operation_id)
    if state['phase']=='ACTIVE' and pin.phase not in ('ACTIVE','ACTIVATING'):
        raise TransitionFailure('external_policy_behind_database',p.operation_id)
    return state


def _save(c,p,state):
    result=c.exec_driver_sql(f'UPDATE {_journal(c,p)} SET state=%s::jsonb WHERE operation_id=%s AND plan_digest=%s',
        (json.dumps(state,separators=(',',':')),p.operation_id,p.digest))
    if result.rowcount!=1:
        raise TransitionFailure('journal_marker_write_failed',p.operation_id)


def _guard_names(p,model):
    # Functions are schema-scoped; this table-independent operation function
    # is shared within each schema. Trigger names are local to each table.
    suffix=p.operation_id.hex
    return '_cryptalis_'+suffix+'_pause', '_cryptalis_'+suffix+'_guard'


def _drop_guards(c,p):
    functions=set()
    for model in p.document['lock']['models']:
        trigger,function=_guard_names(p,model)
        c.exec_driver_sql(f'DROP TRIGGER {_quote(c,trigger)} ON {_table(c,model)}')
        functions.add(_quote(c,model['schema'])+'.'+_quote(c,function))
    # No CASCADE: an unexpected dependent object aborts the transaction.
    for fn in sorted(functions): c.exec_driver_sql(f'DROP FUNCTION {fn}()')


def _guard_facts(c,p,model):
    trigger,function=_guard_names(p,model)
    row=c.exec_driver_sql('''SELECT g.tgenabled, g.tgtype, g.tgqual IS NULL, g.tgnargs,
        n.nspname, f.proname, f.prosecdef, f.proconfig, f.prosrc, pg_catalog.pg_get_userbyid(f.proowner)
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_proc f ON f.oid=g.tgfoid
        JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
        WHERE g.tgrelid=pg_catalog.to_regclass(%s) AND g.tgname=%s''',(_table(c,model),trigger)).one_or_none()
    if row is None: return None
    inventory=c.exec_driver_sql('''SELECT g.tgname, g.tgenabled,
        pg_catalog.pg_get_triggerdef(g.oid), f.prosrc, f.prosecdef, f.proconfig,
        pg_catalog.pg_get_userbyid(f.proowner)
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_proc f ON f.oid=g.tgfoid
        WHERE g.tgrelid=pg_catalog.to_regclass(%s) AND NOT g.tgisinternal
        ORDER BY g.tgname''',(_table(c,model),)).all()
    # The compiler's boolean user_triggers flag cannot distinguish our guard
    # from a subsequently added callback. Bind every non-internal trigger.
    return list(row)+[[list(item) for item in inventory]]


def _lock_tables(c,p,*,verification=False):
    # EXCLUSIVE excludes even locking readers and privileged writers, while
    # plain SELECT retains ACCESS SHARE. DDL upgrades to ACCESS EXCLUSIVE.
    models=sorted(p.document['lock']['models'],key=lambda m:(m['schema'],m['table']))
    if verification:
        for model in models: c.exec_driver_sql(f'LOCK TABLE {_table(c,model)} IN EXCLUSIVE MODE')
        return
    previous=c.exec_driver_sql('SHOW lock_timeout').scalar_one()
    for attempt in range(3):
        try:
            # A waiting ACCESS EXCLUSIVE request also queues new SELECTs.
            # Rollback to this savepoint releases partial upgrades, while
            # retaining earlier verification locks and its validated data.
            with c.begin_nested():
                c.exec_driver_sql("SET LOCAL lock_timeout = '100ms'")
                for model in models:
                    c.exec_driver_sql(f'LOCK TABLE {_table(c,model)} IN ACCESS EXCLUSIVE MODE')
                c.exec_driver_sql("SELECT pg_catalog.set_config('lock_timeout', %s, true)",(previous,))
            return
        except SQLAlchemyError as exc:
            if getattr(getattr(exc,'orig',None),'sqlstate',None)!='55P03': raise
        if attempt<2: time.sleep(.05)
    raise TransitionFailure('table_lock_busy_retry',p.operation_id,'55P03')


def _stream(c,model,*,payloads=False,identity_only=False,after=None,limit=1000):
    names=[model['record']['column']]
    scoped='column' in model['tenancy']
    if scoped: names.append(model['tenancy']['column'])
    if not identity_only:
        for f in model['fields']:
            names.append(f['column'])
            if payloads: names.append(f['payload_column'])
    sql='SELECT '+','.join(_quote(c,n) for n in names)+f' FROM {_table(c,model)}'
    params=()
    if after is not None:
        value=UUID(after) if model['record']['codec']=='uuid16/v1' else int(after)
        sql+=f' WHERE {_quote(c,names[0])} > %s'; params=(value,)
    sql+=f' ORDER BY {_quote(c,names[0])} LIMIT %s'
    return c.exec_driver_sql(sql,params+(limit,)).all()


def _scope(c,model):
    digest=hashlib.sha256(); total=0; cursor=None
    # Membership binds only identities. Full value/frame authentication still
    # runs separately in _verify before the same transaction can switch.
    while rows:=_stream(c,model,identity_only=True,after=cursor):
        for row in rows:
            tenant=row[1] if 'column' in model['tenancy'] else UUID(model['table_id'])
            digest.update(_canonical([str(row[0]),str(tenant)])); total+=1
        cursor=str(rows[-1][0])
    return {'count':total,'membership':digest.hexdigest()}


def _frame_check(c,f):
    col=_quote(c,f['payload_column']); eq=bool(f['queries']); overhead=74 if eq else 42
    magic='434631000101' if eq else '434631000100'
    op='<>' if eq else '='
    return f"{col} IS NULL OR (pg_catalog.octet_length({col}) BETWEEN {overhead} AND {16777216+overhead} AND pg_catalog.substring({col},1,6)=pg_catalog.decode('{magic}','hex') AND pg_catalog.substring({col},7,4)<>pg_catalog.decode('00000000','hex') AND pg_catalog.substring({col},11,4){op}pg_catalog.decode('00000000','hex'))"


def _expand(c,p):
    _lock_tables(c,p)
    for model in p.document['lock']['models']:
        if _facts(c,model)!=model['source_schema']: raise TransitionFailure('source_schema_changed',p.operation_id)
    c.exec_driver_sql(f'CREATE TABLE {_journal(c,p)} (operation_id uuid PRIMARY KEY, plan_digest text NOT NULL, state jsonb NOT NULL)')
    c.exec_driver_sql(f'REVOKE ALL ON {_journal(c,p)} FROM PUBLIC')
    c.exec_driver_sql(f'GRANT SELECT ON {_journal(c,p)} TO {_quote(c,p.document["runtime_role"])}')
    models={}; functions=set()
    for model in p.document['lock']['models']:
        table=_table(c,model); trigger,function=_guard_names(p,model)
        fn=_quote(c,model['schema'])+'.'+_quote(c,function)
        # SECURITY INVOKER. Runtime cannot become the table owner. Operator must
        # separately exclude every writer with owner/DDL credentials.
        owner=p.document['target'][-1].replace("'","''")
        body=f"BEGIN IF CURRENT_USER <> '{owner}' THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Cryptalis maintenance: writers paused; retry only after matching deployment publication'; END IF; RETURN NULL; END"
        literal=sql.Literal(body).as_string(c.connection.driver_connection)
        if fn not in functions:
            try:
                c.exec_driver_sql(f'CREATE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS {literal}')
            except SQLAlchemyError as exc:
                if getattr(getattr(exc,'orig',None),'sqlstate',None)=='42723':
                    raise TransitionFailure('guard_function_conflict',p.operation_id,'42723') from None
                raise
            c.exec_driver_sql(f'REVOKE ALL ON FUNCTION {fn}() FROM PUBLIC')
            functions.add(fn)
        c.exec_driver_sql(f'CREATE TRIGGER {_quote(c,trigger)} BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON {table} FOR EACH STATEMENT EXECUTE FUNCTION {fn}()')
        c.exec_driver_sql(f'ALTER TABLE {table} ENABLE ALWAYS TRIGGER {_quote(c,trigger)}')
        for f in model['fields']:
            c.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN {_quote(c,f["payload_column"])} bytea')
            if f['queries']:
                tenant=_quote(c,model['tenancy']['column'])+', ' if 'column' in model['tenancy'] else ''
                unique='UNIQUE ' if 'unique' in f['queries'] else ''
                c.exec_driver_sql(f'CREATE {unique}INDEX {_quote(c,f["payload_column"]+"_eq")} ON {table} USING btree ({tenant}(pg_catalog.substring({_quote(c,f["payload_column"])},15,32)) pg_catalog.bytea_ops)')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {_quote(c,f["payload_column"]+"_frame")} CHECK ({_frame_check(c,f)})')
        models[model['table_id']]={'scope':_scope(c,model),'cursor':None,'rows':0,'chunks':0,
            'schema':_facts(c,model),'guard':_guard_facts(c,p,model)}
    state={'phase':'EXPANDED','models':models}
    c.exec_driver_sql(f'INSERT INTO {_journal(c,p)} VALUES (%s,%s,%s::jsonb)',(p.operation_id,p.digest,json.dumps(state)))
    return state


def _inspect_paused(c,p,state):
    for model in p.document['lock']['models']:
        observed=state['models'][model['table_id']]
        if _guard_facts(c,p,model)!=observed['guard'] or not observed['guard'] or observed['guard'][0]!='A':
            raise TransitionFailure('writer_fence_changed',p.operation_id)
        if _facts(c,model)!=observed['schema']: raise TransitionFailure('transition_schema_changed',p.operation_id)


def _backfill_chunk(c,p,state,keys,chunk_size):
    _inspect_paused(c,p,state)
    for model in p.document['lock']['models']:
        progress=state['models'][model['table_id']]
        rows=_stream(c,model,after=progress['cursor'],limit=chunk_size)
        if not rows: continue
        # Immutable field-only context. Never retain keys or tenant/row context
        # across chunks; those are still resolved and checked below per value.
        descriptors=tuple(FieldDescriptor.from_compiled(f['descriptor'],f['descriptor_digest']) for f in model['fields'])
        scoped='column' in model['tenancy']; material={}; params=[]
        for row in rows:
            tenant=row[1] if scoped else UUID(model['table_id']); offset=2 if scoped else 1
            if tenant not in material: material[tenant]=_ring(keys,tenant,p).prepare()
            body=[seal_text(row[offset+i],descriptor,tenant,row[0],material[tenant]) for i,descriptor in enumerate(descriptors)]
            params.append(tuple(body)+(row[0],))
        statement=f'UPDATE {_table(c,model)} SET '+','.join(_quote(c,f['payload_column'])+'=%s' for f in model['fields'])+f' WHERE {_quote(c,model["record"]["column"])}=%s'
        c.exec_driver_sql(statement,params)
        progress['cursor']=str(rows[-1][0]); progress['rows']+=len(rows); progress['chunks']+=1
        # Marker and all row updates share THIS transaction. Resume reads cursor
        # only after commit; a NULL source still has durable membership progress.
        _save(c,p,state)
        return True
    state['phase']='BACKFILLED'; _save(c,p,state); return False


def _verify(c,p,state,keys):
    _inspect_paused(c,p,state)
    digests={}
    for model in p.document['lock']['models']:
        progress=state['models'][model['table_id']]
        if _scope(c,model)!=progress['scope']: raise TransitionFailure('membership_changed',p.operation_id)
        if progress['rows']!=progress['scope']['count']: raise TransitionFailure('incomplete_backfill',p.operation_id)
        descriptors=tuple(FieldDescriptor.from_compiled(f['descriptor'],f['descriptor_digest']) for f in model['fields'])
        cursor=None; digest=hashlib.sha256()
        while rows:=_stream(c,model,payloads=True,after=cursor):
            material={}
            for row in rows:
                tenant=row[1] if 'column' in model['tenancy'] else UUID(model['table_id']); offset=2 if 'column' in model['tenancy'] else 1
                if tenant not in material: material[tenant]=_ring(keys,tenant,p).prepare()
                digest.update(_canonical([str(row[0]),str(tenant)]))
                for i,f in enumerate(model['fields']):
                    source,frame=row[offset+2*i:offset+2*i+2]
                    frame=bytes(frame) if frame is not None else None
                    admitted=material[tenant].policy
                    if frame is not None and (int.from_bytes(frame[6:10],'big')!=admitted.payload_generation or int.from_bytes(frame[10:14],'big')!=(admitted.search_generation if f['queries'] else 0)):
                        raise TransitionFailure('generation_mismatch',p.operation_id)
                    value=open_text(frame,descriptors[i],tenant,row[0],material[tenant])
                    if type(value)!=type(source) or value!=source: raise TransitionFailure('value_verification_failed',p.operation_id)
                    digest.update(b'\x00' if frame is None else b'\x01'+len(frame).to_bytes(4,'big')+frame)
            cursor=str(rows[-1][0])
        digests[model['table_id']]=digest.hexdigest()
    return digests


def _switch(c,p,state,keys):
    _lock_tables(c,p,verification=True)
    digests=_verify(c,p,state,keys)
    if 'verification' in state and digests != state['verification']:
        raise TransitionFailure('verification_changed_before_switch',p.operation_id)
    # Verification and DDL share this transaction and its write-excluding lock.
    # A separately committed VERIFIED checkpoint still requires a fresh pass.
    state['verification']=digests
    _lock_tables(c,p)
    for model in p.document['lock']['models']:
        for f in model['fields']:
            table=_table(c,model)
            # No CASCADE: an unexpected dependency blocks the atomic switch.
            c.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN {_quote(c,f["column"])}')
            c.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN {_quote(c,f["payload_column"])} TO {_quote(c,f["column"])}')
            if not f['source']['nullable']:
                c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN {_quote(c,f["column"])} SET NOT NULL')
        state['models'][model['table_id']]['active_schema']=_facts(c,model)
    state['phase']='PENDING'; _save(c,p,state)


def _active_schema(c,p,state):
    for model in p.document['lock']['models']:
        if _facts(c,model)!=state['models'][model['table_id']]['active_schema']:
            raise TransitionFailure('active_schema_mismatch',p.operation_id)


def _activate(c,p,state,pin):
    if pin.phase!='ACTIVATING': raise TransitionFailure('matching_external_publication_required',p.operation_id)
    _lock_tables(c,p); _active_schema(c,p,state)
    for model in p.document['lock']['models']:
        if _guard_facts(c,p,model)!=state['models'][model['table_id']]['guard']: raise TransitionFailure('writer_fence_changed',p.operation_id)
    _drop_guards(c,p)
    for model in p.document['lock']['models']:
        state['models'][model['table_id']]['active_schema']=_facts(c,model)
    state['phase']='ACTIVE'; _save(c,p,state)


def _progress(p,state):
    return Progress(p.operation_id,state['phase'],sum(m['rows'] for m in state['models'].values()),sum(m['chunks'] for m in state['models'].values()),
        'Publish the exact external deployment pin; keep writers stopped.' if state['phase']=='PENDING' else 'Inspect current policy and database before resume.')


def apply(p,engine,*,keys,pin,approval,chunk_size=1000,until='PENDING'):
    """Resume the original operation; committed chunks retain their bytes.

    First call pauses writers durably. Default stops at database switch pending
    external publication. ACTIVE requires the host's independently current pin.
    """
    if type(chunk_size) is not int or not 1<=chunk_size<=5000 or until not in PHASES[1:]: raise TransitionFailure('invalid_apply_bound')
    with _executor(p,engine,pin,approval) as c:
        state=_state(c,p,pin); c.commit()
        if state is None:
            with c.begin(): state=_expand(c,p)
        while PHASES.index(state['phase'])<PHASES.index(until):
            with c.begin():
                if state['phase']=='EXPANDED': _backfill_chunk(c,p,state,keys,chunk_size)
                elif state['phase']=='BACKFILLED':
                    if PHASES.index(until)>PHASES.index('VERIFIED'):
                        _switch(c,p,state,keys)
                    else:
                        _lock_tables(c,p,verification=True); state['verification']=_verify(c,p,state,keys)
                        state['phase']='VERIFIED'; _save(c,p,state)
                elif state['phase']=='VERIFIED': _switch(c,p,state,keys)
                elif state['phase']=='PENDING': _activate(c,p,state,pin)
        with c.begin():
            if state['phase'] in ('PENDING','ACTIVE'): _active_schema(c,p,state)
            else: _inspect_paused(c,p,state)
        return _progress(p,state)


def verify(p,engine,*,keys,pin,approval):
    """Full original-versus-decrypted comparison while source still exists."""
    with _executor(p,engine,pin,approval) as c:
        state=_state(c,p,pin)
        if state is None or state['phase'] not in ('BACKFILLED','VERIFIED'): raise TransitionFailure('source_verification_unavailable',p.operation_id)
        c.commit()
        with c.begin():
            _lock_tables(c,p,verification=True); result=_verify(c,p,state,keys)
        return result


def check_deployment(p,engine,*,pin):
    """Read-only policy inspection; no maintenance approval or exclusive lock.

    The other read-only exemptions are plan and check_attachment. The latter
    inspects a supplied connection and does not acquire or own that connection.
    apply, verify and abort always require approval in their shared executor.
    """
    _admit(p,pin)
    with _connection(engine,p.operation_id) as c: _check_connection(p,c,pin)


def abort(p,engine,*,pin,approval):
    """Remove this operation's additive objects before switch; retain its journal.

    This does not roll back a switched representation. Slice 6 must transform
    current active values back. An aborted identity cannot be resumed by apply.
    """
    with _executor(p,engine,pin,approval) as c:
        state=_state(c,p,pin,allow_aborted=True); c.commit()
        if state is None: return Progress(p.operation_id,'ABORTED',0,0,'No database effects existed.')
        if state['phase']=='ABORTED': return _progress(p,state)
        if state['phase'] in ('PENDING','ACTIVE'): raise TransitionFailure('switched_operation_requires_decrypt_back',p.operation_id)
        with c.begin():
            _lock_tables(c,p); _inspect_paused(c,p,state)
            for model in p.document['lock']['models']:
                for f in model['fields']:
                    c.exec_driver_sql(f'ALTER TABLE {_table(c,model)} DROP COLUMN {_quote(c,f["payload_column"])}')
            _drop_guards(c,p)
            for model in p.document['lock']['models']:
                if _facts(c,model)!=model['source_schema']: raise TransitionFailure('abort_source_schema_changed',p.operation_id)
            state['phase']='ABORTED'; _save(c,p,state)
        return _progress(p,state)


def _check_connection(p,c,pin):
    _admit(p,pin)
    state=_state(c,p,pin)
    # Runtime identity differs; compare the non-principal target facts only.
    if _target(c)[:-1]!=p.document['target'][:-1] or pin.phase!='ACTIVE' or state is None or state['phase']!='ACTIVE':
        raise TransitionFailure('deployment_not_current',p.operation_id)
    _active_schema(c,p,state)


def check_attachment(c,lock,deployment):
    """Migration-owned tables require external-pin admission at startup."""
    models=json.loads(lock)['models']
    found=any(c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_quote(c,m['schema'])+'.'+_quote(c,JOURNAL),)).scalar_one() is not None for m in models)
    if not found:
        if deployment is not None: raise TransitionFailure('missing_transition')
        return
    if not isinstance(deployment,tuple) or len(deployment)!=2: raise TransitionFailure('external_pin_required')
    p,pin=deployment
    if not isinstance(p,MigrationPlan) or p.lock_bytes!=lock: raise TransitionFailure('attachment_lock_mismatch')
    if c.exec_driver_sql('SELECT current_user').scalar_one()!=p.document['runtime_role']:
        raise TransitionFailure('attachment_requires_planned_runtime_role',p.operation_id)
    _check_connection(p,c,pin)
