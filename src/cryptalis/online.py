"""Transactional native-write capture for bounded initial protection.

Native values remain authoritative until a durable maintenance fence. The host
excludes owner/DDL writers throughout and retains both operation artifacts.
This module does not supply external deployment publication or a pause bound.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from threading import local
from time import perf_counter
from uuid import UUID, uuid5

from psycopg import sql

from cryptalis import migration as m
from cryptalis import _access_contract as access
from cryptalis.crypto.cf1 import FieldDescriptor, seal_value
from cryptalis.crypto.keys import Keyring, KeyUnavailable, ProviderAuthenticationUnavailable
from cryptalis.crypto._payload_rotation import MAX_BATCH_BYTES, MAX_BATCH_ROWS
from cryptalis.manifest.declaration import parse_protection_declaration


FORMAT = 'cryptalis.online-protection/v1'
TENANT_FORMAT = 'cryptalis.online-protection/v2'
MAX_NATIVE_TENANTS = 1024
PHASES = ('PREPARED', 'CAPTURING', 'FENCED')


def _tenant_list(value):
    if (type(value) is not list or len(value) > MAX_NATIVE_TENANTS
            or any(type(item) is not str or str(UUID(item)) != item for item in value)
            or value != sorted(set(value))):
        raise ValueError
    return {UUID(item) for item in value}


@dataclass(frozen=True)
class OnlineProtectionPlan:
    artifact: bytes

    def __post_init__(self):
        try:
            d = m._decode_transition_json(self.artifact)
            tenant_scoped = d['format'] == TENANT_FORMAT
            excluded = ('access_contract', 'batch_limits', 'native_tenants') if tenant_scoped else ('access_contract', 'batch_limits')
            base = {k: v for k, v in d.items() if k not in excluded}
            if d['format'] not in (FORMAT, TENANT_FORMAT) or d['kind'] != 'online_protect':
                raise ValueError
            base.update(format='cryptalis.transition/v1', kind='protect')
            native = m.MigrationPlan(m._canonical(base))
            if m._canonical(d) != self.artifact:
                raise ValueError
            limits = d['batch_limits']
            if (type(limits) is not dict or set(limits) != {'max_rows', 'max_bytes'}
                    or type(limits['max_rows']) is not int or not 1 <= limits['max_rows'] <= MAX_BATCH_ROWS
                    or type(limits['max_bytes']) is not int or not 1 <= limits['max_bytes'] <= MAX_BATCH_BYTES):
                raise ValueError
            models = d['lock']['models']
            if any((not tenant_scoped and 'column' in model['tenancy']) or any(
                    field['source']['type'] not in ('text', 'varchar', 'bool', 'int2', 'int4', 'int8', 'date', 'uuid', 'timestamp')
                    for field in model['fields']) for model in models):
                raise ValueError
            if tenant_scoped:
                tenants = _tenant_list(d['native_tenants'])
                expected = {str(tenant) for tenant in tenants} | {
                    model['table_id'] for model in models if 'column' not in model['tenancy']}
                if (set(d['key_policies']) != expected or any(
                        type(value) is not str or len(value) != 64
                        or any(char not in '0123456789abcdef' for char in value)
                        for value in d['key_policies'].values())):
                    raise ValueError
            access.validate(d['access_contract'], models, d['target'][-1], d['runtime_role'])
            if native.operation_id != UUID(d['operation_id']):
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, m.TransitionFailure):
            raise m.TransitionFailure('invalid_online_plan') from None

    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def operation_id(self): return UUID(self.document['operation_id'])
    @property
    def target_id(self): return UUID(self.document['target_id'])
    @property
    def lock_bytes(self): return m._canonical(self.document['lock'])


@dataclass(frozen=True)
class OnlineApproval:
    owner_writer_exclusion: str
    plaintext_capture_accepted: bool
    approved_pause_seconds: float


def plan(manifest, mapping, engine, *, source_role, max_rows=1000,
         max_bytes=MAX_BATCH_BYTES, native_tenants=None, **options):
    """Compile capture authority, including approved future tenant scopes.

    Supply a tuple of native tenant UUIDs to select v2. Without it, v1 retains
    its single-tenant contract. Empty approved scopes retain their policies.
    """
    approved = None
    if native_tenants is not None:
        if (type(native_tenants) is not tuple or len(native_tenants) > MAX_NATIVE_TENANTS
                or any(type(tenant) is not UUID for tenant in native_tenants)
                or len(set(native_tenants)) != len(native_tenants)):
            raise m.TransitionFailure('invalid_native_tenants')
        approved = set(native_tenants)
        declaration = parse_protection_declaration(manifest)
        allowed = approved | {model.table_id for model in declaration.models if model.tenant_column is None}
        searchable = {model.table_id for model in declaration.models
                      if model.tenant_column is None and any(field.queries for field in model.fields)}
        if any(model.tenant_column is not None and any(field.queries for field in model.fields)
               for model in declaration.models):
            searchable |= approved
        host_keys = options['keys']
        rings = {}

        def approved_keys(tenant):
            if tenant not in allowed:
                raise m.TransitionFailure('online_tenant_not_approved')
            if tenant not in rings:
                try:
                    ring = host_keys(tenant) if callable(host_keys) else host_keys
                except ProviderAuthenticationUnavailable:
                    raise ProviderAuthenticationUnavailable() from None
                except Exception:
                    raise KeyUnavailable() from None
                if (not isinstance(ring, Keyring) or ring.policy.tenant_id != tenant
                        or ring.policy.domain_id != declaration.domain_id):
                    raise m.TransitionFailure('missing_key_policy')
                if tenant in searchable and ring.policy.search_generation is None:
                    raise m.TransitionFailure('missing_search_policy')
                rings[tenant] = ring
            return rings[tenant]

        options['keys'] = approved_keys
    native = m.plan(manifest, mapping, engine, **options)
    d = native.document
    if approved is not None:
        for tenant in sorted(approved):
            d['key_policies'][str(tenant)] = m._policy(approved_keys(tenant))
        d['native_tenants'] = sorted(str(tenant) for tenant in approved)
        d['estimates']['provider_unwraps_per_cold_preparation'] = sum(
            len(approved_keys(UUID(tenant)).policy.wrappers) for tenant in d['key_policies'])
    with m._connection(engine) as c:
        if m._target(c) != d['target']:
            raise m.TransitionFailure('wrong_database_target')
        if approved is not None:
            _check_native_tenants(c, d['lock']['models'], approved)
        contract = access.plan(c, d['lock']['models'], owner=d['target'][-1],
                               source_role=source_role, target_role=d['runtime_role'])
    d.update(format=FORMAT if approved is None else TENANT_FORMAT, kind='online_protect', access_contract=contract,
             batch_limits={'max_rows': max_rows, 'max_bytes': max_bytes})
    return OnlineProtectionPlan(m._canonical(d))


def _admit(p, pin):
    if (not isinstance(p, OnlineProtectionPlan) or not isinstance(pin, m.DeploymentPin)
            or (pin.target_id, pin.operation_id, pin.plan_digest) != (p.target_id, p.operation_id, p.digest)
            or pin.phase not in PHASES):
        raise m.TransitionFailure('external_policy_mismatch')


@contextmanager
def _executor(p, engine, pin, approval):
    _admit(p, pin)
    if (not isinstance(approval, OnlineApproval) or approval.plaintext_capture_accepted is not True
            or type(approval.owner_writer_exclusion) is not str or not approval.owner_writer_exclusion.strip()):
        raise m.TransitionFailure('online_capture_approval_required', p.operation_id)
    consent = m.MaintenanceApproval(approval.owner_writer_exclusion, approval.approved_pause_seconds)
    with m._maintenance_executor(p, engine, consent) as c:
        yield c


def _names(p, model=None):
    suffix = p.operation_id.hex
    return ('_cryptalis_' + suffix + '_dirty', '_cryptalis_' + suffix + '_capture',
            '_cryptalis_' + uuid5(p.operation_id,model['table_id'] if model else 'shared').hex + '_capture_fn')


def _body(c, p, model):
    dirty, _, _ = _names(p)
    owner = sql.Literal(p.document['target'][-1]).as_string(c.connection.driver_connection)
    assignments = ' '.join('NEW.' + m._quote(c, f['payload_column']) + ' := NULL;' for f in model['fields'])
    tenant_check = ''
    if 'column' in model['tenancy']:
        tenant = 'NEW.' + m._quote(c, model['tenancy']['column'])
        approved = sql.Literal(p.document['native_tenants']).as_string(c.connection.driver_connection)
        tenant_check = (f'IF {tenant} IS NOT NULL AND NOT ({tenant} = ANY ({approved}::pg_catalog.uuid[])) '
            "THEN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Native tenant is not approved for online capture.'; END IF; ")
    return (f'BEGIN IF CURRENT_USER <> {owner} THEN {tenant_check}{assignments} '
            f'NEW.{m._quote(c, dirty)} := TRUE; END IF; RETURN NEW; END')


def _check_native_tenants(c, models, approved, operation_id=None):
    for model in models:
        if 'column' in model['tenancy']:
            tenant = m._quote(c, model['tenancy']['column'])
            if c.exec_driver_sql(f'SELECT EXISTS (SELECT 1 FROM {m._table(c, model)} '
                    f'WHERE {tenant} IS NULL OR NOT ({tenant} = ANY (%s::pg_catalog.uuid[])))',
                    (sorted(approved),)).scalar_one():
                raise m.TransitionFailure('online_tenant_not_approved', operation_id)


def _capture(c, p, model):
    _, trigger, function = _names(p, model)
    return c.exec_driver_sql('''SELECT g.tgenabled, g.tgtype, g.tgqual IS NULL, g.tgnargs,
        n.nspname, f.proname, f.prosecdef, f.proconfig, f.prosrc,
        pg_catalog.pg_get_userbyid(f.proowner)
        FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_proc f ON f.oid=g.tgfoid
        JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
        WHERE g.tgrelid=pg_catalog.to_regclass(%s) AND g.tgname=%s''',
        (m._table(c, model), trigger)).one_or_none()


def _state(c, p, pin, *, aborted=False):
    exists = c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (m._journal(c, p),)).scalar_one()
    if exists is None:
        if pin.phase != 'PREPARED':
            raise m.TransitionFailure('restored_or_missing_transition', p.operation_id)
        return None
    row = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,p)} WHERE operation_id=%s',
                            (p.operation_id,)).one_or_none()
    if row is None or row[0] != p.digest or type(row[1]) is not dict:
        raise m.TransitionFailure('journal_identity_mismatch', p.operation_id)
    state = row[1]
    if state.get('phase') == 'SUPERSEDED':
        raise m.TransitionFailure('online_successor_artifact_required', p.operation_id)
    if state.get('phase') == 'ABORTED' and aborted and pin.phase == 'PREPARED':
        return state
    if (state.get('phase') not in ('CAPTURING', 'FENCED')
            or PHASES.index(state['phase']) < PHASES.index(pin.phase)
            or set(state) != {'phase', 'models'}
            or type(state['models']) is not dict
            or set(state['models']) != {model['table_id'] for model in p.document['lock']['models']}):
        raise m.TransitionFailure('online_state_changed', p.operation_id)
    for item in state['models'].values():
        if (type(item) is not dict or set(item) != {'rows', 'chunks'}
                or any(type(value) is not int or not 0 <= value < 2**53 for value in item.values())):
            raise m.TransitionFailure('online_state_changed', p.operation_id)
    return state


def _inspect(c, p, state):
    access.check(c, p, plaintext=True)
    dirty, trigger, _ = _names(p)
    for model in p.document['lock']['models']:
        function = _names(p, model)[2]
        facts = m._facts(c, model)
        expected = deepcopy(model['source_schema'])
        expected['relation']['user_triggers'] = True
        template = model['source_schema']['columns'][0]
        plain = dict(template, type_schema='pg_catalog', typmod='-1', identity='', generated='',
                     default_digest=None, collation=None, collation_name=None, collation_schema=None,
                     deterministic=None, provider=None)
        expected['columns'].extend(dict(plain, name=f['payload_column'], type='bytea', nullable=True)
                                  for f in model['fields'])
        # A nullable, default-free marker avoids a table rewrite. NULL means dirty.
        expected['columns'].append(dict(plain, name=dirty, type='bool', nullable=True))
        if m._metadata_diff(expected, facts):
            raise m.TransitionFailure('online_schema_changed', p.operation_id)
        m._check_source_metadata(c, p, model)
        actual = _capture(c, p, model)
        wanted = ['A', 23, True, 0, model['schema'], function, False,
                  ['search_path=pg_catalog'], _body(c, p, model), p.document['target'][-1]]
        if actual is None or list(actual) != wanted:
            raise m.TransitionFailure('online_capture_changed', p.operation_id)
        names = c.exec_driver_sql('''SELECT tgname FROM pg_catalog.pg_trigger
            WHERE tgrelid=pg_catalog.to_regclass(%s) AND NOT tgisinternal ORDER BY tgname''',
            (m._table(c, model),)).scalars().all()
        wanted_names = [trigger]
        if state['phase'] == 'FENCED':
            wanted_names.append(m._guard_names(p, model)[0])
            # _check_guard binds the full trigger inventory and expects one trigger.
            guard = m._guard_facts(c, p, model)
            guard_wanted = ['A', 62, True, 0, model['schema'], m._guard_names(p,model)[1],
                            False, ['search_path=pg_catalog'], m._guard_body(p), p.document['target'][-1]]
            if guard is None or guard[:10] != guard_wanted:
                raise m.TransitionFailure('writer_fence_changed', p.operation_id)
        if names != sorted(wanted_names):
            raise m.TransitionFailure('online_capture_changed', p.operation_id)


def _expand(c, p):
    m._lock_tables(c, p)
    access.check(c, p, plaintext=True)
    for model in p.document['lock']['models']:
        if m._facts(c, model) != model['source_schema']:
            raise m.TransitionFailure('source_schema_changed', p.operation_id)
        m._check_source_metadata(c, p, model)
        m._check_temporal_source_domain(c, model, p.operation_id)
    if p.document['format'] == TENANT_FORMAT:
        _check_native_tenants(c, p.document['lock']['models'],
                              _tenant_list(p.document['native_tenants']), p.operation_id)
    c.exec_driver_sql(f'CREATE TABLE {m._journal(c,p)} (operation_id uuid PRIMARY KEY, plan_digest text NOT NULL, state jsonb NOT NULL)')
    c.exec_driver_sql(f'REVOKE ALL ON {m._journal(c,p)} FROM PUBLIC')
    c.exec_driver_sql(f'GRANT SELECT ON {m._journal(c,p)} TO {m._quote(c,p.document["runtime_role"])}')
    dirty, trigger, _ = _names(p)
    for model in p.document['lock']['models']:
        function = _names(p, model)[2]
        for field in model['fields']:
            c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} ADD COLUMN {m._quote(c,field["payload_column"])} bytea')
        c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} ADD COLUMN {m._quote(c,dirty)} boolean')
        fn = m._quote(c,model['schema']) + '.' + m._quote(c,function)
        literal = sql.Literal(_body(c,p,model)).as_string(c.connection.driver_connection)
        c.exec_driver_sql(f'CREATE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS {literal}')
        c.exec_driver_sql(f'REVOKE ALL ON FUNCTION {fn}() FROM PUBLIC')
        c.exec_driver_sql(f'CREATE TRIGGER {m._quote(c,trigger)} BEFORE INSERT OR UPDATE ON {m._table(c,model)} FOR EACH ROW EXECUTE FUNCTION {fn}()')
        c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} ENABLE ALWAYS TRIGGER {m._quote(c,trigger)}')
    state = {'phase':'CAPTURING', 'models':{model['table_id']:{'rows':0,'chunks':0} for model in p.document['lock']['models']}}
    c.exec_driver_sql(f'INSERT INTO {m._journal(c,p)} VALUES (%s,%s,%s::jsonb)',
                      (p.operation_id,p.digest,json.dumps(state)))
    _inspect(c,p,state)
    return state


def _chunk(c, p, state, keys, *, pool=None, row_limit=None):
    _inspect(c,p,state)
    dirty = _names(p)[0]
    limits = p.document['batch_limits']
    approved = set(p.document.get('native_tenants', ()))
    for model in p.document['lock']['models']:
        scoped = 'column' in model['tenancy']
        fields = [f['column'] for f in model['fields']]
        names = [model['record']['column']] + ([model['tenancy']['column']] if scoped else []) + fields
        widths = {'bool': 1, 'int2': 2, 'int4': 4, 'int8': 8, 'date': 4, 'uuid': 16, 'timestamp': 8}
        sizes = '+'.join((str(widths[f['source']['type']]) if f['source']['type'] in widths else
                         'COALESCE(pg_catalog.octet_length('+m._quote(c,f['column'])+'),0)') + '+74'
                         for f in model['fields'])
        candidates = c.exec_driver_sql('SELECT ' + m._quote(c,names[0]) + ', ' + sizes
            + f' FROM {m._table(c,model)} WHERE {m._quote(c,dirty)} IS DISTINCT FROM FALSE'
            + f' ORDER BY {m._quote(c,names[0])} LIMIT %s FOR UPDATE', (row_limit or limits['max_rows'],)).all()
        if not candidates:
            continue
        selected, size = [], 0
        for identity,row_size in candidates:
            if row_size > limits['max_bytes']:
                raise m.TransitionFailure('online_row_exceeds_batch_bytes', p.operation_id)
            if size + row_size > limits['max_bytes']:
                break
            selected.append(identity)
            size += row_size
        # Lock identities and inspect sizes before fetching native values. The
        # row count alone does not bound memory for large text values.
        for field in model['fields']:
            kind = field['source']['type']
            if kind in ('date', 'timestamp'):
                column = m._quote(c, field['column'])
                lower, upper = (('0001-01-01', '9999-12-31') if kind == 'date' else
                                ('0001-01-01 00:00:00', '9999-12-31 23:59:59.999999'))
                if c.exec_driver_sql(f'SELECT EXISTS (SELECT 1 FROM {m._table(c,model)} '
                        f'WHERE {m._quote(c,names[0])}=ANY(%s) AND '
                        f"({column} < {kind} '{lower}' OR {column} > {kind} '{upper}'))",
                        (selected,)).scalar_one():
                    raise m.TransitionFailure(kind + '_outside_python_range', p.operation_id)
        rows = c.exec_driver_sql('SELECT ' + ','.join(m._quote(c,name) for name in names)
            + f' FROM {m._table(c,model)} WHERE {m._quote(c,names[0])}=ANY(%s)'
            + f' ORDER BY {m._quote(c,names[0])}',(selected,)).all()
        descriptors = [FieldDescriptor.from_compiled(f['descriptor'],f['descriptor_digest']) for f in model['fields']]
        material = local()
        def seal_row(row):
            if not hasattr(material, 'keys'):
                material.keys = {}
            tenant = row[1] if scoped else UUID(model['table_id'])
            offset = 2 if scoped else 1
            if scoped and str(tenant) not in approved:
                raise m.TransitionFailure('online_tenant_not_approved', p.operation_id)
            frames = m._with_row_keys(keys,tenant,p,material.keys,lambda prepared:
                [seal_value(value,descriptor,tenant,row[0],prepared) for value,descriptor in zip(row[offset:],descriptors)])
            return tuple(frames)+(row[0],)
        params = list(pool.map(seal_row, rows) if pool is not None else map(seal_row, rows))
        statement = f'UPDATE {m._table(c,model)} SET ' + ','.join(m._quote(c,f['payload_column'])+'=%s' for f in model['fields'])
        statement += f', {m._quote(c,dirty)}=FALSE WHERE {m._quote(c,names[0])}=%s'
        c.exec_driver_sql(statement,params)
        progress = state['models'][model['table_id']]
        progress['rows'] += len(params)
        progress['chunks'] += 1
        m._save(c,p,state)
        return True
    return False


def _progress(p,state):
    return m.Progress(p.operation_id,state['phase'],sum(v['rows'] for v in state['models'].values()),
                      sum(v['chunks'] for v in state['models'].values()),
                      'Inspect the current host policy and capture before resume. Counts include repeated row versions.')


def apply(p, engine, *, keys, pin, approval, max_chunks=1, fence=False,
          workers=1, target_chunk_seconds=None):
    """Commit bounded dirty-row batches, then optionally install a durable fence.

    An empty backlog is only a current observation. It never authorizes cutover.
    The fence first drains in-flight native writers under an exclusive lock.
    Opt-in crypto workers require thread-safe host resolvers/providers. A target
    chunk duration tunes row counts within the plan; it promises no pause bound.
    """
    if type(max_chunks) is not int or not 0 <= max_chunks <= 100000 or type(fence) is not bool:
        raise m.TransitionFailure('invalid_online_apply_bound')
    if (type(workers) is not int or not 1 <= workers <= 16 or target_chunk_seconds is not None and
            (not m._finite_number(target_chunk_seconds) or not 0 < target_chunk_seconds <= 60)):
        raise m.TransitionFailure('invalid_online_worker_bound')
    with _executor(p,engine,pin,approval) as c, (ThreadPoolExecutor(max_workers=workers)
            if workers > 1 else nullcontext()) as pool:
        row_limit = p.document['batch_limits']['max_rows']
        state = _state(c,p,pin)
        c.commit()
        if state is None:
            with c.begin(): state = _expand(c,p)
        for _ in range(max_chunks):
            started = perf_counter()
            with c.begin():
                changed = _chunk(c,p,state,keys,pool=pool,row_limit=row_limit)
            if not changed:
                break
            if target_chunk_seconds is not None:
                proposed = int(row_limit * target_chunk_seconds / max(perf_counter() - started, 1e-9))
                row_limit = max(1, min(p.document['batch_limits']['max_rows'], row_limit * 2,
                                       max(row_limit // 2, proposed)))
        if fence and state['phase'] == 'CAPTURING':
            with c.begin():
                m._lock_tables(c,p)
                _inspect(c,p,state)
                m._install_guards(c,p)
                state['phase'] = 'FENCED'
                m._save(c,p,state)
        with c.begin(): _inspect(c,p,state)
        return _progress(p,state)


def status(p, engine, *, pin):
    """Inspect the exact capture and access contract without keys or mutations."""
    _admit(p,pin)
    with m._connection(engine,p.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        if m._target(c) != p.document['target']:
            raise m.TransitionFailure('wrong_database_target',p.operation_id)
        state = _state(c,p,pin,aborted=True)
        if state is None or state['phase'] == 'ABORTED':
            access.check(c,p,plaintext=True)
            for model in p.document['lock']['models']:
                if m._facts(c,model) != model['source_schema']:
                    raise m.TransitionFailure('source_schema_changed',p.operation_id)
            return m.Progress(p.operation_id,'PREPARED' if state is None else 'ABORTED',0,0,'No capture is active.')
        _inspect(c,p,state)
        return _progress(p,state)


def _remove_capture(c,p):
    dirty,trigger,_ = _names(p)
    functions = set()
    for model in p.document['lock']['models']:
        c.exec_driver_sql(f'DROP TRIGGER {m._quote(c,trigger)} ON {m._table(c,model)}')
        c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} DROP COLUMN {m._quote(c,dirty)}')
        functions.add(m._quote(c,model['schema'])+'.'+m._quote(c,_names(p,model)[2]))
    for fn in sorted(functions): c.exec_driver_sql(f'DROP FUNCTION {fn}()')


def _successor(p, scopes, frames):
    observed = {table:{'rows':scope['count'],'membership':scope['membership'],'frames':frames[table]}
                for table,scope in scopes.items()}
    d = p.document
    d.pop('batch_limits')
    d.pop('native_tenants', None)
    d.update(format='cryptalis.transition/v8',kind='protect',
             operation_id=str(uuid5(p.operation_id,'cryptalis.online.activation/v1')),
             predecessors=[{'operation_id':str(p.operation_id),'plan_digest':p.digest}],
             online_preparation={'operation_id':str(p.operation_id),'plan_digest':p.digest},
             online_verification=observed,
             scopes=[{'table_id':table,'estimated_rows':scope['count']} for table,scope in scopes.items()])
    d['estimates']['rows'] = sum(scope['count'] for scope in scopes.values())
    return m.MigrationPlan(m._canonical(d))


def _terminal_proof(c,p,state,keys):
    m._lock_tables(c,p)
    _inspect(c,p,state)
    if p.document['format'] == TENANT_FORMAT:
        _check_native_tenants(c, p.document['lock']['models'],
                              _tenant_list(p.document['native_tenants']), p.operation_id)
    for model in p.document['lock']['models']:
        if c.exec_driver_sql(f'SELECT EXISTS (SELECT 1 FROM {m._table(c,model)} WHERE {m._quote(c,_names(p)[0])} IS DISTINCT FROM FALSE)').scalar_one():
            raise m.TransitionFailure('online_catchup_required',p.operation_id)
    scopes = {model['table_id']:m._scope(c,model) for model in p.document['lock']['models']}
    frames = m._verify_values(c,p,keys)
    return scopes,frames


def seal(p, engine, *, keys, pin, approval):
    """Authenticate the fenced native scope and return an immutable proposal.

    Save this artifact outside the database before calling switch. The journal
    cannot reconstruct host authority after a crash or a lost COMMIT reply.
    """
    with _executor(p,engine,pin,approval) as c:
        state = _state(c,p,pin)
        if state is None or state['phase'] != 'FENCED':
            raise m.TransitionFailure('online_fence_required',p.operation_id)
        scopes,frames = _terminal_proof(c,p,state,keys)
        return _successor(p,scopes,frames)


def switch(p, engine, *, successor, keys, pin, approval):
    """Authenticate the final current scope and atomically produce a pending plan.

    Catch-up must finish through bounded ``apply`` calls after the fence. This
    terminal transaction builds indexes and verifies every current row again.
    Supply the exact sealed artifact retained outside the database. A lost
    reply requires inspection with that artifact, never journal-derived policy.
    """
    if not isinstance(successor,m.MigrationPlan):
        raise m.TransitionFailure('sealed_online_successor_required')
    with _executor(p,engine,pin,approval) as c:
        state = _state(c,p,pin)
        c.commit()
        if state is None or state['phase'] != 'FENCED':
            raise m.TransitionFailure('online_fence_required',p.operation_id)
        with c.begin():
            scopes,frames = _terminal_proof(c,p,state,keys)
            if _successor(p,scopes,frames).artifact != successor.artifact:
                raise m.TransitionFailure('sealed_online_successor_changed',p.operation_id)
            d = successor.document
            _remove_capture(c,p)
            m._drop_guards(c,p)
            m._install_guards(c,successor)
            models = {}
            for model in d['lock']['models']:
                table = m._table(c,model)
                for field in model['fields']:
                    if field['queries']:
                        unique = 'UNIQUE ' if 'unique' in field['queries'] else ''
                        tenant = m._quote(c,model['tenancy']['column']) + ', ' if 'column' in model['tenancy'] else ''
                        c.exec_driver_sql(f'CREATE {unique}INDEX {m._quote(c,field["payload_column"]+"_eq")} ON {table} USING btree ({tenant}(pg_catalog.substring({m._quote(c,field["payload_column"])},15,32)) pg_catalog.bytea_ops)')
                    c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {m._quote(c,field["payload_column"]+"_frame")} CHECK ({m._frame_check(c,field)})')
                models[model['table_id']] = {'scope':scopes[model['table_id']],'cursor':None,
                    'rows':scopes[model['table_id']]['count'],'chunks':0,
                    'schema':m._facts(c,model),'guard':m._guard_facts(c,successor,model)}
            active_state = {'phase':'BACKFILLED','models':models,'verification':frames}
            c.exec_driver_sql(f'INSERT INTO {m._journal(c,successor)} VALUES (%s,%s,%s::jsonb)',
                             (successor.operation_id,successor.digest,json.dumps(active_state)))
            m._switch(c,successor,active_state,keys)
            access.transfer(c,successor)
            state.update(phase='SUPERSEDED',superseded_by={'operation_id':str(successor.operation_id),'plan_digest':successor.digest})
            m._save(c,p,state)
        return successor


def abort(p, engine, *, pin, approval):
    """Remove only this capture and preserve all committed native application edits."""
    with _executor(p,engine,pin,approval) as c:
        state = _state(c,p,pin,aborted=True)
        c.commit()
        if state is None or state['phase'] == 'ABORTED':
            return m.Progress(p.operation_id,'ABORTED',0,0,'No capture is active.')
        with c.begin():
            m._lock_tables(c,p)
            _inspect(c,p,state)
            _remove_capture(c,p)
            if state['phase'] == 'FENCED': m._drop_guards(c,p)
            for model in p.document['lock']['models']:
                for field in model['fields']:
                    c.exec_driver_sql(f'ALTER TABLE {m._table(c,model)} DROP COLUMN {m._quote(c,field["payload_column"])}')
                if m._metadata_diff(model['source_schema'],m._facts(c,model)):
                    raise m.TransitionFailure('abort_source_schema_changed',p.operation_id)
            state['phase'] = 'ABORTED'
            m._save(c,p,state)
        return _progress(p,state)
