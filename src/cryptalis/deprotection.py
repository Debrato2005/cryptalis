"""Decrypt-back and removal for active in-place transitions.

This module reverses ``cryptalis.transition/v1`` protection. The runtime holds
CF1 frames in the original public column names. A reverse operation stages
plaintext in companion columns, verifies every frame, then restores the
original columns, constraints, and indexes.

The host keeps the current deployment pin outside database snapshots. The
database journal is progress evidence, never restore authority. This module
does not promise plaintext erasure. Plaintext enters WAL, backups, and
statistics after this operation.

Known limits, made explicit in removal approval:
- Legacy layouts change physical column order. Lock v6 preserves admitted public slots.
- Legacy locks without source_metadata refuse protected-column metadata.
  Current locks capture supported column metadata and protected extended
  statistics for restoration. Lock v5 preserves admitted owned sequence objects.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
import time
from uuid import UUID, uuid4

from psycopg import sql

from sqlalchemy.exc import SQLAlchemyError

from cryptalis import migration as m
from cryptalis.manifest.compiler import _metadata_diff
from cryptalis.crypto.cf1 import FieldDescriptor, open_value
from cryptalis.manifest.compiler import _canonical, _native_text_length, _previous_lock, _validate_catalog_facts

FORMAT = 'cryptalis.reverse/v1'
PHASES = ('PREPARED', 'EXPANDED', 'BACKFILLED', 'VERIFIED',
          'PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE')
PUBLICATION = ('PLAINTEXT_ACTIVATING', 'REMOVING', 'REMOVED')


@dataclass(frozen=True)
class DeprotectionPlan:
    artifact: bytes

    def __post_init__(self):
        try:
            document = m._decode_transition_json(self.artifact)
            if (document.get('format') != FORMAT or document.get('kind') != 'deprotect'
                    or _canonical(document) != self.artifact):
                raise ValueError
            if set(document) != {'format', 'kind', 'operation_id', 'target_id', 'source_plan',
                    'source_pin', 'lock', 'target', 'runtime_role', 'journal_schema', 'key_policies',
                    'active_schemas', 'retirable_aborted', 'estimates', 'plaintext_runtime_role',
                    'restore'}:
                raise ValueError
            source = m.MigrationPlan(_canonical(document['source_plan']))
            source_pin = document['source_pin']
            if set(source_pin) != {'target_id', 'operation_id', 'plan_digest', 'phase'}:
                raise ValueError
            pin = m.DeploymentPin(UUID(source_pin['target_id']), UUID(source_pin['operation_id']),
                                  source_pin['plan_digest'], source_pin['phase'])
            m._admit(source, pin)
            if pin.phase != 'ACTIVE':
                raise ValueError
            if (UUID(document['target_id']) != source.target_id
                    or UUID(document['operation_id']) == source.operation_id
                    or not UUID(document['operation_id']).int):
                raise ValueError
            if (document['lock'] != source.document['lock']
                    or document['target'] != source.document['target']
                    or document['runtime_role'] != source.document['runtime_role']
                    or document['journal_schema'] != source.document['journal_schema']):
                raise ValueError
            if (type(document['plaintext_runtime_role']) is not str
                    or not document['plaintext_runtime_role']
                    or document['plaintext_runtime_role'] == document['runtime_role']):
                raise ValueError
            access_contract = source.document.get('access_contract')
            if access_contract is not None and document['plaintext_runtime_role'] != access_contract['source_role']:
                raise ValueError
            if (not isinstance(document['active_schemas'], dict)
                    or set(document['active_schemas']) != {model['table_id'] for model in document['lock']['models']}):
                raise ValueError
            for model in document['lock']['models']:
                columns = _validate_catalog_facts(document['active_schemas'][model['table_id']])
                if set(columns) != {column['name'] for column in model['source_schema']['columns']}:
                    raise ValueError
            m._validate_estimates(document['estimates'])
            if not isinstance(document['key_policies'], dict) or any(
                    type(value) is not str or len(value) != 64
                    or any(ch not in '0123456789abcdef' for ch in value)
                    for value in document['key_policies'].values()):
                raise ValueError
            retired = set()
            for item in document['retirable_aborted']:
                if set(item) != {'operation_id', 'plan_digest'}:
                    raise ValueError
                identity = UUID(item['operation_id'])
                digest = item['plan_digest']
                if (identity in retired or identity in (UUID(document['operation_id']), source.operation_id)
                        or type(digest) is not str or len(digest) != 64
                        or any(ch not in '0123456789abcdef' for ch in digest)):
                    raise ValueError
                retired.add(identity)
            for name in ('backfill_rows_per_second', 'verify_rows_per_second'):
                value = document['estimates'][name]
                if not m._finite_number(value) or value <= 0:
                    raise ValueError
            if document['restore'] is not None:
                from cryptalis.restore import RestoreBinding
                binding = RestoreBinding(_canonical(document['restore']))
                if (binding.source_plan_digest != source.digest
                        or binding.source_operation_id != source.operation_id
                        or binding.source_target != document['target']):
                    raise ValueError
        except Exception:
            raise m.TransitionFailure('invalid_reverse_plan') from None

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
    @property
    def source(self): return m.MigrationPlan(_canonical(self.document['source_plan']))


@dataclass(frozen=True)
class PlaintextApproval:
    target_id: UUID
    operation_id: UUID
    plan_digest: str
    accept_plaintext_at_rest: bool
    retained_backup_recovery: str


@dataclass(frozen=True)
class RemovalApproval:
    target_id: UUID
    operation_id: UUID
    plan_digest: str
    package_free_workload_evidence: str
    retained_backup_recovery_evidence: str
    old_workers_stopped: bool


def _consent(p, approval):
    if (type(approval) is not PlaintextApproval
            or (approval.target_id, approval.operation_id, approval.plan_digest) != (p.target_id, p.operation_id, p.digest)
            or approval.accept_plaintext_at_rest is not True
            or type(approval.retained_backup_recovery) is not str
            or not approval.retained_backup_recovery.strip()):
        raise m.TransitionFailure('plaintext_approval_required', p.operation_id)


def _removal_consent(p, approval):
    if (type(approval) is not RemovalApproval
            or (approval.target_id, approval.operation_id, approval.plan_digest) != (p.target_id, p.operation_id, p.digest)
            or type(approval.package_free_workload_evidence) is not str
            or not approval.package_free_workload_evidence.strip()
            or type(approval.retained_backup_recovery_evidence) is not str
            or not approval.retained_backup_recovery_evidence.strip()
            or approval.old_workers_stopped is not True):
        raise m.TransitionFailure('removal_approval_required', p.operation_id)


def _pin(p, pin):
    if (type(p) is not DeprotectionPlan or type(pin) is not m.DeploymentPin
            or (pin.target_id, pin.operation_id, pin.plan_digest) != (p.target_id, p.operation_id, p.digest)
            or pin.phase not in PHASES + PUBLICATION):
        raise m.TransitionFailure('external_reverse_policy_mismatch')


def _staging(field):
    return '_cryptalis_' + UUID(field['field_id']).hex + '_plain'


def _grounded(source, plaintext_runtime_role, rates, temporary_bytes_per_row, wal_bytes_per_row):
    if type(plaintext_runtime_role) is not str or not plaintext_runtime_role \
            or plaintext_runtime_role == source.document['runtime_role']:
        raise m.TransitionFailure('distinct_plaintext_runtime_role_required')
    if any(not m._finite_number(rate) or rate <= 0 for rate in rates):
        raise m.TransitionFailure('missing_measured_rates')
    if any(type(cost) is not int or not 1 <= cost < 2 ** 53
           for cost in (temporary_bytes_per_row, wal_bytes_per_row)):
        raise m.TransitionFailure('missing_measured_storage_or_wal_costs')


def _runtime_safety(c, p, role, *, plaintext=False):
    try:
        m._runtime_safety(c,role,p.document['target'][-1],p.document['lock']['models'],
                          journal=m._journal(c,p),operation_id=p.operation_id)
    except m.TransitionFailure as exc:
        if plaintext and exc.code=='unsafe_runtime_role':
            raise m.TransitionFailure('unsafe_plaintext_runtime_role',p.operation_id) from None
        raise


def plan(source, engine, *, source_pin, keys, plaintext_runtime_role, backfill_rows_per_second,
         verify_rows_per_second, temporary_bytes_per_row, wal_bytes_per_row, restore=None):
    """Read-only reverse proposal. No decrypt, staging, or implicit consent.

    ``restore`` is an adopted restore binding when the target
    is a restored protected copy. The binding is recorded in the reverse
    artifact, so apply and remove refuse a different target without it.
    """
    m._admit(source, source_pin)
    if source_pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    if restore is not None:
        from cryptalis.restore import _identity
        _identity(source, restore)
    access_contract = source.document.get('access_contract')
    if access_contract is not None and plaintext_runtime_role != access_contract['source_role']:
        raise m.TransitionFailure('online_plaintext_role_mismatch', source.operation_id)
    _grounded(source, plaintext_runtime_role,
              (backfill_rows_per_second, verify_rows_per_second),
              temporary_bytes_per_row, wal_bytes_per_row)
    try:
        _previous_lock(source.lock_bytes, source.document['lock'], engine)
    except ValueError:
        raise m.TransitionFailure('invalid_compiler_lock', source.operation_id) from None
    policies = {}
    schemas = {}
    rows_total = 0
    plaintext_bytes = 0
    current = source.document['target'] if restore is None else restore.target
    with m._connection(engine, source.operation_id) as c:
        m._check_connection(source, c, source_pin, binding=restore)
        if m._target(c)[:-1] != current[:-1]:
            raise m.TransitionFailure('maintenance_requires_planned_owner', source.operation_id)
        from cryptalis.restore import sequence_admissions, layout_admissions
        for model in source.document['lock']['models']:
            ownership = c.exec_driver_sql(
                'SELECT pg_catalog.pg_get_userbyid(relowner) FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass(%s)',
                (m._table(c, model),)).scalar_one()
            if ownership != source.document['target'][-1]:
                raise m.TransitionFailure('maintenance_requires_table_owner', source.operation_id)
            m._refuse_unrecorded_metadata(c, source, model,
                                          sequences=sequence_admissions(source.document, model, restore),
                                          slots=layout_admissions(source.document, model, restore))
        retired = _inventory(c, source, source, own=None)
        _runtime_safety(c,source,plaintext_runtime_role,plaintext=True)
        for model in source.document['lock']['models']:
            facts = m._facts(c, model)
            schemas[model['table_id']] = facts
            names = {column['name'] for column in facts['columns']}
            for field in model['fields']:
                if _staging(field) in names:
                    raise m.TransitionFailure('generated_name_collision', source.operation_id)
            tenant_column = m._quote(c, model['tenancy']['column']) if 'column' in model['tenancy'] else None
            tenants = (c.exec_driver_sql(f'SELECT DISTINCT {tenant_column} FROM {m._table(c, model)}').scalars().all()
                       if tenant_column else [UUID(model['table_id'])])
            for tenant in tenants:
                policies[str(tenant)] = m._policy(m._ring(keys, tenant, source))
            count = c.exec_driver_sql(f'SELECT count(*) FROM {m._table(c, model)}').scalar_one()
            size = c.exec_driver_sql(
                f'SELECT coalesce(sum(' + '+'.join(
                    f'coalesce(octet_length({m._quote(c, f["column"])}),0)' for f in model['fields'])
                + f'),0) FROM {m._table(c, model)}').scalar_one()
            rows_total += count
            plaintext_bytes += size
    pause_seconds = m._estimate_seconds(rows_total, backfill_rows_per_second, verify_rows_per_second)
    estimates = {'rows': rows_total, 'ciphertext_bytes': plaintext_bytes,
                 'temporary_bytes_estimate': rows_total * temporary_bytes_per_row,
                 'wal_bytes_estimate': rows_total * wal_bytes_per_row,
                 'backfill_rows_per_second': backfill_rows_per_second,
                 'verify_rows_per_second': verify_rows_per_second,
                 'writer_pause_seconds_estimate': pause_seconds,
                 'cost_basis': 'Host-supplied per-row staging observations/estimates; not bounds or qualification.',
                 'limits': 'Plaintext enters WAL and backups. Staging, DDL, and publication delays are excluded.'}
    if m._preserves_public_slots(source):
        estimates['limits'] += (' Preserving public slots rewrites the whole heap and index storage during '
                                'DDL; this cost is excluded from the rate and WAL estimates.')
    return DeprotectionPlan(_canonical({
        'format': FORMAT, 'kind': 'deprotect', 'operation_id': str(uuid4()), 'target_id': str(source.target_id),
        'source_plan': source.document,
        'source_pin': {'target_id': str(source_pin.target_id), 'operation_id': str(source_pin.operation_id),
                       'plan_digest': source_pin.plan_digest, 'phase': source_pin.phase},
        'lock': source.document['lock'], 'target': source.document['target'],
        'runtime_role': source.document['runtime_role'], 'journal_schema': source.document['journal_schema'],
        'key_policies': policies, 'active_schemas': schemas, 'retirable_aborted': retired,
        'estimates': estimates, 'plaintext_runtime_role': plaintext_runtime_role,
        'restore': restore.document if restore is not None else None}))


def _inventory(c, p, source, own):
    """Validate every journal row before any reverse or removal step."""
    ancestors = m._check_predecessors(c, source)
    rows = c.exec_driver_sql(
        f'SELECT operation_id, plan_digest, state FROM {m._journal(c, p)} ORDER BY operation_id').all()
    source_seen = False
    retired = []
    for operation, digest, state in rows:
        if operation in ancestors:
            continue
        if operation == own:
            continue
        if operation == source.operation_id:
            if digest != source.digest or type(state) is not dict or state.get('phase') != 'ACTIVE':
                raise m.TransitionFailure('source_state_changed', p.operation_id)
            source_seen = True
            continue
        if type(state) is dict and state.get('phase') == 'ABORTED':
            retired.append({'operation_id': str(operation), 'plan_digest': digest})
            continue
        if type(state) is dict and state.get('source_operation_id') == str(source.operation_id):
            raise m.TransitionFailure('existing_reverse_requires_inspection', p.operation_id)
        raise m.TransitionFailure('unreviewed_journal_operations', p.operation_id)
    if not source_seen:
        raise m.TransitionFailure('missing_source_journal', p.operation_id)
    return retired


@contextmanager
def _executor(p, engine, pin, approval, consent):
    _pin(p, pin)
    m._approve_maintenance(p, approval)
    _consent(p, consent)
    try:
        _previous_lock(p.lock_bytes, p.document['lock'], engine)
    except ValueError:
        raise m.TransitionFailure('invalid_compiler_lock', p.operation_id) from None
    identity = [(model['schema'], model['table']) for model in p.document['lock']['models']]
    lock = int.from_bytes(hashlib.sha256(_canonical(identity)).digest()[:8], 'big', signed=True)
    target = p.document['target']
    if p.document.get('restore') is not None:
        from cryptalis.restore import RestoreBinding, _identity
        _identity(p.source, RestoreBinding(_canonical(p.document['restore'])))
        target = p.document['restore']['target']
    with m._connection(engine, p.operation_id, exclusive=True) as c:
        if m._target(c)[:-1] != target[:-1]:
            raise m.TransitionFailure('wrong_database_target', p.operation_id)
        c.exec_driver_sql("SET lock_timeout = '5s'")
        c.exec_driver_sql('SET synchronous_commit = on')
        acquired = c.exec_driver_sql('SELECT pg_catalog.pg_try_advisory_lock(%s)', (lock,)).scalar_one()
        c.commit()
        if not acquired:
            raise m.TransitionFailure('executor_already_running', p.operation_id)
        yield c


def _state(c, p, pin, *, allow_aborted=False):
    if c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (m._journal(c, p),)).scalar_one() is None:
        if pin.phase == 'REMOVED':
            return None
        raise m.TransitionFailure('restored_or_missing_reverse_transition', p.operation_id)
    # The host pin selects the runtime boundary. Journal edits cannot change it.
    plaintext=pin.phase in ('PLAINTEXT_ACTIVATING','PLAINTEXT_ACTIVE','REMOVING','REMOVED')
    role=p.document['plaintext_runtime_role' if plaintext else 'runtime_role']
    _runtime_safety(c,p,role,plaintext=plaintext)
    row = c.exec_driver_sql(
        f'SELECT plan_digest, state FROM {m._journal(c, p)} WHERE operation_id=%s', (p.operation_id,)).one_or_none()
    if row is None:
        if pin.phase in ('PREPARED', 'REMOVED'):
            return None
        raise m.TransitionFailure('restored_or_missing_reverse_transition', p.operation_id)
    if row[0] != p.digest:
        raise m.TransitionFailure('journal_identity_mismatch', p.operation_id)
    state = row[1]
    if (type(state) is not dict or state.get('source_operation_id') != str(p.source.operation_id)
            or state.get('source_plan_digest') != p.source.digest):
        raise m.TransitionFailure('source_state_changed', p.operation_id)
    phase = state.get('phase')
    if phase == 'ABORTED':
        if allow_aborted and pin.phase in PHASES[:4]:
            return state
        raise m.TransitionFailure('operation_aborted', p.operation_id)
    if phase not in PHASES:
        raise m.TransitionFailure('unknown_or_aborted_reverse_state', p.operation_id)
    from cryptalis import _access_contract as access
    access.check(c, p, plaintext=phase in ('PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE'))
    source_row = c.exec_driver_sql(
        f'SELECT plan_digest, state FROM {m._journal(c, p)} WHERE operation_id=%s',
        (p.source.operation_id,)).one_or_none()
    if (source_row is None or source_row[0] != p.source.digest
            or type(source_row[1]) is not dict or source_row[1].get('phase') != 'ACTIVE'):
        raise m.TransitionFailure('source_state_changed', p.operation_id)
    if (p.document.get('restore') is not None
            and m._hash(source_row[1]) != p.document['restore']['journal_state_digest']):
        raise m.TransitionFailure('restored_state_changed', p.operation_id)
    required = {'PLAINTEXT_ACTIVATING': 'PLAINTEXT_PENDING', 'REMOVING': 'PLAINTEXT_ACTIVE'}.get(pin.phase, pin.phase)
    if required not in PHASES or PHASES.index(phase) < PHASES.index(required):
        raise m.TransitionFailure('restored_state_behind_external_pin', p.operation_id)
    if phase == 'PLAINTEXT_ACTIVE' and pin.phase not in ('PLAINTEXT_ACTIVATING', 'PLAINTEXT_ACTIVE', 'REMOVING'):
        raise m.TransitionFailure('external_policy_behind_database', p.operation_id)
    return state


def _stream(c, model, *, after=None, limit=1000):
    names = [model['record']['column']]
    scoped = 'column' in model['tenancy']
    if scoped:
        names.append(model['tenancy']['column'])
    names += [field['column'] for field in model['fields']]
    names += [_staging(field) for field in model['fields']]
    statement = 'SELECT ' + ','.join(m._quote(c, name) for name in names) + f' FROM {m._table(c, model)}'
    params = ()
    if after is not None:
        value = UUID(after) if model['record']['codec'] == 'uuid16/v1' else int(after)
        statement += f' WHERE {m._quote(c, names[0])} > %s'
        params = (value,)
    statement += f' ORDER BY {m._quote(c, names[0])} LIMIT %s'
    return c.exec_driver_sql(statement, params + (limit,)).all()


def _guard(c, p, model, functions):
    if model['schema'] in functions:
        return functions[model['schema']]
    _, function = m._guard_names(p, model)
    name = m._quote(c, model['schema']) + '.' + m._quote(c, function)
    literal = sql.Literal(m._guard_body(p)).as_string(c.connection.driver_connection)
    try:
        c.exec_driver_sql(f'CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS {literal}')
    except SQLAlchemyError as exc:
        if getattr(getattr(exc, 'orig', None), 'sqlstate', None) == '42723':
            raise m.TransitionFailure('guard_function_conflict', p.operation_id, '42723') from None
        raise
    c.exec_driver_sql(f'REVOKE ALL ON FUNCTION {name}() FROM PUBLIC')
    functions[model['schema']] = function
    return function


def _expand(c, p):
    m._lock_tables(c, p)
    from cryptalis import _access_contract as access
    access.check(c, p)
    source = p.source
    _inventory(c, p, p.source, own=p.operation_id)
    for model in p.document['lock']['models']:
        m._check_owned_sequences(c, p, model)
        m._check_public_slots(c, p, model)
        if m._preserves_public_slots(p):
            m._refuse_unrecorded_metadata(c, p, model)
        else:
            m._refuse_expression_statistics(c, p, model)
        if m._facts(c, model) != p.document['active_schemas'][model['table_id']]:
            raise m.TransitionFailure('active_schema_mismatch', p.operation_id)
    functions = {}
    models = {}
    for model in p.document['lock']['models']:
        table = m._table(c, model)
        function = _guard(c, p, model, functions)
        trigger, _ = m._guard_names(p, model)
        c.exec_driver_sql(f'CREATE TRIGGER {m._quote(c, trigger)} BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE '
                          f'ON {table} FOR EACH STATEMENT EXECUTE FUNCTION {m._quote(c, model["schema"])}.{m._quote(c, function)}()')
        c.exec_driver_sql(f'ALTER TABLE {table} ENABLE ALWAYS TRIGGER {m._quote(c, trigger)}')
        for field in model['fields']:
            native = next(column for column in model['source_schema']['columns']
                          if column['name'] == field['column'])
            collate = ''
            if native['collation_name']:
                collate = (' COLLATE ' + m._quote(c, native['collation_schema'])
                           + '.' + m._quote(c, native['collation_name']))
            if native['type'] in ('bool', 'int2', 'int4', 'int8', 'date', 'uuid'):
                native_type = 'pg_catalog.' + native['type']
            else:
                limit = _native_text_length(native)
                native_type = 'pg_catalog.text' if native['type'] == 'text' else 'pg_catalog.varchar' + (f'({limit})' if limit is not None else '')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN {m._quote(c, _staging(field))} {native_type}{collate}')
        models[model['table_id']] = {'scope': m._scope(c, model), 'cursor': None, 'rows': 0, 'chunks': 0,
                                     'schema': m._facts(c, model), 'guard': m._guard_facts(c, p, model)}
    state = {'phase': 'EXPANDED', 'models': models,
             'source_operation_id': str(source.operation_id), 'source_plan_digest': source.digest}
    c.exec_driver_sql(f'INSERT INTO {m._journal(c, p)} VALUES (%s,%s,%s::jsonb)',
                      (p.operation_id, p.digest, json.dumps(state)))
    return state


def _backfill_chunk(c, p, state, keys, chunk_size):
    m._inspect_paused(c, p, state)
    source = p.source
    for model in p.document['lock']['models']:
        progress = state['models'][model['table_id']]
        rows = _stream(c, model, after=progress['cursor'], limit=chunk_size)
        if not rows:
            continue
        descriptors = tuple(FieldDescriptor.from_compiled(f['descriptor'], f['descriptor_digest'])
                            for f in model['fields'])
        scoped = 'column' in model['tenancy']
        material = {}
        updates = []
        for row in rows:
            tenant = row[1] if scoped else UUID(model['table_id'])
            offset = 2 if scoped else 1
            values = m._with_row_keys(keys, tenant, source, material, lambda prepared:
                [open_value(row[offset + index], descriptor, tenant, row[0], prepared)
                 for index, descriptor in enumerate(descriptors)])
            updates.append(tuple(values) + (row[0],))
        statement = (f'UPDATE {m._table(c, model)} SET '
                     + ','.join(m._quote(c, _staging(field)) + '=%s' for field in model['fields'])
                     + f' WHERE {m._quote(c, model["record"]["column"])}=%s')
        c.exec_driver_sql(statement, updates)
        progress['cursor'] = str(rows[-1][0])
        progress['rows'] += len(rows)
        progress['chunks'] += 1
        m._save(c, p, state)
        return True
    state['phase'] = 'BACKFILLED'
    m._save(c, p, state)
    return False


def _verify(c, p, state, keys):
    m._inspect_paused(c, p, state)
    source = p.source
    digests = {}
    for model in p.document['lock']['models']:
        progress = state['models'][model['table_id']]
        if m._scope(c, model) != progress['scope']:
            raise m.TransitionFailure('membership_changed', p.operation_id)
        if progress['rows'] != progress['scope']['count']:
            raise m.TransitionFailure('incomplete_backfill', p.operation_id)
        descriptors = tuple(FieldDescriptor.from_compiled(f['descriptor'], f['descriptor_digest'])
                            for f in model['fields'])
        scoped = 'column' in model['tenancy']
        cursor = None
        digest = hashlib.sha256()
        while rows := _stream(c, model, after=cursor):
            material = {}
            for row in rows:
                tenant = row[1] if scoped else UUID(model['table_id'])
                offset = 2 if scoped else 1
                def verify(prepared):
                    frames = []
                    for index, descriptor in enumerate(descriptors):
                        raw = row[offset + index]
                        frame = bytes(raw) if raw is not None else None
                        value = open_value(frame, descriptor, tenant, row[0], prepared)
                        staged = row[offset + len(descriptors) + index]
                        if value != staged:
                            raise m.TransitionFailure('value_verification_failed', p.operation_id)
                        frames.append(frame)
                    return frames
                frames = m._with_row_keys(keys, tenant, source, material, verify)
                digest.update(m._canonical([str(row[0]), str(tenant)]))
                for frame in frames:
                    digest.update(b'\x00' if frame is None else b'\x01' + len(frame).to_bytes(4, 'big') + frame)
            cursor = str(rows[-1][0])
        digests[model['table_id']] = digest.hexdigest()
    return digests


STORAGE_NAMES = {'p': 'PLAIN', 'e': 'EXTERNAL', 'x': 'EXTENDED', 'm': 'MAIN'}
COMPRESSION_NAMES = {'p': 'pglz', 'l': 'lz4'}
STATISTICS_KINDS = {'d': 'ndistinct', 'f': 'dependencies', 'm': 'mcv'}


def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _restore_metadata(c, p, model):
    table = m._table(c, model)
    metadata = m._expected_source_metadata(p, model)
    if metadata is None:
        m._check_owned_sequences(c, p, model)
        return
    for column, facts in metadata['columns'].items():
        target = f'{table} ALTER COLUMN {m._quote(c, column)}'
        if facts['comment'] is not None:
            c.exec_driver_sql(f'COMMENT ON COLUMN {table}.{m._quote(c, column)} IS {_literal(facts["comment"])}')
        if facts['statistics'] != '-1':
            try:
                target_statistics = int(facts['statistics'])
            except (TypeError, ValueError):
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id) from None
            if not 0 <= target_statistics <= 10000:
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
            c.exec_driver_sql(f'ALTER TABLE {target} SET STATISTICS {target_statistics}')
        if facts['storage'] != 'x':
            name = STORAGE_NAMES.get(facts['storage'])
            if name is None:
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
            c.exec_driver_sql(f'ALTER TABLE {target} SET STORAGE {name}')
        if facts['compression']:
            name = COMPRESSION_NAMES.get(facts['compression'])
            if name is None:
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
            c.exec_driver_sql(f'ALTER TABLE {target} SET COMPRESSION {name}')
        if facts['options']:
            for option in facts['options']:
                if not re.fullmatch(r'[a-z_][a-z0-9_]*(=[-0-9.]+)?', option):
                    raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
            c.exec_driver_sql(f'ALTER TABLE {target} SET ({", ".join(facts["options"])})')
        if not m._preserves_public_slots(p):
            m._apply_column_acl(c, table, column, facts['acl'], p.operation_id)
    for name, comment in metadata['constraints'].items():
        c.exec_driver_sql(f'COMMENT ON CONSTRAINT {m._quote(c, name)} ON {table} IS {_literal(comment)}')
    for name, comment in metadata['indexes'].items():
        index = f'{m._quote(c, model["schema"])}.{m._quote(c, name)}'
        c.exec_driver_sql(f'COMMENT ON INDEX {index} IS {_literal(comment)}')
    for entry in metadata['extended_statistics']:
        kinds = [STATISTICS_KINDS.get(kind) for kind in entry['kinds']]
        if any(kind is None for kind in kinds):
            raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
        columns = ', '.join(m._quote(c, column) for column in entry['columns'])
        name = f'{m._quote(c, model["schema"])}.{m._quote(c, entry["name"])}'
        c.exec_driver_sql(f'CREATE STATISTICS {name} ({", ".join(kinds)}) ON {columns} FROM {table}')
        if entry['statistics'] != '-1':
            try:
                target_statistics = int(entry['statistics'])
            except (TypeError, ValueError):
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id) from None
            if not 0 <= target_statistics <= 10000:
                raise m.TransitionFailure('metadata_restore_invalid', p.operation_id)
            c.exec_driver_sql(f'ALTER STATISTICS {name} SET STATISTICS {target_statistics}')
        if entry['comment'] is not None:
            c.exec_driver_sql(f'COMMENT ON STATISTICS {name} IS {_literal(entry["comment"])}')
    observed = m._observed_source_metadata(c, p, model)
    if observed != metadata:
        raise m.TransitionFailure('metadata_restore_mismatch', p.operation_id)


def _switch(c, p, state, keys):
    m._lock_tables(c, p, verification=True)
    digests = _verify(c, p, state, keys)
    if 'verification' in state and digests != state['verification']:
        raise m.TransitionFailure('verification_changed_before_switch', p.operation_id)
    state['verification'] = digests
    m._lock_tables(c, p)
    for model in p.document['lock']['models']:
        table = m._table(c, model)
        m._refuse_unrecorded_metadata(c, p, model)
        if m._preserves_public_slots(p):
            m._convert_public_columns(c, p, model, plaintext=True)
        else:
            for field in model['fields']:
                m._replace_protected_column(c, p, model, field, _staging(field))
                if not field['source']['nullable']:
                    c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN {m._quote(c, field["column"])} SET NOT NULL')
        for original in sorted((item for field in model['fields'] for item in field['original']['constraints']),
                               key=lambda item: item['name']):
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {m._quote(c, original["name"])} '
                              f'{original["definition"]}')
        for original in sorted((item for field in model['fields'] for item in field['original']['indexes']),
                               key=lambda item: item['name']):
            c.exec_driver_sql(original['definition'])
        try:
            _restore_metadata(c, p, model)
        except m.TransitionFailure:
            raise
        except SQLAlchemyError:
            raise m.TransitionFailure('metadata_restore_failed', p.operation_id) from None
        facts = m._facts(c, model)
        if m._preserves_public_slots(p):
            expected = deepcopy(model['source_schema'])
            expected['relation']['user_triggers'] = True
            if _metadata_diff(expected, facts):
                raise m.TransitionFailure('plaintext_schema_mismatch', p.operation_id)
            m._check_public_slots(c, p, model, facts=facts)
        state['models'][model['table_id']]['plaintext_schema'] = facts
    from cryptalis import _access_contract as access
    access.transfer(c, p, plaintext=True)
    state['phase'] = 'PLAINTEXT_PENDING'
    m._save(c, p, state)


def _inspect_plaintext(c, p, state, *, expect_guards):
    from cryptalis import _access_contract as access
    access.check(c, p, plaintext=True)
    for model in p.document['lock']['models']:
        observed = state['models'][model['table_id']]
        guard = m._check_guard(c, p, model) if expect_guards else m._guard_facts(c, p, model)
        if ((expect_guards and guard != observed['guard'])
                or (not expect_guards and guard is not None)):
            raise m.TransitionFailure('writer_fence_changed', p.operation_id)
        facts = m._facts(c, model)
        m._check_public_slots(c, p, model, facts=facts)
        expected = model['source_schema']
        if expect_guards:
            expected = {**expected, 'relation': {**expected['relation'], 'user_triggers': True}}
        # A database journal cannot redefine the host-supplied native contract.
        if facts != observed['plaintext_schema'] or _metadata_diff(expected, facts):
            raise m.TransitionFailure('plaintext_schema_mismatch', p.operation_id)
        metadata = m._expected_source_metadata(p, model)
        if m._observed_source_metadata(c, p, model) != metadata:
            raise m.TransitionFailure('metadata_not_restored:source_metadata', p.operation_id)


def _activate(c, p, state, pin):
    if pin.phase != 'PLAINTEXT_ACTIVATING':
        raise m.TransitionFailure('matching_external_publication_required', p.operation_id)
    m._lock_tables(c, p)
    _inspect_plaintext(c, p, state, expect_guards=True)
    m._drop_guards(c, p)
    for model in p.document['lock']['models']:
        state['models'][model['table_id']]['plaintext_schema'] = m._facts(c, model)
    state['phase'] = 'PLAINTEXT_ACTIVE'
    m._save(c, p, state)


def _progress(p, state):
    remedy = {'PLAINTEXT_PENDING': 'Publish the exact plaintext publication pin; keep writers stopped.',
              'PLAINTEXT_ACTIVE': 'Plaintext is active. Verify package-free operation, then remove with approval.',
              'ABORTED': 'Reverse effects were additive only; source protection is still active.'
              }.get(state['phase'], 'Keep writers stopped; inspect current policy and database before resume.')
    return m.Progress(p.operation_id, state['phase'], sum(model['rows'] for model in state['models'].values()),
                      sum(model['chunks'] for model in state['models'].values()), remedy)


def apply(p, engine, *, keys, pin, approval, consent, chunk_size=1000, until='PLAINTEXT_PENDING'):
    """Stage, verify, switch, or publish decrypt-back. Writers stay paused.

    Default stops at the plaintext switch pending external publication.
    PLAINTEXT_ACTIVE requires the host's independently current publication pin.
    """
    if type(chunk_size) is not int or not 1 <= chunk_size <= 5000 or until not in PHASES[1:]:
        raise m.TransitionFailure('invalid_apply_bound')
    with _executor(p, engine, pin, approval, consent) as c:
        state = _state(c, p, pin)
        c.commit()
        if state is None:
            with c.begin():
                state = _expand(c, p)
        while PHASES.index(state['phase']) < PHASES.index(until):
            with c.begin():
                if state['phase'] == 'EXPANDED':
                    _backfill_chunk(c, p, state, keys, chunk_size)
                elif state['phase'] == 'BACKFILLED':
                    if PHASES.index(until) > PHASES.index('VERIFIED'):
                        _switch(c, p, state, keys)
                    else:
                        m._lock_tables(c, p, verification=True)
                        state['verification'] = _verify(c, p, state, keys)
                        state['phase'] = 'VERIFIED'
                        m._save(c, p, state)
                elif state['phase'] == 'VERIFIED':
                    _switch(c, p, state, keys)
                elif state['phase'] == 'PLAINTEXT_PENDING':
                    _activate(c, p, state, pin)
        with c.begin():
            if state['phase'] == 'PLAINTEXT_PENDING':
                m._lock_tables(c, p, verification=True)
                _inspect_plaintext(c, p, state, expect_guards=True)
            elif state['phase'] == 'PLAINTEXT_ACTIVE':
                _inspect_plaintext(c, p, state, expect_guards=False)
            else:
                m._inspect_paused(c, p, state)
        return _progress(p, state)


def abort(p, engine, *, pin, approval, consent):
    """Remove additive staging before the plaintext switch. Keep the journal.

    This does not remove active protection. An aborted reverse identity cannot
    resume. The source protection and its pin stay current.
    """
    with _executor(p, engine, pin, approval, consent) as c:
        state = _state(c, p, pin, allow_aborted=True)
        c.commit()
        if state is None:
            return m.Progress(p.operation_id, 'ABORTED', 0, 0, 'No database effects existed.')
        if state['phase'] == 'ABORTED':
            return _progress(p, state)
        if state['phase'] in ('PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE'):
            raise m.TransitionFailure('switched_reverse_requires_removal', p.operation_id)
        with c.begin():
            m._lock_tables(c, p)
            m._inspect_paused(c, p, state)
            for model in p.document['lock']['models']:
                for field in model['fields']:
                    c.exec_driver_sql(f'ALTER TABLE {m._table(c, model)} DROP COLUMN {m._quote(c, _staging(field))}')
            m._drop_guards(c, p)
            for model in p.document['lock']['models']:
                if m._facts(c, model) != p.document['active_schemas'][model['table_id']]:
                    raise m.TransitionFailure('abort_source_schema_changed', p.operation_id)
            state['phase'] = 'ABORTED'
            m._save(c, p, state)
        return _progress(p, state)


def _assert_removed(c, p):
    from cryptalis import _access_contract as access
    access.check(c, p, plaintext=True)
    journal = m._quote(c, p.document['journal_schema']) + '.' + m._quote(c, m.JOURNAL)
    if c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)', (journal,)).scalar_one() is not None:
        raise m.TransitionFailure('reverse_removal_incomplete', p.operation_id)
    admitted_sequences = {
        (entry['schema'], entry['name'], entry['oid'])
        for model in p.document['lock']['models']
        for entry in m._check_owned_sequences(c, p, model)
    }
    schemas = sorted({model['schema'] for model in p.document['lock']['models']})
    relations = c.exec_driver_sql(
        "SELECT n.nspname, c.relname, c.oid::text, c.relkind FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=ANY(%s) AND pg_catalog.strpos(c.relname,'_cryptalis')=1", (schemas,)).all()
    leftover = [entry for entry in relations
                if not (entry[3] == 'S' and tuple(entry[:3]) in admitted_sequences)]
    functions = c.exec_driver_sql(
        "SELECT n.nspname, p.proname FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname=ANY(%s) AND pg_catalog.strpos(p.proname,'_cryptalis')=1", (schemas,)).all()
    if leftover or functions:
        raise m.TransitionFailure('retained_cryptalis_objects', p.operation_id)
    for model in p.document['lock']['models']:
        facts = m._facts(c, model)
        m._check_public_slots(c, p, model, facts=facts)
        differences = _metadata_diff(model['source_schema'], facts)
        metadata = m._expected_source_metadata(p, model)
        if m._observed_source_metadata(c, p, model) != metadata:
            differences.append('source_metadata')
        if differences:
            raise m.TransitionFailure('metadata_not_restored:' + ','.join(differences), p.operation_id)


def remove(p, engine, *, pin, approval, removal, consent):
    """Retire the journal and prove package-free schema after plaintext activation."""
    _removal_consent(p, removal)
    with _executor(p, engine, pin, approval, consent) as c:
        state = _state(c, p, pin, allow_aborted=False)
        c.commit()
        if state is None:
            if pin.phase != 'REMOVED':
                raise m.TransitionFailure('reverse_not_started', p.operation_id)
            _assert_removed(c, p)
            return m.Progress(p.operation_id, 'REMOVED', 0, 0, 'Removal evidence is current.')
        if state['phase'] != 'PLAINTEXT_ACTIVE':
            raise m.TransitionFailure('reverse_not_plaintext_active', p.operation_id)
        if pin.phase != 'REMOVING':
            raise m.TransitionFailure('matching_external_publication_required', p.operation_id)
        with c.begin():
            retired = _inventory(c, p, p.source, own=p.operation_id)
            if retired != p.document['retirable_aborted']:
                raise m.TransitionFailure('unreviewed_journal_operations', p.operation_id)
            m._lock_tables(c, p)
            _inspect_plaintext(c, p, state, expect_guards=False)
            c.exec_driver_sql(f'DELETE FROM {m._journal(c, p)}')
            c.exec_driver_sql(f'DROP TABLE {m._journal(c, p)}')
            _assert_removed(c, p)
            state['phase'] = 'REMOVED'
        return _progress(p, state)


def check_removed(p, engine, *, pin):
    """Read-only proof: no journal, no Cryptalis objects, original metadata."""
    _pin(p, pin)
    if pin.phase != 'REMOVED':
        raise m.TransitionFailure('matching_external_publication_required', p.operation_id)
    target = p.document['target'] if p.document.get('restore') is None else p.document['restore']['target']
    with m._connection(engine, p.operation_id) as c:
        if m._target(c)[:-1] != target[:-1]:
            raise m.TransitionFailure('wrong_database_target', p.operation_id)
        _assert_removed(c, p)


def status(p, engine, *, pin):
    """Read one committed reverse snapshot without keys or maintenance effects.

    The supplied pin is host authority. Metadata checks do not verify current
    values, key custody, retained backups, or deployment-wide writer exclusion.
    Retired journals have no available progress counters.
    """
    _pin(p, pin)
    try:
        _previous_lock(p.lock_bytes, p.document['lock'], engine)
    except ValueError:
        raise m.TransitionFailure('invalid_compiler_lock', p.operation_id) from None
    target = p.document['target'] if p.document['restore'] is None else p.document['restore']['target']
    with m._connection(engine, p.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        if m._target(c)[:-1] != target[:-1]:
            raise m.TransitionFailure('wrong_database_target', p.operation_id)
        state = _state(c, p, pin, allow_aborted=True)
        if state is None and pin.phase == 'REMOVED':
            _assert_removed(c, p)
            return m.TransitionStatus(p.operation_id, 'REMOVED', pin.phase, None, None, True,
                'NOT_PERFORMED', 'Native metadata matches the supplied removed pin. Check retained recovery obligations.')
        retired = _inventory(c, p, p.source, own=p.operation_id)
        if retired != p.document['retirable_aborted']:
            raise m.TransitionFailure('unreviewed_journal_operations', p.operation_id)
        phase = 'PREPARED' if state is None else state['phase']
        rows = chunks = 0
        if state is not None:
            models = state.get('models')
            if type(models) is not dict or set(models) != set(p.document['active_schemas']):
                raise m.TransitionFailure('invalid_reverse_progress', p.operation_id)
            for progress in models.values():
                if (type(progress) is not dict or type(progress.get('rows')) is not int
                        or type(progress.get('chunks')) is not int
                        or type(progress.get('scope')) is not dict
                        or type(progress['scope'].get('count')) is not int
                        or not 0 <= progress['rows'] <= progress['scope']['count'] < 2 ** 53
                        or not 0 <= progress['chunks'] <= progress['rows']):
                    raise m.TransitionFailure('invalid_reverse_progress', p.operation_id)
                rows += progress['rows']
                chunks += progress['chunks']
            if rows >= 2 ** 53 or chunks >= 2 ** 53:
                raise m.TransitionFailure('invalid_reverse_progress', p.operation_id)
        if phase in ('PREPARED', 'ABORTED'):
            source = p.source
            source_pin = m.DeploymentPin(source.target_id, source.operation_id, source.digest, 'ACTIVE')
            binding = None
            if p.document['restore'] is not None:
                from cryptalis.restore import RestoreBinding
                binding = RestoreBinding(_canonical(p.document['restore']))
            m._check_connection(source, c, source_pin, binding=binding)
            for model in p.document['lock']['models']:
                if m._facts(c, model) != p.document['active_schemas'][model['table_id']]:
                    raise m.TransitionFailure('active_schema_mismatch', p.operation_id)
        elif phase in ('PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE'):
            _inspect_plaintext(c, p, state, expect_guards=phase == 'PLAINTEXT_PENDING')
        else:
            m._inspect_paused(c, p, state)
        matched = phase == pin.phase == 'PLAINTEXT_ACTIVE'
        remedy = ('Native metadata matches the supplied plaintext pin. Check host writer policy before admission.'
                  if matched else 'Keep writers stopped; inspect this operation and the current external policy before resume.')
        if phase == 'PLAINTEXT_PENDING':
            remedy = 'Publish the exact plaintext publication pin; keep writers stopped.'
        elif phase == 'ABORTED':
            remedy = 'This reverse was aborted. Inspect the source protection before compiling a new reverse plan.'
        return m.TransitionStatus(p.operation_id, phase, pin.phase, rows, chunks, matched, 'NOT_PERFORMED', remedy)
