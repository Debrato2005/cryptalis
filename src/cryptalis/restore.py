"""Restored protected-schema bring-up authority (``cryptalis.restore/v1``).

A copied protected database is never current authority by itself. The host
must adopt it with explicit restore intent, quarantine evidence, and a fenced
source assertion. Adoption inspects the restored target, verifies every
retained frame with the retained key policy, and issues a binding that records:

- the source plan identity and original target facts,
- the observed restored target facts and environment,
- the restored source journal state digest at adoption,
- the retained key custody observed by full frame authentication,
- every schema definition restatement that a logical dump and restore caused.

A logical dump and restore can restate a compiler frame ``CHECK`` with a
different boolean grouping. Adoption accepts only known PG16 forms of the
declared frame policy, with every other schema fact structurally equal. The
restored constraint must also reject malformed frames by savepoint probes.
Every other definition change is refused with
``restored_definition_restatement_unsupported``.

The binding changes the evaluated deployment target only. The source plan,
pin, and journal stay unchanged. Journal rows remain progress and recovery
evidence, never implicit authority. Later operations compare the current
target, the source journal state, and the recorded restatements against the
binding, so a stale, cloned, tampered, or partially restored database is
refused with a typed failure.
"""
from dataclasses import dataclass
import datetime
import hashlib
import json
from uuid import UUID

from sqlalchemy.dialects import postgresql

from cryptalis._sqlalchemy_search import _frame_expressions
from cryptalis import migration as m
from cryptalis.crypto import CryptoFailure, KeyUnavailable
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.manifest.compiler import _canonical, _catalog_path
from cryptalis.manifest.parser import decode_manifest_json

FORMAT = 'cryptalis.restore/v1'


@dataclass(frozen=True)
class RestoreApproval:
    """Host assertion for a restored target. This module does not authenticate
    the source fence; the host must guarantee the source deployment is fenced
    or decommissioned before restoring authority to a copy."""
    host: str
    intent: str
    quarantine: str
    source_fenced: bool


@dataclass(frozen=True)
class RestoreBinding:
    artifact: bytes

    def __post_init__(self):
        try:
            document = decode_manifest_json(self.artifact)
            if (document.get('format') != FORMAT or document.get('kind') != 'restore'
                    or _canonical(document) != self.artifact):
                raise ValueError
            if set(document) != {'format', 'kind', 'adoption_id', 'source', 'target',
                                 'journal_state_digest', 'custody', 'environment', 'approval',
                                 'restatements'}:
                raise ValueError
            if UUID(document['adoption_id']).int == 0:
                raise ValueError
            source = document['source']
            if set(source) != {'operation_id', 'plan_digest', 'target'}:
                raise ValueError
            if UUID(source['operation_id']).int == 0 or not _digest(source['plan_digest']):
                raise ValueError
            if not _target_facts(source['target']) or not _target_facts(document['target']):
                raise ValueError
            if source['target'][:-1] == document['target'][:-1]:
                raise ValueError
            if not _digest(document['journal_state_digest']):
                raise ValueError
            custody = document['custody']
            if not isinstance(custody, dict) or not custody or any(
                    not isinstance(value, str) or not _digest(value) for value in custody.values()):
                raise ValueError
            environment = document['environment']
            if (set(environment) != {'server_version', 'system_identifier'}
                    or type(environment['server_version']) is not str or not environment['server_version']
                    or (environment['system_identifier'] is not None
                        and (type(environment['system_identifier']) is not str
                             or not environment['system_identifier']))):
                raise ValueError
            approval = document['approval']
            if (set(approval) != {'host', 'intent', 'quarantine', 'source_fenced', 'adopted_at'}
                    or approval['source_fenced'] is not True
                    or any(type(approval[name]) is not str or not approval[name].strip()
                           for name in ('host', 'intent', 'quarantine', 'adopted_at'))):
                raise ValueError
            restatements = document['restatements']
            if not isinstance(restatements, list):
                raise ValueError
            seen = set()
            for item in restatements:
                if (not isinstance(item, dict)
                        or set(item) not in ({'model', 'kind', 'name', 'recorded_digest', 'observed_digest',
                                              'definition'},
                                             {'model', 'kind', 'name', 'recorded_digest', 'observed_digest',
                                              'definition', 'probe'})
                        or item['kind'] != 'constraints'
                        or UUID(item['model']).int == 0
                        or type(item['name']) is not str or not item['name'].startswith('_cryptalis_')
                        or not item['name'].endswith('_frame')
                        or not _digest(item['recorded_digest']) or not _digest(item['observed_digest'])
                        or item['recorded_digest'] == item['observed_digest']
                        or type(item['definition']) is not str or not item['definition']
                        or not _frame_expression(item['definition'])
                        or hashlib.sha256(_canonical(item['definition'])).hexdigest() != item['observed_digest']
                        or ('probe' in item and item['probe'] != 'rejected-malformed-frames')
                        or (item['model'], item['name']) in seen):
                    raise ValueError
                seen.add((item['model'], item['name']))
        except Exception:
            raise m.TransitionFailure('invalid_restore_binding') from None

    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def adoption_id(self): return UUID(self.document['adoption_id'])
    @property
    def source_operation_id(self): return UUID(self.document['source']['operation_id'])
    @property
    def source_plan_digest(self): return self.document['source']['plan_digest']
    @property
    def source_target(self): return self.document['source']['target']
    @property
    def target(self): return self.document['target']


def _digest(value):
    return (type(value) is str and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _target_facts(target):
    return (isinstance(target, list) and len(target) == 5
            and type(target[0]) is str and target[0] != ''
            and type(target[1]) is str and target[1].isdigit()
            and (target[2] is None or (type(target[2]) is str and target[2] != ''))
            and (target[3] is None or (type(target[3]) is int and not isinstance(target[3], bool)))
            and type(target[4]) is str and target[4] != '')


def _approval(approval):
    if (type(approval) is not RestoreApproval or approval.source_fenced is not True
            or any(type(value) is not str or not value.strip()
                   for value in (approval.host, approval.intent, approval.quarantine))):
        raise m.TransitionFailure('restore_approval_required')


def _identity(source, binding):
    """Common binding-to-source identity checks."""
    if type(binding) is not RestoreBinding:
        raise m.TransitionFailure('restore_binding_required', source.operation_id)
    if (binding.source_plan_digest != source.digest
            or binding.source_operation_id != source.operation_id
            or binding.source_target != source.document['target']):
        raise m.TransitionFailure('restore_binding_mismatch', source.operation_id)
    fields = {(model['table_id'], field['payload_column'] + '_frame'): field
              for model in source.document['lock']['models'] for field in model['fields']}
    quote = postgresql.dialect().identifier_preparer.quote
    for item in binding.document['restatements']:
        field = fields.get((item['model'], item['name']))
        if field is None or _frame_expression(item['definition']) not in _frame_expressions(field, quote):
            raise m.TransitionFailure('restored_definition_restatement_unsupported', source.operation_id)
    return binding.target


def _current(source, binding, c, state):
    """Validate a binding against the live connection and journal state."""
    target = _identity(source, binding)
    if m._target(c)[:-1] != target[:-1]:
        raise m.TransitionFailure('restore_target_mismatch', source.operation_id)
    if m._hash(state) != binding.document['journal_state_digest']:
        raise m.TransitionFailure('restored_state_changed', source.operation_id)
    m._runtime_safety(c,source.document['runtime_role'],source.document['target'][-1],
                      source.document['lock']['models'],journal=m._journal(c,source),operation_id=source.operation_id)
    return target


def _strip_attnum(columns):
    return [{key: value for key, value in column.items() if key != 'attnum'} for column in columns]


def _frame_expression(definition):
    prefix = 'CHECK ('
    if not (definition.startswith(prefix) and definition.endswith(')')):
        raise ValueError('invalid_restore_binding')
    return definition[len(prefix):-1]


def _restatement_key(item):
    return (item['model'], item['kind'], item['name'], item['recorded_digest'], item['observed_digest'],
            item['definition'])


def admitted_frame(binding, model, field):
    """Return the adopted restatement for a field frame check, or None."""
    name = '_cryptalis_' + UUID(field['field_id']).hex + '_frame'
    for item in binding.document['restatements']:
        if item['model'] == model['table_id'] and item['name'] == name:
            return item
    return None


def _schema_evidence(c, source, state):
    """Structural comparison of live schema facts against the recorded facts.

    Column ordinal numbers are physical slots; a logical restore compacts
    them. Only frame ``CHECK`` constraints may differ in their textual
    definition, and only within the known PG16 policy forms with probe evidence.
    """
    restatements = []
    for model in source.document['lock']['models']:
        start = len(restatements)
        m._refuse_unrecorded_metadata(c,source,model)
        observed = m._facts(c, model)
        recorded = state['models'][model['table_id']]['active_schema']
        if (observed['relation'] != recorded['relation']
                or observed['dependencies'] != recorded['dependencies']
                or _strip_attnum(observed['columns']) != _strip_attnum(recorded['columns'])):
            raise m.TransitionFailure('restored_schema_mismatch', source.operation_id)
        for kind in ('constraints', 'indexes'):
            def identity(item):
                return (item['schema'], item['table'], item['name']) if kind == 'constraints' else item['name']
            observed_items = {identity(item): item for item in observed[kind]}
            recorded_items = {identity(item): item for item in recorded[kind]}
            if set(observed_items) != set(recorded_items):
                raise m.TransitionFailure('restored_schema_mismatch', source.operation_id)
            for key in sorted(observed_items):
                live, saved = dict(observed_items[key]), dict(recorded_items[key])
                name = live['name']
                live_digest, saved_digest = live.pop('definition_digest'), saved.pop('definition_digest')
                if live != saved:
                    raise m.TransitionFailure('restored_schema_mismatch', source.operation_id)
                if live_digest == saved_digest:
                    continue
                field = next((field for field in model['fields']
                              if field['payload_column'] + '_frame' == name), None)
                if (kind == 'constraints' and field is not None
                        and key == (model['schema'], model['table'], name)):
                    with _catalog_path(c):
                        definition = c.exec_driver_sql(
                            'SELECT pg_catalog.pg_get_constraintdef(c.oid) FROM pg_catalog.pg_constraint c '
                            'WHERE c.conrelid=pg_catalog.to_regclass(%s) AND c.conname=%s',
                            (m._table(c, model), name)).scalar_one()
                    if _frame_expression(definition) not in _frame_expressions(
                            field, c.dialect.identifier_preparer.quote):
                        raise m.TransitionFailure('restored_definition_restatement_unsupported', source.operation_id)
                    restatements.append({'model': model['table_id'], 'kind': kind, 'name': name,
                                         'recorded_digest': saved_digest, 'observed_digest': live_digest,
                                         'definition': definition})
                    continue
                raise m.TransitionFailure('restored_definition_restatement_unsupported',
                                          source.operation_id)
        admitted = {item['name']: _frame_expression(item['definition']) for item in restatements[start:]}
        m._protected_contract(c, source, model, observed, admitted=admitted)
    return restatements


def _attempt_rejection(c, source, table, column, record_column, identity, expression):
    """One savepoint probe: the expression must raise a check violation."""
    c.exec_driver_sql('SAVEPOINT _cryptalis_probe')
    rejected, sqlstate = False, None
    try:
        c.exec_driver_sql(f'UPDATE {table} SET {column} = {expression} WHERE {record_column} = %s',
                          (identity,))
    except Exception as exc:
        rejected = True
        sqlstate = getattr(getattr(exc, 'orig', None), 'sqlstate', None)
    finally:
        try:
            c.exec_driver_sql('ROLLBACK TO SAVEPOINT _cryptalis_probe')
        except Exception:
            c.rollback()
    if rejected and sqlstate != '23514':
        raise m.TransitionFailure('restored_constraint_probe_failed', source.operation_id) from None
    return rejected


def _probe_frame_checks(c, source, restatements):
    """Verify each restated frame CHECK rejects crafted malformed frames.

    The probes write only inside savepoints and roll them back. They supplement
    exact policy admission and do not establish general SQL equivalence.
    """
    for restatement in restatements:
        model = next(model for model in source.document['lock']['models']
                     if model['table_id'] == restatement['model'])
        field = next(field for field in model['fields']
                     if '_cryptalis_' + UUID(field['field_id']).hex + '_frame' == restatement['name'])
        table = m._table(c, model)
        column = m._quote(c, field['column'])
        record_column = m._quote(c, model['record']['column'])
        row = c.exec_driver_sql(
            f'SELECT {record_column} FROM {table} WHERE {column} IS NOT NULL '
            f'ORDER BY {record_column} LIMIT 1').scalar_one_or_none()
        if row is None:
            # A restated constraint without a retained frame has no behavioral
            # evidence. Missing evidence is refused, never converted to PASS.
            raise m.TransitionFailure('restored_constraint_probe_failed', source.operation_id)
        attempts = [f'pg_catalog.substring({column},1,10)',
                    f'pg_catalog.set_byte({column},0,0)',
                    f"overlay({column} placing '\\x00000000'::bytea from 7 for 4)"]
        if field['queries']:
            attempts.append(f"overlay({column} placing '\\x00000000'::bytea from 11 for 4)")
        for expression in attempts:
            if not _attempt_rejection(c, source, table, column, record_column, row, expression):
                raise m.TransitionFailure('restored_constraint_probe_failed', source.operation_id)
        restatement['probe'] = 'rejected-malformed-frames'
    return restatements


def _check_schema(c, source, state, binding):
    """Later operations must observe the same structure the adoption approved."""
    try:
        observed = _schema_evidence(c, source, state)
    except m.TransitionFailure as exc:
        if exc.code == 'restored_definition_restatement_unsupported':
            raise m.TransitionFailure('restored_schema_changed', source.operation_id) from None
        raise
    recorded = binding.document['restatements']
    if (sorted(map(_restatement_key, observed)) != sorted(map(_restatement_key, recorded))):
        raise m.TransitionFailure('restored_schema_changed', source.operation_id)


def _scan(c, source, keys):
    """Authenticate every retained active frame; return the observed custody set."""
    custody = {}
    policies = source.document['key_policies']
    for model in source.document['lock']['models']:
        descriptors = tuple(FieldDescriptor.from_compiled(f['descriptor'], f['descriptor_digest'])
                            for f in model['fields'])
        names = [model['record']['column']]
        if 'column' in model['tenancy']:
            names.append(model['tenancy']['column'])
        names.extend(f['column'] for f in model['fields'])
        columns = ','.join(m._quote(c, name) for name in names)
        table = m._table(c, model)
        quoted = m._quote(c, model['record']['column'])
        cursor = None
        while True:
            statement = f'SELECT {columns} FROM {table}'
            params = []
            if cursor is not None:
                statement += f' WHERE {quoted} > %s'
                params.append(UUID(cursor) if model['record']['codec'] == 'uuid16/v1' else int(cursor))
            statement += f' ORDER BY {quoted} LIMIT 1000'
            rows = c.exec_driver_sql(statement, tuple(params)).all()
            if not rows:
                break
            material = {}
            for row in rows:
                tenant = row[1] if 'column' in model['tenancy'] else UUID(model['table_id'])
                offset = 2 if 'column' in model['tenancy'] else 1

                def authenticate(prepared):
                    for i, f in enumerate(model['fields']):
                        frame = row[offset + i]
                        frame = bytes(frame) if frame is not None else None
                        admitted = prepared.policy
                        try:
                            if frame is not None and (
                                    int.from_bytes(frame[6:10], 'big') != admitted.payload_generation
                                    or int.from_bytes(frame[10:14], 'big') != (
                                        admitted.search_generation if f['queries'] else 0)):
                                raise m.TransitionFailure('generation_mismatch', source.operation_id)
                            value = open_text(frame, descriptors[i], tenant, row[0], prepared)
                        except KeyUnavailable:
                            raise
                        except CryptoFailure:
                            raise m.TransitionFailure('restored_frame_verification_failed',
                                                      source.operation_id) from None
                        if value is not None and type(value) is not str:
                            raise m.TransitionFailure('restored_frame_verification_failed',
                                                      source.operation_id)

                m._with_row_keys(keys, tenant, source, material, authenticate)
                # _with_row_keys admitted this exact policy before preparing.
                custody[str(tenant)] = policies[str(tenant)]
            cursor = str(rows[-1][0])
    return custody


def plan(source, engine, *, pin, keys, approval):
    """Read-only restored-target inspection. Issues a binding; changes nothing.

    The binding is a host artifact like the deployment pin. Store it outside
    database snapshots. Re-running adoption issues a new binding; no database
    state references the adoption identity.
    """
    m._admit(source, pin)
    if pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    _approval(approval)
    from cryptalis import deprotection as d
    with m._connection(engine, source.operation_id) as c:
        row = c.exec_driver_sql(
            f'SELECT plan_digest, state FROM {m._journal(c, source)} WHERE operation_id=%s',
            (source.operation_id,)).one_or_none()
        if row is None:
            raise m.TransitionFailure('restored_journal_missing', source.operation_id)
        if row[0] != source.digest:
            raise m.TransitionFailure('restored_journal_mismatch', source.operation_id)
        state = row[1]
        if type(state) is not dict or state.get('phase') != 'ACTIVE':
            raise m.TransitionFailure('restored_state_not_active', source.operation_id)
        if c.exec_driver_sql('SELECT current_user').scalar_one() != source.document['target'][-1]:
            raise m.TransitionFailure('maintenance_requires_planned_owner', source.operation_id)
        target = m._target(c)
        if target[:-1] == source.document['target'][:-1]:
            raise m.TransitionFailure('restore_source_is_current', source.operation_id)
        state=m._state(c,source,pin)
        d._inventory(c,source,source,own=None)
        m._runtime_safety(c,source.document['runtime_role'],source.document['target'][-1],
                          source.document['lock']['models'],journal=m._journal(c,source),operation_id=source.operation_id)
        restatements = _schema_evidence(c, source, state)
        custody = _scan(c, source, keys)
        restatements = _probe_frame_checks(c, source, restatements)
        system_identifier = None
        try:
            with c.begin_nested():
                system_identifier = c.exec_driver_sql(
                    'SELECT system_identifier::text FROM pg_catalog.pg_control_system()').scalar_one()
        except Exception:
            system_identifier = None
        version = c.exec_driver_sql('show server_version').scalar_one()
    return RestoreBinding(_canonical({
        'format': FORMAT, 'kind': 'restore', 'adoption_id': str(m.uuid4()),
        'source': {'operation_id': str(source.operation_id), 'plan_digest': source.digest,
                   'target': source.document['target']},
        'target': list(target), 'journal_state_digest': m._hash(state), 'custody': custody,
        'restatements': restatements,
        'environment': {'server_version': version, 'system_identifier': system_identifier},
        'approval': {'host': approval.host, 'intent': approval.intent,
                     'quarantine': approval.quarantine, 'source_fenced': True,
                     'adopted_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}}))
