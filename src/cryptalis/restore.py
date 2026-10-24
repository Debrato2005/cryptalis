"""Restored protected-schema bring-up authority.

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
from cryptalis.crypto.cf1 import FieldDescriptor, open_value
from cryptalis.manifest.compiler import _canonical, _catalog_path
from cryptalis.manifest.parser import decode_manifest_json

FORMAT = 'cryptalis.restore/v1'
SEQUENCE_FORMAT = 'cryptalis.restore/v2'
LAYOUT_FORMAT = 'cryptalis.restore/v3'


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
            layout_format = document.get('format') == LAYOUT_FORMAT
            sequence_format = document.get('format') in (SEQUENCE_FORMAT, LAYOUT_FORMAT)
            if (document.get('format') not in (FORMAT, SEQUENCE_FORMAT, LAYOUT_FORMAT) or document.get('kind') != 'restore'
                    or _canonical(document) != self.artifact):
                raise ValueError
            members = {'format', 'kind', 'adoption_id', 'source', 'target',
                                 'journal_state_digest', 'custody', 'environment', 'approval',
                                 'restatements'} | ({'sequences'} if sequence_format else set())
            if layout_format:
                members.add('columns')
            if set(document) != members:
                raise ValueError
            if sequence_format:
                _validate_sequence_map(document['sequences'], allow_empty=layout_format)
            if layout_format:
                _validate_layout_map(document['columns'])
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
            or binding.source_target != source.document['target']
            or any(source.document['key_policies'].get(tenant) != policy
                   for tenant, policy in binding.document['custody'].items())):
        raise m.TransitionFailure('restore_binding_mismatch', source.operation_id)
    _sequence_inventory(source.document, binding)
    _layout_inventory(source.document, binding)
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


def _validate_binding_frames(document, binding):
    """Require exact known frame checks and their recorded rejection probes."""
    fields = {(model['table_id'], field['payload_column'] + '_frame'): field
              for model in document['lock']['models'] for field in model['fields']}
    quote = postgresql.dialect().identifier_preparer.quote
    for item in binding.document['restatements']:
        field = fields.get((item['model'], item['name']))
        if (field is None or item.get('probe') != 'rejected-malformed-frames'
                or _frame_expression(item['definition']) not in _frame_expressions(field, quote)):
            raise m.TransitionFailure('invalid_restore_lineage')


def _validate_lineage(document):
    """Validate flat adopted-target authority carried by a successor artifact."""
    try:
        lineage = document['restore_lineage']
        if ((document['format'], document['kind']) not in (
                ('cryptalis.transition/v5', 'rewrap'), ('cryptalis.transition/v6', 'payload_rotation'),
                ('cryptalis.transition/v7', 'search_rotation'), ('cryptalis.transition/v12', 'rewrap'),
                ('cryptalis.transition/v13', 'payload_rotation'), ('cryptalis.transition/v14', 'search_rotation'))
                or type(lineage) is not list or not lineage):
            raise ValueError
        ancestors = {(item['operation_id'], item['plan_digest']): index
                     for index, item in enumerate(document['predecessors'])}
        previous, position, identities = None, -1, set()
        for raw in lineage:
            binding = RestoreBinding(_canonical(raw))
            index = ancestors.get((str(binding.source_operation_id), binding.source_plan_digest))
            if (index is None or index <= position or binding.adoption_id in identities
                    or binding.source_target[-1] != document['target'][-1]
                    or binding.target[-1] != document['target'][-1]
                    or previous is not None and binding.source_target != previous):
                raise ValueError
            _validate_binding_frames(document, binding)
            previous, position = binding.target, index
            identities.add(binding.adoption_id)
        if previous != document['target']:
            raise ValueError
        _sequence_inventory(document)
        _layout_inventory(document)
    except (ValueError, TypeError, KeyError, AttributeError, m.TransitionFailure):
        raise m.TransitionFailure('invalid_restore_lineage') from None


def frame_admissions(document, model, binding=None):
    """Return exact frame expressions from already admitted host artifacts."""
    records = list(document.get('restore_lineage', ()))
    if binding is not None:
        if type(binding) is not RestoreBinding:
            raise m.TransitionFailure('restore_binding_required')
        records.append(binding.document)
    return {item['name']: _frame_expression(item['definition'])
            for record in records for item in record['restatements']
            if item['model'] == model['table_id']}


def _sequence_key(item):
    return tuple(item[name] for name in ('model', 'schema', 'name', 'column'))


def _oid(value):
    return (type(value) is str and value.isascii() and value.isdecimal()
            and len(value) <= 10 and 0 < int(value) < 2**32 and str(int(value)) == value)


def _validate_sequence_map(entries, *, allow_empty=False):
    if type(entries) is not list or not entries and not allow_empty:
        raise ValueError
    source_oids, target_oids, names = set(), set(), set()
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {
                'model', 'schema', 'name', 'column', 'source_oid', 'target_oid'}
                or type(entry['model']) is not str or not UUID(entry['model']).int
                or str(UUID(entry['model'])) != entry['model']
                or any(type(entry[name]) is not str or not entry[name] or '\x00' in entry[name]
                       or len(entry[name].encode('utf8')) > 63 for name in ('schema', 'name', 'column'))
                or not _oid(entry['source_oid']) or not _oid(entry['target_oid'])
                or entry['source_oid'] in source_oids or entry['target_oid'] in target_oids
                or _sequence_key(entry) in names):
            raise ValueError
        source_oids.add(entry['source_oid'])
        target_oids.add(entry['target_oid'])
        names.add(_sequence_key(entry))
    if entries != sorted(entries, key=_sequence_key):
        raise ValueError


def _binding_records(document, binding=None):
    reverse = document.get('kind') == 'deprotect'
    base = document['source_plan'] if reverse else document
    records = list(base.get('restore_lineage', ()))
    if reverse and document.get('restore') is not None:
        records.append(document['restore'])
    if binding is not None:
        if type(binding) is not RestoreBinding:
            raise m.TransitionFailure('restore_binding_required')
        records.append(binding.document)
    return base, records


def _sequence_inventory(document, binding=None):
    """Evaluate sequence identity through exact, ordered host bindings."""
    base, records = _binding_records(document, binding)
    inventory = {tuple((model['table_id'], entry['schema'], entry['name'], entry['column'])): dict(entry)
                 for model in base['lock']['models']
                 for entry in model.get('source_metadata', {}).get('owned_sequences', ())}
    for raw in records:
        record = RestoreBinding(_canonical(raw)).document
        entries = record.get('sequences', [])
        layout = m._preserves_public_slot_lock(base['lock'])
        if ((layout and record['format'] != LAYOUT_FORMAT)
                or (not layout and (record['format'] == LAYOUT_FORMAT
                    or bool(inventory) != (record['format'] == SEQUENCE_FORMAT)))):
            raise m.TransitionFailure('restore_sequence_mismatch')
        if {_sequence_key(entry) for entry in entries} != set(inventory):
            raise m.TransitionFailure('restore_sequence_mismatch')
        for entry in entries:
            key = _sequence_key(entry)
            if entry['source_oid'] != inventory[key]['oid']:
                raise m.TransitionFailure('restore_sequence_mismatch')
            inventory[key]['oid'] = entry['target_oid']
    return inventory


def _validate_layout_map(entries):
    if type(entries) is not list or not entries:
        raise ValueError
    seen, source_slots, target_slots, last_target = set(), set(), set(), {}
    for entry in entries:
        if (type(entry) is not dict or set(entry) != {'model', 'column', 'source_attnum', 'target_attnum'}
                or type(entry['model']) is not str or not UUID(entry['model']).int
                or str(UUID(entry['model'])) != entry['model']
                or type(entry['column']) is not str or not entry['column'] or '\x00' in entry['column']
                or len(entry['column'].encode('utf8')) > 63
                or any(type(entry[name]) is not int or not 0 < entry[name] < 32768
                       for name in ('source_attnum', 'target_attnum'))):
            raise ValueError
        model, column = entry['model'], entry['column']
        source, target = entry['source_attnum'], entry['target_attnum']
        if ((model, column) in seen or (model, source) in source_slots
                or (model, target) in target_slots or target <= last_target.get(model, 0)):
            raise ValueError
        seen.add((model, column))
        source_slots.add((model, source))
        target_slots.add((model, target))
        last_target[model] = target
    if entries != sorted(entries, key=lambda entry: (entry['model'], entry['source_attnum'])):
        raise ValueError


def _layout_inventory(document, binding=None):
    """Compose exact public slots while preserving their original visible order."""
    base, records = _binding_records(document, binding)
    if not m._preserves_public_slot_lock(base['lock']):
        return None
    inventory = {(model['table_id'], column['name']): column['attnum']
                 for model in base['lock']['models'] for column in model['source_schema']['columns']}
    for raw in records:
        record = RestoreBinding(_canonical(raw)).document
        if record['format'] != LAYOUT_FORMAT:
            raise m.TransitionFailure('restore_layout_mismatch')
        entries = record['columns']
        if {(entry['model'], entry['column']) for entry in entries} != set(inventory):
            raise m.TransitionFailure('restore_layout_mismatch')
        for entry in entries:
            key = (entry['model'], entry['column'])
            if entry['source_attnum'] != inventory[key]:
                raise m.TransitionFailure('restore_layout_mismatch')
            inventory[key] = entry['target_attnum']
    return inventory


def layout_admissions(document, model, binding=None):
    """Return original public names with their currently admitted native slots."""
    inventory = _layout_inventory(document, binding)
    if inventory is None:
        return None
    return {column['name']: inventory[(model['table_id'], column['name'])]
            for column in model['source_schema']['columns']}


def _layout_evidence(c, source, binding=None):
    if not m._preserves_public_slot_lock(source.document['lock']):
        return [], {}
    maps, facts = [], {}
    for model in source.document['lock']['models']:
        original = layout_admissions(source.document, model)
        expected = layout_admissions(source.document, model, binding)
        current = m._facts(c, model)
        if current is None:
            raise m.TransitionFailure('restored_layout_mismatch', source.operation_id)
        observed = {column['name']: column['attnum'] for column in current['columns']}
        if list(observed) != list(original) or binding is not None and observed != expected:
            raise m.TransitionFailure('restored_layout_mismatch', source.operation_id)
        for column, slot in original.items():
            maps.append({'model': model['table_id'], 'column': column,
                         'source_attnum': slot, 'target_attnum': observed[column]})
        facts[model['table_id']] = observed
    return sorted(maps, key=lambda entry: (entry['model'], entry['source_attnum'])), facts


def sequence_admissions(document, model, binding=None):
    """Return the immutable sequence facts with the current target identities."""
    inventory = _sequence_inventory(document, binding)
    return [inventory[(model['table_id'], entry['schema'], entry['name'], entry['column'])]
            for entry in model.get('source_metadata', {}).get('owned_sequences', ())]


def _sequence_evidence(c, source, binding=None):
    """Compare every logical fact before admitting restored sequence OIDs."""
    from cryptalis.manifest.compiler import sequence_metadata
    maps, facts = [], {}
    if source.document['lock']['schema'] not in ('cryptalis.lock/v5', 'cryptalis.lock/v6', 'cryptalis.lock/v7'):
        return maps, facts
    for model in source.document['lock']['models']:
        original = sequence_admissions(source.document, model)
        expected = sequence_admissions(source.document, model, binding)
        observed = sequence_metadata(c, model['schema'], model['table'],
                                     [field['column'] for field in model['fields']])
        logical = lambda entries: sorted((_canonical({key: value for key, value in entry.items()
                                                     if key != 'oid'}) for entry in entries))
        if logical(observed) != logical(original) or binding is not None and observed != expected:
            raise m.TransitionFailure('restored_sequence_mismatch', source.operation_id)
        by_name = {(entry['schema'], entry['name'], entry['column']): entry for entry in original}
        for entry in observed:
            old = by_name[(entry['schema'], entry['name'], entry['column'])]
            maps.append(dict(model=model['table_id'], schema=entry['schema'], name=entry['name'],
                             column=entry['column'], source_oid=old['oid'], target_oid=entry['oid']))
        facts[model['table_id']] = observed
    return sorted(maps, key=_sequence_key), facts


def _schema_evidence(c, source, state, *, sequences=None, layouts=None):
    """Structural comparison of live schema facts against the recorded facts.

    Column ordinal numbers are physical slots; a logical restore compacts
    them. Only frame ``CHECK`` constraints may differ in their textual
    definition, and only within the known PG16 policy forms with probe evidence.
    """
    from cryptalis import _access_contract as access
    access.check(c, source)
    restatements = []
    for model in source.document['lock']['models']:
        start = len(restatements)
        expected_sequences = None if sequences is None else sequences.get(model['table_id'])
        expected_slots = None if layouts is None else layouts.get(model['table_id'])
        m._refuse_unrecorded_metadata(c,source,model,sequences=expected_sequences,slots=expected_slots)
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
        m._protected_contract(c, source, model, observed, admitted=admitted,
                              sequences=expected_sequences, slots=expected_slots)
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
        _, sequences = _sequence_evidence(c, source, binding)
        _, layouts = _layout_evidence(c, source, binding)
        observed = _schema_evidence(c, source, state, sequences=sequences, layouts=layouts)
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
                            value = open_value(frame, descriptors[i], tenant, row[0], prepared)
                        except KeyUnavailable:
                            raise
                        except CryptoFailure:
                            raise m.TransitionFailure('restored_frame_verification_failed',
                                                      source.operation_id) from None
                        expected_type = (bool if descriptors[i].value_codec == 'boolean-u8/v1' else
                            int if descriptors[i].value_codec in ('pg-int2-be/v1', 'pg-int4-be/v1', 'pg-int8-be/v1') else str)
                        if value is not None and type(value) is not expected_type:
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
        sequence_map, sequence_facts = _sequence_evidence(c, source)
        layout_map, layout_facts = _layout_evidence(c, source)
        restatements = _schema_evidence(c, source, state, sequences=sequence_facts, layouts=layout_facts)
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
    document = {
        'format': LAYOUT_FORMAT if layout_map else SEQUENCE_FORMAT if sequence_map else FORMAT,
        'kind': 'restore', 'adoption_id': str(m.uuid4()),
        'source': {'operation_id': str(source.operation_id), 'plan_digest': source.digest,
                   'target': source.document['target']},
        'target': list(target), 'journal_state_digest': m._hash(state), 'custody': custody,
        'restatements': restatements,
        'environment': {'server_version': version, 'system_identifier': system_identifier},
        'approval': {'host': approval.host, 'intent': approval.intent,
                     'quarantine': approval.quarantine, 'source_fenced': True,
                     'adopted_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}}
    if sequence_map or layout_map:
        document['sequences'] = sequence_map
    if layout_map:
        document['columns'] = layout_map
    return RestoreBinding(_canonical(document))
