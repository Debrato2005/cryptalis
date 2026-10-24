"""Bounded PostgreSQL maintenance transitions. Research prototype.

The host authenticates the plan, target, writer exclusion, and deployment pin.
A database journal is progress evidence, never authority after restore. No
production provider or publication procedure is supplied by this module.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math
import time
from types import SimpleNamespace
from uuid import UUID, uuid4
from psycopg import sql

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.dialects import postgresql

from cryptalis.crypto.cf1 import FieldDescriptor, seal_value, open_value
from cryptalis.crypto.keys import CryptoFailure, Keyring, KeyUnavailable
from cryptalis.crypto._payload_rotation import MAX_BATCH_BYTES, MAX_BATCH_ROWS
from cryptalis.manifest.compiler import (compile_protection, _schema_facts, _canonical, _previous_lock,
                                          unrecorded_column_metadata, protected_extended_statistics,
                                          sequence_metadata, source_metadata, _metadata_diff, _catalog_path,
                                          _native_text_length)
from cryptalis.manifest.parser import ManifestInvalid, _decode_json

JOURNAL = '_cryptalis_journal'
PHASES = ('PREPARED', 'EXPANDED', 'BACKFILLED', 'VERIFIED', 'PENDING', 'ACTIVE')


def _decode_transition_json(raw):
    """Permit finite positive decimals only at measured throughput paths."""
    document = _decode_json(raw, parse_float=float)
    rate_paths = {prefix + ('estimates', name)
                  for prefix in ((), ('source_plan',))
                  for name in ('backfill_rows_per_second', 'verify_rows_per_second')}
    for prefix, owner in (((),document),(('source_plan',),document.get('source_plan') if type(document) is dict else None)):
        if (type(owner) is dict and (owner.get('format'),owner.get('kind')) in (
                    ('cryptalis.transition/v3','payload_rotation'),('cryptalis.transition/v4','search_rotation'),
                    ('cryptalis.transition/v6','payload_rotation'),('cryptalis.transition/v7','search_rotation'),
                    ('cryptalis.transition/v10','payload_rotation'),('cryptalis.transition/v11','search_rotation'),
                    ('cryptalis.transition/v13','payload_rotation'),('cryptalis.transition/v14','search_rotation'))):
            rate_paths.add(prefix+('estimates','copy_rows_per_second'))

    def check(value, path):
        if type(value) is float:
            if path not in rate_paths or not math.isfinite(value) or value <= 0:
                raise ManifestInvalid('Only measured transition rates permit finite positive decimals')
        elif isinstance(value, dict):
            for key, child in value.items():
                check(child, path + (key,))
        elif isinstance(value, list):
            for i, child in enumerate(value):
                check(child, path + (i,))

    check(document, ())
    return document


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


def _finite_number(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _estimate_seconds(rows, *rates):
    seconds = sum(rows / rate for rate in rates)
    if not math.isfinite(seconds) or not 0 <= seconds < 2 ** 53:
        raise TransitionFailure('unrepresentable_pause_estimate')
    return math.ceil(seconds)


def _validate_estimates(costs):
    for name in ('rows', 'writer_pause_seconds_estimate'):
        if type(costs[name]) is not int or costs[name] < 0:
            raise ValueError
    if not isinstance(costs['limits'], str) or not costs['limits']:
        raise ValueError
    rates = ('backfill_rows_per_second', 'verify_rows_per_second')
    if any(name in costs for name in rates):
        for name in rates:
            value = costs[name]
            if not _finite_number(value) or value <= 0:
                raise ValueError


def _payload_activation_estimates(rows, backfill, verify, copy, copy_wal):
    """Estimate terminal copy and five verification passes from host measurements."""
    if type(rows) is not int or not 0 <= rows < 2**53:
        raise TransitionFailure('invalid_payload_activation_estimates')
    if any(not _finite_number(rate) or rate <= 0 for rate in (backfill, verify, copy)):
        raise TransitionFailure('missing_measured_rates')
    if type(copy_wal) is not int or not 1 <= copy_wal < 2**53:
        raise TransitionFailure('missing_measured_storage_or_wal_costs')
    wal = rows * copy_wal
    if wal >= 2**53:
        raise TransitionFailure('unrepresentable_copy_wal_estimate')
    return dict(rows=rows, backfill_rows_per_second=backfill, verify_rows_per_second=verify,
        copy_rows_per_second=copy, copy_wal_bytes_per_row=copy_wal, copy_wal_bytes_estimate=wal,
        required_verify_passes=5,
        writer_pause_seconds_estimate=_estimate_seconds(rows, copy, verify, verify, verify, verify, verify),
        limits='Estimates cover terminal copy, one source pass, one paired source/target pass, '
               'one post-copy target pass and one publication target pass. They exclude prior staging '
               'and sealing, lock drain, DDL, '
               'index work, capacity guarantees and provider overhead. Copy WAL is a host estimate, not a bound.')


def _search_activation_estimates(rows,backfill,verify,copy,copy_wal):
    costs=_payload_activation_estimates(rows,backfill,verify,copy,copy_wal)
    costs['limits']=('Host-measured copy rate and WAL must include native equality and unique-index maintenance. '
        'Estimates cover terminal copy and five verification passes, excluding prior staging/sealing, '
        'DDL, lock drain, publication, capacity guarantees and provider overhead. '
        'Copy WAL is a host estimate, not a bound.')
    return costs


_GENERATION_ROTATIONS=('payload_rotation','search_rotation')


@dataclass(frozen=True)
class MigrationPlan:
    artifact: bytes
    def __post_init__(self):
        try:
            doc = _decode_transition_json(self.artifact)
            members = {'format', 'kind', 'operation_id', 'target_id', 'target',
                            'runtime_role', 'journal_schema', 'lock', 'source_lock_digest',
                            'key_policies', 'scopes', 'estimates'}
            from cryptalis import _access_contract as access
            formats = {'cryptalis.transition/v9': 'cryptalis.transition/v2',
                       'cryptalis.transition/v10': 'cryptalis.transition/v3',
                       'cryptalis.transition/v11': 'cryptalis.transition/v4',
                       'cryptalis.transition/v12': 'cryptalis.transition/v5',
                       'cryptalis.transition/v13': 'cryptalis.transition/v6',
                       'cryptalis.transition/v14': 'cryptalis.transition/v7'}
            fmt = formats.get(doc.get('format'), doc.get('format'))
            online = fmt == 'cryptalis.transition/v8' and doc.get('kind') == 'protect'
            carries_access = online or doc.get('format') in formats
            if carries_access:
                members.add('access_contract')
            rewrap = fmt in ('cryptalis.transition/v2', 'cryptalis.transition/v5') and doc.get('kind') == 'rewrap'
            payload = fmt in ('cryptalis.transition/v3', 'cryptalis.transition/v6') and doc.get('kind') == 'payload_rotation'
            search = fmt in ('cryptalis.transition/v4', 'cryptalis.transition/v7') and doc.get('kind') == 'search_rotation'
            rotating=payload or search
            if rewrap or rotating:
                proof_key = doc['kind']+'_plan_digest'
                observations_key = doc['kind']+'_observations'
                members |= {'predecessors', proof_key, observations_key}
                if fmt in ('cryptalis.transition/v5', 'cryptalis.transition/v6', 'cryptalis.transition/v7'):
                    members.add('restore_lineage')
                if rotating:
                    members.add(('payload' if payload else 'search')+'_batch_limits')
                ancestors = doc['predecessors']
                if type(ancestors) is not list or len(ancestors) < (2 if rotating else 1):
                    raise ValueError
                seen = {str(UUID(doc['operation_id']))}
                for item in ancestors:
                    if set(item) != {'operation_id', 'plan_digest'}:
                        raise ValueError
                    identity = UUID(item['operation_id'])
                    if not identity.int or str(identity) != item['operation_id'] or str(identity) in seen:
                        raise ValueError
                    seen.add(str(identity))
                    if (type(item['plan_digest']) is not str or len(item['plan_digest']) != 64
                            or any(c not in '0123456789abcdef' for c in item['plan_digest'])):
                        raise ValueError
                if (type(doc[proof_key]) is not str or len(doc[proof_key]) != 64
                        or any(c not in '0123456789abcdef' for c in doc[proof_key])):
                    raise ValueError
                if rotating and ancestors[-1]['plan_digest'] != doc[proof_key]:
                    raise ValueError
            elif online:
                members |= {'predecessors', 'online_preparation', 'online_verification'}
                preparation = doc['online_preparation']
                if (type(preparation) is not dict or set(preparation) != {'operation_id', 'plan_digest'}
                        or type(doc['predecessors']) is not list or doc['predecessors'] != [preparation]
                        or not UUID(preparation['operation_id']).int
                        or str(UUID(preparation['operation_id'])) != preparation['operation_id']
                        or preparation['operation_id'] == doc['operation_id']
                        or type(preparation['plan_digest']) is not str or len(preparation['plan_digest']) != 64
                        or any(c not in '0123456789abcdef' for c in preparation['plan_digest'])):
                    raise ValueError
            elif doc.get('format') != 'cryptalis.transition/v1' or doc.get('kind') != 'protect':
                raise ValueError
            if set(doc) != members or _canonical(doc) != self.artifact:
                raise ValueError
            for name in ('operation_id', 'target_id'):
                if UUID(doc[name]).int == 0: raise ValueError
            target = doc['target']
            if (not isinstance(target, list) or len(target) != 5
                    or any(not isinstance(target[i], str) or not target[i] for i in (0, 1, 4))
                    or target[2] is not None and not isinstance(target[2], str)
                    or target[3] is not None and (type(target[3]) is not int or not 1 <= target[3] <= 65535)):
                raise ValueError
            if any(not isinstance(doc[name], str) or not doc[name] for name in ('runtime_role', 'journal_schema')):
                raise ValueError
            if (any(not isinstance(doc[name], dict) for name in ('lock', 'key_policies', 'estimates'))
                    or not isinstance(doc['scopes'], list)):
                raise ValueError
            # Compiler validation needs identifier quoting, never a connection.
            _previous_lock(_canonical(doc['lock']), doc['lock'], SimpleNamespace(dialect=postgresql.dialect()))
            if fmt in ('cryptalis.transition/v5', 'cryptalis.transition/v6', 'cryptalis.transition/v7'):
                from cryptalis.restore import _validate_lineage
                _validate_lineage(doc)
            _validate_estimates(doc['estimates'])
            if carries_access:
                access.validate(doc['access_contract'], doc['lock']['models'], target[-1], doc['runtime_role'])
            if rewrap or rotating or online:
                observed = doc['online_verification'] if online else doc[observations_key]
                if set(observed) != {model['table_id'] for model in doc['lock']['models']}:
                    raise ValueError
                for item in observed.values():
                    if (set(item) != {'rows', 'membership', 'frames'} or type(item['rows']) is not int
                            or not 0 <= item['rows'] < 2**53):
                        raise ValueError
                    for key in ('membership', 'frames'):
                        if (type(item[key]) is not str or len(item[key]) != 64
                                or any(c not in '0123456789abcdef' for c in item[key])):
                            raise ValueError
                if sum(item['rows'] for item in observed.values()) != doc['estimates']['rows']:
                    raise ValueError
            if online:
                scopes = doc['scopes']
                if (any(type(item) is not dict or set(item) != {'table_id', 'estimated_rows'}
                        or type(item['estimated_rows']) is not int for item in scopes)
                        or len(scopes) != len(observed)
                        or {item['table_id']: item['estimated_rows'] for item in scopes}
                        != {table: item['rows'] for table, item in observed.items()}):
                    raise ValueError
            if rotating:
                limits, costs = doc[('payload' if payload else 'search')+'_batch_limits'], doc['estimates']
                scopes={}
                for item in doc['scopes']:
                    if (type(item) is not dict or set(item)!={'table_id','estimated_rows'}
                            or type(item['table_id']) is not str or item['table_id'] in scopes
                            or type(item['estimated_rows']) is not int):
                        raise ValueError
                    scopes[item['table_id']]=item['estimated_rows']
                if scopes!={table:item['rows'] for table,item in observed.items()}:
                    raise ValueError
                if (type(limits) is not dict or set(limits) != {'max_rows', 'max_bytes'}
                        or type(limits['max_rows']) is not int or not 1 <= limits['max_rows'] <= MAX_BATCH_ROWS
                        or type(limits['max_bytes']) is not int or not 1 <= limits['max_bytes'] <= MAX_BATCH_BYTES):
                    raise ValueError
                for name, value in costs.items():
                    if name not in ('backfill_rows_per_second', 'verify_rows_per_second',
                                    'copy_rows_per_second', 'limits'):
                        if type(value) is not int or not 0 <= value < 2**53:
                            raise ValueError
                estimate=_payload_activation_estimates if payload else _search_activation_estimates
                if costs != estimate(costs['rows'], costs['backfill_rows_per_second'],
                        costs['verify_rows_per_second'], costs['copy_rows_per_second'], costs['copy_wal_bytes_per_row']):
                    raise ValueError
        except (ManifestInvalid, ValueError, TypeError, KeyError, AttributeError, TransitionFailure):
            raise TransitionFailure('invalid_plan') from None
    def __str__(self):
        costs = self.document['estimates']
        if self.document['kind'] == 'rewrap':
            return (f'Estimated root-rewrap verification pause: {costs["writer_pause_seconds_estimate"]} s '
                    f'for {costs["rows"]} rows. Payload and search bytes stay unchanged. ' + costs['limits'])
        if self.document['kind'] in _GENERATION_ROTATIONS:
            return (f'Estimated {self.document["kind"].removesuffix("_rotation")}-rotation copy and verification pause: {costs["writer_pause_seconds_estimate"]} s '
                    f'for {costs["rows"]} rows. Atomic copy WAL estimate: {costs["copy_wal_bytes_estimate"]} bytes. '
                    + costs['limits'])
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


@dataclass(frozen=True)
class TransitionStatus:
    operation_id: UUID
    phase: str
    external_phase: str
    committed_rows: int | None
    committed_chunks: int | None
    runtime_metadata_matches: bool
    verification: str
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


ACL_PRIVILEGES = {'r': 'SELECT', 'w': 'UPDATE', 'a': 'INSERT', 'x': 'REFERENCES'}


def _apply_column_acl(c, table, column, entries, operation_id):
    for entry in entries:
        try:
            grantee, letters, grantable = entry.rsplit('|', 2)
        except (AttributeError, ValueError):
            raise TransitionFailure('metadata_restore_invalid', operation_id) from None
        if grantable not in ('false', 'true') or not letters or any(
                letter not in ACL_PRIVILEGES for letter in letters):
            raise TransitionFailure('metadata_restore_invalid', operation_id)
        if grantee != 'PUBLIC' and c.exec_driver_sql(
                'SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s', (grantee,)).scalar_one_or_none() is None:
            raise TransitionFailure('acl_role_missing', operation_id)
        role = 'PUBLIC' if grantee == 'PUBLIC' else _quote(c, grantee)
        privileges = ', '.join(ACL_PRIVILEGES[letter] for letter in letters)
        statement = f'GRANT {privileges} ({_quote(c, column)}) ON {table} TO {role}'
        if grantable == 'true':
            statement += ' WITH GRANT OPTION'
        c.exec_driver_sql(statement)


def _expected_sequences(p, model, sequences=None):
    if sequences is None:
        from cryptalis.restore import sequence_admissions
        return sequence_admissions(p.document, model)
    return sequences


def _check_owned_sequences(c, p, model, *, sequences=None):
    expected = _expected_sequences(p, model, sequences)
    observed = sequence_metadata(c, model['schema'], model['table'],
                                 [field['column'] for field in model['fields']], expected=expected)
    if observed != expected:
        recorded = 'owned_sequences' in model.get('source_metadata', {})
        raise TransitionFailure('source_metadata_changed' if recorded else 'unsupported_dependency', p.operation_id)
    return expected


def _expected_source_metadata(p, model, *, sequences=None):
    metadata = deepcopy(model.get('source_metadata'))
    if metadata is not None and 'owned_sequences' in metadata:
        metadata['owned_sequences'] = _expected_sequences(p, model, sequences)
    return metadata


def _observed_source_metadata(c, p, model, *, sequences=None):
    _check_owned_sequences(c, p, model, sequences=sequences)
    _check_public_slots(c, p, model)
    _refuse_expression_statistics(c, p, model)
    metadata = model.get('source_metadata')
    if metadata is None:
        return None
    return source_metadata(c, model['schema'], model['table'], model['fields'],
                           sequences='owned_sequences' in metadata)


def _preserves_public_slot_lock(lock):
    return lock['schema'] in ('cryptalis.lock/v6', 'cryptalis.lock/v7') and lock.get('layout') == 'preserve-public-slots/v1'


def _preserves_public_slots(p):
    return _preserves_public_slot_lock(p.document['lock'])


def _refuse_expression_statistics(c, p, model):
    if c.exec_driver_sql(
        'SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_statistic_ext '
        'WHERE stxrelid=pg_catalog.to_regclass(%s) AND stxexprs IS NOT NULL)',
        (_table(c, model),)).scalar_one():
        raise TransitionFailure('unsupported_dependency', p.operation_id)


def _check_public_slots(c, p, model, *, facts=None, slots=None):
    if not _preserves_public_slots(p):
        return
    if slots is None:
        from cryptalis.restore import layout_admissions
        slots = layout_admissions(p.document, model)
    names = [column['name'] for column in model['source_schema']['columns']]
    if (type(slots) is not dict or set(slots) != set(names)
            or any(type(value) is not int or not 0 < value < 32768 for value in slots.values())
            or len(set(slots.values())) != len(slots)):
        raise TransitionFailure('public_slots_changed', p.operation_id)
    facts = _facts(c, model) if facts is None else facts
    if type(facts) is not dict or type(facts.get('columns')) is not list:
        raise TransitionFailure('public_slots_changed', p.operation_id)
    observed = [(column['name'], column['attnum']) for column in facts['columns']
                if column['name'] in slots]
    if observed != [(name, slots[name]) for name in names]:
        raise TransitionFailure('public_slots_changed', p.operation_id)


def _active_metadata(p, model, *, sequences=None):
    metadata = _expected_source_metadata(p, model, sequences=sequences)
    for column in metadata['columns'].values():
        column.update(storage='x', compression='')
    metadata.update(constraints={}, indexes={}, extended_statistics=[])
    return metadata


def _convert_public_columns(c, p, model, *, plaintext=False):
    """Convert verified shadows in one native rewrite without replacing attributes."""
    _check_owned_sequences(c, p, model)
    _check_public_slots(c, p, model)
    table = _table(c, model)
    if not plaintext:
        constraints = {item['name'] for field in model['fields'] for item in field['original']['constraints']}
        indexes = {item['name'] for field in model['fields'] for item in field['original']['indexes']}
        for name in sorted(constraints):
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {_quote(c, name)}')
        for name in sorted(indexes):
            c.exec_driver_sql(f'DROP INDEX {_quote(c, model["schema"])}.{_quote(c, name)}')
        for entry in model['source_metadata']['extended_statistics']:
            c.exec_driver_sql(f'DROP STATISTICS {_quote(c, model["schema"])}.{_quote(c, entry["name"])}')
    for field in model['fields']:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {_quote(c, field["payload_column"] + "_frame")}')
        if field['queries']:
            c.exec_driver_sql(f'DROP INDEX {_quote(c, model["schema"])}.{_quote(c, field["payload_column"] + "_eq")}')
    alterations, shadows = [], []
    for field in model['fields']:
        target = 'pg_catalog.bytea'
        shadow = field['payload_column']
        if plaintext:
            from cryptalis.deprotection import _staging
            shadow = _staging(field)
            native = next(column for column in model['source_schema']['columns'] if column['name'] == field['column'])
            if native['type'] in ('bool', 'int2', 'int4', 'int8'):
                target = 'pg_catalog.' + native['type']
            else:
                limit = _native_text_length(native)
                target = ('pg_catalog.text' if native['type'] == 'text' else
                          'pg_catalog.varchar' + (f'({limit})' if limit is not None else ''))
                target += f' COLLATE {_quote(c, native["collation_schema"])}.{_quote(c, native["collation_name"])}'
        alterations.append(f'ALTER COLUMN {_quote(c, field["column"])} TYPE {target} USING {_quote(c, shadow)}')
        shadows.append(shadow)
    c.exec_driver_sql(f'ALTER TABLE {table} ' + ','.join(alterations))
    if not plaintext:
        for field in model['fields']:
            public = {**field, 'payload_column': field['column']}
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {_quote(c, field["payload_column"] + "_frame")} '
                              f'CHECK ({_frame_check(c, public)})')
            if field['queries']:
                tenant = _quote(c, model['tenancy']['column']) + ', ' if 'column' in model['tenancy'] else ''
                unique = 'UNIQUE ' if 'unique' in field['queries'] else ''
                c.exec_driver_sql(f'CREATE {unique}INDEX {_quote(c, field["payload_column"] + "_eq")} ON {table} '
                                  f'USING btree ({tenant}(pg_catalog.substring({_quote(c, field["column"])},15,32)) pg_catalog.bytea_ops)')
    for shadow in shadows:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN {_quote(c, shadow)}')
    _check_owned_sequences(c, p, model)
    _check_public_slots(c, p, model)


def _replace_protected_column(c, p, model, field, replacement, *, sequences=None):
    expected = _check_owned_sequences(c, p, model, sequences=sequences)
    owned = [entry for entry in expected if entry['column'] == field['column']]
    for entry in owned:
        sequence = f'{_quote(c, entry["schema"])}.{_quote(c, entry["name"])}'
        c.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY NONE')
    if owned:
        detached = sequence_metadata(c, model['schema'], model['table'], [], expected=owned)
        if detached != [{**entry, 'column': None, 'dependency_kind': None} for entry in owned]:
            raise TransitionFailure('source_metadata_changed', p.operation_id)
    table = _table(c, model)
    # No CASCADE: an unexpected dependency blocks the atomic switch.
    c.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN {_quote(c, field["column"])}')
    c.exec_driver_sql(f'ALTER TABLE {table} RENAME COLUMN {_quote(c, replacement)} '
                      f'TO {_quote(c, field["column"])}')
    for entry in owned:
        sequence = f'{_quote(c, entry["schema"])}.{_quote(c, entry["name"])}'
        c.exec_driver_sql(f'ALTER SEQUENCE {sequence} OWNED BY {table}.{_quote(c, field["column"])}')
    _check_owned_sequences(c, p, model, sequences=expected)


def _refuse_unrecorded_metadata(c, p, model, *, sequences=None, slots=None):
    protected = [field['column'] for field in model['fields']]
    metadata = model.get('source_metadata')
    _check_public_slots(c, p, model, slots=slots)
    _refuse_expression_statistics(c, p, model)
    if _preserves_public_slots(p):
        observed = source_metadata(c, model['schema'], model['table'], model['fields'], sequences=True)
        if observed != _active_metadata(p, model, sequences=sequences):
            raise TransitionFailure('source_metadata_changed', p.operation_id)
        _check_owned_sequences(c, p, model, sequences=sequences)
        return
    if metadata is not None:
        observed = source_metadata(c, model['schema'], model['table'], model['fields'],
                                   sequences='owned_sequences' in metadata)
        for field in model['fields']:
            if (observed['columns'][field['column']]['acl']
                    != metadata['columns'][field['column']]['acl']):
                raise TransitionFailure('source_metadata_changed', p.operation_id)
    for column, kinds in unrecorded_column_metadata(c, model['schema'], model['table'], protected):
        if metadata is not None:
            kinds = [kind for kind in kinds if kind != 'column grant']
        if kinds:
            raise TransitionFailure('unsupported_protected_metadata', p.operation_id)
    if protected_extended_statistics(c, model['schema'], model['table'], protected):
        raise TransitionFailure('unsupported_dependency', p.operation_id)
    _check_owned_sequences(c, p, model, sequences=sequences)


def _check_source_metadata(c, p, model):
    if 'source_metadata' not in model:
        _refuse_unrecorded_metadata(c, p, model)
        return
    observed = _observed_source_metadata(c, p, model)
    if observed != _expected_source_metadata(p, model):
        raise TransitionFailure('source_metadata_changed', p.operation_id)


def _target(c):
    return list(c.exec_driver_sql('SELECT current_database(), (SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database()), inet_server_addr()::text, inet_server_port(), current_user').one())


def _runtime_safety(c, runtime_role, owner, models, journal=None, operation_id=None):
    """Check effective runtime privileges before keys or schema admission."""
    role = c.exec_driver_sql(
        'SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, '
        "pg_catalog.pg_has_role(rolname,%s,'MEMBER'), "
        "pg_catalog.has_database_privilege(rolname,current_database(),'CREATE') "
        'FROM pg_catalog.pg_roles WHERE rolname=%s', (owner, runtime_role)).one_or_none()
    if role is None or runtime_role == owner or any(role):
        raise TransitionFailure('unsafe_runtime_role', operation_id)
    models = tuple(models)
    for schema in sorted({model['schema'] for model in models}):
        if c.exec_driver_sql("SELECT pg_catalog.has_schema_privilege(%s,%s,'CREATE')",
                             (runtime_role, schema)).scalar_one():
            raise TransitionFailure('unsafe_runtime_role', operation_id)
    for model in models:
        relation = c.exec_driver_sql(
            'SELECT pg_catalog.pg_get_userbyid(relowner), '
            "pg_catalog.has_table_privilege(%s,oid,'TRIGGER,TRUNCATE') "
            'FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass(%s)',
            (runtime_role, _table(c, model))).one_or_none()
        if relation is None or relation[0] != owner:
            raise TransitionFailure('maintenance_requires_table_owner', operation_id)
        if relation[1]:
            raise TransitionFailure('unsafe_runtime_role', operation_id)
    if journal is not None:
        relation = c.exec_driver_sql(
            'SELECT pg_catalog.pg_get_userbyid(relowner), '
            "pg_catalog.has_table_privilege(%s,oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), "
            "pg_catalog.has_any_column_privilege(%s,oid,'INSERT,UPDATE,REFERENCES') "
            'FROM pg_catalog.pg_class WHERE oid=pg_catalog.to_regclass(%s)',
            (runtime_role, runtime_role, journal)).one_or_none()
        if relation is not None:
            if relation[0] != owner:
                raise TransitionFailure('maintenance_requires_table_owner', operation_id)
            if any(relation[1:]):
                raise TransitionFailure('unsafe_runtime_role', operation_id)


def _policy_document(p):
    return {'domain':str(p.domain_id),'tenant':str(p.tenant_id), 'payload':p.payload_generation,
        'search':p.search_generation, 'wrappers':[{'provider':str(w.provider_id), 'context':{
            'domain':str(w.context.domain_id),'tenant':str(w.context.tenant_id),'purpose':w.context.purpose,
            'root':str(w.context.root_id),'generation':w.context.generation},
            'wrapper':hashlib.sha256(w.sealed).hexdigest()} for w in p.wrappers]}


def _policy(ring):
    if not isinstance(ring, Keyring): raise TransitionFailure('missing_key_policy')
    return _hash(_policy_document(ring.policy))


def _ring(keys, tenant, p):
    ring = keys(tenant) if callable(keys) else keys
    if (not isinstance(ring, Keyring) or ring.policy.tenant_id != tenant or
            str(ring.policy.domain_id) != p.document['lock']['domain_id'] or
            _policy(ring) != p.document['key_policies'].get(str(tenant))):
        raise TransitionFailure('key_policy_changed', p.operation_id)
    return ring


def _with_row_keys(keys, tenant, p, material, operation):
    """Retry local row crypto once after expiry, before SQL or progress effects."""
    if tenant not in material:
        material[tenant] = _ring(keys, tenant, p).prepare()
    try:
        return operation(material[tenant])
    except KeyUnavailable as failure:
        if not failure._lease_expired:
            raise
    # The expired attempt returned no row. Recheck host policy and reacquire
    # expired roots; neither key access nor this retry extends a lease.
    material[tenant] = _ring(keys, tenant, p).prepare()
    return operation(material[tenant])


def plan(manifest, mapping, engine, *, writers, search_reviews=(), keys, runtime_role,
         target_id, backfill_rows_per_second, verify_rows_per_second,
         temporary_bytes_per_row=None, wal_bytes_per_row=None, layout=None):
    """Read-only compiler admission plus target, keys, scope, and cost estimates.

    Rates and per-row costs are explicit host observations/estimates, not
    qualified budgets or upper bounds. Measure representative staging data.
    """
    if not isinstance(target_id, UUID) or not target_id.int or not isinstance(runtime_role,str) or not runtime_role:
        raise TransitionFailure('invalid_target_or_runtime_role')
    rates = (backfill_rows_per_second, verify_rows_per_second)
    if any(not _finite_number(r) or r <= 0 for r in rates):
        raise TransitionFailure('missing_measured_rates')
    proposal = compile_protection(manifest, mapping, engine, writers=writers, search_reviews=search_reviews, layout=layout)
    if any(type(cost) is not int or not 1<=cost<2**53 for cost in (temporary_bytes_per_row,wal_bytes_per_row)):
        raise TransitionFailure('missing_measured_storage_or_wal_costs')
    lock = json.loads(proposal.lock_bytes)
    policies, scopes, rows, plaintext_bytes = {}, [], 0, 0
    with _connection(engine) as c:
        target = _target(c)
        _runtime_safety(c, runtime_role, target[-1], lock['models'])
        for model in lock['models']:
            if _facts(c,model) != model['source_schema']: raise TransitionFailure('stale_plan_schema')
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
            sizes = [(f'CASE WHEN {_quote(c, f["column"])} IS NULL THEN 0 ELSE 1 END'
                      if f['source']['type'] == 'bool' else
                      f'CASE WHEN {_quote(c, f["column"])} IS NULL THEN 0 ELSE {f["source"]["type"][3:]} END'
                      if f['source']['type'] in ('int2', 'int4', 'int8') else
                      f'coalesce(octet_length({_quote(c, f["column"])}),0)') for f in model['fields']]
            size=c.exec_driver_sql(f'SELECT coalesce(sum('+ '+'.join(sizes)+f'),0) FROM {_table(c,model)}').scalar_one()
            scopes.append({'table_id':model['table_id'],'estimated_rows':count})
            rows+=count; plaintext_bytes+=size
        schema=lock['models'][0]['schema']
        if c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_quote(c,schema)+'.'+_quote(c,JOURNAL),)).scalar_one() is not None:
            raise TransitionFailure('existing_transition_requires_inspection')
    estimates={'rows':rows,'plaintext_bytes':plaintext_bytes,'temporary_bytes_estimate':rows*temporary_bytes_per_row,
        'wal_bytes_estimate':rows*wal_bytes_per_row,'provider_unwraps_per_cold_preparation':sum(len((keys(UUID(t)) if callable(keys) else keys).policy.wrappers) for t in policies),
        'backfill_seconds_estimate':_estimate_seconds(rows, rates[0]), 'verify_seconds_estimate':_estimate_seconds(rows, rates[1]),
        'backfill_rows_per_second':rates[0], 'verify_rows_per_second':rates[1],
        'writer_pause_seconds_estimate':_estimate_seconds(rows, *rates),
        'checkpoint_extra_verify_seconds_estimate':_estimate_seconds(rows, rates[1]),
        'cost_basis':'Host-supplied per-row staging observations/estimates; not bounds or qualification.',
        'limits':'Host rate estimates exclude lock drain, DDL, index build, publication delay and capacity guarantees.'}
    if layout is not None:
        estimates['limits'] += (' Preserving public slots rewrites the whole heap and index storage during '
                                'DDL; this cost is excluded from the rate and WAL estimates.')
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
            not _finite_number(approval.approved_pause_seconds) or
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
    with _maintenance_executor(p,engine,approval) as c:
        yield c


@contextmanager
def _maintenance_executor(p,engine,approval):
    """Shared SQL mechanics after the caller admits its typed operation/pin."""
    _approve_maintenance(p,approval)
    try:
        _previous_lock(p.lock_bytes,p.document['lock'],engine)
    except ValueError:
        raise TransitionFailure('invalid_compiler_lock',p.operation_id) from None
    lock=int.from_bytes(hashlib.sha256(_canonical([(m['schema'],m['table']) for m in p.document['lock']['models']])).digest()[:8],'big',signed=True)
    with _connection(engine,p.operation_id,exclusive=True) as c:
        if _target(c) != p.document['target']: raise TransitionFailure('wrong_database_target',p.operation_id)
        _runtime_safety(c,p.document['runtime_role'],p.document['target'][-1],p.document['lock']['models'],
                        journal=_journal(c,p),operation_id=p.operation_id)
        c.exec_driver_sql("SET lock_timeout = '5s'")
        c.exec_driver_sql('SET synchronous_commit = on')
        acquired=c.exec_driver_sql('SELECT pg_catalog.pg_try_advisory_lock(%s)',(lock,)).scalar_one()
        c.commit()
        if not acquired: raise TransitionFailure('executor_already_running',p.operation_id)
        yield c


def _state(c,p,pin,*,allow_aborted=False):
    kind = p.document['kind']
    online = p.document['format'] == 'cryptalis.transition/v8'
    exists=c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_journal(c,p),)).scalar_one()
    if exists is None:
        if online: raise TransitionFailure('missing_online_successor', p.operation_id)
        if kind in _GENERATION_ROTATIONS:
            raise TransitionFailure('missing_'+kind.removesuffix('_rotation')+'_successor', p.operation_id)
        if pin.phase != 'PREPARED': raise TransitionFailure('restored_or_missing_transition',p.operation_id)
        return None
    row=c.exec_driver_sql(f'SELECT plan_digest, state FROM {_journal(c,p)} WHERE operation_id=%s',(p.operation_id,)).one_or_none()
    if row is None and online: raise TransitionFailure('missing_online_successor', p.operation_id)
    if row is None and kind in _GENERATION_ROTATIONS:
        raise TransitionFailure('missing_'+kind.removesuffix('_rotation')+'_successor', p.operation_id)
    if row is None or row[0] != p.digest: raise TransitionFailure('journal_identity_mismatch',p.operation_id)
    state=row[1]
    if state.get('phase') == 'SUPERSEDED':
        raise TransitionFailure('deployment_superseded', p.operation_id)
    if online:
        if state.get('phase') not in ('PENDING', 'ACTIVE'):
            raise TransitionFailure('online_successor_state_changed', p.operation_id)
        _check_predecessors(c, p)
    if kind in ('rewrap',)+_GENERATION_ROTATIONS:
        proof_key = kind+'_plan_digest'
        if (state.get('phase') not in ('PENDING', 'ACTIVE')
                or state.get(proof_key) != p.document[proof_key]):
            raise TransitionFailure(kind+'_state_changed', p.operation_id)
        if kind in _GENERATION_ROTATIONS:
            try:
                if (set(state)!={'phase','models',proof_key,'cutover_measurements'}
                        or type(state['models']) is not dict
                        or set(state['models'])!=set(p.document[kind+'_observations'])):
                    raise ValueError
                for table,observed in p.document[kind+'_observations'].items():
                    item=state['models'][table]
                    if (set(item)!={'rows','chunks','scope','active_schema','guard'}
                            or type(item['rows']) is not int or item['rows']!=observed['rows']
                            or type(item['chunks']) is not int or not 0<=item['chunks']<=item['rows']
                            or item['scope']!={'count':observed['rows'],'membership':observed['membership']}
                            or type(item['scope']['count']) is not int):
                        raise ValueError
                metrics=state['cutover_measurements']
                if (type(metrics) is not dict or set(metrics)!={'copy_wall_ns','copy_wal_bytes_cluster_delta'}
                        or any(type(value) is not int or value<0 for value in metrics.values())):
                    raise ValueError
            except (ValueError,TypeError,KeyError,AttributeError):
                raise TransitionFailure(kind+'_state_changed',p.operation_id) from None
        _check_predecessors(c, p)
    if state['phase']=='ABORTED':
        if allow_aborted and pin.phase=='PREPARED': return state
        raise TransitionFailure('operation_aborted',p.operation_id)
    required='PENDING' if pin.phase=='ACTIVATING' else pin.phase
    if state['phase'] not in PHASES or PHASES.index(state['phase']) < PHASES.index(required):
        raise TransitionFailure('restored_state_behind_external_pin',p.operation_id)
    if state['phase']=='ACTIVE' and pin.phase not in ('ACTIVE','ACTIVATING'):
        raise TransitionFailure('external_policy_behind_database',p.operation_id)
    return state


def _check_predecessors(c, p):
    """The immutable host artifact defines the exact prior-operation chain."""
    ancestors = p.document.get('predecessors', [])
    if not ancestors:
        return set()
    rows = c.exec_driver_sql(
        f'SELECT operation_id, plan_digest, state FROM {_journal(c,p)} WHERE operation_id=ANY(%s::uuid[])',
        ([UUID(item['operation_id']) for item in ancestors],)).all()
    observed = {str(operation): (digest, state) for operation, digest, state in rows}
    chain = ancestors + [{'operation_id': str(p.operation_id), 'plan_digest': p.digest}]
    for index, item in enumerate(ancestors):
        entry = observed.get(item['operation_id'])
        if (entry is None or entry[0] != item['plan_digest'] or type(entry[1]) is not dict
                or entry[1].get('phase') != 'SUPERSEDED'
                or entry[1].get('superseded_by') != chain[index + 1]):
            raise TransitionFailure('predecessor_chain_changed', p.operation_id)
    return {UUID(item['operation_id']) for item in ancestors}


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


def _guard_body(p):
    owner = p.document['target'][-1].replace("'", "''")
    return f"BEGIN IF CURRENT_USER <> '{owner}' THEN RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='Cryptalis maintenance: writers paused; retry only after matching deployment publication'; END IF; RETURN NULL; END"


def _drop_guards(c,p):
    functions=set()
    for model in p.document['lock']['models']:
        trigger,function=_guard_names(p,model)
        c.exec_driver_sql(f'DROP TRIGGER {_quote(c,trigger)} ON {_table(c,model)}')
        functions.add(_quote(c,model['schema'])+'.'+_quote(c,function))
    # No CASCADE: an unexpected dependent object aborts the transaction.
    for fn in sorted(functions): c.exec_driver_sql(f'DROP FUNCTION {fn}()')


def _guard_facts(c,p,model):
    with _catalog_path(c):
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


def _check_guard(c, p, model):
    """The host plan defines the writer fence; the journal records continuity."""
    guard = _guard_facts(c, p, model)
    trigger, function = _guard_names(p, model)
    expected = ['A', 62, True, 0, model['schema'], function, False,
                ['search_path=pg_catalog'], _guard_body(p), p.document['target'][-1]]
    if guard is None or guard[:10] != expected or len(guard[10]) != 1 or guard[10][0][0] != trigger:
        raise TransitionFailure('writer_fence_changed', p.operation_id)
    return guard


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
    width = {'bool': 1, 'int2': 2, 'int4': 4, 'int8': 8}.get(f['source']['type'])
    minimum, maximum = (42 + width, 42 + width) if width is not None else (overhead, 16777216+overhead)
    return f"{col} IS NULL OR (pg_catalog.octet_length({col}) BETWEEN {minimum} AND {maximum} AND pg_catalog.substring({col},1,6)=pg_catalog.decode('{magic}','hex') AND pg_catalog.substring({col},7,4)<>pg_catalog.decode('00000000','hex') AND pg_catalog.substring({col},11,4){op}pg_catalog.decode('00000000','hex'))"


def _install_guards(c,p):
    functions = set()
    for model in p.document['lock']['models']:
        table=_table(c,model); trigger,function=_guard_names(p,model)
        fn=_quote(c,model['schema'])+'.'+_quote(c,function)
        # SECURITY INVOKER. Runtime cannot become the table owner. Operator must
        # separately exclude every writer with owner/DDL credentials.
        literal=sql.Literal(_guard_body(p)).as_string(c.connection.driver_connection)
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


def _expand(c,p):
    _lock_tables(c,p)
    for model in p.document['lock']['models']:
        if _facts(c,model)!=model['source_schema']: raise TransitionFailure('source_schema_changed',p.operation_id)
        _check_source_metadata(c,p,model)
    c.exec_driver_sql(f'CREATE TABLE {_journal(c,p)} (operation_id uuid PRIMARY KEY, plan_digest text NOT NULL, state jsonb NOT NULL)')
    c.exec_driver_sql(f'REVOKE ALL ON {_journal(c,p)} FROM PUBLIC')
    c.exec_driver_sql(f'GRANT SELECT ON {_journal(c,p)} TO {_quote(c,p.document["runtime_role"])}')
    _install_guards(c, p)
    models={}
    for model in p.document['lock']['models']:
        table = _table(c, model)
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
        facts = _facts(c, model)
        if facts != observed['schema']:
            raise TransitionFailure('transition_schema_changed', p.operation_id)
        if p.document['kind'] == 'protect':
            guard = _protected_contract(c, p, model, facts, paused=True, staging=True)
        else:
            _check_owned_sequences(c, p, model)
            if _preserves_public_slots(p):
                _refuse_unrecorded_metadata(c, p, model)
            else:
                _refuse_expression_statistics(c, p, model)
            from cryptalis.deprotection import _staging
            expected = deepcopy(p.document['active_schemas'][model['table_id']])
            expected['relation']['user_triggers'] = True
            for field in model['fields']:
                native = next(column for column in model['source_schema']['columns']
                              if column['name'] == field['column'])
                expected['columns'].append({**native, 'name': _staging(field), 'nullable': True})
            if _metadata_diff(expected, facts):
                raise TransitionFailure('transition_schema_changed', p.operation_id)
            guard = _check_guard(c, p, model)
        if guard!=observed['guard']:
            raise TransitionFailure('writer_fence_changed',p.operation_id)


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
            body=_with_row_keys(keys,tenant,p,material,lambda prepared:
                [seal_value(row[offset+i],descriptor,tenant,row[0],prepared) for i,descriptor in enumerate(descriptors)])
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
    for model in p.document['lock']['models']:
        progress=state['models'][model['table_id']]
        if _scope(c,model)!=progress['scope']: raise TransitionFailure('membership_changed',p.operation_id)
        if progress['rows']!=progress['scope']['count']: raise TransitionFailure('incomplete_backfill',p.operation_id)
    digests = _verify_values(c,p,keys)
    if p.document['format'] == 'cryptalis.transition/v8':
        for model in p.document['lock']['models']:
            expected = p.document['online_verification'][model['table_id']]
            scope = state['models'][model['table_id']]['scope']
            if (scope != {'count': expected['rows'], 'membership': expected['membership']}
                    or digests[model['table_id']] != expected['frames']):
                raise TransitionFailure('online_verification_changed', p.operation_id)
    return digests


def _verify_values(c,p,keys,*,active=False):
    """Authenticate values and frames; callers own schema and membership proof."""
    digests={}
    for model in p.document['lock']['models']:
        descriptors=tuple(FieldDescriptor.from_compiled(f['descriptor'],f['descriptor_digest']) for f in model['fields'])
        cursor=None; digest=hashlib.sha256()
        while rows:=_stream(c,model,payloads=not active,after=cursor):
            material={}
            for row in rows:
                tenant=row[1] if 'column' in model['tenancy'] else UUID(model['table_id']); offset=2 if 'column' in model['tenancy'] else 1
                def verify(prepared):
                    frames=[]
                    for i,f in enumerate(model['fields']):
                        source,frame=(None,row[offset+i]) if active else row[offset+2*i:offset+2*i+2]
                        frame=bytes(frame) if frame is not None else None
                        admitted=prepared.policy
                        if frame is not None and (int.from_bytes(frame[6:10],'big')!=admitted.payload_generation or int.from_bytes(frame[10:14],'big')!=(admitted.search_generation if f['queries'] else 0)):
                            raise TransitionFailure('generation_mismatch',p.operation_id)
                        value=open_value(frame,descriptors[i],tenant,row[0],prepared)
                        if not active and (type(value)!=type(source) or value!=source): raise TransitionFailure('value_verification_failed',p.operation_id)
                        frames.append(frame)
                    return frames
                frames=_with_row_keys(keys,tenant,p,material,verify)
                digest.update(_canonical([str(row[0]),str(tenant)]))
                for frame in frames:
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
        _check_source_metadata(c,p,model)
        table=_table(c,model)
        if _preserves_public_slots(p):
            _convert_public_columns(c, p, model)
            facts = _facts(c, model)
            _protected_contract(c, p, model, facts, paused=True)
            state['models'][model['table_id']]['active_schema'] = facts
            continue
        for f in model['fields']:
            _replace_protected_column(c, p, model, f, f['payload_column'])
            if not f['source']['nullable']:
                c.exec_driver_sql(f'ALTER TABLE {table} ALTER COLUMN {_quote(c,f["column"])} SET NOT NULL')
            if 'source_metadata' in model:
                _apply_column_acl(c, table, f['column'],
                                  model['source_metadata']['columns'][f['column']]['acl'], p.operation_id)
        state['models'][model['table_id']]['active_schema']=_facts(c,model)
    state['phase']='PENDING'; _save(c,p,state)


def _protected_contract(c, p, model, facts, *, paused=False, admitted=None, staging=False, sequences=None, slots=None):
    """Bind recorded catalog shape and generated storage to the host lock."""
    from cryptalis._sqlalchemy_search import validate_frame_storage, validate_search_storage
    from cryptalis.restore import frame_admissions
    _check_owned_sequences(c, p, model, sequences=sequences)
    _check_public_slots(c, p, model, facts=facts, slots=slots)
    if _preserves_public_slots(p):
        if staging:
            _check_source_metadata(c, p, model)
        else:
            _refuse_unrecorded_metadata(c, p, model, sequences=sequences, slots=slots)
    else:
        _refuse_expression_statistics(c, p, model)
    inherited = frame_admissions(p.document, model)
    inherited.update(admitted or {})
    admitted = inherited
    expected = deepcopy(model['source_schema'])
    expected['relation']['user_triggers'] = paused
    observed = deepcopy(facts)
    failure = 'transition_schema_changed' if staging else 'active_schema_mismatch'
    if not staging:
        replaced_constraints = {item['name'] for f in model['fields'] for item in f['original']['constraints']}
        replaced_indexes = {item['name'] for f in model['fields'] for item in f['original']['indexes']}
        expected['constraints'] = [item for item in expected['constraints']
                                   if not (item['outgoing'] and item['name'] in replaced_constraints)]
        expected['indexes'] = [item for item in expected['indexes']
                               if item['constraint_name'] not in replaced_constraints and item['name'] not in replaced_indexes]
    for field in model['fields']:
        column = next(item for item in expected['columns'] if item['name'] == field['column'])
        if staging:
            column = {**column, 'name': field['payload_column'], 'nullable': True}
            expected['columns'].append(column)
            field = {**field, 'column': field['payload_column']}
        column.update(type='bytea', type_schema='pg_catalog', typmod='-1', default_digest=None,
                      collation=None, collation_name=None, collation_schema=None, deterministic=None, provider=None)
        name = field['payload_column'] + '_frame'
        frame = next((item for item in observed['constraints'] if item['outgoing'] and item['name'] == name), None)
        expected_frame = dict(name=name, kind='c', deferrable=False, deferred=False, validated=True,
                              outgoing=True, incoming=False, schema=model['schema'], table=model['table'],
                              columns=[field['column']], referenced_columns=[])
        if frame is None or {k: v for k, v in frame.items() if k != 'definition_digest'} != expected_frame:
            raise TransitionFailure(failure, p.operation_id)
        observed['constraints'].remove(frame)
        try:
            expression = (admitted or {}).get(name)
            if field['queries']:
                index_name = field['payload_column'] + '_eq'
                index = next((item for item in observed['indexes'] if item['name'] == index_name), None)
                scoped = 'column' in model['tenancy']
                tenant = [model['tenancy']['column']] if scoped else []
                expected_index = dict(name=index_name, primary=False, unique='unique' in field['queries'],
                    exclusion=False, nulls_not_distinct=False, immediate=True, valid=True, ready=True,
                    live=True, replica_identity=False, total_columns=1 + len(tenant), key_columns=1 + len(tenant),
                    method='btree', partial=False, expression=True, columns=tenant + [None],
                    dependency_columns=sorted(tenant + [field['column']]),
                    opclasses=(['pg_catalog.uuid_ops'] if scoped else []) + ['pg_catalog.bytea_ops'],
                    collations=[None] * (1 + len(tenant)), constraint_name=None)
                if index is None or {k: v for k, v in index.items() if k != 'definition_digest'} != expected_index:
                    raise ValueError
                observed['indexes'].remove(index)
                validate_search_storage(c, model, field, admitted=expression)
            else:
                validate_frame_storage(c, model, field, admitted=expression)
        except ValueError:
            raise TransitionFailure(failure, p.operation_id) from None
    if _metadata_diff(expected, observed):
        raise TransitionFailure(failure, p.operation_id)
    if paused:
        return _check_guard(c, p, model)


def _active_schema(c,p,state):
    from cryptalis import _access_contract as access
    access.check(c, p)
    for model in p.document['lock']['models']:
        facts = _facts(c, model)
        if facts!=state['models'][model['table_id']]['active_schema']:
            raise TransitionFailure('active_schema_mismatch',p.operation_id)
        _protected_contract(c, p, model, facts, paused=state['phase'] == 'PENDING')


def _verify_online_target(c,p,keys):
    digests = _verify_values(c,p,keys,active=True)
    for model in p.document['lock']['models']:
        expected = p.document['online_verification'][model['table_id']]
        if (_scope(c,model) != {'count': expected['rows'], 'membership': expected['membership']}
                or digests[model['table_id']] != expected['frames']):
            raise TransitionFailure('online_activation_target_changed', p.operation_id)


def _activate(c,p,state,pin,keys):
    if pin.phase!='ACTIVATING': raise TransitionFailure('matching_external_publication_required',p.operation_id)
    _lock_tables(c,p); _active_schema(c,p,state)
    if p.document['format'] == 'cryptalis.transition/v8':
        _verify_online_target(c,p,keys)
    if p.document['kind'] == 'rewrap':
        from cryptalis.rotation import _verify_rewrap_target
        _verify_rewrap_target(c, p, keys)
    elif p.document['kind'] in _GENERATION_ROTATIONS:
        from cryptalis._rotation_activation import verify_target
        verify_target(c, p, keys)
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
    _admit(p, pin)
    online = p.document['format'] == 'cryptalis.transition/v8'
    if online and (until != 'ACTIVE' or pin.phase not in ('ACTIVATING', 'ACTIVE')):
        raise TransitionFailure('online_executor_required', p.operation_id)
    if p.document['kind'] == 'rewrap' and (until != 'ACTIVE' or pin.phase not in ('ACTIVATING', 'ACTIVE')):
        raise TransitionFailure('rewrap_executor_required', p.operation_id)
    if p.document['kind'] in _GENERATION_ROTATIONS and (until != 'ACTIVE' or pin.phase not in ('ACTIVATING', 'ACTIVE')):
        raise TransitionFailure(p.document['kind']+'_executor_required', p.operation_id)
    with _executor(p,engine,pin,approval) as c:
        state=_state(c,p,pin); c.commit()
        if state is not None and state['phase'] == 'ACTIVE' and (online or p.document['kind'] in ('rewrap',)+_GENERATION_ROTATIONS) and pin.phase == 'ACTIVATING':
            # A journal phase cannot replace the host's publication evidence.
            with c.begin():
                _lock_tables(c,p,verification=True)
                _active_schema(c,p,state)
                if online:
                    _verify_online_target(c,p,keys)
                elif p.document['kind'] == 'rewrap':
                    from cryptalis.rotation import _verify_rewrap_target
                    _verify_rewrap_target(c,p,keys)
                else:
                    from cryptalis._rotation_activation import verify_target
                    verify_target(c,p,keys)
        if state is None:
            if online: raise TransitionFailure('missing_online_successor', p.operation_id)
            if p.document['kind'] in _GENERATION_ROTATIONS:
                raise TransitionFailure('missing_'+p.document['kind'].removesuffix('_rotation')+'_successor', p.operation_id)
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
                elif state['phase']=='PENDING': _activate(c,p,state,pin,keys)
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


def check_deployment(p,engine,*,pin,restore=None):
    """Read-only policy inspection; no maintenance approval or exclusive lock.

    The other read-only exemptions are plan and check_attachment. The latter
    inspects a supplied connection and does not acquire or own that connection.
    apply, verify and abort always require approval in their shared executor.

    ``restore`` is an adopted ``cryptalis.restore/v1`` binding for a restored
    copy of the planned target. It changes target and journal-state evidence
    checks only; the pin and the plan stay the source artifacts.
    """
    _admit(p,pin)
    with _connection(engine,p.operation_id) as c: _check_connection(p,c,pin,binding=restore)


def diagnose_deployment(p, engine, *, pin, restore=None):
    """Inspect active attachment admission in one read-only catalog snapshot.

    Use the declared runtime connection. This checks no provider, frame, query
    route, writer exclusion, host authority, or recovery/capacity guarantee.
    A successful return means only that current attachment metadata matches.
    """
    _admit(p, pin)
    if pin.phase != 'ACTIVE':
        raise TransitionFailure('external_policy_mismatch', p.operation_id)
    if restore is not None:
        from cryptalis.restore import _identity
        _identity(p, restore)
    with _connection(engine, p.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        check_attachment(c, p.lock_bytes, (p, pin, restore))


def status(p, engine, *, pin, restore=None):
    """Observe one committed journal/schema snapshot without keys or effects.

    The supplied external pin remains host authority. Recorded progress is not
    fresh cryptographic verification, provider qualification, or writer exclusion.
    """
    _admit(p, pin)
    target = p.document['target']
    if restore is not None:
        from cryptalis.restore import _identity
        target = _identity(p, restore)
    with _connection(engine, p.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        if _target(c)[:-1] != target[:-1]:
            raise TransitionFailure('wrong_database_target', p.operation_id)
        state = _state(c, p, pin, allow_aborted=True)
        phase = 'PREPARED' if state is None else state['phase']
        if restore is not None:
            if phase != 'ACTIVE':
                raise TransitionFailure('restored_state_not_active', p.operation_id)
            from cryptalis.restore import _current, _check_schema
            _current(p, restore, c, state)
            _check_schema(c, p, state, restore)
        elif phase in ('PREPARED', 'ABORTED'):
            for model in p.document['lock']['models']:
                if _facts(c, model) != model['source_schema']:
                    raise TransitionFailure('source_schema_changed', p.operation_id)
                _check_source_metadata(c, p, model)
        elif phase in ('PENDING', 'ACTIVE'):
            _runtime_safety(c, p.document['runtime_role'], target[-1], p.document['lock']['models'],
                            journal=_journal(c, p), operation_id=p.operation_id)
            _active_schema(c, p, state)
            if phase == 'PENDING':
                for model in p.document['lock']['models']:
                    if _guard_facts(c, p, model) != state['models'][model['table_id']]['guard']:
                        raise TransitionFailure('writer_fence_changed', p.operation_id)
        else:
            _inspect_paused(c, p, state)
        progress = Progress(p.operation_id, phase, 0, 0, '') if state is None else _progress(p, state)
        matched = phase == 'ACTIVE' and pin.phase == 'ACTIVE'
        remedy = ('Metadata matches the supplied active pin. Check keys and host writer policy before admission.'
                  if matched else 'Inspect this operation and the current external policy before resume.')
        if phase == 'PENDING' or (phase == 'ACTIVE' and not matched):
            remedy = 'Publish the exact current deployment pin; keep writers stopped.'
        elif phase == 'ABORTED':
            remedy = 'This operation was aborted. Compile a new plan before applying protection.'
        return TransitionStatus(p.operation_id, phase, pin.phase, progress.committed_rows,
                                progress.committed_chunks, matched, 'NOT_PERFORMED', remedy)


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


def _check_connection(p,c,pin,*,binding=None):
    _admit(p,pin)
    state=_state(c,p,pin)
    target=p.document['target']
    if binding is not None and state is not None:
        from cryptalis.restore import _current
        target=_current(p,binding,c,state)
    # Runtime identity differs; compare the non-principal target facts only.
    if _target(c)[:-1]!=target[:-1] or pin.phase!='ACTIVE' or state is None or state['phase']!='ACTIVE':
        raise TransitionFailure('deployment_not_current',p.operation_id)
    if binding is None:
        _runtime_safety(c, p.document['runtime_role'], target[-1], p.document['lock']['models'],
                        journal=_journal(c, p), operation_id=p.operation_id)
        _active_schema(c,p,state)
    else:
        from cryptalis.restore import _check_schema
        _check_schema(c,p,state,binding)


def check_attachment(c,lock,deployment):
    """Migration-owned tables require external-pin admission at startup.

    ``deployment`` is ``(plan, pin)`` or ``(plan, pin, restore_binding)``. The
    third element is an adopted ``cryptalis.restore/v1`` binding for a restored
    protected copy; ``None`` keeps the source-target check.
    """
    models=json.loads(lock)['models']
    found=any(c.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',(_quote(c,m['schema'])+'.'+_quote(c,JOURNAL),)).scalar_one() is not None for m in models)
    if not found:
        if deployment is not None: raise TransitionFailure('missing_transition')
        return
    if not isinstance(deployment,tuple) or len(deployment) not in (2,3): raise TransitionFailure('external_pin_required')
    p,pin=deployment[0],deployment[1]
    binding=deployment[2] if len(deployment)==3 else None
    if not isinstance(p,MigrationPlan) or p.lock_bytes!=lock: raise TransitionFailure('attachment_lock_mismatch')
    if c.exec_driver_sql('SELECT current_user').scalar_one()!=p.document['runtime_role']:
        raise TransitionFailure('attachment_requires_planned_runtime_role',p.operation_id)
    _check_connection(p,c,pin,binding=binding)
