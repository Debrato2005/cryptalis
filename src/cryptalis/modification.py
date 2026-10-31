"""Explicit search-profile changes through the shared encrypted transition engine.

Admitted changes enable or disable exact search on existing encrypted text.
It preserves custody and physical/value identities. The host approves leakage,
retains proposal/successor artifacts and publishes the successor separately.
"""
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
from hmac import compare_digest
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

from sqlalchemy import Column, Table
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import registry

from cryptalis import migration as m, rotation as r
from cryptalis.crypto.cf1 import FieldDescriptor, open_value, seal_value
from cryptalis.manifest import compiler as compiler
from cryptalis.manifest.declaration import parse_protection_declaration


FORMAT = 'cryptalis.modification/v1'
KIND = 'profile_rotation'
_DIALECT = SimpleNamespace(dialect=postgresql.dialect())


def _target_lock(source_lock, manifest, *, writers, search_reviews):
    declaration = parse_protection_declaration(manifest)
    issues = []
    host, reviews = compiler._host_evidence(declaration, writers, search_reviews, issues)
    if issues:
        raise compiler.PlanningRejected(issues)
    target = deepcopy(source_lock)
    desired = json.loads(declaration.canonical_bytes())
    expected = deepcopy(source_lock['declaration'])
    try:
        if host != source_lock['writer_inventory'] or len(desired['models']) != len(expected['models']):
            raise ValueError
        changed = 0
        removed_reviews = set()
        for old_model, new_model, compiled in zip(expected['models'], desired['models'], target['models'], strict=True):
            if len(old_model['fields']) != len(new_model['fields']):
                raise ValueError
            for old, new, field in zip(old_model['fields'], new_model['fields'], compiled['fields'], strict=True):
                if old == new:
                    continue
                orderable = compiler._orderable(field['source'])
                search = ['equality', 'order'] if orderable else ['equality']
                if ((old['queries'], new['queries']) not in (([], search), (search, [])) or
                        new['accept_leakage'] != new['queries'] or
                        not orderable and field['source']['type'] not in ('text', 'varchar', 'numeric')):
                    raise ValueError
                old.update(queries=new['queries'], accept_leakage=new['accept_leakage'])
                if old != new:
                    raise ValueError
                native = next(c for c in compiled['source_schema']['columns'] if c['name'] == field['column'])
                if new['queries'] and field['source']['type'] in ('text', 'varchar') and not compiler._exact_search_collation(native):
                    raise ValueError
                if not new['queries']:
                    removed_reviews.add(field['field_id'])
                field.update(queries=new['queries'], representation=compiler._representation(new['queries']))
                descriptor = field['descriptor']
                field['descriptor'] = compiler._descriptor(descriptor['domain_id'], descriptor['table_id'],
                    descriptor['field_id'], descriptor['record_codec'], descriptor['tenant_codec'],
                    field['representation'], descriptor.get('value_codec', descriptor.get('text_codec')))
                field['descriptor_digest'] = compiler._digest(field['descriptor'])
                changed += 1
        if not changed or expected != desired:
            raise ValueError
        retained = {review['field_id']: review for review in reviews}
        if any(retained.get(review['field_id']) != review for review in source_lock['search_reviews']
               if review['field_id'] not in removed_reviews):
            raise ValueError
        target.update(declaration=desired, writer_inventory=host, search_reviews=reviews)
        target['schema'] = compiler._lock_schema(target['models'], target.get('layout'),
                                                legacy=source_lock['schema'] == 'cryptalis.lock/v1')
        target['ddl'] = compiler._ddl(target, _DIALECT)
        target['required_readers'] = compiler._required_readers(target['models'])
        compiler._previous_lock(m._canonical(target), target, _DIALECT)
    except (KeyError, TypeError, ValueError, StopIteration):
        raise m.TransitionFailure('unsupported_manifest_modification') from None
    return target


def _validate_target(source_lock, target):
    """Re-derive every admitted target byte when reading a retained artifact."""
    inventory = target['writer_inventory']
    writers = compiler.WriterInventory(inventory['complete'], tuple(compiler.Writer(
        UUID(item['table_id']), item['name'], item['route'], item['excluded'], item['evidence'])
        for item in inventory['writers']))
    reviews = tuple(compiler.SearchReview(UUID(item['field_id']), item['small_domain'], item['evidence'])
                    for item in target['search_reviews'])
    expected = _target_lock(source_lock, m._canonical(target['declaration']),
                            writers=writers, search_reviews=reviews)
    if m._canonical(expected) != m._canonical(target):
        raise ValueError


def _mapping(lock, mapping):
    if not isinstance(mapping, registry):
        raise m.TransitionFailure('modification_mapping_mismatch')
    try:
        for declaration, model in zip(lock['declaration']['models'], lock['models'], strict=True):
            matches = [mapper for mapper in mapping.mappers if mapper.class_.__name__ == model['model']]
            if len(matches) != 1:
                raise ValueError
            mapper = matches[0]
            table = mapper.local_table
            if (not isinstance(table, Table) or mapper.inherits is not None or mapper.persist_selectable is not table
                    or (table.schema, table.name) != (model['schema'], model['table']) or len(mapper.primary_key) != 1):
                raise ValueError
            facts = {column['name']: column for column in model['source_schema']['columns']}
            record = mapper.primary_key[0]
            if (record.table is not table or record.name != model['record']['column'] or
                    list(table.primary_key.columns) != [record] or record.nullable or
                    compiler._id_codec(record, facts[record.name]) != model['record']['codec'] or
                    compiler._server_generation(record, facts[record.name]) or record.onupdate is not None):
                raise ValueError
            if 'column' in model['tenancy']:
                prop = mapper.column_attrs[declaration['tenancy']['column']]
                if len(prop.columns) != 1 or not isinstance(prop.columns[0], Column):
                    raise ValueError
                tenant = prop.columns[0]
                if (tenant.table is not table or tenant.name != model['tenancy']['column'] or tenant.nullable or
                        compiler._id_codec(tenant, facts[tenant.name]) != 'uuid16/v1' or
                        compiler._server_generation(tenant, facts[tenant.name]) or tenant.onupdate is not None):
                    raise ValueError
            for field in model['fields']:
                prop = mapper.column_attrs[field['name']]
                if len(prop.columns) != 1 or not isinstance(prop.columns[0], Column):
                    raise ValueError
                column = prop.columns[0]
                if (column.table is not table or column.name != field['column'] or
                        column.nullable != field['source']['nullable'] or
                        not compiler._value_mapping_matches(column, facts[column.name]) or
                        compiler._server_generation(column, facts[column.name]) or column.onupdate is not None or
                        not compiler._default_matches(compiler._value_default(column,
                            compiler._value_codec(field['source'])), field)):
                    raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise m.TransitionFailure('modification_mapping_mismatch') from None


def same_roots(source, target):
    if source.policy != target.policy:
        raise m.TransitionFailure('profile_key_policy_changed')
    for wrapper in source.policy.wrappers:
        context = wrapper.context
        old = source._resolve(context.domain_id, context.tenant_id, context.purpose, context.generation)
        new = target._resolve(context.domain_id, context.tenant_id, context.purpose, context.generation)
        if old.context != new.context or not compare_digest(old.root, new.root):
            raise m.TransitionFailure('profile_key_policy_changed')


def transform_value(frame, field, target_field, tenant, record, source, target):
    old = FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest'])
    value = open_value(frame, old, tenant, record, source)
    if field['descriptor'] == target_field['descriptor']:
        return frame
    new = FieldDescriptor.from_compiled(target_field['descriptor'], target_field['descriptor_digest'])
    return seal_value(value, new, tenant, record, target)


def prepare_keys(source, target_lock, keys, target_keys):
    policies, prepared = {}, {}
    searchable = [model for model in target_lock['models'] if any(field['queries'] for field in model['fields'])]
    for tenant in source.document['key_policies']:
        identity = UUID(tenant)
        old = m._ring(keys, identity, source)
        new = m._ring(target_keys, identity, source)
        pair = old.prepare(), new.prepare()
        same_roots(*pair)
        if (any('column' in model['tenancy'] or model['table_id'] == tenant for model in searchable)
                and old.policy.search_generation is None):
            raise m.TransitionFailure('profile_requires_approved_search_root', source.operation_id)
        prepared[identity] = pair
        policies[tenant] = dict(source=m._policy(old), target=m._policy(new),
            source_contexts=r._contexts(old.policy), target_contexts=r._contexts(new.policy),
            payload_generation=old.policy.payload_generation, search_generation=old.policy.search_generation)
    return policies, prepared


@dataclass(frozen=True, repr=False)
class ModificationPlan:
    artifact: bytes
    purpose = 'profile'

    def __post_init__(self):
        try:
            sizes = ('frame_bytes', 'target_frame_bytes', 'logical_bytes', 'largest_row_logical_bytes')
            document, source, _ = r._read_proposal(self.artifact, FORMAT, KIND,
                extra=('successor_operation_id', 'batch_limits', 'target_lock'), sizes=sizes)
            if source.document.get('restore_lineage'):
                raise ValueError
            _validate_target(source.document['lock'], document['target_lock'])
            identities = {source.operation_id, r._uuid(document['operation_id'])} | {
                UUID(item['operation_id']) for item in source.document.get('predecessors', [])}
            if (len(identities) != len(source.document.get('predecessors', [])) + 2 or
                    r._uuid(document['successor_operation_id']) in identities):
                raise ValueError
            for tenant, policy in document['key_policies'].items():
                if set(policy) != {'source', 'target', 'source_contexts', 'target_contexts',
                                   'payload_generation', 'search_generation'}:
                    raise ValueError
                if (policy['source'] != source.document['key_policies'][tenant] or
                        policy['target'] != policy['source'] or policy['source_contexts'] != policy['target_contexts']):
                    raise ValueError
                contexts = r._read_contexts(policy['source_contexts'], UUID(source.document['lock']['domain_id']), UUID(tenant))
                generations = {(context.purpose, context.generation) for context in contexts}
                for purpose in ('payload', 'search'):
                    generation = policy[purpose + '_generation']
                    if purpose == 'search' and generation is None:
                        if any(any(field['queries'] for field in model['fields']) and
                               ('column' in model['tenancy'] or model['table_id'] == tenant)
                               for model in document['target_lock']['models']):
                            raise ValueError
                        continue
                    if type(generation) is not int or (purpose, generation) not in generations:
                        raise ValueError
            costs, limits = document['estimates'], document['batch_limits']
            for name, value in costs.items():
                if name not in ('backfill_rows_per_second', 'verify_rows_per_second', 'limits'):
                    r._counter(value)
            r._payload_inputs(costs['backfill_rows_per_second'], costs['verify_rows_per_second'],
                costs['temporary_bytes_per_row'], costs['wal_bytes_per_row'], limits)
            for old_model, target_model in zip(source.document['lock']['models'], document['target_lock']['models'], strict=True):
                observed = document['models'][old_model['table_id']]
                rows, total, largest = observed['rows'], observed['logical_bytes'], observed['largest_row_logical_bytes']
                growth = [r._frame_growth(old, new) for old, new in zip(old_model['fields'], target_model['fields'], strict=True)]
                minimum = max(0, observed['frame_bytes'] + rows * sum(min(0, size) for size in growth))
                maximum = observed['frame_bytes'] + rows * sum(max(0, size) for size in growth)
                if (largest > limits['max_bytes'] or (not rows and any(observed[key] for key in sizes)) or
                        (rows and not 0 < largest <= total <= rows * largest) or
                        observed['frame_bytes'] > total or
                        not minimum <= observed['target_frame_bytes'] <= min(maximum, total)):
                    raise ValueError
            if costs != r._payload_estimates(document['models'], document['key_policies'],
                    costs['backfill_rows_per_second'], costs['verify_rows_per_second'],
                    costs['temporary_bytes_per_row'], costs['wal_bytes_per_row']):
                raise ValueError
        except Exception:
            raise m.TransitionFailure('invalid_modification_plan') from None

    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def operation_id(self): return UUID(self.document['operation_id'])
    @property
    def source(self): return m.MigrationPlan(m._canonical(self.document['source_plan']))
    @property
    def restore_binding(self): return None

    def __repr__(self):
        return 'Inactive encrypted profile change; retain, verify and publish the exact successor separately.'


def plan(source, engine, *, source_pin, manifest, mapping, writers, search_reviews, keys,
         backfill_rows_per_second, verify_rows_per_second, temporary_bytes_per_row, wal_bytes_per_row,
         max_batch_rows=1000, max_batch_bytes=64 * 1024 * 1024, queries=()):
    m._admit(source, source_pin)
    if source_pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    if source.document.get('restore_lineage'):
        raise m.TransitionFailure('restored_modification_not_admitted', source.operation_id)
    if type(queries) is not tuple or len(queries) > 128:
        raise m.TransitionFailure('invalid_query_samples', source.operation_id)
    target = _target_lock(source.document['lock'], manifest, writers=writers, search_reviews=search_reviews)
    _mapping(target, mapping)
    if queries:
        from cryptalis.doctor import _query_samples
        candidate = compiler.ProtectionPlan(m._canonical(target), ())
        report = {'status': 'UNKNOWN', 'checks': {'query_routes': 'UNKNOWN'}, 'issues': []}
        _query_samples(report, candidate, mapping, engine, queries)
        outcome = report['checks']['query_samples']
        if outcome != 'PASS':
            raise m.TransitionFailure('query_samples_incompatible' if outcome == 'FAIL'
                                      else 'query_inspection_unavailable', source.operation_id)
    limits = dict(max_rows=max_batch_rows, max_bytes=max_batch_bytes)
    r._payload_inputs(backfill_rows_per_second, verify_rows_per_second,
                      temporary_bytes_per_row, wal_bytes_per_row, limits)
    try:
        with m._connection(engine, source.operation_id) as connection:
            connection.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            m._check_connection(source, connection, source_pin)
            from cryptalis.deprotection import _inventory
            _inventory(connection, source, source, own=None)
            state = m._state(connection, source, source_pin)
            for old_model, new_model in zip(source.document['lock']['models'], target['models'], strict=True):
                for old, new in zip(old_model['fields'], new_model['fields'], strict=True):
                    if old['descriptor'] == new['descriptor'] or not new['queries']:
                        continue
                    collision = connection.exec_driver_sql('SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c '
                        'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace '
                        'WHERE n.nspname=%s AND c.relname=%s)',
                        (new_model['schema'], new['payload_column'] + '_eq')).scalar_one()
                    if collision:
                        raise m.TransitionFailure('generated_name_collision', source.operation_id)
            policies, prepared = prepare_keys(source, target, keys, keys)
            models = r._observe_active(connection, source, keys,
                prepared={tenant: pair[0] for tenant, pair in prepared.items()},
                peers={tenant: pair[1] for tenant, pair in prepared.items()}, batch_limits=limits,
                target_models=target['models'])
            for model in source.document['lock']['models']:
                models[model['table_id']]['schema'] = m._hash(m._facts(connection, model))
        pin = asdict(source_pin)
        pin.update(target_id=str(source_pin.target_id), operation_id=str(source_pin.operation_id))
        proposal = ModificationPlan(m._canonical(dict(format=FORMAT, kind=KIND,
            operation_id=str(uuid4()), successor_operation_id=str(uuid4()), source_plan=source.document,
            source_pin=pin, required_readers=source.document['lock']['required_readers'],
            journal_state_digest=m._hash(state), models=models, key_policies=policies,
            target_lock=target, batch_limits=limits, estimates=r._payload_estimates(models, policies,
                backfill_rows_per_second, verify_rows_per_second, temporary_bytes_per_row, wal_bytes_per_row))))
        for pair in prepared.values(): same_roots(*pair)
        return proposal
    except Exception as failure:
        raise m._safe_failure(failure, source.operation_id, ()) from None


def validate_activation(document, artifact):
    if document.get('format') not in ('cryptalis.transition/v17', 'cryptalis.transition/v18') or document.get('kind') != KIND:
        raise ValueError
    source_lock = document['profile_source_lock']
    compiler._previous_lock(m._canonical(source_lock), source_lock, _DIALECT)
    _validate_target(source_lock, document['lock'])
    if (document['source_lock_digest'] != m._hash(source_lock) or
            (document['format'] == 'cryptalis.transition/v18') != ('access_contract' in document)):
        raise ValueError
    # Reuse the strict common staged-activation validator. This temporary value
    # is never returned, persisted, published or passed to an executor.
    base = dict(document)
    base.pop('profile_source_lock')
    base.update(format='cryptalis.transition/v11' if 'access_contract' in document else 'cryptalis.transition/v4',
                kind='search_rotation', search_rotation_plan_digest=base.pop('profile_rotation_plan_digest'),
                search_rotation_observations=base.pop('profile_rotation_observations'),
                search_batch_limits=base.pop('profile_batch_limits'))
    m.MigrationPlan(m._canonical(base))
    if m._canonical(document) != artifact:
        raise ValueError


def activation(proposal, observations, copy, copy_wal):
    from cryptalis._rotation_activation import _BASE, _costs
    source = proposal.source
    original = source.document
    document = {key: original[key] for key in _BASE}
    document.update(format='cryptalis.transition/v17', kind=KIND,
        operation_id=proposal.document['successor_operation_id'],
        lock=proposal.document['target_lock'], source_lock_digest=m._hash(original['lock']),
        profile_source_lock=original['lock'],
        predecessors=original.get('predecessors', []) + [
            {'operation_id': str(source.operation_id), 'plan_digest': source.digest},
            {'operation_id': str(proposal.operation_id), 'plan_digest': proposal.digest}],
        key_policies={tenant: item['target'] for tenant, item in proposal.document['key_policies'].items()},
        scopes=[{'table_id': model['table_id'], 'estimated_rows': observations[model['table_id']]['rows']}
                for model in original['lock']['models']], estimates=_costs(proposal, copy, copy_wal),
        profile_rotation_plan_digest=proposal.digest, profile_rotation_observations=observations,
        profile_batch_limits=proposal.document['batch_limits'])
    from cryptalis import _access_contract as access
    access.carry(source, document)
    return m.MigrationPlan(m._canonical(document))


def replace_storage_contract(connection, proposal, successor, *, before_copy):
    """Change only verified owned checks/indexes in the atomic cutover transaction."""
    for old_model, model in zip(proposal.source.document['lock']['models'], successor.document['lock']['models'], strict=True):
        table = m._table(connection, model)
        for old, field in zip(old_model['fields'], model['fields'], strict=True):
            if old['descriptor'] == field['descriptor']:
                continue
            constraint = m._quote(connection, field['payload_column'] + '_frame')
            if before_copy:
                connection.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {constraint}')
                if old['queries']:
                    index = m._quote(connection, model['schema']) + '.' + m._quote(connection, old['payload_column'] + '_eq')
                    connection.exec_driver_sql(f'DROP INDEX {index}')
                continue
            public = {**field, 'payload_column': field['column']}
            connection.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {constraint} '
                                      f'CHECK ({m._frame_check(connection, public)})')
            if not field['queries']:
                continue
            tenant = m._quote(connection, model['tenancy']['column']) + ', ' if 'column' in model['tenancy'] else ''
            index = m._quote(connection, field['payload_column'] + '_eq')
            column = m._quote(connection, field['column'])
            connection.exec_driver_sql(f'CREATE INDEX {index} ON {table} USING btree '
                                      f'({tenant}(pg_catalog.substring({column},15,32)) pg_catalog.bytea_ops)')
