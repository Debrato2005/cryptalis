"""Add one empty tenant through the existing maintenance/publication lifecycle.

The host authenticates approval and retains custody and the exact successor
outside PostgreSQL. Existing data, capabilities and policies stay unchanged.
This is an O(N), writer-paused operation, not online signup provisioning.
"""
from dataclasses import dataclass
import hashlib
import json
from uuid import UUID, uuid4

from cryptalis import migration as m, rotation as r
from cryptalis.crypto.keys import Keyring

FORMAT = 'cryptalis.tenant-provision/v1'
KIND = 'tenant_provision'
PROOF = KIND + '_plan_digest'
OBSERVATIONS = KIND + '_observations'
MAX_TENANTS = 1024


def _identity(source, tenant):
    if type(tenant) is not UUID:
        raise m.TransitionFailure('typed_tenant_uuid_required', source.operation_id)
    models = source.document['lock']['models']
    fixed = {model['table_id'] for model in models if 'column' not in model['tenancy']}
    policies = source.document['key_policies']
    if (source.document.get('access_contract') is None
            or not any('column' in model['tenancy'] for model in models)):
        raise m.TransitionFailure('tenant_provision_requires_scoped_access_contract', source.operation_id)
    if str(tenant) in policies or str(tenant) in fixed:
        raise m.TransitionFailure('tenant_policy_already_declared', source.operation_id)
    if len(set(policies) - fixed) >= MAX_TENANTS:
        raise m.TransitionFailure('tenant_policy_limit', source.operation_id)


def _empty(c, source, tenant):
    for model in source.document['lock']['models']:
        if 'column' in model['tenancy']:
            found = c.exec_driver_sql(f'SELECT 1 FROM {m._table(c, model)} WHERE '
                f'{m._quote(c, model["tenancy"]["column"])}=%s LIMIT 1', (tenant,)).first()
            if found is not None:
                raise m.TransitionFailure('tenant_scope_not_empty', source.operation_id)


def _validate_activation(document, artifact):
    """Reuse strict common transition validation, then validate additive authority."""
    if (document.get('kind') != KIND or document.get('format') not in (
            'cryptalis.transition/v15', 'cryptalis.transition/v16')):
        raise ValueError
    item = document['tenant_provision']
    if type(item) is not dict or set(item) != {'tenant_id', 'policy_digest', 'source_policy_digest'}:
        raise ValueError
    tenant = r._uuid(item['tenant_id'], nonzero=False)
    for name in ('policy_digest', 'source_policy_digest'):
        r._digest(item[name])
    policies = document['key_policies']
    for identity, digest in policies.items():
        r._uuid(identity, nonzero=False)
        r._digest(digest)
    fixed = {model['table_id'] for model in document['lock']['models'] if 'column' not in model['tenancy']}
    if (str(tenant) in fixed or policies.get(str(tenant)) != item['policy_digest']
            or len(set(policies) - fixed) > MAX_TENANTS
            or not any('column' in model['tenancy'] for model in document['lock']['models'])
            or m._hash({key: value for key, value in policies.items() if key != str(tenant)})
                != item['source_policy_digest']):
        raise ValueError
    base = dict(document)
    for name in ('tenant_provision', PROOF, OBSERVATIONS):
        base.pop(name)
    base.update(format='cryptalis.transition/v12' if document['format'].endswith('/v16')
        else 'cryptalis.transition/v9', kind='rewrap', rewrap_plan_digest=document[PROOF],
        rewrap_observations=document[OBSERVATIONS])
    m.MigrationPlan(m._canonical(base))
    observed = document[OBSERVATIONS]
    if document['scopes'] != [{'table_id': model['table_id'],
            'estimated_rows': observed[model['table_id']]['rows']} for model in document['lock']['models']]:
        raise ValueError
    if m._canonical(document) != artifact:
        raise ValueError


@dataclass(frozen=True, repr=False)
class TenantProvisionPlan:
    artifact: bytes

    def __post_init__(self):
        try:
            d, source, rows = r._read_proposal(self.artifact, FORMAT, KIND,
                extra=('tenant_policy', 'restore'))
            item = d['tenant_policy']
            if type(item) is not dict or set(item) != {
                    'tenant_id', 'policy_digest', 'contexts', 'payload_generation', 'search_generation'}:
                raise ValueError
            tenant = r._uuid(item['tenant_id'], nonzero=False)
            _identity(source, tenant)
            r._digest(item['policy_digest'])
            contexts = r._read_contexts(item['contexts'], UUID(source.document['lock']['domain_id']), tenant)
            identities = {(context.purpose, context.generation) for context in contexts}
            for purpose in ('payload', 'search'):
                generation = item[purpose + '_generation']
                if purpose == 'search' and generation is None:
                    continue
                if type(generation) is not int or (purpose, generation) not in identities:
                    raise ValueError
            if any('column' in model['tenancy'] and any(field['queries'] for field in model['fields'])
                    for model in source.document['lock']['models']) and item['search_generation'] is None:
                raise ValueError
            if d['key_policies'] != source.document['key_policies']:
                raise ValueError
            costs = d['estimates']
            if (set(costs) != {'rows', 'verify_rows_per_second', 'verify_seconds_estimate', 'limits'}
                    or costs['rows'] != rows or not m._finite_number(costs['verify_rows_per_second'])
                    or costs['verify_rows_per_second'] <= 0
                    or costs['verify_seconds_estimate'] != m._estimate_seconds(rows, costs['verify_rows_per_second'])
                    or type(costs['limits']) is not str or not costs['limits']):
                raise ValueError
            binding = self.restore_binding
            if binding is not None:
                from cryptalis.restore import _identity as restore_identity
                restore_identity(source, binding)
                if (binding.target[-1] != source.document['target'][-1]
                        or d['journal_state_digest'] != binding.document['journal_state_digest']):
                    raise ValueError
        except Exception:
            raise m.TransitionFailure('invalid_tenant_provision_plan') from None

    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def operation_id(self): return UUID(self.document['operation_id'])
    @property
    def source(self): return m.MigrationPlan(m._canonical(self.document['source_plan']))
    @property
    def restore_binding(self):
        if self.document['restore'] is None:
            return None
        from cryptalis.restore import RestoreBinding
        return RestoreBinding(m._canonical(self.document['restore']))
    @property
    def activation_plan(self):
        d, source = self.document, self.source
        document = source.document
        lineage = document.get('restore_lineage', [])
        if d['restore'] is not None:
            lineage.append(d['restore'])
            document['target'] = d['restore']['target']
        for name in ('online_preparation', 'online_verification', 'rewrap_plan_digest', 'rewrap_observations',
                'payload_rotation_plan_digest', 'payload_rotation_observations', 'payload_batch_limits',
                'search_rotation_plan_digest', 'search_rotation_observations', 'search_batch_limits',
                'profile_rotation_plan_digest', 'profile_rotation_observations', 'profile_batch_limits', 'profile_source_lock'):
            document.pop(name, None)
        if lineage:
            document['restore_lineage'] = lineage
        item = d['tenant_policy']
        document.update(format='cryptalis.transition/v16' if lineage else 'cryptalis.transition/v15', kind=KIND,
            operation_id=str(self.operation_id), predecessors=document.get('predecessors', []) + [
                {'operation_id': str(source.operation_id), 'plan_digest': source.digest}],
            key_policies={**source.document['key_policies'], item['tenant_id']: item['policy_digest']},
            tenant_provision={'tenant_id': item['tenant_id'], 'policy_digest': item['policy_digest'],
                'source_policy_digest': m._hash(source.document['key_policies'])},
            scopes=[{'table_id': model['table_id'], 'estimated_rows': d['models'][model['table_id']]['rows']}
                for model in document['lock']['models']],
            estimates={'rows': d['estimates']['rows'],
                'writer_pause_seconds_estimate': d['estimates']['verify_seconds_estimate'],
                'limits': d['estimates']['limits']}, **{PROOF: self.digest,
                OBSERVATIONS: {table: {key: value for key, value in item.items() if key != 'schema'}
                    for table, item in d['models'].items()}})
        return m.MigrationPlan(m._canonical(document))

    def __str__(self):
        return ('Inactive maintenance tenant policy proposal; global writer pause and O(N) frame verification. '
            'Persist and publish the exact successor separately; provider, locks and DDL costs are unqualified.')
    __repr__ = __str__


def plan(source, engine, *, source_pin, keys, tenant_id, key_policy, verify_rows_per_second, restore=None):
    """Inspect one explicitly host-approved empty tenant without database effects."""
    m._admit(source, source_pin)
    if source_pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    _identity(source, tenant_id)
    if (not isinstance(key_policy, Keyring) or key_policy.policy.tenant_id != tenant_id
            or str(key_policy.policy.domain_id) != source.document['lock']['domain_id']):
        raise m.TransitionFailure('tenant_policy_context_mismatch', source.operation_id)
    if not m._finite_number(verify_rows_per_second) or verify_rows_per_second <= 0:
        raise m.TransitionFailure('missing_measured_rates', source.operation_id)
    try:
        with m._connection(engine, source.operation_id) as c:
            c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            m._check_connection(source, c, source_pin, binding=restore)
            from cryptalis.deprotection import _inventory
            _inventory(c, source, source, own=None)
            state = m._state(c, source, source_pin)
            _empty(c, source, tenant_id)
            observed = r._observe_active(c, source, keys)
            key_policy.prepare()
            models = {model['table_id']: dict(observed[model['table_id']], schema=m._hash(m._facts(c, model)))
                for model in source.document['lock']['models']}
        rows = sum(item['rows'] for item in observed.values())
        return TenantProvisionPlan(m._canonical(dict(format=FORMAT, kind=KIND, operation_id=str(uuid4()),
            source_plan=source.document, source_pin={'target_id': str(source_pin.target_id),
                'operation_id': str(source_pin.operation_id), 'plan_digest': source_pin.plan_digest, 'phase': 'ACTIVE'},
            required_readers=source.document['lock']['required_readers'], journal_state_digest=m._hash(state),
            models=models, key_policies=source.document['key_policies'], restore=restore.document if restore else None,
            tenant_policy=dict(tenant_id=str(tenant_id), policy_digest=m._policy(key_policy),
                contexts=r._contexts(key_policy.policy), payload_generation=key_policy.policy.payload_generation,
                search_generation=key_policy.policy.search_generation),
            estimates=dict(rows=rows, verify_rows_per_second=verify_rows_per_second,
                verify_seconds_estimate=m._estimate_seconds(rows, verify_rows_per_second),
                limits='O(N) frame verification and a global writer pause. Provider, locks, DDL and publication '
                    'costs are excluded; no online signup throughput qualification.'))))
    except Exception as exc:
        raise m._safe_failure(exc, source.operation_id, ()) from None


def verify_target(c, successor, keys):
    """Verify the host-pinned unchanged frames and still-empty added scope."""
    tenant = UUID(successor.document['tenant_provision']['tenant_id'])
    _empty(c, successor, tenant)
    if r._observe_active(c, successor, keys) != successor.document[OBSERVATIONS]:
        raise m.TransitionFailure('tenant_provision_source_changed', successor.operation_id)


def apply(proposal, engine, *, keys, pin, approval):
    """Atomically fence writers and retain the exact successor as PENDING."""
    if type(proposal) is not TenantProvisionPlan:
        raise m.TransitionFailure('invalid_tenant_provision_plan')
    source, successor = proposal.source, proposal.activation_plan
    if type(pin) is not m.DeploymentPin or pin.phase not in ('PREPARED', 'PENDING'):
        raise m.TransitionFailure('tenant_provision_prepublication_pin_required', proposal.operation_id)
    with m._executor(successor, engine, pin, approval) as c:
        with c.begin():
            m._lock_tables(c, successor, verification=True)
            row = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c, successor)} '
                'WHERE operation_id=%s', (successor.operation_id,)).one_or_none()
            if row is not None:
                state = m._state(c, successor, pin)
                m._active_schema(c, successor, state)
            else:
                if pin.phase != 'PREPARED':
                    raise m.TransitionFailure('missing_tenant_provision_operation', proposal.operation_id)
                m._check_connection(source, c, m.DeploymentPin(source.target_id, source.operation_id,
                    source.digest, 'ACTIVE'), binding=proposal.restore_binding)
                from cryptalis.deprotection import _inventory
                _inventory(c, source, source, own=None)
                source_state = m._state(c, source, m.DeploymentPin(source.target_id, source.operation_id,
                    source.digest, 'ACTIVE'))
                if m._hash(source_state) != proposal.document['journal_state_digest'] or any(
                        m._hash(m._facts(c, model)) != proposal.document['models'][model['table_id']]['schema']
                        for model in source.document['lock']['models']):
                    raise m.TransitionFailure('tenant_provision_source_changed', proposal.operation_id)
            verify_target(c, successor, keys)
            if row is None:
                m._lock_tables(c, successor)
                m._install_guards(c, successor)
                models = {model['table_id']: dict(rows=successor.document[OBSERVATIONS][model['table_id']]['rows'],
                    chunks=0, scope={'count': successor.document[OBSERVATIONS][model['table_id']]['rows'],
                        'membership': successor.document[OBSERVATIONS][model['table_id']]['membership']},
                    active_schema=m._facts(c, model), guard=m._check_guard(c, successor, model))
                    for model in successor.document['lock']['models']}
                state = {'phase': 'PENDING', 'models': models, PROOF: proposal.digest}
                source_state.update(phase='SUPERSEDED', superseded_by={
                    'operation_id': str(successor.operation_id), 'plan_digest': successor.digest})
                m._save(c, source, source_state)
                c.exec_driver_sql(f'INSERT INTO {m._journal(c, successor)} VALUES (%s,%s,%s::jsonb)',
                    (successor.operation_id, successor.digest, json.dumps(state)))
                m._active_schema(c, successor, state)
        return m._progress(successor, state)


def abort(proposal, engine, *, keys, pin, approval):
    """Cancel only a PENDING addition under the republished source ACTIVE pin."""
    if type(proposal) is not TenantProvisionPlan:
        raise m.TransitionFailure('invalid_tenant_provision_plan')
    source, successor = proposal.source, proposal.activation_plan
    m._admit(source, pin)
    if pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    expected = {'operation_id': str(source.operation_id), 'plan_digest': source.digest}
    pending = m.DeploymentPin(successor.target_id, successor.operation_id, successor.digest, 'PREPARED')
    with m._executor(successor, engine, pending, approval) as c:
        with c.begin():
            m._lock_tables(c, successor, verification=True)
            row = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c, successor)} WHERE operation_id=%s',
                (successor.operation_id,)).one_or_none()
            original = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c, source)} WHERE operation_id=%s',
                (source.operation_id,)).one_or_none()
            if row is None or row[0] != successor.digest or original is None or original[0] != source.digest:
                raise m.TransitionFailure('journal_identity_mismatch', successor.operation_id)
            state, source_state = row[1], original[1]
            if type(state) is not dict or type(source_state) is not dict or state.get(PROOF) != proposal.digest:
                raise m.TransitionFailure('tenant_provision_state_changed', successor.operation_id)
            from cryptalis.deprotection import _inventory
            if state.get('phase') == 'ABORTED':
                if (state.get('aborted_to') != expected
                        or m._hash(source_state) != proposal.document['journal_state_digest']):
                    raise m.TransitionFailure('tenant_provision_abort_source_changed', successor.operation_id)
                m._check_connection(source, c, pin, binding=proposal.restore_binding)
                _inventory(c, source, source, own=successor.operation_id)
            else:
                if state.get('phase') != 'PENDING':
                    raise m.TransitionFailure('tenant_provision_abort_requires_pending', successor.operation_id)
                m._state(c, successor, pending)
                m._active_schema(c, successor, state)
                for model in successor.document['lock']['models']:
                    if m._check_guard(c, successor, model) != state['models'][model['table_id']]['guard']:
                        raise m.TransitionFailure('writer_fence_changed', successor.operation_id)
                restored = dict(source_state, phase='ACTIVE')
                restored.pop('superseded_by', None)
                if m._hash(restored) != proposal.document['journal_state_digest']:
                    raise m.TransitionFailure('tenant_provision_abort_source_changed', successor.operation_id)
                _empty(c, successor, UUID(successor.document['tenant_provision']['tenant_id']))
                if r._observe_active(c, source, keys) != successor.document[OBSERVATIONS]:
                    raise m.TransitionFailure('tenant_provision_source_changed', successor.operation_id)
                m._save(c, source, restored)
                _inventory(c, source, source, own=successor.operation_id)
                m._lock_tables(c, successor)
                m._drop_guards(c, successor)
                if any(m._hash(m._facts(c, model)) != proposal.document['models'][model['table_id']]['schema']
                        for model in source.document['lock']['models']):
                    raise m.TransitionFailure('tenant_provision_abort_schema_changed', successor.operation_id)
                m._check_connection(source, c, pin, binding=proposal.restore_binding)
                state.update(phase='ABORTED', aborted_to=expected)
                m._save(c, successor, state)
        return m.Progress(successor.operation_id, 'ABORTED', 0, 0,
            'Source authority restored; inspect current host policy before reopening writers.')
