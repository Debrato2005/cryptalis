"""Root-rewrap planning and maintenance cutover through the existing lifecycle.

The host retains both wrapped policies outside the database. This artifact
records their identities, not their wrapped bytes or unwrapped roots. Native
The host publishes the successor plan separately from the database cutover.
"""
from dataclasses import asdict, dataclass
import hashlib
from hmac import compare_digest
import json
from uuid import UUID, uuid4

from cryptalis import migration as m
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.crypto.keys import KeyContext, Keyring, KeyUnavailable


FORMAT = 'cryptalis.rewrap/v1'


def _uuid(value, *, nonzero=True):
    identity = UUID(value)
    if str(identity) != value or nonzero and not identity.int:
        raise ValueError
    return identity


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError


def _counter(value):
    if type(value) is not int or not 0 <= value < 2**53:
        raise ValueError


def _contexts(policy):
    return [dict(domain_id=str(w.context.domain_id), tenant_id=str(w.context.tenant_id),
                 purpose=w.context.purpose, root_id=str(w.context.root_id),
                 generation=w.context.generation) for w in policy.wrappers]


@dataclass(frozen=True, repr=False)
class RewrapPlan:
    artifact: bytes

    def __post_init__(self):
        try:
            d = m._decode_transition_json(self.artifact)
            if (set(d) != {'format', 'kind', 'operation_id', 'source_plan', 'source_pin',
                           'required_readers', 'journal_state_digest', 'models', 'key_policies', 'estimates'}
                    or d['format'] != FORMAT or d['kind'] != 'rewrap'
                    or m._canonical(d) != self.artifact):
                raise ValueError
            source = m.MigrationPlan(m._canonical(d['source_plan']))
            if _uuid(d['operation_id']) == source.operation_id:
                raise ValueError
            pin = d['source_pin']
            if set(pin) != {'target_id', 'operation_id', 'plan_digest', 'phase'}:
                raise ValueError
            m._admit(source, m.DeploymentPin(_uuid(pin['target_id']), _uuid(pin['operation_id']),
                                            pin['plan_digest'], pin['phase']))
            if pin['phase'] != 'ACTIVE' or d['required_readers'] != source.document['lock']['required_readers']:
                raise ValueError
            _digest(d['journal_state_digest'])
            if set(d['models']) != {model['table_id'] for model in source.document['lock']['models']}:
                raise ValueError
            total = 0
            for observed in d['models'].values():
                if set(observed) != {'rows', 'membership', 'frames', 'schema'}:
                    raise ValueError
                _counter(observed['rows'])
                total += observed['rows']
                for name in ('membership', 'frames', 'schema'):
                    _digest(observed[name])
            policies = d['key_policies']
            if set(policies) != set(source.document['key_policies']):
                raise ValueError
            domain = _uuid(source.document['lock']['domain_id'])
            for tenant, policy in policies.items():
                tenant_id = _uuid(tenant, nonzero=False)
                if set(policy) != {'source', 'target', 'contexts', 'payload_generation', 'search_generation'}:
                    raise ValueError
                _digest(policy['source'])
                _digest(policy['target'])
                if policy['source'] != source.document['key_policies'][tenant] or policy['source'] == policy['target']:
                    raise ValueError
                contexts = policy['contexts']
                if type(contexts) is not list or not 1 <= len(contexts) <= 32:
                    raise ValueError
                identities, roots = set(), set()
                for context in contexts:
                    if set(context) != {'domain_id', 'tenant_id', 'purpose', 'root_id', 'generation'}:
                        raise ValueError
                    parsed = KeyContext(_uuid(context['domain_id']), _uuid(context['tenant_id'], nonzero=False),
                                        context['purpose'], _uuid(context['root_id']), context['generation'])
                    identity = (parsed.purpose, parsed.generation)
                    if ((parsed.domain_id, parsed.tenant_id) != (domain, tenant_id)
                            or identity in identities or parsed.root_id in roots):
                        raise ValueError
                    identities.add(identity)
                    roots.add(parsed.root_id)
                for purpose, generation in (('payload', policy['payload_generation']),
                                            ('search', policy['search_generation'])):
                    if purpose == 'search' and generation is None:
                        continue
                    if type(generation) is not int or (purpose, generation) not in identities:
                        raise ValueError
            costs = d['estimates']
            if set(costs) != {'rows', 'verify_rows_per_second', 'verify_seconds_estimate', 'limits'}:
                raise ValueError
            _counter(costs['rows'])
            _counter(costs['verify_seconds_estimate'])
            rate = costs['verify_rows_per_second']
            if (costs['rows'] != total or not m._finite_number(rate) or rate <= 0
                    or costs['verify_seconds_estimate'] != m._estimate_seconds(total, rate)
                    or type(costs['limits']) is not str or not costs['limits']):
                raise ValueError
        except Exception:
            raise m.TransitionFailure('invalid_rewrap_plan') from None

    @property
    def document(self): return json.loads(self.artifact)
    @property
    def digest(self): return hashlib.sha256(self.artifact).hexdigest()
    @property
    def operation_id(self): return UUID(self.document['operation_id'])
    @property
    def source(self): return m.MigrationPlan(m._canonical(self.document['source_plan']))
    @property
    def activation_plan(self):
        """Deterministic successor artifact. This property grants no authority."""
        d = self.document
        source = self.source
        document = source.document
        ancestors = document.get('predecessors', [])
        ancestors.append({'operation_id': str(source.operation_id), 'plan_digest': source.digest})
        document.update(format='cryptalis.transition/v2', kind='rewrap',
            operation_id=str(self.operation_id), predecessors=ancestors, rewrap_plan_digest=self.digest,
            key_policies={tenant: item['target'] for tenant, item in d['key_policies'].items()},
            rewrap_observations={table: {key: value for key, value in item.items() if key != 'schema'}
                                 for table, item in d['models'].items()},
            scopes=[{'table_id': table, 'estimated_rows': item['rows']} for table, item in d['models'].items()],
            estimates={'rows': d['estimates']['rows'],
                       'writer_pause_seconds_estimate': d['estimates']['verify_seconds_estimate'],
                       'limits': d['estimates']['limits']})
        return m.MigrationPlan(m._canonical(document))

    def __str__(self):
        costs = self.document['estimates']
        return (f'Inactive rewrap plan: {costs["rows"]} rows; estimated verification '
                f'{costs["verify_seconds_estimate"]} s. No policy publication or database changes.')

    __repr__ = __str__


def _same_roots(source, target):
    a, b = source.policy, target.policy
    if ((a.domain_id, a.tenant_id, a.payload_generation, a.search_generation)
            != (b.domain_id, b.tenant_id, b.payload_generation, b.search_generation)
            or {w.context for w in a.wrappers} != {w.context for w in b.wrappers}):
        raise KeyUnavailable()
    for wrapper in a.wrappers:
        context = wrapper.context
        old = source._resolve(context.domain_id, context.tenant_id, context.purpose, context.generation)
        new = target._resolve(context.domain_id, context.tenant_id, context.purpose, context.generation)
        if old.context != new.context or not compare_digest(old.root, new.root):
            raise KeyUnavailable()


def _prepare_rewrap(source, keys, target_keys, expected=None):
    policies, prepared = {}, {}
    for tenant_text in source.document['key_policies']:
        tenant = UUID(tenant_text)
        old = m._ring(keys, tenant, source)
        try:
            new = target_keys(tenant) if callable(target_keys) else target_keys
        except Exception:
            raise KeyUnavailable() from None
        if not isinstance(new, Keyring):
            raise m.TransitionFailure('missing_target_key_policy', source.operation_id)
        if m._policy(old) == m._policy(new):
            raise m.TransitionFailure('rewrap_policy_unchanged', source.operation_id)
        pair = old.prepare(), new.prepare()
        _same_roots(*pair)
        prepared[tenant] = pair
        policies[tenant_text] = {'source': m._policy(old), 'target': m._policy(new),
                                'contexts': _contexts(old.policy),
                                'payload_generation': old.policy.payload_generation,
                                'search_generation': old.policy.search_generation}
    if expected is not None and policies != expected:
        raise m.TransitionFailure('rewrap_key_policy_changed', source.operation_id)
    return policies, prepared


def _observe_active(c, source, keys, *, prepared=None, peers=None):
    """Authenticate all active frames, including empty-scope key admission."""
    if prepared is None:
        prepared = {UUID(tenant): m._ring(keys, UUID(tenant), source).prepare()
                    for tenant in source.document['key_policies']}
    models = {}
    for model in source.document['lock']['models']:
        descriptors = [FieldDescriptor.from_compiled(f['descriptor'], f['descriptor_digest'])
                       for f in model['fields']]
        membership, frames = hashlib.sha256(), hashlib.sha256()
        count, cursor = 0, None
        while rows := m._stream(c, model, after=cursor):
            for row in rows:
                scoped = 'column' in model['tenancy']
                tenant = row[1] if scoped else UUID(model['table_id'])
                if tenant not in prepared:
                    raise m.TransitionFailure('key_policy_changed', source.operation_id)
                materials = (prepared[tenant],) if peers is None else (prepared[tenant], peers[tenant])
                identity = [str(row[0]), str(tenant)]
                membership.update(m._canonical(identity))
                frame_digests = []
                for index, field in enumerate(model['fields']):
                    raw = row[(2 if scoped else 1) + index]
                    frame = bytes(raw) if raw is not None else None
                    if frame is not None and (
                            int.from_bytes(frame[6:10], 'big') != materials[0].policy.payload_generation
                            or int.from_bytes(frame[10:14], 'big') != (
                                materials[0].policy.search_generation if field['queries'] else 0)):
                        raise m.TransitionFailure('generation_mismatch', source.operation_id)
                    for material in materials:
                        open_text(frame, descriptors[index], tenant, row[0], material)
                    frame_digests.append(hashlib.sha256(frame).hexdigest() if frame is not None else None)
                frames.update(m._canonical(identity + [frame_digests]))
                count += 1
            cursor = str(rows[-1][0])
        models[model['table_id']] = {'rows': count, 'membership': membership.hexdigest(),
                                    'frames': frames.hexdigest()}
    for materials in (prepared, peers or {}):
        for admitted in materials.values():
            for wrapper in admitted.policy.wrappers:
                context = wrapper.context
                admitted._resolve(context.domain_id, context.tenant_id, context.purpose, context.generation)
    return models


def _verify_rewrap_target(c, p, keys):
    if _observe_active(c, p, keys) != p.document['rewrap_observations']:
        raise m.TransitionFailure('rewrap_source_changed', p.operation_id)


def plan_rewrap(source, engine, *, source_pin, keys, target_keys, verify_rows_per_second):
    """Authenticate unchanged roots and current frames in one read-only snapshot.

    The snapshot does not stop writers or authorize a future switch. Rewrap
    execution must reinspect current rows and host policy under maintenance.
    Provider unwrap calls can have external provider-side effects.
    """
    m._admit(source, source_pin)
    if source_pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    if not m._finite_number(verify_rows_per_second) or verify_rows_per_second <= 0:
        raise m.TransitionFailure('missing_measured_rates')
    with m._connection(engine, source.operation_id) as c:
        c.exec_driver_sql('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        m._check_connection(source, c, source_pin)
        state = m._state(c, source, source_pin)
        policies, prepared = _prepare_rewrap(source, keys, target_keys)
        models = _observe_active(c, source, keys, prepared={t: pair[0] for t,pair in prepared.items()},
                                 peers={t: pair[1] for t,pair in prepared.items()})
        for model in source.document['lock']['models']:
            models[model['table_id']]['schema'] = m._hash(m._facts(c, model))
    try:
        rows = sum(model['rows'] for model in models.values())
        pin = asdict(source_pin)
        pin.update(target_id=str(source_pin.target_id), operation_id=str(source_pin.operation_id))
        proposal = RewrapPlan(m._canonical({
            'format': FORMAT, 'kind': 'rewrap', 'operation_id': str(uuid4()),
            'source_plan': source.document, 'source_pin': pin,
            'required_readers': source.document['lock']['required_readers'],
            'journal_state_digest': m._hash(state), 'models': models, 'key_policies': policies,
            'estimates': {'rows': rows, 'verify_rows_per_second': verify_rows_per_second,
                          'verify_seconds_estimate': m._estimate_seconds(rows, verify_rows_per_second),
                          'limits': 'Host-measured scan estimate. Provider, DDL and publication costs are excluded.'}}))
        # Cleanup and artifact validation can consume a short remaining lease.
        for pair in prepared.values():
            _same_roots(*pair)
    except Exception as exc:
        raise m._safe_failure(exc, source.operation_id, ()) from None
    return proposal


def apply_rewrap(proposal, engine, *, keys, target_keys, pin, approval):
    """Atomically fence writers and record a verified successor as PENDING.

    Keep writers stopped. Publish ``proposal.activation_plan`` through the host,
    then use the existing migration apply operation with its ACTIVATING pin.
    A retry inspects the same immutable successor, rather than creating another.
    """
    if type(proposal) is not RewrapPlan:
        raise m.TransitionFailure('invalid_rewrap_plan')
    successor = proposal.activation_plan
    if type(pin) is not m.DeploymentPin or pin.phase not in ('PREPARED', 'PENDING'):
        raise m.TransitionFailure('rewrap_prepublication_pin_required', proposal.operation_id)
    source = proposal.source
    d = proposal.document
    source_pin = m.DeploymentPin(UUID(d['source_pin']['target_id']), UUID(d['source_pin']['operation_id']),
                                 d['source_pin']['plan_digest'], 'ACTIVE')
    with m._executor(successor, engine, pin, approval) as c:
        with c.begin():
            m._lock_tables(c, successor, verification=True)
            row = c.exec_driver_sql(f'SELECT plan_digest, state FROM {m._journal(c,successor)} WHERE operation_id=%s',
                                    (successor.operation_id,)).one_or_none()
            if row is not None:
                state = m._state(c, successor, pin)
                m._active_schema(c, successor, state)
            else:
                if pin.phase != 'PREPARED':
                    raise m.TransitionFailure('missing_rewrap_operation', proposal.operation_id)
                m._check_connection(source, c, source_pin)
                from cryptalis.deprotection import _inventory
                _inventory(c, source, source, own=None)
                source_state = m._state(c, source, source_pin)
                if m._hash(source_state) != d['journal_state_digest']:
                    raise m.TransitionFailure('rewrap_source_changed', proposal.operation_id)
                for model in source.document['lock']['models']:
                    if m._hash(m._facts(c, model)) != d['models'][model['table_id']]['schema']:
                        raise m.TransitionFailure('rewrap_source_changed', proposal.operation_id)
            _, prepared = _prepare_rewrap(source, keys, target_keys, d['key_policies'])
            observed = _observe_active(c, source, keys,
                prepared={t: pair[0] for t,pair in prepared.items()}, peers={t: pair[1] for t,pair in prepared.items()})
            if observed != successor.document['rewrap_observations']:
                raise m.TransitionFailure('rewrap_source_changed', proposal.operation_id)
            if row is None:
                m._lock_tables(c, successor)
                m._install_guards(c, successor)
                models = {}
                for model in successor.document['lock']['models']:
                    item = observed[model['table_id']]
                    models[model['table_id']] = {'rows': item['rows'], 'chunks': 0,
                        'scope': {'count': item['rows'], 'membership': item['membership']},
                        'active_schema': m._facts(c, model), 'guard': m._check_guard(c, successor, model)}
                state = {'phase': 'PENDING', 'models': models, 'rewrap_plan_digest': proposal.digest}
                source_state.update(phase='SUPERSEDED', superseded_by={
                    'operation_id': str(successor.operation_id), 'plan_digest': successor.digest})
                m._save(c, source, source_state)
                c.exec_driver_sql(f'INSERT INTO {m._journal(c,successor)} VALUES (%s,%s,%s::jsonb)',
                                  (successor.operation_id, successor.digest, json.dumps(state)))
                m._active_schema(c, successor, state)
        return m._progress(successor, state)


def abort_rewrap(proposal, engine, *, keys, pin, approval):
    """Cancel a PENDING successor under the republished source ACTIVE pin.

    Keep writers stopped until this operation commits. Target custody is not
    required. A terminal retry inspects current source authority without
    restoring snapshot data or authenticating obsolete frame observations.
    """
    if type(proposal) is not RewrapPlan:
        raise m.TransitionFailure('invalid_rewrap_plan')
    source, successor = proposal.source, proposal.activation_plan
    m._admit(source, pin)
    if pin.phase != 'ACTIVE':
        raise m.TransitionFailure('source_pin_must_be_active', source.operation_id)
    expected_source = {'operation_id': str(source.operation_id), 'plan_digest': source.digest}
    # Source ACTIVE is the external authority admitted above. This internal pin
    # selects the immutable successor identity and its measured maintenance cost.
    pending = m.DeploymentPin(successor.target_id, successor.operation_id, successor.digest, 'PREPARED')
    with m._executor(successor, engine, pending, approval) as c:
        with c.begin():
            m._lock_tables(c, successor, verification=True)
            row = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,successor)} '
                                    'WHERE operation_id=%s', (successor.operation_id,)).one_or_none()
            original = c.exec_driver_sql(f'SELECT plan_digest,state FROM {m._journal(c,source)} '
                                         'WHERE operation_id=%s', (source.operation_id,)).one_or_none()
            if row is None or row[0] != successor.digest or original is None or original[0] != source.digest:
                raise m.TransitionFailure('journal_identity_mismatch', successor.operation_id)
            state, source_state = row[1], original[1]
            if (type(state) is not dict or type(source_state) is not dict
                    or state.get('rewrap_plan_digest') != proposal.digest):
                raise m.TransitionFailure('rewrap_state_changed', successor.operation_id)
            from cryptalis.deprotection import _inventory
            if state.get('phase') == 'ABORTED':
                if (state.get('aborted_to') != expected_source
                        or m._hash(source_state) != proposal.document['journal_state_digest']):
                    raise m.TransitionFailure('rewrap_abort_source_changed', successor.operation_id)
                m._check_connection(source, c, pin)
                _inventory(c, source, source, own=successor.operation_id)
            else:
                if state.get('phase') != 'PENDING':
                    raise m.TransitionFailure('rewrap_abort_requires_pending', successor.operation_id)
                m._state(c, successor, pending)
                m._active_schema(c, successor, state)
                for model in successor.document['lock']['models']:
                    if m._check_guard(c, successor, model) != state['models'][model['table_id']]['guard']:
                        raise m.TransitionFailure('writer_fence_changed', successor.operation_id)
                restored = dict(source_state, phase='ACTIVE')
                restored.pop('superseded_by', None)
                if m._hash(restored) != proposal.document['journal_state_digest']:
                    raise m.TransitionFailure('rewrap_abort_source_changed', successor.operation_id)
                if _observe_active(c, source, keys) != successor.document['rewrap_observations']:
                    raise m.TransitionFailure('rewrap_source_changed', successor.operation_id)
                # This update is uncommitted. Any inventory, DDL or frame failure
                # rolls back the source marker together with the successor fence.
                m._save(c, source, restored)
                _inventory(c, source, source, own=successor.operation_id)
                m._lock_tables(c, successor)
                m._drop_guards(c, successor)
                for model in source.document['lock']['models']:
                    if m._hash(m._facts(c, model)) != proposal.document['models'][model['table_id']]['schema']:
                        raise m.TransitionFailure('rewrap_abort_schema_changed', successor.operation_id)
                m._check_connection(source, c, pin)
                state.update(phase='ABORTED', aborted_to=expected_source)
                m._save(c, successor, state)
        return m._progress(successor, state)
