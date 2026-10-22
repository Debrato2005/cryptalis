"""Offline rewrap protocol controls. No database evidence or publication.

Run directly with Python. Catalog facts below are synthetic structural inputs.
They do not establish PostgreSQL behavior, active deployment, or key custody.
"""
from dataclasses import asdict, replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from sqlalchemy import create_engine, event
from sqlalchemy.dialects import postgresql

from cryptalis import migration as m
from cryptalis.crypto import DevelopmentKeyProvider, KeyContext, KeyPolicy, Keyring
from cryptalis.crypto.keys import KeyUnavailable
from cryptalis.crypto._rewrap import prepare_rewrap
from cryptalis.manifest import compiler as c
from cryptalis.rotation import RewrapPlan, _contexts, _same_roots, plan_rewrap


DOMAIN, TABLE, FIELD = (UUID(int=n) for n in (9001, 9002, 9003))
ROOTS = (bytes(range(32)), bytes(range(32, 64)))  # Public fixture material.


def fixture():
    """Construct admitted artifacts through real validators, without an engine."""
    domain, table, field = map(str, (DOMAIN, TABLE, FIELD))
    declaration = {
        'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': domain,
        'models': [{'model': 'Customer', 'table_id': table,
                    'tenancy': {'single_tenant': True}, 'fields': [
                        {'name': 'note', 'field_id': field, 'protect': True,
                         'queries': [], 'accept_leakage': []}]}],
    }

    def column(number, name, native_type, nullable):
        return dict(attnum=number, name=name, type=native_type,
                    type_schema='pg_catalog', typmod='-1', nullable=nullable,
                    identity='', generated='', collation_name=None,
                    collation_schema=None, deterministic=None, provider=None,
                    default_digest=None, collation=None)

    facts = {
        'relation': dict(relkind='r', relpersistence='p', relrowsecurity=False,
                         relforcerowsecurity=False, relhasrules=False,
                         inherited=False, user_triggers=False),
        'columns': [column(1, 'id', 'uuid', False), column(2, 'note', 'text', True)],
        'constraints': [dict(name='customer_pkey', kind='p', deferrable=False,
                             deferred=False, validated=True, outgoing=True,
                             incoming=False, schema='synthetic', table='customer',
                             columns=['id'], referenced_columns=[],
                             definition_digest=m._hash('PRIMARY KEY (id)'))],
        'indexes': [], 'dependencies': [],
    }
    descriptor = c._descriptor(domain, table, field, 'uuid16/v1',
                               'single-tenant-uuid/v1', 'cf1-storage/v1')
    protected = dict(name='note', column='note', field_id=field, queries=[],
                     representation='cf1-storage/v1',
                     payload_column='_cryptalis_' + FIELD.hex, unique_indexes=[],
                     original={'constraints': [], 'indexes': []},
                     source={'type': 'text', 'nullable': True, 'collation': None},
                     descriptor=descriptor, descriptor_digest=m._hash(descriptor))
    model = dict(model='Customer', table_id=table, schema='synthetic', table='customer',
                 record={'column': 'id', 'codec': 'uuid16/v1'},
                 tenancy={'single_tenant': True, 'context_id': table},
                 fields=[protected], source_schema=facts)
    lock = dict(schema='cryptalis.lock/v1', profile='cf1', domain_id=domain,
                database={'major': 16, 'encoding': 'UTF8'}, declaration=declaration,
                models=[model], writer_inventory={
                    'complete': True, 'evidence_kind': 'host_assertion',
                    'writers': [dict(table_id=table, name='application',
                                     route='sqlalchemy', excluded=False,
                                     evidence='Synthetic offline structural fixture only.')]},
                search_reviews=[], required_readers=['cf1/v1', 'utf8-exact/v1', 'uuid16/v1'])
    lock['ddl'] = c._ddl(lock, SimpleNamespace(dialect=postgresql.dialect()))
    provider = DevelopmentKeyProvider()
    contexts = tuple(KeyContext(DOMAIN, TABLE, 'payload', UUID(int=9100 + i), i + 1)
                     for i in range(2))
    wrappers = tuple(provider.wrap(root, context) for root, context in zip(ROOTS, contexts))
    source = Keyring(KeyPolicy(DOMAIN, TABLE, wrappers, 1), {provider.provider_id: provider})
    target_provider = DevelopmentKeyProvider()
    target = Keyring(prepare_rewrap(source, target_provider),
                     {target_provider.provider_id: target_provider})
    source_plan = m.MigrationPlan(m._canonical(dict(
        format='cryptalis.transition/v1', kind='protect',
        operation_id=str(UUID(int=9004)), target_id=str(UUID(int=9005)),
        target=['synthetic', '1', None, None, 'owner'], runtime_role='runtime',
        journal_schema='synthetic', lock=lock, source_lock_digest=None,
        key_policies={table: m._policy(source)},
        scopes=[{'table_id': table, 'estimated_rows': 0}],
        estimates={'rows': 0, 'writer_pause_seconds_estimate': 0,
                   'limits': 'Synthetic offline structural fixture only.'})))
    pin = m.DeploymentPin(source_plan.target_id, source_plan.operation_id,
                          source_plan.digest, 'ACTIVE')
    pin_document = {name: str(value) for name, value in asdict(pin).items()}
    proposal = RewrapPlan(m._canonical(dict(
        format='cryptalis.rewrap/v1', kind='rewrap', operation_id=str(UUID(int=9006)),
        source_plan=source_plan.document, source_pin=pin_document,
        required_readers=lock['required_readers'], journal_state_digest='a' * 64,
        models={table: {'rows': 3, 'membership': 'b' * 64,
                        'frames': 'c' * 64, 'schema': 'd' * 64}},
        key_policies={table: {'source': m._policy(source), 'target': m._policy(target),
                             'contexts': _contexts(source.policy),
                             'payload_generation': 1, 'search_generation': None}},
        estimates={'rows': 3, 'verify_rows_per_second': 2.5,
                   'verify_seconds_estimate': 2, 'limits': 'Synthetic protocol check only.'})))
    return SimpleNamespace(proposal=proposal, source_plan=source_plan, pin=pin,
                           source=source, target=target, target_provider=target_provider)


class RewrapProtocolTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture()

    def test_valid_fractional_rate_reload_and_safe_display(self):
        proposal = RewrapPlan(self.f.proposal.artifact)
        self.assertEqual(proposal.artifact, self.f.proposal.artifact)
        self.assertEqual(proposal.digest, self.f.proposal.digest)
        self.assertIn('Inactive rewrap plan', str(proposal))
        self.assertEqual(repr(proposal), str(proposal))
        for root in ROOTS:
            self.assertNotIn(root, proposal.artifact)
            self.assertNotIn(root.hex(), repr(proposal))
        for wrapper in self.f.source.policy.wrappers:
            self.assertNotIn(wrapper.sealed.hex(), proposal.artifact.decode())

    def test_malformed_protocol_inputs_fail_closed(self):
        def policy(d):
            return d['key_policies'][str(TABLE)]

        mutations = {
            'unknown member': lambda d: d.update(unexpected=True),
            'boolean rows': lambda d: d['models'][str(TABLE)].update(rows=True),
            'row mismatch': lambda d: d['estimates'].update(rows=4),
            'estimate mismatch': lambda d: d['estimates'].update(verify_seconds_estimate=1),
            'zero rate': lambda d: d['estimates'].update(verify_rows_per_second=0),
            'boolean rate': lambda d: d['estimates'].update(verify_rows_per_second=True),
            'overflow rate': lambda d: d['estimates'].update(verify_rows_per_second=10**400),
            'underflow duration': lambda d: d['estimates'].update(verify_rows_per_second=5e-324),
            'inactive source pin': lambda d: d['source_pin'].update(phase='PENDING'),
            'wrong source pin': lambda d: d['source_pin'].update(plan_digest='0' * 64),
            'wrong source policy': lambda d: policy(d).update(source='0' * 64),
            'unchanged target policy': lambda d: policy(d).update(target=policy(d)['source']),
            'missing active payload': lambda d: policy(d).update(contexts=policy(d)['contexts'][1:]),
            'duplicate historical context': lambda d: policy(d)['contexts'].append(policy(d)['contexts'][-1]),
            'missing policy': lambda d: d.update(key_policies={}),
            'unknown context member': lambda d: policy(d)['contexts'][0].update(extra='private'),
            'changed tenant context': lambda d: policy(d)['contexts'][0].update(tenant_id=str(UUID(int=999))),
            'missing reader': lambda d: d['required_readers'].pop(),
        }
        for label, change in mutations.items():
            with self.subTest(label=label):
                document = self.f.proposal.document
                change(document)
                with self.assertRaises(m.TransitionFailure) as caught:
                    RewrapPlan(m._canonical(document))
                self.assertEqual(caught.exception.code, 'invalid_rewrap_plan')
        duplicate = self.f.proposal.artifact[:-1] + b',"kind":"rewrap"}'
        with self.assertRaises(m.TransitionFailure) as caught:
            RewrapPlan(duplicate)
        self.assertEqual(caught.exception.code, 'invalid_rewrap_plan')

    def test_both_current_and_historical_roots_must_match(self):
        _same_roots(self.f.source.prepare(), self.f.target.prepare())
        for index in range(2):
            with self.subTest(generation=index + 1):
                wrappers = list(self.f.target.policy.wrappers)
                wrappers[index] = self.f.target_provider.wrap(b'x' * 32, wrappers[index].context)
                changed = Keyring(replace(self.f.target.policy, wrappers=tuple(wrappers)),
                                  {self.f.target_provider.provider_id: self.f.target_provider})
                with self.assertRaises(KeyUnavailable):
                    _same_roots(self.f.source.prepare(), changed.prepare())
        missing = Keyring(replace(self.f.target.policy, wrappers=self.f.target.policy.wrappers[:1]),
                          {self.f.target_provider.provider_id: self.f.target_provider})
        with self.assertRaises(KeyUnavailable):
            _same_roots(self.f.source.prepare(), missing.prepare())

    def test_expired_prepared_material_cannot_admit_rewrap(self):
        source, target = self.f.source.prepare(), self.f.target.prepare()
        for expired, observations in (('source', [1e30]), ('target', [0, 1e30])):
            with self.subTest(expired=expired):
                with patch('cryptalis.crypto.keys.time.monotonic', side_effect=observations):
                    with self.assertRaises(KeyUnavailable):
                        _same_roots(source, target)

    def test_invalid_rate_is_rejected_before_connection_or_key_access(self):
        engine = create_engine('postgresql+psycopg://synthetic@invalid.example/synthetic',
                               echo=False, hide_parameters=True)
        attempts = []

        def forbidden(*args, **kwargs):
            attempts.append('unexpected access')
            raise AssertionError('The protocol check must remain offline.')

        event.listen(engine, 'do_connect', forbidden)
        try:
            for rate in (0, -1, True, float('nan'), float('inf'), 10**400):
                with self.subTest(rate_type=type(rate).__name__):
                    with self.assertRaises(m.TransitionFailure) as caught:
                        plan_rewrap(self.f.source_plan, engine, source_pin=self.f.pin,
                                    keys=forbidden, target_keys=forbidden,
                                    verify_rows_per_second=rate)
                    self.assertEqual(caught.exception.code, 'missing_measured_rates')
            self.assertEqual(attempts, [])
        finally:
            engine.dispose()


if __name__ == '__main__':
    unittest.main(verbosity=2)
