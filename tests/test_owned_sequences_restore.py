"""Genuine restore maps sequence identities and preserves current native counters."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID

import pytest

from cryptalis import migration as m, restore, rotation
from rewrap_worker import target_keys as rewrap_keys
from smolink_fresh_cluster import rotated_keys
from test_owned_sequences import facts, next_value
import test_adopted_rewrap as recovery

adopted = recovery.adopted


def old_reader_refuses(source, binding, directory):
    interpreter = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    assert interpreter, 'set CRYPTALIS_PREVIOUS_READER_PYTHON to the unchanged pre-v5 installed reader'
    plan, adoption = directory / 'sequence-plan.json', directory / 'sequence-binding.json'
    plan.write_bytes(source.artifact)
    adoption.write_bytes(binding.artifact)
    script = r'''
import json, pathlib, sys
import cryptalis, psycopg
from cryptalis import migration as m, restore
assert pathlib.Path(cryptalis.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())
calls = []
def forbidden(*args, **kwargs):
    calls.append(True)
    raise AssertionError('old reader attempted database work')
psycopg.connect = forbidden
for constructor, path in ((m.MigrationPlan, sys.argv[2]), (restore.RestoreBinding, sys.argv[3])):
    try:
        constructor(pathlib.Path(path).read_bytes())
    except m.TransitionFailure:
        pass
    else:
        raise AssertionError('old reader accepted new sequence authority')
assert calls == []
print(json.dumps({'lock_v5_source': 'REFUSED', 'restore_v2': 'REFUSED', 'database_calls': 0}))
'''
    environment = {name: value for name, value in os.environ.items() if name != 'PYTHONPATH'}
    child = subprocess.run([interpreter, '-I', '-B', '-c', script, str(Path(interpreter).parent.parent),
        str(plan), str(adoption)], env=environment, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, 'installed old sequence reader failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'lock_v5_source': 'REFUSED', 'restore_v2': 'REFUSED', 'database_calls': 0}


def test_fresh_sequence_mapping_root_payload_latest_value_exit_and_native_counter(adopted, tmp_path):
    app = adopted
    app.schema = recovery.fresh.SCHEMA
    manifest = recovery.fresh.MANIFEST
    assert manifest['owned_sequences'] is True
    original, observed = manifest['sequence_facts'], list(facts(app))
    assert original[0] != observed[0] and original[1:] == observed[1:]
    binding = app.binding
    assert binding.document['format'] == 'cryptalis.restore/v2'
    assert binding.document['sequences'] == [{'model': app.source.document['lock']['models'][0]['table_id'],
        'schema': app.schema, 'name': 'preserved_seq', 'column': 'name',
        'source_oid': original[0], 'target_oid': observed[0]}]
    assert restore.RestoreBinding(binding.artifact).artifact == binding.artifact
    old_reader_refuses(app.source, binding, tmp_path)
    before = recovery.snapshot(app)
    calls = []
    def forbidden(tenant):
        calls.append(tenant)
        pytest.fail('invalid sequence identity reached provider work')
    class Closed:
        def connect(self): pytest.fail('invalid sequence mapping reached connection')
    for fault in ('missing', 'duplicate', 'source_oid', 'target_oid'):
        document = binding.document
        if fault == 'missing': document['sequences'] = []
        elif fault == 'duplicate': document['sequences'] *= 2
        else: document['sequences'][0][fault] = str(int(document['sequences'][0][fault]) + 1)
        with pytest.raises(m.TransitionFailure):
            altered = restore.RestoreBinding(m._canonical(document))
            rotation.plan_rewrap(app.source, app.owner if fault == 'target_oid' else Closed(),
                source_pin=app.source_pin, keys=forbidden, target_keys=forbidden,
                verify_rows_per_second=1000, restore=altered)
        assert recovery.snapshot(app) == before and list(facts(app)) == observed
    assert calls == []
    assert next_value(app) == manifest['sequence_next_expected'] == 115
    rewrap = recovery.proposal(app)
    active = recovery.publish_rewrap(app, rewrap, recovery.fresh.keys, rewrap_keys)
    assert active.document['restore_lineage'] == [binding.document]
    assert list(facts(app)) == observed
    assert next_value(app) == 122
    proposal = rotation.plan_payload_rotation(active, app.owner, source_pin=recovery.pin(active, 'ACTIVE'),
        keys=rewrap_keys, target_keys=rotated_keys, backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    prep = m.DeploymentPin(active.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    assert rotation.apply_payload_rotation(proposal, app.owner, keys=rewrap_keys, target_keys=rotated_keys,
        pin=prep, approval=recovery.MAINTENANCE).phase == 'BACKFILLED'
    activation = rotation.seal_payload_rotation(proposal, app.owner, keys=rewrap_keys, target_keys=rotated_keys,
        pin=prep, approval=recovery.MAINTENANCE, copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048)
    assert activation.document['restore_lineage'] == [binding.document]
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    assert rotation.switch_payload_rotation(proposal, activation, app.owner, keys=rewrap_keys, target_keys=rotated_keys,
        pin=recovery.pin(activation, 'PREPARED'), approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=rotated_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    assert list(facts(app)) == observed
    recovery.current_edit(app, activation, rotated_keys, 'latest restored owned-sequence value')
    expected = dict(manifest['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest restored owned-sequence value']
    recovery.decrypt_remove_and_restart(app, activation, rotated_keys, expected)
    assert list(facts(app)) == observed and next_value(app) == 129
    script = r'''
import importlib.abc, json, os, sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis denied after removal')
sys.meta_path.insert(0, DenyCryptalis())
import psycopg
with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], connect_timeout=5) as connection:
    value = connection.execute('SELECT pg_catalog.nextval(%s::regclass)',
                              ('"' + os.environ['OWNED_SEQUENCE_SCHEMA'] + '".preserved_seq',)).fetchone()[0]
    assert value == 136
assert not any(name == 'cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print(json.dumps({'native_sequence': 'PASS', 'cryptalis_imported': False}))
'''
    child = subprocess.run([sys.executable, '-I', '-B', '-c', script],
        env=dict(os.environ, OWNED_SEQUENCE_SCHEMA=app.schema), capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'package-free native sequence restart failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_sequence': 'PASS', 'cryptalis_imported': False}


def direct_cycle(app, source, pin, binding, purpose, source_keys, target_keys):
    before = facts(app)
    planner = getattr(rotation, 'plan_' + purpose + '_rotation')
    proposal = planner(source, app.owner, source_pin=pin, restore=binding, keys=source_keys, target_keys=target_keys,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    assert proposal.document['restore'] == binding.document
    prep = m.DeploymentPin(source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    options = dict(keys=source_keys, target_keys=target_keys, pin=prep, approval=recovery.MAINTENANCE)
    apply = getattr(rotation, 'apply_' + purpose + '_rotation')
    assert apply(proposal, app.owner, max_chunks=1, **options).committed_rows == 3
    assert apply(proposal, app.owner, **options).phase == 'BACKFILLED'
    activation = getattr(rotation, 'seal_' + purpose + '_rotation')(proposal, app.owner,
        copy_rows_per_second=1000.5, copy_wal_bytes_per_row=2048, **options)
    assert m.MigrationPlan(activation.artifact).artifact == activation.artifact
    assert getattr(rotation, 'switch_' + purpose + '_rotation')(proposal, activation, app.owner,
        keys=source_keys, target_keys=target_keys, pin=recovery.pin(activation, 'PREPARED'),
        approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(activation, app.owner, keys=target_keys, pin=recovery.pin(activation, 'ACTIVATING'),
                   approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    assert facts(app) == before
    return activation


@pytest.mark.parametrize('purpose', ['payload', 'search'])
def test_direct_generation_uses_original_sequence_restore_v2_identity_map(adopted, purpose):
    from payload_rotation_worker import target_keys as payload_keys
    from search_rotation_worker import target_keys as search_keys
    app = adopted
    app.schema = recovery.fresh.SCHEMA
    before = facts(app)
    assert next_value(app) == recovery.fresh.MANIFEST['sequence_next_expected'] == 115
    target = payload_keys if purpose == 'payload' else search_keys
    active = direct_cycle(app, app.source, app.source_pin, app.binding, purpose, recovery.fresh.keys, target)
    assert active.document['restore_lineage'] == [app.binding.document]
    latest = 'latest direct sequence ' + purpose
    recovery.current_edit(app, active, target, latest)
    expected = dict(recovery.fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), latest]
    recovery.decrypt_remove_and_restart(app, active, target, expected)
    assert facts(app) == before and next_value(app) == 122


def test_second_adoption_composes_effective_sequence_oids_in_two_v2_bindings(adopted):
    from types import SimpleNamespace
    import psycopg
    from sqlalchemy import create_engine
    from payload_rotation_worker import target_keys as payload_keys
    from search_rotation_worker import target_keys as new_search_keys
    from test_fresh_cluster_export import dump, environment
    app = adopted
    app.schema = recovery.fresh.SCHEMA
    first = direct_cycle(app, app.source, app.source_pin, app.binding, 'payload', recovery.fresh.keys, payload_keys)
    first_facts = facts(app)
    assert next_value(app) == 115
    backup = recovery.fresh.WORKDIR / ('sequence-v6-' + first.operation_id.hex + '.sql')
    dump(backup, app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
    original_copy = recovery.snapshot(app)
    database = recovery.fresh.PLAIN_DATABASE
    owner = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**recovery.fresh.environment('CRYPTALIS_TEST_DATABASE_URL', database), connect_timeout=5))
    runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**recovery.fresh.environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', database), connect_timeout=5))
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{app.schema}" CASCADE')
        recovery.fresh.restore(backup, 'CRYPTALIS_TEST_DATABASE_URL', database)
        second = SimpleNamespace(owner=owner, runtime=runtime, source=first, schema=app.schema)
        second_facts = facts(second)
        assert first_facts[0] != second_facts[0] and first_facts[1:] == second_facts[1:]
        binding = restore.plan(first, owner, pin=recovery.pin(first, 'ACTIVE'), keys=payload_keys,
            approval=restore.RestoreApproval('qualification host', 'recover current sequence-bearing v6 copy',
                'original app sessions stopped and both disposable copies quarantined', True))
        mapping = dict(app.binding.document['sequences'][0], source_oid=first_facts[0], target_oid=second_facts[0])
        assert binding.document['sequences'] == [mapping]
        def target(tenant): return new_search_keys(tenant, source=payload_keys)
        active = direct_cycle(second, first, recovery.pin(first, 'ACTIVE'), binding, 'search', payload_keys, target)
        assert active.document['restore_lineage'] == [app.binding.document, binding.document]
        recovery.current_edit(second, active, target, 'latest second sequence adoption')
        expected = dict(recovery.fresh.MANIFEST['expected'])
        expected[str(UUID(int=101))] = [str(recovery.fresh.TENANT), 'latest second sequence adoption']
        recovery.decrypt_remove_and_restart(second, active, target, expected)
        assert facts(second) == second_facts and recovery.snapshot(app) == original_copy
        with runtime.begin() as connection:
            assert connection.exec_driver_sql('SELECT pg_catalog.nextval(%s::regclass)',
                (f'"{app.schema}".preserved_seq',)).scalar_one() == 122
    finally:
        runtime.dispose()
        owner.dispose()
