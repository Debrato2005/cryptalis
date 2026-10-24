"""Real compacted restores require complete, ordered public-slot authority."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
from uuid import UUID

import psycopg
import pytest
from sqlalchemy import create_engine

from cryptalis import deprotection as d, migration as m, restore, rotation
from payload_rotation_worker import target_keys as payload_keys
from search_rotation_worker import target_keys as search_keys
from rewrap_worker import target_keys as rewrap_keys
from test_fresh_cluster_export import assert_source_metadata, dump, environment
from test_owned_sequences import facts
from test_public_slots import slots
import test_adopted_rewrap as recovery

adopted = recovery.adopted
fresh = recovery.fresh


def direct_cycle(app, source, pin, binding, purpose, source_keys, target_keys):
    before = slots(app)
    proposal = getattr(rotation, 'plan_' + purpose + '_rotation')(source, app.owner,
        source_pin=pin, restore=binding, keys=source_keys, target_keys=target_keys,
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=1024, wal_bytes_per_row=2048, max_batch_rows=3)
    prep = m.DeploymentPin(source.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    options = dict(keys=source_keys, target_keys=target_keys, pin=prep, approval=recovery.MAINTENANCE)
    apply = getattr(rotation, 'apply_' + purpose + '_rotation')
    assert apply(proposal, app.owner, max_chunks=1, **options).committed_rows == 3
    assert apply(proposal, app.owner, **options).phase == 'BACKFILLED'
    active = getattr(rotation, 'seal_' + purpose + '_rotation')(proposal, app.owner,
        copy_rows_per_second=1000, copy_wal_bytes_per_row=2048, **options)
    assert getattr(rotation, 'switch_' + purpose + '_rotation')(proposal, active, app.owner,
        keys=source_keys, target_keys=target_keys, pin=recovery.pin(active, 'PREPARED'),
        approval=recovery.MAINTENANCE).phase == 'PENDING'
    assert m.apply(active, app.owner, keys=target_keys, pin=recovery.pin(active, 'ACTIVATING'),
        approval=recovery.MAINTENANCE, until='ACTIVE').phase == 'ACTIVE'
    assert slots(app) == before
    return active


def old_reader_refuses(source, binding, directory):
    interpreter = os.environ.get('CRYPTALIS_PREVIOUS_READER_PYTHON')
    assert interpreter, 'Set the unchanged installed pre-v6 reader interpreter.'
    plan, adoption = directory / 'slot-plan.json', directory / 'slot-binding.json'
    plan.write_bytes(source.artifact)
    adoption.write_bytes(binding.artifact)
    script = r'''
from pathlib import Path
import json,sys
import cryptalis,psycopg
from cryptalis import migration as m,restore
assert Path(cryptalis.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
calls=[]
def forbidden(*args,**kwargs):
    calls.append(True)
    raise AssertionError('old reader attempted database work')
psycopg.connect=forbidden
for constructor,path in ((m.MigrationPlan,sys.argv[2]),(restore.RestoreBinding,sys.argv[3])):
    try:constructor(Path(path).read_bytes())
    except m.TransitionFailure:pass
    else:raise AssertionError('old reader accepted new layout authority')
assert calls==[]
print(json.dumps({'lock_v6_source':'REFUSED','restore_v3':'REFUSED','database_calls':0}))
'''
    environment = {name: value for name, value in os.environ.items() if name != 'PYTHONPATH'}
    child = subprocess.run([interpreter, '-I', '-B', '-c', script, str(Path(interpreter).parent.parent),
        str(plan), str(adoption)], env=environment, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, 'installed pre-v6 reader failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'lock_v6_source': 'REFUSED', 'restore_v3': 'REFUSED', 'database_calls': 0}


def test_compacted_restore_v3_is_complete_and_rejects_wrong_maps_before_providers(adopted, tmp_path):
    app = adopted
    app.schema = fresh.SCHEMA
    source_slots = dict(fresh.MANIFEST['source_public_slots'])
    target_slots = dict(slots(app)[1])
    assert source_slots == {'id': 1, 'tenant_id': 2, 'name': 4, 'label': 5}
    assert target_slots == {'id': 1, 'tenant_id': 2, 'name': 3, 'label': 4}
    binding = app.binding
    assert binding.document['format'] == 'cryptalis.restore/v3'
    model = app.source.document['lock']['models'][0]
    assert binding.document['columns'] == [{'model': model['table_id'], 'column': name,
        'source_attnum': value, 'target_attnum': target_slots[name]} for name, value in source_slots.items()]
    assert restore.layout_admissions(app.source.document, model) == source_slots
    assert restore.layout_admissions(app.source.document, model, binding) == target_slots
    assert bool(binding.document['sequences']) is fresh.MANIFEST['owned_sequences']
    old_reader_refuses(app.source, binding, tmp_path)
    before, calls = recovery.snapshot(app), []
    def forbidden(tenant):
        calls.append(tenant)
        pytest.fail('invalid layout authority reached provider work')
    class Closed:
        def connect(self): pytest.fail('invalid layout authority reached connection')
    for fault in ('missing', 'duplicate', 'boolean_slot', 'overflow', 'wrong_source',
                  'wrong_target', 'column', 'order', 'sequences', 'downgrade'):
        document = binding.document
        if fault == 'missing': document['columns'].pop()
        elif fault == 'duplicate': document['columns'].append(document['columns'][-1])
        elif fault == 'boolean_slot': document['columns'][0]['source_attnum'] = True
        elif fault == 'overflow': document['columns'][-1]['target_attnum'] = 32768
        elif fault == 'wrong_source':
            document['columns'][2]['source_attnum'] = 3
        elif fault == 'wrong_target': document['columns'][-1]['target_attnum'] = 6
        elif fault == 'column': document['columns'][-1]['column'] = 'missing_public_column'
        elif fault == 'order': document['columns'].reverse()
        elif fault == 'sequences': document.pop('sequences')
        else:
            document['format'] = 'cryptalis.restore/v2' if document['sequences'] else 'cryptalis.restore/v1'
            document.pop('columns')
            if document['format'] == 'cryptalis.restore/v1': document.pop('sequences')
        with pytest.raises(m.TransitionFailure):
            altered = restore.RestoreBinding(m._canonical(document))
            rotation.plan_rewrap(app.source, app.owner if fault == 'wrong_target' else Closed(),
                source_pin=app.source_pin, keys=forbidden, target_keys=forbidden,
                verify_rows_per_second=1000, restore=altered)
        assert recovery.snapshot(app) == before and calls == []
    assert m.check_deployment(app.source, app.owner, pin=app.source_pin, restore=binding) is None


def finish_exit(app, source, resolver, expected, original_slots, binding=None):
    reverse = d.plan(source, app.owner, source_pin=recovery.pin(source, 'ACTIVE'), keys=resolver,
        restore=binding, plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
        backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=700, wal_bytes_per_row=700)
    consent = d.PlaintextApproval(reverse.target_id, reverse.operation_id, reverse.digest, True,
                                  'public disposable slot-preserving native exit')
    assert d.apply(reverse, app.owner, keys=resolver, pin=recovery.pin(reverse, 'PREPARED'),
        approval=recovery.MAINTENANCE, consent=consent).phase == 'PLAINTEXT_PENDING'
    assert slots(app) == original_slots
    assert d.apply(reverse, app.owner, keys=resolver, pin=recovery.pin(reverse, 'PLAINTEXT_ACTIVATING'),
        approval=recovery.MAINTENANCE, consent=consent, until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
    removal = d.RemovalApproval(reverse.target_id, reverse.operation_id, reverse.digest,
        'native positional reader refuses Cryptalis imports', 'public fixture backups remain quarantined', True)
    assert d.remove(reverse, app.owner, pin=recovery.pin(reverse, 'REMOVING'),
        approval=recovery.MAINTENANCE, removal=removal, consent=consent).phase == 'REMOVED'
    assert d.check_removed(reverse, app.owner, pin=recovery.pin(reverse, 'REMOVED')) is None
    assert slots(app) == original_slots
    assert_source_metadata(app, fresh.MANIFEST['runtime_role'])
    script = r'''
import importlib.abc,json,os,sys
class DenyCryptalis(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='cryptalis' or fullname.startswith('cryptalis.'):
            raise ImportError('Cryptalis refused after native removal')
sys.meta_path.insert(0,DenyCryptalis())
import psycopg
from psycopg import sql
expected=json.loads(sys.stdin.read())
with psycopg.connect(os.environ['NATIVE_RESTART_URL'],connect_timeout=5) as connection:
    cursor=connection.execute(sql.SQL('SELECT * FROM {}.customer ORDER BY id').format(
        sql.Identifier(os.environ['NATIVE_RESTART_SCHEMA'])))
    assert [column.name for column in cursor.description]==['id','tenant_id','name','label']
    assert {str(row[0]):[str(row[1]),row[2]] for row in cursor}==expected
assert not any(name=='cryptalis' or name.startswith('cryptalis.') for name in sys.modules)
print(json.dumps({'native_positional_latest_values':'PASS','cryptalis_imported':False}))
'''
    database = binding.target[0] if binding is not None else source.document['target'][0]
    url = psycopg.conninfo.make_conninfo(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL'], dbname=database)
    child = subprocess.run([sys.executable, '-I', '-B', '-c', script], input=json.dumps(expected),
        env=dict(os.environ, NATIVE_RESTART_URL=url, NATIVE_RESTART_SCHEMA=app.schema),
        capture_output=True, text=True, timeout=30)
    assert child.returncode == 0, 'package-free positional restart failed; diagnostics suppressed'
    assert json.loads(child.stdout) == {'native_positional_latest_values': 'PASS', 'cryptalis_imported': False}


@pytest.mark.parametrize('purpose', ['none', 'rewrap', 'payload', 'search'])
def test_restored_slots_survive_successors_and_latest_value_positional_exit(adopted, purpose):
    app = adopted
    app.schema = fresh.SCHEMA
    before = slots(app)
    sequence = facts(app) if fresh.MANIFEST['owned_sequences'] else None
    binding = None
    if purpose == 'none':
        active, resolver, binding = app.source, fresh.keys, app.binding
    elif purpose == 'rewrap':
        resolver = rewrap_keys
        active = recovery.publish_rewrap(app, recovery.proposal(app), fresh.keys, resolver)
    else:
        resolver = payload_keys if purpose == 'payload' else search_keys
        active = direct_cycle(app, app.source, app.source_pin, app.binding, purpose, fresh.keys, resolver)
    assert slots(app) == before
    if purpose != 'none':
        assert active.document['lock']['schema'] == 'cryptalis.lock/v6'
        assert active.document['restore_lineage'] == [app.binding.document]
    latest = 'latest mapped-slot ' + purpose
    recovery.current_edit(app, active, resolver, latest, binding)
    expected = dict(fresh.MANIFEST['expected'])
    expected[str(UUID(int=101))] = [str(fresh.TENANT), latest]
    finish_exit(app, active, resolver, expected, before, binding)
    if sequence is not None:
        assert facts(app) == sequence


def test_second_real_adoption_composes_current_slots_instead_of_original_gaps(adopted):
    app = adopted
    app.schema = fresh.SCHEMA
    first = direct_cycle(app, app.source, app.source_pin, app.binding, 'payload', fresh.keys, payload_keys)
    before_first = recovery.snapshot(app)
    backup = fresh.WORKDIR / ('public-slots-v6-' + first.operation_id.hex + '.sql')
    dump(backup, app.schema, environment('CRYPTALIS_TEST_DATABASE_URL'))
    database = fresh.PLAIN_DATABASE
    owner = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**fresh.environment('CRYPTALIS_TEST_DATABASE_URL', database), connect_timeout=5))
    runtime = create_engine('postgresql+psycopg://', hide_parameters=True,
        creator=lambda: psycopg.connect(**fresh.environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL', database), connect_timeout=5))
    try:
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{app.schema}" CASCADE')
        fresh.restore(backup, 'CRYPTALIS_TEST_DATABASE_URL', database)
        second = SimpleNamespace(owner=owner, runtime=runtime, source=first, schema=app.schema)
        binding = restore.plan(first, owner, pin=recovery.pin(first, 'ACTIVE'), keys=payload_keys,
            approval=restore.RestoreApproval('qualification host', 'recover current slot-preserving copy',
                'both disposable copies fenced and quarantined', True))
        assert [(entry['column'], entry['source_attnum']) for entry in binding.document['columns']] == list(slots(app)[1])
        assert next(entry for entry in binding.document['columns'] if entry['column'] == 'name')['source_attnum'] == 3
        def target(tenant): return search_keys(tenant, source=payload_keys)
        before = slots(second)
        active = direct_cycle(second, first, recovery.pin(first, 'ACTIVE'), binding, 'search', payload_keys, target)
        assert active.document['restore_lineage'] == [app.binding.document, binding.document]
        altered = active.document
        altered['restore_lineage'][-1]['columns'][2]['source_attnum'] = 4
        altered['restore_lineage'][-1]['columns'][3]['source_attnum'] = 5
        with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(altered))
        recovery.current_edit(second, active, target, 'latest twice-adopted slots')
        expected = dict(fresh.MANIFEST['expected'])
        expected[str(UUID(int=101))] = [str(fresh.TENANT), 'latest twice-adopted slots']
        finish_exit(second, active, target, expected, before)
        assert recovery.snapshot(app) == before_first
    finally:
        runtime.dispose()
        owner.dispose()
