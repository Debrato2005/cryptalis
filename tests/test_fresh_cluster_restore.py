"""Fresh-cluster recovery evidence for a restored protected schema.

This module runs against a newly initialized PostgreSQL 16 cluster with a
temporary HOME credential pair. It proves native readability of a plaintext
pre-protection backup, frame-level recovery of a protected backup with the
retained key policy and reader path, loud refusal of the restored journal as
current authority, and the full adopted lifecycle: explicit fenced restore
approval, a verified ``cryptalis.restore/v1`` binding, attached reads and
exact search, protected modifications, decrypt-back, and approved removal.
"""
import base64
from dataclasses import replace
import importlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import uuid

import psycopg
import pytest
from sqlalchemy import Column, Index, MetaData, String, Table, Text, Uuid, create_engine, select
from sqlalchemy.orm import registry

import cryptalis.migration as m
import cryptalis.restore as r
from cryptalis.crypto.cf1 import FieldDescriptor, open_text
from cryptalis.manifest.compiler import _canonical
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_migration import engine, independent_open, keys, TENANT
from test_migration import keys as original_keys
from test_fresh_cluster_export import assert_source_metadata

d = importlib.import_module('cryptalis.deprotection')

if 'CRYPTALIS_FRESH_CLUSTER_DIR' not in os.environ:
    pytest.skip('run through scripts/fresh_cluster_qualification.py', allow_module_level=True)

WORKDIR = Path(os.environ['CRYPTALIS_FRESH_CLUSTER_DIR'])
MANIFEST = json.loads((WORKDIR / 'restore-manifest.json').read_text())
if MANIFEST.get('rewrapped') is not (os.environ.get('CRYPTALIS_FRESH_SOURCE_REWRAP') == '1'):
    pytest.fail('restore manifest does not match the requested root-rewrap profile')
if MANIFEST.get('payload_rotated') is not (os.environ.get('CRYPTALIS_FRESH_SOURCE_PAYLOAD_ROTATION') == '1'):
    pytest.fail('restore manifest does not match the requested payload-rotation profile')
if MANIFEST.get('search_rotated') is not (os.environ.get('CRYPTALIS_FRESH_SOURCE_SEARCH_ROTATION') == '1'):
    pytest.fail('restore manifest does not match the requested search-rotation profile')
if sum((MANIFEST['rewrapped'], MANIFEST['payload_rotated'], MANIFEST['search_rotated'])) > 1:
    pytest.fail('restore manifest contains incompatible rotation profiles')
if MANIFEST.get('rewrapped'):
    from rewrap_worker import target_keys as keys
if MANIFEST.get('payload_rotated'):
    from payload_rotation_worker import target_keys as keys
if MANIFEST.get('search_rotated'):
    from search_rotation_worker import target_keys as keys
SCHEMA = MANIFEST['schema']
PLAIN_DATABASE = os.environ['CRYPTALIS_FRESH_PLAIN_DATABASE']


def environment(variable, database=None):
    parsed = psycopg.conninfo.conninfo_to_dict(os.environ[variable])
    return {'host': parsed.get('host', ''), 'port': parsed.get('port', '5432'),
            'user': parsed['user'], 'password': parsed['password'],
            'dbname': database or parsed['dbname']}


def restore(path, variable, database=None):
    values = environment(variable, database)
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', str(path)],
                            env=dict(os.environ, PGHOST=values['host'], PGPORT=values['port'],
                                     PGUSER=values['user'], PGPASSWORD=values['password'],
                                     PGDATABASE=values['dbname']),
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    assert result.returncode == 0, 'psql restore failed (diagnostics withheld)'


def rows(variable, statement, database=None):
    with psycopg.connect(**environment(variable, database)) as c:
        return c.execute(statement).fetchall()


def artifacts():
    source = m.MigrationPlan(base64.b64decode(MANIFEST['plan']))
    if MANIFEST['rewrapped']:
        assert source.document['format'] == 'cryptalis.transition/v2'
        assert source.document['kind'] == 'rewrap'
        assert source.document['predecessors']
    if MANIFEST['payload_rotated']:
        document=source.document
        assert document['format']=='cryptalis.transition/v3' and document['kind']=='payload_rotation'
        assert len(document['predecessors'])>=2
        assert document['predecessors'][-1]['plan_digest']==document['payload_rotation_plan_digest']
    if MANIFEST['search_rotated']:
        document=source.document
        assert document['format']=='cryptalis.transition/v4' and document['kind']=='search_rotation'
        assert len(document['predecessors'])>=2
        assert document['predecessors'][-1]['plan_digest']==document['search_rotation_plan_digest']
    pin = m.DeploymentPin(uuid.UUID(MANIFEST['pin']['target_id']), uuid.UUID(MANIFEST['pin']['operation_id']),
                          MANIFEST['pin']['plan_digest'], MANIFEST['pin']['phase'])
    return source, pin


def source_value_type():
    return (String(MANIFEST['native_limit'], collation='C') if MANIFEST.get('native_type') == 'varchar'
            else Text(collation='C'))


def customer_mapping():
    mapping = registry(metadata=MetaData(schema=SCHEMA))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', source_value_type()),
                  Column('label', Text))
    Index('native_name', table.c.tenant_id, table.c.name, unique=True)
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    return mapping, Customer


def approval():
    return r.RestoreApproval('qualification host', 'authorize the restored protected copy',
                                   'source cluster fenced and quarantined during restore test', True)


def flip_name_byte(identity):
    column = f'"{MANIFEST["column"]}"'
    statement = (f'UPDATE "{SCHEMA}".customer SET {column}=pg_catalog.set_byte({column},'
                 f'octet_length({column})-1,pg_catalog.get_byte({column},octet_length({column})-1) # 1) '
                 'WHERE id=%s')
    with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
        c.execute(statement, (identity,))
        c.commit()


def test_plaintext_backup_restores_natively():
    restore(WORKDIR / 'plain.sql', 'CRYPTALIS_TEST_DATABASE_URL', PLAIN_DATABASE)
    observed = {str(identity): [str(tenant), value] for identity, tenant, value in rows(
        'CRYPTALIS_TEST_DATABASE_URL', f'SELECT id, tenant_id, name FROM "{SCHEMA}".customer ORDER BY id',
        PLAIN_DATABASE)}
    assert observed == MANIFEST['source']
    # The plaintext dump is restored into the orchestrator's second database.
    values = environment('CRYPTALIS_TEST_DATABASE_URL', PLAIN_DATABASE)
    plaintext = create_engine('postgresql+psycopg://', hide_parameters=True,
                              creator=lambda: psycopg.connect(**values))
    try:
        assert_source_metadata(SimpleNamespace(owner=plaintext, schema=SCHEMA), MANIFEST['runtime_role'])
    finally:
        plaintext.dispose()


def test_protected_backup_recovers_values_with_retained_keys():
    restore(WORKDIR / 'protected.sql', 'CRYPTALIS_TEST_DATABASE_URL')
    with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
        assert c.execute(
            'SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s '
            'AND column_name=%s', (SCHEMA, 'customer', MANIFEST['column'])).fetchone()[0] == 'bytea'
        assert c.execute('SELECT pg_catalog.to_regclass(%s)',
                         (f'{MANIFEST["journal_schema"]}.{m.JOURNAL}',)).fetchone()[0] is not None
        restored = c.execute(
            f'SELECT id, tenant_id, "{MANIFEST["column"]}" FROM "{SCHEMA}".customer ORDER BY id').fetchall()
    with psycopg.connect(**environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')) as c:
        assert c.execute(f'SELECT count(*) FROM "{SCHEMA}".customer').fetchone()[0] == len(MANIFEST['expected'])
        assert c.execute(f'SELECT count(*) FROM "{SCHEMA}".customer '
                         "WHERE name = pg_catalog.convert_to('edited while protected','UTF8')").fetchone()[0] == 0
    descriptor = FieldDescriptor.from_compiled(MANIFEST['descriptor'], MANIFEST['descriptor_digest'])
    material = keys(TENANT).prepare()
    recovered = {str(identity): [str(tenant), open_text(None if frame is None else bytes(frame), descriptor,
                                                        tenant, identity, material)]
                 for identity, tenant, frame in restored}
    assert recovered == MANIFEST['expected']
    assert MANIFEST['deleted_id'] not in recovered and MANIFEST['added_id'] in recovered
    independent_options={}
    if MANIFEST['payload_rotated']:
        from cryptalis.crypto import KeyContext
        from test_migration import DOMAIN
        independent_options=dict(
            payload_context=KeyContext(DOMAIN,TENANT,'payload',uuid.uuid5(DOMAIN,f'payload-worker:{TENANT}:2'),2),
            payload_root=hashlib.sha256(b'PUBLIC PAYLOAD WORKER ROOT'+TENANT.bytes+(2).to_bytes(4,'big')).digest())
    if MANIFEST['search_rotated']:
        independent_options=dict(
            search_root=hashlib.sha256(b'PUBLIC SEARCH WORKER ROOT'+TENANT.bytes+(2).to_bytes(4,'big')).digest())
    independent = {str(identity): [str(tenant), independent_open(None if frame is None else bytes(frame),
                                                                 MANIFEST['descriptor'], tenant, identity,**independent_options)]
                   for identity, tenant, frame in restored}
    assert independent == MANIFEST['expected']


def test_restored_journal_cannot_override_current_authority():
    import cryptalis.deprotection as d
    source = m.MigrationPlan(base64.b64decode(MANIFEST['plan']))
    pin = m.DeploymentPin(uuid.UUID(MANIFEST['pin']['target_id']), uuid.UUID(MANIFEST['pin']['operation_id']),
                          MANIFEST['pin']['plan_digest'], MANIFEST['pin']['phase'])
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping = registry(metadata=MetaData(schema=SCHEMA))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', source_value_type()),
                  Column('label', Text))
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    try:
        with pytest.raises(m.TransitionFailure, match='deployment_not_current'):
            m.check_deployment(source, owner, pin=pin)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin))
        with pytest.raises(m.TransitionFailure, match='deployment_not_current'):
            d.plan(source, owner, source_pin=pin, keys=keys, plaintext_runtime_role='postgres',
                   backfill_rows_per_second=1000, verify_rows_per_second=1000,
                   temporary_bytes_per_row=700, wal_bytes_per_row=700)
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()


def test_restore_adoption_requires_explicit_fenced_approval():
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            r.plan(source, owner, pin=pin, keys=keys, approval=None)
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            r.plan(source, owner, pin=pin, keys=keys, approval=replace(approval(), source_fenced=False))
        with pytest.raises(m.TransitionFailure, match='source_pin_must_be_active'):
            r.plan(source, owner, pin=replace(pin, phase='PENDING'), keys=keys, approval=approval())
        with pytest.raises(m.TransitionFailure, match='external_policy_mismatch'):
            r.plan(source, owner, pin=replace(pin, plan_digest='0' * 64), keys=keys, approval=approval())
        if MANIFEST['rewrapped'] or MANIFEST['payload_rotated'] or MANIFEST['search_rotated']:
            with pytest.raises(m.TransitionFailure, match='key_policy_changed'):
                r.plan(source, owner, pin=pin, keys=original_keys, approval=approval())
    finally:
        owner.dispose()


@pytest.mark.parametrize('drift', ['extra_column', 'unprotected_check', 'weakened_frame'])
def test_restore_adoption_refuses_schema_and_journal_forged_together(drift):
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    model = source.document['lock']['models'][0]
    table = f'"{SCHEMA}".customer'
    journal = f'"{MANIFEST["journal_schema"]}"."_cryptalis_journal"'
    frame = model['fields'][0]['payload_column'] + '_frame'
    changed = False
    try:
        with owner.begin() as c:
            state = c.exec_driver_sql(f'SELECT state FROM {journal} WHERE operation_id=%s',
                                      (source.operation_id,)).scalar_one()
            original_state = json.dumps(state)
            if drift == 'extra_column':
                c.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN unplanned_plaintext text')
            elif drift == 'unprotected_check':
                c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT unplanned_rule CHECK (label IS NOT NULL)')
            else:
                definition = c.exec_driver_sql(
                    'SELECT pg_catalog.pg_get_constraintdef(oid) FROM pg_catalog.pg_constraint '
                    'WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                    (table, frame)).scalar_one()
                weakened = definition.replace('>= 74', '>= 73')
                assert weakened != definition
                c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "{frame}"')
                c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{frame}" {weakened}')
            state['models'][model['table_id']]['active_schema'] = m._facts(c, model)
            c.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                              (json.dumps(state), source.operation_id))
        changed = True
        with pytest.raises(m.TransitionFailure, match='active_schema_mismatch'):
            r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    finally:
        try:
            if changed:
                with owner.begin() as c:
                    if drift == 'extra_column':
                        c.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN unplanned_plaintext')
                    elif drift == 'unprotected_check':
                        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT unplanned_rule')
                    else:
                        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "{frame}"')
                        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{frame}" {definition}')
                    c.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                                      (original_state, source.operation_id))
        finally:
            owner.dispose()


def test_restored_target_refuses_corrupt_frames_and_tampered_bindings():
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    identity = uuid.UUID(int=101)
    flip_name_byte(identity)
    try:
        with pytest.raises(m.TransitionFailure, match='restored_frame_verification_failed'):
            r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    finally:
        flip_name_byte(identity)
    try:
        binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        assert binding.source_plan_digest == source.digest
        assert binding.source_target == source.document['target']
        assert binding.target[:-1] != source.document['target'][:-1]
        assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
        document = binding.document
        bad_state = r.RestoreBinding(_canonical({**document, 'journal_state_digest': '0' * 64}))
        with pytest.raises(m.TransitionFailure, match='restored_state_changed'):
            m.check_deployment(source, owner, pin=pin, restore=bad_state)
        document = binding.document
        document['target'] = [document['target'][0], '0'] + document['target'][2:]
        bad_target = r.RestoreBinding(_canonical(document))
        with pytest.raises(m.TransitionFailure, match='restore_target_mismatch'):
            m.check_deployment(source, owner, pin=pin, restore=bad_target)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, bad_state))
        with pytest.raises(m.TransitionFailure, match='restore_binding_mismatch'):
            m.check_deployment(source, owner, pin=pin,
                               restore=r.RestoreBinding(_canonical({
                                   **binding.document, 'source': {**binding.document['source'],
                                                                  'plan_digest': '0' * 64}})))
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()


def test_restored_target_refuses_post_adoption_drift():
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    table = f'"{SCHEMA}".customer'
    field_id = source.document['lock']['models'][0]['fields'][0]['field_id']
    frame = '_cryptalis_' + uuid.UUID(field_id).hex + '_frame'
    definition = binding.document['restatements'][0]['definition']
    weakened = definition.replace('>= 74', '>= 73')
    assert weakened != definition
    with owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {weakened}')
    try:
        with pytest.raises(m.TransitionFailure, match='restored_schema_changed'):
            m.check_deployment(source, owner, pin=pin, restore=binding)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {definition}')
    with owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} CHECK (true)')
    try:
        with pytest.raises(m.TransitionFailure, match='restored_schema_mismatch'):
            m.check_deployment(source, owner, pin=pin, restore=binding)
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT {frame}')
            c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT {frame} {definition}')
    journal = f'"{MANIFEST["journal_schema"]}"."_cryptalis_journal"'
    with owner.begin() as c:
        c.exec_driver_sql(f"""UPDATE {journal} SET state = state || '{{"drift": true}}'::jsonb""")
    try:
        with pytest.raises(m.TransitionFailure, match=(source.document['kind']+'_state_changed'
                if MANIFEST['payload_rotated'] or MANIFEST['search_rotated'] else 'restored_state_changed')):
            m.check_deployment(source, owner, pin=pin, restore=binding)
        with pytest.raises(PolicyMismatch):
            attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f"UPDATE {journal} SET state = state - 'drift'")
    try:
        assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
    finally:
        owner.dispose()
        runtime.dispose()
        mapping.dispose()


def _frame_policy_snapshot(owner, source):
    model = source.document['lock']['models'][0]
    field = model['fields'][0]
    frame = field['payload_column'] + '_frame'
    with owner.connect() as c:
        table = m._table(c, model)
        journal = m._journal(c, source)
        with r._catalog_path(c):
            definition, expression = c.exec_driver_sql(
                'SELECT pg_catalog.pg_get_constraintdef(oid), '
                'pg_catalog.pg_get_expr(conbin,conrelid) FROM pg_catalog.pg_constraint '
                'WHERE conrelid=pg_catalog.to_regclass(%s) AND conname=%s',
                (table, frame)).one()
        recorded = c.exec_driver_sql(f'SELECT plan_digest,state FROM {journal} WHERE operation_id=%s',
                                     (source.operation_id,)).one()
        values = c.exec_driver_sql(f'SELECT * FROM {table} ORDER BY id').all()
    return table, frame, definition, (tuple(recorded), values), expression


def _replace_frame_policy(owner, table, frame, definition):
    with owner.begin() as c:
        c.exec_driver_sql(f'ALTER TABLE {table} DROP CONSTRAINT "{frame}"')
        c.exec_driver_sql(f'ALTER TABLE {table} ADD CONSTRAINT "{frame}" {definition}')


def test_restored_frame_expression_and_same_named_incoming_fk_remain_admitted():
    from cryptalis._sqlalchemy_search import _frame_expressions
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        model = source.document['lock']['models'][0]
        field = model['fields'][0]
        table, frame, definition, _, expression = _frame_policy_snapshot(owner, source)
        canonical, flattened, *_ = _frame_expressions(field, owner.dialect.identifier_preparer.quote)
        assert expression == flattened, expression
        assert expression != canonical
        with owner.connect() as c:
            identities = c.exec_driver_sql(
                'SELECT t.relname, co.contype FROM pg_catalog.pg_constraint co '
                'JOIN pg_catalog.pg_class t ON t.oid=co.conrelid '
                'WHERE co.conname=%s AND (co.conrelid=pg_catalog.to_regclass(%s) '
                'OR co.confrelid=pg_catalog.to_regclass(%s)) ORDER BY t.relname',
                (frame, table, table)).all()
        assert [tuple(row) for row in identities] == [('customer', 'c'), ('z_frame_reference', 'f')]
        binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        restatements = [item for item in binding.document['restatements']
                        if item['model'] == model['table_id'] and item['name'] == frame]
        assert len(restatements) == 1
        assert restatements[0]['definition'] == definition
        assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
    finally:
        owner.dispose()


@pytest.mark.parametrize('old_bound,new_bound', [('>= 74', '>= 73'),
                                               ('<= 16777290', '<= 16777291')])
def test_restore_adoption_refuses_weaker_bounds_with_original_journal(old_bound, new_bound):
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    changed = False
    try:
        # Establish valid admission before changing only the framing policy.
        assert r.plan(source, owner, pin=pin, keys=keys, approval=approval()).source_plan_digest == source.digest
        table, frame, definition, before, _ = _frame_policy_snapshot(owner, source)
        weaker = definition.replace(old_bound, new_bound)
        assert weaker != definition
        _replace_frame_policy(owner, table, frame, weaker)
        changed = True
        assert _frame_policy_snapshot(owner, source)[3] == before
        with pytest.raises(m.TransitionFailure):
            r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        assert _frame_policy_snapshot(owner, source)[3] == before
    finally:
        try:
            if changed:
                _replace_frame_policy(owner, table, frame, definition)
        finally:
            owner.dispose()


@pytest.mark.parametrize('old_bound,new_bound', [('>= 74', '>= 73'),
                                               ('<= 16777290', '<= 16777291')])
def test_previously_adopted_weaker_bounds_cannot_admit_deployment(old_bound, new_bound):
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    changed = False
    try:
        binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        table, frame, definition, before, _ = _frame_policy_snapshot(owner, source)
        weaker = definition.replace(old_bound, new_bound)
        assert weaker != definition
        document = binding.document
        item = next(item for item in document['restatements'] if item['name'] == frame)
        item['definition'] = weaker
        item['observed_digest'] = m._hash(weaker)
        # This models an old binding that finite malformed-frame probes could
        # issue. Its source journal and host approval remain unchanged.
        assert item['probe'] == 'rejected-malformed-frames'
        _replace_frame_policy(owner, table, frame, weaker)
        changed = True
        assert _frame_policy_snapshot(owner, source)[3] == before
        with pytest.raises(m.TransitionFailure):
            previous = r.RestoreBinding(_canonical(document))
            m.check_deployment(source, owner, pin=pin, restore=previous)
        assert _frame_policy_snapshot(owner, source)[3] == before
    finally:
        try:
            if changed:
                _replace_frame_policy(owner, table, frame, definition)
        finally:
            owner.dispose()


AUTHORITY_FAULTS=['own_digest']
if MANIFEST['rewrapped'] or MANIFEST['payload_rotated'] or MANIFEST['search_rotated']:
    AUTHORITY_FAULTS+=['missing_ancestor','wrong_successor','own_proof']
if MANIFEST['payload_rotated'] or MANIFEST['search_rotated']:
    AUTHORITY_FAULTS+=['counter_type','missing_source_ancestor']


@pytest.mark.parametrize('fault',AUTHORITY_FAULTS)
def test_restore_authority_refusal_precedes_probes_and_providers(fault,monkeypatch):
    source,pin=artifacts()
    owner=engine('CRYPTALIS_TEST_DATABASE_URL')
    journal=f'"{MANIFEST["journal_schema"]}"."_cryptalis_journal"'
    identity=source.operation_id
    if fault in ('missing_ancestor','missing_source_ancestor','wrong_successor'):
        index=-2 if fault=='missing_source_ancestor' else -1
        identity=uuid.UUID(source.document['predecessors'][index]['operation_id'])
    with owner.connect() as c:
        saved=c.exec_driver_sql(f'SELECT plan_digest,state FROM {journal} WHERE operation_id=%s',(identity,)).one()
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(True)
        raise AssertionError('authority refusal must precede probes and provider work')
    monkeypatch.setattr(r,'_probe_frame_checks',forbidden)
    try:
        with owner.begin() as c:
            changed=json.loads(json.dumps(saved[1]))
            if fault in ('missing_ancestor','missing_source_ancestor'):
                c.exec_driver_sql(f'DELETE FROM {journal} WHERE operation_id=%s',(identity,))
            elif fault=='own_digest':
                c.exec_driver_sql(f'UPDATE {journal} SET plan_digest=%s WHERE operation_id=%s',('0'*64,identity))
            else:
                if fault=='wrong_successor':changed['superseded_by']['plan_digest']='0'*64
                if fault=='own_proof':changed[source.document['kind']+'_plan_digest']='0'*64
                if fault=='counter_type':next(iter(changed['models'].values()))['rows']=True
                c.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',(json.dumps(changed),identity))
        code=('restored_journal_mismatch' if fault=='own_digest' else
              'predecessor_chain_changed' if fault in ('missing_ancestor','missing_source_ancestor','wrong_successor') else
              source.document['kind']+'_state_changed')
        with pytest.raises(m.TransitionFailure,match=code):
            r.plan(source,owner,pin=pin,keys=forbidden,approval=approval())
        assert calls==[]
    finally:
        with owner.begin() as c:
            c.exec_driver_sql(f'DELETE FROM {journal} WHERE operation_id=%s',(identity,))
            c.exec_driver_sql(f'INSERT INTO {journal} VALUES (%s,%s,%s::jsonb)',(identity,saved[0],json.dumps(saved[1])))
        owner.dispose()


@pytest.mark.parametrize('privilege',['journal_update','journal_column_update','schema_create','database_create','public_column_acl'])
def test_restore_rejects_unsafe_privileges_before_effectful_verification(privilege,monkeypatch):
    source,pin=artifacts()
    owner=engine('CRYPTALIS_TEST_DATABASE_URL')
    quote=owner.dialect.identifier_preparer.quote_identifier
    role=quote(MANIFEST['runtime_role'])
    journal=f'{quote(MANIFEST["journal_schema"])}.{quote(m.JOURNAL)}'
    table=f'{quote(SCHEMA)}.customer'
    grant,revoke={
        'journal_update':(f'GRANT UPDATE ON {journal} TO {role}',f'REVOKE UPDATE ON {journal} FROM {role}'),
        'journal_column_update':(f'GRANT UPDATE (state) ON {journal} TO {role}',f'REVOKE UPDATE (state) ON {journal} FROM {role}'),
        'schema_create':(f'GRANT CREATE ON SCHEMA {quote(SCHEMA)} TO {role}',f'REVOKE CREATE ON SCHEMA {quote(SCHEMA)} FROM {role}'),
        'database_create':(f'GRANT CREATE ON DATABASE {quote(MANIFEST["database"])} TO {role}',f'REVOKE CREATE ON DATABASE {quote(MANIFEST["database"])} FROM {role}'),
        'public_column_acl':(f'GRANT SELECT (name) ON {table} TO PUBLIC',f'REVOKE SELECT (name) ON {table} FROM PUBLIC'),
    }[privilege]
    calls=[]
    def forbidden(*args,**kwargs):
        calls.append(True)
        raise AssertionError('unsafe privilege refusal must precede probes and provider work')
    monkeypatch.setattr(r,'_probe_frame_checks',forbidden)
    try:
        with owner.begin() as c:c.exec_driver_sql(grant)
        with pytest.raises(m.TransitionFailure,match='unsafe_runtime|source_metadata_changed'):
            r.plan(source,owner,pin=pin,keys=forbidden,approval=approval())
        assert calls==[]
    finally:
        with owner.begin() as c:c.exec_driver_sql(revoke)
        owner.dispose()


@pytest.mark.parametrize('privilege',['journal_column_update','public_column_acl'])
def test_adopted_attachment_refuses_later_privilege_drift(privilege):
    source,pin=artifacts()
    owner=engine('CRYPTALIS_TEST_DATABASE_URL')
    binding=r.plan(source,owner,pin=pin,keys=keys,approval=approval())
    quote=owner.dialect.identifier_preparer.quote_identifier
    if privilege=='journal_column_update':
        table=f'{quote(MANIFEST["journal_schema"])}.{quote(m.JOURNAL)}'
        grant=f'GRANT UPDATE (state) ON {table} TO {quote(MANIFEST["runtime_role"])}'
        revoke=f'REVOKE UPDATE (state) ON {table} FROM {quote(MANIFEST["runtime_role"])}'
    else:
        grant=f'GRANT SELECT (name) ON {quote(SCHEMA)}.customer TO PUBLIC'
        revoke=f'REVOKE SELECT (name) ON {quote(SCHEMA)}.customer FROM PUBLIC'
    try:
        with owner.begin() as c:c.exec_driver_sql(grant)
        with pytest.raises(m.TransitionFailure,match='unsafe_runtime|source_metadata_changed'):
            m.check_deployment(source,owner,pin=pin,restore=binding)
    finally:
        with owner.begin() as c:c.exec_driver_sql(revoke)
        owner.dispose()


@pytest.mark.skipif(not (MANIFEST['payload_rotated'] or MANIFEST['search_rotated']),
                    reason='requires a retained pre-rotation generation')
def test_valid_old_generation_frame_cannot_enter_a_rotated_restore():
    source,pin=artifacts()
    fixture=MANIFEST['pre_rotation_frame']
    identity=uuid.UUID(fixture['record_id'])
    retained=base64.b64decode(fixture['frame'])
    assert independent_open(retained,MANIFEST['descriptor'],TENANT,identity)=='edited while protected'
    owner=engine('CRYPTALIS_TEST_DATABASE_URL')
    table=f'"{SCHEMA}".customer'
    with owner.connect() as c:
        current=c.exec_driver_sql(f'SELECT name FROM {table} WHERE id=%s',(identity,)).scalar_one()
    try:
        with owner.begin() as c:c.exec_driver_sql(f'UPDATE {table} SET name=%s WHERE id=%s',(retained,identity))
        with pytest.raises(m.TransitionFailure,match='generation_mismatch'):
            r.plan(source,owner,pin=pin,keys=keys,approval=approval())
    finally:
        with owner.begin() as c:c.exec_driver_sql(f'UPDATE {table} SET name=%s WHERE id=%s',(current,identity))
        owner.dispose()


def test_doctor_refuses_source_incompatible_binding_before_connection(tmp_path):
    from test_cli import _run_cli
    from test_doctor_cli import diagnostic, doctor_arguments, doctor_inputs
    source, pin = artifacts()
    owner = engine('CRYPTALIS_TEST_DATABASE_URL')
    try:
        binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
        document = binding.document
        document['restatements'][0]['definition'] = 'CHECK (true)'
        document['restatements'][0]['observed_digest'] = hashlib.sha256(_canonical('CHECK (true)')).hexdigest()
        bad = r.RestoreBinding(_canonical(document))
        paths = doctor_inputs(SimpleNamespace(plan=source, pin=pin), tmp_path)
        binding_path = tmp_path / 'binding.json'
        binding_path.write_bytes(bad.artifact)
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_DOCTOR_INPUT')
        diagnostic(_run_cli(*doctor_arguments(paths), '--restore-binding', str(binding_path)),
                   2, 'UNKNOWN', 'restored_definition_restatement_unsupported')
    finally:
        owner.dispose()


def test_restored_cluster_completes_adopted_lifecycle(tmp_path, monkeypatch, capsys):
    source, pin = artifacts()
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    mapping, Customer = customer_mapping()
    binding = r.plan(source, owner, pin=pin, keys=keys, approval=approval())
    assert m.check_deployment(source, owner, pin=pin, restore=binding) is None
    observed_status = m.status(source, owner, pin=pin, restore=binding)
    assert observed_status.phase == 'ACTIVE' and observed_status.runtime_metadata_matches
    assert observed_status.verification == 'NOT_PERFORMED'
    with runtime.connect() as c:
        assert m.check_attachment(c, source.lock_bytes, (source, pin, binding)) is None
    assert m.diagnose_deployment(source, runtime, pin=pin, restore=binding) is None
    from test_cli import _run_cli
    from test_doctor_cli import checks, doctor_arguments, doctor_inputs
    paths = doctor_inputs(SimpleNamespace(plan=source, pin=pin), tmp_path)
    binding_path = tmp_path / 'binding.json'
    binding_path.write_bytes(binding.artifact)
    observed = _run_cli(*doctor_arguments(paths), '--restore-binding', str(binding_path))
    assert observed.returncode == 0 and observed.stderr == ''
    checks(json.loads(observed.stdout), 'PASS')
    sessions = attach(mapping, runtime, lock=source.lock_bytes, keys=keys, deployment=(source, pin, binding))
    with sessions(tenant_id=TENANT) as session:
        observed = {str(row.id): [str(row.tenant_id), row.name] for row in session.scalars(select(Customer))}
        found = [row.id for row in session.scalars(
            select(Customer).where(Customer.name == 'edited while protected'))]
    assert observed == MANIFEST['expected']
    assert found == [uuid.UUID(int=101)]
    with sessions(tenant_id=TENANT) as session:
        session.get(Customer, uuid.UUID(int=101)).name = 'edited on restored copy'
        session.commit()
        session.add(Customer(id=uuid.UUID(int=1000), tenant_id=TENANT,
                             name='added on restored copy', label='restored'))
        session.commit()
        session.delete(session.get(Customer, uuid.UUID(int=999)))
        session.commit()
    runtime.dispose()
    proposal = d.plan(source, owner, source_pin=pin, keys=keys,
                      plaintext_runtime_role=os.environ['CRYPTALIS_FRESH_PLAINTEXT_ROLE'],
                      backfill_rows_per_second=1000, verify_rows_per_second=1000,
                      temporary_bytes_per_row=700, wal_bytes_per_row=700, restore=binding)
    assert proposal.document['restore']['adoption_id'] == binding.document['adoption_id']
    reverse_pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
    consent = d.PlaintextApproval(proposal.target_id, proposal.operation_id, proposal.digest, True,
                                  'fresh-cluster retained backup recovery')
    maintenance = m.MaintenanceApproval('fresh-cluster qualification stopped and excluded writers', 3600)
    try:
        assert d.status(proposal, owner, pin=reverse_pin).phase == 'PREPARED'
        assert d.apply(proposal, owner, keys=keys, pin=reverse_pin, approval=maintenance,
                       consent=consent, chunk_size=2).phase == 'PLAINTEXT_PENDING'
        assert d.status(proposal, owner, pin=reverse_pin).phase == 'PLAINTEXT_PENDING'
        assert d.apply(proposal, owner, keys=keys, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVATING'),
                       approval=maintenance, consent=consent, chunk_size=2,
                       until='PLAINTEXT_ACTIVE').phase == 'PLAINTEXT_ACTIVE'
        assert d.status(proposal, owner, pin=replace(reverse_pin, phase='PLAINTEXT_ACTIVE')).runtime_metadata_matches
        removal = d.RemovalApproval(proposal.target_id, proposal.operation_id, proposal.digest,
                                    'fresh-cluster package-free psycopg workload',
                                    'fresh-cluster retained backup recovery', True)
        assert d.remove(proposal, owner, pin=replace(reverse_pin, phase='REMOVING'),
                        approval=maintenance, removal=removal, consent=consent).phase == 'REMOVED'
        assert d.check_removed(proposal, owner, pin=replace(reverse_pin, phase='REMOVED')) is None
        removed_status = d.status(proposal, owner, pin=replace(reverse_pin, phase='REMOVED'))
        assert removed_status.phase == 'REMOVED' and removed_status.runtime_metadata_matches
        assert removed_status.committed_rows is removed_status.committed_chunks is None
        expected = dict(MANIFEST['expected'])
        expected[str(uuid.UUID(int=101))] = [str(TENANT), 'edited on restored copy']
        expected[str(uuid.UUID(int=1000))] = [str(TENANT), 'added on restored copy']
        del expected[str(uuid.UUID(int=999))]
        with psycopg.connect(**environment('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')) as c:
            observed = {str(identity): [str(tenant), value] for identity, tenant, value in c.execute(
                f'SELECT id, tenant_id, name FROM "{SCHEMA}".customer')}
            kind, limit = c.execute('SELECT data_type, character_maximum_length FROM information_schema.columns WHERE table_schema=%s '
                             'AND table_name=%s AND column_name=%s', (SCHEMA, 'customer', 'name')).fetchone()
        assert observed == expected
        assert kind == ('character varying' if MANIFEST.get('native_type') == 'varchar' else 'text')
        assert limit == MANIFEST.get('native_limit')
        assert_source_metadata(SimpleNamespace(owner=owner, schema=SCHEMA), MANIFEST['runtime_role'])
        with psycopg.connect(**environment('CRYPTALIS_TEST_DATABASE_URL')) as c:
            assert c.execute('SELECT pg_catalog.to_regclass(%s)',
                             (f'{MANIFEST["journal_schema"]}.{m.JOURNAL}',)).fetchone()[0] is None
        if os.environ.get('CRYPTALIS_RETAINED_OBLIGATIONS_READER_ARTIFACT'):
            retained_status_after_removal(source, proposal, replace(reverse_pin, phase='REMOVED'),
                                          owner, tmp_path, monkeypatch, capsys)
    finally:
        owner.dispose()
        mapping.dispose()



def retained_status_after_removal(source, reverse, pin, owner, tmp_path, monkeypatch, capsys):
    """Bind actual restored-backup references without claiming a current drill."""
    from dataclasses import asdict
    import sys
    from types import ModuleType
    from cryptalis.cli_host import RetainedBackupObligation, RetainedObligationsContext
    from cryptalis.crypto import Keyring
    from test_operational_cli import invoke

    reader = Path(os.environ['CRYPTALIS_RETAINED_OBLIGATIONS_READER_ARTIFACT'])
    dump = WORKDIR / 'protected.sql'
    assert reader.is_file() and dump.is_file()
    dump_digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    reader_digest = hashlib.sha256(reader.read_bytes()).hexdigest()
    retained = RetainedBackupObligation(uuid.uuid4(), source.artifact, dump_digest, reader_digest, None)
    context = RetainedObligationsContext(reverse.operation_id, reverse.digest, (retained,))
    module = ModuleType('fresh_retained_status_' + uuid.uuid4().hex)
    module.factory = lambda: context
    monkeypatch.setitem(sys.modules, module.__name__, module)
    plan_path, pin_path = tmp_path / 'removed-plan.json', tmp_path / 'removed-pin.json'
    plan_path.write_bytes(reverse.artifact)
    pin_path.write_text(json.dumps(asdict(pin), default=str))
    runtime_file = Path.home() / '.cryptalis-test-runtime-url'
    assert runtime_file.is_file()
    table = f'"{SCHEMA}".customer'
    with owner.connect() as connection:
        before = connection.exec_driver_sql(f'SELECT * FROM {table} ORDER BY id').all()
        catalog = m._facts(connection, reverse.document['lock']['models'][0])
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('retained-obligation status must not prepare provider keys')
    with monkeypatch.context() as no_keys:
        no_keys.setattr(Keyring, 'prepare', forbidden)
        code, text, error = invoke(capsys, 'status', str(plan_path), '--pin', str(pin_path),
            '--database-url-file', str(runtime_file), '--host-context', module.__name__ + ':factory', '--json')
    assert code == 0 and error == '' and calls == []
    summary = json.loads(text)
    obligations = summary['retained_obligations']
    assert summary['phase'] == 'REMOVED' and summary['runtime_metadata_matches'] is True
    assert obligations['status'] == obligations['inventory_completeness'] == 'UNKNOWN'
    assert obligations['reader_availability'] == obligations['provider_availability'] == 'UNKNOWN'
    assert obligations['verification'] == 'NOT_PERFORMED' and obligations['reported_count'] == 1
    record = obligations['records'][0]
    assert record['source_operation_id'] == str(source.operation_id) and record['source_plan_digest'] == source.digest
    assert record['required_policy_digests'] == source.document['key_policies']
    assert record['dump_sha256'] == dump_digest and record['reader_sha256'] == reader_digest
    assert record['drill_sha256'] is None and record['provenance'] == 'HOST_DECLARED_DIGEST_REFERENCES'
    with owner.connect() as connection:
        assert connection.exec_driver_sql(f'SELECT * FROM {table} ORDER BY id').all() == before
        assert m._facts(connection, reverse.document['lock']['models'][0]) == catalog
        assert connection.exec_driver_sql('SELECT pg_catalog.to_regclass(%s)',
            (f'{MANIFEST["journal_schema"]}.{m.JOURNAL}',)).scalar_one() is None
    receipt = os.environ.get('CRYPTALIS_RETAINED_OBLIGATIONS_RECEIPT')
    if receipt:
        with Path(receipt).open('x') as stream:
            json.dump({'scope': 'genuine_restored_backup_removed_status', 'source_operation_id': str(source.operation_id),
                'source_plan_digest': source.digest, 'required_policy_digests': source.document['key_policies'],
                'dump_sha256': dump_digest, 'reader_sha256': reader_digest, 'drill_sha256': None,
                'status': obligations, 'journal_absent': True, 'provider_preparations': len(calls),
                'boundary': 'Actual fresh backup recovery and latest native removal precede this status; references remain host declarations, availability and completeness UNKNOWN',
                'gates': 'all seven UNKNOWN'}, stream, indent=2)
            stream.write('\n')
