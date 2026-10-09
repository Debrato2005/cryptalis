"""Native PostgreSQL, an independent CF1 decoder, and process death are oracles."""
import asyncio
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import UUID, uuid4, uuid5

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import psycopg
from psycopg import sql
import pytest
from sqlalchemy import Column, Index, MetaData, Table, Text, Uuid, create_engine, select, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import registry, sessionmaker

from cryptalis.crypto import KeyContext, KeyPolicy, Keyring
from cryptalis.crypto.keys import WrappedRoot
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
from cryptalis.sqlalchemy import attach, PolicyMismatch

DOMAIN, TABLE_ID, FIELD_ID, TENANT = (UUID(int=i) for i in range(501, 505))
PROVIDER = UUID(int=505)


class PublicFixtureProvider:
    """PUBLIC TEST ROOTS. No custody claim, persisted secret, or product provider."""
    provider_id = PROVIDER
    def unwrap(self, wrapper, context):
        assert wrapper.context == context and wrapper.provider_id == PROVIDER
        return hashlib.sha256(('PUBLIC MIGRATION FIXTURE:' + str(context)).encode()).digest()
    async def unwrap_async(self, wrapper, context):
        return self.unwrap(wrapper, context)


def keys(tenant):
    provider = PublicFixtureProvider()
    contexts = [KeyContext(DOMAIN, tenant, p, uuid5(DOMAIN, f'{tenant}:{p}'), 1) for p in ('payload', 'search')]
    wrappers = tuple(WrappedRoot(PROVIDER, c, b'PUBLIC TEST WRAPPER') for c in contexts)
    return Keyring(KeyPolicy(DOMAIN, tenant, wrappers, 1, 1), {PROVIDER: provider})


def independent_open(body, descriptor, tenant, record, payload_context=None):
    """Separate HKDF/HMAC/framing path; same qualified AEAD primitive only."""
    if body is None:
        return None
    def pack(*parts):
        return len(parts).to_bytes(4, 'big') + b''.join(len(p).to_bytes(4, 'big') + p for p in parts)
    def derive(purpose, info):
        context = next(w.context for w in keys(tenant).policy.wrappers if w.context.purpose == purpose)
        if purpose=='payload' and payload_context is not None: context=payload_context
        root = PublicFixtureProvider().unwrap(WrappedRoot(PROVIDER, context, b'PUBLIC TEST WRAPPER'), context)
        salt = hashlib.sha256(pack(b'CF1/root', DOMAIN.bytes, tenant.bytes, context.root_id.bytes, context.generation.to_bytes(4, 'big'))).digest()
        prk = hmac.digest(salt, root, 'sha256')
        return hmac.digest(prk, info + b'\x01', 'sha256')
    assert body[:6] == bytes.fromhex('434631000101')
    assert int.from_bytes(body[6:10],'big')==(payload_context.generation if payload_context else 1)
    assert body[10:14] == bytes.fromhex('00000001')
    header = body[:46]
    key = derive('payload', pack(b'CF1/payload-key', FIELD_ID.bytes, record.bytes))
    digest = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).digest()
    aad = pack(b'CF1/payload', DOMAIN.bytes, tenant.bytes, FIELD_ID.bytes, record.bytes, digest, header)
    value = AESGCMSIV(key).decrypt(body[46:58], body[58:], aad)
    search_key = derive('search', pack(b'CF1/search-key', FIELD_ID.bytes, b'utf8-exact/v1', b'identity/v1', b'equality'))
    assert hmac.compare_digest(header[14:46], hmac.digest(search_key, pack(b'equality', value), 'sha256'))
    return value.decode('utf8')


def engine(variable):
    return create_engine('postgresql+psycopg://', hide_parameters=True,
                         creator=lambda: psycopg.connect(os.environ[variable]))


@contextmanager
def application(rows=7, unique=True):
    owner, runtime = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'cryptalis_migration_' + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('customer', mapping.metadata, Column('id', Uuid, primary_key=True, autoincrement=False),
                  Column('tenant_id', Uuid, nullable=False), Column('name', Text(collation='C')),
                  Column('label', Text))
    Index('native_name', table.c.tenant_id, table.c.name, unique=unique)
    class Customer: pass
    mapping.map_imperatively(Customer, table)
    declaration = {'schema':'cryptalis.protection/v1','profile':'cf1','domain_id':str(DOMAIN),
        'models':[{'model':'Customer','table_id':str(TABLE_ID),'tenancy':{'column':'tenant_id'},
            'fields':[{'name':'name','field_id':str(FIELD_ID),'protect':True,
                'queries':['equality','unique'] if unique else ['equality'],
                'accept_leakage':['equality','unique'] if unique else ['equality']}]}]}
    with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
        role = c.execute('select current_user').fetchone()[0]
    try:
        with owner.begin() as c: c.execute(text(f'CREATE SCHEMA "{schema}"'))
        mapping.metadata.create_all(owner)
        with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as c:
            c.execute(sql.SQL('REVOKE ALL ON SCHEMA {} FROM PUBLIC').format(sql.Identifier(schema)))
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema), sql.Identifier(role)))
            c.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON {}.customer TO {}').format(sql.Identifier(schema), sql.Identifier(role)))
        source = {UUID(int=i+100): (TENANT, [None, '', '雪😀', 'e\u0301', 'é', 'exact', 'trailing '][i % 7] if i < 7 else f'user-{i}@example.invalid') for i in range(rows)}
        with sessionmaker(runtime)() as s:
            s.add_all(Customer(id=k, tenant_id=t, name=v, label=f'label-{k.int}') for k,(t,v) in source.items())
            s.commit()
        m = importlib.import_module('cryptalis.migration')
        proposal = m.plan(json.dumps(declaration).encode(), mapping, owner,
            writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='owned synthetic application'),)),
            search_reviews=(SearchReview(FIELD_ID,False,'synthetic unbounded names'),),
            keys=keys, runtime_role=role, target_id=uuid4(),
            backfill_rows_per_second=1000, verify_rows_per_second=1000,
            temporary_bytes_per_row=700, wal_bytes_per_row=2000)
        pin = m.DeploymentPin(proposal.target_id, proposal.operation_id, proposal.digest, 'PREPARED')
        yield SimpleNamespace(m=m, owner=owner, runtime=runtime, schema=schema, mapping=mapping,
            table=table, Customer=Customer, source=source, plan=proposal, pin=pin, role=role,
            approval=m.MaintenanceApproval('test operator stopped inventoried workers and excluded owner writers', 3600))
    finally:
        runtime.dispose()
        with owner.begin() as c: c.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        owner.dispose(); mapping.dispose()


def run(app, until='PENDING', pin=None, chunk_size=2, key_resolver=None):
    return app.m.apply(app.plan, app.owner, keys=key_resolver or keys, pin=pin or app.pin,
                       approval=app.approval, chunk_size=chunk_size, until=until)


def frames(app, switched=False):
    column = 'name' if switched else '_cryptalis_' + FIELD_ID.hex
    with app.owner.connect() as c:
        return {r[0]:bytes(r[2]) if r[2] is not None else None for r in c.exec_driver_sql(
            f'SELECT id, tenant_id, "{column}" FROM "{app.schema}".customer ORDER BY id')}


def publish(app):
    app.pin = replace(app.pin, phase='ACTIVATING')
    result = run(app, until='ACTIVE')
    app.pin = replace(app.pin, phase='ACTIVE')
    return result


def test_existing_plaintext_migrates_and_native_sync_async_application_resumes():
    with application() as app:
        assert run(app).phase == 'PENDING'
        descriptor = json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
        original = dict(app.source)
        for identity, body in frames(app, True).items():
            tenant, value = original[identity]
            assert independent_open(body, descriptor, tenant, identity) == value
        with pytest.raises(PolicyMismatch):
            attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys)
        publish(app)
        sessions = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys, deployment=(app.plan,app.pin))
        with sessions(tenant_id=TENANT) as s:
            assert {r.id:(r.tenant_id,r.name) for r in s.scalars(select(app.Customer))} == original
            row=s.get(app.Customer,UUID(int=101)); row.name='after switch'; s.commit()
            assert s.scalar(select(app.Customer.name).where(app.Customer.name=='after switch'))=='after switch'
            s.delete(s.get(app.Customer,UUID(int=106))); s.commit()
            s.add(app.Customer(id=uuid4(),tenant_id=TENANT,name='new value')); s.commit()
        async def check():
            async_engine=create_async_engine('postgresql+psycopg://',hide_parameters=True,
                async_creator=lambda: psycopg.AsyncConnection.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']))
            fresh=registry(metadata=MetaData(schema=app.schema))
            t=Table('customer',fresh.metadata,Column('id',Uuid,primary_key=True,autoincrement=False),Column('tenant_id',Uuid,nullable=False),Column('name',Text(collation='C')),Column('label',Text))
            class Customer: pass
            fresh.map_imperatively(Customer,t)
            try:
                factory=await attach(fresh,async_engine,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
                async with factory(tenant_id=TENANT) as s:
                    row=await s.get(Customer,UUID(int=101)); assert row.name=='after switch'
                    row.name='async edit'; await s.commit()
                    assert await s.scalar(select(Customer.name).where(Customer.name=='async edit'))=='async edit'
            finally: await async_engine.dispose(); fresh.dispose()
        asyncio.run(check())
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',(app.schema,'customer','name')).scalar_one()=='bytea'
            assert c.exec_driver_sql('SELECT count(*) FROM information_schema.columns WHERE table_schema=%s AND table_name=%s',(app.schema,'customer')).scalar_one()==4


@pytest.mark.parametrize('phase',['EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'])
def test_durable_phase_resume_preserves_committed_ciphertext(phase):
    with application() as app:
        if phase=='ACTIVE': run(app); publish(app)
        else: run(app,phase)
        before=frames(app,phase in ('PENDING','ACTIVE'))
        run(app,'ACTIVE' if phase=='ACTIVE' else 'PENDING')
        after=frames(app,True)
        assert before==after or phase=='EXPANDED'
        assert len(after)==len(app.source)


@pytest.mark.parametrize('attack',['tag','missing','null','source','generation','index','fence'])
def test_full_verification_refuses_corruption_and_never_switches(attack):
    with application() as app:
        run(app,'BACKFILLED')
        payload='_cryptalis_'+FIELD_ID.hex
        with app.owner.begin() as c:
            if attack=='tag': c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{payload}"=set_byte("{payload}",octet_length("{payload}")-1,1) WHERE id=%s',(UUID(int=103),))
            if attack=='missing': c.exec_driver_sql(f'DELETE FROM "{app.schema}".customer WHERE id=%s',(UUID(int=103),))
            if attack=='null': c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{payload}"=NULL WHERE id=%s',(UUID(int=103),))
            if attack=='source': c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',('changed',UUID(int=103)))
            if attack=='generation': c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "{payload}"=set_byte("{payload}",9,2) WHERE id=%s',(UUID(int=103),))
            if attack=='index': c.exec_driver_sql(f'DROP INDEX "{app.schema}"."{payload}_eq"')
            if attack=='fence': c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER ALL')
        with pytest.raises(app.m.TransitionFailure): run(app)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',(app.schema,'customer','name')).scalar_one()=='text'


def test_verification_is_repeated_at_switch_instead_of_trusting_a_marker():
    with application() as app:
        run(app,'VERIFIED')
        with app.owner.begin() as c: c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',('changed after verify',UUID(int=103)))
        with pytest.raises(app.m.TransitionFailure): run(app)


def test_runtime_writes_are_refused_between_chunks_and_after_crash():
    with application() as app:
        run(app,'EXPANDED')
        for command in ('INSERT INTO {t} (id,tenant_id,name) VALUES (%s,%s,%s)',
                        'UPDATE {t} SET name=%s WHERE id=%s', 'DELETE FROM {t} WHERE id=%s'):
            params=(uuid4(),TENANT,'paused') if command.startswith('INSERT') else ('paused',UUID(int=103)) if command.startswith('UPDATE') else (UUID(int=103),)
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
                with pytest.raises(psycopg.Error) as exc:
                    c.execute(command.format(t=f'"{app.schema}".customer'),params)
                assert exc.value.sqlstate=='55000'
        run(app)
        assert len(frames(app,True))==len(app.source)


def test_older_database_snapshot_cannot_override_external_current_pin(tmp_path):
    with application() as app:
        run(app,'BACKFILLED')
        # A real pg_dump/psql restore of only our own schema; keep URLs in env.
        parsed=psycopg.conninfo.conninfo_to_dict(os.environ['CRYPTALIS_TEST_DATABASE_URL'])
        env=dict(os.environ,PGHOST=parsed.get('host',''),PGPORT=parsed.get('port','5432'),PGUSER=parsed['user'],PGPASSWORD=parsed['password'],PGDATABASE=parsed['dbname'])
        snapshot=tmp_path/'snapshot.sql'
        with snapshot.open('wb') as stream:
            result=subprocess.run(['pg_dump','--schema='+app.schema,'--no-owner','--no-privileges'],env=env,stdout=stream,stderr=subprocess.PIPE)
        assert result.returncode==0, 'pg_dump failed (diagnostics withheld)'
        run(app); publish(app)
        with app.owner.begin() as c: c.exec_driver_sql(f'DROP SCHEMA "{app.schema}" CASCADE')
        result=subprocess.run(['psql','-X','-v','ON_ERROR_STOP=1','-f',str(snapshot)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        assert result.returncode==0, 'schema restore failed (diagnostics withheld)'
        with pytest.raises(app.m.TransitionFailure,match='restored_state_behind_external_pin'): run(app,'ACTIVE')
        with pytest.raises(app.m.TransitionFailure): app.m.check_deployment(app.plan,app.owner,pin=app.pin)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',(app.schema,'customer','name')).scalar_one()=='text'


def child(app, tmp_path, phase='PENDING', pause=False):
    artifact=tmp_path/'plan.json'; artifact.write_bytes(app.plan.artifact)
    return subprocess.Popen([sys.executable,str(Path(__file__).with_name('migration_worker.py')),
        str(artifact),phase,app.pin.phase,'pause' if pause else 'exit'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)


@pytest.mark.parametrize('phase',['EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'])
def test_sigkill_then_independent_process_resume(phase,tmp_path):
    with application() as app:
        if phase=='ACTIVE': run(app); app.pin=replace(app.pin,phase='ACTIVATING')
        process=child(app,tmp_path,phase,True)
        try:
            assert process.stdout.readline().strip()==phase
            before=frames(app,phase in ('PENDING','ACTIVE'))
            os.kill(process.pid,signal.SIGKILL); assert process.wait(timeout=10)==-signal.SIGKILL
            resumed=child(app,tmp_path,'ACTIVE' if phase=='ACTIVE' else 'PENDING')
            stdout,stderr=resumed.communicate(timeout=20)
            assert resumed.returncode==0,stderr
            assert stdout.strip()==('ACTIVE' if phase=='ACTIVE' else 'PENDING')
            after=frames(app,True)
            assert before==after or phase=='EXPANDED'
            assert len(after)==len(app.source)
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)


def test_sigkill_inside_chunk_rolls_back_data_and_marker(tmp_path):
    with application() as app:
        run(app,'EXPANDED')
        with app.owner.begin() as c:
            # Real PostgreSQL delay keeps the SECOND chunk in flight. Trigger
            # installation is intentional test-only failure injection.
            c.exec_driver_sql(f'CREATE FUNCTION "{app.schema}".test_sleep() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.id=\'00000000-0000-0000-0000-000000000066\'::uuid THEN PERFORM pg_sleep(1); END IF; RETURN NEW; END$$')
            c.exec_driver_sql(f'CREATE TRIGGER test_sleep BEFORE UPDATE ON "{app.schema}".customer FOR EACH ROW EXECUTE FUNCTION "{app.schema}".test_sleep()')
            # Account for this known test trigger in the observed schema only;
            # an unrecorded trigger is separately rejected by schema admission.
            from cryptalis.migration import _facts, _guard_facts
            state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
            state['models'][str(TABLE_ID)]['schema']=_facts(c,app.plan.document['lock']['models'][0])
            state['models'][str(TABLE_ID)]['guard']=_guard_facts(c,app.plan,app.plan.document['lock']['models'][0])
            c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb',(json.dumps(state),))
        process=child(app,tmp_path)
        try:
            deadline=time.monotonic()+10
            while True:
                with app.owner.connect() as c:
                    asleep=c.exec_driver_sql("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename=current_user AND wait_event='PgSleep' AND query LIKE %s",(f'UPDATE "{app.schema}"."customer"%',)).scalar_one()
                if asleep: break
                assert time.monotonic()<deadline,'executor did not reach injected PostgreSQL wait'
                time.sleep(.02)
            os.kill(process.pid,signal.SIGKILL); process.wait(timeout=10)
            committed_before=frames(app)
            with app.owner.begin() as c:
                c.exec_driver_sql(f'LOCK TABLE "{app.schema}".customer IN ACCESS EXCLUSIVE MODE')
                state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
                assert state['models'][str(TABLE_ID)]['rows']==2
                assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer WHERE "_cryptalis_{FIELD_ID.hex}" IS NOT NULL').scalar_one()==1
                c.exec_driver_sql(f'DROP TRIGGER test_sleep ON "{app.schema}".customer')
                c.exec_driver_sql(f'DROP FUNCTION "{app.schema}".test_sleep()')
                state['models'][str(TABLE_ID)]['schema']=_facts(c,app.plan.document['lock']['models'][0])
                state['models'][str(TABLE_ID)]['guard']=_guard_facts(c,app.plan,app.plan.document['lock']['models'][0])
                c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb',(json.dumps(state),))
            resumed=child(app,tmp_path); stdout,stderr=resumed.communicate(timeout=20)
            assert resumed.returncode==0,stderr
            assert stdout.strip()=='PENDING'
            assert frames(app,True)[UUID(int=101)]==committed_before[UUID(int=101)]
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=10)


@pytest.mark.parametrize('phase',['EXPANDED','BACKFILLED','VERIFIED','PENDING'])
def test_runtime_reconnect_cannot_write_during_maintenance(phase):
    with application() as app:
        run(app,phase)
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                c.execute(f'UPDATE "{app.schema}".customer SET label=%s WHERE id=%s',('must not be lost',UUID(int=103)))
        with app.owner.connect() as c:
            assert c.exec_driver_sql(f'SELECT label FROM "{app.schema}".customer WHERE id=%s',(UUID(int=103),)).scalar_one()=='label-103'


def test_current_external_pin_rejects_consistent_pending_snapshot(tmp_path):
    with application() as app:
        run(app)
        with app.owner.connect() as c:
            old=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
        publish(app)
        with app.owner.begin() as c:
            c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb',(json.dumps(old),))
        with pytest.raises(app.m.TransitionFailure): run(app,'ACTIVE')


def test_external_publication_unavailable_keeps_runtime_stopped():
    with application() as app:
        run(app)
        with pytest.raises(app.m.TransitionFailure): run(app,'ACTIVE')
        with pytest.raises(PolicyMismatch):
            attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
                c.execute(f'UPDATE "{app.schema}".customer SET label=%s',('paused',))


def test_plan_is_read_only_and_rejects_unsafe_native_schema():
    from cryptalis.manifest.compiler import PlanningRejected
    with application() as app:
        with app.owner.begin() as c: c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN id SET DEFAULT gen_random_uuid()')
        declaration=json.loads(app.plan.lock_bytes)['declaration']
        with pytest.raises(PlanningRejected,match='server_generated_key'):
            app.m.plan(json.dumps(declaration).encode(),app.mapping,app.owner,
                writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='synthetic app'),)),
                search_reviews=(SearchReview(FIELD_ID,False,'unbounded synthetic labels'),),keys=keys,
                runtime_role=app.role,target_id=app.plan.target_id,backfill_rows_per_second=1000,verify_rows_per_second=1000)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT to_regclass(%s)',(f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one()==len(app.source)


def test_concurrent_committed_writes_are_included_and_paused_writes_are_explicit():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    with application(rows=70) as app:
        ready,done=Event(),Event(); committed={}; denied=[]
        def writer():
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
                while not done.is_set():
                    identity=uuid4(); value=f'concurrent-{identity}@example.invalid'
                    try:
                        with c.transaction():
                            c.execute(f'INSERT INTO "{app.schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',(identity,TENANT,value,'concurrent'))
                        committed[identity]=(TENANT,value)
                    except psycopg.Error as exc:
                        assert exc.sqlstate=='55000'; denied.append(exc.sqlstate)
                    ready.set()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(writer)
            assert ready.wait(10)
            try: run(app,'BACKFILLED',chunk_size=2)
            finally: done.set()
            future.result(timeout=10)
        assert committed and denied
        expected=app.source|committed
        app.m.verify(app.plan,app.owner,keys=keys,pin=app.pin,approval=app.approval)
        descriptor=json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]['descriptor']
        assert {identity:(TENANT,independent_open(body,descriptor,TENANT,identity)) for identity,body in frames(app).items()}==expected
        run(app); publish(app)
        sessions=attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))
        with sessions(tenant_id=TENANT) as s:
            identity=uuid4(); s.add(app.Customer(id=identity,tenant_id=TENANT,name='retried after pause')); s.commit()
            assert s.get(app.Customer,identity).name=='retried after pause'


def test_competing_executor_is_refused_without_effects():
    with application() as app:
        from cryptalis.migration import _executor
        with _executor(app.plan,app.owner,app.pin,app.approval):
            with pytest.raises(app.m.TransitionFailure,match='executor_already_running'): run(app)
        assert run(app).committed_rows==len(app.source)


@pytest.mark.parametrize('unsafe',['type','tenancy','domain'])
def test_plan_reuses_compiler_unsafe_configuration_refusals(unsafe):
    from cryptalis.manifest.compiler import PlanningRejected
    from cryptalis.manifest.parser import ManifestInvalid
    with application() as app:
        declaration=json.loads(app.plan.lock_bytes)['declaration']
        if unsafe=='type':
            with app.owner.begin() as c: c.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name TYPE integer USING NULL::integer')
        if unsafe=='tenancy': declaration['models'][0].pop('tenancy')
        reviews=(SearchReview(FIELD_ID,unsafe=='domain','host fixture domain review'),)
        with pytest.raises((PlanningRejected,ManifestInvalid)):
            app.m.plan(json.dumps(declaration).encode(),app.mapping,app.owner,
                writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='synthetic app'),)),
                search_reviews=reviews,keys=keys,runtime_role=app.role,target_id=app.plan.target_id,
                backfill_rows_per_second=1000,verify_rows_per_second=1000)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT to_regclass(%s)',(f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None


def test_source_schema_change_and_key_policy_change_block_resume():
    with application() as app:
        run(app,'EXPANDED')
        with app.owner.begin() as c: c.exec_driver_sql(f'DROP INDEX "{app.schema}".native_name')
        with pytest.raises(app.m.TransitionFailure): run(app)
    with application() as app:
        run(app,'EXPANDED')
        other=lambda tenant: Keyring(replace(keys(tenant).policy,wrappers=tuple(
            replace(w,context=replace(w.context,root_id=uuid4())) for w in keys(tenant).policy.wrappers)),{PROVIDER:PublicFixtureProvider()})
        # A valid but different root policy rejects before any frame update.
        with pytest.raises(app.m.TransitionFailure):
            app.m.apply(app.plan,app.owner,keys=other,pin=app.pin,approval=app.approval)
        assert all(body is None for body in frames(app).values())


def test_active_deployment_rejects_different_keys_before_search_can_hide_rows():
    with application() as app:
        run(app); publish(app)
        different=Keyring(replace(keys(TENANT).policy,wrappers=tuple(
            replace(w,context=replace(w.context,root_id=UUID(int=999))) if w.context.purpose=='search' else w
            for w in keys(TENANT).policy.wrappers)),{PROVIDER:PublicFixtureProvider()})
        sessions=attach(app.mapping,app.runtime,lock=app.plan.lock_bytes,keys=different,deployment=(app.plan,app.pin))
        with pytest.raises(PolicyMismatch):
            with sessions(tenant_id=TENANT) as s:
                # An unpinned search root otherwise silently returns no matches.
                s.scalar(select(app.Customer.name).where(app.Customer.name=='exact'))


def test_stale_prepared_pin_cannot_report_an_active_deployment():
    with application() as app:
        old=app.pin
        run(app); publish(app)
        with pytest.raises(app.m.TransitionFailure): run(app,'ACTIVE',pin=old)


def test_owner_credentials_cannot_replace_planned_runtime_attachment():
    with application() as app:
        run(app); publish(app)
        with pytest.raises(PolicyMismatch):
            attach(app.mapping,app.owner,lock=app.plan.lock_bytes,keys=keys,deployment=(app.plan,app.pin))


def test_lost_commit_reply_is_reconciled_from_terminal_real_transaction():
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        run(app,'EXPANDED')
        # Executor lock COMMIT, journal-inspection COMMIT, then the first
        # backfill chunk COMMIT. Dialect initialization rolls its read back.
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'],3) as (url,dropped):
            faulty=create_engine('postgresql+psycopg://',hide_parameters=True,creator=lambda:psycopg.connect(url))
            try:
                with pytest.raises(app.m.TransitionFailure):
                    app.m.apply(app.plan,faulty,keys=keys,pin=app.pin,approval=app.approval,chunk_size=2)
                assert dropped.wait(5),'proxy did not discard a committed reply'
            finally: faulty.dispose()
        before=frames(app)
        # Inspect terminal marker independently, then resume. The first NULL
        # and empty-string rows share a committed marker; NULL is not a cursor.
        with app.owner.connect() as c:
            state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
            assert state['models'][str(TABLE_ID)]['rows']==2
        run(app)
        after=frames(app,True)
        assert after[UUID(int=101)]==before[UUID(int=101)]
        assert len(after)==len(app.source)


def test_connection_loss_inside_switch_rolls_back_ddl_and_keeps_verified_source():
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        run(app,'VERIFIED')
        before=frames(app)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'],drop_after_sql='DROP COLUMN "name"') as (url,dropped):
            faulty=create_engine('postgresql+psycopg://',hide_parameters=True,creator=lambda:psycopg.connect(url))
            try:
                with pytest.raises(app.m.TransitionFailure):
                    app.m.apply(app.plan,faulty,keys=keys,pin=app.pin,approval=app.approval)
                assert dropped.wait(5)
            finally: faulty.dispose()
        assert frames(app)==before
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',(app.schema,'customer','name')).scalar_one()=='text'
        run(app); assert frames(app,True)==before


@pytest.mark.parametrize('needle,initial_phase',[('ADD COLUMN','PREPARED'),('SELECT "id","tenant_id","name"','BACKFILLED')])
def test_connection_loss_inside_expand_or_verify_never_marks_completion(needle,initial_phase):
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        if initial_phase!='PREPARED': run(app,initial_phase)
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'],drop_after_sql=needle) as (url,dropped):
            faulty=create_engine('postgresql+psycopg://',hide_parameters=True,creator=lambda:psycopg.connect(url))
            try:
                with pytest.raises(app.m.TransitionFailure):
                    app.m.apply(app.plan,faulty,keys=keys,pin=app.pin,approval=app.approval)
                assert dropped.wait(5)
            finally: faulty.dispose()
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=%s',(app.schema,'customer','name')).scalar_one()=='text'
            if initial_phase=='PREPARED':
                assert c.exec_driver_sql('SELECT to_regclass(%s)',(f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None
            else:
                assert c.exec_driver_sql(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').scalar_one()=='BACKFILLED'
        run(app)


def test_abort_before_switch_preserves_native_values_and_runtime_writes():
    with application() as app:
        run(app,'BACKFILLED')
        app.m.abort(app.plan,app.owner,pin=app.pin,approval=app.approval)
        with sessionmaker(app.runtime)() as s:
            assert {r.id:(r.tenant_id,r.name) for r in s.scalars(select(app.Customer))}==app.source
            row=s.get(app.Customer,UUID(int=103)); row.name='native after abort'; s.commit()
            assert row.name=='native after abort'
        app.m.abort(app.plan,app.owner,pin=app.pin,approval=app.approval)
    with application() as app:
        run(app)
        with pytest.raises(app.m.TransitionFailure): app.m.abort(app.plan,app.owner,pin=app.pin,approval=app.approval)


def test_missing_chunk_marker_write_rolls_back_actual_row_changes():
    with application() as app:
        run(app,'EXPANDED')
        from cryptalis.migration import _facts, _guard_facts
        with app.owner.begin() as c:
            c.exec_driver_sql(f'CREATE FUNCTION "{app.schema}".test_lose_marker() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN DELETE FROM "{app.schema}"._cryptalis_journal; RETURN NEW; END$$')
            c.exec_driver_sql(f'CREATE TRIGGER test_lose_marker BEFORE UPDATE ON "{app.schema}".customer FOR EACH ROW EXECUTE FUNCTION "{app.schema}".test_lose_marker()')
            state=c.exec_driver_sql(f'SELECT state FROM "{app.schema}"._cryptalis_journal').scalar_one()
            state['models'][str(TABLE_ID)]['schema']=_facts(c,app.plan.document['lock']['models'][0])
            state['models'][str(TABLE_ID)]['guard']=_guard_facts(c,app.plan,app.plan.document['lock']['models'][0])
            c.exec_driver_sql(f'UPDATE "{app.schema}"._cryptalis_journal SET state=%s::jsonb',(json.dumps(state),))
        with pytest.raises(app.m.TransitionFailure): run(app)
        with app.owner.connect() as c:
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}"._cryptalis_journal').scalar_one()==1
            assert c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer WHERE "_cryptalis_{FIELD_ID.hex}" IS NOT NULL').scalar_one()==0


@pytest.mark.parametrize('change',['target','operation','digest','approval'])
def test_invalid_external_authority_or_missing_writer_approval_has_no_effects(change):
    with application() as app:
        if change=='target': app.pin=replace(app.pin,target_id=uuid4())
        if change=='operation': app.pin=replace(app.pin,operation_id=uuid4())
        if change=='digest': app.pin=replace(app.pin,plan_digest='0'*64)
        if change=='approval': app.approval=replace(app.approval,writer_exclusion='')
        with pytest.raises(app.m.TransitionFailure): run(app)
        with app.owner.connect() as c:
            assert c.exec_driver_sql('SELECT to_regclass(%s)',(f'"{app.schema}"._cryptalis_journal',)).scalar_one() is None
            assert c.exec_driver_sql(f'SELECT id,tenant_id,name FROM "{app.schema}".customer').all()==[(i,t,v) for i,(t,v) in app.source.items()]


def test_runtime_can_read_progress_but_cannot_change_journal_or_ownership():
    with application() as app:
        run(app,'EXPANDED')
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
            assert c.execute(f'SELECT state->>\'phase\' FROM "{app.schema}"._cryptalis_journal').fetchone()==('EXPANDED',)
        for command in (f'UPDATE "{app.schema}"._cryptalis_journal SET state=\'{{}}\'::jsonb',
                        f'ALTER TABLE "{app.schema}"._cryptalis_journal ADD COLUMN forged text',
                        f'ALTER TABLE "{app.schema}".customer DISABLE TRIGGER ALL',
                        f'ALTER TABLE "{app.schema}".customer OWNER TO "{app.role}"'):
            with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
                with pytest.raises(psycopg.errors.InsufficientPrivilege): c.execute(command)
        run(app)


def test_plan_cost_estimates_use_explicit_host_observations():
    with application() as app:
        declaration=json.loads(app.plan.lock_bytes)['declaration']
        measured=app.m.plan(json.dumps(declaration).encode(),app.mapping,app.owner,
            writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='synthetic app'),)),
            search_reviews=(SearchReview(FIELD_ID,False,'reviewed synthetic labels'),),keys=keys,
            runtime_role=app.role,target_id=app.plan.target_id,backfill_rows_per_second=1000,verify_rows_per_second=1000,
            temporary_bytes_per_row=701,wal_bytes_per_row=2003)
        costs=measured.document['estimates']
        assert costs['temporary_bytes_estimate']==len(app.source)*701
        assert costs['wal_bytes_estimate']==len(app.source)*2003


def test_valid_retained_generation_cannot_satisfy_active_generation_verification():
    from cryptalis.crypto.cf1 import FieldDescriptor, seal_text
    with application() as app:
        extra=KeyContext(DOMAIN,TENANT,'payload',uuid5(DOMAIN,'retained payload root'),2)
        original=keys(TENANT)
        reader=Keyring(replace(original.policy,wrappers=original.policy.wrappers+(WrappedRoot(PROVIDER,extra,b'PUBLIC TEST WRAPPER'),)),{PROVIDER:PublicFixtureProvider()})
        declaration=json.loads(app.plan.lock_bytes)['declaration']
        app.plan=app.m.plan(json.dumps(declaration).encode(),app.mapping,app.owner,
            writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='synthetic app'),)),
            search_reviews=(SearchReview(FIELD_ID,False,'reviewed synthetic labels'),),keys=reader,
            runtime_role=app.role,target_id=app.plan.target_id,backfill_rows_per_second=1000,verify_rows_per_second=1000,
            temporary_bytes_per_row=700,wal_bytes_per_row=2000)
        app.pin=app.m.DeploymentPin(app.plan.target_id,app.plan.operation_id,app.plan.digest,'PREPARED')
        run(app,'BACKFILLED',key_resolver=reader)
        field=json.loads(app.plan.lock_bytes)['models'][0]['fields'][0]
        older=Keyring(replace(reader.policy,payload_generation=2),{PROVIDER:PublicFixtureProvider()})
        identity=UUID(int=103); value=app.source[identity][1]
        frame=seal_text(value,FieldDescriptor.from_compiled(field['descriptor'],field['descriptor_digest']),TENANT,identity,older.prepare())
        assert independent_open(frame,field['descriptor'],TENANT,identity,payload_context=extra)==value
        with app.owner.begin() as c:
            c.exec_driver_sql(f'UPDATE "{app.schema}".customer SET "_cryptalis_{FIELD_ID.hex}"=%s WHERE id=%s',(frame,identity))
        with pytest.raises(app.m.TransitionFailure,match='generation_mismatch'):
            run(app,key_resolver=reader)


def test_switch_verification_holds_table_lock_until_ddl_commit():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from migration_commit_proxy import lost_commit_reply
    with application() as app:
        run(app,'VERIFIED')
        ready,resume=Event(),Event()
        with lost_commit_reply(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                pause_after_sql='SELECT "id","tenant_id","name","_cryptalis_',pause_events=(ready,resume)) as (url,dropped):
            faulty=create_engine('postgresql+psycopg://',hide_parameters=True,creator=lambda:psycopg.connect(url))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(app.m.apply,app.plan,faulty,keys=keys,pin=app.pin,approval=app.approval)
                try:
                    assert ready.wait(10),'switch did not reach full value verification'
                    with psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']) as c:
                        c.execute("SET LOCAL lock_timeout='100ms'")
                        with pytest.raises(psycopg.errors.LockNotAvailable):
                            # Owner bypass is outside writer admission, but the
                            # lock must still stop a late privileged race.
                            c.execute(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',('late change',UUID(int=103)))
                finally: resume.set()
                assert future.result(timeout=20).phase=='PENDING'
            faulty.dispose()


def test_unplanned_trigger_blocks_resume_without_relying_on_boolean_schema_flag():
    with application() as app:
        run(app,'EXPANDED')
        with app.owner.begin() as c:
            c.exec_driver_sql(f'CREATE FUNCTION "{app.schema}".unexpected_writer() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$')
            c.exec_driver_sql(f'CREATE TRIGGER unexpected_writer BEFORE UPDATE ON "{app.schema}".customer FOR EACH ROW EXECUTE FUNCTION "{app.schema}".unexpected_writer()')
        with pytest.raises(app.m.TransitionFailure): run(app)
