"""Isolated million-row maintenance measurement; public synthetic text only."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sys
import time
from uuid import UUID
import cryptography
import psycopg
import sqlalchemy
from cryptalis.migration import plan, DeploymentPin, apply, check_deployment
from cryptalis.manifest.compiler import Writer, WriterInventory, SearchReview
from test_migration import application, DOMAIN, TABLE_ID, FIELD_ID, TENANT, keys


def main():
    rows=int(sys.argv[1]) if len(sys.argv)>1 else 1_000_000
    if not 1000<=rows<=1_000_000: raise ValueError('Use 1000..1000000 synthetic rows')
    fingerprints={}
    for variable in ('CRYPTALIS_TEST_DATABASE_URL','CRYPTALIS_TEST_RUNTIME_DATABASE_URL'):
        url=os.environ.get(variable)
        if not url: raise SystemExit('Missing authorized private database URL')
        fingerprints[variable]=hashlib.sha256(url.encode()).hexdigest()[:8]
        try:
            with psycopg.connect(url,connect_timeout=5) as c:
                assert c.execute('select 1').fetchone()==(1,)
                server=c.execute('show server_version').fetchone()[0]
        except psycopg.Error as exc:
            print(json.dumps({'fingerprints':fingerprints,'error':type(exc).__name__,'sqlstate':exc.sqlstate})); raise SystemExit(2)
    hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('src/cryptalis').rglob('*.py')}
    print(json.dumps({'stage':'start','rows':rows,'fingerprints':fingerprints}),flush=True)
    initial_cpu=time.process_time()
    with application(rows=0,unique=True) as app:
        seed=time.perf_counter()
        with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
            for lower in range(0,rows,2000):
                with c.transaction():
                    with c.cursor() as cur:
                        cur.executemany(f'INSERT INTO "{app.schema}".customer(id,tenant_id,name,label) VALUES (%s,%s,%s,%s)',
                            [(UUID(int=i+100),TENANT,f'user-{hashlib.blake2b(str(i).encode(),digest_size=16).hexdigest()}@example.invalid',f'label-{i}') for i in range(lower,min(rows,lower+2000))])
        seed_seconds=time.perf_counter()-seed
        proposal=plan(json.dumps(json.loads(app.plan.lock_bytes)['declaration']).encode(),app.mapping,app.owner,
            writers=WriterInventory(True,(Writer(TABLE_ID,'app','sqlalchemy',evidence='synthetic runtime application'),)),
            search_reviews=(SearchReview(FIELD_ID,False,'synthetic unbounded email identifiers'),),keys=keys,
            runtime_role=app.role,target_id=app.plan.target_id,backfill_rows_per_second=1000,verify_rows_per_second=1000,
            temporary_bytes_per_row=700,wal_bytes_per_row=2000)
        pin=DeploymentPin(proposal.target_id,proposal.operation_id,proposal.digest,'PREPARED')
        print(json.dumps({'stage':'seeded','seconds':seed_seconds}),flush=True)
        with app.owner.connect() as c:
            wal_start=c.exec_driver_sql('SELECT pg_current_wal_insert_lsn()::text').scalar_one()
            initial_bytes=c.exec_driver_sql('SELECT pg_total_relation_size(%s::regclass)',(f'"{app.schema}".customer',)).scalar_one()
        pause=time.perf_counter(); durations={}; writer_checks=[]; phase_storage={}
        for phase in ('EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'):
            if phase=='ACTIVE': pin=replace(pin,phase='ACTIVATING')
            start=time.perf_counter()
            progress=apply(proposal,app.owner,keys=keys,pin=pin,approval=app.approval,chunk_size=2000,until=phase)
            durations[phase]=time.perf_counter()-start
            with app.owner.connect() as c:
                phase_storage[phase]=c.exec_driver_sql('SELECT pg_total_relation_size(%s::regclass)',(f'"{app.schema}".customer',)).scalar_one()
            if phase!='ACTIVE':
                with psycopg.connect(os.environ['CRYPTALIS_TEST_RUNTIME_DATABASE_URL']) as c:
                    start=time.perf_counter()
                    try: c.execute(f'UPDATE "{app.schema}".customer SET label=%s WHERE id=%s',('paused',UUID(int=100)))
                    except psycopg.Error as exc:
                        if exc.sqlstate!='55000': raise
                        writer_checks.append({'phase':phase,'sqlstate':exc.sqlstate,'refusal_ms':(time.perf_counter()-start)*1000})
                    else: raise AssertionError('writer fence did not refuse mutation')
            print(json.dumps({'stage':phase,'seconds':durations[phase],'committed_rows':progress.committed_rows}),flush=True)
        paused_seconds=time.perf_counter()-pause
        pin=replace(pin,phase='ACTIVE'); check_deployment(proposal,app.owner,pin=pin)
        with app.owner.connect() as c:
            count=c.exec_driver_sql(f'SELECT count(*) FROM "{app.schema}".customer').scalar_one(); assert count==rows
            final_bytes=c.exec_driver_sql('SELECT pg_total_relation_size(%s::regclass)',(f'"{app.schema}".customer',)).scalar_one()
            wal_bytes=int(c.exec_driver_sql('SELECT pg_wal_lsn_diff(pg_current_wal_insert_lsn(),%s::pg_lsn)',(wal_start,)).scalar_one())
        from cryptalis.sqlalchemy import attach
        from sqlalchemy import select
        factory=attach(app.mapping,app.runtime,lock=proposal.lock_bytes,keys=keys,deployment=(proposal,pin))
        start=time.perf_counter()
        with factory(tenant_id=TENANT) as s:
            row=s.get(app.Customer,UUID(int=100)); row.name='after-million-row-switch@example.invalid'; s.commit()
            assert s.scalar(select(app.Customer.name).where(app.Customer.id==UUID(int=100)))==row.name
        first_write_ms=(time.perf_counter()-start)*1000
    stable=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest for p,digest in hashes.items())
    result={'rows':rows,'fingerprints':fingerprints,'versions':{'python':platform.python_version(),'postgresql':server,
        'sqlalchemy':sqlalchemy.__version__,'psycopg':psycopg.__version__,'cryptography':cryptography.__version__},
        'source_hashes':hashes,'source_stable':stable,'seed_seconds':seed_seconds,'phase_seconds':durations,
        'backfill_rows_per_second':rows/durations['BACKFILLED'],'total_writer_pause_seconds':paused_seconds,
        'writer_pause_definition':'First expand invocation through ACTIVE database acknowledgement; local publication is an immediate test pin update. Real deployment publication delay is additional.',
        'writer_refusals':writer_checks,'first_post_switch_write_read_ms':first_write_ms,
        'initial_total_relation_bytes':initial_bytes,'final_total_relation_bytes_including_dead_tuples':final_bytes,
        'phase_total_relation_bytes':phase_storage,'plan_cost_estimates':proposal.document['estimates'],
        'wal_bytes_cluster_wide_context_only':wal_bytes,'cpu_seconds':time.process_time()-initial_cpu,
        'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'limits':['Public synthetic fixture keys; no provider custody claim','Host exclusion and publication attested by test caller, not a production deployment','WAL LSN measures entire cluster, not attribution','No plaintext erasure claim','No numeric pause ceiling approved'],
        'gates':{g:'UNKNOWN' for g in ('G-ADAPTER','G-CRYPTO','G-QUERY','G-LIFECYCLE','G-PROVIDER','G-POLICY','G-RELEASE')}}
    if not stable: raise AssertionError('Source changed during profile')
    Path('docs/_reset/slice5-performance.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='source_hashes'}),flush=True)

if __name__=='__main__': main()
