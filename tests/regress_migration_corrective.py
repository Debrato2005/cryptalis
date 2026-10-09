"""Real PG regression proofs in isolated copies; preserve the starting worktree."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
NODE = 'tests/test_migration_multitable.py::'
MUTATIONS = (
    ('create_per_table', 'if fn not in functions:', 'if True:',
     'test_same_schema_tables_publish_and_use_native_application_values'),
    ('replace_conflict', 'CREATE FUNCTION {fn}()', 'CREATE OR REPLACE FUNCTION {fn}()',
     'test_same_schema_existing_function_is_not_replaced_or_adopted'),
    ('field_pairing', 'seal_text(row[offset+i],descriptor,', 'seal_text(row[offset+i],descriptors[0],',
     'test_same_schema_tables_publish_and_use_native_application_values'),
    ('authentication', 'value=open_text(frame,descriptors[i],tenant,row[0],material[tenant])', 'value=source',
     'test_reused_descriptors_still_reject_valid_wrong_context_frames'),
)


def main():
    baseline = Path(sys.argv[1])
    paths = sorted((ROOT/'src').rglob('*.py')) + sorted((ROOT/'tests').rglob('*.py')) + sorted((ROOT/'scripts').rglob('*.py'))
    hashes = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    revision = hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()[:16]
    results = []
    with tempfile.TemporaryDirectory(prefix='cryptalis-corrective-proof-',dir='/tmp') as directory:
        copy = Path(directory)
        shutil.copytree(ROOT/'src',copy/'src',ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT/'tests',copy/'tests',ignore=shutil.ignore_patterns('__pycache__'))
        file = copy/'src/cryptalis/migration.py'; fixed = file.read_text()
        env = dict(os.environ,PYTHONPATH=str(copy/'src'),PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        def run(node):
            for cache in (copy/'src').rglob('__pycache__'): shutil.rmtree(cache)
            result = subprocess.run([sys.executable,str(ROOT/'scripts/test_postgres.py'),'--','-q',node,'--tb=short'],
                cwd=copy,env=env,capture_output=True,text=True,timeout=90)
            if result.returncode == 2:
                print(result.stdout,flush=True); raise SystemExit(2)
            return result
        file.write_text((baseline/'src/cryptalis/migration.py').read_text())
        before = run(NODE+'test_same_schema_tables_publish_and_use_native_application_values')
        file.write_text(fixed)
        after = run(NODE+'test_same_schema_tables_publish_and_use_native_application_values')
        assert before.returncode==1 and 'ProgrammingError; database failure details suppressed.' in before.stdout, before.stdout[-2000:]
        assert after.returncode==0, after.stdout[-2000:]
        comparison = {'baseline_migration_sha256':hashlib.sha256((baseline/'src/cryptalis/migration.py').read_bytes()).hexdigest(),
                      'original_exit':before.returncode,'fixed_exit':after.returncode,
                      'original_output':before.stdout,'fixed_output':after.stdout}
        print('Same-schema native application: original fails; fixed passes',flush=True)
        start = fixed.index('def _drop_guards(c,p):'); end = fixed.index('\ndef _guard_facts',start)
        old_drop = fixed[start:end]
        early_drop = '''def _drop_guards(c,p):
    for model in p.document['lock']['models']:
        trigger,function=_guard_names(p,model)
        c.exec_driver_sql(f'DROP TRIGGER {_quote(c,trigger)} ON {_table(c,model)}')
        c.exec_driver_sql(f'DROP FUNCTION {_quote(c,model["schema"])}.{_quote(c,function)}()')

'''
        mutations = (*MUTATIONS,
            ('early_function_retirement', old_drop, early_drop, 'test_same_schema_tables_publish_and_use_native_application_values'),
            ('early_function_retirement_abort', old_drop, early_drop, 'test_same_schema_abort_restores_native_writes_idempotently[BACKFILLED]'))
        for name,old,new,test in mutations:
            assert fixed.count(old)==1, (name,fixed.count(old))
            file.write_text(fixed.replace(old,new)); removed = run(NODE+test)
            file.write_text(fixed); restored = run(NODE+test)
            signals = ('AssertionError','DID NOT RAISE','database failure details suppressed.')
            valid = removed.returncode==1 and any(s in removed.stdout for s in signals) and restored.returncode==0
            result = {'mechanism':name,'test':NODE+test,'removed_exit':removed.returncode,'restored_exit':restored.returncode,
                      'behavioral_failure':valid,'removed_output':removed.stdout,'restored_output':restored.stdout}
            results.append(result)
            print(json.dumps({k:v for k,v in result.items() if not k.endswith('_output')}),flush=True)
            if not valid:
                print(removed.stdout[-2000:]); print(restored.stdout[-2000:]); raise SystemExit(1)
        # A real old single-table checkpoint must remain usable by the new
        # engine. Generate it with the preserved engine, then resume in this
        # copy with the new one and inspect through the normal application.
        compatibility = []
        bridge = copy/'tests/test_old_checkpoint.py'
        bridge.write_text('''import os, subprocess, sys
from pathlib import Path
from dataclasses import replace
import pytest
from test_migration import application, child, frames, independent_open, publish, run
@pytest.mark.parametrize('phase',['EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'])
def test_old_checkpoint_resumes(phase,tmp_path):
    with application() as app:
        env=dict(os.environ,PYTHONPATH=os.environ['CRYPTALIS_OLD_SOURCE']+os.pathsep+str(Path(__file__).parent))
        artifact=tmp_path/'plan.json'; artifact.write_bytes(app.plan.artifact)
        worker=Path(__file__).with_name('migration_worker.py')
        def old_run(target,pin_phase):
            result=subprocess.run([sys.executable,str(worker),str(artifact),target,pin_phase,'exit'],
                env=env,capture_output=True,text=True,timeout=30)
            assert result.returncode==0,'old checkpoint creation failed; diagnostics withheld'
        if phase=='ACTIVE': old_run('PENDING','PREPARED')
        old_run(phase,'ACTIVATING' if phase=='ACTIVE' else 'PREPARED')
        if phase=='ACTIVE': app.pin=replace(app.pin,phase='ACTIVE')
        before=frames(app,phase in ('PENDING','ACTIVE'))
        run(app,'ACTIVE' if phase=='ACTIVE' else 'PENDING')
        after=frames(app,True)
        if phase!='EXPANDED': assert before==after
        descriptor=app.plan.document['lock']['models'][0]['fields'][0]['descriptor']
        assert {k:independent_open(v,descriptor,app.source[k][0],k) for k,v in after.items()}=={k:v[1] for k,v in app.source.items()}
        if phase!='ACTIVE': publish(app)
''')
        env['CRYPTALIS_OLD_SOURCE'] = str(baseline/'src')
        legacy = run('tests/test_old_checkpoint.py')
        assert legacy.returncode==0 and '5 passed' in legacy.stdout, legacy.stdout[-2000:]
        compatibility.append({'old_to_new_phases':['EXPANDED','BACKFILLED','VERIFIED','PENDING','ACTIVE'],
                              'exit':legacy.returncode,'output':legacy.stdout})
        print('All five old single-table checkpoint phases resume',flush=True)
    assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h for p,h in hashes.items())
    receipt={'scope':'Same-schema migration correctness and descriptor-reuse safety; research prototype',
        'fixing_revision':'worktree-'+revision,'source_test_sha256':hashes,'original_comparison':comparison,
        'mutations':results,'old_checkpoint_compatibility':compatibility,'worktree_unchanged':True,
        'gates':{g:'UNKNOWN' for g in ('G-ADAPTER','G-CRYPTO','G-QUERY','G-LIFECYCLE','G-PROVIDER','G-POLICY','G-RELEASE')}}
    with (ROOT/'docs/_reset'/f'step-a-corrective-regressions-{revision}.json').open('x') as stream:
        stream.write(json.dumps(receipt,indent=2)+'\n')


if __name__=='__main__': main()
