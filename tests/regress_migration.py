"""Remove safety mechanisms only in an isolated copy; exercise real PG oracles."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
MUTATIONS=[
 ('authentication','migration.py','value=open_text(frame,FieldDescriptor.from_compiled(f[\'descriptor\'],f[\'descriptor_digest\']),tenant,row[0],material[tenant])','value=source','test_full_verification_refuses_corruption_and_never_switches[tag]'),
 ('value_comparison','migration.py','if type(value)!=type(source) or value!=source:','if False:','test_full_verification_refuses_corruption_and_never_switches[source]'),
 ('membership','migration.py','if _scope(c,model)!=progress[\'scope\']:','if False:','test_full_verification_refuses_corruption_and_never_switches[missing]'),
 ('source_schema','migration.py','if _facts(c,model)!=observed[\'schema\']:','if False:','test_full_verification_refuses_corruption_and_never_switches[index]'),
 ('fence_inspection','migration.py','if _guard_facts(c,p,model)!=observed[\'guard\'] or not observed[\'guard\'] or observed[\'guard\'][0]!=\'A\':','if False:','test_full_verification_refuses_corruption_and_never_switches[fence]'),
 ('runtime_fence','migration.py',"IF CURRENT_USER <> '{owner}' THEN","IF FALSE THEN",'test_runtime_reconnect_cannot_write_during_maintenance[BACKFILLED]'),
 ('switch_reverification','migration.py','digests=_verify(c,p,state,keys)','digests=state[\'verification\']','test_verification_is_repeated_at_switch_instead_of_trusting_a_marker'),
 ('restore_pin','migration.py','if state[\'phase\'] not in PHASES or PHASES.index(state[\'phase\']) < PHASES.index(required):','if False:','test_older_database_snapshot_cannot_override_external_current_pin'),
 ('stale_pin','migration.py','if state[\'phase\']==\'ACTIVE\' and pin.phase not in (\'ACTIVE\',\'ACTIVATING\'):','if False:','test_stale_prepared_pin_cannot_report_an_active_deployment'),
 ('key_policy','sqlalchemy.py','if _policy(ring) != plan.document["key_policies"].get(str(tenant)):','if False:','test_active_deployment_rejects_different_keys_before_search_can_hide_rows'),
 ('runtime_principal','migration.py','if c.exec_driver_sql(\'SELECT current_user\').scalar_one()!=p.document[\'runtime_role\']:','if False:','test_owner_credentials_cannot_replace_planned_runtime_attachment'),
 ('executor_lock','migration.py',"if not acquired: raise TransitionFailure('executor_already_running',p.operation_id)",'if False: pass','test_competing_executor_is_refused_without_effects'),
 ('marker_affected_row','migration.py','if result.rowcount!=1:','if False:','test_missing_chunk_marker_write_rolls_back_actual_row_changes'),
 ('atomic_marker','migration.py',"_save(c,p,state)\n        return True","c.commit()\n        _save(c,p,state)\n        return True",'test_lost_commit_reply_is_reconciled_from_terminal_real_transaction'),
 ('publication','migration.py',"if pin.phase!='ACTIVATING': raise TransitionFailure('matching_external_publication_required',p.operation_id)",'if False: pass','test_external_publication_unavailable_keeps_runtime_stopped'),
 ('external_authority','migration.py','if (not isinstance(p,MigrationPlan) or not isinstance(pin,DeploymentPin) or','if False and (not isinstance(p,MigrationPlan) or not isinstance(pin,DeploymentPin) or','test_invalid_external_authority_or_missing_writer_approval_has_no_effects[target]'),
 ('writer_approval','migration.py','if (not isinstance(approval.writer_exclusion,str) or','if False and (not isinstance(approval.writer_exclusion,str) or','test_invalid_external_authority_or_missing_writer_approval_has_no_effects[approval]'),
 ('active_generation','migration.py',"if frame is not None and (int.from_bytes(frame[6:10],'big')!=admitted.payload_generation or int.from_bytes(frame[10:14],'big')!=(admitted.search_generation if f['queries'] else 0)):",'if False:','test_valid_retained_generation_cannot_satisfy_active_generation_verification'),
 ('switch_table_lock','migration.py','def _lock_tables(c,p,*,verification=False):','def _lock_tables(c,p,*,verification=False):\n    return','test_switch_verification_holds_table_lock_until_ddl_commit'),
 ('trigger_inventory','migration.py','return list(row)+[[list(item) for item in inventory]]','return list(row)','test_unplanned_trigger_blocks_resume_without_relying_on_boolean_schema_flag'),
]

def main():
    originals={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'src').rglob('*.py')}
    receipts=[]
    with tempfile.TemporaryDirectory(prefix='cryptalis-slice5-mutants-',dir='/tmp') as directory:
        copy=Path(directory); shutil.copytree(ROOT/'src',copy/'src'); shutil.copytree(ROOT/'tests',copy/'tests',ignore=shutil.ignore_patterns('__pycache__'))
        env=dict(os.environ,PYTHONPATH=str(copy/'src'),PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        for name,file,old,new,test in MUTATIONS:
            path=copy/'src'/'cryptalis'/file; source=path.read_text()
            assert source.count(old)==1,(name,source.count(old))
            path.write_text(source.replace(old,new))
            for cache in (copy/'src').rglob('__pycache__'): shutil.rmtree(cache)
            command=[sys.executable,str(ROOT/'scripts/test_postgres.py'),'--','-q','tests/test_migration.py::'+test,'--tb=short']
            failed=subprocess.run(command,cwd=copy,env=env,capture_output=True,text=True,timeout=90)
            if failed.returncode==2:
                print(failed.stdout); raise SystemExit(2)
            path.write_text(source)
            for cache in (copy/'src').rglob('__pycache__'): shutil.rmtree(cache)
            restored=subprocess.run(command,cwd=copy,env=env,capture_output=True,text=True,timeout=90)
            # Require behavioral assertion failures; setup/import failures do
            # not qualify as a regression proof.
            valid=failed.returncode==1 and ('AssertionError' in failed.stdout or '\nE   assert ' in failed.stdout or 'DID NOT RAISE' in failed.stdout or 'Regex pattern did not match' in failed.stdout) and restored.returncode==0
            receipts.append({'mechanism':name,'test':test,'removed_exit':failed.returncode,'restored_exit':restored.returncode,'behavioral_failure':valid})
            print(json.dumps(receipts[-1]),flush=True)
            if not valid:
                print(failed.stdout[-4000:]); print(restored.stdout[-2000:]); raise SystemExit(1)
    assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest for p,digest in originals.items())
    revision=hashlib.sha256(json.dumps(originals,sort_keys=True).encode()).hexdigest()[:16]
    with (ROOT/'docs/_reset'/f'slice5-regressions-audit-{revision}.json').open('x') as stream:
        stream.write(json.dumps({'source_hashes':originals,'worktree_unchanged':True,'mutations':receipts},indent=2)+'\n')

if __name__=='__main__': main()
