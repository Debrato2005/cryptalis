"""Step 0 proofs in disposable source copies; every PG run uses the wrapper."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ('duplicate_final_pass', "if PHASES.index(until)>PHASES.index('VERIFIED'):", 'if False:',
     'test_uninterrupted_switch_reads_each_payload_once'),
    ('read_blocking_lock', "mode='EXCLUSIVE' if verification else 'ACCESS EXCLUSIVE'", "mode='ACCESS EXCLUSIVE'",
     'test_final_verification_permits_native_reads_but_blocks_all_writes'),
    ('no_verification_lock', 'def _lock_tables(c,p,*,verification=False):',
     'def _lock_tables(c,p,*,verification=False):\n    if verification: return',
     'test_final_verification_permits_native_reads_but_blocks_all_writes[switch]'),
    ('two_pass_estimate', 'math.ceil(rows/rates[0]+rows/rates[1])', 'math.ceil(rows/rates[0]+2*rows/rates[1])',
     'test_printed_plan_estimates_one_final_pass_from_native_count'),
    ('missing_plan_report', '    def __str__(self):', '    def historical_report(self):',
     'test_printed_plan_estimates_one_final_pass_from_native_count'),
    ('trust_saved_verification', 'digests=_verify(c,p,state,keys)', "digests=state['verification']",
     'test_migration.py::test_verification_is_repeated_at_switch_instead_of_trusting_a_marker'),
    ('changed_verified_frames', "if 'verification' in state and digests != state['verification']:", 'if False:',
     'test_saved_verification_cannot_accept_changed_valid_frames'),
]


def main():
    paths = sorted((ROOT / 'src').rglob('*.py')) + sorted((ROOT / 'tests').rglob('*.py')) + sorted((ROOT / 'scripts').rglob('*.py'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    original = subprocess.run(['git', 'show', base + ':src/cryptalis/migration.py'], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout
    results = []
    with tempfile.TemporaryDirectory(prefix='cryptalis-pause-proof-', dir='/tmp') as directory:
        copy = Path(directory)
        shutil.copytree(ROOT / 'src', copy / 'src', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'tests', copy / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
        file = copy / 'src/cryptalis/migration.py'
        fixed = file.read_text()
        env = dict(os.environ, PYTHONPATH=str(copy / 'src'), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        def run(test):
            for cache in (copy / 'src').rglob('__pycache__'):
                shutil.rmtree(cache)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/test_postgres.py'), '--',
                                     '-q', test, '--tb=short'], cwd=copy, env=env,
                                    capture_output=True, text=True, timeout=100)
            if result.returncode == 2:
                print(result.stdout, flush=True)
                raise SystemExit(2)
            return result
        file.write_text(original)
        before = run('tests/test_migration_pause.py')
        file.write_text(fixed)
        after = run('tests/test_migration_pause.py')
        assert before.returncode == 1 and '6 failed, 1 passed' in before.stdout, before.stdout[-2000:]
        assert after.returncode == 0 and '7 passed' in after.stdout, after.stdout[-2000:]
        comparison = {'original_revision': base, 'original': '6 failed, 1 passed', 'fixed': '7 passed'}
        print(json.dumps(comparison), flush=True)
        for name, old, new, test in MUTATIONS:
            assert fixed.count(old) == 1, (name, fixed.count(old))
            file.write_text(fixed.replace(old, new))
            node = 'tests/' + test if test.startswith('test_migration.py::') else 'tests/test_migration_pause.py::' + test
            removed = run(node)
            file.write_text(fixed)
            restored = run(node)
            signals = ('AssertionError', '\nE   assert ', 'DID NOT RAISE', 'LockNotAvailable; database failure details suppressed.')
            valid = removed.returncode == 1 and any(s in removed.stdout for s in signals) and restored.returncode == 0
            result = {'mechanism': name, 'test': node, 'removed_exit': removed.returncode,
                      'restored_exit': restored.returncode, 'behavioral_failure': valid}
            results.append(result)
            print(json.dumps(result), flush=True)
            if not valid:
                print(removed.stdout[-2000:])
                print(restored.stdout[-2000:])
                raise SystemExit(1)
    assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == digest for p, digest in hashes.items())
    receipt = {'scope': 'Step 0 local protection-pause changes; research prototype', 'base_revision': base,
               'fixing_revision': 'worktree-' + revision, 'source_test_sha256': hashes,
               'original_comparison': comparison, 'mutations': results, 'worktree_unchanged': True,
               'gates': {g: 'UNKNOWN' for g in ('G-ADAPTER', 'G-CRYPTO', 'G-QUERY', 'G-LIFECYCLE', 'G-PROVIDER', 'G-POLICY', 'G-RELEASE')}}
    with (ROOT / 'docs/_reset' / ('step0-regressions-' + revision + '.json')).open('x') as stream:
        stream.write(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
