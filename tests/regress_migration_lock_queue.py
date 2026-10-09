"""Remove lock protections in disposable copies; run only the PG wrapper."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = (
    ('short_timeout', "SET LOCAL lock_timeout = '100ms'", "SET LOCAL lock_timeout = '5s'",
     'test_cutover_releases_queued_readers_promptly_and_preserves_retry_state'),
    ('retry', 'for attempt in range(3):', 'for attempt in range(1):',
     'test_cutover_retries_after_reader_leaves_without_repeating_verification'),
    ('savepoint', 'with c.begin_nested():', 'with __import__("contextlib").nullcontext():',
     'test_failed_partial_upgrade_releases_read_lock_but_retains_write_exclusion'),
    ('explicit_cutover_upgrade', "state['verification']=digests\n    _lock_tables(c,p)",
     "state['verification']=digests",
     'test_cutover_releases_queued_readers_promptly_and_preserves_retry_state'),
    ('verification_write_exclusion', 'if verification:\n        for model in models:',
     'if verification: return\n    if False:\n        for model in models:',
     'test_migration_pause.py::test_final_verification_permits_native_reads_but_blocks_all_writes[switch]'),
)


def main():
    paths = sorted((ROOT / 'src').rglob('*.py')) + sorted((ROOT / 'tests').rglob('*.py')) + sorted((ROOT / 'scripts').rglob('*.py'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    base = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    original = subprocess.run(['git', 'show', base + ':src/cryptalis/migration.py'], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout
    results = []
    with tempfile.TemporaryDirectory(prefix='cryptalis-lock-proof-', dir='/tmp') as directory:
        copy = Path(directory)
        shutil.copytree(ROOT / 'src', copy / 'src', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT / 'tests', copy / 'tests', ignore=shutil.ignore_patterns('__pycache__'))
        file = copy / 'src/cryptalis/migration.py'; fixed = file.read_text()
        env = dict(os.environ, PYTHONPATH=str(copy / 'src'), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        def run(node):
            for cache in (copy / 'src').rglob('__pycache__'):
                shutil.rmtree(cache)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/test_postgres.py'), '--',
                                     '-q', node, '--tb=short'], cwd=copy, env=env,
                                    capture_output=True, text=True, timeout=90)
            if result.returncode == 2:
                print(result.stdout, flush=True); raise SystemExit(2)
            return result
        file.write_text(original); before = run('tests/test_migration_lock_queue.py')
        file.write_text(fixed); after = run('tests/test_migration_lock_queue.py')
        assert before.returncode == 1 and '3 failed, 1 passed' in before.stdout, before.stdout[-2000:]
        assert after.returncode == 0 and '4 passed' in after.stdout, after.stdout[-2000:]
        comparison = {'original_revision': base, 'original': '3 failed, 1 passed', 'fixed': '4 passed'}
        print(json.dumps(comparison), flush=True)
        for name, old, new, test in MUTATIONS:
            assert fixed.count(old) == 1, (name, fixed.count(old))
            node = 'tests/' + test if test.startswith('test_migration_pause.py::') else 'tests/test_migration_lock_queue.py::' + test
            file.write_text(fixed.replace(old, new)); removed = run(node)
            file.write_text(fixed); restored = run(node)
            signals = ('AssertionError', '\nE   assert ', 'DID NOT RAISE',
                       'LockNotAvailable; database failure details suppressed.',
                       'OperationalError; database failure details suppressed.', 'table_lock_busy_retry')
            valid = removed.returncode == 1 and any(s in removed.stdout for s in signals) and restored.returncode == 0
            record = {'mechanism': name, 'test': node, 'removed_exit': removed.returncode,
                      'restored_exit': restored.returncode, 'behavioral_failure': valid,
                      'removed_output': removed.stdout, 'restored_output': restored.stdout}
            results.append(record)
            print(json.dumps({k:v for k,v in record.items() if not k.endswith('_output')}), flush=True)
            if not valid:
                print(removed.stdout[-2000:]); print(restored.stdout[-2000:]); raise SystemExit(1)
    assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == digest for p, digest in hashes.items())
    receipt = {'scope': 'Step A bounded table-lock acquisition; research prototype', 'base_revision': base,
               'fixing_revision': 'worktree-' + revision, 'source_test_sha256': hashes,
               'original_comparison': comparison, 'mutations': results, 'worktree_unchanged': True,
               'gates': {g: 'UNKNOWN' for g in ('G-ADAPTER', 'G-CRYPTO', 'G-QUERY', 'G-LIFECYCLE', 'G-PROVIDER', 'G-POLICY', 'G-RELEASE')}}
    with (ROOT / 'docs/_reset' / ('step-a-lock-regressions-' + revision + '.json')).open('x') as stream:
        stream.write(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
