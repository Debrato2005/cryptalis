"""Compare committed source and isolated removals through the PG wrapper."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASELINE = '7edd1647b39c933ec1eac14f24ce84ff7d29bfba'


def main():
    paths = sorted((ROOT/'src').rglob('*.py')) + sorted((ROOT/'tests').rglob('*.py')) + sorted((ROOT/'scripts').rglob('*.py'))
    hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    original = subprocess.run(['git', 'show', BASELINE+':src/cryptalis/migration.py'],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    results = []
    with tempfile.TemporaryDirectory(prefix='cryptalis-membership-proof-', dir='/tmp') as directory:
        copy = Path(directory)
        shutil.copytree(ROOT/'src', copy/'src', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copytree(ROOT/'tests', copy/'tests', ignore=shutil.ignore_patterns('__pycache__'))
        path = copy/'src/cryptalis/migration.py'; fixed = path.read_text()
        env = dict(os.environ, PYTHONPATH=str(copy/'src'), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        def run(source):
            path.write_text(source)
            for cache in (copy/'src').rglob('__pycache__'): shutil.rmtree(cache)
            result = subprocess.run([sys.executable, str(ROOT/'scripts/test_postgres.py'), '--',
                '-q', 'tests/test_migration_membership.py', '--tb=short'],
                cwd=copy, env=env, capture_output=True, text=True, timeout=90)
            if result.returncode == 2:
                print(result.stdout, flush=True); raise SystemExit(2)
            return result
        before = run(original); after = run(fixed)
        assert before.returncode == 1 and '4 failed, 1 passed' in before.stdout and '42501' in before.stdout
        assert after.returncode == 0 and '5 passed' in after.stdout
        comparison = {'baseline_revision': BASELINE, 'baseline_source_sha256': hashlib.sha256(original.encode()).hexdigest(),
            'original_exit': before.returncode, 'fixed_exit': after.returncode,
            'original_output': before.stdout, 'fixed_output': after.stdout}
        print('Committed source: four native permission failures / one control pass; fixed: five passes', flush=True)
        start = fixed.index('def _scope(c,model):'); end = fixed.index('\ndef _frame_check', start)
        scope = fixed[start:end]
        mutations = (
            ('source_values_read_again', 'identity_only=True', 'identity_only=False'),
            ('tenant_binding_removed', 'str(tenant)', "'tenant omitted'"),
            ('membership_stops_after_first_page', "cursor=str(rows[-1][0])", "break"),
        )
        for name, old, new in mutations:
            assert scope.count(old) == 1
            removed = run(fixed[:start]+scope.replace(old, new)+fixed[end:]); restored = run(fixed)
            valid = removed.returncode == 1 and 'AssertionError' in removed.stdout and restored.returncode == 0
            result = {'mechanism': name, 'removed_exit': removed.returncode, 'restored_exit': restored.returncode,
                'behavioral_failure': valid, 'removed_output': removed.stdout, 'restored_output': restored.stdout}
            results.append(result)
            print(json.dumps({k: v for k, v in result.items() if not k.endswith('_output')}), flush=True)
            assert valid
    assert all(hashlib.sha256((ROOT/path).read_bytes()).hexdigest() == digest for path, digest in hashes.items())
    revision = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()[:16]
    with (ROOT/'docs/_reset'/f'membership-regressions-{revision}.json').open('x') as stream:
        stream.write(json.dumps({'source_test_sha256': hashes, 'worktree_unchanged': True,
            'comparison': comparison, 'mutations': results,
            'qualification': 'Scoped regression evidence; all seven gates UNKNOWN'}, indent=2)+'\n')


if __name__ == '__main__':
    main()
