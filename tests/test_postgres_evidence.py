"""Receipt admission refuses source mutations around a controlled pytest call.

The outer and inner runners both use fresh PostgreSQL role probes. Only the
inner pytest result is controlled; these tests make no application test claim.
All file mutations occur in a disposable source tree outside the repository.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest


@pytest.mark.parametrize('mutation,with_receipt', [('none', True), ('replace', True),
    ('add', True), ('remove', True), ('none', False), ('replace', False)])
@pytest.mark.parametrize('pytest_code', [0, 1])
def test_receipt_admission_binds_the_source_that_preceded_pytest(tmp_path, monkeypatch, capsys, mutation, pytest_code, with_receipt):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('_cryptalis_evidence_runner', root / 'scripts/test_postgres.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    source = tmp_path / 'src/cryptalis/probe.py'
    source.parent.mkdir(parents=True)
    source.write_text('value = 1\n')
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    receipt = tmp_path / 'receipt.json'
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, 'ROOT', tmp_path, raising=False)
    options = ['--receipt', str(receipt)] if with_receipt else []
    monkeypatch.setattr(sys, 'argv', ['test_postgres.py', *options,
                                    '--scope', 'controlled pytest source-stability admission'])
    urls = tuple(os.environ[name] for name in runner.VARIABLES)
    for name, value in zip(runner.VARIABLES, urls):
        monkeypatch.setenv(name, value)
    monkeypatch.setitem(sys.modules, '_cryptalis_test_preflight', sys.modules['_cryptalis_test_preflight'])
    def controlled_pytest(arguments, plugins):
        assert arguments == [] and len(plugins) == 1
        if mutation == 'replace':
            original = source.stat()
            source.write_text('value = 2\n')
            os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
        elif mutation == 'add':
            source.with_name('added.py').write_text('value = 3\n')
        elif mutation == 'remove':
            source.unlink()
        return pytest_code
    monkeypatch.setattr(pytest, 'main', controlled_pytest)
    observed = runner.main()
    assert observed == (pytest_code if mutation == 'none' else 4)
    output = capsys.readouterr().out
    assert all(url not in output for url in urls)
    if not with_receipt:
        assert not receipt.exists()
        return
    saved = json.loads(receipt.read_text())
    assert saved['exit_code'] == observed
    assert saved['pytest_exit_code'] == pytest_code
    assert saved['source_test_sha256'] == {'src/cryptalis/probe.py': before}
    assert saved['source_stability']['unchanged'] is (mutation == 'none')
    changed = [] if mutation == 'none' else ['src/cryptalis/added.py' if mutation == 'add' else 'src/cryptalis/probe.py']
    assert saved['source_stability']['changed_paths'] == changed
    if mutation == 'remove':
        assert saved['source_after_sha256']['src/cryptalis/probe.py'] is None
    elif mutation != 'none':
        assert saved['source_after_sha256'][changed[0]] == hashlib.sha256((tmp_path / changed[0]).read_bytes()).hexdigest()
    assert all(value == 'UNKNOWN' for value in saved['gates'].values())
