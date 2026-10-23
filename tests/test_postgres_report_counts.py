"""Real pytest report partitions; no database or wrapper preflight execution."""
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[1]


SCENARIOS = {
    'green': {
        'test_runtime.py': '''
            import unittest
            import pytest

            def test_pass():
                assert True

            def test_call_skip():
                pytest.skip('public call skip')

            @pytest.fixture
            def skipped_setup():
                pytest.skip('public setup skip')

            def test_setup_skip(skipped_setup):
                raise AssertionError('unreachable')

            def test_pytest_subtests(subtests):
                for number in (1, 2):
                    with subtests.test(number=number):
                        assert number > 0

            class TestUnittest(unittest.TestCase):
                def test_subtests(self):
                    for number in (3, 4):
                        with self.subTest(number=number):
                            self.assertGreater(number, 0)

            @pytest.mark.xfail(reason='public expected failure')
            def test_xfail():
                assert False

            @pytest.mark.xfail(reason='public non-strict unexpected pass', strict=False)
            def test_xpass():
                assert True
        ''',
        'test_module_skip.py': '''
            import pytest
            pytest.skip('public module skip', allow_module_level=True)
        ''',
    },
    'red': {
        'test_runtime.py': '''
            import unittest
            import pytest

            def test_fail():
                assert False, 'public ordinary failure'

            @pytest.fixture
            def failed_setup():
                raise RuntimeError('public setup failure')

            def test_setup_error(failed_setup):
                raise AssertionError('unreachable')

            @pytest.fixture
            def failed_teardown():
                yield
                raise RuntimeError('public teardown failure')

            def test_teardown_error(failed_teardown):
                assert True

            def test_pytest_subtests(subtests):
                with subtests.test(label='pass'):
                    assert True
                with subtests.test(label='fail'):
                    assert False, 'public pytest subtest failure'

            class TestUnittest(unittest.TestCase):
                def test_subtests(self):
                    with self.subTest(label='pass'):
                        self.assertTrue(True)
                    with self.subTest(label='fail'):
                        self.assertTrue(False, 'public unittest subtest failure')
        ''',
    },
    'collection_error': {
        'test_bad_import.py': "raise RuntimeError('public collection failure')\n",
        'test_not_run.py': 'def test_not_run():\n    assert True\n',
    },
}


EXPECTED = {
    'green': {
        'exit_code': 0,
        'legacy_counts': {'passed': 8, 'skipped': 2},
        'pytest_report_counts': {
            'test_calls': {'passed': 4, 'skipped': 2},
            'subtest_calls': {'passed': 4},
            'setup': {'passed': 6, 'skipped': 1},
            'teardown': {'passed': 7},
            'collection': {'skipped': 1},
            'selected_items': 7,
        },
    },
    'red': {
        'exit_code': 1,
        'legacy_counts': {'failed': 4, 'errors': 2, 'passed': 4},
        'pytest_report_counts': {
            'test_calls': {'failed': 2, 'passed': 2},
            'subtest_calls': {'passed': 2, 'failed': 2},
            'setup': {'passed': 4, 'failed': 1},
            'teardown': {'passed': 4, 'failed': 1},
            'collection': {},
            'selected_items': 5,
        },
    },
    'collection_error': {
        'exit_code': 2,
        'legacy_counts': {},
        'pytest_report_counts': {
            'test_calls': {}, 'subtest_calls': {}, 'setup': {}, 'teardown': {},
            'collection': {'failed': 1}, 'selected_items': 1,
        },
    },
}


@pytest.mark.parametrize('scenario', ['green', 'red', 'collection_error'])
def test_real_pytest_report_counts_preserve_legacy_and_partition_final_reports(tmp_path, scenario):
    """xfail/xpass here assert raw report outcomes, not terminal categories."""
    suite = tmp_path / scenario
    suite.mkdir()
    for filename, source in SCENARIOS[scenario].items():
        (suite / filename).write_text(textwrap.dedent(source).lstrip())
    result_path = tmp_path / 'observed.json'
    runner = tmp_path / 'run_reports.py'
    runner.write_text(textwrap.dedent('''
        import json
        from pathlib import Path
        import runpy
        import sys
        import pytest

        wrapper, suite, destination = map(Path, sys.argv[1:])
        Results = runpy.run_path(str(wrapper), run_name='_receipt_counter_test')['Results']
        results = Results()
        code = int(pytest.main([
            '-c', '/dev/null', '--rootdir', str(suite), '--confcutdir', str(suite),
            '-q', '--tb=short', str(suite),
        ], plugins=[results]))
        Path(destination).write_text(json.dumps({
            'pytest_version': pytest.__version__, 'exit_code': code,
            'legacy_counts': results.counts, 'legacy_modules': results.modules,
            'pytest_report_counts': getattr(results, 'pytest_report_counts', None),
        }))
        raise SystemExit(code)
    ''').lstrip())
    environment = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    environment.pop('PYTEST_ADDOPTS', None)
    observed = subprocess.run([
        sys.executable, str(runner), str(ROOT / 'scripts/test_postgres.py'),
        str(suite), str(result_path),
    ], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    assert result_path.exists(), observed.stdout + observed.stderr
    saved = json.loads(result_path.read_text())
    expected = EXPECTED[scenario]
    assert observed.returncode == saved['exit_code'] == expected['exit_code'], observed.stdout + observed.stderr
    assert saved['legacy_counts'] == expected['legacy_counts']
    assert saved['legacy_modules'] == ({'test_runtime.py': expected['legacy_counts']}
                                       if scenario != 'collection_error' else {})
    assert saved['pytest_report_counts'] == expected['pytest_report_counts']
