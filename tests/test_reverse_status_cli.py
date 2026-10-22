"""Public status command dispatches reverse artifacts without plaintext or keys."""
from dataclasses import asdict
import json

import pytest

from test_cli import _run_cli
from test_reverse_status import reversing, reach
from test_status_cli import arguments, inputs


@pytest.mark.parametrize('phase,code', [('PREPARED', 3), ('EXPANDED', 3),
    ('PLAINTEXT_PENDING', 3), ('PLAINTEXT_ACTIVE', 0), ('ABORTED', 3), ('REMOVED', 0)])
def test_cli_observes_reverse_and_retired_journal(tmp_path, phase, code):
    with reversing() as (app, plan):
        pin = reach(app, plan, phase)
        paths = inputs(app, tmp_path)
        paths['plan'].write_bytes(plan.artifact)
        paths['pin'].write_text(json.dumps(asdict(pin), default=str))
        result = _run_cli(*arguments(paths))
        assert result.returncode == code, result.stderr
        assert not result.stderr
        observed = json.loads(result.stdout)
        assert observed['scope'] == 'reverse_transition'
        assert observed['operation_id'] == str(plan.operation_id)
        assert observed['source_operation_id'] == str(app.plan.operation_id)
        assert observed['phase'] == phase and observed['external_phase'] == pin.phase
        assert observed['runtime_metadata_matches'] is (phase in ('PLAINTEXT_ACTIVE', 'REMOVED'))
        assert observed['verification'] == 'NOT_PERFORMED'
        assert observed['effects'] == 'NONE' and observed['authority'] == 'HOST_SUPPLIED_PIN'
        if phase == 'REMOVED':
            assert observed['committed_rows'] is observed['committed_chunks'] is None


@pytest.mark.parametrize('damage', ['wrong_pin', 'malformed_reverse', 'extra_binding'])
def test_reverse_cli_rejects_invalid_authority_before_database(tmp_path, damage):
    with reversing() as (app, plan):
        pin = reach(app, plan, 'PREPARED')
        paths = inputs(app, tmp_path)
        paths['plan'].write_bytes(plan.artifact)
        paths['pin'].write_text(json.dumps(asdict(pin), default=str))
        args = arguments(paths)
        if damage == 'wrong_pin':
            bad = asdict(pin)
            bad['plan_digest'] = '0' * 64
            paths['pin'].write_text(json.dumps(bad, default=str))
        elif damage == 'malformed_reverse':
            doc = plan.document
            doc['source_pin']['phase'] = 'PRIVATE_REVERSE_INPUT'
            paths['plan'].write_text(json.dumps(doc, sort_keys=True, separators=(',', ':')))
        else:
            binding = tmp_path / 'extra-binding.json'
            binding.write_text('{"private":"PRIVATE_REVERSE_INPUT"}')
            args += ('--restore-binding', str(binding))
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_REVERSE_INPUT')
        result = _run_cli(*args)
        assert result.returncode == 2
        assert not result.stdout
        assert 'PRIVATE_REVERSE_INPUT' not in result.stderr
        assert 'Traceback' not in result.stderr


def test_reverse_cli_output_and_database_failures_are_safe(tmp_path):
    import os
    import subprocess
    import sys
    with reversing() as (app, plan):
        pin = reach(app, plan, 'PREPARED')
        paths = inputs(app, tmp_path)
        paths['plan'].write_bytes(plan.artifact)
        paths['pin'].write_text(json.dumps(asdict(pin), default=str))
        with open('/dev/full', 'w') as unavailable:
            result = subprocess.run([sys.executable, '-m', 'cryptalis', *arguments(paths)],
                stdout=unavailable, stderr=subprocess.PIPE, text=True, timeout=15)
        assert result.returncode == 4 and 'OutputUnavailable' in result.stderr
        assert os.environ['CRYPTALIS_TEST_DATABASE_URL'] not in result.stderr
        paths['database'].write_text('host=127.0.0.1 port=1 dbname=PRIVATE_REVERSE_DATABASE')
        result = _run_cli(*arguments(paths))
        assert result.returncode == 4 and not result.stdout
        assert 'PRIVATE_REVERSE_DATABASE' not in result.stderr
        assert 'Traceback' not in result.stderr
