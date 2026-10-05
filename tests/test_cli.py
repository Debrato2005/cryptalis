import errno
import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest


_REPOSITORY_ROOT = Path(__file__).parent.parent
_EXAMPLES = _REPOSITORY_ROOT / "examples" / "manifests"
_EXPECTED_DIGEST = (
    "7b7c4bdb543a0a89ba3493e06735ada4"
    "5a3457f686fb4a65c23d3562e5525e3e"
)


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cryptalis", *arguments],
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )


def test_manifest_inspect_prints_text_result():
    result = _run_cli(
        "manifest", "inspect", str(_EXAMPLES / "genesis.json")
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == (
        "scope: manifest_header\n"
        "schema_version: 1\n"
        "manifest_id: 018f4f87-6f95-7e2a-9d95-38f9b7646f24\n"
        "revision: 0\n"
        "parent_digest: null\n"
        f"digest: {_EXPECTED_DIGEST}\n"
    )


def test_manifest_inspect_prints_machine_json():
    result = _run_cli(
        "manifest",
        "inspect",
        str(_EXAMPLES / "genesis.json"),
        "--json",
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "digest": _EXPECTED_DIGEST,
        "manifest_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f24",
        "parent_digest": None,
        "revision": 0,
        "schema_version": 1,
        "scope": "manifest_header",
    }


@pytest.mark.parametrize(
    ("filename", "marker"),
    [
        ("invalid-successor.json", "do-not-echo-successor"),
        ("invalid-duplicate.json", "do-not-echo-duplicate"),
    ],
)
def test_manifest_inspect_rejects_invalid_input_without_echo(
    filename: str, marker: str
):
    result = _run_cli(
        "manifest", "inspect", str(_EXAMPLES / filename), "--json"
    )

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error == {
        "code": "Invalid",
        "cause": "ManifestInvalid",
        "correlation_id": error["correlation_id"],
        "family": "Manifest",
        "input_role": "child",
        "operation": "manifest.inspect",
        "reason": "The child manifest JSON or identity header is invalid.",
        "retryable": False,
        "stage": "header",
    }
    UUID(error["correlation_id"])
    assert marker not in result.stderr


def test_manifest_inspect_rejects_unreadable_path_without_echo(tmp_path):
    missing = tmp_path / "do-not-echo-missing.json"

    result = _run_cli("manifest", "inspect", str(missing), "--json")

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "Manifest"
    assert error["code"] == "Invalid"
    assert error["stage"] == "open"
    assert error["input_role"] == "child"
    assert error["cause"] == "ENOENT"
    assert str(missing) not in result.stderr


def test_manifest_inspect_rejects_oversized_file(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (16 * 1024 * 1024 + 1))

    result = _run_cli("manifest", "inspect", str(oversized), "--json")

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "Manifest"
    assert error["code"] == "Invalid"


def test_cli_rejects_unknown_command_without_echo():
    result = _run_cli("sensitive-command-token")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "The command arguments are invalid." in result.stderr
    assert "sensitive-command-token" not in result.stderr


@pytest.mark.parametrize("machine_json", [False, True])
def test_manifest_inspect_checks_supplied_parent(tmp_path, machine_json):
    parent = tmp_path / "parent.json"
    child = tmp_path / "child.json"
    parent_raw = (_EXAMPLES / "genesis.json").read_bytes()
    parent.write_bytes(parent_raw)
    document = json.loads(parent_raw)
    document.update(revision=1, parent_digest=_EXPECTED_DIGEST)
    child_raw = json.dumps(document).encode("utf-8")
    child.write_bytes(child_raw)
    options = ["--json"] if machine_json else []

    result = _run_cli(
        "manifest", "inspect", str(child), "--parent", str(parent), *options
    )

    assert result.returncode == 0
    assert result.stderr == ""
    if machine_json:
        output = json.loads(result.stdout)
        assert output["scope"] == "manifest_parent_link"
        assert output["revision"] == 1
        assert output["parent_digest"] == _EXPECTED_DIGEST
    else:
        assert "scope: manifest_parent_link\n" in result.stdout
        assert "revision: 1\n" in result.stdout
        assert f"parent_digest: {_EXPECTED_DIGEST}\n" in result.stdout
    assert parent.read_bytes() == parent_raw
    assert child.read_bytes() == child_raw


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"description": "do-not-echo-policy"}, id="tampered-content"),
        pytest.param(
            {"manifest_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f25"},
            id="wrong-manifest",
        ),
        pytest.param(
            {"revision": 1, "parent_digest": "a" * 64}, id="same-revision"
        ),
    ],
)
def test_manifest_inspect_rejects_wrong_parent_without_echo(tmp_path, changes):
    parent = tmp_path / "do-not-echo-parent.json"
    child = tmp_path / "child.json"
    genesis = json.loads((_EXAMPLES / "genesis.json").read_bytes())
    parent.write_text(json.dumps({**genesis, **changes}), encoding="utf-8")
    child.write_text(
        json.dumps({**genesis, "revision": 1, "parent_digest": _EXPECTED_DIGEST}),
        encoding="utf-8",
    )

    result = _run_cli(
        "manifest", "inspect", str(child), "--parent", str(parent), "--json"
    )

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "Manifest"
    assert error["code"] == "Invalid"
    assert error["retryable"] is False
    assert error["stage"] == "parent_link"
    assert error["input_role"] == "pair"
    UUID(error["correlation_id"])
    assert "do-not-echo" not in result.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ["manifest", "inspect", str(_EXAMPLES / "genesis.json"), "--json", "--parent"],
        ["manifest", "inspect", str(_EXAMPLES / "genesis.json"), "--parent", "--json"],
        [
            "manifest", "inspect", str(_EXAMPLES / "genesis.json"),
            "--json", "--unknown", "do-not-echo",
        ],
        ["do-not-echo-command", "--json"],
    ],
)
def test_argument_failures_use_redacted_machine_error(arguments):
    result = _run_cli(*arguments)

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "CLI"
    assert error["code"] == "InvalidArguments"
    assert error["operation"] == "cli"
    assert error["stage"] == "arguments"
    assert error["input_role"] is None
    assert error["cause"] == "ArgumentError"
    UUID(error["correlation_id"])
    assert "do-not-echo" not in result.stderr
    assert "usage:" not in result.stderr


@pytest.mark.parametrize("missing_first", [False, True])
@pytest.mark.parametrize("option_form", ["separate", "equals"])
def test_duplicate_parent_options_reject_both_orders(
    tmp_path, missing_first, option_form
):
    missing = str(tmp_path / "do-not-echo-missing-parent")
    valid = str(_EXAMPLES / "genesis.json")
    parents = [missing, valid] if missing_first else [valid, missing]
    options = []
    for parent in parents:
        options.extend(
            ["--parent", parent]
            if option_form == "separate"
            else [f"--parent={parent}"]
        )

    result = _run_cli(
        "manifest", "inspect", str(_EXAMPLES / "successor.json"), *options, "--json"
    )

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "CLI"
    assert error["code"] == "InvalidArguments"
    assert error["stage"] == "arguments"
    assert error["cause"] == "DuplicateParent"
    assert "do-not-echo" not in result.stderr


def test_duplicate_identical_parent_is_ambiguous():
    parent = str(_EXAMPLES / "genesis.json")
    result = _run_cli("manifest", "inspect", str(_EXAMPLES / "successor.json"),
                      "--parent", parent, "--parent", parent, "--json")

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["cause"] == "DuplicateParent"


def test_option_terminator_does_not_enable_json_for_a_path():
    result = _run_cli("manifest", "inspect", "--", "--json")

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.startswith("cryptalis: Manifest.Invalid:")
    assert "stage=open" in result.stderr


@pytest.mark.parametrize("role", ["child", "parent"])
@pytest.mark.parametrize("failure_errno, expected_exit, expected_code", [
    (errno.EIO, 4, "Unavailable"),
    (errno.EACCES, 2, "Invalid"),
])
def test_filesystem_failures_have_safe_context(
    monkeypatch, capsys, role, failure_errno, expected_exit, expected_code
):
    from cryptalis import cli

    original_open = cli.os.open
    target = _EXAMPLES / ("successor.json" if role == "child" else "genesis.json")

    def fail_target(path, flags):
        if path == target:
            raise OSError(failure_errno, "do-not-echo-filesystem-secret", str(target))
        return original_open(path, flags)

    monkeypatch.setattr(cli.os, "open", fail_target)
    result = cli.main(["manifest", "inspect", str(_EXAMPLES / "successor.json"),
                       "--parent", str(_EXAMPLES / "genesis.json"), "--json"])
    output = capsys.readouterr()

    assert result == expected_exit
    assert output.out == ""
    error = json.loads(output.err)["error"]
    assert error["family"] == "Manifest"
    assert error["code"] == expected_code
    assert error["operation"] == "manifest.inspect"
    assert error["stage"] == "open"
    assert error["input_role"] == role
    assert error["cause"] == errno.errorcode[failure_errno]
    assert "do-not-echo" not in output.err
    assert str(target) not in output.err


def test_invalid_parent_header_identifies_parent(tmp_path):
    parent = tmp_path / "do-not-echo-parent.json"
    parent.write_bytes(b'{"private":"do-not-echo-payload"}')
    result = _run_cli("manifest", "inspect", str(_EXAMPLES / "successor.json"),
                      "--parent", str(parent), "--json")

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["stage"] == "header"
    assert error["input_role"] == "parent"
    assert error["cause"] == "ManifestInvalid"
    assert "do-not-echo" not in result.stderr


@pytest.mark.parametrize("failure_errno, expected_exit, expected_code", [
    (errno.EIO, 4, "Unavailable"),
    (errno.EACCES, 2, "Invalid"),
    (errno.EPERM, 2, "Invalid"),
])
def test_read_failure_has_explicit_category(
    monkeypatch, capsys, failure_errno, expected_exit, expected_code
):
    from cryptalis import cli

    original_fdopen = cli.os.fdopen

    class UnreadableStream:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def read(self, size):
            raise OSError(failure_errno, "do-not-echo-read-secret")

        def close(self):
            self.wrapped.close()

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            self.close()

    def unreadable_stream(descriptor, mode):
        return UnreadableStream(original_fdopen(descriptor, mode))

    monkeypatch.setattr(cli.os, "fdopen", unreadable_stream)
    result = cli.main([
        "manifest", "inspect", str(_EXAMPLES / "genesis.json"), "--json"
    ])
    output = capsys.readouterr()

    assert result == expected_exit
    assert output.out == ""
    error = json.loads(output.err)["error"]
    assert error["code"] == expected_code
    assert error["stage"] == "read"
    assert error["input_role"] == "child"
    assert error["cause"] == errno.errorcode[failure_errno]
    assert "do-not-echo" not in output.err


def test_metadata_permission_failure_is_authorization_error(monkeypatch, capsys):
    from cryptalis import cli

    def denied_metadata(descriptor):
        raise PermissionError(errno.EACCES, "do-not-echo-metadata-secret")

    monkeypatch.setattr(cli.os, "fstat", denied_metadata)
    result = cli.main([
        "manifest", "inspect", str(_EXAMPLES / "genesis.json"), "--json"
    ])
    output = capsys.readouterr()

    assert result == 2
    assert output.out == ""
    error = json.loads(output.err)["error"]
    assert error["code"] == "Invalid"
    assert error["stage"] == "stat"
    assert error["cause"] == "EACCES"
    assert "do-not-echo" not in output.err


@pytest.mark.parametrize("read_fails", [False, True])
def test_stream_close_failure_retains_read_outcome(monkeypatch, capsys, read_fails):
    from cryptalis import cli

    original_fdopen = cli.os.fdopen

    class ClosingFailureStream:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def read(self, size):
            if read_fails:
                raise OSError(errno.EINTR, "do-not-echo-read-secret")
            return self.wrapped.read(size)

        def close(self):
            self.wrapped.close()
            raise OSError(errno.EIO, "do-not-echo-close-secret")

        def __enter__(self):
            return self

        def __exit__(self, *exception):
            self.close()

    def closing_failure_stream(descriptor, mode):
        return ClosingFailureStream(original_fdopen(descriptor, mode))

    monkeypatch.setattr(cli.os, "fdopen", closing_failure_stream)
    result = cli.main([
        "manifest", "inspect", str(_EXAMPLES / "genesis.json"), "--json"
    ])
    output = capsys.readouterr()

    assert result == 4
    assert output.out == ""
    error = json.loads(output.err)["error"]
    assert error["stage"] == "close"
    assert error["cause"] == "EIO"
    if read_fails:
        assert error["related_error"]["stage"] == "read"
        assert error["related_error"]["cause"] == "EINTR"
    else:
        assert "related_error" not in error
    assert "do-not-echo" not in output.err


@pytest.mark.parametrize("machine_json", [False, True])
def test_cleanup_failure_preserves_primary_diagnostic(
    monkeypatch, capsys, machine_json
):
    from cryptalis import cli

    original_close = cli.os.close

    def stat_failure(descriptor):
        raise OSError(errno.EIO, "do-not-echo-stat-secret")

    def close_failure(descriptor):
        original_close(descriptor)
        raise OSError(errno.EIO, "do-not-echo-close-secret")

    monkeypatch.setattr(cli.os, "fstat", stat_failure)
    monkeypatch.setattr(cli.os, "close", close_failure)
    options = ["--json"] if machine_json else []
    result = cli.main([
        "manifest", "inspect", str(_EXAMPLES / "genesis.json"), *options
    ])
    output = capsys.readouterr()

    assert result == 4
    assert output.out == ""
    if machine_json:
        error = json.loads(output.err)["error"]
        assert error["stage"] == "close"
        assert error["cause"] == "EIO"
        assert error["related_error"]["stage"] == "stat"
        assert error["related_error"]["cause"] == "EIO"
    else:
        assert "stage=close" in output.err
        assert "related_stage=stat" in output.err
        assert "related_cause=EIO" in output.err
    assert "do-not-echo" not in output.err


@pytest.mark.parametrize("kind", ["missing", "directory", "oversized", "invalid"])
def test_manifest_inspect_rejects_unusable_parent(tmp_path, kind):
    parent = tmp_path / "do-not-echo-parent"
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps({
            "schema_version": 1,
            "manifest_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f24",
            "revision": 1,
            "parent_digest": _EXPECTED_DIGEST,
        }),
        encoding="utf-8",
    )
    if kind == "directory":
        parent.mkdir()
    elif kind == "oversized":
        parent.write_bytes(b" " * (16 * 1024 * 1024 + 1))
    elif kind == "invalid":
        parent.write_bytes(b'{"description":"do-not-echo-content"')

    result = _run_cli(
        "manifest", "inspect", str(child), "--parent", str(parent), "--json"
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "Invalid"
    assert "do-not-echo" not in result.stderr


@pytest.mark.parametrize(
    ("parent_revision", "child_revision", "same_id", "accepted"),
    [
        pytest.param(1, 2, True, True, id="non-genesis-parent"),
        pytest.param(1, 4, True, True, id="monotonic-gap"),
        pytest.param(1, 2**53 - 1, True, True, id="maximum-revision"),
        pytest.param(1, 1, True, False, id="equal-revision"),
        pytest.param(2, 1, True, False, id="revision-rollback"),
        pytest.param(0, 1, False, False, id="different-id-matching-digest"),
        pytest.param(0, 0, True, False, id="genesis-cannot-have-parent"),
    ],
)
def test_manifest_parent_identity_and_revision_rules(
    tmp_path, parent_revision, child_revision, same_id, accepted
):
    parent = tmp_path / "parent.json"
    child = tmp_path / "child.json"
    document = json.loads((_EXAMPLES / "genesis.json").read_bytes())
    document.update(
        revision=parent_revision,
        parent_digest=None if parent_revision == 0 else "a" * 64,
    )
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    parent_digest = sha256(
        b"cryptalis-manifest-v1\x00" + canonical.encode("utf-8")
    ).hexdigest()
    # Different whitespace and member order must preserve the parent link.
    parent.write_text(json.dumps(document, indent=2), encoding="utf-8")
    document.update(revision=child_revision, parent_digest=parent_digest)
    if not same_id:
        document["manifest_id"] = "018f4f87-6f95-7e2a-9d95-38f9b7646f25"
    child.write_text(json.dumps(document), encoding="utf-8")

    result = _run_cli(
        "manifest", "inspect", str(child), "--parent", str(parent), "--json"
    )

    if accepted:
        assert result.returncode == 0
        assert result.stderr == ""
        assert json.loads(result.stdout)["scope"] == "manifest_parent_link"
    else:
        assert result.returncode == 2
        assert result.stdout == ""
        assert json.loads(result.stderr)["error"]["code"] == "Invalid"


@pytest.mark.parametrize('machine_json', [False, True])
@pytest.mark.parametrize('command', ['inspect', 'help'])
@pytest.mark.parametrize('destination', ['full', 'closed_pipe'])
def test_failed_stdout_returns_redacted_operational_failure(
    machine_json, command, destination
):
    import os

    if destination == 'full':
        if not Path('/dev/full').exists():
            pytest.skip('The full-device fixture requires /dev/full.')
        sink = open('/dev/full', 'wb', buffering=0)
    else:
        reader, writer = os.pipe()
        os.close(reader)
        sink = os.fdopen(writer, 'wb', buffering=0)
    arguments = (
        ['manifest', 'inspect', str(_EXAMPLES / 'genesis.json')]
        if command == 'inspect'
        else ['--help']
    )
    if machine_json:
        arguments.append('--json')
    with sink:
        result = subprocess.run(
            [sys.executable, '-m', 'cryptalis', *arguments],
            cwd=_REPOSITORY_ROOT, stdout=sink, stderr=subprocess.PIPE,
            text=True, check=False, timeout=10,
        )

    assert result.returncode == 4
    assert 'Traceback' not in result.stderr
    assert 'Exception ignored' not in result.stderr
    assert str(_EXAMPLES) not in result.stderr
    if machine_json:
        error = json.loads(result.stderr)['error']
        assert error['family'] == 'CLI'
        assert error['code'] == 'OutputUnavailable'
        assert error['stage'] in ('output_write', 'output_flush')
        assert error['input_role'] is None
        assert error['output_role'] == 'stdout'
        assert error['cause'] == ('ENOSPC' if destination == 'full' else 'EPIPE')
    else:
        assert 'CLI.OutputUnavailable' in result.stderr
        assert 'output_role=stdout' in result.stderr


@pytest.mark.parametrize('machine_json', [False, True])
def test_failed_diagnostic_destination_still_returns_operational_failure(
    machine_json
):
    if not Path('/dev/full').exists():
        pytest.skip('The full-device fixture requires /dev/full.')
    arguments = ['manifest', 'inspect', 'do-not-echo-output-secret']
    if machine_json:
        arguments.append('--json')
    with open('/dev/full', 'wb', buffering=0) as sink:
        result = subprocess.run(
            [sys.executable, '-m', 'cryptalis', *arguments],
            cwd=_REPOSITORY_ROOT, stdout=subprocess.PIPE, stderr=sink,
            text=True, check=False, timeout=10,
        )

    assert result.returncode == 4
    assert result.stdout == ''


@pytest.mark.parametrize('channel', ['stdout', 'stderr'])
def test_missing_output_channel_is_explicit_failure(monkeypatch, capsys, channel):
    from cryptalis import cli

    monkeypatch.setattr(cli.sys, channel, None)
    path = _EXAMPLES / 'genesis.json' if channel == 'stdout' else Path('missing')
    result = cli.main(['manifest', 'inspect', str(path), '--json'])
    output = capsys.readouterr()

    assert result == 4
    assert output.out == ''
    if channel == 'stdout':
        error = json.loads(output.err)['error']
        assert error['code'] == 'OutputUnavailable'
        assert error['cause'] == 'MissingOutputStream'
        assert error['output_role'] == 'stdout'
    else:
        assert output.err == ''


def test_short_output_write_is_not_success(monkeypatch, capsys):
    import io
    from cryptalis import cli

    class ShortWriter(io.StringIO):
        def write(self, text):
            return 0

    monkeypatch.setattr(cli.sys, 'stdout', ShortWriter())
    result = cli.main([
        'manifest', 'inspect', str(_EXAMPLES / 'genesis.json'), '--json'
    ])
    output = capsys.readouterr()

    assert result == 4
    error = json.loads(output.err)['error']
    assert error['cause'] == 'EIO'
    assert error['stage'] == 'output_write'
    assert error['output_role'] == 'stdout'


@pytest.mark.parametrize('channel', ['stdout', 'stderr'])
def test_closed_output_channel_is_explicit_failure(monkeypatch, capsys, channel):
    import io
    from cryptalis import cli

    stream = io.StringIO()
    stream.close()
    monkeypatch.setattr(cli.sys, channel, stream)
    path = _EXAMPLES / 'genesis.json' if channel == 'stdout' else Path('missing')
    result = cli.main(['manifest', 'inspect', str(path), '--json'])
    output = capsys.readouterr()

    assert result == 4
    assert output.out == ''
    if channel == 'stdout':
        error = json.loads(output.err)['error']
        assert error['cause'] == 'InvalidOutputStream'
        assert error['output_role'] == 'stdout'
    else:
        assert output.err == ''


def test_closed_stdout_descriptor_keeps_operational_exit():
    result = subprocess.run(
        [sys.executable, '-c',
         'import os, sys; from cryptalis.cli import main; '
         'os.close(sys.stdout.fileno()); raise SystemExit(main(sys.argv[1:]))',
         'manifest', 'inspect', str(_EXAMPLES / 'genesis.json'), '--json'],
        cwd=_REPOSITORY_ROOT, capture_output=True, text=True,
        check=False, timeout=10,
    )

    assert result.returncode == 4
    assert result.stdout == ''
    error = json.loads(result.stderr)['error']
    assert error['code'] == 'OutputUnavailable'
    assert error['cause'] == 'EBADF'
    assert 'Exception ignored' not in result.stderr


@pytest.mark.parametrize('cleanup_step', ['open', 'dup2'])
@pytest.mark.parametrize('machine_json', [False, True])
def test_output_cleanup_failure_retains_primary_and_operational_exit(
    cleanup_step, machine_json
):
    if not Path('/dev/full').exists():
        pytest.skip('The full-device fixture requires /dev/full.')
    program = '''
import errno, os, sys
from cryptalis import cli
original_open = cli.os.open

def failing_open(path, flags):
    if path == os.devnull:
        raise OSError(errno.EIO, 'do-not-echo-cleanup-secret')
    return original_open(path, flags)

def failing_dup2(source, target):
    raise OSError(errno.EIO, 'do-not-echo-cleanup-secret')

if sys.argv[1] == 'open':
    cli.os.open = failing_open
else:
    cli.os.dup2 = failing_dup2
raise SystemExit(cli.main(sys.argv[2:]))
'''
    arguments = ['manifest', 'inspect', str(_EXAMPLES / 'genesis.json')]
    if machine_json:
        arguments.append('--json')
    with open('/dev/full', 'wb', buffering=0) as sink:
        result = subprocess.run(
            [sys.executable, '-c', program, cleanup_step, *arguments],
            cwd=_REPOSITORY_ROOT, stdout=sink, stderr=subprocess.PIPE,
            text=True, check=False, timeout=10,
        )

    assert result.returncode == 4
    if machine_json:
        error = json.loads(result.stderr)['error']
        stages = []
        while error:
            stages.append(error['stage'])
            assert error['code'] == 'OutputUnavailable'
            error = error.get('related_error')
        assert 'output_cleanup' in stages
        assert 'output_flush' in stages
    else:
        assert 'CLI.OutputUnavailable' in result.stderr
        assert 'related_stage=output_flush' in result.stderr
        assert 'related_cause=ENOSPC' in result.stderr
    assert 'do-not-echo' not in result.stderr
    assert 'Exception ignored' not in result.stderr
