import errno
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cryptalis import cli
from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES

_ROOT = Path(__file__).parent.parent
_GENESIS = _ROOT / "examples/manifests/genesis.json"


def _run(*paths: Path, json_mode=True):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "cryptalis",
            "manifest",
            "inspect-history",
            *(str(path) for path in paths),
            *(["--json"] if json_mode else []),
        ],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def _chain(tmp_path):
    raw = _GENESIS.read_bytes()
    paths = []
    for index, revision in enumerate((0, 2, 7)):
        if index:
            document = json.loads(raw)
            document.update(revision=revision, parent_digest=digest_manifest_json(raw))
            raw = json.dumps(document).encode()
        path = tmp_path / f"revision-{revision}.json"
        path.write_bytes(raw)
        paths.append(path)
    return paths


@pytest.mark.parametrize("json_mode", [False, True])
@pytest.mark.parametrize("length", [1, 3])
def test_history_result_states_scope_and_preserves_input(tmp_path, json_mode, length):
    paths = _chain(tmp_path)[:length]
    before = [path.read_bytes() for path in paths]
    result = _run(*paths, json_mode=json_mode)

    assert result.returncode == 0
    assert result.stderr == ""
    expected = {
        **json.loads(before[-1]),
        "digest": digest_manifest_json(before[-1]),
        "scope": "manifest_history",
        "document_count": length,
        "genesis_digest": digest_manifest_json(before[0]),
        "authenticated": False,
    }
    if json_mode:
        assert json.loads(result.stdout) == expected
    else:
        for key, value in expected.items():
            text = (
                "null" if value is None else "false" if value is False else str(value)
            )
            assert f"{key}: {text}\n" in result.stdout
    assert [path.read_bytes() for path in paths] == before


@pytest.mark.parametrize(
    "change",
    [
        "tamper",
        "reorder",
        "missing_genesis",
        "missing_middle",
        "duplicate",
        "wrong_identity",
        "malformed",
        "unsupported_version",
    ],
)
def test_history_rejects_invalid_chains_without_success_or_echo(tmp_path, change):
    paths = _chain(tmp_path)
    if change in ("tamper", "wrong_identity", "unsupported_version"):
        document = json.loads(paths[1].read_bytes())
        if change == "tamper":
            document["description"] = "do-not-echo-policy"
        elif change == "wrong_identity":
            document["manifest_id"] = "018f4f87-6f95-7e2a-9d95-38f9b7646f25"
        else:
            document["schema_version"] = 2
        paths[1].write_text(json.dumps(document), encoding="utf-8")
    elif change == "reorder":
        paths.reverse()
    elif change == "missing_genesis":
        paths = paths[1:]
    elif change == "missing_middle":
        paths.pop(1)
    elif change == "duplicate":
        paths.insert(1, paths[0])
    else:
        paths[1].write_bytes(b'{"do-not-echo-policy":')

    result = _run(*paths)

    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "Manifest"
    assert error["code"] == "Invalid"
    assert error["operation"] == "manifest.inspect_history"
    assert error["input_role"] == "history"
    assert error["stage"] == "history"
    assert error["retryable"] is False
    assert "do-not-echo" not in result.stderr
    assert str(tmp_path) not in result.stderr


def test_history_canonical_links_accept_presentation_changes(tmp_path):
    paths = _chain(tmp_path)
    for path in paths:
        path.write_text(
            json.dumps(json.loads(path.read_bytes()), indent=4), encoding="utf-8"
        )
    assert _run(*paths).returncode == 0


def test_internally_consistent_attacker_history_is_not_authenticated(tmp_path):
    paths = _chain(tmp_path)
    previous = None
    for path in paths:
        document = json.loads(path.read_bytes())
        document["description"] = "synthetic attacker policy"
        document["parent_digest"] = previous
        raw = json.dumps(document).encode()
        path.write_bytes(raw)
        previous = digest_manifest_json(raw)
    result = _run(*paths)
    assert result.returncode == 0
    assert json.loads(result.stdout)["authenticated"] is False
    assert "synthetic attacker policy" not in result.stdout


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo"])
def test_history_rejects_invalid_file_sources(tmp_path, kind):
    path = tmp_path / "do-not-echo-input"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("The FIFO fixture requires os.mkfifo.")
        os.mkfifo(path)
    result = _run(_GENESIS, path)
    assert result.returncode == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["stage"] == ("open" if kind == "missing" else "stat")
    assert error["input_role"] == "history"
    assert error["operation"] == "manifest.inspect_history"
    assert "do-not-echo" not in result.stderr


def test_history_count_limit_precedes_file_access(capsys):
    result = cli.main(
        ["manifest", "inspect-history", *(["do-not-echo-missing"] * 4097), "--json"]
    )
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["stage"] == "history_limits"
    assert error["cause"] == "DocumentLimit"
    assert "do-not-echo" not in captured.err


@pytest.mark.parametrize("excess", [0, 1])
def test_history_enforces_aggregate_byte_limit_during_reads(
    tmp_path, monkeypatch, capsys, excess
):
    paths = _chain(tmp_path)[:2]
    first = paths[0].read_bytes()
    second = paths[1].read_bytes()
    paths[0].write_bytes(first + b" " * (MAX_DOCUMENT_BYTES - len(first) - len(second)))
    paths[1].write_bytes(second + b" " * excess)
    original_fdopen = cli.os.fdopen
    read_sizes = []

    class MeasuredStream:
        def __init__(self, descriptor, mode):
            self.stream = original_fdopen(descriptor, mode)

        def read(self, size):
            read_sizes.append(size)
            return self.stream.read(size)

        def close(self):
            self.stream.close()

    monkeypatch.setattr(cli.os, "fdopen", MeasuredStream)
    result = cli.main(
        ["manifest", "inspect-history", *(str(p) for p in paths), "--json"]
    )
    captured = capsys.readouterr()
    assert read_sizes == [MAX_DOCUMENT_BYTES + 1, len(second) + 1]
    assert result == (2 if excess else 0)
    if excess:
        assert captured.out == ""
        assert json.loads(captured.err)["error"]["cause"] == "ByteLimit"
    else:
        assert captured.err == ""
        assert json.loads(captured.out)["document_count"] == 2


@pytest.mark.parametrize("stage", ["read", "close"])
def test_history_io_failures_retain_redacted_operation(
    tmp_path, monkeypatch, capsys, stage
):
    original_fdopen = cli.os.fdopen

    class FailedStream:
        def __init__(self, descriptor, mode):
            self.stream = original_fdopen(descriptor, mode)

        def read(self, size):
            if stage == "read":
                raise OSError(errno.EIO, "do-not-echo-secret")
            return self.stream.read(size)

        def close(self):
            self.stream.close()
            if stage == "close":
                raise OSError(errno.EIO, "do-not-echo-secret")

    monkeypatch.setattr(cli.os, "fdopen", FailedStream)
    result = cli.main(["manifest", "inspect-history", str(_GENESIS), "--json"])
    captured = capsys.readouterr()
    assert result == 4
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["stage"] == stage
    assert error["operation"] == "manifest.inspect_history"
    assert error["cause"] == "EIO"
    assert "do-not-echo" not in captured.err


@pytest.mark.parametrize("extra", [[], [str(_GENESIS), "--parent", str(_GENESIS)]])
def test_history_requires_paths_and_rejects_parent_selector(extra):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cryptalis",
            "manifest",
            "inspect-history",
            *extra,
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["family"] == "CLI"


def test_history_failed_output_returns_operational_exit():
    if not Path("/dev/full").exists():
        pytest.skip("The full-device fixture requires /dev/full.")
    with open("/dev/full", "wb", buffering=0) as sink:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "cryptalis",
                "manifest",
                "inspect-history",
                str(_GENESIS),
                "--json",
            ],
            stdout=sink,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    assert result.returncode == 4
    assert json.loads(result.stderr)["error"]["code"] == "OutputUnavailable"
    assert "Traceback" not in result.stderr


def test_terminal_demo_checks_real_positive_negative_and_scope_controls(tmp_path):
    result = subprocess.run(
        [sys.executable, str(_ROOT / "examples/demo_manifest_history.py")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.count("ACCEPTED") == 3
    assert result.stdout.count("REJECTED") == 3
    assert "All six expected outcomes passed." in result.stdout
    assert "authentication remains absent" in result.stdout
