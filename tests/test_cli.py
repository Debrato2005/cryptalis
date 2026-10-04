import json
import subprocess
import sys
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
        "correlation_id": error["correlation_id"],
        "family": "Manifest",
        "reason": "The manifest input is invalid.",
        "retryable": False,
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
