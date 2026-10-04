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
    UUID(error["correlation_id"])
    assert "do-not-echo" not in result.stderr


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
