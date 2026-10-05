import base64
import errno
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).parent.parent
_DEMO = _ROOT / "examples/demo_smolink_crypto.py"


def _run(*arguments):
    return subprocess.run(
        [sys.executable, str(_DEMO), *arguments],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def _module():
    spec = importlib.util.spec_from_file_location("smolink_crypto_demo", _DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_checks_real_round_trips_and_attack_controls():
    result = _run("--json")
    assert result.returncode == 0
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["scope"] == "smolink_synthetic_aead_lab"
    assert report["algorithm"] == "AES-256-GCM-SIV"
    assert report["runtime_admitted"] is False
    assert report["protected_field_count"] == 5
    assert report["checks"] == {
        "round_trip": "PASS",
        "randomized_rewrite": "PASS",
        "tampered_ciphertext": "REJECTED",
        "truncated_ciphertext": "REJECTED",
        "wrong_key": "REJECTED",
        "wrong_nonce": "REJECTED",
        "wrong_domain": "REJECTED",
        "wrong_tenant": "REJECTED",
        "wrong_subject": "REJECTED",
        "wrong_record": "REJECTED",
        "wrong_field": "REJECTED",
        "wrong_representation": "REJECTED",
        "wrong_purpose": "REJECTED",
        "same_context_replay": "ACCEPTED_SCOPE_LIMIT",
    }
    assert report["synthetic_input"] == report["recovered"]
    assert report["synthetic_input"]["users"][0]["email"] == "alice@example.invalid"
    assert report["synthetic_input"]["urls"][2]["owner_id"] is None
    assert "key" not in report
    assert "ciphertext" not in report


def test_demo_writes_only_ciphertext_and_declared_metadata(tmp_path):
    output = tmp_path / "protected.json"
    result = _run("--json", "--output", str(output))
    assert result.returncode == 0
    assert result.stderr == ""
    report = json.loads(result.stdout)
    snapshot = json.loads(output.read_bytes())
    assert snapshot["scope"] == "smolink_synthetic_aead_lab"
    assert snapshot["runtime_admitted"] is False
    assert snapshot["rows"]["urls"][2]["owner_id"] is None
    assert snapshot["rows"]["urls"][0]["short_code"] == "alice-demo"
    for table, field in (("users", "email"), ("urls", "destination")):
        for original, protected in zip(
            report["synthetic_input"][table], snapshot["rows"][table], strict=True
        ):
            frame = protected[field]
            assert len(base64.b64decode(frame["nonce"], validate=True)) == 12
            ciphertext = base64.b64decode(frame["ciphertext"], validate=True)
            plaintext = original[field].encode()
            assert len(ciphertext) == len(plaintext) + 16
            assert plaintext not in ciphertext
            assert plaintext not in output.read_bytes()
    assert "key" not in snapshot
    assert output.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("kind", ["existing", "missing_parent"])
def test_output_failures_are_redacted_and_preserve_existing_files(tmp_path, kind):
    output = tmp_path / "do-not-echo-secret.json"
    if kind == "existing":
        output.write_bytes(b"preserve-existing-content")
    else:
        output = output / "nested.json"
    result = _run("--json", "--output", str(output))
    assert result.returncode == 4
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["family"] == "Lab"
    assert error["code"] == "OutputUnavailable"
    assert "do-not-echo" not in result.stderr
    assert "Traceback" not in result.stderr
    if kind == "existing":
        assert output.read_bytes() == b"preserve-existing-content"


def test_demo_rejects_external_input_and_duplicate_output_selectors(tmp_path):
    for arguments in (
        ["--input", "do-not-echo-secret", "--json"],
        ["--output", "do-not-echo-one", "--output", "do-not-echo-two", "--json"],
    ):
        result = _run(*arguments)
        assert result.returncode == 2
        assert result.stdout == ""
        assert json.loads(result.stderr)["error"]["code"] == "InvalidArguments"
        assert "do-not-echo" not in result.stderr


def test_demo_redacts_backend_failure(monkeypatch, capsys):
    from cryptography.exceptions import UnsupportedAlgorithm

    demo = _module()

    def unavailable():
        raise UnsupportedAlgorithm("do-not-echo-key-material")

    monkeypatch.setattr(demo, "_build_demo", unavailable)
    assert demo.main(["--json"]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "BackendUnavailable"
    assert "do-not-echo" not in captured.err


def test_attack_control_detects_an_authentication_bypass():
    demo = _module()

    class PermissiveBackend:
        def decrypt(self, nonce, ciphertext, aad):
            return b"released-without-authentication"

    with pytest.raises(RuntimeError, match="authentication control"):
        demo._require_rejection(PermissiveBackend(), b"n" * 12, b"c" * 16, b"aad")


def test_repeated_rng_nonce_fails_without_a_retry(monkeypatch, capsys):
    demo = _module()
    monkeypatch.setattr(demo.os, "urandom", lambda size: b"x" * size)
    assert demo.main(["--json"]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "CheckFailed"


def test_generated_keys_never_enter_report_or_snapshot(monkeypatch, capsys, tmp_path):
    demo = _module()
    original = demo.AESGCMSIV
    keys = []

    class CapturedKeyBackend:
        def __new__(cls, key):
            return original(key)

        @staticmethod
        def generate_key(bit_length):
            key = original.generate_key(bit_length=bit_length)
            keys.append(key)
            return key

    monkeypatch.setattr(demo, "AESGCMSIV", CapturedKeyBackend)
    output = tmp_path / "snapshot.json"
    assert demo.main(["--json", "--output", str(output)]) == 0
    captured = capsys.readouterr()
    channels = (captured.out + captured.err).encode() + output.read_bytes()
    assert len(keys) == 2
    for key in keys:
        leaked = any(
            form in channels
            for form in (key, key.hex().encode(), base64.b64encode(key))
        )
        assert not leaked, "A generated lab key reached an output channel."


@pytest.mark.parametrize("write_errno", [errno.ENOSPC, None])
def test_snapshot_close_failure_preserves_primary_write_failure(
    monkeypatch, capsys, tmp_path, write_errno
):
    import errno

    demo = _module()
    original = demo.os.fdopen

    class FailedFile:
        def __init__(self, descriptor, mode, encoding):
            self.wrapped = original(descriptor, mode, encoding=encoding)

        def write(self, text):
            if write_errno is None:
                raise OSError("do-not-echo-write-secret")
            raise OSError(write_errno, "do-not-echo-write-secret")

        def close(self):
            self.wrapped.close()
            raise OSError(errno.EIO, "do-not-echo-close-secret")

    monkeypatch.setattr(demo.os, "fdopen", FailedFile)
    assert demo.main(["--json", "--output", str(tmp_path / "snapshot.json")]) == 4
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["stage"] == "artifact_close"
    assert error["cause"] == "EIO"
    assert error["related_error"]["stage"] == "artifact_write"
    assert error["related_error"]["cause"] == (
        "ENOSPC" if write_errno else "UnknownIoError"
    )
    assert "do-not-echo" not in captured.err


def test_demo_output_failure_is_operational():
    if not Path("/dev/full").exists():
        pytest.skip("The full-device fixture requires /dev/full.")
    with open("/dev/full", "wb", buffering=0) as sink:
        result = subprocess.run(
            [sys.executable, str(_DEMO), "--json"],
            stdout=sink,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    assert result.returncode == 4
    assert json.loads(result.stderr)["error"]["code"] == "OutputUnavailable"
    assert "Traceback" not in result.stderr


def test_invalid_output_path_is_a_redacted_argument_error(capsys):
    demo = _module()
    assert demo.main(["--json", "--output", "do-not-echo\x00invalid"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)["error"]
    assert error["code"] == "InvalidArguments"
    assert error["cause"] == "InvalidPath"
    assert "do-not-echo" not in captured.err
