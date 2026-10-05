"""Synthetic Smolink AEAD research example. No Cryptalis runtime admission."""

import base64
import copy
import errno
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID, uuid5

import cryptography
from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from cryptalis.cli import _ArgumentParser, _CommandFailure, _write_error, _write_output

_SCOPE = "smolink_synthetic_aead_lab"
_ALGORITHM = "AES-256-GCM-SIV"
_LAB_NAMESPACE = UUID("89eb8d21-a432-4b03-a081-b000f81cc714")


def _lab_id(label: str) -> str:
    return str(uuid5(_LAB_NAMESPACE, label))


def _synthetic_rows() -> dict[str, list[dict[str, Any]]]:
    # Only these built-in values can enter the example. No application data is read.
    return {
        "users": [
            {"id": 101, "email": "alice@example.invalid"},
            {"id": 102, "email": "bob@example.invalid"},
        ],
        "urls": [
            {
                "id": 201,
                "owner_id": 101,
                "short_code": "alice-demo",
                "destination": "https://example.invalid/alice/report",
            },
            {
                "id": 202,
                "owner_id": 102,
                "short_code": "bob-demo",
                "destination": "https://example.invalid/bob/notes",
            },
            {
                "id": 203,
                "owner_id": None,
                "short_code": "guest-demo",
                "destination": "https://example.invalid/guest/notes",
            },
        ],
    }


def _binding(table: str, row: dict[str, Any], field: str) -> dict[str, str]:
    subject = row["id"] if table == "users" else row["owner_id"]
    return {
        "lab_version": "1",
        "algorithm": _ALGORITHM,
        "domain": _lab_id("environment:synthetic"),
        "tenant": _lab_id("tenant:synthetic-only"),
        "subject": _lab_id(f"subject:{subject}"),
        "record": _lab_id(f"record:{table}:{row['id']}"),
        "model": _lab_id(f"model:{table}"),
        "table": _lab_id(f"table:{table}"),
        "field": _lab_id(f"field:{table}:{field}"),
        "representation": _lab_id(f"representation:{table}:{field}:lab-1"),
        "purpose": "synthetic-payload-trial",
    }


def _aad(binding: dict[str, str]) -> bytes:
    # This encoding is lab-specific. It is neither F1 nor the future runtime binding.
    return json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fresh_nonce(seen: set[bytes]) -> bytes:
    nonce = os.urandom(12)
    if nonce in seen:
        raise RuntimeError("The nonce control failed.")
    seen.add(nonce)
    return nonce


def _require_rejection(
    cipher: AESGCMSIV, nonce: bytes, ciphertext: bytes, aad: bytes
) -> None:
    try:
        cipher.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        return
    raise RuntimeError("The authentication control failed.")


def _build_demo() -> tuple[dict[str, Any], dict[str, Any]]:
    if cryptography.__version__ != "50.0.2":
        raise UnsupportedAlgorithm("The example requires its pinned library version.")
    cipher = AESGCMSIV(AESGCMSIV.generate_key(bit_length=256))
    original = _synthetic_rows()
    protected = copy.deepcopy(original)
    recovered = copy.deepcopy(original)
    preview = copy.deepcopy(original)
    seen: set[bytes] = set()
    vectors: list[tuple[bytes, bytes, bytes, dict[str, str]]] = []
    for table, field in (("users", "email"), ("urls", "destination")):
        for index, row in enumerate(original[table]):
            plaintext = row[field].encode("utf-8")
            binding = _binding(table, row, field)
            nonce = _fresh_nonce(seen)
            ciphertext = cipher.encrypt(nonce, plaintext, _aad(binding))
            decoded = cipher.decrypt(nonce, ciphertext, _aad(binding))
            if decoded != plaintext:
                raise RuntimeError("The round-trip control failed.")
            recovered[table][index][field] = decoded.decode("utf-8")
            protected[table][index][field] = {
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "binding": binding,
            }
            preview[table][index][field] = f"<encrypted: {len(ciphertext)} bytes>"
            vectors.append((nonce, ciphertext, plaintext, binding))

    nonce, ciphertext, plaintext, binding = vectors[0]
    rewrite_nonce = _fresh_nonce(seen)
    rewrite = cipher.encrypt(rewrite_nonce, plaintext, _aad(binding))
    if (
        rewrite == ciphertext
        or cipher.decrypt(rewrite_nonce, rewrite, _aad(binding)) != plaintext
    ):
        raise RuntimeError("The randomized-rewrite control failed.")
    checks = {"round_trip": "PASS", "randomized_rewrite": "PASS"}
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    wrong_nonce = bytes([nonce[0] ^ 1]) + nonce[1:]
    wrong_key = AESGCMSIV(AESGCMSIV.generate_key(bit_length=256))
    for name, candidate_cipher, candidate_nonce, candidate_bytes in (
        ("tampered_ciphertext", cipher, nonce, tampered),
        ("truncated_ciphertext", cipher, nonce, ciphertext[:-1]),
        ("wrong_key", wrong_key, nonce, ciphertext),
        ("wrong_nonce", cipher, wrong_nonce, ciphertext),
    ):
        _require_rejection(
            candidate_cipher, candidate_nonce, candidate_bytes, _aad(binding)
        )
        checks[name] = "REJECTED"
    for component in (
        "domain",
        "tenant",
        "subject",
        "record",
        "field",
        "representation",
        "purpose",
    ):
        changed = {**binding, component: _lab_id(f"substitution:{component}")}
        _require_rejection(cipher, nonce, ciphertext, _aad(changed))
        checks[f"wrong_{component}"] = "REJECTED"
    if cipher.decrypt(nonce, ciphertext, _aad(binding)) != plaintext:
        raise RuntimeError("The replay scope control failed.")
    checks["same_context_replay"] = "ACCEPTED_SCOPE_LIMIT"

    report = {
        "scope": _SCOPE,
        "runtime_admitted": False,
        "algorithm": _ALGORITHM,
        "cryptography_version": cryptography.__version__,
        "openssl_version": backend.openssl_version_text(),
        "protected_field_count": len(vectors),
        "synthetic_input": original,
        "storage_preview": preview,
        "recovered": recovered,
        "checks": checks,
    }
    snapshot = {
        "scope": _SCOPE,
        "runtime_admitted": False,
        "algorithm": _ALGORITHM,
        "key_persisted": False,
        "rows": protected,
    }
    return report, snapshot


def _artifact_failure(error: OSError | ValueError, stage: str) -> _CommandFailure:
    if isinstance(error, OSError):
        cause = (
            errno.errorcode.get(error.errno, "UnknownIoError")
            if error.errno is not None
            else "UnknownIoError"
        )
    else:
        cause = "InvalidOutputStream"
    return _CommandFailure(
        "Choose a new output path in an existing writable directory.",
        family="Lab",
        code="OutputUnavailable",
        exit_code=4,
        operation="lab.smolink_crypto",
        stage=stage,
        cause=cause,
    )


def _save_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    text = json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise _artifact_failure(error, "artifact_open") from error
    except ValueError as error:
        raise _CommandFailure(
            "Supply a valid output path.",
            family="Lab",
            code="InvalidArguments",
            operation="lab.smolink_crypto",
            stage="artifact_open",
            cause="InvalidPath",
        ) from error
    stream: TextIO | None = None
    try:
        stream = os.fdopen(descriptor, "w", encoding="utf-8")
        if stream.write(text) != len(text):
            raise OSError(errno.EIO, "Snapshot write was incomplete.")
        stream.flush()
    except (OSError, ValueError) as error:
        raise _artifact_failure(error, "artifact_write") from error
    finally:
        primary = sys.exception()
        try:
            if stream is None:
                os.close(descriptor)
            else:
                stream.close()
        except (OSError, ValueError) as error:
            failure = _artifact_failure(error, "artifact_close")
            if isinstance(primary, _CommandFailure):
                failure.error["related_error"] = primary.error
            raise failure from error


def _render(report: dict[str, Any]) -> str:
    lines = [
        "CRYPTALIS RESEARCH: synthetic Smolink field encryption",
        "Fixed fake data. No application, database, or production key is read.",
        f"{report['algorithm']} | cryptography {report['cryptography_version']} | {report['openssl_version']}",
    ]
    for title, member in (
        ("1. SYNTHETIC INPUT", "synthetic_input"),
        ("2. ENCRYPTED STORAGE PREVIEW", "storage_preview"),
        ("3. RECOVERED VALUES", "recovered"),
    ):
        lines.extend(("", title, json.dumps(report[member], indent=2)))
    lines.extend(("", "4. CHECKED OUTCOMES"))
    for name, outcome in report["checks"].items():
        lines.append(f"  {outcome:22} {name}")
    lines.extend(
        (
            "",
            "Five field values recovered exactly. Eleven misuse cases rejected.",
            "Same-context replay still works. AEAD alone supplies no freshness.",
            "The temporary key stays in memory. No key is printed or saved.",
            "Research example only. Cryptalis runtime admission remains pending.",
        )
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    machine_json = (
        "--json" in tokens[: tokens.index("--") if "--" in tokens else len(tokens)]
    )
    try:
        parser = _ArgumentParser(
            prog="demo_smolink_crypto",
            allow_abbrev=False,
            description="Run one fixed synthetic AEAD research example.",
        )
        parser.add_argument("--json", action="store_true", help="Write a JSON report.")
        parser.add_argument(
            "--output",
            type=Path,
            action="append",
            help="Create one new synthetic ciphertext snapshot. Never overwrite.",
        )
        args = parser.parse_args(tokens)
        if args.output is not None and len(args.output) != 1:
            raise _CommandFailure(
                "Supply the output option only once.",
                family="Lab",
                code="InvalidArguments",
                operation="lab.smolink_crypto",
                stage="arguments",
                cause="DuplicateOutput",
            )
        try:
            report, snapshot = _build_demo()
        except UnsupportedAlgorithm as error:
            raise _CommandFailure(
                "Run uv sync --locked with a compatible backend.",
                family="Lab",
                code="BackendUnavailable",
                exit_code=4,
                operation="lab.smolink_crypto",
                stage="crypto",
                cause="UnsupportedAlgorithm",
            ) from error
        except (InvalidTag, RuntimeError, OSError) as error:
            raise _CommandFailure(
                "The synthetic encryption checks failed.",
                family="Lab",
                code="CheckFailed",
                exit_code=4,
                operation="lab.smolink_crypto",
                stage="crypto",
                cause="ControlFailure",
            ) from error
        if args.output is not None:
            _save_snapshot(args.output[0], snapshot)
        text = (
            json.dumps(report, sort_keys=True) + "\n" if args.json else _render(report)
        )
        _write_output(text, sys.stdout, "stdout")
        return 0
    except _CommandFailure as failure:
        try:
            _write_error(failure, machine_json)
        except _CommandFailure as delivery_failure:
            return delivery_failure.exit_code
        return failure.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
