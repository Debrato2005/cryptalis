import argparse
import json
import os
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn, cast
from uuid import uuid4

from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.header import decode_manifest_header
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid


_INVALID_REASON = "The manifest input is invalid."


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"{self.prog}: input error: "
            "The command arguments are invalid.\n",
        )


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="cryptalis",
        description="Inspect Cryptalis Protection Manifests.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser(
        "manifest", help="Work with Protection Manifests."
    )
    manifest_commands = manifest.add_subparsers(
        dest="manifest_command", required=True
    )
    inspect = manifest_commands.add_parser(
        "inspect", help="Inspect one manifest without changing it."
    )
    inspect.add_argument(
        "path", type=Path, help="Path to the manifest JSON file."
    )
    inspect.add_argument(
        "--json",
        action="store_true",
        dest="machine_json",
        help="Write one machine-readable JSON object.",
    )
    inspect.set_defaults(handler=_inspect_command)
    return parser


def _read_manifest(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ManifestInvalid(_INVALID_REASON) from None

    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ManifestInvalid(_INVALID_REASON)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(MAX_DOCUMENT_BYTES + 1)
    except OSError:
        raise ManifestInvalid(_INVALID_REASON) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _result(raw: bytes) -> dict[str, object]:
    header = decode_manifest_header(raw)
    return {
        "scope": "manifest_header",
        "schema_version": header.schema_version,
        "manifest_id": str(header.manifest_id),
        "revision": header.revision,
        "parent_digest": header.parent_digest,
        "digest": digest_manifest_json(raw),
    }


def _write_result(result: dict[str, object], machine_json: bool) -> None:
    if machine_json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return

    parent_digest = result["parent_digest"]
    parent_text = "null" if parent_digest is None else str(parent_digest)
    print(f"scope: {result['scope']}")
    print(f"schema_version: {result['schema_version']}")
    print(f"manifest_id: {result['manifest_id']}")
    print(f"revision: {result['revision']}")
    print(f"parent_digest: {parent_text}")
    print(f"digest: {result['digest']}")


def _write_manifest_error(machine_json: bool) -> None:
    error = {
        "family": "Manifest",
        "code": "Invalid",
        "reason": _INVALID_REASON,
        "retryable": False,
        "correlation_id": str(uuid4()),
    }
    if machine_json:
        print(
            json.dumps(
                {"error": error}, sort_keys=True, separators=(",", ":")
            ),
            file=sys.stderr,
        )
        return

    print(
        "cryptalis: Manifest.Invalid: "
        f"{_INVALID_REASON} retryable=false "
        f"correlation_id={error['correlation_id']}",
        file=sys.stderr,
    )


def _inspect_command(arguments: argparse.Namespace) -> int:
    try:
        raw = _read_manifest(arguments.path)
        result = _result(raw)
    except ManifestInvalid:
        _write_manifest_error(arguments.machine_json)
        return 2

    _write_result(result, arguments.machine_json)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Cryptalis command-line interface."""
    arguments = _parser().parse_args(argv)
    handler = cast(Callable[[argparse.Namespace], int], arguments.handler)
    return handler(arguments)
