import argparse
import errno
import io
import json
import os
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import BinaryIO, Literal, NoReturn, TextIO, cast
from uuid import uuid4

from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.header import (
    ManifestHeader,
    decode_manifest_header,
    validate_manifest_parent_link,
)
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES, ManifestInvalid


_INVALID_PATH_ERRNOS = frozenset(
    (
        errno.ENOENT,
        errno.ENOTDIR,
        errno.EACCES,
        errno.EPERM,
        errno.ELOOP,
        errno.ENAMETOOLONG,
        errno.EISDIR,
    )
)


class _CommandFailure(Exception):
    def __init__(
        self,
        reason: str,
        *,
        stage: str,
        cause: str,
        input_role: str | None = None,
        code: str = "Invalid",
        exit_code: int = 2,
        family: str = "Manifest",
        operation: str = "manifest.inspect",
    ) -> None:
        super().__init__(reason)
        self.exit_code = exit_code
        self.error: dict[str, object] = {
            "family": family,
            "code": code,
            "reason": reason,
            "retryable": False,
            "operation": operation,
            "stage": stage,
            "input_role": input_role,
            "cause": cause,
        }


class _ArgumentParser(argparse.ArgumentParser):
    def print_help(self, file: TextIO | None = None) -> None:
        _write_output(
            self.format_help(), sys.stdout if file is None else file, "stdout"
        )

    def print_usage(self, file: TextIO | None = None) -> None:
        _write_output(
            self.format_usage(), sys.stdout if file is None else file, "stdout"
        )

    def error(self, message: str) -> NoReturn:
        raise _CommandFailure(
            "The command arguments are invalid.",
            family="CLI",
            code="InvalidArguments",
            operation="cli",
            stage="arguments",
            cause="ArgumentError",
        ) from argparse.ArgumentError(None, message)


class _SingleParent(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            raise _CommandFailure(
                "The parent option must occur only once.",
                family="CLI",
                code="InvalidArguments",
                operation="cli",
                stage="arguments",
                cause="DuplicateParent",
            )
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="cryptalis",
        allow_abbrev=False,
        description="Inspect Cryptalis Protection Manifests.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser(
        "manifest",
        help="Work with Protection Manifests.",
        allow_abbrev=False,
    )
    manifest_commands = manifest.add_subparsers(
        dest="manifest_command", required=True
    )
    inspect = manifest_commands.add_parser(
        "inspect",
        help="Inspect one manifest without changing it.",
        allow_abbrev=False,
    )
    inspect.add_argument(
        "path", type=Path, help="Path to the manifest JSON file."
    )
    inspect.add_argument(
        "--parent",
        type=Path,
        action=_SingleParent,
        help="Check the link to one supplied local parent manifest.",
    )
    inspect.add_argument(
        "--json",
        action="store_true",
        dest="machine_json",
        help="Write one machine-readable JSON object.",
    )
    inspect.set_defaults(handler=_inspect_command)
    return parser


def _io_failure(
    error: OSError,
    stage: Literal["open", "stat", "read", "close"],
    input_role: Literal["child", "parent"],
) -> _CommandFailure:
    invalid_path = (
        stage == "open" and error.errno in _INVALID_PATH_ERRNOS
    ) or (
        stage != "close" and error.errno in (errno.EACCES, errno.EPERM)
    )
    reasons = {
        "open": f"Cannot open the {input_role} manifest file.",
        "stat": f"The {input_role} manifest file metadata is unavailable.",
        "read": f"Cannot read the {input_role} manifest file.",
        "close": f"Cannot close the {input_role} manifest file.",
    }
    return _CommandFailure(
        reasons[stage],
        stage=stage,
        input_role=input_role,
        cause=(
            errno.errorcode.get(error.errno, "UnknownIoError")
            if error.errno is not None
            else "UnknownIoError"
        ),
        code="Invalid" if invalid_path else "Unavailable",
        exit_code=2 if invalid_path else 4,
    )


def _read_manifest(path: Path, input_role: Literal["child", "parent"]) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _io_failure(error, "open", input_role) from error
    except ValueError as error:
        raise _CommandFailure(
            f"The {input_role} manifest path is invalid.",
            stage="open",
            input_role=input_role,
            cause="InvalidPath",
        ) from error

    stage: Literal["stat", "read"] = "stat"
    stream: BinaryIO | None = None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _CommandFailure(
                f"The {input_role} manifest input must be a regular file.",
                stage="stat",
                input_role=input_role,
                cause="NotRegularFile",
            )
        stage = "read"
        stream = os.fdopen(descriptor, "rb")
        return stream.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as error:
        raise _io_failure(error, stage, input_role) from error
    finally:
        primary_error = sys.exception()
        try:
            if stream is None:
                os.close(descriptor)
            else:
                stream.close()
        except OSError as error:
            failure = _io_failure(error, "close", input_role)
            if isinstance(primary_error, _CommandFailure):
                failure.error["related_error"] = primary_error.error
            raise failure from error


def _header(
    raw: bytes, input_role: Literal["child", "parent"]
) -> ManifestHeader:
    try:
        return decode_manifest_header(raw)
    except ManifestInvalid as error:
        raise _CommandFailure(
            f"The {input_role} manifest JSON or identity header is invalid.",
            stage="header",
            input_role=input_role,
            cause="ManifestInvalid",
        ) from error


def _result(raw: bytes, parent_raw: bytes | None = None) -> dict[str, object]:
    header = _header(raw, "child")
    if parent_raw is not None:
        _header(parent_raw, "parent")
        try:
            header = validate_manifest_parent_link(raw, parent_raw)
        except ManifestInvalid as error:
            raise _CommandFailure(
                "The supplied manifest parent link is invalid.",
                stage="parent_link",
                input_role="pair",
                cause="ManifestInvalid",
            ) from error
    return {
        "scope": (
            "manifest_header" if parent_raw is None else "manifest_parent_link"
        ),
        "schema_version": header.schema_version,
        "manifest_id": str(header.manifest_id),
        "revision": header.revision,
        "parent_digest": header.parent_digest,
        "digest": digest_manifest_json(raw),
    }


def _output_failure(
    error: OSError | ValueError | None,
    stage: str,
    output_role: Literal["stdout", "stderr"],
) -> _CommandFailure:
    if error is None:
        cause = "MissingOutputStream"
    elif isinstance(error, ValueError):
        cause = "InvalidOutputStream"
    else:
        cause = errno.errorcode.get(error.errno, "UnknownIoError")
    failure = _CommandFailure(
        f"Cannot deliver command output to {output_role}.",
        family="CLI",
        code="OutputUnavailable",
        operation="cli.output",
        stage=stage,
        cause=cause,
        exit_code=4,
    )
    failure.error["output_role"] = output_role
    return failure


def _write_output(
    text: str, stream: TextIO | None, output_role: Literal["stdout", "stderr"]
) -> None:
    if stream is None:
        raise _output_failure(None, "output_write", output_role)
    stage = "output_write"
    try:
        if stream.write(text) != len(text):
            raise OSError(errno.EIO, "Command output write was incomplete.")
        stage = "output_flush"
        stream.flush()
    except (OSError, ValueError) as error:
        failure = _output_failure(error, stage, output_role)
        # A failed native buffer must not retry at interpreter shutdown.
        if isinstance(stream, io.TextIOWrapper) and not stream.closed:
            try:
                target = stream.fileno()
                sink = os.open(os.devnull, os.O_WRONLY)
                if sink != target:
                    try:
                        os.dup2(sink, target)
                    finally:
                        os.close(sink)
                # If open reused the target, ownership stays with the stream.
            except (OSError, ValueError) as cleanup_error:
                cleanup = _output_failure(
                    cleanup_error, "output_cleanup", output_role
                )
                cleanup.error["related_error"] = failure.error
                try:
                    stream.close()
                except (OSError, ValueError) as close_error:
                    close_failure = _output_failure(
                        close_error, "output_close", output_role
                    )
                    close_failure.error["related_error"] = cleanup.error
                    raise close_failure from close_error
                raise cleanup from cleanup_error
        raise failure from error


def _write_result(result: dict[str, object], machine_json: bool) -> None:
    if machine_json:
        text = json.dumps(result, sort_keys=True, separators=(",", ":"))
    else:
        parent_digest = result["parent_digest"]
        parent_text = "null" if parent_digest is None else str(parent_digest)
        text = (
            f"scope: {result['scope']}\n"
            f"schema_version: {result['schema_version']}\n"
            f"manifest_id: {result['manifest_id']}\n"
            f"revision: {result['revision']}\n"
            f"parent_digest: {parent_text}\n"
            f"digest: {result['digest']}"
        )
    _write_output(text + "\n", sys.stdout, "stdout")


def _write_error(failure: _CommandFailure, machine_json: bool) -> None:
    error = {**failure.error, "correlation_id": str(uuid4())}
    if machine_json:
        _write_output(
            json.dumps({"error": error}, sort_keys=True, separators=(",", ":"))
            + "\n",
            sys.stderr,
            "stderr",
        )
        return

    related = cast(dict[str, object] | None, error.get("related_error"))
    related_context = ""
    related_depth = 1
    while related is not None:
        related_context += (
            f" related_depth={related_depth}"
            f" related_error={related['family']}.{related['code']}"
            f" related_stage={related['stage']}"
            f" related_input_role={related['input_role']}"
            f" related_cause={related['cause']}"
        )
        related = cast(dict[str, object] | None, related.get("related_error"))
        related_depth += 1
    output_context = (
        f" output_role={error['output_role']}" if "output_role" in error else ""
    )
    _write_output(
        f"cryptalis: {error['family']}.{error['code']}: {error['reason']} "
        f"operation={error['operation']} stage={error['stage']} "
        f"input_role={error['input_role']} cause={error['cause']} retryable=false "
        f"correlation_id={error['correlation_id']}{output_context}{related_context}\n",
        sys.stderr,
        "stderr",
    )


def _inspect_command(arguments: argparse.Namespace) -> int:
    raw = _read_manifest(arguments.path, "child")
    parent_raw = (
        None
        if arguments.parent is None
        else _read_manifest(arguments.parent, "parent")
    )
    result = _result(raw, parent_raw)
    _write_result(result, arguments.machine_json)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Cryptalis command-line interface."""
    tokens = list(sys.argv[1:] if argv is None else argv)
    option_end = tokens.index("--") if "--" in tokens else len(tokens)
    machine_json = "--json" in tokens[:option_end]
    try:
        arguments = _parser().parse_args(tokens)
        handler = cast(Callable[[argparse.Namespace], int], arguments.handler)
        return handler(arguments)
    except _CommandFailure as failure:
        try:
            _write_error(failure, machine_json)
        except _CommandFailure as diagnostic_failure:
            diagnostic_failure.error["related_error"] = failure.error
            # With stderr unavailable, the exit status is the error channel.
            return diagnostic_failure.exit_code
        return failure.exit_code
