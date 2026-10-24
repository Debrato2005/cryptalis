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
from uuid import UUID, uuid4

from cryptalis.manifest.canonical import digest_manifest_json
from cryptalis.manifest.header import (
    _MAX_HISTORY_BYTES,
    _MAX_HISTORY_DOCUMENTS,
    ManifestHeader,
    decode_manifest_header,
    validate_manifest_history,
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
        description="Plan protection, run approved transitions and inspect Cryptalis state.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    initialization = commands.add_parser('init', help='Create a declaration and inspect explicit host configuration.',
        allow_abbrev=False)
    initialization.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
        help='Trusted synchronous factory returning the exact key-free InitializationContext.')
    initialization.add_argument('--out', type=Path, required=True, help='New private canonical declaration path. Existing paths refuse.')
    initialization.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    initialization.set_defaults(handler=_operational_command)
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
    history = manifest_commands.add_parser(
        "inspect-history",
        help="Inspect a supplied genesis-to-head history without authentication.",
        allow_abbrev=False,
    )
    history.add_argument(
        "paths",
        type=Path,
        nargs="+",
        help="Local manifest files in genesis-to-head order.",
    )
    history.add_argument(
        "--json",
        action="store_true",
        dest="machine_json",
        help="Write one machine-readable JSON object.",
    )
    history.set_defaults(handler=_inspect_history_command)
    status = commands.add_parser('status', help='Inspect protection, rotation preparation or reverse progress without changes.',
                                 allow_abbrev=False)
    status.add_argument('plan', type=Path, help='Protection, rotation preparation or reverse plan artifact.')
    status.add_argument('--pin', type=Path, required=True, help='Current host-controlled deployment pin.')
    status.add_argument('--database-url-file', type=Path, required=True,
                        help='Private file with the PostgreSQL connection URL or conninfo.')
    status.add_argument('--restore-binding', type=Path, help='Approved restored-target binding, when applicable.')
    status.add_argument('--host-context', metavar='MODULE:FACTORY',
                        help='Optional trusted synchronous factory for declared lineage backup references; completeness and availability remain UNKNOWN.')
    status.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    status.set_defaults(handler=_status_command)
    doctor = commands.add_parser('doctor', help='Inspect native schema or ACTIVE runtime admission.',
        description='Compiler inspection is read-only. An explicit host context imports and calls trusted '
                    'Python code; its effects remain UNKNOWN. This command does not sandbox host code.',
        allow_abbrev=False)
    modes = doctor.add_mutually_exclusive_group(required=True)
    modes.add_argument('plan', type=Path, nargs='?', help='Published protection or rotation activation artifact.')
    modes.add_argument('--pre-adoption', type=Path, metavar='MANIFEST', help='Inspect a native schema before adoption.')
    doctor.add_argument('--host-context', metavar='MODULE:FACTORY',
        help='Explicit trusted synchronous factory returning (registry, WriterInventory, tuple[SearchReview]). '
             'Host Python effects remain UNKNOWN; no keys or engine belong in this tuple.')
    doctor.add_argument('--pin', type=Path, help='Current host-controlled ACTIVE deployment pin.')
    doctor.add_argument('--database-url-file', type=Path, required=True,
                        help='Private file with the declared runtime PostgreSQL connection URL or conninfo.')
    doctor.add_argument('--restore-binding', type=Path, help='Approved restored-target binding, when applicable.')
    doctor.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    doctor.set_defaults(handler=_doctor_command)
    plan = commands.add_parser('plan', help='Plan protection or current-value reverse with an explicit host context.',
        allow_abbrev=False)
    plan.add_argument('manifest', type=Path, nargs='?', help='Protection declaration JSON file; excludes --reverse.')
    plan.add_argument('--reverse', type=Path, metavar='SOURCE', help='Plan reverse from this protection artifact; excludes MANIFEST and --layout.')
    plan.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
        help='Trusted synchronous factory returning a PlanningContext or ReversePlanningContext. Host effects remain UNKNOWN.')
    plan.add_argument('--out', type=Path, required=True, help='New private plan artifact. Existing paths refuse.')
    plan.add_argument('--layout', choices=('preserve-public-slots/v1',),
        help='Select the explicit original public-column layout.')
    plan.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    plan.set_defaults(handler=_operational_command)
    for name, description in (
            ('apply', 'Apply, resume or abort a protection or reverse transition.'),
            ('rollback', 'Transform current protected values using an approved saved reverse plan.')):
        apply = commands.add_parser(name, help=description, allow_abbrev=False)
        apply.add_argument('plan', type=Path, help='Immutable plan artifact. Rollback accepts reverse plans only.')
        apply.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
            help='Trusted synchronous factory returning the matching ApplyContext or ReverseApplyContext.')
        modes = apply.add_mutually_exclusive_group()
        modes.add_argument('--resume', type=UUID, metavar='OPERATION', help='Inspect and resume this exact operation.')
        modes.add_argument('--abort', type=UUID, metavar='OPERATION', help='Remove owned staging before switch.')
        apply.add_argument('--until', choices=('EXPANDED', 'BACKFILLED', 'VERIFIED', 'PENDING', 'ACTIVE',
            'PLAINTEXT_PENDING', 'PLAINTEXT_ACTIVE'),
            help='Requested phase for the supplied plan. Publication requires matching host authority.')
        apply.add_argument('--chunk-size', type=int, default=1000, help='Rows per committed chunk, from 1 through 5000.')
        apply.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
        apply.set_defaults(handler=_operational_command)
    remove = commands.add_parser('remove', help='Retire generated objects with explicit plaintext and removal approvals.',
        allow_abbrev=False)
    remove.add_argument('plan', type=Path, help='Immutable reverse plan artifact.')
    remove.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
        help='Trusted synchronous factory returning a key-free RemovalContext with current host approvals.')
    remove.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    remove.set_defaults(handler=_operational_command)
    keys = commands.add_parser('keys', help='Run explicitly authorized key lifecycle operations.', allow_abbrev=False)
    key_commands = keys.add_subparsers(dest='keys_command', required=True)
    rotate = key_commands.add_parser('rotate', help='Rotate admitted key custody.', allow_abbrev=False)
    purposes = rotate.add_subparsers(dest='rotation_kind', required=True)
    rewrap = purposes.add_parser('rewrap', help='Rewrap unchanged roots through saved proposal and successor artifacts.',
        allow_abbrev=False)
    actions = rewrap.add_subparsers(dest='rewrap_action', required=True)
    for action, description in (
            ('plan', 'Authenticate current roots and frames and save a rewrap proposal.'),
            ('apply', 'Save the exact successor and commit the approved rewrap as PENDING.'),
            ('activate', 'Publish a saved rewrap successor under explicit host authority.'),
            ('abort', 'Cancel a pending rewrap under republished source ACTIVE authority.')):
        command = actions.add_parser(action, help=description, allow_abbrev=False)
        command.add_argument('source' if action == 'plan' else 'plan', type=Path,
            help='Source protection artifact.' if action == 'plan' else
                 'Saved successor artifact.' if action == 'activate' else 'Saved rewrap proposal.')
        command.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
            help='Trusted synchronous factory returning the exact context for this rewrap action.')
        if action in ('plan', 'apply'):
            command.add_argument('--out', type=Path, required=True,
                help='New private proposal artifact.' if action == 'plan' else 'Durable exact successor artifact.')
        if action == 'apply':
            command.add_argument('--resume', type=UUID, metavar='OPERATION',
                help='Resume this operation and re-sync an existing exact private successor artifact.')
        command.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
        command.set_defaults(handler=_operational_command)
    for purpose in ('payload', 'search'):
        generation = purposes.add_parser(purpose, help=f'Stage, seal and publish an admitted {purpose} generation.',
            allow_abbrev=False)
        generation_actions = generation.add_subparsers(dest=purpose + '_action', required=True)
        for action, description in (
                ('plan', f'Save a {purpose} preparation proposal with explicit host inputs.'),
                ('apply', 'Stage encrypted chunks under the saved preparation.'),
                ('status', 'Inspect recorded preparation or successor progress without keys.'),
                ('seal', 'Authenticate completed staging and save its activation artifact.'),
                ('switch', 'Switch verified staging using a saved durable activation artifact.'),
                ('activate', 'Publish the saved successor under explicit host authority.'),
                ('abort', 'Discard preparation staging under republished source authority.')):
            command = generation_actions.add_parser(action, help=description, allow_abbrev=False)
            command.add_argument('source' if action == 'plan' else 'plan', type=Path,
                help='Source protection artifact.' if action == 'plan' else 'Saved preparation or activation artifact.')
            command.add_argument('--host-context', required=True, metavar='MODULE:FACTORY',
                help=f'Trusted synchronous factory returning the exact context for this {purpose} action.')
            if action in ('plan', 'seal'):
                command.add_argument('--out', type=Path, required=True, help='New private artifact path. Existing paths refuse.')
            if action == 'plan':
                command.add_argument('--max-batch-rows', type=int, help='Preparation row bound; omitted uses the existing planner default.')
                command.add_argument('--max-batch-bytes', type=int, help='Preparation byte bound; omitted uses the existing planner default.')
            if action in ('apply', 'switch'):
                command.add_argument('--resume', type=UUID, metavar='OPERATION',
                    help='Resume the exact preparation UUID for apply or activation UUID for switch.')
            if action == 'apply':
                command.add_argument('--until', choices=('EXPANDED', 'BACKFILLED'),
                    help='Requested staging phase. The default is BACKFILLED.')
                command.add_argument('--max-chunks', type=int, help='Stop after this many committed chunks.')
            if action == 'switch':
                command.add_argument('--activation', type=Path, required=True,
                    help='Exact private activation artifact sealed from the completed staging.')
            command.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
            command.set_defaults(handler=_operational_command)
    return parser


def _io_failure(
    error: OSError,
    stage: Literal["open", "stat", "read", "close"],
    input_role: str,
    operation: str = "manifest.inspect",
) -> _CommandFailure:
    invalid_path = (
        stage == "open" and error.errno in _INVALID_PATH_ERRNOS
    ) or (
        stage != "close" and error.errno in (errno.EACCES, errno.EPERM)
    )
    reasons = {
        "open": f"Cannot open the {input_role} input file.",
        "stat": f"The {input_role} input file metadata is unavailable.",
        "read": f"Cannot read the {input_role} input file.",
        "close": f"Cannot close the {input_role} input file.",
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
        operation=operation,
    )


def _read_local_file(
    path: Path,
    input_role: str,
    *,
    max_bytes: int = MAX_DOCUMENT_BYTES,
    operation: str = "manifest.inspect",
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise _io_failure(error, "open", input_role, operation) from error
    except ValueError as error:
        raise _CommandFailure(
            f"The {input_role} input path is invalid.",
            stage="open",
            input_role=input_role,
            cause="InvalidPath",
            operation=operation,
        ) from error

    stage: Literal["stat", "read"] = "stat"
    stream: BinaryIO | None = None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _CommandFailure(
                f"The {input_role} input must be a regular file.",
                stage="stat",
                input_role=input_role,
                cause="NotRegularFile",
                operation=operation,
            )
        stage = "read"
        stream = os.fdopen(descriptor, "rb")
        return stream.read(max_bytes + 1)
    except OSError as error:
        raise _io_failure(error, stage, input_role, operation) from error
    finally:
        primary_error = sys.exception()
        try:
            if stream is None:
                os.close(descriptor)
            else:
                stream.close()
        except OSError as error:
            failure = _io_failure(error, "close", input_role, operation)
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
        if result["scope"] == "manifest_history":
            text += (
                f"\ndocument_count: {result['document_count']}"
                f"\ngenesis_digest: {result['genesis_digest']}"
                "\nauthenticated: false"
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
    inspection_context = (
        f" operation_id={error['operation_id']}" if 'operation_id' in error else ''
    )
    if 'remedy' in error:
        inspection_context += f" remedy={error['remedy']}"
    _write_output(
        f"cryptalis: {error['family']}.{error['code']}: {error['reason']} "
        f"operation={error['operation']} stage={error['stage']} "
        f"input_role={error['input_role']} cause={error['cause']} retryable=false "
        f"correlation_id={error['correlation_id']}{output_context}{inspection_context}{related_context}\n",
        sys.stderr,
        "stderr",
    )


def _inspect_command(arguments: argparse.Namespace) -> int:
    raw = _read_local_file(arguments.path, "child")
    parent_raw = (
        None
        if arguments.parent is None
        else _read_local_file(arguments.parent, "parent")
    )
    result = _result(raw, parent_raw)
    _write_result(result, arguments.machine_json)
    return 0


def _inspect_history_command(arguments: argparse.Namespace) -> int:
    operation = "manifest.inspect_history"
    if len(arguments.paths) > _MAX_HISTORY_DOCUMENTS:
        raise _CommandFailure(
            "Supply at most 4096 manifest history files.",
            stage="history_limits",
            input_role="history",
            cause="DocumentLimit",
            operation=operation,
        )

    documents: list[bytes] = []
    remaining = _MAX_HISTORY_BYTES
    for path in arguments.paths:
        # The sentinel byte detects overflow without reading another full file.
        raw = _read_local_file(
            path,
            "history",
            max_bytes=min(MAX_DOCUMENT_BYTES, remaining),
            operation=operation,
        )
        if len(raw) > remaining:
            raise _CommandFailure(
                "The complete manifest history must not exceed 16 MiB.",
                stage="history_limits",
                input_role="history",
                cause="ByteLimit",
                operation=operation,
            )
        remaining -= len(raw)
        documents.append(raw)

    try:
        header = validate_manifest_history(tuple(documents))
    except ManifestInvalid as error:
        raise _CommandFailure(
            "Supply a valid manifest history in genesis-to-head order.",
            stage="history",
            input_role="history",
            cause="ManifestInvalid",
            operation=operation,
        ) from error

    result: dict[str, object] = {
        "scope": "manifest_history",
        "schema_version": header.schema_version,
        "manifest_id": str(header.manifest_id),
        "revision": header.revision,
        "parent_digest": header.parent_digest,
        "digest": digest_manifest_json(documents[-1]),
        "document_count": len(documents),
        "genesis_digest": digest_manifest_json(documents[0]),
        "authenticated": False,
    }
    _write_result(result, arguments.machine_json)
    return 0


def _doctor_checks(runtime_status='UNKNOWN', runtime_code='RuntimeDeployment.NotInspected'):
    unknown = {
        'provider_keys': 'Provider access, key compatibility and custody were not inspected.',
        'frame_authentication': 'Stored frames and their current generations were not authenticated.',
        'query_routes': 'Application query routes were not inspected.',
        'writer_exclusion': 'External writers and deployment fencing were not inspected.',
        'host_authority': 'The supplied host pin and restore approval were not authenticated.',
        'recovery_capacity': 'Recovery inventory, pause, storage and WAL capacity were not measured.',
    }
    return {
        'runtime_deployment': {'status': runtime_status, 'code': runtime_code},
        **{name: {'status': 'UNKNOWN', 'reason': reason} for name, reason in unknown.items()},
    }


def _doctor_failure(failure, *, observed=False):
    failure.error['status'] = 'FAIL' if observed else 'UNKNOWN'
    failure.error['checks'] = _doctor_checks('FAIL' if observed else 'UNKNOWN', failure.error['code'])
    return failure


def _preflight_failure(failure, report=None):
    failure.error.update(report or {
        'scope': 'pre_adoption', 'status': 'UNKNOWN',
        'checks': {name: 'UNKNOWN' for name in (
            'manifest_schema', 'provider_keys', 'query_routes', 'writer_exclusion',
            'runtime_deployment', 'host_authority', 'recovery_capacity')},
    })
    failure.error.update(effects='NONE', effects_scope='compiler_inspection',
                         host_configuration_effects='UNKNOWN')
    return failure


def _operational_command(arguments):
    try:
        from cryptalis._cli_operations import run
    except ImportError:
        raise _CommandFailure('Install the declared runtime dependencies before lifecycle operations.',
            family='Transition', code='DependenciesUnavailable', operation='transition.' + arguments.command,
            stage='load_runtime', cause='ImportError', exit_code=4) from None
    return run(arguments)


def _doctor_command(arguments):
    if arguments.pre_adoption is None:
        valid = arguments.host_context is None and arguments.pin is not None
    else:
        reference = (arguments.host_context or '').split(':')
        valid = (arguments.pin is None and arguments.restore_binding is None and len(reference) == 2
            and all(part.isidentifier() for part in reference[0].split('.'))
            and reference[1].isidentifier())
    if not valid:
        raise _CommandFailure('Supply either an ACTIVE plan and pin, or a pre-adoption manifest and trusted host context.',
            family='CLI', code='InvalidArguments', operation='cli', stage='arguments', cause='ArgumentError')
    return _status_command(arguments) if arguments.pre_adoption is None else _preflight_command(arguments)


def _preflight_command(arguments):
    operation = 'deployment.preflight'
    try:
        import importlib
        import inspect
        from contextlib import redirect_stderr, redirect_stdout
        from types import CoroutineType
        import psycopg
        from sqlalchemy import create_engine
        from sqlalchemy.orm import registry as Registry
        from cryptalis.doctor import preflight
        from cryptalis.manifest.compiler import WriterInventory, SearchReview
        from cryptalis.manifest.declaration import parse_protection_declaration
    except ImportError:
        raise _preflight_failure(_CommandFailure('Install the declared runtime dependencies before database inspection.',
            family='Doctor', code='DependenciesUnavailable', operation=operation,
            stage='load_runtime', cause='ImportError', exit_code=4)) from None
    try:
        raw = _read_local_file(arguments.pre_adoption, 'manifest', operation=operation)
        parse_protection_declaration(raw)
        connection_info = _read_local_file(arguments.database_url_file, 'database',
            max_bytes=65536, operation=operation)
        if len(connection_info) > 65536:
            raise ValueError
        connection_info = connection_info.decode('utf-8').strip()
        if not connection_info or '\x00' in connection_info:
            raise ValueError
        if connection_info.startswith('postgresql+psycopg://'):
            connection_info = 'postgresql://' + connection_info[len('postgresql+psycopg://'):]
        psycopg.conninfo.conninfo_to_dict(connection_info)
    except _CommandFailure as failure:
        raise _preflight_failure(failure) from None
    except (ManifestInvalid, ValueError, UnicodeError, psycopg.ProgrammingError):
        raise _preflight_failure(_CommandFailure('Supply a valid protection declaration and private PostgreSQL connection file.',
            family='Doctor', code='InvalidInput', operation=operation,
            stage='inputs', cause='InvalidInput')) from None

    module_name, factory_name = arguments.host_context.split(':')
    try:
        # Discard Python stream output without retaining private host configuration.
        # Native descriptor writes remain outside this trusted-code boundary.
        with open(os.devnull, 'w', encoding='utf-8') as discard, redirect_stdout(discard), redirect_stderr(discard):
            factory = getattr(importlib.import_module(module_name), factory_name)
            valid_factory = callable(factory) and not inspect.iscoroutinefunction(factory)
            context = factory() if valid_factory else None
    except BaseException:
        # Host exception classes and messages can contain private configuration.
        raise _preflight_failure(_CommandFailure('The trusted host context could not load. Check its module and synchronous factory.',
            family='Doctor', code='HostContextUnavailable', operation=operation,
            stage='host_context', cause='HostContextError', exit_code=4)) from None
    if isinstance(context, CoroutineType):
        context.close()
    if (type(context) is not tuple or len(context) != 3 or not isinstance(context[0], Registry)
            or not isinstance(context[1], WriterInventory) or type(context[2]) is not tuple
            or any(not isinstance(review, SearchReview) for review in context[2])):
        raise _preflight_failure(_CommandFailure('Return exactly (registry, WriterInventory, tuple[SearchReview]) without keys or an engine.',
            family='Doctor', code='HostContextInvalid', operation=operation,
            stage='host_context', cause='InvalidContext')) from None

    engine = report = None
    try:
        engine = create_engine('postgresql+psycopg://', echo=False, hide_parameters=True,
            creator=lambda: psycopg.connect(connection_info, connect_timeout=5))
        report = preflight(raw, context[0], engine, writers=context[1], search_reviews=context[2])
        report.update(effects_scope='compiler_inspection', host_configuration_effects='UNKNOWN')
    except Exception:
        raise _preflight_failure(_CommandFailure('Schema inspection is unavailable. Check the connection and trusted host configuration.',
            family='Doctor', code='InspectionUnavailable', operation=operation,
            stage='inspection', cause='InspectionError', exit_code=4)) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                engine.dispose()
            except Exception:
                failure = _preflight_failure(_CommandFailure('Inspection connection cleanup failed. Inspect the database session.',
                    family='Doctor', code='CleanupUnavailable', operation=operation,
                    stage='connection_cleanup', cause='CleanupError', exit_code=4))
                if report is not None:
                    failure.error['inspection'] = report
                if isinstance(primary, _CommandFailure):
                    failure.error['related_error'] = primary.error
                raise failure from None
    if report['checks']['manifest_schema'] != 'PASS':
        incompatible = report['checks']['manifest_schema'] == 'FAIL'
        raise _preflight_failure(_CommandFailure(
            'Resolve the schema issues before planning protection.' if incompatible else
            'Schema inspection is unavailable. Check the connection and retry inspection.',
            family='Doctor', code='SchemaIncompatible' if incompatible else 'InspectionUnavailable',
            operation=operation, stage='inspection', cause='SchemaAdmission' if incompatible else 'InspectionUnavailable',
            exit_code=3 if incompatible else 4), report) from None
    output = (json.dumps(report, sort_keys=True, separators=(',', ':')) if arguments.machine_json else
        '\n'.join(f'{key}: {value}' for key, value in report.items() if key not in ('checks', 'issues'))
        + '\n' + '\n'.join(f'{name}: {status}' for name, status in report['checks'].items()))
    _write_output(output + '\n', sys.stdout, 'stdout')
    return 0


def _status_command(arguments: argparse.Namespace) -> int:
    # Runtime dependencies stay lazy: manifest inspection and CLI help remain
    # usable without database or cryptographic imports.
    doctor = arguments.command == 'doctor'
    operation = 'deployment.doctor' if doctor else 'transition.status'
    retained_specification = None if doctor else getattr(arguments, 'host_context', None)
    retained = None

    def metadata_failure(failure):
        if retained_specification is not None:
            failure.error.update(effects='NONE', host_configuration_effects='UNKNOWN')
            if retained is not None:
                failure.error['retained_obligations'] = retained
        return failure
    try:
        import psycopg
        from sqlalchemy import create_engine
        from cryptalis.migration import (DeploymentPin, MigrationPlan, TransitionFailure,
                                         status, diagnose_deployment, _decode_transition_json)
        from cryptalis.deprotection import DeprotectionPlan, status as reverse_status
        from cryptalis.rotation import (PayloadRotationPlan, SearchRotationPlan,
                                        status_payload_rotation, status_search_rotation)
        from cryptalis.manifest.parser import decode_manifest_json
        from cryptalis.restore import RestoreBinding
        from uuid import UUID
    except ImportError:
        failure = _CommandFailure('Install the declared runtime dependencies before database inspection.',
            family='Transition', code='DependenciesUnavailable', operation=operation,
            stage='load_runtime', cause='ImportError', exit_code=4)
        raise (_doctor_failure(failure) if doctor else metadata_failure(failure)) from None

    try:
        def read(path, role, limit=MAX_DOCUMENT_BYTES):
            raw = _read_local_file(path, role, max_bytes=limit, operation=operation)
            if len(raw) > limit:
                raise ValueError('input bound')
            return raw
        raw_plan = read(arguments.plan, 'plan')
        artifact_format = _decode_transition_json(raw_plan).get('format')
        reverse = artifact_format == 'cryptalis.reverse/v1'
        preparation_type = next((candidate for candidate in (PayloadRotationPlan, SearchRotationPlan)
            if artifact_format in (candidate.format, candidate.restore_format)), None)
        preparation = preparation_type is not None
        if doctor and (reverse or preparation):
            raise ValueError('Doctor requires an active protection artifact')
        if preparation:
            plan = preparation_type(raw_plan)
            if arguments.restore_binding is not None:
                raise ValueError('Set restore authority when planning the rotation. Do not pass a separate binding to status.')
        else:
            plan = DeprotectionPlan(raw_plan) if reverse else MigrationPlan(raw_plan)
        pin_document = decode_manifest_json(read(arguments.pin, 'pin', 65536))
        if set(pin_document) != {'target_id', 'operation_id', 'plan_digest', 'phase'}:
            raise ValueError('pin members')
        pin = DeploymentPin(UUID(pin_document['target_id']), UUID(pin_document['operation_id']),
                            pin_document['plan_digest'], pin_document['phase'])
        binding = None if arguments.restore_binding is None else RestoreBinding(
            read(arguments.restore_binding, 'restore_binding'))
        if reverse:
            from cryptalis.deprotection import _pin
            _pin(plan, pin)
            if binding is not None and binding.document != plan.document['restore']:
                raise ValueError('reverse restore identity')
        connection_info = read(arguments.database_url_file, 'database', 65536).decode('utf-8').strip()
        if not connection_info or '\x00' in connection_info:
            raise ValueError('invalid connection input')
        connection_info = connection_info.replace('postgresql+psycopg://', 'postgresql://', 1)
        if retained_specification is not None:
            if preparation:
                from cryptalis._rotation_transition import _pin as admit_preparation
                admit_preparation(plan, pin)
            elif not reverse:
                from cryptalis.migration import _admit
                _admit(plan, pin)
                if binding is not None:
                    from cryptalis.restore import _identity
                    _identity(plan, binding)
    except _CommandFailure as failure:
        failure.error['family'] = 'Transition'
        raise (_doctor_failure(failure) if doctor else metadata_failure(failure)) from None
    except (ValueError, TypeError, KeyError, AttributeError, TransitionFailure):
        failure = _CommandFailure('Supply a valid plan, pin, private connection file, and optional restore binding.',
            family='Transition', code='InvalidInput', operation=operation,
            stage='inputs', cause='InvalidInput')
        raise (_doctor_failure(failure) if doctor else metadata_failure(failure)) from None

    if retained_specification is not None:
        from cryptalis._retained_obligations import report
        retained = report(plan, retained_specification)

    engine = None
    try:
        engine = create_engine('postgresql+psycopg://', echo=False, hide_parameters=True,
            creator=lambda: psycopg.connect(connection_info, connect_timeout=5))
        if doctor:
            diagnose_deployment(plan, engine, pin=pin, restore=binding)
        elif preparation:
            inspect_preparation = status_payload_rotation if plan.purpose=='payload' else status_search_rotation
            observed = inspect_preparation(plan, engine, pin=pin)
        else:
            observed = reverse_status(plan, engine, pin=pin) if reverse else status(plan, engine, pin=pin, restore=binding)
    except TransitionFailure as error:
        operational = bool(error.cleanup_errors) or error.code in ('operation_failed_requires_inspection',
            'database_effect_requires_inspection', 'connection_cleanup_requires_inspection')
        denied = error.code in ('external_policy_mismatch', 'wrong_database_target',
            'payload_operation_pin_mismatch', 'search_operation_pin_mismatch',
            'restore_binding_mismatch', 'restore_binding_required', 'restored_definition_restatement_unsupported',
            'invalid_plan', 'invalid_reverse_plan', 'external_reverse_policy_mismatch')
        reason, remedy = {
            'attachment_requires_planned_runtime_role': (
                'This inspection requires the runtime role declared in the plan.',
                'Use a private connection file for the declared runtime role.'),
            'unsafe_runtime_role': (
                'The declared runtime role is missing or has unsafe privileges.',
                'Restore the declared runtime role. Remove unsafe administrative or inherited rights, '
                'database/schema CREATE, table TRIGGER/TRUNCATE, and journal mutation rights; '
                'keep required application CRUD.'),
            'external_policy_mismatch': (
                'The supplied pin does not authorize this plan and phase.',
                'Obtain the current pin from the host authority and check its plan identity, '
                'digest, and permitted phase.'),
        }.get(error.code, ('Inspection failed. Check this operation and the current external policy.', None))
        failure = _CommandFailure(reason,
            family='Transition', code=error.code, operation=operation,
            stage='database_inspection', cause=error.sqlstate or 'InspectionFailed',
            exit_code=4 if operational else 2 if denied else 3)
        failure.error['operation_id'] = str(plan.operation_id)
        if remedy is not None:
            failure.error['remedy'] = remedy
        if error.cleanup_errors:
            failure.error['cleanup_errors'] = [
                {'stage': stage, 'cause': cause, 'sqlstate': sqlstate}
                for stage, cause, sqlstate in error.cleanup_errors]
        raise (_doctor_failure(failure, observed=not (operational or denied)) if doctor else metadata_failure(failure)) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                engine.dispose()
            except Exception as error:
                failure = _CommandFailure('Inspection connection cleanup failed. Inspect the database session.',
                    family='Transition', code='CleanupUnavailable', operation=operation,
                    stage='connection_cleanup', cause=type(error).__name__, exit_code=4)
                failure.error['operation_id'] = str(plan.operation_id)
                if isinstance(primary, _CommandFailure):
                    failure.error['related_error'] = primary.error
                raise (_doctor_failure(failure) if doctor else metadata_failure(failure)) from None
    if doctor:
        result = {
            'scope': 'active_runtime_deployment', 'operation_id': str(plan.operation_id),
            'status': 'UNKNOWN', 'checks': _doctor_checks('PASS', 'RuntimeDeployment.Matches'),
            'verification': 'NOT_PERFORMED', 'authority': 'HOST_SUPPLIED_PIN', 'effects': 'NONE',
        }
        if arguments.machine_json:
            output = json.dumps(result, sort_keys=True, separators=(',', ':'))
        else:
            output = '\n'.join(f'{key}: {value}' for key, value in result.items() if key != 'checks')
            output += '\n' + '\n'.join(f'{name}: {check["status"]} '
                f'({check.get("code", check.get("reason"))})' for name, check in result['checks'].items())
        _write_output(output + '\n', sys.stdout, 'stdout')
        return 0
    result = {
        'scope': (plan.purpose+'_rotation_preparation' if preparation else
                  'reverse_transition' if reverse else 'protection_transition'),
        'operation_id': str(observed.operation_id),
        'phase': observed.phase, 'external_phase': observed.external_phase,
        'committed_rows': observed.committed_rows, 'committed_chunks': observed.committed_chunks,
        'runtime_metadata_matches': observed.runtime_metadata_matches,
        'verification': observed.verification, 'authority': 'HOST_SUPPLIED_PIN',
        'effects': 'NONE', 'remedy': observed.remedy,
    }
    if reverse or preparation:
        result['source_operation_id'] = str(plan.source.operation_id)
    if retained is not None:
        result.update(retained_obligations=retained, host_configuration_effects='UNKNOWN')
    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {str(value).lower() if type(value) is bool else "UNKNOWN" if value is None else value}' for key, value in result.items())
    try:
        _write_output(output + '\n', sys.stdout, 'stdout')
    except _CommandFailure as failure:
        raise metadata_failure(failure) from None
    return 0 if observed.runtime_metadata_matches else 3


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
        if tokens and tokens[0] == 'doctor' and 'checks' not in failure.error:
            if any(token.split('=', 1)[0] in ('--pre-adoption', '--host-context') for token in tokens[:option_end]):
                _preflight_failure(failure)
            else:
                _doctor_failure(failure)
        try:
            _write_error(failure, machine_json)
        except _CommandFailure as diagnostic_failure:
            diagnostic_failure.error["related_error"] = failure.error
            # With stderr unavailable, the exit status is the error channel.
            return diagnostic_failure.exit_code
        return failure.exit_code
