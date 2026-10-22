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
        description="Inspect Cryptalis artifacts, deployments and transition progress.",
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
    status = commands.add_parser('status', help='Inspect one protection or reverse transition without changes.',
                                 allow_abbrev=False)
    status.add_argument('plan', type=Path, help='Original protection or reverse plan artifact.')
    status.add_argument('--pin', type=Path, required=True, help='Current host-controlled deployment pin.')
    status.add_argument('--database-url-file', type=Path, required=True,
                        help='Private file with the PostgreSQL connection URL or conninfo.')
    status.add_argument('--restore-binding', type=Path, help='Approved restored-target binding, when applicable.')
    status.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    status.set_defaults(handler=_status_command)
    doctor = commands.add_parser('doctor', help='Inspect active runtime admission without changes.',
                                 allow_abbrev=False)
    doctor.add_argument('plan', type=Path, help='Published protection or rotation activation artifact.')
    doctor.add_argument('--pin', type=Path, required=True, help='Current host-controlled ACTIVE deployment pin.')
    doctor.add_argument('--database-url-file', type=Path, required=True,
                        help='Private file with the declared runtime PostgreSQL connection URL or conninfo.')
    doctor.add_argument('--restore-binding', type=Path, help='Approved restored-target binding, when applicable.')
    doctor.add_argument('--json', action='store_true', dest='machine_json', help='Write one JSON object.')
    doctor.set_defaults(handler=_status_command)
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
    _write_output(
        f"cryptalis: {error['family']}.{error['code']}: {error['reason']} "
        f"operation={error['operation']} stage={error['stage']} "
        f"input_role={error['input_role']} cause={error['cause']} retryable=false "
        f"correlation_id={error['correlation_id']}{output_context}{related_context}\n",
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


def _status_command(arguments: argparse.Namespace) -> int:
    # Runtime dependencies stay lazy: manifest inspection and CLI help remain
    # usable without database or cryptographic imports.
    doctor = arguments.command == 'doctor'
    operation = 'deployment.doctor' if doctor else 'transition.status'
    try:
        import psycopg
        from sqlalchemy import create_engine
        from cryptalis.migration import (DeploymentPin, MigrationPlan, TransitionFailure,
                                         status, diagnose_deployment, _decode_transition_json)
        from cryptalis.deprotection import DeprotectionPlan, status as reverse_status
        from cryptalis.manifest.parser import decode_manifest_json
        from cryptalis.restore import RestoreBinding
        from uuid import UUID
    except ImportError:
        failure = _CommandFailure('Install the declared runtime dependencies before database inspection.',
            family='Transition', code='DependenciesUnavailable', operation=operation,
            stage='load_runtime', cause='ImportError', exit_code=4)
        raise (_doctor_failure(failure) if doctor else failure) from None

    try:
        def read(path, role, limit=MAX_DOCUMENT_BYTES):
            raw = _read_local_file(path, role, max_bytes=limit, operation=operation)
            if len(raw) > limit:
                raise ValueError('input bound')
            return raw
        raw_plan = read(arguments.plan, 'plan')
        reverse = _decode_transition_json(raw_plan).get('format') == 'cryptalis.reverse/v1'
        if doctor and reverse:
            raise ValueError('Doctor requires an active protection artifact')
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
    except _CommandFailure as failure:
        failure.error['family'] = 'Transition'
        raise (_doctor_failure(failure) if doctor else failure) from None
    except (ValueError, TypeError, KeyError, AttributeError, TransitionFailure):
        failure = _CommandFailure('Supply a valid plan, pin, private connection file, and optional restore binding.',
            family='Transition', code='InvalidInput', operation=operation,
            stage='inputs', cause='InvalidInput')
        raise (_doctor_failure(failure) if doctor else failure) from None

    engine = None
    try:
        engine = create_engine('postgresql+psycopg://', echo=False, hide_parameters=True,
            creator=lambda: psycopg.connect(connection_info, connect_timeout=5))
        if doctor:
            diagnose_deployment(plan, engine, pin=pin, restore=binding)
        else:
            observed = reverse_status(plan, engine, pin=pin) if reverse else status(plan, engine, pin=pin, restore=binding)
    except TransitionFailure as error:
        operational = bool(error.cleanup_errors) or error.code in ('operation_failed_requires_inspection',
            'database_effect_requires_inspection', 'connection_cleanup_requires_inspection')
        denied = error.code in ('external_policy_mismatch', 'wrong_database_target',
            'restore_binding_mismatch', 'restore_binding_required', 'restored_definition_restatement_unsupported',
            'invalid_plan', 'invalid_reverse_plan', 'external_reverse_policy_mismatch')
        failure = _CommandFailure('Inspection failed. Check this operation and the current external policy.',
            family='Transition', code=error.code, operation=operation,
            stage='database_inspection', cause=error.sqlstate or 'InspectionFailed',
            exit_code=4 if operational else 2 if denied else 3)
        if error.cleanup_errors:
            failure.error['cleanup_errors'] = [
                {'stage': stage, 'cause': cause, 'sqlstate': sqlstate}
                for stage, cause, sqlstate in error.cleanup_errors]
        raise (_doctor_failure(failure, observed=not (operational or denied)) if doctor else failure) from None
    finally:
        if engine is not None:
            primary = sys.exception()
            try:
                engine.dispose()
            except Exception as error:
                failure = _CommandFailure('Inspection connection cleanup failed. Inspect the database session.',
                    family='Transition', code='CleanupUnavailable', operation=operation,
                    stage='connection_cleanup', cause=type(error).__name__, exit_code=4)
                if isinstance(primary, _CommandFailure):
                    failure.error['related_error'] = primary.error
                raise (_doctor_failure(failure) if doctor else failure) from None
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
        'scope': 'reverse_transition' if reverse else 'protection_transition', 'operation_id': str(observed.operation_id),
        'phase': observed.phase, 'external_phase': observed.external_phase,
        'committed_rows': observed.committed_rows, 'committed_chunks': observed.committed_chunks,
        'runtime_metadata_matches': observed.runtime_metadata_matches,
        'verification': observed.verification, 'authority': 'HOST_SUPPLIED_PIN',
        'effects': 'NONE', 'remedy': observed.remedy,
    }
    if reverse:
        result['source_operation_id'] = str(plan.source.operation_id)
    output = json.dumps(result, sort_keys=True, separators=(',', ':')) if arguments.machine_json else '\n'.join(
        f'{key}: {str(value).lower() if type(value) is bool else "UNKNOWN" if value is None else value}' for key, value in result.items())
    _write_output(output + '\n', sys.stdout, 'stdout')
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
            _doctor_failure(failure)
        try:
            _write_error(failure, machine_json)
        except _CommandFailure as diagnostic_failure:
            diagnostic_failure.error["related_error"] = failure.error
            # With stderr unavailable, the exit status is the error channel.
            return diagnostic_failure.exit_code
        return failure.exit_code
