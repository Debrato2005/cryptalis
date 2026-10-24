"""Validate host-declared backup references without inspecting keys or files."""
import re
from uuid import UUID

from cryptalis import migration as m
from cryptalis.cli_host import RetainedBackupObligation, RetainedObligationsContext
from cryptalis.manifest.parser import MAX_DOCUMENT_BYTES


_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def _digest(value):
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _failure(code, *, operational=False):
    from cryptalis.cli import _CommandFailure
    failure = _CommandFailure('Supply an explicit retained-backup context bound to this status artifact.',
        family='Transition', code=code, operation='transition.status', stage='retained_obligations',
        cause=code, exit_code=4 if operational else 2)
    failure.error.update(effects='NONE', host_configuration_effects='UNKNOWN',
        remedy='Check the current operation and saved lineage source artifacts. Digest references do not prove availability or complete inventory.')
    return failure


def report(plan, specification):
    """Return scoped public declarations, never recovery or retirement authority."""
    from cryptalis._cli_operations import _load_host, _quiet
    from cryptalis.cli import _CommandFailure
    try:
        context = _load_host(specification, 'transition.status')
    except _CommandFailure as failure:
        raise _failure(failure.error['code'], operational=failure.exit_code == 4) from None
    try:
        with _quiet():
            if (type(context) is not RetainedObligationsContext
                    or set(vars(context)) != {'operation_id', 'plan_digest', 'records'}
                    or type(context.operation_id) is not UUID or context.operation_id.int == 0
                    or not _digest(context.plan_digest)
                    or (context.operation_id, context.plan_digest) != (plan.operation_id, plan.digest)
                    or type(context.records) is not tuple or len(context.records) > 64):
                raise ValueError
            source = plan if type(plan) is m.MigrationPlan else plan.source
            allowed = {(str(source.operation_id), source.digest)} | {
                (entry['operation_id'], entry['plan_digest']) for entry in source.document.get('predecessors', [])}
            total = 0
            identities = set()
            records = []
            for record in context.records:
                if (type(record) is not RetainedBackupObligation
                        or set(vars(record)) != {'backup_id', 'source_plan', 'dump_sha256', 'reader_sha256', 'drill_sha256'}
                        or type(record.backup_id) is not UUID or record.backup_id.int == 0
                        or record.backup_id in identities or type(record.source_plan) is not bytes
                        or not _digest(record.dump_sha256)
                        or any(value is not None and not _digest(value) for value in (record.reader_sha256, record.drill_sha256))):
                    raise ValueError
                total += len(record.source_plan)
                if total > MAX_DOCUMENT_BYTES:
                    raise ValueError
                identities.add(record.backup_id)
                saved = m.MigrationPlan(record.source_plan)
                if (str(saved.operation_id), saved.digest) not in allowed:
                    raise ValueError
                records.append(dict(backup_id=str(record.backup_id), source_operation_id=str(saved.operation_id),
                    source_plan_digest=saved.digest, required_policy_digests=saved.document['key_policies'],
                    dump_sha256=record.dump_sha256, reader_sha256=record.reader_sha256, drill_sha256=record.drill_sha256,
                    provenance='HOST_DECLARED_DIGEST_REFERENCES'))
    except Exception:
        raise _failure('RetainedObligationsInvalid') from None
    return dict(scope='host_declared_lineage_backup_obligations', status='UNKNOWN',
        authority='HOST_SUPPLIED_METADATA', verification='NOT_PERFORMED', inventory_completeness='UNKNOWN',
        reader_availability='UNKNOWN', provider_availability='UNKNOWN', reported_count=len(records), records=records)
