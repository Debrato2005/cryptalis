"""Explicit trusted host inputs for operational CLI commands.

Factories supply a fresh, owned synchronous PostgreSQL psycopg Engine with
transactional connections. The command disposes it on every outcome. This
ownership assertion is a host responsibility, not proof of deployment fencing.
Initialization and pre-adoption Doctor can share a key-free context.
"""
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.orm import registry

from cryptalis.crypto.keys import KeyPolicy, Keyring
from cryptalis.deprotection import PlaintextApproval, RemovalApproval
from cryptalis.manifest.compiler import SearchReview, WriterInventory
from cryptalis.migration import DeploymentPin, MaintenanceApproval
from cryptalis.restore import RestoreBinding


@dataclass(frozen=True, repr=False)
class PlanningContext:
    engine: Engine
    mapping: registry
    writers: WriterInventory
    search_reviews: tuple[SearchReview, ...]
    keys: Keyring | Callable[[UUID], Keyring]
    runtime_role: str
    target_id: UUID
    backfill_rows_per_second: float
    verify_rows_per_second: float
    temporary_bytes_per_row: int
    wal_bytes_per_row: int
    declaration: bytes | None = None
    queries: tuple = ()


@dataclass(frozen=True, repr=False)
class ApplyContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class ReversePlanningContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    plaintext_runtime_role: str
    backfill_rows_per_second: float
    verify_rows_per_second: float
    temporary_bytes_per_row: int
    wal_bytes_per_row: int
    restore: RestoreBinding | None


@dataclass(frozen=True, repr=False)
class ReverseApplyContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval
    consent: PlaintextApproval


@dataclass(frozen=True, repr=False)
class RemovalContext:
    engine: Engine
    pin: DeploymentPin
    approval: MaintenanceApproval
    consent: PlaintextApproval
    removal: RemovalApproval


@dataclass(frozen=True, repr=False)
class TenantPlanningContext:
    """One host-approved typed scope and trusted policy, never CLI-selected keys."""
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    tenant_id: UUID
    key_policy: Keyring
    verify_rows_per_second: float
    restore: RestoreBinding | None


@dataclass(frozen=True, repr=False)
class TenantApplyContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class TenantActivationContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class TenantAbortContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class RewrapPlanningContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    verify_rows_per_second: float
    restore: RestoreBinding | None


@dataclass(frozen=True, repr=False)
class RewrapApplyContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class RewrapActivationContext:
    engine: Engine
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class RewrapAbortContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class PayloadPlanningContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    backfill_rows_per_second: float
    verify_rows_per_second: float
    temporary_bytes_per_row: int
    wal_bytes_per_row: int
    restore: RestoreBinding | None


@dataclass(frozen=True, repr=False)
class PayloadApplyContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class PayloadStatusContext:
    engine: Engine
    pin: DeploymentPin


@dataclass(frozen=True, repr=False)
class PayloadSealingContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval
    copy_rows_per_second: float
    copy_wal_bytes_per_row: int


@dataclass(frozen=True, repr=False)
class PayloadSwitchContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class PayloadActivationContext:
    engine: Engine
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class PayloadAbortContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class SearchPlanningContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    backfill_rows_per_second: float
    verify_rows_per_second: float
    temporary_bytes_per_row: int
    wal_bytes_per_row: int
    restore: RestoreBinding | None


@dataclass(frozen=True, repr=False)
class SearchApplyContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class SearchStatusContext:
    engine: Engine
    pin: DeploymentPin


@dataclass(frozen=True, repr=False)
class SearchSealingContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval
    copy_rows_per_second: float
    copy_wal_bytes_per_row: int


@dataclass(frozen=True, repr=False)
class SearchSwitchContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class SearchActivationContext:
    engine: Engine
    target_keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class SearchAbortContext:
    engine: Engine
    source_keys: Keyring | Callable[[UUID], Keyring]
    source_pin: DeploymentPin
    approval: MaintenanceApproval


@dataclass(frozen=True, repr=False)
class InitializationContext:
    """Explicit declaration and optional SELECT samples; no keys or approvals."""
    engine: Engine
    mapping: registry
    declaration: bytes
    writers: WriterInventory
    search_reviews: tuple[SearchReview, ...]
    queries: tuple = ()


@dataclass(frozen=True, repr=False)
class RetainedBackupObligation:
    backup_id: UUID
    source_plan: bytes
    dump_sha256: str
    reader_sha256: str | None
    drill_sha256: str | None


@dataclass(frozen=True, repr=False)
class RetainedObligationsContext:
    operation_id: UUID
    plan_digest: str
    records: tuple[RetainedBackupObligation, ...]


@dataclass(frozen=True, repr=False)
class KeyPolicyStatusContext:
    operation_id: UUID
    plan_digest: str
    policies: tuple[KeyPolicy, ...]
