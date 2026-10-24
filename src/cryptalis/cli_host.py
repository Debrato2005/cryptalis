"""Explicit trusted host inputs for operational CLI commands.

Factories supply a fresh, owned synchronous PostgreSQL psycopg Engine with
transactional connections. The command disposes it on every outcome. This
ownership assertion is a host responsibility, not proof of deployment fencing.
Doctor uses its separate key-free context contract.
"""
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.orm import registry

from cryptalis.crypto.keys import Keyring
from cryptalis.manifest.compiler import SearchReview, WriterInventory
from cryptalis.migration import DeploymentPin, MaintenanceApproval


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


@dataclass(frozen=True, repr=False)
class ApplyContext:
    engine: Engine
    keys: Keyring | Callable[[UUID], Keyring]
    pin: DeploymentPin
    approval: MaintenanceApproval
