"""Private transition-plan admission without execution or authority."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hmac import compare_digest
from uuid import UUID


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_MAX_TARGET_IDENTITY_BYTES = 4096
_TRANSITION_KINDS = frozenset(
    {
        "PROTECT",
        "RECONFIGURE_PAYLOAD",
        "REINDEX",
        "DEPROTECT",
        "KEY_REWRAP",
        "KEY_REENCRYPT",
        "UPGRADE_FORMAT",
        "RESTORE_ADMISSION",
        "DECOMMISSION",
    }
)


class TransitionPlanInvalid(ValueError):
    """A transition plan or observation violates the local contract."""


class TransitionPlanRejected(RuntimeError):
    """A valid transition plan does not match the current observation."""


class TransitionPlanExpired(TransitionPlanRejected):
    """The transition plan reached its exclusive expiry boundary."""


class TransitionPlanWrongTarget(TransitionPlanRejected):
    """The observed domain or target does not match the plan."""


class TransitionPlanStale(TransitionPlanRejected):
    """The observed ActiveState head does not match the plan source."""


class TransitionPlanUnsupportedStrategy(TransitionPlanRejected):
    """The plan requests a strategy outside the initial offline profile."""


@dataclass(frozen=True, slots=True)
class TransitionPlanHeader:
    """Immutable in-memory fields needed for transition admission."""

    schema_version: int
    plan_id: UUID
    operation_id: UUID
    kind: str
    strategy: str
    created_at: datetime
    expires_at: datetime
    protection_domain_id: UUID
    source_authority_revision: int
    source_active_digest: str
    desired_manifest_digest: str
    target_identity: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class TransitionObservation:
    """Immutable trusted facts observed before a transition boundary."""

    observed_at: datetime
    protection_domain_id: UUID
    authority_revision: int
    active_digest: str
    target_identity: bytes = field(repr=False)


def _invalid(reason: str) -> None:
    raise TransitionPlanInvalid(reason)


def _uuid(value: object, label: str) -> None:
    if type(value) is not UUID:
        _invalid(f"{label} must be a UUID")


def _counter(value: object, label: str) -> None:
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        _invalid(f"{label} must be a nonnegative integer")


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        _invalid(f"{label} must be 64 lowercase hexadecimal characters")


def _timestamp(value: object, label: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is not timezone.utc
    ):
        _invalid(f"{label} must be an aware UTC datetime")


def _target_identity(value: object, label: str) -> None:
    if (
        type(value) is not bytes
        or not value
        or len(value) > _MAX_TARGET_IDENTITY_BYTES
    ):
        _invalid(f"{label} must be immutable bytes in the supported size range")


def _validate_plan(plan: object) -> TransitionPlanHeader:
    if type(plan) is not TransitionPlanHeader:
        _invalid("Transition plan must use the immutable header type")

    if type(plan.schema_version) is not int or plan.schema_version != 1:
        _invalid("Transition plan schema version must be the integer 1")
    _uuid(plan.plan_id, "Transition plan ID")
    _uuid(plan.operation_id, "Transition operation ID")
    if not isinstance(plan.kind, str) or plan.kind not in _TRANSITION_KINDS:
        _invalid("Transition plan kind is invalid")
    if not isinstance(plan.strategy, str):
        _invalid("Transition plan strategy must be text")
    if plan.strategy != "offline":
        raise TransitionPlanUnsupportedStrategy(
            "Transition plan strategy is unsupported"
        )
    _timestamp(plan.created_at, "Transition plan creation time")
    _timestamp(plan.expires_at, "Transition plan expiry time")
    if plan.created_at >= plan.expires_at:
        _invalid("Transition plan expiry must be after creation")
    _uuid(plan.protection_domain_id, "Transition protection domain ID")
    _counter(plan.source_authority_revision, "Transition source authority revision")
    _digest(plan.source_active_digest, "Transition source ActiveState digest")
    _digest(plan.desired_manifest_digest, "Transition desired manifest digest")
    _target_identity(plan.target_identity, "Transition target identity")
    return plan


def _validate_observation(observation: object) -> TransitionObservation:
    if type(observation) is not TransitionObservation:
        _invalid("Transition observation must use the immutable observation type")

    _timestamp(observation.observed_at, "Transition observation time")
    _uuid(
        observation.protection_domain_id,
        "Observed protection domain ID",
    )
    _counter(observation.authority_revision, "Observed authority revision")
    _digest(observation.active_digest, "Observed ActiveState digest")
    _target_identity(observation.target_identity, "Observed target identity")
    return observation


def admit_transition_plan(
    plan: object,
    observation: object,
) -> TransitionPlanHeader:
    """Check private transition preconditions without mutation or authority."""
    checked_plan = _validate_plan(plan)
    checked_observation = _validate_observation(observation)

    if checked_observation.observed_at >= checked_plan.expires_at:
        raise TransitionPlanExpired("Transition plan expired")
    if checked_observation.observed_at < checked_plan.created_at:
        raise TransitionPlanStale(
            "Transition observation predates plan creation"
        )
    if (
        checked_observation.protection_domain_id
        != checked_plan.protection_domain_id
        or not compare_digest(
            checked_observation.target_identity,
            checked_plan.target_identity,
        )
    ):
        raise TransitionPlanWrongTarget(
            "Transition plan target does not match"
        )
    if (
        checked_observation.authority_revision
        != checked_plan.source_authority_revision
        or not compare_digest(
            checked_observation.active_digest,
            checked_plan.source_active_digest,
        )
    ):
        raise TransitionPlanStale(
            "Transition plan source is no longer current"
        )
    return checked_plan
