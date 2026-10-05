"""Behavior checks for private transition-plan admission."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone, tzinfo
from uuid import UUID

import pytest


_PLAN_ID = UUID("018f4f87-6f95-7e2a-9d95-38f9b7646f30")
_OPERATION_ID = UUID("018f4f87-6f95-7e2a-9d95-38f9b7646f31")
_DOMAIN_ID = UUID("018f4f87-6f95-7e2a-9d95-38f9b7646f24")
_OTHER_DOMAIN_ID = UUID("018f4f87-6f95-7e2a-9d95-38f9b7646f32")
_CREATED_AT = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)
_EXPIRES_AT = _CREATED_AT + timedelta(hours=1)
_ACTIVE_DIGEST = "a" * 64
_DESIRED_DIGEST = "b" * 64
_TARGET_IDENTITY = b"synthetic-target-identity-v1"


class _ExplodingTimezone(tzinfo):
    def utcoffset(self, dt):
        raise RuntimeError("do-not-echo-timezone-error")

    def dst(self, dt):
        return None


def _api():
    from cryptalis.contracts import transition

    return transition


def _plan(**changes: object):
    api = _api()
    values = {
        "schema_version": 1,
        "plan_id": _PLAN_ID,
        "operation_id": _OPERATION_ID,
        "kind": "PROTECT",
        "strategy": "offline",
        "created_at": _CREATED_AT,
        "expires_at": _EXPIRES_AT,
        "protection_domain_id": _DOMAIN_ID,
        "source_authority_revision": 4,
        "source_active_digest": _ACTIVE_DIGEST,
        "desired_manifest_digest": _DESIRED_DIGEST,
        "target_identity": _TARGET_IDENTITY,
    }
    values.update(changes)
    return api.TransitionPlanHeader(**values)


def _observation(**changes: object):
    api = _api()
    values = {
        "observed_at": _CREATED_AT + timedelta(minutes=15),
        "protection_domain_id": _DOMAIN_ID,
        "authority_revision": 4,
        "active_digest": _ACTIVE_DIGEST,
        "target_identity": _TARGET_IDENTITY,
    }
    values.update(changes)
    return api.TransitionObservation(**values)


def test_admits_an_exact_unexpired_offline_plan_without_mutation():
    api = _api()
    plan = _plan()
    observation = _observation()

    admitted = api.admit_transition_plan(plan, observation)

    assert admitted is plan
    assert "target_identity=" not in repr(plan)
    assert "target_identity=" not in repr(observation)
    with pytest.raises(FrozenInstanceError):
        plan.strategy = "online"


@pytest.mark.parametrize(
    "kind",
    [
        "PROTECT",
        "RECONFIGURE_PAYLOAD",
        "REINDEX",
        "DEPROTECT",
        "KEY_REWRAP",
        "KEY_REENCRYPT",
        "UPGRADE_FORMAT",
        "RESTORE_ADMISSION",
        "DECOMMISSION",
    ],
)
def test_admits_each_declared_transition_kind(kind):
    api = _api()

    assert api.admit_transition_plan(_plan(kind=kind), _observation()).kind == kind


@pytest.mark.parametrize(
    "observed_at",
    [_EXPIRES_AT, _EXPIRES_AT + timedelta(microseconds=1)],
)
def test_rejects_a_plan_at_or_after_its_expiry(observed_at):
    api = _api()

    with pytest.raises(api.TransitionPlanExpired, match="^Transition plan expired$"):
        api.admit_transition_plan(
            _plan(),
            _observation(observed_at=observed_at),
        )


def test_rejects_an_observation_that_predates_plan_creation():
    api = _api()

    with pytest.raises(
        api.TransitionPlanStale,
        match="^Transition observation predates plan creation$",
    ):
        api.admit_transition_plan(
            _plan(),
            _observation(observed_at=_CREATED_AT - timedelta(microseconds=1)),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"protection_domain_id": _OTHER_DOMAIN_ID},
        {"target_identity": b"replacement-at-the-same-endpoint"},
    ],
)
def test_rejects_the_wrong_domain_or_target_without_echoing_identity(changes):
    api = _api()
    marker = next(iter(changes.values()))

    with pytest.raises(api.TransitionPlanWrongTarget) as failure:
        api.admit_transition_plan(_plan(), _observation(**changes))

    assert str(marker) not in str(failure.value)
    assert str(failure.value) == "Transition plan target does not match"


@pytest.mark.parametrize(
    "changes",
    [
        {"authority_revision": 5},
        {"active_digest": "c" * 64},
    ],
)
def test_rejects_a_stale_active_head_without_echoing_values(changes):
    api = _api()
    marker = next(iter(changes.values()))

    with pytest.raises(api.TransitionPlanStale) as failure:
        api.admit_transition_plan(_plan(), _observation(**changes))

    assert str(marker) not in str(failure.value)
    assert str(failure.value) == "Transition plan source is no longer current"


def test_rejects_an_unsupported_strategy_before_other_preconditions():
    api = _api()
    observation = _observation(
        protection_domain_id=_OTHER_DOMAIN_ID,
        authority_revision=5,
    )

    with pytest.raises(
        api.TransitionPlanUnsupportedStrategy,
        match="^Transition plan strategy is unsupported$",
    ):
        api.admit_transition_plan(_plan(strategy="online"), observation)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"plan_id": str(_PLAN_ID)},
        {"operation_id": str(_OPERATION_ID)},
        {"kind": "UNKNOWN"},
        {"created_at": _CREATED_AT.replace(tzinfo=None)},
        {
            "created_at": _CREATED_AT.replace(
                tzinfo=_ExplodingTimezone()
            )
        },
        {"expires_at": _CREATED_AT},
        {"protection_domain_id": str(_DOMAIN_ID)},
        {"source_authority_revision": True},
        {"source_authority_revision": -1},
        {"source_authority_revision": 2**53},
        {"source_active_digest": "A" * 64},
        {"desired_manifest_digest": "b" * 63},
        {"target_identity": bytearray(_TARGET_IDENTITY)},
        {"target_identity": b""},
        {"target_identity": b"x" * 4097},
    ],
)
def test_rejects_malformed_plan_fields(changes):
    api = _api()

    with pytest.raises(api.TransitionPlanInvalid):
        api.admit_transition_plan(_plan(**changes), _observation())


@pytest.mark.parametrize(
    "changes",
    [
        {"observed_at": _CREATED_AT.replace(tzinfo=None)},
        {"protection_domain_id": str(_DOMAIN_ID)},
        {"authority_revision": True},
        {"authority_revision": -1},
        {"authority_revision": 2**53},
        {"active_digest": "A" * 64},
        {"target_identity": bytearray(_TARGET_IDENTITY)},
        {"target_identity": b""},
        {"target_identity": b"x" * 4097},
    ],
)
def test_rejects_malformed_observations(changes):
    api = _api()

    with pytest.raises(api.TransitionPlanInvalid):
        api.admit_transition_plan(_plan(), _observation(**changes))
