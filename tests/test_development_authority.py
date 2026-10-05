"""Observable behavior for the process-local development authority."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier

import pytest


_EXAMPLES = Path(__file__).parent.parent / "examples" / "active-state"
_OPERATION_IDS = (
    "018f4f87-6f95-7e2a-9d95-38f9b7646f27",
    "018f4f87-6f95-7e2a-9d95-38f9b7646f28",
)


def _api():
    from cryptalis.contracts import development_authority

    return development_authority


def _examples() -> tuple[bytes, bytes]:
    return (
        (_EXAMPLES / "genesis.json").read_bytes(),
        (_EXAMPLES / "successor.json").read_bytes(),
    )


def _competing_successor(genesis: bytes, operation_id: str) -> bytes:
    from cryptalis.contracts.active_state import digest_active_state_json

    document = json.loads(genesis)
    document.update(
        authority_revision=1,
        parent_digest=digest_active_state_json(genesis),
        current_operation_id=operation_id,
    )
    return json.dumps(document, separators=(",", ":")).encode()


def test_authority_loads_only_a_valid_history_and_returns_immutable_snapshots():
    api = _api()
    genesis, successor = _examples()

    authority = api.InMemoryDevelopmentAuthority((genesis, successor))
    snapshot = authority.read()

    assert snapshot.raw == successor
    assert snapshot.digest == api.digest_active_state_json(successor)
    assert authority.history() == (genesis, successor)
    assert "raw=" not in repr(snapshot)
    with pytest.raises(FrozenInstanceError):
        snapshot.digest = "0" * 64
    with pytest.raises(api.ActiveStateInvalid):
        api.InMemoryDevelopmentAuthority((successor,))


def test_compare_and_swap_applies_one_valid_successor():
    api = _api()
    genesis, successor = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    expected = authority.read().digest

    applied = authority.compare_and_swap(expected, successor)

    assert applied == authority.read()
    assert applied.raw == successor
    assert authority.history() == (genesis, successor)


def test_exact_retry_after_a_lost_response_is_idempotent_in_process():
    api = _api()
    genesis, successor = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    expected = authority.read().digest
    first = authority.compare_and_swap(expected, successor)

    retried = authority.compare_and_swap(expected, successor)

    assert retried == first
    assert authority.history() == (genesis, successor)


def test_stale_expected_head_fails_before_the_proposal_is_parsed():
    api = _api()
    genesis, _ = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    secret_marker = b'"do-not-echo-this"'

    with pytest.raises(api.DevelopmentAuthorityStale) as failure:
        authority.compare_and_swap("f" * 64, secret_marker)

    assert secret_marker.decode() not in str(failure.value)
    assert authority.history() == (genesis,)


def test_invalid_successor_fails_without_changing_the_head():
    api = _api()
    genesis, _ = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    before = authority.read()

    with pytest.raises(api.ActiveStateInvalid):
        authority.compare_and_swap(before.digest, b"not-json")

    assert authority.read() == before
    assert authority.history() == (genesis,)


def test_old_head_does_not_authorize_a_different_successor():
    api = _api()
    genesis, successor = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    expected = authority.read().digest
    authority.compare_and_swap(expected, successor)
    competitor = _competing_successor(genesis, _OPERATION_IDS[0])

    with pytest.raises(api.DevelopmentAuthorityStale):
        authority.compare_and_swap(expected, competitor)

    assert authority.history() == (genesis, successor)


def test_only_one_competing_writer_wins():
    api = _api()
    genesis, _ = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))
    expected = authority.read().digest
    candidates = tuple(
        _competing_successor(genesis, operation_id)
        for operation_id in _OPERATION_IDS
    )
    ready = Barrier(2)

    def apply(candidate: bytes) -> str:
        ready.wait()
        try:
            authority.compare_and_swap(expected, candidate)
        except api.DevelopmentAuthorityStale:
            return "stale"
        return "applied"

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = tuple(workers.map(apply, candidates))

    assert sorted(outcomes) == ["applied", "stale"]
    assert len(authority.history()) == 2
    assert authority.read().raw in candidates


@pytest.mark.parametrize("expected", [None, b"0" * 64, "A" * 64, "0" * 63])
def test_compare_and_swap_requires_a_canonical_expected_digest(expected):
    api = _api()
    genesis, successor = _examples()
    authority = api.InMemoryDevelopmentAuthority((genesis,))

    with pytest.raises(api.DevelopmentAuthorityInvalid):
        authority.compare_and_swap(expected, successor)

    assert authority.history() == (genesis,)
