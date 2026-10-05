"""Structural ActiveState history tests without authority authentication."""

import json
from dataclasses import FrozenInstanceError
from pathlib import Path
from uuid import UUID

import pytest


_DOMAIN_ID = "018f4f87-6f95-7e2a-9d95-38f9b7646f24"
_MANIFEST_ID = "018f4f87-6f95-7e2a-9d95-38f9b7646f25"
_OPERATION_ID = "018f4f87-6f95-7e2a-9d95-38f9b7646f26"
_ACTIVE_MANIFEST_DIGEST = "a" * 64
_EXAMPLES = Path(__file__).parent.parent / "examples" / "active-state"


def _api():
    from cryptalis.contracts import active_state

    return active_state


def _state_json(**changes: object) -> bytes:
    document = {
        "schema_version": 1,
        "protection_domain_id": _DOMAIN_ID,
        "authority_revision": 0,
        "parent_digest": None,
        "active_manifest_id": _MANIFEST_ID,
        "active_manifest_revision": 0,
        "active_manifest_digest": _ACTIVE_MANIFEST_DIGEST,
        "schema_generation": 0,
        "current_operation_id": None,
        **changes,
    }
    return json.dumps(document, separators=(",", ":")).encode()


def _history(length: int) -> tuple[bytes, ...]:
    api = _api()
    documents = [_state_json()]
    for revision in range(1, length):
        active_revision = revision // 2
        documents.append(
            _state_json(
                authority_revision=revision,
                parent_digest=api.digest_active_state_json(documents[-1]),
                active_manifest_revision=active_revision,
                active_manifest_digest=(
                    _ACTIVE_MANIFEST_DIGEST
                    if active_revision == 0
                    else f"{active_revision:064x}"
                ),
                schema_generation=revision // 3,
            )
        )
    return tuple(documents)


def test_decodes_an_immutable_active_state_header():
    api = _api()
    raw = _state_json(current_operation_id=_OPERATION_ID, extension={"future": 1})

    header = api.decode_active_state_header(raw)

    assert header == api.ActiveStateHeader(
        schema_version=1,
        protection_domain_id=UUID(_DOMAIN_ID),
        authority_revision=0,
        parent_digest=None,
        active_manifest_id=UUID(_MANIFEST_ID),
        active_manifest_revision=0,
        active_manifest_digest=_ACTIVE_MANIFEST_DIGEST,
        schema_generation=0,
        current_operation_id=UUID(_OPERATION_ID),
    )
    with pytest.raises(FrozenInstanceError):
        header.schema_generation = 1


def test_validates_the_fixed_active_state_example_history():
    api = _api()
    genesis = (_EXAMPLES / "genesis.json").read_bytes()
    successor = (_EXAMPLES / "successor.json").read_bytes()

    assert api.digest_active_state_json(genesis) == (
        "24ec34f029d1939dd354bf5df28a2ac1"
        "e5f0a39cebae0ce161798bff9ab3512d"
    )
    assert api.validate_active_state_history((genesis, successor)) == (
        api.decode_active_state_header(successor)
    )


@pytest.mark.parametrize(
    "member",
    [
        "schema_version",
        "protection_domain_id",
        "authority_revision",
        "parent_digest",
        "active_manifest_id",
        "active_manifest_revision",
        "active_manifest_digest",
        "schema_generation",
        "current_operation_id",
    ],
)
def test_active_state_header_rejects_each_missing_member(member):
    document = json.loads(_state_json())
    del document[member]

    with pytest.raises(_api().ActiveStateInvalid):
        _api().decode_active_state_header(json.dumps(document).encode())


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"schema_version": True}, id="boolean-schema-version"),
        pytest.param({"schema_version": 2}, id="unknown-schema-version"),
        pytest.param({"protection_domain_id": _DOMAIN_ID.upper()}, id="domain-case"),
        pytest.param({"protection_domain_id": "not-a-uuid"}, id="domain-syntax"),
        pytest.param({"authority_revision": True}, id="boolean-authority-revision"),
        pytest.param({"authority_revision": -1}, id="negative-authority-revision"),
        pytest.param({"parent_digest": "A" * 64}, id="parent-digest-case"),
        pytest.param({"parent_digest": "b" * 63}, id="parent-digest-length"),
        pytest.param({"active_manifest_id": _MANIFEST_ID.upper()}, id="manifest-case"),
        pytest.param({"active_manifest_revision": True}, id="boolean-manifest-revision"),
        pytest.param({"active_manifest_revision": -1}, id="negative-manifest-revision"),
        pytest.param({"active_manifest_digest": "a" * 63}, id="manifest-digest-length"),
        pytest.param({"schema_generation": True}, id="boolean-schema-generation"),
        pytest.param({"schema_generation": -1}, id="negative-schema-generation"),
        pytest.param({"current_operation_id": _OPERATION_ID.upper()}, id="operation-case"),
        pytest.param({"current_operation_id": 1}, id="operation-type"),
    ],
)
def test_active_state_header_rejects_noncanonical_security_fields(changes):
    with pytest.raises(_api().ActiveStateInvalid):
        _api().decode_active_state_header(_state_json(**changes))


@pytest.mark.parametrize(
    ("authority_revision", "parent_digest"),
    [(0, "b" * 64), (1, None)],
)
def test_active_state_header_rejects_invalid_local_parent_state(
    authority_revision, parent_digest
):
    with pytest.raises(_api().ActiveStateInvalid):
        _api().decode_active_state_header(
            _state_json(
                authority_revision=authority_revision,
                parent_digest=parent_digest,
            )
        )


@pytest.mark.parametrize("raw", [None, "{}", bytearray(b"{}"), memoryview(b"{}")])
def test_active_state_header_requires_immutable_bytes(raw):
    with pytest.raises(_api().ActiveStateInvalid):
        _api().decode_active_state_header(raw)


def test_active_state_digest_is_domain_separated_and_covers_extensions():
    api = _api()
    baseline = _state_json(extension={"read_formats": [1, 2]})
    changed = _state_json(extension={"read_formats": [1, 3]})

    assert api.digest_active_state_json(baseline) == (
        "677275631feebbcfc2dea321d1f5a335"
        "8ade8b65f2b3977da0743c8971628672"
    )
    assert api.digest_active_state_json(changed) != api.digest_active_state_json(baseline)


def test_active_state_parent_link_accepts_monotonic_authority_and_state():
    api = _api()
    parent = _state_json(
        active_manifest_revision=3,
        schema_generation=2,
        current_operation_id=_OPERATION_ID,
    )
    child = _state_json(
        authority_revision=2,
        parent_digest=api.digest_active_state_json(parent),
        active_manifest_revision=5,
        active_manifest_digest="b" * 64,
        schema_generation=4,
    )

    assert api.validate_active_state_parent_link(child, parent) == (
        api.decode_active_state_header(child)
    )


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param(
            {"protection_domain_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f27"},
            id="different-domain",
        ),
        pytest.param(
            {"active_manifest_id": "018f4f87-6f95-7e2a-9d95-38f9b7646f28"},
            id="different-manifest",
        ),
        pytest.param({"authority_revision": 0, "parent_digest": None}, id="authority-rollback"),
        pytest.param({"active_manifest_revision": 2}, id="manifest-rollback"),
        pytest.param({"schema_generation": 1}, id="schema-rollback"),
    ],
)
def test_active_state_parent_link_rejects_cross_domain_or_rollback(changes):
    api = _api()
    parent = _state_json(
        authority_revision=3,
        parent_digest="b" * 64,
        active_manifest_revision=3,
        schema_generation=2,
    )
    child_values = {
        "authority_revision": 4,
        "parent_digest": api.digest_active_state_json(parent),
        "active_manifest_revision": 4,
        "active_manifest_digest": "b" * 64,
        "schema_generation": 3,
        **changes,
    }

    with pytest.raises(api.ActiveStateInvalid):
        api.validate_active_state_parent_link(_state_json(**child_values), parent)


def test_active_state_parent_link_rejects_content_substitution():
    api = _api()
    parent = _state_json(extension={"writer": "one"})
    child = _state_json(
        authority_revision=1,
        parent_digest=api.digest_active_state_json(parent),
    )
    substituted_parent = _state_json(extension={"writer": "two"})

    with pytest.raises(api.ActiveStateInvalid):
        api.validate_active_state_parent_link(child, substituted_parent)


@pytest.mark.parametrize(
    ("active_manifest_revision", "active_manifest_digest"),
    [
        pytest.param(3, "b" * 64, id="same-revision-different-digest"),
        pytest.param(4, "a" * 64, id="different-revision-same-digest"),
    ],
)
def test_active_state_parent_link_rejects_inconsistent_manifest_identity(
    active_manifest_revision, active_manifest_digest
):
    api = _api()
    parent = _state_json(active_manifest_revision=3)
    child = _state_json(
        authority_revision=1,
        parent_digest=api.digest_active_state_json(parent),
        active_manifest_revision=active_manifest_revision,
        active_manifest_digest=active_manifest_digest,
    )

    with pytest.raises(api.ActiveStateInvalid):
        api.validate_active_state_parent_link(child, parent)


def test_active_state_history_validates_genesis_to_head():
    api = _api()
    history = _history(7)

    assert api.validate_active_state_history(history) == api.decode_active_state_header(
        history[-1]
    )


@pytest.mark.parametrize("history", [(), [], iter(())])
def test_active_state_history_requires_a_nonempty_immutable_sequence(history):
    with pytest.raises(_api().ActiveStateInvalid):
        _api().validate_active_state_history(history)


def test_active_state_history_rejects_missing_genesis_or_middle_state():
    api = _api()
    genesis, first, second = _history(3)

    for history in ((first, second), (genesis, second)):
        with pytest.raises(api.ActiveStateInvalid):
            api.validate_active_state_history(history)


def test_active_state_history_checks_limits_before_parsing():
    api = _api()
    marker = b"do-not-echo-active-state"

    for history in (
        (marker,) * 4097,
        (marker + b" " * (16 * 1024 * 1024),),
    ):
        with pytest.raises(api.ActiveStateInvalid) as error:
            api.validate_active_state_history(history)
        assert marker.decode() not in str(error.value)


def test_active_state_history_accepts_exactly_4096_linked_documents():
    history = _history(4096)

    assert _api().validate_active_state_history(history).authority_revision == 4095


def test_active_state_errors_do_not_echo_invalid_input():
    api = _api()
    marker = b"do-not-echo-active-state"

    with pytest.raises(api.ActiveStateInvalid) as error:
        api.decode_active_state_header(marker)

    assert marker.decode() not in str(error.value)
