"""Process-local ActiveState authority for development and demonstrations."""

import re
from dataclasses import dataclass, field
from hmac import compare_digest
from threading import Lock

from cryptalis.contracts.active_state import (
    ActiveStateHeader,
    ActiveStateInvalid,
    digest_active_state_json,
    validate_active_state_history,
    validate_active_state_parent_link,
)


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class DevelopmentAuthorityInvalid(ValueError):
    """A development-authority request violates the local API contract."""


class DevelopmentAuthorityStale(RuntimeError):
    """The expected ActiveState head is no longer current."""


@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """One immutable view of the current structural ActiveState head."""

    header: ActiveStateHeader
    digest: str
    raw: bytes = field(repr=False)


def _expected_digest(value: object) -> str:
    if not isinstance(value, str) or _SHA256_HEX.fullmatch(value) is None:
        raise DevelopmentAuthorityInvalid(
            "Expected head digest must be 64 lowercase hexadecimal characters"
        )
    return value


def _snapshot(raw: bytes, header: ActiveStateHeader) -> AuthoritySnapshot:
    return AuthoritySnapshot(
        header=header,
        digest=digest_active_state_json(raw),
        raw=raw,
    )


class InMemoryDevelopmentAuthority:
    """Serialize structural ActiveState changes within one Python process."""

    def __init__(self, history: tuple[bytes, ...]) -> None:
        head = validate_active_state_history(history)
        self._history = history
        self._current = _snapshot(history[-1], head)
        self._lock = Lock()

    def read(self) -> AuthoritySnapshot:
        """Return the immutable current snapshot."""
        with self._lock:
            return self._current

    def history(self) -> tuple[bytes, ...]:
        """Return the immutable genesis-to-head structural history."""
        with self._lock:
            return self._history

    def compare_and_swap(
        self,
        expected_digest: object,
        successor_raw: bytes,
    ) -> AuthoritySnapshot:
        """Apply one valid successor when the expected head is current."""
        expected = _expected_digest(expected_digest)
        with self._lock:
            current = self._current
            if compare_digest(expected, current.digest):
                header = validate_active_state_parent_link(
                    successor_raw,
                    current.raw,
                )
                candidate_history = self._history + (successor_raw,)
                validate_active_state_history(candidate_history)
                applied = _snapshot(successor_raw, header)
                self._history = candidate_history
                self._current = applied
                return applied

            if (
                current.header.parent_digest is not None
                and compare_digest(expected, current.header.parent_digest)
                and compare_digest(
                    digest_active_state_json(successor_raw),
                    current.digest,
                )
            ):
                return current

            raise DevelopmentAuthorityStale(
                "Expected ActiveState head is no longer current"
            )
