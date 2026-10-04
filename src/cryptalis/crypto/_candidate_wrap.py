"""Bounded W1 structural parsing for experiments, without authentication."""

from dataclasses import dataclass, field
from struct import Struct

from ._candidate_envelope import (
    EnvelopeInvalid as EnvelopeInvalid,
    EnvelopeMalformed,
    EnvelopeOversize,
    EnvelopeUnsupportedFormat,
    _NONCE_LENGTHS,
)


_HEADER = Struct(">4sBBBBHBB16sQ16sQ32sI")
_MAX_WRAP_BYTES = 168


@dataclass(frozen=True, slots=True)
class CandidateWrap:
    """Untrusted parsed bytes. This object grants no authority to release a secret."""

    header: bytes = field(repr=False)
    suite_id: int
    kind: int
    parent_branch_handle: bytes = field(repr=False)
    parent_generation: int
    child_handle: bytes = field(repr=False)
    child_generation: int
    wrapper_seed: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    tag: bytes = field(repr=False)


def parse_candidate_wrap(raw: bytes) -> CandidateWrap:
    """Parse candidate W1 structure without key lookup or decryption.

    Every returned byte remains unauthenticated. This is a private experiment.
    """
    if type(raw) is not bytes:
        raise EnvelopeMalformed("W1 input must be immutable bytes.")
    if len(raw) > _MAX_WRAP_BYTES:
        raise EnvelopeOversize("W1 record exceeds the size limit.")
    if len(raw) < _HEADER.size:
        raise EnvelopeMalformed("W1 header is incomplete.")

    (
        magic,
        format_version,
        suite_id,
        kind,
        flags,
        header_length,
        nonce_length,
        tag_length,
        parent_branch_handle,
        parent_generation,
        child_handle,
        child_generation,
        wrapper_seed,
        ciphertext_length,
    ) = _HEADER.unpack_from(raw)

    if magic != b"CRYW":
        raise EnvelopeMalformed("W1 magic is invalid.")
    if format_version != 1:
        raise EnvelopeUnsupportedFormat("W1 does not support this version.")
    if suite_id not in _NONCE_LENGTHS:
        raise EnvelopeUnsupportedFormat("W1 does not support this suite.")
    if flags != 0:
        raise EnvelopeUnsupportedFormat("W1 does not support these flags.")
    if kind not in (1, 2):
        raise EnvelopeUnsupportedFormat("W1 does not support this kind.")
    if header_length != _HEADER.size:
        raise EnvelopeMalformed("W1 header length is invalid.")
    if nonce_length != _NONCE_LENGTHS[suite_id]:
        raise EnvelopeMalformed("W1 nonce length is invalid.")
    if tag_length != 16:
        raise EnvelopeMalformed("W1 tag length is invalid.")
    if ciphertext_length != 32:
        raise EnvelopeMalformed("W1 ciphertext length is invalid.")
    if parent_generation == 0:
        raise EnvelopeMalformed("W1 parent generation is invalid.")
    if child_generation == 0:
        raise EnvelopeMalformed("W1 child generation is invalid.")

    nonce_end = header_length + nonce_length
    ciphertext_end = nonce_end + ciphertext_length
    if len(raw) != ciphertext_end + tag_length:
        raise EnvelopeMalformed("W1 total length is invalid.")

    return CandidateWrap(
        header=raw[:header_length],
        suite_id=suite_id,
        kind=kind,
        parent_branch_handle=parent_branch_handle,
        parent_generation=parent_generation,
        child_handle=child_handle,
        child_generation=child_generation,
        wrapper_seed=wrapper_seed,
        nonce=raw[header_length:nonce_end],
        ciphertext=raw[nonce_end:ciphertext_end],
        tag=raw[ciphertext_end:],
    )
