"""Bounded F1 structural parsing for experiments, without authentication."""

from dataclasses import dataclass, field
from struct import Struct


_HEADER = Struct(">4sBBHHBBI16sQ32s32sHH")
_NONCE_LENGTHS = {1: 12, 2: 12, 3: 24, 4: 12}
_CODEC_ENTRY_IDS = frozenset((1, 2, 3, 4))
_MAX_CIPHERTEXT_BYTES = 1_048_576
_MAX_ENVELOPE_BYTES = 1_048_724
_MIN_CIPHERTEXT_BYTES = 5


class EnvelopeInvalid(ValueError):
    """Candidate envelope input violates the structural contract."""


class EnvelopeMalformed(EnvelopeInvalid):
    """Candidate envelope structure is malformed."""


class EnvelopeUnsupportedFormat(EnvelopeInvalid):
    """Candidate envelope selectors or extensions are unsupported."""


class EnvelopeOversize(EnvelopeInvalid):
    """Candidate envelope input exceeds a resource limit."""


@dataclass(frozen=True, slots=True)
class CandidateEnvelope:
    """Untrusted parsed bytes. This object grants no decryption authority."""

    header: bytes = field(repr=False)
    suite_id: int
    subject_key_handle: bytes = field(repr=False)
    subject_generation: int
    creation_policy_digest: bytes = field(repr=False)
    value_seed: bytes = field(repr=False)
    codec_entry_id: int
    aad_binding_version: int
    nonce: bytes = field(repr=False)
    ciphertext: bytes = field(repr=False)
    tag: bytes = field(repr=False)


def parse_candidate_envelope(raw: bytes) -> CandidateEnvelope:
    """Parse candidate F1 structure without key lookup, decode, or decryption.

    Every returned byte remains unauthenticated. This is a private experiment.
    """
    if type(raw) is not bytes:
        raise EnvelopeMalformed("Candidate envelope input must be immutable bytes")
    if len(raw) > _MAX_ENVELOPE_BYTES:
        raise EnvelopeOversize("Candidate envelope exceeds the size limit")
    if len(raw) < _HEADER.size:
        raise EnvelopeMalformed("Candidate envelope header is truncated")

    (
        magic,
        format_version,
        suite_id,
        flags,
        header_length,
        nonce_length,
        tag_length,
        ciphertext_length,
        subject_key_handle,
        subject_generation,
        creation_policy_digest,
        value_seed,
        codec_entry_id,
        aad_binding_version,
    ) = _HEADER.unpack_from(raw)

    if magic != b"CRYP":
        raise EnvelopeMalformed("Candidate envelope magic is invalid")
    if format_version != 1 or suite_id not in _NONCE_LENGTHS or flags != 0:
        raise EnvelopeUnsupportedFormat("Candidate envelope format is unsupported")
    if codec_entry_id not in _CODEC_ENTRY_IDS or aad_binding_version != 1:
        raise EnvelopeUnsupportedFormat("Candidate envelope binding is unsupported")
    if header_length != _HEADER.size or tag_length != 16:
        raise EnvelopeMalformed("Candidate envelope fixed lengths are invalid")
    if nonce_length != _NONCE_LENGTHS[suite_id]:
        raise EnvelopeMalformed("Candidate envelope nonce length is invalid")
    if ciphertext_length > _MAX_CIPHERTEXT_BYTES:
        raise EnvelopeOversize("Candidate ciphertext exceeds the size limit")
    if ciphertext_length < _MIN_CIPHERTEXT_BYTES or subject_generation == 0:
        raise EnvelopeMalformed("Candidate envelope length or generation is invalid")

    nonce_end = header_length + nonce_length
    ciphertext_end = nonce_end + ciphertext_length
    if len(raw) != ciphertext_end + tag_length:
        raise EnvelopeMalformed("Candidate envelope total length is invalid")

    return CandidateEnvelope(
        header=raw[:header_length],
        suite_id=suite_id,
        subject_key_handle=subject_key_handle,
        subject_generation=subject_generation,
        creation_policy_digest=creation_policy_digest,
        value_seed=value_seed,
        codec_entry_id=codec_entry_id,
        aad_binding_version=aad_binding_version,
        nonce=raw[header_length:nonce_end],
        ciphertext=raw[nonce_end:ciphertext_end],
        tag=raw[ciphertext_end:],
    )
