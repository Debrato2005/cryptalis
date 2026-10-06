"""Local canonical-byte and operation-identity fixtures; no production imports."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from psycopg import adapters
from psycopg.pq import Format
from run_crypto import E, enc_label, enc_uuid, enc_u64, enc_bytes


def validate(value, depth=0):
    if depth > 32:
        raise ValueError("DepthLimit")
    if value is None or type(value) is bool:
        return
    if type(value) is int and 0 <= value <= 2**53 - 1:
        return
    if type(value) is str:
        value.encode("utf-8", errors="strict")
        return
    if type(value) is list:
        for item in value:
            validate(item, depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key.isascii():
                raise ValueError("MemberName")
            validate(item, depth + 1)
        return
    raise ValueError("ValueTypeOrRange")


def library_encoder(value):
    validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def explicit_encoder(value):
    validate(value)
    # Separate recursive serialization, including explicit string escaping.
    def quote(s):
        escapes = {8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r",
                   34: '\\"', 92: "\\\\"}
        parts = ['"']
        for c in s:
            n = ord(c)
            parts.append(escapes.get(n, f"\\u{n:04x}" if n < 32 else c))
        return "".join(parts) + '"'
    def encode(x):
        if x is None:
            return "null"
        if type(x) is bool:
            return "true" if x else "false"
        if type(x) is int:
            return str(x)
        if type(x) is str:
            return quote(x)
        if type(x) is list:
            return "[" + ",".join(encode(i) for i in x) + "]"
        return "{" + ",".join(quote(k) + ":" + encode(x[k]) for k in sorted(x)) + "}"
    return encode(value).encode("utf-8")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DuplicateMember")
        result[key] = value
    return result


def ordinary_changes(changes):
    ids = [uuid.UUID(c["attribute_id"]).bytes for c in changes]
    if len(ids) != len(set(ids)):
        raise ValueError("DuplicateAttribute")
    return sorted(changes, key=lambda c: uuid.UUID(c["attribute_id"]).bytes)


def run():
    edge = {"z": [None, True, False, 0, 2**53 - 1],
            "a": "é/\u2028\u2029\"\\\b\t\n\f\r\x00\x1f", "m": "e\u0301"}
    vectors = []
    for value in [edge, dict(reversed(list(edge.items()))), {"empty": []},
                  {"array": [2, 1]}, {"value": "é"}, {"value": "e\u0301"}]:
        a, b = library_encoder(value), explicit_encoder(value)
        assert a == b
        vectors.append({"input": value, "canonical_hex": a.hex(),
                        "sha256": hashlib.sha256(a).hexdigest()})
    assert vectors[0]["canonical_hex"] == vectors[1]["canonical_hex"]
    assert vectors[-1]["canonical_hex"] != vectors[-2]["canonical_hex"]
    assert b'[2,1]' in library_encoder({"array": [2, 1]})
    rejected = []
    for name, value in [("float", 1.0), ("negative", -1), ("oversize_integer", 2**53),
                        ("surrogate", "\ud800"), ("non_ASCII_member", {"é": 1})]:
        try:
            library_encoder(value)
        except (ValueError, UnicodeError):
            rejected.append(name)
        else:
            raise AssertionError(name)
    try:
        json.loads('{"a":1,"a":2}', object_pairs_hook=no_duplicates)
    except ValueError:
        rejected.append("duplicate_member")
    else:
        raise AssertionError("DuplicateMember")

    uid = lambda n: str(uuid.UUID(int=n))
    # Actual installed public driver adaptation for one original PostgreSQL type.
    dumper = adapters.get_dumper_by_oid(25, Format.TEXT)(str)
    wire = bytes(dumper.dump("same-value"))
    assert wire == b"same-value"
    entry = {"attribute_id": uid(101), "sql_type_id": uid(201), "wire_oid": 25,
             "wire_format": 0, "value": base64.b64encode(wire).decode("ascii")}
    mutation = {"model_id": uid(4), "record": {"kind": "u64", "value": "1"},
                "tenant_id": uid(2), "subject_id": uid(3), "action": "update",
                "expected_revision": "1", "ordinary_changes": ordinary_changes([entry]),
                "fields": [{"field_id": uid(6), "descriptor_digest": "11" * 32,
                            "codec_id": 1, "value": None}]}
    request = {"version": 1, "domain_id": uid(1), "target_incarnation": uid(10),
               "transaction_id": uid(11), "compiled_lock_digest": "22" * 32,
               "fence_token": 1, "anchor_handle": uid(8), "anchor_generation": 1,
               "operation_id": uid(12), "mutations": [mutation]}
    salt = hashlib.sha256(E([enc_label("cryptalis/payload-extract/2"),
                            enc_uuid(uuid.UUID(int=1)), enc_uuid(uuid.UUID(int=2)),
                            enc_uuid(uuid.UUID(int=3)), enc_u64(1)])).digest()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=E([enc_label("cryptalis/mutation-commitment/1"),
                       enc_uuid(uuid.UUID(int=12))])).derive(bytes(range(32)))
    digest = lambda value: hmac.digest(key, E([enc_label("cryptalis/mutation-request/1"),
                                             enc_bytes(library_encoder(value))]), "sha256")
    canonical = library_encoder(request)
    assert canonical == explicit_encoder(request)
    first_digest = digest(request)
    assert first_digest == digest(dict(reversed(list(request.items()))))
    second = json.loads(json.dumps(request))
    second["mutations"][0]["ordinary_changes"][0]["attribute_id"] = uid(102)
    second_digest = digest(second)
    assert first_digest != second_digest
    registered = {uid(12): first_digest}
    assert not hmac.compare_digest(registered[uid(12)], second_digest)
    try:
        ordinary_changes([entry, dict(entry)])
    except ValueError:
        rejected.append("duplicate_ordinary_attribute")
    else:
        raise AssertionError("DuplicateAttribute")
    return {"canonical_vectors": vectors, "rejected": rejected,
            "request_canonical_hex": canonical.hex(),
            "same_type_same_value_different_attribute_digests": [first_digest.hex(), second_digest.hex()],
            "same_operation_changed_identity": "CONFLICT",
            "driver_TEXT_oid_25": wire.hex()}


if __name__ == "__main__":
    result = {"spike": "canonical/request supplement", "status": "PASS_LOCAL_FIXTURE",
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "evidence": run(), "limits": ["first-party encoders, not independent human vectors",
              "not a full manifest/lock/request schema compiler", "one original driver type only",
              "does not prove immutable wire parameter emission or full changed/default inventory"]}
    (Path(__file__).parent / "results" / "canonical.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
