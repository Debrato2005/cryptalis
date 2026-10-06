"""S4: exact local construction smoke; synthetic material only."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import uuid
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def E(parts):
    return struct.pack(">H", len(parts)) + b"".join(
        struct.pack(">BI", tag, len(value)) + value for tag, value in parts)


def enc_label(s):return (1, s.encode("ascii"))
def enc_uuid(x):return (2, x.bytes)
def enc_u64(x):return (4, struct.pack(">Q", x))
def enc_bytes(x):return (5, x)
def enc_digest(x):return (3, x)


class ForkDenied(Exception):pass


class LocalMaterial:
    def __init__(self, key):self.key = key; self.pid = os.getpid()
    def encrypt(self, value, aad):
        if os.getpid() != self.pid:raise ForkDenied("Inherited material requires fresh admission")
        nonce = os.urandom(12)
        return nonce, AESGCMSIV(self.key).encrypt(nonce, value, aad)


def smoke():
    ids = [uuid.UUID(int=i) for i in range(1, 9)]
    domain, tenant, subject, model, table, field, representation, handle = ids
    descriptor = hashlib.sha256(b"synthetic descriptor fixture").digest()
    root = bytes(range(32)); gen = 1
    salt = hashlib.sha256(E([enc_label("cryptalis/payload-extract/2"),enc_uuid(domain),
        enc_uuid(tenant),enc_uuid(subject),enc_u64(gen)])).digest()
    info = E([enc_label("cryptalis/payload-key/2"),enc_uuid(model),enc_uuid(table),
              enc_uuid(field),enc_uuid(representation),enc_digest(descriptor)])
    key = HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=info).derive(root)
    nonce = os.urandom(12); value = b"synthetic payload"
    header = struct.pack(">4sBBH16sQ32sI12s",b"CPD2",1,1,0,handle.bytes,gen,descriptor,len(value),nonce)
    def aad(record):
        return hashlib.sha256(E([enc_label("cryptalis/payload-aad/2"),enc_bytes(header),
            enc_uuid(domain),enc_uuid(tenant),enc_uuid(subject),enc_bytes(b"\x04"+struct.pack(">Q",record)),
            enc_uuid(model),enc_uuid(table),enc_uuid(field),enc_uuid(representation),
            enc_digest(descriptor),(6,b"payload"),enc_u64(gen)])).digest()
    a = AESGCMSIV(key); ct = a.encrypt(nonce,value,aad(1))
    assert len(header)==80 and len(header+ct)==len(value)+96
    assert a.decrypt(nonce,ct,aad(1))==value
    failed=[]
    for name, bad_key, bad_ct, bad_aad, bad_nonce in [
        ("tamper",key,ct[:-1]+bytes([ct[-1]^1]),aad(1),nonce),
        ("relocation",key,ct,aad(2),nonce),
        ("wrong_key",bytes(32),ct,aad(1),nonce),
        ("wrong_context",key,ct,bytes(32),nonce),
        ("wrong_nonce",key,ct,aad(1),bytes(12))]:
        try:AESGCMSIV(bad_key).decrypt(bad_nonce,bad_ct,bad_aad)
        except InvalidTag:failed.append(name)
        else:raise AssertionError(name)
    assert a.decrypt(nonce,ct,aad(1))==value  # Authentic same-context replay remains accepted.
    material=LocalMaterial(key); material.encrypt(value,aad(1))
    read_fd, write_fd=os.pipe(); pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:material.encrypt(value,aad(1)); outcome=b"BAD"
        except ForkDenied:outcome=b"DENIED"
        fresh=LocalMaterial(key); n,_=fresh.encrypt(value,aad(1))
        os.write(write_fd,outcome+b":"+n.hex().encode());os.close(write_fd);os._exit(0)
    os.close(write_fd);child=os.read(read_fd,128);os.close(read_fd);_,status=os.waitpid(pid,0)
    assert os.waitstatus_to_exitcode(status)==0 and child.startswith(b"DENIED:")
    parent_nonce,_=material.encrypt(value,aad(1));assert child.split(b":")[1]!=parent_nonce.hex().encode()
    # Demonstrate a cheap presence MAC, including its replay limitation. This is not an adopted profile.
    presence_key=bytes(range(31,-1,-1))
    present=hmac.digest(presence_key,b"record-1:present","sha256")
    absent=hmac.digest(presence_key,b"record-1:absent","sha256")
    assert not hmac.compare_digest(present,hmac.digest(presence_key,b"record-1:absent","sha256"))
    assert hmac.compare_digest(absent,hmac.digest(presence_key,b"record-1:absent","sha256"))
    return {"openssl":backend.openssl_version_text(),"header_bytes":len(header),"rejected":failed,
            "same_context_replay":"ACCEPTED_DOCUMENTED_LIMIT","fork_inherited":"DENIED",
            "fresh_child_nonce_observation":"distinct in this sample, not an RNG proof",
            "presence_MAC_counterexample":"detects fresh substitution but accepts historical absent-marker replay",
            "descriptor_limit":"synthetic digest; not a complete canonical-descriptor vector suite"}


if __name__=="__main__":
    result={"spike":"S4","status":"PASS_LOCAL_SMOKE","evidence":smoke(),
            "limits":["not an independent cryptographic audit","no live provider, quota or destruction proof"]}
    out=Path(__file__).parent/"results";out.mkdir(exist_ok=True)
    (out/"S4.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps(result,indent=2))
