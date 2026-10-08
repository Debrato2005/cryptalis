"""Observable CF1 attacks, provider failures, and real PostgreSQL persistence."""

import asyncio
import json
import os
import time
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from sqlalchemy import BigInteger, Column, MetaData, Table, Text, Uuid, create_engine, text
from sqlalchemy.orm import registry

from cryptalis.crypto.cf1 import FieldDescriptor, open_text, seal_text, MAX_TEXT_BYTES
from cryptalis.crypto.keys import (
    AuthenticationFailed, CryptoFailure, DevelopmentKeyProvider, InvalidContext,
    InvalidFrame, InvalidText, KeyContext, KeyPolicy, Keyring, KeyUnavailable,
    RepresentationMismatch, create_root,
)
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory, compile_protection


DOMAIN, TABLE, FIELD, TENANT, RECORD = (UUID(int=i) for i in range(1, 6))


def descriptor(*, equality=False, bigint=False):
    document = {
        "schema": "cryptalis.context/v1", "domain_id": str(DOMAIN),
        "table_id": str(TABLE), "field_id": str(FIELD),
        "text_codec": "utf8-exact/v1", "normalizer": "identity/v1",
        "null_policy": "sql-null/v1",
        "record_codec": "int64-be/v1" if bigint else "uuid16/v1",
        "tenant_codec": "uuid16/v1",
        "representation": "cf1-packed-equality/v1" if equality else "cf1-storage/v1",
    }
    from hashlib import sha256
    digest = sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return FieldDescriptor.from_compiled(document, digest)


def setup_keys(*, equality=False, max_age=60, provider=None, tenant=TENANT):
    provider = provider or DevelopmentKeyProvider()
    payload = KeyContext(DOMAIN, tenant, "payload", UUID(int=6), 1)
    wrappers = [provider.wrap(bytes(range(32)), payload)]
    if equality:
        search = KeyContext(DOMAIN, tenant, "search", UUID(int=7), 2)
        wrappers.append(provider.wrap(bytes(range(32, 64)), search))
    policy = KeyPolicy(DOMAIN, tenant, tuple(wrappers), 1, 2 if equality else None)
    return provider, Keyring(policy, {provider.provider_id: provider}, max_age=max_age)


VECTORS = json.loads((Path(__file__).parent / "fixtures" / "cf1_vectors.json").read_text())


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["name"])
def test_frozen_independent_cf1_vectors(vector, monkeypatch):
    field = FieldDescriptor.from_compiled(vector["descriptor"], vector["descriptor_digest"])
    tenant = UUID(vector["tenant_id"])
    record = UUID(vector["record_id"]) if field.record_codec == "uuid16/v1" else vector["record_id"]
    provider = DevelopmentKeyProvider()
    wrappers = [provider.wrap(bytes.fromhex(vector["payload_root"]),
                              KeyContext(field.domain_id, tenant, "payload",
                                         UUID(vector["payload_root_id"]), vector["payload_generation"]))]
    if field.equality:
        wrappers.append(provider.wrap(bytes.fromhex(vector["search_root"]),
                                      KeyContext(field.domain_id, tenant, "search",
                                                 UUID(vector["search_root_id"]), vector["search_generation"])))
    policy = KeyPolicy(field.domain_id, tenant, tuple(wrappers), vector["payload_generation"],
                       vector["search_generation"] or None)
    keys = Keyring(policy, {provider.provider_id: provider}).prepare()
    frozen = bytes.fromhex(vector["frame"])
    assert open_text(frozen, field, tenant, record, keys) == vector["text"]
    # Only this test substitutes the RNG; production has no nonce parameter.
    monkeypatch.setattr(os, "urandom", lambda n: bytes.fromhex(vector["nonce"]) if n == 12 else bytes(n))
    assert seal_text(vector["text"], field, tenant, record, keys) == frozen


def test_published_primitive_vectors_for_installed_backend():
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    primitives = VECTORS["primitive_vectors"]
    for v in primitives["aes256_gcm_siv"]:
        cipher = AESGCMSIV(bytes.fromhex(v["key"]))
        assert cipher.encrypt(bytes.fromhex(v["nonce"]), bytes.fromhex(v["plaintext"]),
                              bytes.fromhex(v["aad"])).hex() == v["sealed"]
        assert cipher.decrypt(bytes.fromhex(v["nonce"]), bytes.fromhex(v["sealed"]),
                              bytes.fromhex(v["aad"])).hex() == v["plaintext"]
    v = primitives["hkdf_sha256"]
    assert HKDF(algorithm=hashes.SHA256(), length=v["length"], salt=bytes.fromhex(v["salt"]),
                info=bytes.fromhex(v["info"])).derive(bytes.fromhex(v["ikm"])).hex() == v["output"]
    v = primitives["hmac_sha256"]
    mac = hmac.HMAC(bytes.fromhex(v["key"]), hashes.SHA256())
    mac.update(bytes.fromhex(v["message"]))
    assert mac.finalize().hex() == v["output"]


@pytest.mark.parametrize("equality", [False, True])
def test_exact_text_null_empty_and_fresh_os_nonces(equality):
    _, ring = setup_keys(equality=equality)
    keys = ring.prepare()
    field = descriptor(equality=equality)
    for value in (None, "", "café", "cafe\u0301", "雪😀\n", " leading trailing "):
        frame = seal_text(value, field, TENANT, RECORD, keys)
        assert open_text(frame, field, TENANT, RECORD, keys) == value
        if value is not None:
            assert isinstance(frame, bytes)
            assert len(frame) == len(value.encode()) + (74 if equality else 42)
            assert seal_text(value, field, TENANT, RECORD, keys) != frame
    assert seal_text("café", field, TENANT, RECORD, keys) != seal_text("cafe\u0301", field, TENANT, RECORD, keys)


@pytest.mark.parametrize("equality", [False, True])
def test_attack_cases_reject_before_plaintext_release(equality):
    _, ring = setup_keys(equality=equality)
    keys, field = ring.prepare(), descriptor(equality=equality)
    frame = seal_text("private-value", field, TENANT, RECORD, keys)
    attacks = [b"", frame[:41], frame[:-1], frame + b"trailing",
               frame[:4] + b"\x02" + frame[5:], frame[:5] + b"\x04" + frame[6:]]
    # Every header, nonce, term, ciphertext and tag byte is authenticated or refused.
    for index in range(len(frame)):
        changed = bytearray(frame)
        changed[index] ^= 1
        attacks.append(bytes(changed))
    for attack in attacks:
        with pytest.raises(CryptoFailure):
            open_text(attack, field, TENANT, RECORD, keys)
    for tenant, record in ((uuid4(), RECORD), (TENANT, uuid4())):
        with pytest.raises(CryptoFailure):
            open_text(frame, field, tenant, record, keys)
    other = descriptor(equality=equality)
    from dataclasses import replace
    with pytest.raises(AuthenticationFailed):
        open_text(frame, replace(other, field_id=uuid4()), TENANT, RECORD, keys)
    # Freshness is explicitly outside the CF1 contract.
    assert open_text(frame, field, TENANT, RECORD, keys) == "private-value"


def test_strict_codec_bounds_and_typed_record_ids():
    _, ring = setup_keys()
    keys, field = ring.prepare(), descriptor()
    for value in ("x\x00y", "\ud800", 42, b"text", "x" * (MAX_TEXT_BYTES + 1)):
        with pytest.raises(InvalidText):
            seal_text(value, field, TENANT, RECORD, keys)
    for record in (5, str(RECORD), None):
        with pytest.raises(InvalidContext):
            seal_text("x", field, TENANT, record, keys)
    bigint = descriptor(bigint=True)
    for record in (-2**63, 0, 2**63 - 1):
        frame = seal_text("x", bigint, TENANT, record, keys)
        assert open_text(frame, bigint, TENANT, record, keys) == "x"
    for record in (True, 2**63, -2**63 - 1, RECORD):
        with pytest.raises(InvalidContext):
            seal_text("x", bigint, TENANT, record, keys)
    with pytest.raises(InvalidFrame):
        open_text(b"x" * (MAX_TEXT_BYTES + 75), field, TENANT, RECORD, keys)


def test_os_rng_failures_and_independent_root_generation(monkeypatch):
    provider, ring = setup_keys(equality=True)
    p, s = (wrapper.context for wrapper in ring.policy.wrappers)
    first, second = create_root(provider, p), create_root(provider, s)
    assert provider.unwrap(first, p) != provider.unwrap(second, s)
    repeated = provider.wrap(provider.unwrap(first, p), s)
    with pytest.raises(KeyUnavailable):
        Keyring(KeyPolicy(DOMAIN, TENANT, (first, repeated), 1, 2),
                {provider.provider_id: provider}).prepare()
    keys = ring.prepare()
    def failed_rng(_):
        raise OSError("private OS diagnostic")
    monkeypatch.setattr(os, "urandom", failed_rng)
    # Operation IDs must remain available when the RNG itself fails.
    for operation in (DevelopmentKeyProvider, lambda: create_root(provider, p),
                      lambda: seal_text("x", descriptor(equality=True), TENANT, RECORD, keys)):
        with pytest.raises(CryptoFailure) as failure:
            operation()
        assert "private OS diagnostic" not in str(failure.value)


def test_authenticated_invalid_text_and_wrong_search_root_are_refused():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    from dataclasses import replace
    vector = VECTORS["vectors"][0]
    field = FieldDescriptor.from_compiled(vector["descriptor"], vector["descriptor_digest"])
    tenant, record = UUID(vector["tenant_id"]), UUID(vector["record_id"])
    provider = DevelopmentKeyProvider()
    context = KeyContext(field.domain_id, tenant, "payload", UUID(vector["payload_root_id"]),
                         vector["payload_generation"])
    wrapper = provider.wrap(bytes.fromhex(vector["payload_root"]), context)
    keys = Keyring(KeyPolicy(field.domain_id, tenant, (wrapper,), context.generation),
                   {provider.provider_id: provider}).prepare()
    for encoded in (b"\xff", b"x\x00y"):
        nonce = bytes.fromhex(vector["nonce"])
        malicious = (bytes.fromhex(vector["header"]) + nonce +
                     AESGCMSIV(bytes.fromhex(vector["payload_key"])).encrypt(nonce, encoded,
                                                                          bytes.fromhex(vector["aad"])))
        with pytest.raises(InvalidText):
            open_text(malicious, field, tenant, record, keys)
    provider, ring = setup_keys(equality=True)
    frame = seal_text("x", descriptor(equality=True), TENANT, RECORD, ring.prepare())
    payload, search = ring.policy.wrappers
    other_search = provider.wrap(b"z" * 32, search.context)
    wrong = Keyring(replace(ring.policy, wrappers=(payload, other_search)), {provider.provider_id: provider}).prepare()
    with pytest.raises(RepresentationMismatch):
        open_text(frame, descriptor(equality=True), TENANT, RECORD, wrong)


class OutageProvider(DevelopmentKeyProvider):
    offline = False

    def unwrap(self, wrapper, context):
        if self.offline:
            raise RuntimeError("provider-secret must not escape")
        return super().unwrap(wrapper, context)


def test_cache_never_refreshes_on_access_and_expiry_fails_closed(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    provider, ring = setup_keys(provider=OutageProvider(), max_age=10)
    keys = ring.prepare()
    provider.offline = True
    for instant in (101, 105, 109.999):
        now[0] = instant
        assert open_text(seal_text("x", descriptor(), TENANT, RECORD, ring.prepare()),
                         descriptor(), TENANT, RECORD, keys) == "x"
    now[0] = 110
    with pytest.raises(KeyUnavailable) as failure:
        ring.prepare()
    assert "provider-secret" not in str(failure.value)
    with pytest.raises(KeyUnavailable):
        seal_text("x", descriptor(), TENANT, RECORD, keys)
    assert failure.value.effects == "none"
    assert failure.value.remedy


def test_wrapper_context_provider_pinning_rewrap_and_retirement():
    provider, ring = setup_keys()
    policy = ring.policy
    wrapper = policy.wrappers[0]
    replacement = DevelopmentKeyProvider()
    rewritten = provider.rewrap(wrapper, replacement, wrapper.context)
    assert replacement.unwrap(rewritten, wrapper.context) == provider.unwrap(wrapper, wrapper.context)
    frame = seal_text("rewrap preserves data", descriptor(), TENANT, RECORD, ring.prepare())
    rewritten_keys = Keyring(KeyPolicy(DOMAIN, TENANT, (rewritten,), 1),
                            {replacement.provider_id: replacement}).prepare()
    assert open_text(frame, descriptor(), TENANT, RECORD, rewritten_keys) == "rewrap preserves data"
    with pytest.raises(KeyUnavailable):
        provider.unwrap(rewritten, wrapper.context)
    from dataclasses import replace
    with pytest.raises(KeyUnavailable):
        provider.unwrap(wrapper, replace(wrapper.context, tenant_id=uuid4()))
    frame = seal_text("x", descriptor(), TENANT, RECORD, ring.prepare())
    retired = KeyPolicy(DOMAIN, TENANT, (replacement.wrap(bytes(range(32)),
                        replace(wrapper.context, generation=2)),), 2)
    with pytest.raises(AttributeError):
        ring.policy = retired
    with pytest.raises(KeyUnavailable):
        open_text(frame, descriptor(), TENANT, RECORD,
                  Keyring(retired, {replacement.provider_id: replacement}).prepare())
    wrong = provider.wrap(b"z" * 32, wrapper.context)
    wrong_ring = Keyring(replace(policy, wrappers=(wrong,)), {provider.provider_id: provider})
    with pytest.raises(AuthenticationFailed):
        open_text(frame, descriptor(), TENANT, RECORD, wrong_ring.prepare())


def test_canceled_and_failed_preparation_publish_no_partial_roots():
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        class DelayedProvider(OutageProvider):
            reject_payload = False

            def unwrap(self, wrapper, context):
                if self.reject_payload and context.purpose == "payload":
                    raise RuntimeError("payload unavailable after canceled preparation")
                return super().unwrap(wrapper, context)

            async def unwrap_async(self, wrapper, context):
                if context.purpose == "search":
                    entered.set()
                    try:
                        await release.wait()
                    except asyncio.CancelledError:
                        # Deliberately misbehaving provider returns late material.
                        pass
                return self.unwrap(wrapper, context)

        provider, ring = setup_keys(equality=True, provider=DelayedProvider())
        task = asyncio.create_task(ring.prepare_async())
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        provider.reject_payload = True
        release.set()
        with pytest.raises(KeyUnavailable):
            ring.prepare()
        provider.reject_payload = False
        provider.offline = True
        with pytest.raises(KeyUnavailable):
            await ring.prepare_async()
        with pytest.raises(KeyUnavailable):
            ring.prepare()
        provider.offline = False
        release.set()
        keys = await ring.prepare_async()
        assert open_text(seal_text("ok", descriptor(equality=True), TENANT, RECORD, keys),
                         descriptor(equality=True), TENANT, RECORD, keys) == "ok"

    asyncio.run(scenario())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_failed_preparation_cannot_leave_the_first_root_warm(asynchronous):
    class FailingProvider(DevelopmentKeyProvider):
        denied = "search"

        def unwrap(self, wrapper, context):
            if context.purpose == self.denied:
                raise RuntimeError("injected provider failure")
            return super().unwrap(wrapper, context)

    provider, ring = setup_keys(equality=True, provider=FailingProvider())
    def prepare():
        return asyncio.run(ring.prepare_async()) if asynchronous else ring.prepare()
    with pytest.raises(KeyUnavailable):
        prepare()
    # Search now works, but payload custody fails. A partially cached payload
    # from the first failed preparation must not make the second one succeed.
    provider.denied = "payload"
    with pytest.raises(KeyUnavailable):
        prepare()
    provider.denied = None
    keys = prepare()
    assert open_text(seal_text("x", descriptor(equality=True), TENANT, RECORD, keys),
                     descriptor(equality=True), TENANT, RECORD, keys) == "x"


def test_fork_cannot_use_inherited_prepared_keys_or_provider():
    provider, ring = setup_keys()
    keys = ring.prepare()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        results = []
        for operation in (lambda: seal_text("x", descriptor(), TENANT, RECORD, keys),
                          ring.prepare, lambda: provider.unwrap(ring.policy.wrappers[0],
                                                               ring.policy.wrappers[0].context)):
            try:
                operation()
                results.append(b"BAD")
            except KeyUnavailable:
                results.append(b"refused")
        _, fresh_ring = setup_keys()
        if seal_text("fresh child context", descriptor(), TENANT, RECORD, fresh_ring.prepare()):
            results.append(b"fresh")
        os.write(write_fd, b",".join(results))
        os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 100)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert result == b"refused,refused,refused,fresh"
    assert seal_text("parent", descriptor(), TENANT, RECORD, keys)


@pytest.mark.parametrize("equality", [False, True])
@pytest.mark.parametrize("bigint", [False, True])
@pytest.mark.parametrize("single", [False, True])
def test_native_postgresql_text_nulls_and_compiled_descriptor_frames(equality, bigint, single):
    if not os.environ.get("CRYPTALIS_TEST_DATABASE_URL"):
        pytest.skip("Real PostgreSQL evidence requires the authorized database")
    with psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"], connect_timeout=5) as connection:
        assert connection.execute("select 1").fetchone() == (1,)
        assert int(connection.execute("show server_version_num").fetchone()[0]) // 10000 == 16
    engine = create_engine("postgresql+psycopg://", echo=False, hide_parameters=True,
                           creator=lambda: psycopg.connect(os.environ["CRYPTALIS_TEST_DATABASE_URL"]))
    schema = "cryptalis_cf1_" + uuid4().hex
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table("customer", mapping.metadata,
                  Column("id", BigInteger if bigint else Uuid, primary_key=True, autoincrement=False),
                  Column("tenant_id", Uuid, nullable=False), Column("note", Text(collation="C")))
    class Customer:
        pass
    mapping.map_imperatively(Customer, table)
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        mapping.metadata.create_all(engine)
        raw = {"schema": "cryptalis.protection/v1", "profile": "cf1", "domain_id": str(DOMAIN),
               "models": [{"model": "Customer", "table_id": str(TABLE),
                           "tenancy": {"single_tenant": True} if single else {"column": "tenant_id"},
                           "fields": [{"name": "note", "field_id": str(FIELD), "protect": True,
                                       "queries": ["equality"] if equality else [],
                                       "accept_leakage": ["equality"] if equality else []}]}]}
        plan = compile_protection(json.dumps(raw).encode(), mapping, engine,
                                  writers=WriterInventory(True, (Writer(TABLE, "test", "sqlalchemy", evidence="native fixture owns all writers"),)),
                                  search_reviews=(SearchReview(FIELD, False, "free-form synthetic text"),) if equality else ())
        locked = json.loads(plan.lock_bytes)["models"][0]["fields"][0]
        field = FieldDescriptor.from_compiled(locked["descriptor"], locked["descriptor_digest"])
        tenant = TABLE if single else UUID(int=0)
        _, ring = setup_keys(equality=equality, tenant=tenant)
        keys = ring.prepare()
        values = [None, "", "café", "cafe\u0301", "雪😀\n", "  exact  "]
        with engine.begin() as connection:
            connection.execute(text(f'ALTER TABLE "{schema}".customer ADD COLUMN protected pg_catalog.bytea'))
            for index, value in enumerate(values):
                record = (-2**63, -1, 0, 1, 42, 2**63 - 1)[index] if bigint else UUID(int=index)
                connection.execute(table.insert().values(id=record, tenant_id=tenant, note=value))
                frame = seal_text(value, field, tenant, record, keys)
                connection.execute(text(f'UPDATE "{schema}".customer SET protected=:frame WHERE id=:id'),
                                   {"frame": frame, "id": record})
        with engine.connect() as connection:
            rows = connection.execute(text(f'SELECT id, tenant_id, note, protected FROM "{schema}".customer')).all()
            assert len(rows) == len(values)
            for record, tenant, native, stored in rows:
                assert open_text(stored, field, tenant, record, keys) == native
                if stored is not None:
                    with pytest.raises(AuthenticationFailed):
                        open_text(stored, field, tenant, 123 if bigint else uuid4(), keys)
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()
