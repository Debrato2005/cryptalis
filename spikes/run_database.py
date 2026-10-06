"""S1/S3: disposable PostgreSQL experiments using documented SQLAlchemy APIs."""
import asyncio
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import struct
import threading
from types import MappingProxyType
import uuid

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from sqlalchemy import (BigInteger, Column, LargeBinary, MetaData, String, Table,
                        bindparam, create_engine, event, inspect, select, update)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.hybrid import Comparator, hybrid_property
from sqlalchemy.orm import Session, add_mapped_attribute, registry
from sqlalchemy.orm.attributes import flag_dirty, set_committed_value
from sqlalchemy.orm.util import identity_key
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import BindParameter
from sqlalchemy.types import TypeDecorator


SOCKET = "/tmp/cryptalis-hardening-postgres"
SYNC_URL = "postgresql+psycopg://debrato@/postgres?host=" + SOCKET + "&port=55432"
DSN = "dbname=postgres user=debrato host=" + SOCKET + " port=55432"
TENANT = "00000000-0000-0000-0000-000000000002"
KEY = bytes(range(32))  # Synthetic fixture, never production material.
TERM_KEY = bytes(range(31, -1, -1))


class ProtectedUnavailable(Exception): pass
class LateProtectedWrite(Exception): pass
class UnsupportedProtectedOperation(Exception): pass
class IndexInconsistent(Exception): pass
class ProtectedAuthenticationFailure(Exception): pass
class StaleFenceDenied(Exception): pass


def term(value):
    if value is None: return None
    if type(value) is not str: raise TypeError("Exact text required")
    return hmac.digest(TERM_KEY, b"S3/tenant/field/" + value.encode(), "sha256")


def aad(identity, tenant):
    return b"S1/fixture/email/" + uuid.UUID(tenant).bytes + struct.pack(">Q", identity)


def protect(identity, tenant, value):
    if value is None: return None
    n = os.urandom(12)
    return n + AESGCMSIV(KEY).encrypt(n, value.encode(), aad(identity, tenant))


def reveal(identity, tenant, ct):
    if ct is None: return None
    if len(ct) < 28: raise ProtectedAuthenticationFailure("Malformed fixture envelope")
    return AESGCMSIV(KEY).decrypt(ct[:12], ct[12:], aad(identity, tenant)).decode()


mapper_registry = registry()
metadata = MetaData()
table = Table("spike_user", metadata, Column("id", BigInteger, primary_key=True),
              Column("tenant_id", String, nullable=False), Column("email", String))


class User:
    def __init__(self, id, email, tenant_id=TENANT):
        self.id = id; self.tenant_id = tenant_id; self.email = email


mapper_registry.map_imperatively(User, table)
# Bootstrap-only, before instances/queries. The adapter owns this dedicated registry.
mapper_registry.dispose()
metadata = MetaData()
table = Table("spike_user", metadata, Column("id", BigInteger, primary_key=True),
              Column("tenant_id", String, nullable=False), Column("ct", LargeBinary),
              Column("eq", LargeBinary))
mapper_registry.map_imperatively(User, table, properties={"_ct": table.c.ct, "_term": table.c.eq})


class QueryValue(TypeDecorator):
    impl = String
    cache_ok = False
    def process_bind_param(self, value, dialect):
        raise UnsupportedProtectedOperation("Unprepared protected query value")


class EmailComparator(Comparator):
    def __clause_element__(self): return User._ct.label("email")
    def __eq__(self, value):
        if value is None: return User._ct.is_(None)
        return User._term == bindparam(None, value, type_=QueryValue())
    def in_(self, values):
        values = list(values)
        if len(values) > 1000: raise UnsupportedProtectedOperation("IN budget")
        return User._term.in_(bindparam(None, values, expanding=True, type_=QueryValue()))


def get_email(instance):
    state = inspect(instance)
    session = state.session
    if session is None or "_ct" in state.unloaded:
        raise ProtectedUnavailable("Explicit refresh required")
    if hasattr(instance, "_pending_email"): return instance._pending_email
    frame = session.info.get("publication", {})
    if instance.id not in frame: raise ProtectedUnavailable("Explicit read required")
    return frame[instance.id]


def set_email(instance, value):
    if value is not None and type(value) is not str: raise TypeError("Exact text required")
    instance._pending_email = value
    flag_dirty(instance)


email_property = hybrid_property(get_email, set_email).comparator(lambda cls: EmailComparator(cls._ct))
add_mapped_attribute(User, "email", email_property)


def write_set(session):
    entries = []
    for obj in set(session.new) | set(session.dirty) | set(session.deleted):
        if isinstance(obj, User):
            entries.append((id(obj), obj.id, obj.tenant_id,
                            getattr(obj, "_pending_email", "NO_PENDING"), obj in session.deleted))
    return tuple(sorted(entries))


class LogicalResult:
    def __init__(self, rows): self.rows = rows
    def all(self): return list(self.rows)
    def first(self): return self.rows[0] if self.rows else None
    def scalars(self): return LogicalResult([r[0] for r in self.rows])
    def scalar(self): return self.rows[0][0] if self.rows else None
    def scalar_one_or_none(self):
        if len(self.rows) > 1: raise ValueError("Multiple rows")
        return self.scalar()
    def __iter__(self): return iter(self.rows)


class ProtectedSession(Session):
    def freeze(self):
        self.info["sealed_write_set"] = write_set(self)
        self.info["material_ready"] = True
    def commit(self):
        if not self.info.get("async_prepared"): self.freeze()
        super().commit()
        for obj in list(self.identity_map.values()):
            if hasattr(obj, "_pending_email"): del obj._pending_email
        self.info["publication"] = MappingProxyType({})
    def rollback(self):
        self.info["publication"] = MappingProxyType({})
        for obj in list(self.identity_map.values()):
            if hasattr(obj, "_pending_email"): del obj._pending_email
        super().rollback()
    def merge(self, *args, **kwargs): raise UnsupportedProtectedOperation("Merge excluded")
    def execute(self, statement, params=None, **kwargs):
        if self.info.get("collecting"):
            return super().execute(statement, params, **kwargs)
        if not statement.is_select: raise UnsupportedProtectedOperation("Bulk/Core DML excluded")
        self.freeze()
        def rewrite(node):
            if isinstance(node, BindParameter) and isinstance(node.type, QueryValue):
                val = [term(x) for x in node.value] if node.expanding else term(node.value)
                return bindparam(node.key, val, expanding=node.expanding, type_=LargeBinary())
            return None
        statement = visitors.replacement_traverse(statement, {}, rewrite)
        desc = statement.column_descriptions
        entity = len(desc) == 1 and desc[0]["expr"] is User
        projection = len(desc) == 1 and desc[0]["name"] == "email"
        if not entity and not projection: raise UnsupportedProtectedOperation("Projection excluded")
        raw_stmt = statement.with_only_columns(User.id, User.tenant_id, User._ct, User._term,
                                               maintain_column_froms=True).where(User.tenant_id == TENANT)
        self.info["collecting"] = True
        try:
            raw = list(super().execute(raw_stmt, params, execution_options={"compiled_cache": None}))
            staged = {}
            for rid, tenant, ct, eq in raw:
                value = reveal(rid, tenant, ct)
                if term(value) != eq: raise IndexInconsistent("Stored term mismatch")
                staged[rid] = value
            objects = []
            if entity:
                for rid, tenant, ct, eq in raw:
                    obj = self.identity_map.get(identity_key(User, (rid,)))
                    if obj is None: obj = super().get(User, rid)
                    set_committed_value(obj, "id", rid)
                    set_committed_value(obj, "tenant_id", tenant)
                    set_committed_value(obj, "_ct", ct)
                    set_committed_value(obj, "_term", eq)
                    objects.append(obj)
            # One frame-reference publication. Pending logical values are independent.
            frame = dict(self.info.get("publication", {})); frame.update(staged)
            self.info["publication"] = MappingProxyType(frame)
            return LogicalResult([(x,) for x in objects] if entity else [(staged[r[0]],) for r in raw])
        except Exception:
            self.info["publication"] = MappingProxyType({}); self.close(); raise
        finally: self.info["collecting"] = False
    def scalar(self, statement, params=None, **kwargs):
        return self.execute(statement, params, **kwargs).scalar()
    def get(self, entity, ident, **kwargs):
        if self.info.get("collecting"): return super().get(entity, ident, **kwargs)
        return self.execute(select(User).where(User.id == ident)).scalar_one_or_none()
    def refresh(self, instance, attribute_names=None, **kwargs):
        if attribute_names not in (None, ["email"]):
            raise UnsupportedProtectedOperation("Only complete protected refresh in this spike")
        self.get(User, inspect(instance).identity[0])
        if hasattr(instance, "_pending_email"): del instance._pending_email
    def close(self):
        self.info["publication"] = MappingProxyType({}); super().close()


@event.listens_for(ProtectedSession, "before_flush")
def seal_rows(session, flush_context, instances):
    if instances is not None: raise UnsupportedProtectedOperation("Selective flush excluded")
    if not session.info.get("material_ready") or write_set(session) != session.info.get("sealed_write_set"):
        raise LateProtectedWrite("Write set changed after preparation")
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, User) and hasattr(obj, "_pending_email"):
            obj._ct = protect(obj.id, obj.tenant_id, obj._pending_email)
            obj._term = term(obj._pending_email)
    session.connection().info["sealed_session"] = session


@event.listens_for(ProtectedSession, "after_flush_postexec")
def observe_flush(session, flush_context):
    # A later flush cycle must use a fresh explicitly prepared set.
    session.info["material_ready"] = False


class ProtectedAsyncSession(AsyncSession):
    sync_session_class = ProtectedSession
    async def prepare(self):
        await self.run_sync(lambda s: s.freeze())
        await asyncio.sleep(0)  # Bounded fake async material preparation boundary.
        self.sync_session.info["async_prepared"] = True
    async def execute(self, statement, params=None, **kwargs):
        await self.prepare()
        return await self.run_sync(lambda s: s.execute(statement, params, **kwargs))
    async def scalar(self, statement, params=None, **kwargs):
        return (await self.execute(statement, params, **kwargs)).scalar()
    async def get(self, entity, ident, **kwargs):
        return (await self.execute(select(User).where(User.id == ident))).scalar_one_or_none()
    async def commit(self):
        await self.prepare(); await super().commit()
    async def refresh(self, instance, attribute_names=None, **kwargs):
        await self.prepare(); await self.run_sync(lambda s: s.refresh(instance, attribute_names, **kwargs))


def expect(kind, fn):
    try: fn()
    except kind: return
    raise AssertionError("Expected " + kind.__name__)


def sql_guard(conn, clauseelement, multiparams, params, execution_options):
    session = conn.info.get("sealed_session")
    if session is not None and not session.info.get("collecting") and getattr(clauseelement, "is_dml", False):
        if write_set(session) != session.info.get("sealed_write_set"):
            raise LateProtectedWrite("Late protected mutation before SQL emission")


def raw_engine():
    engine = create_engine(SYNC_URL, hide_parameters=True, echo=False)
    event.listen(engine, "before_execute", sql_guard)
    event.listen(engine, "checkin", lambda connection, record: record.info.pop("sealed_session", None))
    return engine


def initial_data(engine):
    metadata.drop_all(engine); metadata.create_all(engine)
    with engine.begin() as c:
        for rid, value in [(1, "stored-A"), (2, "stored-C")]:
            c.execute(table.insert().values(id=rid, tenant_id=TENANT, ct=protect(rid,TENANT,value), eq=term(value)))


def sync_cases(engine):
    traces = []
    with ProtectedSession(engine, expire_on_commit=False) as s:
        u = s.get(User, 1); assert u.email == "stored-A"
        u.email = "pending-B"
        with s.no_autoflush:
            assert s.scalar(select(User.email).where(User.id == 1)) == "stored-A"
            assert s.get(User, 1) is u and u.email == "pending-B"
        s.commit(); assert s.get(User,1).email == "pending-B"
        traces.append("dirty_no_autoflush_entity_vs_scalar")
        u.email = "discard-on-refresh"; s.refresh(u); assert u.email == "pending-B"
        s.expire(u); expect(ProtectedUnavailable, lambda: u.email)
        s.refresh(u); assert u.email == "pending-B"
        u.email = "discard-on-rollback"; s.rollback(); expect(ProtectedUnavailable, lambda: u.email)
        s.refresh(u); assert u.email == "pending-B"
        expect(UnsupportedProtectedOperation, lambda: s.merge(u))
        expect(UnsupportedProtectedOperation, lambda: s.execute(update(User).values(tenant_id=TENANT)))
        traces.extend(["refresh_discards_pending", "expiry_explicit_refresh", "rollback_invalidates", "merge_and_bulk_rejected"])
    with ProtectedSession(engine, expire_on_commit=False) as s:
        u=s.get(User,1)
        with engine.begin() as c:c.execute(table.update().where(table.c.id==2).values(ct=b"corrupt",eq=term("stored-C")))
        expect(ProtectedAuthenticationFailure,lambda:s.execute(select(User).order_by(User.id)))
        expect(ProtectedUnavailable,lambda:u.email)
        assert not s.info["publication"]
        traces.append("last_row_corruption_no_publication")
    initial_data(engine)
    with ProtectedSession(engine, expire_on_commit=False) as s:
        s.add(User(3,"prepared"));s.freeze()
        def late(session,ctx,instances):session.add(User(4,"late"))
        event.listen(s,"before_flush",late,insert=True)
        expect(LateProtectedWrite,lambda:s.flush());s.rollback()
        traces.append("late_before_flush_write_rejected")
    return traces


async def async_cases():
    engine=create_async_engine(SYNC_URL,hide_parameters=True,echo=False)
    event.listen(engine.sync_engine,"before_execute",sql_guard)
    event.listen(engine.sync_engine,"checkin",lambda connection,record:record.info.pop("sealed_session",None))
    traces=[]
    try:
        async with ProtectedAsyncSession(engine,expire_on_commit=False) as s:
            u=await s.get(User,1);assert u.email=="stored-A"
            u.email="async-B"
            with s.no_autoflush:
                assert await s.scalar(select(User.email).where(User.id==1))=="stored-A"
                assert await s.get(User,1) is u and u.email=="async-B"
            await s.commit();assert (await s.get(User,1)).email=="async-B"
            u.email="discard";await s.refresh(u);assert u.email=="async-B"
            traces.extend(["async_dirty_scalar_identity", "async_commit_refresh"])
        async with ProtectedAsyncSession(engine,expire_on_commit=False) as s:
            s.add(User(5,"prepared"))
            def late(session,ctx,instances):session.add(User(6,"late"))
            event.listen(s.sync_session,"before_flush",late,insert=True)
            try:await s.commit()
            except LateProtectedWrite:pass
            else:raise AssertionError("Late async addition accepted")
            await s.rollback();traces.append("async_late_addition_rejected_without_provider_IO_in_event")
    finally:await engine.dispose()
    return traces


def search_cases():
    with psycopg.connect(DSN) as c:
        c.execute("DROP TABLE IF EXISTS spike_search")
        c.execute("CREATE TABLE spike_search (id bigint primary key, tenant text not null, eq bytea, deleted boolean not null default false, UNIQUE(tenant,eq))")
    barrier=threading.Barrier(2)
    def insert(rid):
        with psycopg.connect(DSN) as c:
            barrier.wait()
            try:c.execute("INSERT INTO spike_search(id,tenant,eq) VALUES(%s,%s,%s)",(rid,TENANT,term("same")))
            except psycopg.errors.UniqueViolation:return "CONFLICT"
        return "COMMITTED"
    with ThreadPoolExecutor(max_workers=2) as pool:race=list(pool.map(insert,[1,2]))
    assert sorted(race)==["COMMITTED","CONFLICT"]
    with psycopg.connect(DSN) as c:
        c.execute("INSERT INTO spike_search(id,tenant,eq) VALUES(3,%s,NULL),(4,%s,NULL)",(TENANT,TENANT))
        nulls=c.execute("SELECT count(*) FROM spike_search WHERE eq IS NULL").fetchone()[0];assert nulls==2
        assert c.execute("SELECT count(*) FROM spike_search WHERE eq = ANY(%s::bytea[])",([],)).fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM spike_search WHERE eq IN (%s,NULL)",(term("same"),)).fetchone()[0]==1
        assert c.execute("SELECT count(*) FROM spike_search WHERE eq IN (NULL)").fetchone()[0]==0
        # Soft deletion does not release uniqueness in the chosen all-row profile.
        c.execute("UPDATE spike_search SET deleted=true WHERE eq=%s",(term("same"),))
    with psycopg.connect(DSN) as c:
        try:c.execute("INSERT INTO spike_search(id,tenant,eq) VALUES(5,%s,%s)",(TENANT,term("same")))
        except psycopg.errors.UniqueViolation:soft_delete="CONFLICT"
        else:raise AssertionError("Soft delete unexpectedly released uniqueness")
    with psycopg.connect(DSN) as c:
        c.execute("INSERT INTO spike_search(id,tenant,eq) SELECT g,%s,decode(md5(g::text)||md5((g+1)::text),'hex') FROM generate_series(100,10100) AS g",(TENANT,))
        c.execute("ANALYZE spike_search")
        plan=c.execute("EXPLAIN (FORMAT JSON) SELECT id FROM spike_search WHERE tenant=%s AND eq=%s",(TENANT,term("same"))).fetchone()[0]
        assert "Index" in json.dumps(plan), "No equality index plan"
        sizes=c.execute("SELECT pg_relation_size('spike_search'),pg_indexes_size('spike_search'),avg(pg_column_size(eq)) FROM spike_search").fetchone()
        # Counterexample: changing an unreturned valid term permits a logical duplicate.
        c.execute("UPDATE spike_search SET eq=%s WHERE eq=%s",(bytes(32),term("same")))
        c.execute("INSERT INTO spike_search(id,tenant,eq) VALUES(6,%s,%s)",(TENANT,term("same")))
        omission=c.execute("SELECT count(*) FROM spike_search WHERE eq=%s",(term("same"),)).fetchone()[0];assert omission==1
        version=c.execute("SELECT version()").fetchone()[0]
    return {"server":version,"race":race,"null_rows":nulls,"soft_delete":soft_delete,
            "index_plan":plan,"heap_bytes":sizes[0],"indexes_bytes":sizes[1],"mean_term_datum_bytes":str(sizes[2]),
            "hostile_term_corruption":"logical duplicate accepted; expected boundary"}


def database_protocol_cases():
    with psycopg.connect(DSN) as c:
        c.execute("DROP TABLE IF EXISTS spike_outcome,spike_mutation,spike_fence")
        c.execute("CREATE TABLE spike_fence(id int primary key, token bigint not null)")
        c.execute("INSERT INTO spike_fence VALUES(1,0)")
        c.execute("CREATE TABLE spike_mutation(id int primary key, value text)")
        c.execute("CREATE TABLE spike_outcome(operation uuid primary key, request_digest bytea not null)")
    op=uuid.UUID(int=900);digest=hashlib.sha256(b"synthetic immutable request").digest()
    with psycopg.connect(DSN) as c:
        assert c.execute("SELECT token FROM spike_fence WHERE id=1 FOR SHARE").fetchone()[0]==0
        with psycopg.connect(DSN) as other:
            try:other.execute("SELECT token FROM spike_fence WHERE id=1 FOR UPDATE NOWAIT")
            except psycopg.errors.LockNotAvailable:exclusive="BLOCKED_BY_SHARED"
            else:raise AssertionError("Exclusive mutation escaped shared fence")
        c.execute("INSERT INTO spike_mutation VALUES(1,'synthetic')")
        c.execute("INSERT INTO spike_outcome VALUES(%s,%s)",(op,digest))
        c.commit()  # Then deliberately discard application acknowledgement.
    with psycopg.connect(DSN) as c:
        c.execute("DELETE FROM spike_mutation WHERE id=1")
        assert c.execute("SELECT request_digest FROM spike_outcome WHERE operation=%s",(op,)).fetchone()[0]==digest
        c.execute("UPDATE spike_fence SET token=1 WHERE id=1")
        # The stale token is checked by PostgreSQL, not merely by local code.
        changed=c.execute("INSERT INTO spike_mutation SELECT 2,'synthetic' WHERE EXISTS (SELECT 1 FROM spike_fence WHERE id=1 AND token=%s)",(0,)).rowcount
        try:
            if changed != 1: raise StaleFenceDenied("Current database fence required")
        except StaleFenceDenied:
            stale = "TYPED_DENIAL_BEFORE_MUTATION"
        else: raise AssertionError("Stale database token accepted")
        assert c.execute("SELECT count(*) FROM spike_mutation").fetchone()[0]==0
    rollback_op=uuid.UUID(int=901)
    with psycopg.connect(DSN) as c:
        c.execute("INSERT INTO spike_mutation VALUES(3,'rolled-back')")
        c.execute("INSERT INTO spike_outcome VALUES(%s,%s)",(rollback_op,digest));c.rollback()
    with psycopg.connect(DSN) as c:
        assert c.execute("SELECT count(*) FROM spike_outcome WHERE operation=%s",(rollback_op,)).fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM spike_mutation WHERE id=3").fetchone()[0]==0
    return {"exclusive":exclusive,"outcome_after_later_delete":"COMMITTED_MARKER_RETAINED",
            "stale_database_token":stale, "rollback":"DATA_AND_MARKER_ABSENT",
            "acknowledgement_fault":"application acknowledgement discarded after commit; not an actual transport cut"}


if __name__=="__main__":
    out=Path(__file__).parent/"results";out.mkdir(exist_ok=True)
    engine=raw_engine()
    try:
        initial_data(engine);sync=sync_cases(engine);initial_data(engine);async_=asyncio.run(async_cases())
        s1={"spike":"S1","status":"PASS_LOCAL_PROTOTYPE","sync":sync,"async":async_,
            "mapping":"bootstrap public registry.dispose/map_imperatively/add_mapped_attribute",
            "publication":"single Session.info frame replacement; pending descriptor values independent",
            "limits":["one model/field and synthetic local keys", "not CPD2 or real authority",
                      "full Result/query/relationship/mapping cell not established", "not production implementation"]}
        (out/"S1.json").write_text(json.dumps(s1,indent=2)+"\n");print(json.dumps(s1,indent=2))
        s3={"spike":"S3","status":"PASS_LOCAL_POSTGRES","evidence":search_cases(),
            "limits":["one synthetic text normalizer", "not a complete differential SQL grammar oracle"]}
        (out/"S3.json").write_text(json.dumps(s3,indent=2)+"\n");print(json.dumps(s3,indent=2))
        protocol={"spike":"S2-PostgreSQL-supplement","status":"PASS_LOCAL_POSTGRES",
                  "evidence":database_protocol_cases(), "limits":["no DynamoDB or real worker termination"]}
        (out/"S2-postgres.json").write_text(json.dumps(protocol,indent=2)+"\n");print(json.dumps(protocol,indent=2))
    finally:engine.dispose()
