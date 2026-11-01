"""Native application and authenticated PostgreSQL boundaries for JSONB admission."""
from contextlib import contextmanager
from copy import deepcopy
from decimal import Decimal
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import psycopg
from psycopg.types.json import set_json_loads
import pytest
from sqlalchemy import ColumnDefault, DefaultClause, Numeric, Text, create_engine, event, func, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from cryptalis import migration as m
from cryptalis._search_layout import _prefix_qualification
from cryptalis.application import ApplicationConfig
from cryptalis.crypto import AuthenticationFailed, RepresentationMismatch
from cryptalis.crypto.keys import PrefixCapabilityUnadmitted
from cryptalis.manifest.compiler import PlanningRejected, SearchReview, Writer, WriterInventory, compile_protection
from cryptalis.sqlalchemy import PolicyMismatch, attach
from test_application_modification import prepare, propose, seal
from test_deprotection import app_pin
from test_jsonb_storage import application, mapping_for, protect, wire
from test_migration import (DOMAIN, FIELD_ID, TABLE_ID, TENANT, PublicFixtureProvider,
                            application as scalar_application, engine, independent_open, keys, publish, run)


def inventory():
    return WriterInventory(True, (Writer(TABLE_ID, 'JSONB admission application', 'sqlalchemy',
        evidence='Disposable native application; no external writer.'),))


def plan(app, *, declaration=None, database=None, resolver=keys):
    declaration = app.declaration if declaration is None else declaration
    reviews = tuple(SearchReview(UUID(field['field_id']), False,
        'Public synthetic input domain; this review supplies no capability admission.')
        for model in declaration['models'] for field in model['fields'] if field['queries'])
    return m.plan(json.dumps(declaration).encode(), app.mapping, database or app.owner,
        writers=inventory(), search_reviews=reviews, keys=resolver, runtime_role=app.role,
        target_id=uuid4(), backfill_rows_per_second=1000, verify_rows_per_second=1000,
        temporary_bytes_per_row=16384, wal_bytes_per_row=32768)


def database_state(app, *, native=True):
    with app.owner.connect() as connection:
        value = 'pg_catalog.jsonb_send(name)' if native else 'name'
        rows = connection.exec_driver_sql(
            f'SELECT id,tenant_id,{value},label FROM "{app.schema}".customer ORDER BY id').all()
        columns = connection.exec_driver_sql('''
            SELECT a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,
                   pg_catalog.pg_get_expr(d.adbin,d.adrelid)
            FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
            JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
            WHERE n.nspname=%s AND c.relname='customer' AND a.attnum>0 AND NOT a.attisdropped
            ORDER BY a.attnum
        ''', (app.schema,)).all()
        relations = connection.exec_driver_sql('''
            SELECT c.relname,c.relkind::text,
                   CASE WHEN c.relkind='i' THEN pg_catalog.pg_get_indexdef(c.oid) END
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=%s ORDER BY c.relname
        ''', (app.schema,)).all()
        routines = connection.exec_driver_sql('''
            SELECT p.proname,p.prokind::text,pg_catalog.pg_get_function_identity_arguments(p.oid)
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=%s ORDER BY p.proname,p.oid
        ''', (app.schema,)).all()
    return rows, columns, relations, routines


def refused_without_effects(app, code, *, declaration=None, database=None):
    before, calls = database_state(app), []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError('Refused native JSONB planning reached key preparation.')
    with pytest.raises(PlanningRejected) as failure:
        plan(app, declaration=declaration, database=database, resolver=forbidden)
    assert code in {issue.code for issue in failure.value.issues}
    assert failure.value.effects == 'NONE'
    assert all(issue.remedy for issue in failure.value.issues)
    assert calls == []
    assert database_state(app) == before


def test_jsonb_planning_refuses_unadmitted_search_generated_defaults_indexes_and_nonstandard_mapping_without_effects():
    with application() as app:
        original = wire(app)
        searchable = deepcopy(app.declaration)
        searchable['models'][0]['fields'][0].update(queries=['order'], accept_leakage=['equality', 'order'])
        refused_without_effects(app, 'unsupported_query', declaration=searchable)

        column = app.table.c.name
        column.default = ColumnDefault(lambda: {'client': 'default'})
        try:
            refused_without_effects(app, 'protected_default')
        finally:
            column.default = None

        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer '
                "ALTER COLUMN name SET DEFAULT '{}'::jsonb")
        column.server_default = DefaultClause(text("'{}'::jsonb"))
        try:
            refused_without_effects(app, 'protected_default')
        finally:
            column.server_default = None
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer ALTER COLUMN name DROP DEFAULT')

        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE INDEX native_document ON "{app.schema}".customer USING gin(name)')
        try:
            refused_without_effects(app, 'unsupported_index')
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'DROP INDEX "{app.schema}".native_document')

        original_type = column.type
        column.type = JSONB().with_variant(JSONB(), 'postgresql')
        try:
            refused_without_effects(app, 'unsupported_type')
        finally:
            column.type = original_type
        original_type.none_as_null = 1
        try:
            refused_without_effects(app, 'unsupported_type')
        finally:
            original_type.none_as_null = False
        assert wire(app) == original
        assert all(not row[0].startswith('_cryptalis') for row in database_state(app)[2])


def test_jsonb_compiler_refuses_custom_global_engine_and_connection_json_hooks(monkeypatch):
    with application() as app:
        before, reached = database_state(app), []
        def forbidden(*args, **kwargs):
            reached.append(True)
            raise AssertionError('Unadmitted JSON hook reached SQL or key preparation.')
        def custom_loads(value):
            return json.loads(value)

        set_json_loads(custom_loads)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(Engine, 'connect', forbidden)
                with pytest.raises(PlanningRejected) as failure:
                    plan(app, resolver=forbidden)
                assert {issue.code for issue in failure.value.issues} == {'unsupported_mapping'}
        finally:
            set_json_loads(json.loads)
        assert reached == []

        configured = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL']),
            json_deserializer=custom_loads)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(Engine, 'connect', forbidden)
                with pytest.raises(PlanningRejected) as failure:
                    plan(app, database=configured, resolver=forbidden)
                assert {issue.code for issue in failure.value.issues} == {'unsupported_mapping'}
        finally:
            configured.dispose()
        assert reached == []

        checkouts, executed = [], []
        def customize(connection, record, proxy):
            set_json_loads(custom_loads, connection)
            checkouts.append(True)
        def observe(*args):
            executed.append(True)
        event.listen(app.owner, 'checkout', customize)
        event.listen(app.owner, 'before_cursor_execute', observe)
        try:
            with pytest.raises(PlanningRejected) as failure:
                plan(app, resolver=forbidden)
            assert {issue.code for issue in failure.value.issues} == {'unsupported_mapping'}
            assert checkouts and executed == [] and reached == []
        finally:
            event.remove(app.owner, 'checkout', customize)
            event.remove(app.owner, 'before_cursor_execute', observe)
            app.owner.dispose()  # Discard the deliberately customized connection.
        assert database_state(app) == before


def test_jsonb_pinned_null_mode_and_retained_mapping_drift_refuse_before_keys_or_effects(monkeypatch):
    with application() as app:
        protect(app)
        before, calls = database_state(app, native=False), []
        def resolve(tenant):
            calls.append(True)
            return keys(tenant)
        for mode in (True, False):
            mapping, table, Customer = mapping_for(app.schema, mode)
            runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
            try:
                if mode:
                    with pytest.raises(PolicyMismatch):
                        attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolve,
                               deployment=(app.plan, app.pin))
                    assert calls == []
                    continue
                native_type = table.c.name.type
                factory = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolve,
                                 deployment=(app.plan, app.pin))
                with factory(tenant_id=TENANT) as session:
                    assert session.get(Customer, UUID(int=103)).name is None
                count = len(calls)
                native_type.none_as_null = True
                def forbidden(*args, **kwargs):
                    raise AssertionError('Changed JSONB NULL policy reached SQL.')
                with monkeypatch.context() as patch:
                    patch.setattr(Engine, 'connect', forbidden)
                    with pytest.raises(PolicyMismatch):
                        factory(tenant_id=TENANT)
                assert len(calls) == count
                native_type.none_as_null = False
                with factory(tenant_id=TENANT) as session:
                    assert session.get(Customer, UUID(int=100)).name['b'] == 1.0
            finally:
                runtime.dispose()
                mapping.dispose()
        assert database_state(app, native=False) == before


@contextmanager
def substituted(app, identity, replacement):
    with app.owner.begin() as connection:
        original = connection.exec_driver_sql(f'SELECT name FROM "{app.schema}".customer WHERE id=%s',
            (identity,)).scalar_one()
        connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                  (replacement, identity))
    try:
        yield
    finally:
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET name=%s WHERE id=%s',
                                      (original, identity))


def authenticated_payload(original, descriptor, identity, payload):
    """Independent existing CF1/HKDF/AEAD path, using public fixture roots only."""
    def pack(*parts):
        return len(parts).to_bytes(4, 'big') + b''.join(len(part).to_bytes(4, 'big') + part for part in parts)
    wrapper = next(wrapper for wrapper in keys(TENANT).policy.wrappers if wrapper.context.purpose == 'payload')
    context = wrapper.context
    root = PublicFixtureProvider().unwrap(wrapper, context)
    salt = hashlib.sha256(pack(b'CF1/root', DOMAIN.bytes, TENANT.bytes, context.root_id.bytes,
                               context.generation.to_bytes(4, 'big'))).digest()
    prk = hmac.digest(salt, root, 'sha256')
    key = hmac.digest(prk, pack(b'CF1/payload-key', FIELD_ID.bytes, identity.bytes) + b'\x01', 'sha256')
    header, nonce = original[:14], os.urandom(12)
    digest = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).digest()
    aad = pack(b'CF1/payload', DOMAIN.bytes, TENANT.bytes, FIELD_ID.bytes, identity.bytes, digest, header)
    return header + nonce + AESGCMSIV(key).encrypt(nonce, payload, aad)


def test_jsonb_sql_null_visibility_and_authenticated_value_canonicalization():
    with application() as app:
        with Session(app.runtime) as session:
            nulls = session.scalars(select(app.Customer.id).where(app.Customer.name.is_(None))
                                   .order_by(app.Customer.id)).all()
            count = session.scalar(select(func.count(app.Customer.name)))
        factory = protect(app)
        before = database_state(app, native=False)
        with factory(tenant_id=TENANT) as session:
            assert session.scalars(select(app.Customer.id).where(app.Customer.name.is_(None))
                                   .order_by(app.Customer.id)).all() == nulls
            assert session.scalar(select(func.count(app.Customer.name))) == count
            assert session.get(app.Customer, UUID(int=103)).name is None
            assert session.get(app.Customer, UUID(int=104)).name is None
        with app.owner.connect() as connection:
            original = bytes(connection.exec_driver_sql(
                f'SELECT name FROM "{app.schema}".customer WHERE id=%s', (UUID(int=100),)).scalar_one())
            assert connection.exec_driver_sql(f'SELECT name IS NULL FROM "{app.schema}".customer '
                'WHERE id=%s', (UUID(int=103),)).scalar_one() is False
        # SQL NULL substitution remains the documented unauthenticated-presence limit.
        with substituted(app, UUID(int=103), None), factory(tenant_id=TENANT) as session:
            assert session.get(app.Customer, UUID(int=103)).name is None
            assert session.scalar(select(func.count(app.Customer.name))) == count - 1
            assert UUID(int=103) in session.scalars(select(app.Customer.id)
                .where(app.Customer.name.is_(None))).all()
        corrupt = original[:-1] + bytes((original[-1] ^ 1,))
        for identity, replacement in ((UUID(int=100), corrupt), (UUID(int=101), original)):
            with substituted(app, identity, replacement), factory(tenant_id=TENANT) as session:
                with pytest.raises(AuthenticationFailed):
                    session.get(app.Customer, identity)
        descriptor = app.plan.document['lock']['models'][0]['fields'][0]['descriptor']
        noncanonical = b'{"longer_key": 1, "a": 2}'
        with app.owner.connect() as connection:
            canonical = bytes(connection.exec_driver_sql(
                "SELECT pg_catalog.convert_to((%s::jsonb)::text,'UTF8')", (noncanonical.decode(),)).scalar_one())
        assert canonical != noncanonical
        for payload, valid in ((canonical, True), (noncanonical, False)):
            body = authenticated_payload(original, descriptor, UUID(int=100), payload)
            assert independent_open(body, descriptor, TENANT, UUID(int=100), return_bytes=True) == payload
            with substituted(app, UUID(int=100), body), factory(tenant_id=TENANT) as session:
                if valid:
                    assert session.get(app.Customer, UUID(int=100)).name == json.loads(canonical)
                else:
                    with pytest.raises(RepresentationMismatch):
                        session.get(app.Customer, UUID(int=100))
        assert database_state(app, native=False) == before


def test_retained_v14_reader_accepts_text_and_numeric_and_refuses_jsonb_before_sql(tmp_path):
    reader = os.environ.get('CRYPTALIS_JSONB_PREVIOUS_READER_PYTHON')
    if not reader:
        pytest.skip('supply the retained installed v14 reader interpreter')
    assert Path(reader).is_absolute() and Path(reader).is_file()
    artifacts = []
    for kind, dtype, values, queries in (
        ('text', Text(collation='C'), ('ordinary text', None), []),
        ('numeric', Numeric(), (Decimal('1.2300'), None), ['equality']),
    ):
        with scalar_application(rows=2, value_type=dtype, protected_values=values, queries=queries,
                                unique=False) as app:
            artifact = tmp_path / (kind + '.json')
            artifact.write_bytes(app.plan.artifact)
            artifacts.append(str(artifact))
    with application() as app:
        artifact = tmp_path / 'jsonb.json'
        artifact.write_bytes(plan(app).artifact)
        artifacts.append(str(artifact))
    child = subprocess.run([reader, '-B', '-I', '-c', '''
from pathlib import Path
import sys
from sqlalchemy.engine import Engine
attempted = []
def forbidden(*args, **kwargs):
    attempted.append(True)
    raise AssertionError('historical reader attempted SQL')
Engine.connect = forbidden
from cryptalis.migration import MigrationPlan, TransitionFailure
for index, artifact in enumerate(sys.argv[1:]):
    try:
        MigrationPlan(Path(artifact).read_bytes()).document
    except TransitionFailure as failure:
        assert index == 2 and failure.code == 'invalid_plan'
    else:
        assert index < 2
assert attempted == []
print('v14 text/numeric controls accepted; JSONB refused before SQL')
''', *artifacts], capture_output=True, text=True, timeout=30,
        env={'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8'})
    assert child.returncode == 0, 'retained reader boundary failed; diagnostics withheld'
    assert child.stdout.strip() == 'v14 text/numeric controls accepted; JSONB refused before SQL'


def test_mixed_jsonb_prefix_and_retained_pattern_successor_stay_internal_before_sql(monkeypatch):
    with application() as app:
        prefix_id = UUID(int=506)
        app.table.c.label.type = Text(collation='C')
        with app.owner.begin() as connection:
            connection.exec_driver_sql(f'ALTER TABLE "{app.schema}".customer '
                'ALTER COLUMN label TYPE text COLLATE "C" USING label')
            connection.exec_driver_sql(f'UPDATE "{app.schema}".customer SET label=\'public label \' || id::text')
            connection.exec_driver_sql(f'CREATE INDEX native_label_pattern ON "{app.schema}".customer '
                                       '(label text_pattern_ops)')
        app.declaration['models'][0]['fields'].append({'name': 'label', 'field_id': str(prefix_id),
            'protect': True, 'queries': ['equality', 'prefix'], 'accept_leakage': ['equality', 'prefix'],
            'prefix_lengths': {'min': 1, 'max': 16}})
        with _prefix_qualification():
            app.plan = plan(app)
            assert app.plan.document['lock']['schema'] == 'cryptalis.lock/v15'
            app.pin = app_pin(app.plan, 'PREPARED')
            run(app); publish(app)
            target = deepcopy(app.declaration)
            field = next(field for field in target['models'][0]['fields'] if field['name'] == 'label')
            field.update(queries=[], accept_leakage=[])
            del field['prefix_lengths']
            configured = ApplicationConfig(json.dumps(target).encode(), app.mapping, inventory())
            modification = propose(configured, app)
            prepare(configured, app, modification)
            successor = seal(configured, app, modification)
            source_artifact, source_lock = app.plan.artifact, app.plan.lock_bytes
            target_artifact, target_lock = successor.artifact, successor.lock_bytes
            retained = successor.document['lock']
            assert retained['schema'] == 'cryptalis.lock/v15'
            assert 'pg-text-pattern-index/v1' in retained['required_readers']
            assert 'pg-text-prefix/v1' not in retained['required_readers']
            assert not any('prefix' in field['queries'] for model in retained['models'] for field in model['fields'])
        before, reached = database_state(app, native=False), []
        def forbidden(*args, **kwargs):
            reached.append(True)
            raise AssertionError('Mixed unadmitted prefix plan reached SQL or keys.')
        with _prefix_qualification(False), monkeypatch.context() as patch:
            patch.setattr(Engine, 'connect', forbidden)
            for action in (
                lambda: m.MigrationPlan(source_artifact),
                lambda: m.MigrationPlan(target_artifact),
                lambda: attach(app.mapping, app.runtime, lock=source_lock, keys=forbidden),
                lambda: attach(app.mapping, app.runtime, lock=target_lock, keys=forbidden),
                lambda: compile_protection(json.dumps(target).encode(), app.mapping, app.owner,
                    writers=inventory(), previous_lock=target_lock),
            ):
                with pytest.raises(PrefixCapabilityUnadmitted):
                    action()
        assert reached == []
        assert database_state(app, native=False) == before


def test_jsonb_modification_pins_null_mode_before_sql_then_preserves_current_native_wire(monkeypatch):
    from test_application_modification import activate_change, propose
    from test_jsonb_lifecycle import jsonb_application, native_wire, protected_wire
    from test_jsonb_storage import remove

    with jsonb_application(none_as_null=False) as app:
        # Both flags are valid native mappings; they have different None writes.
        for mode in (False, True):
            mapping, _, Customer = mapping_for(app.schema, mode)
            try:
                with Session(app.runtime) as session:
                    session.get(Customer, UUID(int=100)).name = None
                    session.flush()
                    assert native_wire(app, connection=session.connection())[UUID(int=100)] == (
                        (True, None) if mode else (False, b'\x01null'))
                    session.rollback()
            finally:
                mapping.dispose()
        expected = native_wire(app)
        native_type = app.table.c.name.type
        assert native_type.none_as_null is False
        run(app); publish(app)

        lock = app.plan.document['lock']
        declaration = deepcopy(lock['declaration'])
        label = next(field for field in declaration['models'][0]['fields'] if field['name'] == 'label')
        assert label['queries'] == ['equality']
        label.update(queries=[], accept_leakage=[])
        writers = WriterInventory(lock['writer_inventory']['complete'], tuple(
            Writer(UUID(writer['table_id']), writer['name'], writer['route'], writer['excluded'], writer['evidence'])
            for writer in lock['writer_inventory']['writers']))
        configured = ApplicationConfig(json.dumps(declaration).encode(), app.mapping, writers)
        before, reached = database_state(app, native=False), []
        def no_sql(*args, **kwargs):
            reached.append('sql')
            raise AssertionError('Changed JSONB null mode reached SQL before modification admission.')
        def no_keys(*args, **kwargs):
            reached.append('keys')
            raise AssertionError('Changed JSONB null mode reached key preparation.')
        native_type.none_as_null = True
        try:
            with monkeypatch.context() as patch:
                patch.setattr(Engine, 'connect', no_sql)
                with pytest.raises(m.TransitionFailure) as failure:
                    configured.plan_modification(app.owner, deployment=(app.plan, app.pin), keys=no_keys,
                        backfill_rows_per_second=1000, verify_rows_per_second=1000,
                        temporary_bytes_per_row=16384, wal_bytes_per_row=32768, max_batch_rows=2)
                assert failure.value.code == 'modification_mapping_mismatch'
                assert reached == []
        finally:
            native_type.none_as_null = False
        assert database_state(app, native=False) == before

        # Restoring the pinned flag permits the same real text-profile transition.
        modification = propose(configured, app)
        activate_change(configured, app, modification)
        assert protected_wire(app, keys) == expected
        factory = attach(app.mapping, app.runtime, lock=app.plan.lock_bytes, keys=keys,
                         deployment=(app.plan, app.pin))
        with factory(tenant_id=TENANT) as session:
            # Editing another protected field must not round these JSON numbers.
            session.get(app.Customer, UUID(int=301)).label = 'current label after modification'
            session.commit()
        assert protected_wire(app, keys) == expected
        remove(app)
        assert native_wire(app) == expected


def test_jsonb_compiler_checks_native_prospective_cursor_json_hooks_before_inspection_sql():
    # An unchanged connection map does not establish a cursor factory's loaders.
    with application() as app:
        armed, loaded, constructed = [False], [], []
        def custom_loads(value):
            loaded.append(True)
            return json.loads(value)
        class CustomCursor(psycopg.Cursor):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                if armed[0]:
                    set_json_loads(custom_loads, self)
                    constructed.append(True)
        configured = create_engine('postgresql+psycopg://', hide_parameters=True,
            creator=lambda: psycopg.connect(os.environ['CRYPTALIS_TEST_DATABASE_URL'],
                                           cursor_factory=CustomCursor))
        try:
            # Initialize the ordinary dialect before arming the cursor callback.
            with configured.connect() as connection:
                assert connection.exec_driver_sql('SELECT 1').scalar_one() == 1
            armed[0] = True
            configured.dispose()
            with configured.connect() as connection:
                assert connection.exec_driver_sql("SELECT '{\"cursor\":true}'::jsonb").scalar_one() == {'cursor': True}
            assert loaded and constructed
            configured.dispose()

            before, inspected, prepared = database_state(app), [], []
            def observe(*args):
                inspected.append(True)
            def no_keys(*args, **kwargs):
                prepared.append(True)
                raise AssertionError('Custom JSON cursor reached key preparation.')
            event.listen(configured, 'before_cursor_execute', observe)
            try:
                with pytest.raises(PlanningRejected) as failure:
                    plan(app, database=configured, resolver=no_keys)
                assert {issue.code for issue in failure.value.issues} == {'unsupported_mapping'}
                assert failure.value.effects == 'NONE'
                assert inspected == [] and prepared == []
            finally:
                event.remove(configured, 'before_cursor_execute', observe)
            assert database_state(app) == before
        finally:
            configured.dispose()


def test_jsonb_native_comparison_hooks_refuse_and_retained_type_hooks_cannot_drift(monkeypatch):
    from types import MethodType
    from sqlalchemy import Column, MetaData, Table, Uuid
    from sqlalchemy.orm import registry
    from test_jsonb_storage import BASE

    def native_mapping(schema, dtype):
        mapping = registry(metadata=MetaData(schema=schema))
        table = Table('customer', mapping.metadata,
            Column('id', Uuid, primary_key=True, autoincrement=False),
            Column('tenant_id', Uuid, nullable=False), Column('name', dtype), Column('label', Text))
        class Customer: pass
        mapping.map_imperatively(Customer, table)
        return mapping, table, Customer

    def customize(dtype, kind, calls):
        if kind == 'compare_values':
            def compare(self, left, right):
                calls.append(kind)
                return True
            dtype.compare_values = MethodType(compare, dtype)
        elif kind == 'coerce_compared_value':
            def coerce(self, operation, value):
                calls.append(kind)
                return self
            dtype.coerce_compared_value = MethodType(coerce, dtype)
        else:
            class NativeComparator(JSONB.Comparator):
                def is_(self, other):
                    calls.append(kind)
                    return super().is_(other)
            dtype.comparator_factory = NativeComparator

    with application() as app:
        original_wire = wire(app)
        original_mapping = app.mapping
        for kind in ('compare_values', 'coerce_compared_value', 'comparator_factory'):
            calls, dtype = [], JSONB()
            customize(dtype, kind, calls)
            mapping, _, Customer = native_mapping(app.schema, dtype)
            try:
                with Session(app.runtime) as session:
                    if kind == 'compare_values':
                        row = session.get(Customer, UUID(int=100))
                        row.name = {'changed': 'native comparison suppresses this update'}
                        session.flush()
                        session.refresh(row)
                        assert row.name == BASE
                    elif kind == 'coerce_compared_value':
                        assert UUID(int=100) in session.scalars(
                            select(Customer.id).where(Customer.name == deepcopy(BASE))).all()
                    else:
                        assert session.scalars(select(Customer.id).where(Customer.name.is_(None))
                            .order_by(Customer.id)).all() == sorted(
                                identity for identity, (sql_null, _) in original_wire.items() if sql_null)
                    session.rollback()
                assert calls, 'the native application must exercise its configured hook'
                app.mapping = mapping
                refused_without_effects(app, 'unsupported_type')
            finally:
                app.mapping = original_mapping
                mapping.dispose()
        assert wire(app) == original_wire

        protect(app)
        before, preparations = database_state(app, native=False), []
        def resolve(tenant):
            preparations.append(True)
            return keys(tenant)
        dtype = JSONB()
        mapping, _, Customer = native_mapping(app.schema, dtype)
        runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        try:
            factory = attach(mapping, runtime, lock=app.plan.lock_bytes, keys=resolve,
                             deployment=(app.plan, app.pin))
            with factory(tenant_id=TENANT) as session:
                assert session.get(Customer, UUID(int=100)).name == BASE
            for kind in ('compare_values', 'coerce_compared_value', 'comparator_factory'):
                called, reached = [], []
                customize(dtype, kind, called)
                count = len(preparations)
                def no_sql(*args, **kwargs):
                    reached.append(True)
                    raise AssertionError('Changed retained JSONB comparison hook reached SQL.')
                try:
                    with monkeypatch.context() as patch:
                        patch.setattr(Engine, 'connect', no_sql)
                        with pytest.raises(PolicyMismatch):
                            factory(tenant_id=TENANT)
                    assert len(preparations) == count and reached == [] and called == []
                finally:
                    delattr(dtype, kind)
            with factory(tenant_id=TENANT) as session:
                assert session.get(Customer, UUID(int=100)).name == BASE
        finally:
            runtime.dispose()
            mapping.dispose()
        assert database_state(app, native=False) == before
