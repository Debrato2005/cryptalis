"""Native PostgreSQL E2E observation of Sorting-Atk on one full signed-int2 domain.

Naveed, Kamara and Wright (CCS2015), section6.1: sort distinct order ciphertexts
and the known dense plaintext domain; pair equal ranks. This synthetic experiment
deliberately misclassifies its enumerable domain after proving honest refusal.
It is neither healthy capability admission nor a customer recovery-rate estimate.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
from time import perf_counter
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
import sqlalchemy
from sqlalchemy import Column, Index, Integer, MetaData, SmallInteger, Table, Uuid, insert, select
from sqlalchemy.orm import Session, registry

from cryptalis import Project
from cryptalis.crypto import CryptoFailure, DevelopmentKeyProvider, KeyUnavailable
from cryptalis.manifest.compiler import PlanningRejected, SearchReview, Writer, WriterInventory, compile_protection
from cryptalis.migration import TransitionFailure
from test_deprotection import least_privilege_role
from test_migration import engine


DOMAIN = (-32768, 32767)
DOMAIN_SIZE = 65536
DUPLICATES = 1024
NULLS = 16
STOPPED = 'All synthetic experiment writers are stopped; only this test writes the disposable table.'
MISCLASSIFIED = 'deliberately false small-domain host attestation for public synthetic leakage experiment'
PAPER = 'https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf'
REPORT = os.environ.get('CRYPTALIS_ORDER_SORTING_REPORT')
if not REPORT:
    pytest.skip('Set CRYPTALIS_ORDER_SORTING_REPORT to a new absolute JSON path.', allow_module_level=True)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def truth_digest(rows):
    return digest(sorted((identity.hex, small, amount) for identity, small, amount in rows))


def mapping_for(schema):
    mapping = registry(metadata=MetaData(schema=schema))
    table = Table('observation', mapping.metadata,
        Column('id', Uuid, primary_key=True, autoincrement=False), Column('tenant_id', Uuid, nullable=False),
        Column('small', SmallInteger), Column('amount', Integer))
    Index('native_small', table.c.small)
    class Observation: pass
    mapping.map_imperatively(Observation, table)
    return mapping, Observation


@contextmanager
def application(tmp_path):
    owner, native = engine('CRYPTALIS_TEST_DATABASE_URL'), engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
    schema = 'cryptalis_sorting_' + uuid4().hex
    tenant, domain, table_id, small_id, amount_id = (uuid4() for _ in range(5))
    mapping, Observation = mapping_for(schema)
    provider = DevelopmentKeyProvider()
    runtimes, mappings = [native], [mapping]
    manifest = json.dumps({'schema': 'cryptalis.protection/v1', 'profile': 'cf1', 'domain_id': str(domain),
        'models': [{'model': 'Observation', 'table_id': str(table_id), 'tenancy': {'column': 'tenant_id'},
            'fields': [{'name': 'small', 'field_id': str(small_id), 'protect': True,
                        'queries': ['equality', 'order'], 'accept_leakage': ['equality', 'order']},
                       {'name': 'amount', 'field_id': str(amount_id), 'protect': True,
                        'queries': [], 'accept_leakage': []}]}]}).encode()
    writers = WriterInventory(True, (Writer(table_id, 'synthetic experiment', 'sqlalchemy', evidence=STOPPED),))
    state_dir = tmp_path / 'private-project-state'
    def process():
        current, Model = mapping_for(schema)
        runtime = engine('CRYPTALIS_TEST_RUNTIME_DATABASE_URL')
        mappings.append(current); runtimes.append(runtime)
        return SimpleNamespace(Model=Model, runtime=runtime, project=Project(manifest, current,
            provider=provider, state_dir=state_dir, writers=writers))
    try:
        with native.connect() as connection:
            role = connection.exec_driver_sql('SELECT current_user').scalar_one()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            connection.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO '
                                      + connection.dialect.identifier_preparer.quote(role))
        mapping.metadata.create_all(owner)
        with owner.begin() as connection:
            connection.exec_driver_sql(f'GRANT SELECT,INSERT,UPDATE,DELETE ON "{schema}".observation TO '
                                      + connection.dialect.identifier_preparer.quote(role))
        values = list(range(DOMAIN[0], DOMAIN[1] + 1))
        values.extend(DOMAIN[0] + secrets.randbelow(DOMAIN_SIZE) for _ in range(DUPLICATES))
        values.extend([None] * NULLS)
        secrets.SystemRandom().shuffle(values)
        rows = [{'id': uuid4(), 'tenant_id': tenant, 'small': value, 'amount': value} for value in values]
        with Session(native) as session:
            session.execute(insert(Observation), rows)
            session.commit()
        yield SimpleNamespace(owner=owner, native=native, Model=Observation, schema=schema, tenant=tenant,
            role=role, manifest=manifest, mapping=mapping, writers=writers, small_id=small_id,
            state_dir=state_dir, process=process)
    finally:
        for runtime in runtimes:
            runtime.dispose()
        with owner.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        owner.dispose()
        for current in mappings:
            current.dispose()


def native_rows(app):
    with app.native.connect() as connection:
        return list(connection.exec_driver_sql(f'SELECT id,small,amount FROM "{app.schema}".observation'))


def schema_digest(app):
    with app.owner.connect() as connection:
        columns = list(connection.exec_driver_sql('SELECT a.attname,a.atttypid::regtype::text,a.atttypmod '
            'FROM pg_catalog.pg_attribute a WHERE a.attrelid=pg_catalog.to_regclass(%s) '
            'AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum', (f'"{app.schema}".observation',)))
        relations = list(connection.exec_driver_sql('SELECT c.relname,c.relkind FROM pg_catalog.pg_class c '
            'JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s ORDER BY c.relname', (app.schema,)))
    return digest([list(map(tuple, columns)), list(map(tuple, relations))])


def snapshot(app):
    with app.owner.connect() as connection:
        rows = list(connection.exec_driver_sql(f'SELECT id,tenant_id,small,amount FROM "{app.schema}".observation'))
        sql_order = [identity.hex for identity, in connection.exec_driver_sql(
            f'SELECT id FROM "{app.schema}".observation WHERE small IS NOT NULL '
            'ORDER BY pg_catalog.substring(small,15,32),id')]
    visible, storage, generations = [], [], set()
    for identity, tenant, small, amount in rows:
        assert tenant == app.tenant
        if small is None:
            assert amount is None
            visible.append([identity.hex, None])
            continue
        frame, control = bytes(small), bytes(amount)
        assert len(frame[14:46]) == 32 and len(control) >= 42
        visible.append([identity.hex, frame[14:46].hex()])
        storage.append(control)
        generations.add(int.from_bytes(frame[10:14], 'big'))
    python_order = [identifier for identifier, term in sorted(
        ((identifier, bytes.fromhex(term)) for identifier, term in visible if term is not None),
        key=lambda pair: (pair[1], pair[0]))]
    assert digest(sql_order) == digest(python_order)
    assert len(generations) == 1
    return dict(visible=visible, storage=storage, generation=next(iter(generations)),
        snapshot_sha256=digest(sorted(visible)), native_order_sha256=digest(sql_order),
        full_public_frames_sha256=digest(sorted((identity.hex, tenant.hex,
            None if small is None else bytes(small).hex(),
            None if amount is None else bytes(amount).hex()) for identity, tenant, small, amount in rows)))


def attack(visible, tmp_path):
    payload = {'domain': list(DOMAIN), 'rows': visible}
    started = perf_counter()
    child = subprocess.run([sys.executable, '-I', '-B', '-S', str(Path(__file__).with_name('order_sorting_attacker.py'))],
        input=json.dumps(payload), text=True, encoding='utf8', capture_output=True, timeout=60,
        cwd=tmp_path, env={'PATH': os.defpath, 'LC_ALL': 'C.UTF-8'})
    assert child.returncode == 0, 'Isolated sorting attacker failed; diagnostics withheld.'
    result = json.loads(child.stdout)
    assert all(result['isolation'].values())
    result['elapsed_seconds'] = perf_counter() - started
    return result


def score(result, truth):
    guesses = dict(result['guesses'])
    expected = {identity.hex: value for identity, value, _ in truth if value is not None}
    assert result['status'] == 'APPLICABLE'
    assert len(guesses) == len(result['guesses']) == len(expected)
    assert set(guesses) == set(expected)
    recovered = sum(guesses[identity] == value for identity, value in expected.items())
    assert recovered == len(expected)
    classes = set(expected.values())
    recovered_classes = {value for identity, value in expected.items() if guesses[identity] == value}
    return {'recovered_cells': recovered, 'nonnull_scored_cells': len(expected),
            'recovery_fraction': recovered / len(expected), 'null_cells_excluded': len(truth) - len(expected),
            'recovered_distinct_values': len(recovered_classes), 'distinct_values': len(classes)}


def escaping_lease_expiry(failure):
    # Diagnostic-only inspection of the suppressed terminal cause. Keep no
    # exception/traceback references after returning; handled row retries are
    # not evidence that the escaping error was expiry.
    current, seen = failure, set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, CryptoFailure):
            return isinstance(current, KeyUnavailable) and current._lease_expired
        current = current.__cause__ or current.__context__
    return False


def verify_attached(app, expected_digest):
    process = app.process()
    with process.project.attach(process.runtime)(tenant_id=app.tenant) as session:
        observed = list(session.execute(select(process.Model.id, process.Model.small, process.Model.amount)
                                       .where(process.Model.tenant_id == app.tenant)))
    assert truth_digest(observed) == expected_digest


def test_dense_int2_published_sorting_attack_rotation_and_sparse_refusal(tmp_path, monkeypatch):
    destination = Path(REPORT)
    if not destination.is_absolute() or destination.exists():
        pytest.fail('Order sorting report requires a new absolute JSON path.', pytrace=False)
    with application(tmp_path) as app:
        truth = native_rows(app)
        expected_digest, before_schema = truth_digest(truth), schema_digest(app)
        with app.native.connect() as connection:
            native_order = [identity.hex for identity, in connection.exec_driver_sql(
                f'SELECT id FROM "{app.schema}".observation WHERE small IS NOT NULL ORDER BY small,id')]
            server = connection.exec_driver_sql('SHOW server_version').scalar_one()
        def forbidden_connection(*args, **kwargs):
            raise AssertionError('Honest enumerable-domain planning reached PostgreSQL.')
        with monkeypatch.context() as boundary, pytest.raises(PlanningRejected) as refusal:
            boundary.setattr(app.owner, 'connect', forbidden_connection)
            compile_protection(app.manifest, app.mapping, app.owner, writers=app.writers,
                search_reviews=(SearchReview(app.small_id, True, 'The full finite int2 domain is enumerable.'),))
        assert 'small_search_domain' in {issue.code for issue in refusal.value.issues}
        assert schema_digest(app) == before_schema and truth_digest(native_rows(app)) == expected_digest
        assert not app.state_dir.exists()
        assert app.process().project.protect(app.owner, runtime_role=app.role, writers_stopped=STOPPED,
            search_reviewed=MISCLASSIFIED, chunk_size=1000).phase == 'ACTIVE'
        recorded = json.loads(json.loads((app.state_dir / 'state.json').read_text())['plan'])
        review = next(item for item in recorded['lock']['search_reviews'] if item['field_id'] == str(app.small_id))
        assert review['small_domain'] is False and review['evidence'] == MISCLASSIFIED
        field = next(item for item in recorded['lock']['models'][0]['fields'] if item['field_id'] == str(app.small_id))
        assert field['descriptor']['value_codec'] == 'pg-int2-be/v1'
        assert field['representation'] == 'cf1-packed-order/v1'
        verify_attached(app, expected_digest)
        initial = snapshot(app)
        assert initial['native_order_sha256'] == digest(native_order) and initial['generation'] == 1
        initial_attack = attack(initial['visible'], tmp_path)
        initial_score = score(initial_attack, truth)
        assert initial_attack['preconditions'] == {'known_domain_distinct': DOMAIN_SIZE,
            'observed_distinct_terms': DOMAIN_SIZE, 'nonnull_cells': DOMAIN_SIZE + DUPLICATES,
            'null_cells': NULLS, 'duplicate_cells': DUPLICATES}
        control_classes = len(set(initial['storage']))
        assert control_classes > DOMAIN_SIZE
        storage_control = {'status': 'INAPPLICABLE', 'attack_attempted': False,
            'reason': 'Storage-only frames have no order representation and exceed known-domain class cardinality.',
            'observed_distinct_frames': control_classes, 'nonnull_cells': len(initial['storage']),
            'known_domain_distinct': DOMAIN_SIZE}
        rotation_recovery = {'status': 'NOT_NEEDED'}
        try:
            assert app.process().project.rotate(app.owner, 'search', writers_stopped=STOPPED).phase == 'ACTIVE'
        except TransitionFailure as failure:
            if failure.code != 'KeyUnavailable' or failure.cleanup_errors or not escaping_lease_expiry(failure):
                raise
            rotation_recovery = {'status': 'EXPIRED_LEASE_REQUIRES_INSPECTION', 'code': failure.code,
                                 'operation_id': str(failure.operation_id)}
        # Leave the exception scope before any inspection/resume: its traceback
        # can hold the unfinished scan's decoded buffers.
        if rotation_recovery['status'] != 'NOT_NEEDED':
            pending = json.loads((app.state_dir / 'state.json').read_text())['pending']
            assert pending['op'] == 'search' and pending['phase'] == 'PREPARED'
            proposal = json.loads(pending['proposal'])
            source_operation = proposal['operation_id']
            allowed_failure_operations = {source_operation}
            if pending['successor'] is not None:
                allowed_failure_operations.add(json.loads(pending['successor'])['operation_id'])
            assert rotation_recovery.pop('operation_id') in allowed_failure_operations
            inspection = app.process().project.status(app.owner)
            assert str(inspection.operation_id) == source_operation and inspection.phase == 'BACKFILLED'
            assert inspection.verification == 'NOT_PERFORMED' and inspection.committed_rows == len(truth)
            assert snapshot(app)['full_public_frames_sha256'] == initial['full_public_frames_sha256']
            assert app.process().project.rotate(app.owner, 'search', writers_stopped=STOPPED).phase == 'ACTIVE'
            active = json.loads(json.loads((app.state_dir / 'state.json').read_text())['plan'])
            assert active['search_rotation_plan_digest'] == hashlib.sha256(pending['proposal'].encode()).hexdigest()
            rotation_recovery.update(status='INSPECTED_AND_RESUMED_ONCE', phase=inspection.phase,
                                     verification=inspection.verification, public_frames_unchanged=True,
                                     same_proposal=True)
        verify_attached(app, expected_digest)
        rotated = snapshot(app)
        assert rotated['generation'] == 2 and rotated['native_order_sha256'] == digest(native_order)
        old_terms = dict(initial['visible'])
        changed = sum(old_terms[identity] != term for identity, term in rotated['visible'] if term is not None)
        assert changed == sum(term is not None for _, term in rotated['visible'])
        rotated_attack = attack(rotated['visible'], tmp_path)
        rotated_score = score(rotated_attack, truth)
        process = app.process()
        with process.project.attach(process.runtime)(tenant_id=app.tenant) as session:
            removed = list(session.scalars(select(process.Model.id).where(
                process.Model.tenant_id == app.tenant, process.Model.small == DOMAIN[0])))
            for identity in removed:
                session.delete(session.get(process.Model, identity))
            session.commit()
        assert removed
        remaining = [row for row in truth if row[1] != DOMAIN[0]]
        verify_attached(app, truth_digest(remaining))
        sparse = snapshot(app)
        sparse_attack = attack(sparse['visible'], tmp_path)
        assert sparse_attack['status'] == 'OUT_OF_SCOPE' and sparse_attack['guesses'] == []
        assert sparse_attack['preconditions']['observed_distinct_terms'] == DOMAIN_SIZE - 1
        assert app.process().project.decrypt(app.owner, plaintext_role=least_privilege_role(app),
            writers_stopped=STOPPED, accept_plaintext=True,
            retained_backups='No backups retained for the disposable synthetic experiment.').phase == 'PLAINTEXT_ACTIVE'
        assert truth_digest(native_rows(app)) == truth_digest(remaining)
        assert app.process().project.remove(app.owner, writers_stopped=STOPPED, old_workers_stopped=True,
            application_verified='Native PostgreSQL current membership and both integer columns match.').phase == 'REMOVED'
        assert truth_digest(native_rows(app)) == truth_digest(remaining)
    report = {
        'schema': 'cryptalis.order-sorting-experiment/v1',
        'scope': 'One synthetic PostgreSQL16 signed-int2 order field; no customer or other-codec estimate.',
        'source': {'paper': PAPER, 'section': '6.1', 'algorithm': 'Sorting-Atk'},
        'experimental_inputs': {'codec': 'pg-int2-be/v1', 'public_domain': list(DOMAIN),
            'domain_distinct': DOMAIN_SIZE, 'duplicate_cells': DUPLICATES, 'null_cells': NULLS,
            'placement': 'OS-random shuffle and independent random UUIDs; no public data seed',
            'provider': 'Random ephemeral DevelopmentKeyProvider; no production custody claim'},
        'admission': {'honest_small_domain_review': 'REFUSED small_search_domain',
            'experiment': MISCLASSIFIED, 'recorded_small_domain': False, 'healthy_admission': False},
        'versions': {'python': platform.python_version(), 'sqlalchemy': sqlalchemy.__version__,
                     'psycopg': psycopg.__version__, 'postgresql': server},
        'initial': {'status': initial_attack['status'], 'preconditions': initial_attack['preconditions'],
            'score': initial_score, 'snapshot_sha256': initial['snapshot_sha256'],
            'native_term_order_matches_plaintext': True, 'attacker_elapsed_seconds': initial_attack['elapsed_seconds']},
        'search_rotation': {'status': rotated_attack['status'], 'preconditions': rotated_attack['preconditions'],
            'score': rotated_score, 'changed_nonnull_terms': changed, 'search_generation': rotated['generation'],
            'snapshot_sha256': rotated['snapshot_sha256'], 'native_term_order_matches_plaintext': True,
            'attacker_elapsed_seconds': rotated_attack['elapsed_seconds'], 'recovery': rotation_recovery},
        'storage_only_control': storage_control,
        'sparse': {'status': sparse_attack['status'], 'reason': sparse_attack['reason'],
            'preconditions': sparse_attack['preconditions'], 'attack_attempted': False,
            'deleted_minimum_cells': len(removed), 'snapshot_sha256': sparse['snapshot_sha256']},
        'attacker_isolation': initial_attack['isolation'],
        'native_correctness': {'full_authenticated_reads': True, 'current_value_native_removal': True},
        'limits': ('Dense full-domain experiment only; no auxiliary-frequency or low-density attack. '
                   'The storage control shares rows and values with the order field, so it is not an independent '
                   'confidentiality control. Interpreter isolation is not an OS sandbox claim. All production gates UNKNOWN.'),
    }
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
