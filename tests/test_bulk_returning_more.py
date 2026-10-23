"""Native RETURNING recovery, projection admission and typed identity controls."""
from copy import deepcopy
import json
from uuid import UUID

import pytest
from sqlalchemy import event, insert, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, registry

from cryptalis import migration as m
from cryptalis.crypto import CryptoFailure
from cryptalis.manifest.compiler import SearchReview, Writer, WriterInventory
from test_bulk_insert import protect
from test_bulk_insert_native import assert_aborted, native_application, row
from test_bulk_returning import fresh_mapping, statement, stored_selection
from test_driver_event_boundary import raw_calls
from test_migration import application, keys, TENANT, TABLE_ID, FIELD_ID
from test_rewrap_plan import _snapshot
from test_deprotection import native_rows
from test_search_retained_readers import remove_current
from test_sqlalchemy_adapter import (app as adapter_app, db,
                                     factory as adapter_factory,
                                     TABLE_ID as ADAPTER_TABLE_ID,
                                     TENANT as ADAPTER_TENANT)


@pytest.mark.parametrize('fault,varchar,expected_code', [
    ('unique', False, '23505'),
    ('duplicate_before_length', True, '23505'),
    ('length_before_duplicate', True, '22001'),
])
def test_returning_savepoint_failure_precedence_and_healthy_retry_match_native(
        fault, varchar, expected_code):
    with native_application(varchar) as app:
        if fault == 'unique':
            inputs = [row(1001, 'dupe', label='same group'), row(1002, 'dupe', label='same group')]
        else:
            duplicate = row(100, 'good', label='first shape')
            overlength = row(1001, 'abcde')
            inputs = ([duplicate, overlength] if fault == 'duplicate_before_length'
                      else [overlength, duplicate])
        original = deepcopy(inputs)

        def scenario(session, protected):
            assert session.execute(statement(app, True), [row(1000, 'keep', label='outer')]).scalars().all() == ['keep']
            savepoint = session.begin_nested()
            error_type = CryptoFailure if protected and expected_code == '22001' else DBAPIError
            with pytest.raises(error_type) as failed:
                session.execute(statement(app, False), inputs)
            assert getattr(getattr(failed.value, 'orig', failed.value), 'sqlstate', None) == expected_code
            assert len(session.identity_map) == 0
            assert_aborted(session)
            savepoint.rollback()
            assert [tuple(value) for value in session.execute(stored_selection(app))] == [
                (UUID(int=1000), TENANT, 'keep', 'outer')]
            retry = session.execute(statement(app, True), [row(1003, 'done', label='after savepoint')])
            assert retry.scalars().all() == ['done']
            final = [tuple(value) for value in session.execute(stored_selection(app))]
            assert len(session.identity_map) == 0
            session.commit() if protected else session.rollback()
            return final

        with Session(app.runtime) as session:
            expected = scenario(session, False)
        with fresh_mapping(app):
            factory = protect(app)
            with factory(tenant_id=TENANT) as session:
                assert scenario(session, True) == expected
            with factory(tenant_id=TENANT) as session:
                assert [tuple(value) for value in session.execute(stored_selection(app))] == expected
        assert inputs == original


@pytest.mark.parametrize('fault', ['alias', 'defaults_pk_alias', 'nonboolean_sort'])
def test_late_returning_grammar_change_refuses_before_raw_insert_and_retries(fault, monkeypatch):
    with native_application(False) as app:
        factory = protect(app)
        inputs = [row(1000, 'first', label='public')]
        original, before, injected = deepcopy(inputs), _snapshot(app), []

        def change(connection, current, multiparams, params, execution_options):
            if getattr(current, 'is_insert', False):
                injected.append(True)
                alias = app.table.alias('public_returning_alias')
                if fault == 'alias':
                    current = insert(app.Customer).returning(alias.c.name)
                elif fault == 'defaults_pk_alias':
                    current = insert(app.Customer).return_defaults(
                        alias.c.id, supplemental_cols=[app.Customer.name])
                else:
                    current = current._generate()
                    current._sort_by_parameter_order = 1
            return current, multiparams, params

        event.listen(app.runtime, 'before_execute', change, retval=True)
        try:
            with raw_calls(monkeypatch, app.schema, 'INSERT') as sent:
                with factory(tenant_id=TENANT) as session:
                    with pytest.raises(CryptoFailure):
                        session.execute(statement(app, False), inputs)
                    session.rollback()
                assert injected and sent == []
        finally:
            event.remove(app.runtime, 'before_execute', change)
        assert inputs == original and _snapshot(app) == before
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, True), inputs).scalars().all() == ['first']
            session.commit()


@pytest.mark.parametrize('adapter_app', [{'bigint': True, 'single_tenant': True}], indirect=True)
def test_returning_single_tenant_signed_int64_extremes_keep_native_scalar_results(adapter_app):
    app = adapter_app
    old_mapping, old_customer = app.mapping, app.Customer
    identities = [-2**63, -1, 0, 2**63 - 1]
    rows = [dict(id=identity, tenant_id=ADAPTER_TENANT, name=f'public {index}', rank=index,
                 note=['雪😀', None, '', 'e\u0301'][index], secret=f'other {index}')
            for index, identity in enumerate(identities)]
    original = deepcopy(rows)
    # The adapter fixture admits its compiled single-tenant table UUID.
    with adapter_factory(app, False)(tenant_id=ADAPTER_TABLE_ID) as session:
        result = session.execute(insert(app.Customer).returning(app.Customer.note,
            sort_by_parameter_order=True), rows, execution_options={'render_nulls': True})
        assert tuple(result.keys()) == ('note',)
        expected = result.scalars().all()
        assert len(session.identity_map) == 0
        session.rollback()
    mapping = registry(metadata=old_mapping.metadata)
    class Customer:
        pass
    mapping.map_imperatively(Customer, old_customer.__table__)
    app.mapping, app.Customer = mapping, Customer
    try:
        with adapter_factory(app, True)(tenant_id=ADAPTER_TABLE_ID) as session:
            result = session.execute(insert(Customer).returning(Customer.note,
                sort_by_parameter_order=True), rows, execution_options={'render_nulls': True})
            assert tuple(result.keys()) == ('note',)
            assert result.scalars().all() == expected == ['雪😀', None, '', 'e\u0301']
            assert len(session.identity_map) == 0
            session.commit()
    finally:
        app.mapping, app.Customer = old_mapping, old_customer
        mapping.dispose()
    assert rows == original


def test_returning_single_tenant_renamed_attribute_matches_native_scalar_key():
    with application(rows=3, unique=False, queries=['equality']) as app:
        original_mapping, original_customer = app.mapping, app.Customer

        def renamed_mapping():
            mapping = registry(metadata=app.table.metadata)
            class Customer:
                pass
            mapping.map_imperatively(Customer, app.table, properties={
                'record': app.table.c.id, 'scope': app.table.c.tenant_id,
                'value': app.table.c.name, 'public': app.table.c.label})
            return mapping, Customer

        native_mapping, NativeCustomer = renamed_mapping()
        inputs = [dict(record=UUID(int=1000), scope=TENANT, value='first', public='renamed'),
                  dict(record=UUID(int=1001), scope=TENANT, value=None, public=None)]
        original = deepcopy(inputs)
        try:
            with Session(app.runtime) as session:
                result = session.execute(insert(NativeCustomer).returning(NativeCustomer.value,
                    sort_by_parameter_order=True), inputs, execution_options={'render_nulls': True})
                expected_keys, expected = tuple(result.keys()), result.scalars().all()
                assert len(session.identity_map) == 0
                session.rollback()
        finally:
            native_mapping.dispose()
        mapping, Customer = renamed_mapping()
        app.mapping, app.Customer = mapping, Customer
        try:
            declaration = json.loads(json.dumps(app.plan.document['lock']['declaration']))
            declaration['models'][0]['tenancy'] = {'single_tenant': True}
            declaration['models'][0]['fields'][0]['name'] = 'value'
            app.plan = m.plan(json.dumps(declaration).encode(), mapping, app.owner,
                writers=WriterInventory(True, (Writer(TABLE_ID, 'app', 'sqlalchemy',
                    evidence='native renamed single-tenant RETURNING fixture'),)),
                search_reviews=(SearchReview(FIELD_ID, False, 'public synthetic values'),),
                keys=keys, runtime_role=app.role, target_id=app.plan.target_id,
                backfill_rows_per_second=1000, verify_rows_per_second=1000,
                temporary_bytes_per_row=700, wal_bytes_per_row=2000)
            app.pin = m.DeploymentPin(app.plan.target_id, app.plan.operation_id, app.plan.digest, 'PREPARED')
            factory = protect(app)
            with factory(tenant_id=TABLE_ID) as session:
                result = session.execute(insert(Customer).returning(Customer.value,
                    sort_by_parameter_order=True), inputs, execution_options={'render_nulls': True})
                assert tuple(result.keys()) == expected_keys == ('value',)
                assert result.scalars().all() == expected == ['first', None]
                assert len(session.identity_map) == 0
                session.commit()
        finally:
            app.mapping, app.Customer = original_mapping, original_customer
            mapping.dispose()
        assert inputs == original


@pytest.mark.parametrize('varchar', [False, True], ids=['text', 'varchar'])
def test_returning_insert_and_later_edit_survive_native_current_value_removal(varchar):
    with native_application(varchar) as app:
        factory = protect(app)
        inputs = [row(1000, 'first' if not varchar else 'one'), row(1001, None)]
        with factory(tenant_id=TENANT) as session:
            assert session.execute(statement(app, True), inputs,
                execution_options={'render_nulls': True}).scalars().all() == [inputs[0]['name'], None]
            session.commit()
            session.get(app.Customer, UUID(int=1000)).name = 'late'
            session.commit()
        remove_current(app, keys)
        assert native_rows(app) == {
            **app.source, UUID(int=1000): (TENANT, 'late'), UUID(int=1001): (TENANT, None)}
