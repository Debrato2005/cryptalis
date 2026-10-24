"""Explicit public-slot layout selection is immutable and fails closed."""
import json
from uuid import UUID

import pytest
from sqlalchemy import Boolean, String

from cryptalis import migration as m
from cryptalis.manifest.compiler import (
    PlanningRejected, SearchReview, Writer, WriterInventory, compile_protection,
)
from cryptalis.manifest.parser import ManifestInvalid
from test_migration import application
from test_owned_sequences import _snapshot, install_sequence, next_value
from test_public_slots import original_gap


LAYOUT = 'preserve-public-slots/v1'


def compile_app(app, **options):
    lock = app.plan.document['lock']
    writers = WriterInventory(lock['writer_inventory']['complete'], tuple(
        Writer(**{key: item[key] for key in ('table_id', 'name', 'route', 'excluded', 'evidence')})
        for item in (dict(item, table_id=UUID(item['table_id']))
                     for item in lock['writer_inventory']['writers'])))
    reviews = tuple(SearchReview(UUID(item['field_id']), item['small_domain'], item['evidence'])
                    for item in lock['search_reviews'])
    return compile_protection(m._canonical(lock['declaration']), app.mapping, app.owner,
                              writers=writers, search_reviews=reviews, **options)


@pytest.mark.parametrize('kind,legacy', [('text', 'v2'), ('varchar', 'v3'), ('boolean', 'v4'), ('sequence', 'v5')])
def test_explicit_layout_keeps_legacy_bytes_and_accepts_all_native_families(kind, legacy):
    options = {}
    if kind == 'varchar': options['value_type'] = String(64, collation='C')
    elif kind == 'boolean': options.update(value_type=Boolean(), queries=[], rows=3, protected_values=(None, True, False))
    elif kind == 'sequence': options['setup'] = install_sequence
    with application(**options) as app:
        before = _snapshot(app)
        assert compile_app(app).lock_bytes == compile_app(app, layout=None).lock_bytes == app.plan.lock_bytes
        assert app.plan.document['lock']['schema'] == 'cryptalis.lock/' + legacy
        selected = compile_app(app, layout=LAYOUT)
        lock = json.loads(selected.lock_bytes)
        assert lock['schema'] == 'cryptalis.lock/v6' and lock['layout'] == LAYOUT
        assert all('owned_sequences' in model['source_metadata'] for model in lock['models'])
        assert bool(lock['models'][0]['source_metadata']['owned_sequences']) is (kind == 'sequence')
        transition = app.plan.document
        transition['lock'] = lock
        assert m.MigrationPlan(m._canonical(transition)).document['lock'] == lock
        assert compile_app(app, layout=LAYOUT, previous_lock=selected.lock_bytes).changes == ()
        assert _snapshot(app) == before
        if kind == 'sequence': assert next_value(app) == 101


def test_invalid_layout_is_rejected_before_connection_or_input_inspection():
    class Token(str): pass
    class Closed:
        def connect(self): pytest.fail('invalid layout reached connection')
    for layout in ('', 'unknown', 'preserve-public-slots/v2', b'preserve-public-slots/v1',
                   False, True, 0, [], {}, Token(LAYOUT)):
        with pytest.raises(PlanningRejected) as caught:
            compile_protection(b'invalid declaration must remain unread', None, Closed(),
                               writers=WriterInventory(True, ()), layout=layout)
        assert [(issue.code, issue.location) for issue in caught.value.issues] == [('unsupported_layout', 'layout')]
        assert caught.value.effects == 'NONE'


def test_v6_prior_requires_exact_layout_metadata_and_positive_ordered_distinct_slots():
    def setup(connection, schema, role): original_gap(connection, schema, role, sequence=False)
    with application(setup=setup) as app:
        selected = compile_app(app, layout=LAYOUT)
        valid = json.loads(selected.lock_bytes)
        assert [column['attnum'] for column in valid['models'][0]['source_schema']['columns']] == [1, 2, 4, 5]
        assert compile_app(app, layout=LAYOUT, previous_lock=selected.lock_bytes).changes == ()
        before = _snapshot(app)
        for fault in ('missing_layout', 'unknown_layout', 'layout_type', 'downgrade', 'missing_sequences',
                      'extra', 'duplicate_slot', 'zero_slot', 'oversized_slot', 'boolean_slot', 'unordered_slots'):
            lock = json.loads(selected.lock_bytes)
            columns = lock['models'][0]['source_schema']['columns']
            if fault == 'missing_layout': lock.pop('layout')
            elif fault == 'unknown_layout': lock['layout'] = 'unknown/v1'
            elif fault == 'layout_type': lock['layout'] = None
            elif fault == 'downgrade': lock['schema'] = 'cryptalis.lock/v5'
            elif fault == 'missing_sequences': lock['models'][0]['source_metadata'].pop('owned_sequences')
            elif fault == 'extra': lock['unrecognized'] = True
            elif fault == 'duplicate_slot': columns[1]['attnum'] = columns[0]['attnum']
            elif fault == 'zero_slot': columns[0]['attnum'] = 0
            elif fault == 'oversized_slot': columns[-1]['attnum'] = 32768
            elif fault == 'boolean_slot': columns[0]['attnum'] = True
            else: columns.reverse()
            with pytest.raises(ManifestInvalid):
                compile_app(app, layout=LAYOUT, previous_lock=m._canonical(lock))
            transition = app.plan.document
            transition['lock'] = lock
            with pytest.raises(m.TransitionFailure): m.MigrationPlan(m._canonical(transition))
            assert _snapshot(app) == before


def test_previous_layout_is_comparison_evidence_and_never_implicit_opt_in():
    with application() as app:
        legacy = compile_app(app)
        selected = compile_app(app, layout=LAYOUT, previous_lock=legacy.lock_bytes)
        assert [change.kind for change in selected.changes] == ['layout_changed']
        assert selected.source_lock_digest == legacy.lock_digest
        implicit = compile_app(app, previous_lock=selected.lock_bytes)
        assert implicit.lock_bytes == legacy.lock_bytes
        assert [change.kind for change in implicit.changes] == ['layout_changed']
        assert implicit.source_lock_digest == selected.lock_digest
        assert 'layout' not in json.loads(implicit.lock_bytes)
