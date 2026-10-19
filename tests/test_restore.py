"""Restore adoption authority evidence for cryptalis.restore/v1.

The fresh-cluster module proves the adopted lifecycle. This module proves the
current-deployment refusal on the primary test cluster and the structural
validation of binding artifacts.
"""
from dataclasses import replace
import hashlib
import json
from uuid import uuid4

import pytest

import cryptalis.migration as m
import cryptalis.restore as restore
from cryptalis.manifest.compiler import _canonical
from test_migration import application, keys, publish, run


def binding_bytes(**changes):
    document = {
        'format': 'cryptalis.restore/v1', 'kind': 'restore', 'adoption_id': str(uuid4()),
        'source': {'operation_id': str(uuid4()), 'plan_digest': 'a' * 64,
                   'target': ['source_db', '10', '127.0.0.1', 5432, 'owner']},
        'target': ['restored_db', '20', '127.0.0.1', 5433, 'owner'],
        'journal_state_digest': 'b' * 64, 'custody': {'tenant': 'c' * 64}, 'restatements': [],
        'environment': {'server_version': '16.15', 'system_identifier': None},
        'approval': {'host': 'operator', 'intent': 'adopt restored copy', 'quarantine': 'source fenced',
                     'source_fenced': True, 'adopted_at': '2026-10-19T00:00:00+00:00'}}
    document.update(changes)
    return _canonical(document)


def test_binding_artifacts_reject_structural_tampering():
    assert restore.RestoreBinding(binding_bytes()).document['kind'] == 'restore'
    assert restore.RestoreBinding(binding_bytes()).target == ['restored_db', '20', '127.0.0.1', 5433, 'owner']
    definition = 'CHECK ((name IS NULL) OR (octet_length(name) >= 74))'
    restatement = {'model': str(uuid4()), 'kind': 'constraints', 'name': '_cryptalis_ab_frame',
                   'recorded_digest': 'd' * 64, 'definition': definition,
                   'observed_digest': hashlib.sha256(_canonical(definition)).hexdigest(),
                   'probe': 'rejected-malformed-frames'}
    assert restore.RestoreBinding(binding_bytes(restatements=[restatement])).document['restatements'] == [
        restatement]
    for bad in (binding_bytes(approval={**json.loads(binding_bytes())['approval'], 'source_fenced': False}),
                binding_bytes(target=['source_db', '10', '127.0.0.1', 5432, 'owner']),
                binding_bytes(journal_state_digest='b'),
                binding_bytes(extra='unexpected'),
                binding_bytes(restatements=[{**restatement, 'observed_digest': 'e' * 64}]),
                binding_bytes(restatements=[{**restatement, 'recorded_digest': restatement['observed_digest']}]),
                binding_bytes(restatements=[{**restatement, 'name': 'native_name'}]),
                binding_bytes(restatements=[{**restatement, 'probe': 'assumed-equal'}]),
                json.dumps(json.loads(binding_bytes()), indent=2).encode()):
        with pytest.raises(m.TransitionFailure, match='invalid_restore_binding'):
            restore.RestoreBinding(bad)


def test_adoption_refuses_current_deployment_and_requires_fenced_approval():
    with application() as app:
        run(app)
        publish(app)
        good = restore.RestoreApproval('operator', 'adopt restored copy', 'source fenced and quarantined', True)
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            restore.plan(app.plan, app.owner, pin=app.pin, keys=keys, approval=None)
        with pytest.raises(m.TransitionFailure, match='restore_approval_required'):
            restore.plan(app.plan, app.owner, pin=app.pin, keys=keys, approval=replace(good, quarantine=' '))
        with pytest.raises(m.TransitionFailure, match='restore_source_is_current'):
            restore.plan(app.plan, app.owner, pin=app.pin, keys=keys, approval=good)
