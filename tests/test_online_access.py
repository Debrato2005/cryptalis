"""Offline hostile-artifact checks for the online access boundary."""
from copy import deepcopy
from dataclasses import replace
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cryptalis import migration as m


MODELS = [{'table_id': '00000000-0000-0000-0000-000000000001',
           'schema': 'public', 'table': 'items',
           'source_schema': {'columns': [{'name': 'id'}, {'name': 'value'}]}}]


def contract():
    def grants(role, privileges):
        return [dict(grantor='owner', grantee=role, privilege=p, grantable=False)
                for p in privileges]
    owner = grants('owner', ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'))
    crud = ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
    return dict(format='cryptalis.access/v1', owner='owner', source_role='native', target_role='encrypted',
                tables={MODELS[0]['table_id']: dict(schema='public', table='items',
                    native=sorted(owner + grants('native', crud), key=m._canonical),
                    encrypted=sorted(owner + grants('encrypted', crud), key=m._canonical),
                    columns={'id': [], 'value': []})})


def test_access_contract_requires_exact_reversible_role_transfer():
    from cryptalis import _access_contract as access
    valid = contract()
    access.validate(valid, MODELS, 'owner', 'encrypted')
    mutations = []
    for side in ('native', 'encrypted'):
        for field, value in (('grantor', 'delegate'), ('grantee', 'PUBLIC'), ('grantable', True)):
            bad = deepcopy(valid)
            bad['tables'][MODELS[0]['table_id']][side][0][field] = value
            mutations.append(bad)
        bad = deepcopy(valid)
        bad['tables'][MODELS[0]['table_id']][side].pop()
        mutations.append(bad)
    bad = deepcopy(valid)
    bad['tables'][MODELS[0]['table_id']]['columns']['value'] = ['native|w|false']
    mutations.append(bad)
    bad = deepcopy(valid)
    bad['source_role'] = 'encrypted'
    mutations.append(bad)
    bad = deepcopy(valid)
    bad['tables'][MODELS[0]['table_id']]['columns'].pop('id')
    mutations.append(bad)
    for bad in mutations:
        with pytest.raises(m.TransitionFailure, match='invalid_access_contract'):
            access.validate(bad, MODELS, 'owner', 'encrypted')


def test_access_contract_cannot_change_owner_or_runtime_authority():
    from cryptalis import _access_contract as access
    for owner, role in (('other', 'encrypted'), ('owner', 'native')):
        with pytest.raises(m.TransitionFailure, match='invalid_access_contract'):
            access.validate(contract(), MODELS, owner, role)


def test_native_grant_transfer_is_atomic_and_fences_existing_connections():
    """Real grants, separate logins, rollback, stale writer denial, and reversal."""
    from cryptalis import _access_contract as access
    from sqlalchemy.exc import DBAPIError
    from test_migration import application, engine

    if not os.environ.get('CRYPTALIS_TEST_SOURCE_URL'):
        pytest.skip('requires mandatory --source-role probe and a third private test URL')
    target_engine = engine('CRYPTALIS_TEST_SOURCE_URL')
    try:
        with application(queries=[]) as app:
            models = app.plan.document['lock']['models']
            with target_engine.connect() as target:
                target_role = target.exec_driver_sql('SELECT current_user').scalar_one()
                target.commit()
                with app.owner.begin() as c:
                    c.exec_driver_sql(f'GRANT USAGE ON SCHEMA {m._quote(c, app.schema)} TO {m._quote(c, target_role)}')
                    policy = access.plan(c, models, owner=app.plan.document['target'][-1],
                                         source_role=app.role, target_role=target_role)
                document = app.plan.document
                document.update(access_contract=policy, runtime_role=target_role)
                context = SimpleNamespace(document=document, operation_id=app.plan.operation_id)
                with app.runtime.connect() as native:
                    table = m._table(native, models[0])
                    native.exec_driver_sql(f'SELECT id FROM {table} LIMIT 1').first()
                    native.commit()
                    with pytest.raises(RuntimeError, match='cancel grant transfer'):
                        with app.owner.begin() as c:
                            access.transfer(c, context)
                            raise RuntimeError('cancel grant transfer')
                    with app.owner.connect() as c:
                        access.check(c, context, plaintext=True)
                    with app.owner.begin() as c:
                        access.transfer(c, context)
                    with pytest.raises(DBAPIError):
                        native.exec_driver_sql(f'UPDATE {table} SET label=%s', ('stale writer',))
                    native.rollback()
                    target.exec_driver_sql(f'UPDATE {table} SET label=%s', ('current target write',))
                    target.commit()
                    with app.owner.begin() as c:
                        access.transfer(c, context, plaintext=True)
                    with pytest.raises(DBAPIError):
                        target.exec_driver_sql(f'UPDATE {table} SET label=%s', ('stale encrypted writer',))
                    target.rollback()
                    assert set(native.exec_driver_sql(f'SELECT label FROM {table}').scalars()) == {'current target write'}
                    native.rollback()
                    with app.owner.begin() as c:
                        c.exec_driver_sql(f'GRANT SELECT ON {table} TO PUBLIC')
                    with app.owner.connect() as c:
                        with pytest.raises(m.TransitionFailure, match='access_contract_changed'):
                            access.check(c, context, plaintext=True)
    finally:
        target_engine.dispose()


def test_online_activation_artifact_cannot_enter_maintenance_expansion():
    from cryptalis import _access_contract as access
    from test_migration import application, keys

    with application(queries=[]) as app:
        document = app.plan.document
        models = document['lock']['models']
        source_role = 'public_fixture_native_role'
        owner, target = document['target'][-1], document['runtime_role']
        policy = dict(format=access.FORMAT, owner=owner, source_role=source_role, target_role=target,
            tables={model['table_id']: dict(schema=model['schema'], table=model['table'],
                native=access._grants(owner, source_role), encrypted=access._grants(owner, target),
                columns={column['name']: [] for column in model['source_schema']['columns']}) for model in models})
        preparation = {'operation_id': str(uuid4()), 'plan_digest': 'a' * 64}
        with app.owner.connect() as c:
            observations = {model['table_id']: m._scope(c, model) for model in models}
        document.update(format='cryptalis.transition/v8', access_contract=policy,
            online_preparation=preparation, predecessors=[preparation],
            online_verification={table: {'rows': value['count'], 'membership': value['membership'], 'frames': 'b' * 64}
                                 for table, value in observations.items()})
        online = m.MigrationPlan(m._canonical(document))
        pin = replace(app.pin, plan_digest=online.digest)
        with pytest.raises(m.TransitionFailure, match='online_executor_required'):
            m.apply(online, None, keys=keys, pin=pin, approval=app.approval)
        with pytest.raises(m.TransitionFailure, match='missing_online_successor'):
            m.apply(online, app.owner, keys=keys, pin=replace(pin, phase='ACTIVATING'),
                    approval=app.approval, until='ACTIVE')
        for mutate in ('old_format', 'extra_ancestor', 'wrong_scope', 'changed_grants'):
            bad = deepcopy(document)
            if mutate == 'old_format': bad['format'] = 'cryptalis.transition/v1'
            elif mutate == 'extra_ancestor': bad['predecessors'].append({'operation_id': str(uuid4()), 'plan_digest': 'c' * 64})
            elif mutate == 'wrong_scope': bad['online_verification'][models[0]['table_id']]['rows'] += 1
            else: bad['access_contract']['source_role'] = target
            with pytest.raises(m.TransitionFailure, match='invalid_plan'):
                m.MigrationPlan(m._canonical(bad))
