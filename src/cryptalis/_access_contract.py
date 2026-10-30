"""Exact reversible table grants for the bounded online protection profile.

The host artifact supplies authority. Catalog observations only check it.
These helpers never commit or provision roles.
"""
from copy import deepcopy

from cryptalis import migration as m


FORMAT = 'cryptalis.access/v1'
CRUD = ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
OWNER = CRUD + ('TRUNCATE', 'REFERENCES', 'TRIGGER')
SUCCESSOR_FORMATS = {
    ('rewrap', False): 'cryptalis.transition/v9',
    ('payload_rotation', False): 'cryptalis.transition/v10',
    ('search_rotation', False): 'cryptalis.transition/v11',
    ('rewrap', True): 'cryptalis.transition/v12',
    ('payload_rotation', True): 'cryptalis.transition/v13',
    ('search_rotation', True): 'cryptalis.transition/v14',
    ('tenant_provision', False): 'cryptalis.transition/v15',
    ('tenant_provision', True): 'cryptalis.transition/v16',
    ('profile_rotation', False): 'cryptalis.transition/v18',
}


def _grants(owner, role):
    entries = [dict(grantor=owner, grantee=owner, privilege=p, grantable=False) for p in OWNER]
    entries += [dict(grantor=owner, grantee=role, privilege=p, grantable=False) for p in CRUD]
    return sorted(entries, key=m._canonical)


def validate(contract, models, owner, runtime_role):
    """Reject any grant layout outside the exact direct-CRUD profile."""
    try:
        if (type(contract) is not dict or set(contract) != {
                'format', 'owner', 'source_role', 'target_role', 'tables'}
                or contract['format'] != FORMAT or contract['owner'] != owner
                or contract['target_role'] != runtime_role):
            raise ValueError
        roles = [contract[k] for k in ('owner', 'source_role', 'target_role')]
        if (any(type(role) is not str or not role or '\x00' in role or role == 'PUBLIC' for role in roles)
                or len(set(roles)) != 3):
            raise ValueError
        tables = contract['tables']
        if type(tables) is not dict or set(tables) != {model['table_id'] for model in models}:
            raise ValueError
        for model in models:
            item = tables[model['table_id']]
            columns = {column['name']: [] for column in model['source_schema']['columns']}
            if (type(item) is not dict or set(item) != {'schema', 'table', 'native', 'encrypted', 'columns'}
                    or (item['schema'], item['table']) != (model['schema'], model['table'])
                    or item['columns'] != columns
                    or item['native'] != _grants(owner, contract['source_role'])
                    or item['encrypted'] != _grants(owner, runtime_role)):
                raise ValueError
            # bool compares equal to 0/1. Compare canonical bytes as well.
            for side, role in (('native', contract['source_role']), ('encrypted', runtime_role)):
                if m._canonical(item[side]) != m._canonical(_grants(owner, role)):
                    raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise m.TransitionFailure('invalid_access_contract') from None


def inspect(c, models):
    """Read complete table grants and all live column grants."""
    result = {}
    for model in models:
        table = m._table(c, model)
        grants = c.exec_driver_sql('''SELECT pg_catalog.pg_get_userbyid(x.grantor),
            CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(x.grantee) END,
            x.privilege_type, x.is_grantable
            FROM pg_catalog.pg_class t CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(t.relacl,pg_catalog.acldefault('r',t.relowner))) x
            WHERE t.oid=pg_catalog.to_regclass(%s)''', (table,)).all()
        columns = c.exec_driver_sql('''SELECT a.attname, a.attacl IS NOT NULL AND pg_catalog.cardinality(a.attacl)>0
            FROM pg_catalog.pg_attribute a WHERE a.attrelid=pg_catalog.to_regclass(%s)
            AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum''', (table,)).all()
        if not grants or not columns:
            raise m.TransitionFailure('access_contract_table_missing')
        if any(has_acl for _, has_acl in columns):
            raise m.TransitionFailure('online_column_grants_unsupported')
        result[model['table_id']] = dict(schema=model['schema'], table=model['table'],
            grants=sorted((dict(grantor=a, grantee=b, privilege=d, grantable=e)
                           for a, b, d, e in grants), key=m._canonical),
            columns={name: [] for name, _ in columns})
    return result


def _roles(c, contract, models, operation_id=None, journal=None):
    owner, source, target = (contract[key] for key in ('owner', 'source_role', 'target_role'))
    for role in (source, target):
        m._runtime_safety(c, role, owner, models, journal=journal, operation_id=operation_id)
        if not c.exec_driver_sql('SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=%s',
                                 (role,)).scalar_one():
            raise m.TransitionFailure('online_runtime_login_required', operation_id)
        for schema in sorted({model['schema'] for model in models}):
            if not c.exec_driver_sql("SELECT pg_catalog.has_schema_privilege(%s,%s,'USAGE')",
                                     (role, schema)).scalar_one():
                raise m.TransitionFailure('online_schema_usage_required', operation_id)
        # A NOINHERIT membership can still allow SET ROLE. Refuse all parents.
        if c.exec_driver_sql('''SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members a
            JOIN pg_catalog.pg_roles r ON r.oid=a.member WHERE r.rolname=%s)''', (role,)).scalar_one():
            raise m.TransitionFailure('online_role_membership_unsupported', operation_id)
    for left, right in ((owner, source), (owner, target), (source, target), (target, source)):
        if c.exec_driver_sql("SELECT pg_catalog.pg_has_role(%s,%s,'MEMBER')", (left, right)).scalar_one():
            raise m.TransitionFailure('online_role_membership_unsupported', operation_id)


def _check(c, contract, models, *, plaintext, operation_id=None, journal=None):
    validate(contract, models, contract['owner'], contract['target_role'])
    _roles(c, contract, models, operation_id, journal)
    observed = inspect(c, models)
    side = 'native' if plaintext else 'encrypted'
    allowed = contract['source_role' if plaintext else 'target_role']
    denied = contract['target_role' if plaintext else 'source_role']
    for model in models:
        expected, actual = contract['tables'][model['table_id']], observed[model['table_id']]
        if (actual['grants'] != expected[side]
                or not set(expected['columns']) <= set(actual['columns'])):
            raise m.TransitionFailure('access_contract_changed', operation_id)
        table = m._table(c, model)
        for privilege in CRUD:
            if not c.exec_driver_sql('SELECT pg_catalog.has_table_privilege(%s,%s,%s)',
                                     (allowed, table, privilege)).scalar_one():
                raise m.TransitionFailure('online_writer_privilege_missing', operation_id)
            if c.exec_driver_sql('SELECT pg_catalog.has_table_privilege(%s,%s,%s)',
                                 (denied, table, privilege)).scalar_one():
                raise m.TransitionFailure('online_writer_fence_failed', operation_id)
        if c.exec_driver_sql("SELECT pg_catalog.has_any_column_privilege(%s,%s,'SELECT,INSERT,UPDATE,REFERENCES')",
                             (denied, table)).scalar_one():
            raise m.TransitionFailure('online_writer_fence_failed', operation_id)


def plan(c, models, *, owner, source_role, target_role, operation_id=None):
    observed = inspect(c, models)
    contract = dict(format=FORMAT, owner=owner, source_role=source_role, target_role=target_role,
        tables={model['table_id']: dict(schema=model['schema'], table=model['table'],
            native=observed[model['table_id']]['grants'], encrypted=_grants(owner, target_role),
            columns=observed[model['table_id']]['columns']) for model in models})
    validate(contract, models, owner, target_role)
    _check(c, contract, models, plaintext=True, operation_id=operation_id)
    return contract


def get(p):
    document = p.document
    return document.get('access_contract', document.get('source_plan', {}).get('access_contract'))


def check(c, p, *, plaintext=False):
    contract = get(p)
    if contract is not None:
        _check(c, contract, p.document['lock']['models'], plaintext=plaintext,
               operation_id=p.operation_id, journal=m._journal(c, p))


def transfer(c, p, *, plaintext=False):
    """Change only admitted grants inside the caller's locked transaction."""
    contract = get(p)
    if contract is None:
        return
    if c.exec_driver_sql('SELECT current_user').scalar_one() != contract['owner']:
        raise m.TransitionFailure('maintenance_requires_planned_owner', p.operation_id)
    check(c, p, plaintext=not plaintext)
    old = contract['target_role' if plaintext else 'source_role']
    new = contract['source_role' if plaintext else 'target_role']
    for model in p.document['lock']['models']:
        table = m._table(c, model)
        c.exec_driver_sql(f'REVOKE SELECT, INSERT, UPDATE, DELETE ON {table} FROM {m._quote(c, old)}')
        c.exec_driver_sql(f'GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {m._quote(c, new)}')
    check(c, p, plaintext=plaintext)


def carry(source, document):
    """Carry the exact source contract into an explicitly versioned successor."""
    contract = source.document.get('access_contract')
    if contract is None:
        return
    existing = document.get('access_contract')
    if existing is not None and existing != contract:
        raise m.TransitionFailure('access_contract_successor_mismatch', source.operation_id)
    document['access_contract'] = deepcopy(contract)
    document.pop('online_preparation', None)
    document.pop('online_verification', None)
    document['format'] = SUCCESSOR_FORMATS[(document['kind'], bool(document.get('restore_lineage')))]
