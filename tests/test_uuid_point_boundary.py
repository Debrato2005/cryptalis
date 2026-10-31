"""Expected UUID points must fail closed before authenticated result release."""
from types import MethodType, SimpleNamespace

import pytest
from sqlalchemy import Column, MetaData, Table, Uuid, bindparam, select

from cryptalis.crypto import AuthenticationFailed, seal_value
from cryptalis.sqlalchemy import _Operation, _points, _ReadText, UnsupportedProtectedOperation
from test_cf1 import descriptor, setup_keys, TENANT, RECORD


@pytest.mark.parametrize('bad', ['bad', 'urn:uuid:' + str(RECORD), ' ' + str(RECORD),
    str(RECORD) + ' ', '-' + RECORD.hex, '\uff10' + RECORD.hex[1:], 7])
@pytest.mark.parametrize('expanding', [False, True])
def test_invalid_uuid_point_refuses_real_frame_and_outer_join_null(bad, expanding):
    table = Table('public_fixture', MetaData(), Column('id', Uuid, primary_key=True))
    value = [str(RECORD), bad] if expanding else bad
    bound = bindparam('point', value, type_=Uuid(), expanding=expanding)
    predicate = table.c.id.in_(bound) if expanding else table.c.id == bound
    points = _points(select(table.c.id).where(predicate), {})
    field = descriptor()
    _, ring = setup_keys()
    prepared = ring.prepare()
    frame = seal_value('PUBLIC native UUID point', field, TENANT, RECORD, prepared)
    binding = SimpleNamespace(descriptor=field, max_characters=None)
    operation = _Operation(None, prepared, TENANT, None, points=points)
    processor = _ReadText(binding, operation, table.c.id)
    for transport in ([frame.hex(), str(RECORD), str(TENANT)], [None, None, None]):
        with pytest.raises(AuthenticationFailed):
            processor.process_result_value(transport, None)
    valid = _points(select(table.c.id).where(table.c.id == str(RECORD)), {})
    operation.points = valid
    assert _ReadText(binding, operation, table.c.id).process_result_value(
        [frame.hex(), str(RECORD), str(TENANT)], None) == 'PUBLIC native UUID point'
    empty = _points(select(table.c.id).where(table.c.id.in_([])), {})
    operation.points = empty
    assert _ReadText(binding, operation, table.c.id).process_result_value([None, None, None], None) is None


@pytest.mark.parametrize('mode', ['as_uuid', 'native_uuid', 'bind_processor', 'result_processor',
    'wrong_bound_bind', 'wrong_bound_result', 'proxy_bind', 'proxy_result', 'same_key_flags'])
def test_uuid_text_bind_with_changed_native_contract_refuses(mode):
    table = Table('public_fixture', MetaData(), Column('id', Uuid, primary_key=True))
    dtype = Uuid()
    if mode in ('as_uuid', 'native_uuid'):
        setattr(dtype, mode, False)
    elif mode.startswith('wrong_bound'):
        name = 'bind_processor' if mode.endswith('bind') else 'result_processor'
        setattr(dtype, name, MethodType(getattr(Uuid, name), Uuid(native_uuid=False)))
    elif mode.startswith('proxy'):
        name = 'bind_processor' if mode.endswith('bind') else 'result_processor'
        class ProcessorProxy:
            @property
            def __func__(self):
                return getattr(Uuid, name)
            def __call__(self, dialect):
                return lambda value: value
        setattr(dtype, name, ProcessorProxy())
    elif mode != 'same_key_flags':
        setattr(dtype, mode, lambda dialect: lambda value: value)
    statement = select(table.c.id).where(table.c.id == bindparam('point', str(RECORD), type_=dtype))
    parameters = {}
    if mode == 'same_key_flags':
        statement = statement.where(table.c.id == bindparam('point', type_=Uuid(as_uuid=False)))
        parameters = {'point': str(RECORD)}
    with pytest.raises(UnsupportedProtectedOperation):
        _points(statement, parameters)


def test_boolean_identity_stays_unadmitted_and_null_cannot_authorize_a_real_row():
    table = Table('public_fixture', MetaData(), Column('id', Uuid, primary_key=True))
    with pytest.raises(UnsupportedProtectedOperation):
        _points(select(table.c.id).where(table.c.id == bindparam('point', True, type_=Uuid())), {})
    statement = select(table.c.id).where(table.c.id == bindparam('point', None, type_=Uuid()))
    _, ring = setup_keys()
    prepared, field = ring.prepare(), descriptor()
    frame = seal_value('PUBLIC NULL point refusal', field, TENANT, RECORD, prepared)
    operation = _Operation(None, prepared, TENANT, None, points=_points(statement, {}))
    processor = _ReadText(SimpleNamespace(descriptor=field, max_characters=None), operation, table.c.id)
    with pytest.raises(AuthenticationFailed):
        processor.process_result_value([frame.hex(), str(RECORD), str(TENANT)], None)
