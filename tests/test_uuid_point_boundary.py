"""Expected UUID points must fail closed before authenticated result release."""
from types import MethodType

import pytest
from sqlalchemy import Column, MetaData, Table, Uuid, bindparam, select

from cryptalis.sqlalchemy import _points, UnsupportedProtectedOperation
from test_cf1 import RECORD


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


