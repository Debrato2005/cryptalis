"""Exact optional SQLModel AutoString contract for PostgreSQL."""

from types import MethodType

from sqlalchemy import String
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import TypeDecorator

try:
    from sqlmodel import __version__ as _version
    from sqlmodel.sql.sqltypes import AutoString as _AutoString
except ModuleNotFoundError as error:
    if error.name != 'sqlmodel':
        raise
    _AutoString = None
    _version = None


_LOAD = _AutoString.load_dialect_impl if _AutoString is not None else None
_METHODS = {
    name: getattr(TypeDecorator, name)
    for name in ('adapt', 'dialect_impl', 'type_engine', 'copy', 'bind_expression',
                 'column_expression', 'bind_processor', 'result_processor',
                 'literal_processor', 'process_bind_param', 'process_result_value',
                 'process_literal_param', 'coerce_compared_value', 'compare_values')
}
_STRING_METHODS = {name: getattr(String, name) for name in (
    'adapt', 'dialect_impl', 'bind_expression', 'column_expression',
    'bind_processor', 'result_processor', 'literal_processor', '_compiler_dispatch')}


def autostring_impl(dtype):
    """Return the native String implementation, or reject a changed contract."""
    if _AutoString is None or not isinstance(dtype, _AutoString):
        return None
    if (type(dtype) is not _AutoString or _version != '0.0.48' or
            _AutoString.impl is not String or _AutoString.cache_ok is not True or
            type(dtype.mysql_default_length) is not int or dtype.mysql_default_length != 255 or
            dtype.cache_ok is not True or
            dtype._variant_mapping or dtype._has_bind_expression or dtype._has_column_expression):
        raise ValueError('Unsupported SQLModel AutoString contract')
    for name, expected in dict(_METHODS, load_dialect_impl=_LOAD,
                               _compiler_dispatch=TypeDecorator._original_compiler_dispatch).items():
        method = getattr(dtype, name)
        if (type(method) is not MethodType or method.__self__ is not dtype or
                method.__func__ is not expected):
            raise ValueError('Unsupported SQLModel AutoString hook')
    impl = dtype.impl_instance
    if (type(impl) is not String or dtype.impl is not impl or
            impl._variant_mapping or impl._has_bind_expression or impl._has_column_expression or
            impl.length is not None and (type(impl.length) is not int or impl.length < 1) or
            impl.collation is not None and type(impl.collation) is not str or
            dtype.load_dialect_impl(postgresql.dialect()) is not impl):
        raise ValueError('Unsupported SQLModel AutoString implementation')
    for name, expected in _STRING_METHODS.items():
        method = getattr(impl, name)
        if (type(method) is not MethodType or method.__self__ is not impl or
                method.__func__ is not expected):
            raise ValueError('Unsupported SQLModel String hook')
    return impl
