"""Finite native SELECT functions and explicit PostgreSQL resolution.

This is an admission table, not a claim that arbitrary SQL functions are pure.
Special SQL expressions retain their native syntax. Ordinary function calls
resolve in pg_catalog instead of the connection's mutable search_path.
"""
from sqlalchemy.sql import functions
from sqlalchemy.sql.annotation import annotated_classes


_CALLS = frozenset({
    'abs', 'avg', 'array_agg', 'bit_length', 'btrim', 'char_length',
    'concat', 'concat_ws', 'count', 'date_part', 'date_trunc', 'dense_rank',
    'encode', 'first_value', 'floor', 'jsonb_build_array', 'lag', 'last_value',
    'lead', 'length', 'lower', 'ltrim', 'max', 'md5', 'min', 'mode',
    'now', 'octet_length', 'pg_backend_pid', 'pg_sleep', 'rank', 'replace',
    'reverse', 'round', 'row_number', 'rtrim', 'split_part', 'stddev',
    'string_agg', 'substr', 'substring', 'sum', 'upper', 'varchar',
})
_SYNTAX = frozenset({'coalesce', 'nullif', 'greatest', 'least',
                     'current_date', 'current_time', 'current_timestamp',
                     'localtime', 'localtimestamp'})
_CLASSES = frozenset((functions.Function, functions.count, functions.sum,
                      functions.min, functions.max, functions.array_agg,
                      functions.mode, functions.coalesce, functions.char_length,
                      functions.concat, functions.rank, functions.dense_rank,
                      functions.now, functions.current_date, functions.current_time,
                      functions.current_timestamp, functions.localtime,
                      functions.localtimestamp))
_BY_TYPE = {native: native for native in _CLASSES}
_BY_TYPE.update({annotated_classes[native]: native for native in _CLASSES
                 if native in annotated_classes})


def admit_function(node, validate, error):
    """Validate native dispatch and return whether catalog qualification is needed."""
    native = _BY_TYPE.get(type(node))
    if native is None:
        native = next((candidate for candidate in _CLASSES
                       if type(node) is annotated_classes.get(candidate)), None)
    if native is None:
        raise error()
    original = validate(node, native)
    name, packages = node.name, node.packagenames
    if (type(name) is not str or type(packages) is not tuple
            or name != original.name or packages != original.packagenames
            or packages not in ((), ('pg_catalog',))):
        raise error()
    if name in _SYNTAX:
        if packages:
            raise error()
        return False
    if name not in _CALLS:
        raise error()
    return True
