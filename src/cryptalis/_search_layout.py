"""Pinned packed-search layout and native index expressions."""
from contextlib import contextmanager
from contextvars import ContextVar


_PREFIX_QUALIFICATION = ContextVar('cryptalis_prefix_qualification', default=False)


@contextmanager
def _prefix_qualification(enabled=True):
    """Internal synthetic-fixture scope; supplies no capability admission."""
    if type(enabled) is not bool:
        raise ValueError('Qualification scope requires an explicit Boolean.')
    token = _PREFIX_QUALIFICATION.set(enabled)
    try:
        yield
    finally:
        _PREFIX_QUALIFICATION.reset(token)


def require_prefix_qualification():
    if not _PREFIX_QUALIFICATION.get():
        from .crypto.keys import PrefixCapabilityUnadmitted
        raise PrefixCapabilityUnadmitted()


def prefix_plan_scope(document):
    """Keep saved preparation/activation artifacts within synthetic scope."""
    if not _PREFIX_QUALIFICATION.get():
        current = document
        while type(current) is dict:
            for name in ('lock', 'target_lock', 'profile_source_lock'):
                lock = current.get(name)
                if type(lock) is dict and lock.get('schema') == 'cryptalis.lock/v14':
                    require_prefix_qualification()
            current = current.get('source_plan')
    return document


def prefix_block_size(bounds):
    # One slot per admitted prefix length, plus the ordinary equality term.
    return 65 * (bounds[1] - bounds[0] + 2) - 1


def prefix_lengths(field):
    bounds = field['descriptor'].get('prefix_lengths')
    return None if bounds is None else (bounds['min'], bounds['max'])


def frame_overhead(field):
    bounds = prefix_lengths(field)
    return (74 if field['queries'] else 42) + (prefix_block_size(bounds) if bounds else 0)


def frame_flags(field):
    return 5 if prefix_lengths(field) else int(bool(field['queries']))


def prefix_index_expression(column, bounds):
    # The block contains only ASCII hex, commas and reserved '~' padding.
    # encode(...,'escape') preserves that alphabet and is IMMUTABLE on PG16.
    return (f"pg_catalog.string_to_array(pg_catalog.encode(pg_catalog.substring({column},47,"
            f"{prefix_block_size(bounds)}),'escape'),',') COLLATE pg_catalog.\"C\"")


def search_index_names(field):
    if not field['queries']:
        return ()
    return (field['payload_column'] + '_eq',) + ((field['payload_column'] + '_prefix',)
                                              if prefix_lengths(field) else ())


def search_index_statements(model, field, quote, table_sql, *, column=None):
    if not field['queries']:
        return ()
    payload = quote(field['payload_column'] if column is None else column)
    tenant = quote(model['tenancy']['column']) + ', ' if 'column' in model['tenancy'] else ''
    unique = 'UNIQUE ' if 'unique' in field['queries'] else ''
    equality, *prefix = search_index_names(field)
    result = [f'CREATE {unique}INDEX {quote(equality)} ON {table_sql} USING btree '
              f'({tenant}(pg_catalog.substring({payload}, 15, 32)) pg_catalog.bytea_ops)']
    if prefix:
        expression = prefix_index_expression(payload, prefix_lengths(field))
        result.append(f'CREATE INDEX {quote(prefix[0])} ON {table_sql} USING gin '
                      f'(({expression}) pg_catalog.array_ops)')
    return tuple(result)
