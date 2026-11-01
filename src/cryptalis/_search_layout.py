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


def requires_prefix_scope(lock):
    """Recognize internal prefix facts, including mixed newer lock versions."""
    if type(lock) is not dict:
        return False
    if lock.get('schema') == 'cryptalis.lock/v14':
        return True
    readers = lock.get('required_readers')
    if type(readers) in (list, tuple) and any(
            reader in ('pg-text-prefix/v1', 'pg-text-pattern-index/v1') for reader in readers):
        return True
    for document in (lock, lock.get('declaration')):
        if type(document) is not dict or type(document.get('models')) is not list:
            continue
        for model in document['models']:
            if type(model) is not dict or type(model.get('fields')) is not list:
                continue
            protected = set()
            for field in model['fields']:
                if type(field) is not dict:
                    continue
                if type(field.get('column')) is str:
                    protected.add(field['column'])
                descriptor = field.get('descriptor')
                queries = field.get('queries')
                if ('prefix_lengths' in field or field.get('representation') == 'cf1-packed-prefix/v1'
                        or type(queries) in (list, tuple) and 'prefix' in queries
                        or type(descriptor) is dict and (
                            'prefix_lengths' in descriptor or descriptor.get('schema') == 'cryptalis.context/v3'
                            or descriptor.get('representation') == 'cf1-packed-prefix/v1')):
                    return True
            facts = model.get('source_schema')
            if type(facts) is not dict or type(facts.get('indexes')) is not list:
                continue
            for index in facts['indexes']:
                if type(index) is not dict:
                    continue
                columns, dependencies, opclasses = (index.get(name) for name in
                                                     ('columns', 'dependency_columns', 'opclasses'))
                if (type(columns) is list and type(dependencies) is list and type(opclasses) is list
                        and any(type(name) is str and name in protected for name in columns + dependencies)
                        and any(op in ('pg_catalog.text_pattern_ops', 'pg_catalog.varchar_pattern_ops')
                                for op in opclasses)):
                    return True
    return False


def plan_requires_prefix(document):
    current = document
    while type(current) is dict:
        if requires_prefix_scope(current) or any(
                requires_prefix_scope(current.get(name)) for name in ('lock', 'target_lock', 'profile_source_lock')):
            return True
        current = current.get('source_plan')
    return False


def prefix_plan_scope(document):
    """Keep saved preparation/activation artifacts within synthetic scope."""
    if not _PREFIX_QUALIFICATION.get() and plan_requires_prefix(document):
        require_prefix_qualification()
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
