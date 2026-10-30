"""Pre-adoption diagnostics through the existing read-only schema compiler."""

from .manifest.compiler import InspectionUnavailable, PlanningRejected, compile_protection
from .manifest.parser import ManifestInvalid


def _query_samples(report, plan, mapping, engine, queries):
    """Reuse statement admission without attachment, execution or key resolution."""
    from sqlalchemy import inspect
    from sqlalchemy.sql import Select
    from sqlalchemy.sql.dml import Insert
    from .crypto.cf1 import FieldDescriptor
    from .manifest.parser import decode_manifest_json
    from .sqlalchemy import (_Attachment, _Binding, UnsupportedProtectedOperation,
                             _delete_name_state, _delete_node)

    scope = 'supplied_statement_structures' if any(isinstance(query, Insert) for query in queries) else 'supplied_select_structures'
    samples = report['query_samples'] = {'scope': scope, 'submitted': len(queries),
        'execution': 'NOT_PERFORMED', 'items': []}
    try:
        owner = _Attachment(mapping, engine, decode_manifest_json(plan.lock_bytes), None)
        for model in owner.document['models']:
            mapper = next(mapper for mapper in mapping.mappers if mapper.class_.__name__ == model['model'])
            record = mapper.local_table.c[model['record']['column']]
            tenant = mapper.local_table.c[model['tenancy']['column']] if 'column' in model['tenancy'] else None
            for field in model['fields']:
                column = mapper.local_table.c[field['column']]
                owner.bindings.append(_Binding(column, mapper.get_property_by_column(column).key,
                    FieldDescriptor.from_compiled(field['descriptor'], field['descriptor_digest']),
                    record, mapper.get_property_by_column(record).key, tenant,
                    mapper.get_property_by_column(tenant).key if tenant is not None else None, mapper.class_))
            owner.models[mapper.class_] = tuple(binding for binding in owner.bindings if binding.model is mapper.class_)
        owner.returning_columns = {
            id(column): (column, column.table, _delete_name_state(column.name), _delete_name_state(column.key))
            for model in owner.models for column in inspect(model).local_table.c
        }
        for index, query in enumerate(queries):
            item = {'index': index}
            if isinstance(query, Insert):
                item.update(kind='insert', parameters='NOT_INSPECTED')
            try:
                if isinstance(query, Select):
                    owner.admit(query)
                elif isinstance(query, Insert):
                    _delete_node(query, Insert)
                    mapper = query._propagate_attrs.get('plugin_subject')
                    if not any(mapper is inspect(model) for model in owner.models):
                        raise UnsupportedProtectedOperation()
                    owner.admit(query, bulk=mapper.local_table)
                else:
                    raise UnsupportedProtectedOperation()
            except UnsupportedProtectedOperation:
                item['status'] = 'FAIL'
                report['issues'].append({'code': 'Query.UnsupportedStructure', 'location': f'queries[{index}]',
                    'remedy': 'Use an admitted SELECT or mapped INSERT structure. Check row inputs and other operations in an affected runtime journey.'})
            else:
                item['status'] = 'STRUCTURE_ADMITTED'
            samples['items'].append(item)
    except Exception:
        report['checks']['query_samples'] = 'UNKNOWN'
        if any(item['status'] == 'FAIL' for item in samples['items']):
            report['status'] = report['checks']['query_routes'] = 'FAIL'
        report['issues'].append({'code': 'Query.InspectionUnavailable', 'location': 'queries',
            'remedy': 'Inspect the supplied query objects and mapping, then repeat preflight.'})
    else:
        failed = any(item['status'] == 'FAIL' for item in samples['items'])
        report['checks']['query_samples'] = 'FAIL' if failed else 'PASS'
        if failed:
            report['status'] = report['checks']['query_routes'] = 'FAIL'


def preflight(manifest, mapping, engine, *, writers, search_reviews=(), queries=()):
    """Report schema and optional SELECT/INSERT structures without rows or keys.

    A schema PASS is not permission to apply protection. Provider access,
    route coverage and external operational requirements remain UNKNOWN. Supply
    at most 128 SELECT or mapped INSERT samples as a tuple. INSERT parameters
    are not inspected. Samples are never executed and their values are not reported.
    """
    report = {
        'format': 'cryptalis.doctor/v1', 'scope': 'pre_adoption',
        'status': 'UNKNOWN', 'effects': 'NONE',
        'checks': {name: 'UNKNOWN' for name in (
            'manifest_schema', 'provider_keys', 'query_routes', 'writer_exclusion',
            'runtime_deployment', 'host_authority', 'recovery_capacity')},
        'issues': [],
    }
    if type(queries) is not tuple or len(queries) > 128:
        report['status'] = report['checks']['query_routes'] = 'FAIL'
        report['issues'] = [{'code': 'Query.InvalidSamples', 'location': 'queries',
            'remedy': 'Supply a tuple of at most 128 SELECT or mapped INSERT samples.'}]
        return report
    try:
        plan = compile_protection(manifest, mapping, engine, writers=writers,
                                  search_reviews=search_reviews)
    except ManifestInvalid:
        report['status'] = report['checks']['manifest_schema'] = 'FAIL'
        report['issues'] = [{'code': 'Manifest.Invalid', 'location': 'manifest',
            'remedy': 'Supply a valid protection declaration with supported fields and explicit leakage acceptance.'}]
    except PlanningRejected as failure:
        report['status'] = report['checks']['manifest_schema'] = 'FAIL'
        report['issues'] = [dict(code=issue.code, location=issue.location, remedy=issue.remedy)
                            for issue in failure.issues]
    except InspectionUnavailable as failure:
        report['issues'] = [{'code': failure.code, 'location': 'database', 'remedy': failure.remedy}]
        state = failure.sqlstate
        report['sqlstate'] = (state if type(state) is str and len(state) == 5
            and all(character in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' for character in state) else 'UNKNOWN')
    else:
        report['checks']['manifest_schema'] = 'PASS'
        if queries:
            _query_samples(report, plan, mapping, engine, queries)
    return report
