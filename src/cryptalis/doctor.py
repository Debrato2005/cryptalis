"""Bounded schema, query and explicitly requested cold-key diagnostics."""

from .manifest.compiler import InspectionUnavailable, PlanningRejected, compile_protection
from .manifest.parser import ManifestInvalid
from ._doctor_code import scan_routes


def check_keys(keyrings=()):
    """Observe cold access for at most 16 supplied Keyrings; no database access.

    No roots, wrapper identities or underlying exception text enter the report.
    Caller caches and their lease deadlines are unchanged. A successful check
    establishes access only at observation time, not complete provider health.
    """
    from .crypto.keys import Keyring, ProviderAuthenticationUnavailable

    report = {
        'format': 'cryptalis.doctor/v1', 'scope': 'cold_provider_access',
        'status': 'UNKNOWN', 'effects': 'NONE', 'cache': 'BYPASSED',
        'checks': {name: 'UNKNOWN' for name in (
            'cold_key_preparation', 'frame_authentication', 'runtime_deployment',
            'host_authority', 'recovery_capacity', 'production_custody')},
        'items': [], 'issues': [],
    }
    if (type(keyrings) is not tuple or len(keyrings) > 16
            or any(type(ring) is not Keyring for ring in keyrings)):
        report['status'] = report['checks']['cold_key_preparation'] = 'FAIL'
        report['issues'].append({'code': 'Provider.InvalidKeyrings', 'location': 'keyrings',
            'remedy': 'Supply a tuple of at most 16 Keyring instances from trusted host policy.'})
        return report
    if keyrings:
        report['effects'] = 'PROVIDER_ACCESS'
    for index, ring in enumerate(keyrings):
        try:
            ring.check_access()
        except ProviderAuthenticationUnavailable:
            state = 'FAIL'
            report['effects'] = 'UNKNOWN'
            report['issues'].append({'code': 'Provider.AuthenticationUnavailable',
                'location': f'keyrings[{index}]', 'retryable': False,
                'remedy': 'Inspect workload credentials, role policy and native token issuance before retry; authentication may already have issued a token.'})
        except Exception:
            state = 'FAIL'
            report['issues'].append({'code': 'Provider.KeyUnavailable', 'location': f'keyrings[{index}]',
                'remedy': 'Check provider access, credentials and the exact wrapped-root policy, then repeat diagnosis.'})
        else:
            state = 'PASS'
        report['items'].append({'index': index, 'status': state})
    if keyrings:
        failed = any(item['status'] == 'FAIL' for item in report['items'])
        report['checks']['cold_key_preparation'] = 'FAIL' if failed else 'PASS'
        if failed:
            report['status'] = 'FAIL'
    return report


def _query_samples(report, plan, mapping, engine, queries):
    """Reuse SELECT admission without attachment, execution or key resolution."""
    from sqlalchemy.sql import Select
    from .crypto.cf1 import FieldDescriptor
    from .manifest.parser import decode_manifest_json
    from .sqlalchemy import _Attachment, _Binding, UnsupportedProtectedOperation

    samples = report['query_samples'] = {'scope': 'supplied_select_structures', 'submitted': len(queries),
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
        for index, query in enumerate(queries):
            try:
                if not isinstance(query, Select):
                    raise UnsupportedProtectedOperation()
                owner.admit(query)
            except UnsupportedProtectedOperation:
                samples['items'].append({'index': index, 'status': 'FAIL'})
                report['issues'].append({'code': 'Query.UnsupportedStructure', 'location': f'queries[{index}]',
                    'remedy': 'Use an admitted SELECT structure. Check other operations in an affected runtime journey.'})
            else:
                samples['items'].append({'index': index, 'status': 'STRUCTURE_ADMITTED'})
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
    """Report schema and optional SELECT structures without rows or keys.

    A schema PASS is not permission to apply protection. Provider access,
    route coverage and external operational requirements remain UNKNOWN. Supply
    at most 128 SELECT samples as a tuple. Their values are not executed or reported.
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
            'remedy': 'Supply a tuple of at most 128 SELECT samples.'}]
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
