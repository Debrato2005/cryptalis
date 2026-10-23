"""Pre-adoption diagnostics through the existing read-only schema compiler."""

from .manifest.compiler import InspectionUnavailable, PlanningRejected, compile_protection
from .manifest.parser import ManifestInvalid


def preflight(manifest, mapping, engine, *, writers, search_reviews=()):
    """Report native schema compatibility without keys or application values.

    A schema PASS is not permission to apply protection. Provider access,
    application queries and external operational requirements remain UNKNOWN.
    """
    report = {
        'format': 'cryptalis.doctor/v1', 'scope': 'pre_adoption',
        'status': 'UNKNOWN', 'effects': 'NONE',
        'checks': {name: 'UNKNOWN' for name in (
            'manifest_schema', 'provider_keys', 'query_routes', 'writer_exclusion',
            'runtime_deployment', 'host_authority', 'recovery_capacity')},
        'issues': [],
    }
    try:
        compile_protection(manifest, mapping, engine, writers=writers,
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
    return report
