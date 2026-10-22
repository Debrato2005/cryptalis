"""Doctor admits later ACTIVE edits and checks the immutable rotation lineage."""
import json
from uuid import UUID

from search_rotation_worker import target_keys
from test_cli import _run_cli
from test_doctor_cli import checks, diagnostic, doctor_arguments, doctor_inputs
from test_migration import application, publish, run, TENANT
from test_rewrap_plan import _snapshot
from test_search_retained_readers import attached
from test_search_rotation_lifecycle import plan, stage, seal, switch, activate

def test_doctor_checks_published_search_lineage_without_freezing_later_values(tmp_path):
    with application() as app:
        run(app); publish(app)
        proposal = plan(app)
        stage(app, proposal)
        activation = seal(app, proposal)
        switch(app, proposal, activation)
        activate(app, activation)
        with attached(app, target_keys) as current:
            with current.sessions(tenant_id=TENANT) as session:
                session.get(current.Customer, UUID(int=101)).name = 'later active search edit'
                session.commit()
        paths = doctor_inputs(app, tmp_path)
        before = _snapshot(app)
        observed = _run_cli(*doctor_arguments(paths))
        assert observed.returncode == 0 and observed.stderr == ''
        checks(json.loads(observed.stdout), 'PASS')
        assert _snapshot(app) == before
        journal = f'"{app.schema}"."_cryptalis_journal"'
        predecessor = UUID(app.plan.document['predecessors'][0]['operation_id'])
        with app.owner.begin() as connection:
            state = connection.exec_driver_sql(
                f'SELECT state FROM {journal} WHERE operation_id=%s', (predecessor,)).scalar_one()
            changed = {**state, 'superseded_by': {**state['superseded_by'], 'plan_digest': '0' * 64}}
            connection.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                                      (json.dumps(changed), predecessor))
        try:
            tampered = _snapshot(app)
            diagnostic(_run_cli(*doctor_arguments(paths)), 3, 'FAIL', 'predecessor_chain_changed')
            assert _snapshot(app) == tampered
        finally:
            with app.owner.begin() as connection:
                connection.exec_driver_sql(f'UPDATE {journal} SET state=%s::jsonb WHERE operation_id=%s',
                                          (json.dumps(state), predecessor))
        assert _snapshot(app) == before
