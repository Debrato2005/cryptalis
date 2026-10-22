"""Fresh-process search cutover/publication using public fixture keys only."""
import json
from pathlib import Path
import signal
import sys
from uuid import UUID

from cryptalis import migration as m, rotation as r
from search_rotation_worker import target_keys
from test_migration import engine, keys


def main(argv=None):
    database=None
    try:
        proposal_path,activation_path,pin_path,approval_path,action,pause=(sys.argv[1:] if argv is None else argv)
        if action not in ('switch','publish','status') or pause not in ('exit','pause'):raise ValueError()
        proposal=r.SearchRotationPlan(Path(proposal_path).read_bytes())
        activation=m.MigrationPlan(Path(activation_path).read_bytes())
        pin=json.loads(Path(pin_path).read_text())
        pin.update(target_id=UUID(pin['target_id']),operation_id=UUID(pin['operation_id']))
        pin=m.DeploymentPin(**pin)
        approval=m.MaintenanceApproval(**json.loads(Path(approval_path).read_text()))
        database=engine('CRYPTALIS_TEST_DATABASE_URL')
        if action=='switch':
            result=r.switch_search_rotation(proposal,activation,database,keys=keys,target_keys=target_keys,
                                               pin=pin,approval=approval)
        elif action=='publish':
            result=m.apply(activation,database,keys=target_keys,pin=pin,approval=approval,until='ACTIVE')
        else:result=m.status(activation,database,pin=pin)
        output={'phase':result.phase,'rows':result.committed_rows,'chunks':result.committed_chunks,
                'operation_id':str(result.operation_id),'digest':activation.digest}
        database.dispose();database=None
        print(json.dumps(output),flush=True)
        if pause=='pause':signal.pause()
        return 0
    except Exception as error:
        output={'error':type(error).__name__}
        if isinstance(error,m.TransitionFailure):output['code']=error.code
        print(json.dumps(output),flush=True)
        return 1
    finally:
        if database is not None:database.dispose()


if __name__=='__main__':
    raise SystemExit(main())
