"""Independent child executor. Synthetic fixture material only; no product hooks."""
import json
from pathlib import Path
import signal
import sys
from dataclasses import replace
from cryptalis.migration import MigrationPlan, DeploymentPin, MaintenanceApproval, apply
from test_migration import engine, keys

artifact, phase, pin_phase, pause = sys.argv[1:]
p = MigrationPlan(Path(artifact).read_bytes())
pin = DeploymentPin(p.target_id,p.operation_id,p.digest,pin_phase)
e = engine('CRYPTALIS_TEST_DATABASE_URL')
try:
    result = apply(p,e,keys=keys,pin=pin,approval=MaintenanceApproval('synthetic operator excludes other owner writers',3600),chunk_size=2,until=phase)
    print(result.phase, flush=True)
    if pause=='pause': signal.pause()
finally: e.dispose()
