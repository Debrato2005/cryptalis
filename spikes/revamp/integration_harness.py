"""Safe owned-schema harness for new evidence, never a full-gate verdict."""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.schema import CreateSchema, DropSchema

from integration_adapter import attach
from integration_crypto import LocalKeyring
from run_gate_retrofit import MANIFEST, fixture
from probe_service import EXPECTED

LOCAL_WRITERS = {"attached": ["orm", "core", "async", "background"], "unknown": [], "unexcluded": [],
                 "maintenance": "OWNED_LOCAL_FIXTURE_WRITERS_STOPPED"}

class Harness:
    def __init__(self, name):
        self.name = name
        self.schema = "revamp_gate_" + name + "_" + uuid.uuid4().hex
        self.outcomes = {}
        self.result = {"status": "FAIL", "connection_url": "NEVER_RECORDED",
                       "outcomes": self.outcomes, "schema": self.schema,
                       "full_gates": "UNKNOWN_OR_FAIL_UNTIL_COMPLETE_EVIDENCE"}
        self.app, self.result["adoption_edits"] = fixture()
        self.url = make_url(os.environ["CRYPTALIS_TEST_DATABASE_URL"]).set(drivername="postgresql+psycopg")
        self.engine = create_engine(self.url, hide_parameters=True, echo=False,
                                    connect_args={**EXPECTED, "hostaddr": "127.0.0.1", "connect_timeout": 3})
        self.engine = self.engine.execution_options(schema_translate_map={self.app.APP_SCHEMA: self.schema})
        self.provider = LocalKeyring()
        self.attachment = None
        self.created = False

    def create(self):
        with self.engine.begin() as connection:
            connection.execute(CreateSchema(self.schema))
        self.created = True
        self.app.Base.metadata.create_all(self.engine)

    def attach(self):
        self.attachment = attach(self.app.Base.registry, self.engine, MANIFEST,
                                 provider=self.provider, physical_schema=self.schema, local_mode=True,
                                 writer_inventory=LOCAL_WRITERS)
        return self.attachment

    def run(self, action, source):
        self.result["source_sha256"] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
        self.result["implementation_sha256"] = {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("integration_adapter.py", "integration_crypto.py", "integration_transition.py",
                         "integration_async.py", "integration_harness.py", "plain_app.py")}
        try:
            self.create()
            action(self)
            self.result["status"] = "PASS_LOCAL_CASES_ONLY"
        except BaseException as failure:
            original = getattr(failure, "orig", failure)
            self.result.update(exception_type=type(failure).__name__, code=getattr(original, "code", None),
                               sqlstate=getattr(original, "sqlstate", None), details="WITHHELD")
            if isinstance(failure, AssertionError) and len(failure.args) == 1 and re.fullmatch(r"[a-z_]+", str(failure.args[0])):
                self.result["failed_check"] = failure.args[0]
            locations = []
            trace = failure.__traceback__
            while trace:
                locations.append({"file": Path(trace.tb_frame.f_code.co_filename).name,
                                  "line": trace.tb_lineno, "function": trace.tb_frame.f_code.co_name})
                trace = trace.tb_next
            self.result["safe_locations"] = locations
        finally:
            try:
                if self.attachment is not None:
                    self.attachment.detach()
                if self.created:
                    with self.engine.begin() as connection:
                        connection.execute(DropSchema(self.schema, cascade=True))
                self.result["cleanup"] = "OWN_SCHEMA_DROPPED"
            except BaseException as failure:
                self.result.update(status="FAIL", cleanup="FAILED", cleanup_exception_type=type(failure).__name__)
            self.engine.dispose()
        destination = Path(__file__).with_name("results") / ("gate-" + self.name + ".json")
        destination.write_text(json.dumps(self.result, indent=2) + "\n")
        print(json.dumps({key: self.result.get(key) for key in
                          ("status", "exception_type", "code", "sqlstate", "failed_check", "safe_locations", "cleanup")}))
        print(json.dumps({"passed": len(self.outcomes), "full_gates": self.result["full_gates"]}))
        raise SystemExit(0 if self.result["status"] == "PASS_LOCAL_CASES_ONLY" else 1)
