"""Fresh original application removal oracle. No Cryptalis or crypto reader permitted."""
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
from probe_service import EXPECTED
import sys

from sqlalchemy import create_engine, delete, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


def snapshot(app, engine):
    # Hash all three models and all original columns, not just recovered email.
    data = {}
    with Session(engine) as session:
        for model in (app.Account, app.Customer, app.Invoice):
            values = []
            for obj in session.scalars(select(model).order_by(model.id)):
                row = []
                for column in model.__table__.columns:
                    value = getattr(obj, column.key)
                    row.append((column.name, type(value).__name__, None if value is None else str(value)))
                values.append(row)
            data[model.__name__] = values
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class NoCrypto(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "cryptalis" or fullname.startswith("cryptalis.") or fullname == "cryptography" or fullname.startswith("cryptography.") or fullname.startswith("integration_") or fullname.startswith("run_cf1"):
            raise ImportError("PACKAGE_FREE_IMPORT_BLOCKED")


def main():
    out = {}
    engine = None
    try:
        schema, expected = sys.argv[1:]
        if not schema.startswith("revamp_gate_lifecycle_") or len(expected) != 64:
            raise ValueError("OWNED_SCHEMA_ARGUMENT_REQUIRED")
        sys.meta_path.insert(0, NoCrypto())
        import plain_app as app
        for name in ("cryptalis", "cryptography", "integration_crypto", "integration_adapter"):
            try:
                __import__(name)
            except ImportError:
                out["blocked_" + name] = "PASS"
            else:
                raise AssertionError("package_import_was_not_blocked")
        url = make_url(os.environ["CRYPTALIS_TEST_DATABASE_URL"]).set(drivername="postgresql+psycopg")
        engine = create_engine(url, echo=False, hide_parameters=True, connect_args={**EXPECTED, "hostaddr": "127.0.0.1", "connect_timeout": 3})
        engine = engine.execution_options(schema_translate_map={app.APP_SCHEMA: schema})
        if snapshot(app, engine) != expected:
            raise AssertionError("current_application_snapshot_changed")
        out["all_current_original_columns_and_types_match"] = "PASS"
        with Session(engine) as session:
            customer = session.get(app.Customer, 2)
            original = customer.email
            customer.display_name = "Package-free current edit"
            session.commit()
            if customer.email != original or customer.display_name != "Package-free current edit":
                raise AssertionError("package_free_current_data_read_write")
            out["package_free_current_data_read_write"] = "PASS"
            # The frozen oracle assumes an empty database for its global SUM.
            # First prove all current data and a committed ordinary edit above;
            # then reset only these owned synthetic fixtures for that oracle.
            for model in (app.Invoice, app.Customer, app.Account):
                session.execute(delete(model))
            session.commit()
        app.exercise(engine, out)
        print(json.dumps({"status": "PASS_PACKAGE_FREE_ORIGINAL_APPLICATION", "outcomes": out,
                          "original_source_sha256": hashlib.sha256(Path(app.__file__).read_bytes()).hexdigest()}))
        return 0
    except BaseException as failure:
        locations = []
        trace = failure.__traceback__
        while trace:
            locations.append({"file": Path(trace.tb_frame.f_code.co_filename).name, "line": trace.tb_lineno,
                              "function": trace.tb_frame.f_code.co_name})
            trace = trace.tb_next
        print(json.dumps({"status": "FAIL", "exception_type": type(failure).__name__, "details": "WITHHELD",
                          "sqlstate": getattr(getattr(failure, "orig", failure), "sqlstate", None),
                          "safe_locations": locations}))
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
