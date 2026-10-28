"""Measure column-lineage inspection only; no database, keys or SQL execution.

Run the same script before and after a change. This is not application latency.
"""
import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import sqlalchemy
from sqlalchemy import Column, MetaData, Table, Text, select

from cryptalis.sqlalchemy import _Attachment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = {}
    for count in (1, 8, 32):
        table = Table("customer", MetaData(),
                      *(Column(f"field_{index}", Text) for index in range(count + 1)))
        owner = SimpleNamespace(bindings=[SimpleNamespace(column=column) for column in list(table.c)[1:]])
        alias = table.alias()
        other = Table("unrelated", MetaData(), Column("field_1", Text))
        checks = ((table.c.field_0, False), (other.c.field_1, False),
                  (table.c.field_1, True), (alias.c.field_1, True),
                  (select(table.c.field_0).where(table.c.field_1 == "public fixture"), True))
        for expression, expected in checks:
            if _Attachment.protected(owner, expression) != expected:
                raise RuntimeError("Column-lineage result disagrees with the expected mapping.")
        statement = select(*[table.c.field_0.label(f"public_{index}") for index in range(32)])
        for _ in range(100):
            _Attachment.protected(owner, statement)
        samples = []
        for _ in range(31):
            start = time.perf_counter_ns()
            for _ in range(200):
                if _Attachment.protected(owner, statement):
                    raise RuntimeError("An unprotected projection was classified as protected.")
            samples.append((time.perf_counter_ns() - start) / 200 / 1000)
        cases[str(count)] = {"median_us": statistics.median(samples), "samples_us": samples}
    source = Path(__file__).resolve().parents[1] / "src/cryptalis/sqlalchemy.py"
    result = {"scope": "warm column-lineage inspection; 32 public projection labels",
              "python": platform.python_version(), "sqlalchemy": sqlalchemy.__version__,
              "platform": platform.platform(), "clock": "perf_counter_ns",
              "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "warmups": 100, "batches": 31, "calls_per_batch": 200, "cases": cases}
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value["median_us"] for key, value in cases.items()}))


if __name__ == "__main__":
    main()
