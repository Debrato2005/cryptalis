"""Measure column-lineage inspection only; no database, keys or SQL execution.

Run the same script before and after a change. This is not application latency.
"""
import argparse
import ast
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path
from types import CodeType, FunctionType, SimpleNamespace

import sqlalchemy
from sqlalchemy import Column, MetaData, Table, Text, select
from sqlalchemy.sql import visitors
from sqlalchemy.sql.elements import ColumnClause

from cryptalis.sqlalchemy import _Attachment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", default="origin/main")
    args = parser.parse_args()
    baseline_source = subprocess.check_output(
        ["git", "show", f"{args.baseline}:src/cryptalis/sqlalchemy.py"], text=True)
    attachment = next(node for node in ast.parse(baseline_source).body
                      if isinstance(node, ast.ClassDef) and node.name == "_Attachment")
    method = next(node for node in attachment.body
                  if isinstance(node, ast.FunctionDef) and node.name == "protected")
    namespace = {"ColumnClause": ColumnClause, "visitors": visitors}
    compiled = compile(ast.Module(body=[method], type_ignores=[]), "<baseline protected>", "exec")
    method_code = next(value for value in compiled.co_consts if isinstance(value, CodeType))
    implementations = {"baseline": FunctionType(method_code, namespace), "candidate": _Attachment.protected}
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
        for implementation in implementations.values():
            for expression, expected in checks:
                if implementation(owner, expression) != expected:
                    raise RuntimeError("Column-lineage result disagrees with the expected mapping.")
        public = [table.c.field_0.label(f"public_{index}") for index in range(32)]
        workloads = {"public_scalar": (table.c.field_0, False),
                     "public_projection": (select(*public), False),
                     "first_protected": (select(table.c.field_1), True),
                     "last_protected": (select(list(table.c)[-1]), True),
                     "mixed_projection": (select(*public, list(table.c)[-1]), True)}
        cases[str(count)] = {}
        for workload, (statement, expected) in workloads.items():
            samples = {name: [] for name in implementations}
            for implementation in implementations.values():
                for _ in range(100):
                    implementation(owner, statement)
            for batch in range(31):
                order = list(implementations.items())
                if batch % 2:
                    order.reverse()
                for name, implementation in order:
                    start = time.perf_counter_ns()
                    for _ in range(200):
                        if implementation(owner, statement) != expected:
                            raise RuntimeError("A measured projection changed its admission result.")
                    samples[name].append((time.perf_counter_ns() - start) / 200 / 1000)
            cases[str(count)][workload] = {
                name: {"median_us": statistics.median(values), "samples_us": values}
                for name, values in samples.items()}
    source = Path(__file__).resolve().parents[1] / "src/cryptalis/sqlalchemy.py"
    result = {"scope": "warm column-lineage inspection; alternating target-branch and candidate batches",
              "python": platform.python_version(), "sqlalchemy": sqlalchemy.__version__,
              "platform": platform.platform(), "clock": "perf_counter_ns",
              "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "baseline_revision": subprocess.check_output(
                  ["git", "rev-parse", args.baseline], text=True).strip(),
              "baseline_source_sha256": hashlib.sha256(baseline_source.encode()).hexdigest(),
              "warmups": 100, "batches": 31, "calls_per_batch": 200, "cases": cases}
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({count: {workload: {name: value["median_us"] for name, value in paths.items()}
                             for workload, paths in workloads.items()} for count, workloads in cases.items()}))


if __name__ == "__main__":
    main()
