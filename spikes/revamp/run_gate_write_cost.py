"""Current adapter write/read costs after assignment inspection changed; reuse million-row evidence."""
from decimal import Decimal
from sqlalchemy import insert
from sqlalchemy.orm import Session

from integration_harness import Harness
import run_gate_performance as benchmark
from run_gate_retrofit import check


def cases(h):
    app, out = h.app, h.outcomes
    benchmark.ROWS = 10_000
    with Session(h.engine) as session:
        accounts = [app.Account(name="current-cost-" + str(n)) for n in range(10)]
        session.add_all(accounts)
        session.commit()
        tenants = [account.id for account in accounts]
        for start in range(0, benchmark.ROWS, 1000):
            session.execute(insert(app.Customer), [{"account_id": tenants[n % 10], "email": None if n % 100 == 0 else "person-" + str(n) + "@example.test",
                                                   "display_name": "Name " + str(n % 1000), "age": n % 100} for n in range(start, start + 1000)])
        session.add_all([app.Invoice(customer_id=1001 + n, amount=Decimal("20.00")) for n in range(10)])
        session.commit()
    plain_reads, plain_truth = benchmark.read_workloads(h, tenants)
    plain_writes = benchmark.write_workload(h, restore=True)
    h.attach()
    protected_reads, protected_truth = benchmark.read_workloads(h, tenants)
    check(out, "current_adapter_identical_workload_results", protected_truth == plain_truth)
    protected_writes = benchmark.write_workload(h, restore=False)
    with Session(h.engine) as session:
        check(out, "current_adapter_committed_batch_readback", session.get(app.Customer, 401).email == "updated-401@example.test")
    h.result.update(rows=benchmark.ROWS, baseline={"reads": plain_reads, "writes": plain_writes},
                    protected={"reads": protected_reads, "writes": protected_writes},
                    reused_scale_receipt="gate-performance.json", production_budgets="UNKNOWN",
                    limits=["Ten thousand rows for changed adapter cost; not a replacement million-row plan",
                            "Four hundred committed updated rows, ten batches; no long production soak",
                            "Local provider only; real provider latency, approved budgets and production profile remain UNKNOWN"])


if __name__ == "__main__":
    Harness("write-cost").run(cases, __file__)
