# Disposable hardening experiments

These experiments test narrow hypotheses. They are not Cryptalis runtime IMPLEMENTED or VERIFIED capability.
Production package imports/code are not used or changed. All keys/rows/identities are public synthetic fixtures.
The selected production cell remains unqualified. Exact local versions are in [environment.json](results/environment.json).
[requirements.txt](requirements.txt) pins all direct/transitive dependencies with hashes; [requirements.in](requirements.in) records the exact inputs.
The environment is project-local `spikes/.venv`. No global package was installed.

| Spike | Hypothesis / pass criteria | Raw evidence / limits |
|---|---|---|
| S1 | Public bootstrap remapping and one publication frame preserve dirty B versus stored A, explicit refresh/expiry/rollback. Failed refresh does not autoflush or publish. Merge/bulk and late sync/async flush, autoflush and await-time mutations reject. Last-row corruption publishes zero values | [source](run_database.py), [S1](results/S1.json). One imperative model/field, small Result wrapper, synthetic AEAD/material and no current remote admission |
| S2 | All reachable two-operation states preserve atomic commit marker/outcome and denial drain. Lock loss retains ownership. Stale owner and lease takeover reject. Repeated fake recovery cannot duplicate work/clear denial | [source](run_protocol.py), [S2](results/S2.json). 1,216 states/3,664 transitions. Fake atomic authority and imperative effect/recovery/capacity supplements do not prove AWS/termination |
| S2 PG supplement | Shared fence blocks exclusive acquisition, DB checks stale token, two immutable batch markers commit together in one transaction, mutation/marker rollback is atomic, markers survive later row deletion | [source](run_database.py), [result](results/S2-postgres.json). Application ACK deliberately discarded after successful commit, not actual transport cut/failover |
| S3 | Real PG arbitrates concurrent equivalent inserts, NULLS DISTINCT/IN/soft-delete scope hold, equality plan uses an index. Storage is measured | [source](run_database.py), [S3](results/S3.json). Counterexample intentionally permits a logical duplicate after malicious unreturned term change |
| S4 | Installed AES-256-GCM-SIV round-trips and rejects tamper/relocation/wrong key/context/nonce. Inherited PID handle rejects across fork | [source](run_crypto.py), [S4](results/S4.json). Fresh child fixture is not a real re-admitted provider/cache. Distinct nonce sample is not an RNG proof. Synthetic descriptor, no full independent vectors |
| M5 | Public expression validator rejects non-total/unknown forms even under OR/NOT; PG truth cases agree. Forced division projection exhibits the error | [source](run_semantics.py), [result](results/M5.json). Small closed subset, not production rewrite or complete differential oracle |

| Canonical/request supplement | Two differently structured encoders agree on reordered members, Unicode/control escapes, NULL and numeric limits. Same-type/value different attributes yield different digests and duplicate attributes reject | [source](run_canonical.py), [result](results/canonical.json). First-party fixtures, one actual driver TEXT type. No full compiler, independent human vectors or immutable DML-wire emission proof |

## Reproduction on an owned disposable target

The actual run used bundled PostgreSQL 16.2 with TCP disabled, `max_prepared_transactions=0`,
data/socket/log under `/tmp/cryptalis-hardening-postgres`, Unix socket port 55432, database postgres and role debrato.
Trust authentication is confined to this owned disposable local fixture. It is ineligible for production.
The experiments recreate only `spike_*` synthetic tables on that target. Do not point them at another database.
The host sandbox required scoped socket/process access for this authorized local server and DB runs.

```bash
uv venv spikes/.venv --python /usr/bin/python3 --cache-dir /tmp/cryptalis-hardening-uv-cache
uv pip install --python spikes/.venv/bin/python --require-hashes -r spikes/requirements.txt
spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/initdb -D /tmp/cryptalis-hardening-postgres/data -A trust --no-locale --encoding=UTF8
spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/pg_ctl -D /tmp/cryptalis-hardening-postgres/data -l /tmp/cryptalis-hardening-postgres/server.log -o "-k /tmp/cryptalis-hardening-postgres -h '' -p 55432 -c max_prepared_transactions=0" -w start
spikes/.venv/bin/python spikes/run_protocol.py
spikes/.venv/bin/python spikes/run_crypto.py
spikes/.venv/bin/python spikes/run_database.py
spikes/.venv/bin/python spikes/run_semantics.py
spikes/.venv/bin/python spikes/run_canonical.py
spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/pg_ctl -D /tmp/cryptalis-hardening-postgres/data -m fast -w stop
```

The socket directory must already exist and the cluster must not be reused accidentally. The binary path depends on Python/platform.
Do not rerun initdb over an existing cluster. No Docker/global/server installation or AWS call occurred.
Each experiment exits nonzero on an unexpected case. Output files contain the successful run's assertions/counterexamples;
an interrupted later run must not be mistaken for a fresh result receipt. Final verification records hashes and command exit status.
The original source baseline is [package-baseline.json](results/package-baseline.json).

## Failed observations retained

The first ORM attempts failed on expired-ID loading and callback ordering. Their exact outputs are in
[initial failures](results/initial-orm-failures.json). A later change exposed a
[refresh regression](results/refresh-regression.json): refresh autoflushed pending data before verification.
The new [autoflush oracle failed](results/autoflush-failure.json) when private collection skipped ordinary ORM autoflush.
The corrected adapter suppresses refresh autoflush, invokes guarded query autoflush and rejects changes after async preparation.
The final S1 receipt includes the unchanged failure oracles. These failures remain evidence rather than disappear after correction.
