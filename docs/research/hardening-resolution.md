# Architecture hardening resolution record

Date: 2026-10-07, Asia/Calcutta. This is first-party design/evidence work, not an audit or production qualification.
Canonical owners define future implementation. Existing production source remains outside the write scope.
The first council's exact [report](council-review-1/report.md), [brief](council-review-1/frozen-brief.txt), recovered outputs,
and original complete request are preserved. The report controls over its summary.

## Finding dispositions

RESOLVED_DESIGN means a mechanism or explicitly narrower claim exists with stated evidence/gates.
It does not mean the complete runtime protocol is implemented or verified.

| ID | Resolution | Canonical owner / ledger | Executed subset / remaining test |
|---|---|---|---|
| H1 | Fence before admission, DB token check, registered worker/mutation drain, immutable external dispatcher. No TTL takeover | [security](../security.md#admission-and-fencing), D33 | S2 exploration + PG stale-token/shared-lock checks. Real AWS/CAS/IAM/failover/termination UNKNOWN |
| H2 | Atomic ordinary outcome row, original UUID/digest, terminal-backend-before-absence rule, retained marker independent of data deletion | [lifecycle](../lifecycle.md#ordinary-commit-evidence), D34 | S2 + real PG commit/rollback/delete marker. Transport-cut/target lineage/retention unbuilt |
| H3 | Public bootstrap mapping, separate pending state and physical snapshots, one logical publication frame, explicit identity refresh. Partial refresh/merge/deferred host mappings rejected | [integration](../architecture/README.md#orm-state-and-publication), D35 | S1 real sync/async subset. Full declarative/Result/history/loader cell UNKNOWN |
| H4 | Freeze complete write set before await, prepare outside hooks, check again at final SQL emission, reject late writes | [integration](../architecture/README.md#closed-write-preparation), D35 | S1 late sync/async callbacks reject. Cascades/defaults/autoflush/cancel/end-hook coverage UNKNOWN |
| M5 | Closed total plain atoms and protected leaves, full-tree rejection including unused branches, exact three-valued semantics | [compatibility](../compatibility.md#query-semantics), D36 | M5 reproduces division error, rejects 10 unsafe forms, checks six truth results. Full oracle unbuilt |
| M6 | Live/target/retry/growth/mirror root headroom and physical/provider preflight. Exhaustion pauses; mirror failure denies whole write | [lifecycle](../lifecycle.md#capacity-preflight-and-exhaustion), D37 | S2 tiny-cap three failure checks. Live account/storage/quota/rollback evidence UNKNOWN |
| M7 | Exactly all-row tenant/field uniqueness, NULLS DISTINCT, no partial/composite/global/soft-delete reuse. Intact-term assumption and membership oracle stated | [compatibility](../compatibility.md#query-semantics), D38 | S3 actual concurrent conflict and hostile-term duplicate counterexample. Broader cells unbuilt |
| M8 | Original-proposal operation-ID resume, inspect-only reconcile, reversible abort, proof-only break-glass with current authority | [lifecycle](../lifecycle.md#recovery-catalogue), D39 | S2 repeat/wrong-target/digest/unknown-owner subset. Real commands and all catalogue rows unbuilt |
| M9 | `revoke --subject` means managed denial. `destroy --domain` is separately observed custody destruction | [lifecycle](../lifecycle.md#revocation-and-destruction), D26/D27 | Terminology checks. Operator comprehension and actual command outputs UNKNOWN |
| M10 | AWS-only eligibility, bootstrap/mapping/session/schema changes, maintenance/backup/IAM obligations first. Finalized ordinary ciphertext versus approved plaintext copies explicit | [README](../../README.md#intended-adoption), D32/D40 | Static claim check. Representative adoption/usability UNKNOWN |

All ten have explicit invariant/failure behavior in their owner and named [adversarial build scenarios](../build-guide.md#hardening-specific-acceptance-scenarios).
No first-review finding is dismissed because existing source already chooses an abstraction.

## Additional investigation

| ID | Outcome / evidence | Remaining decision or gate |
|---|---|---|
| A1 | Retain AWS-only minimum KMS/table/independent bucket. Small internal provider, fake test-only implementation. Reads two snapshots, mutations also ownership writes, cold roots/quota add calls. Cost formula/target and outage/IAM costs explicit | G-AUTHORITY/G-PERFORMANCE/G-RELEASE. Real cost and small-customer adoption UNKNOWN |
| A2 | Every selected version's publication checked against primary sources. Local AESGCMSIV 50.0.2/OpenSSL4.0.3 exercised. HKDF/nonce/message-size facts checked | Exact production artifacts/interoperability, RNG and composed confidentiality/forgery bounds need review. No formal bound claimed |
| A3 | Revision/presence MAC/commitment/count mitigations assessed. S4 shows fresh presence check helps but authentic historical absence replays. Keep narrower returned-non-null authenticity claim and customer ineligibility for stronger requirements | Independent review of intended customer boundary. No freshness service or automatic full scan |
| A4 | All 33 blocked decisions contain INVALIDATING properties. Only bounded parameters/optimizations are tuning within those contracts. F01–F06 precede compiler/provider implementation | Failed feasibility gate changes architecture/scope, never weakens oracle |
| A5 | All 15 original kill criteria reproduced below. No whole-product PASS inferred from prose/local spikes | Production feasibility remains UNKNOWN |
| A6 | Numerical hot read/write p50/p95/p99, cold-root, async lag, maintenance throughput and monthly control-plane TARGETS set with workload definition | UNMEASURED. Failing target blocks intended deployment eligibility |
| A7 | [Cryptographer packet](cryptographer-review-packet.md) exports exact owned construction bytes/contexts/bounds and questions, with source hashes | No independent review returned |
| A8 | Historical section/property traceability retained with explicit hardening dispositions. Canonical-owner, links/anchors, old naming, gates/counts and scope checks recorded at final verification | Machine checks do not prove semantic completeness. Council and human review remain separate |

## Complete product kill list

Source: verbatim criterion wording from the recovered [original request](council-review-1/original-reset-request.txt).
PASS_DESIGN means the declared contract avoids the stated inherent failure. UNKNOWN means decisive product evidence is missing.
Neither is a production PASS. A concrete inherent FAIL requires redesign. Unknown eligibility blocks deployment.

| # | Original kill criterion | Design/evidence outcome | Required deciding evidence |
|---|---|---|---|
| 1 | key rotation commonly risks permanent data loss | UNKNOWN. Reader-first, retained dependencies and no automatic destruction designed | Interrupted real rotation plus backup recovery trials |
| 2 | migration corruption is easy | UNKNOWN. Full verifier/fences/atomic chunks designed | Mutant verifier, stale-owner/crash/schema/capacity trials |
| 3 | rollback is mostly theoretical | UNKNOWN. Current atomic mirror and deadline designed | Real post-switch writes/rollback/exhaustion/equivalence |
| 4 | uninstall strands data | UNKNOWN. Package-free host and retained backup reader/key gate designed | Actual host exit without package and independent backup recovery |
| 5 | search makes sensitive values nearly plaintext without warning | PASS_DESIGN for explicit leakage/rejected low-cardinality scope. Safety of accepted data UNKNOWN | Chosen-input/auxiliary-frequency demonstration and customer acceptance |
| 6 | raw/common backend paths silently bypass protection | UNKNOWN. Guard/role/inventory rejects or records gaps. No universal ORM claim | Writer-path/canary/COPY/raw/ETL evidence on representative host |
| 7 | old data becomes unreadable after normal upgrades | UNKNOWN. Required reader/dependency retention designed | Adjacent-binary/old-job/backup matrix and retirement trials |
| 8 | key loss/recovery behaviour is unclear | PASS_DESIGN for explicit permanent-loss/unknown-authority denial and ownership | Restore/reader/wrapper/KEK/current-history exercises |
| 9 | normal ORM queries silently return wrong results | UNKNOWN. Narrow grammar, atomic failure and dirty-state subset observed | Complete admitted Result/query/null/error/loader differential cell |
| 10 | security depends on source/config secrecy | PASS_DESIGN. Public algorithms/context/config assumed; keys external | Independent crypto/authority review and source+dump trial |
| 11 | KMS latency makes ordinary workloads unusable | UNKNOWN. No per-field warm call, bounded preparation and latency targets | Whole-backend hot/cold/load/outage benchmarks |
| 12 | developers need crypto expertise to use the system | UNKNOWN. No public crypto API, but IAM/ops/mapping adoption remains substantial | Representative builder/operator task study |
| 13 | architecture requires giant control plane for small library | UNKNOWN. Three managed resources, no daemon, but ownership/calls/IAM add real cost | Monthly cost target, deployment effort, drain/recovery usability and load tests |
| 14 | package so complex nobody can audit it | UNKNOWN. Narrow codecs/queries/providers and independent packet reduce scope | Human cryptographer/ORM/distributed-system and artifact review |
| 15 | docs have multiple competing truths | PASS_DESIGN under owner map/archived evidence separation, subject to final integrity checks | Link/traceability/duplicate-contract/council review; human semantic review |

Current tally: 4 PASS_DESIGN, 11 UNKNOWN, 0 demonstrated inherent FAIL. **Production PASS: 0.**
This tally is not a security score. A new FAIL overrides it and requires redesign.

## Limits, assumptions and claim changes

- First council outputs were recovered from the current chat, because they had not been saved separately in /tmp. Provenance and hashes are preserved.
- Disposable local PG16.2/CPython3.12.3 is sufficient for these narrow experiments. It cannot qualify RDS18.6/CPython3.14.8.
- S2 uses two operations and an atomic fake authority. External ownership/capacity/recovery supplements are imperative examples, not explored AWS state machines.
- Real PG supplement discards the application acknowledgement after COMMIT. Actual transport cuts, failover loss and backend terminality are untested.
- S4 fresh child material is a fixture. It proves inherited PID rejection, not actual provider/worker re-admission or global nonce entropy.
- Nullable integrity, row freshness/completeness and hostile global uniqueness are explicit ineligibility boundaries, not fulfilled requirements.
- Complete Result, mappings, cascades/defaults, closed ordinary write inventory, command outputs and representative usability remain unproved.
- No numerical documentation cap appeared in the recovered request. It asked for crawlable owners and avoidance of another 50k-word document.
  Local review budget assumption: canonical product/workflow owners together <=2,500 lines and <=30,000 raw words. Evidence archives,
  traceability tables and the requested frozen expert export are excluded from the runtime reading path. Measurements are recorded below.
  The first self-imposed 25,000-word draft ceiling was missed (28,295 raw words). It was revised explicitly to retain the required
  exact protocols and evidence limits. This is a chair budget assumption, not a user-supplied limit or a claim that the first target passed.
- Subject shred/erased, zero-change adoption, generalized query breadth, hostile-DB logical uniqueness and before_flush-only sealing claims were removed/narrowed.
- Production runtime file hashes remain the acceptance boundary. Spike files never upgrade maturity labels.

## Verification and second council

Pending at draft time. Final command receipts, documentation integrity metrics, native reviewer findings/dispositions and commit IDs
will be recorded here after the frozen second review. No pending check is currently labeled PASS.
