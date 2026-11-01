# Cryptalis engineering handoff

## Resume the frozen installed-library checkpoint

The 2026-11-01 pasted brief authorized preview preparation, independent parallel
work and verified commits/pushes. It supersedes the earlier pause and JSON/text
priority below. The [preview contract](preview.md) preserves every production
objective and the single-public-release policy.

- Library `v0.1.0a1`: `655d52271d90effb4df918a9547f61c89055fbc7`, normal wheel/sdist,
  eight clean installer/interpreter cells, exact hosted/local artifact equality.
  Both jobs in run 41280665577 pass at PR merge `ac6b86b`; every inventoried
  source/build byte matches the actual frozen head. [Boundary](_reset/preview-hosted-boundary-20261101.json).
- Separate Smolink tag `cryptalis-demo-0.1.0a1-20261101-final`:
  `269aed4bcfcbbf40ffea444f2e2a748013c862d4`, measured code `2a66223`.
  Original backend files are unchanged. Real OpenBao/PG/Redis, original Swagger,
  source-stopped restore, latest edits/removal and an actual package-absent
  restart pass. Supplemental installed original applications cover crash/resume,
  native search oracles and all three rotations. [Report and evidence](https://github.com/Debrato2005/smolink/blob/269aed4bcfcbbf40ffea444f2e2a748013c862d4/cryptalis_demo/REPORT.md).
- Final point-read added p95 is 4.849 ms at concurrency 1: MISS against 3 ms;
  concurrency 4/16 also miss. Destination bytes are 1.5114×, observed total
  relation/index allocation 2.5987×. Smolink destination equality/IN and its
  search-key rotation remain unsupported by its storage-only profile.
- Separate source-bound local maintenance evidence at demo `b84f54d` measures
  real-host stop to committed POST201 of 4.071 s protect, 4.501 s wrapping rewrap
  and 12.169 s payload rotation. [Definitions, raw service counters and retained failure](https://github.com/Debrato2005/smolink/blob/b84f54d2fde83105c3e208be1ef16af68dd54801/cryptalis_demo/evidence/writer-interruption-20261101/README.md).
  It preserves the original freeze and makes no production outage guarantee.
- Draft release payload/review notes and disabled Trusted Publishing template
  are prepared. No remote Release exists: the connector has no release-create
  operation and direct GitHub API access is denied. No public index upload or
  public preview release is authorized or performed.

Private role files, OpenBao initialization/token/TLS keys, Project state and raw
backups remain outside both repositories. All database/Redis/app services were
stopped after their checks. Retain recovery keys/readers; retire the local OpenBao
container only after private-log retention, preserving its Raft storage.

Continue production work on a separate development branch against all 34
objectives. Integrate reusable verified fixes through normal Git workflow;
do not create permanent library forks. The first post-preview tooling fix reuses
the demo's standard X.509 extensions in `scripts/openbao_qualification.py`.
A fresh OpenBao service passes strict Python 3.13.5 TLS and public installed-wheel
root creation/unwrap; wrong-AAD and key-administration controls refuse. The
earlier certificate failure and a runner readiness failure remain recorded in
the [exact boundary](_reset/openbao-strict-tls-boundary-20261101.json).
Both new temporary containers were retired after private-log retention; private
custody files remain available. Runtime/build inputs and the frozen preview
are unchanged. The full hosted source/installed jobs pass for this exact tooling
revision, with matching frozen preview artifacts; the independent local strict
TLS boundary used no PostgreSQL. [Hosted evidence](_reset/openbao-strict-tls-hosted-boundary-20261101.json).
No full provider qualification follows. Continue the production objective ledger. All seven gates
and independent human review remain UNKNOWN. [Status](status.md) owns current results.

The independently installable package, separate fresh application demonstration,
current-data removal, source-bound measurements and freeze are delivered within
their stated limits. The requested remote draft Release remains blocked by
connector/network capabilities; equivalent CipherStash execution requires its
unconfigured workspace/client credentials. Local release payloads/notes and the
complete preview kit are ready. Public package-index upload has no approval.
Preserve all remaining product objectives; do not convert these blockers or
missed targets into completed production requirements.

## Previous native JSONB checkpoint

This handoff accompanies the native JSONB storage slice. Use
[current status](status.md) for exact verification and hosted revisions, and the
[34-objective ledger](BUILD_CHECKLIST.md) for remaining work. This file is a
resume guide, not a second product contract. The full product goal is unfinished;
all seven production gates remain UNKNOWN.

Implementation and local evidence are committed at
[`4ae1b76`](https://github.com/Debrato2005/cryptalis/commit/4ae1b76df0e177a8cc54a2f37fbf013ca4b0fd72).
Both hosted jobs pass in
[run 41279005913](https://github.com/Debrato2005/cryptalis/actions/runs/41279005913).
The [retained hosted boundary](_reset/github-jsonb-green-20261101.json) verifies
all recorded Python/build inputs against that exact commit and binds the CI
receipt archive. Subsequent handoff/contract wording changes are documentation only.

### Historical scope and next instruction

The target remains all [18 product requirements](requirements.md) and all 34
objectives in one comprehensive first release. Functionality precedes further
optimization. Apply KISS and use meaningful end-to-end/native PostgreSQL oracles.
The earlier instruction covered completing, verifying and pushing that JSONB
slice and then waiting. The newer preview instruction above has superseded that
pause; it remains historical context only.

Inspect the actual checkout root, branch, working tree and remote before making
claims. Read `AGENTS.md`, the [documentation map](README.md), current status,
affected objective and contract owner, then the procedure. Cross-cutting changes
also require architecture, security, lifecycle, compatibility, decisions, build
guide and engineering playbook. Historical pauses and workstation paths do not
define current authorization or product scope.

## What is implemented

The repository contains the manifest/Project/Doctor front door, authenticated
pre-PostgreSQL encryption, bounded sync/async SQLAlchemy and SQLModel integration,
resumable and online lifecycle, three rotation workflows, fresh adoption and
current-data removal followed by a package-free native restart. The
[compatibility matrix](compatibility.md#full-capability-matrix) defines exact
admitted storage, query and ORM behavior.

The latest slice adds bounded [native JSONB storage](compatibility.md#jsonb-storage):

- Existing CF1 encryption, `pg-jsonb-text/v1`, lock/v15 and context/v2; no new
  dependency or cryptographic primitive. Earlier descriptor bytes remain valid.
- Both native `none_as_null` policies, omitted values, JSON.NULL and SQL null(),
  ordinary and MutableDict tracking, sync/async CRUD and RETURNING.
- Exact canonical PostgreSQL UTF-8 bytes through migration, online capture,
  rotations, restore and removal. Application JSON decoding occurs only after
  authentication; its float rounding is never lifecycle truth.
- Default JSON adapter admission, immutable caller-input checks across provider
  callbacks/awaits, typed unsupported-operation refusal, transaction cleanup on
  failure/cancellation, and source/installed/fresh-recovery E2Es in CI.

The [local JSONB boundary](_reset/jsonb-boundary-20261101.json) retains exact
receipts, distributions, failures and source snapshots. [Type history](history/types-2026-11.md)
records the fixes and evidence limits. Runtime-role isolation repair and earlier
hosted results remain retained in current status and their original boundaries.

The exact-prefix prototype remains INTERNAL ONLY, including mixed v15 plans and
retained pattern-index obligations. Its retained storage cost is 13.1527× native
versus the 2× target. The published dense-int2 sorting experiment recovers all
non-NULL values in a deliberately misclassified fixture; honest small-domain
admission refuses it. Neither observation supplies production/security admission.

## What remains

The ledger owns all remaining objectives. The next large functionality gap is
JSON and broader text search. JSONB storage does not implement JSON equality,
path/containment operators, protected defaults, indexes, CHECK, foreign-key or
uniqueness constraints. JSON null and SQL NULL remain distinct internally, while
both return native Python None. Native nullability is supported.

Choose each search representation from published constructions and primary
sources, documenting dump leakage and exact native semantics before coding.
A flat bag of leaf HMACs is not an established general JSON containment solution:
array/object structure and correlation require an exact argument and oracle.
No JSON search design is admitted by this handoff.

Other open work includes wider native ORM/type/query behavior, prefix admission
and attack/cost acceptance, numeric ordering/arithmetic/nonfinite values,
performance targets, upgrades, deployment fencing, provider identity/custody,
audit/HA, retained-copy inventory and controlled key retirement, combined disaster
drills, independent human review and release provenance. Passing tests or AI
review do not close these gates. Do not infer a completion percentage.

## Verification and safe resumption

Use [local setup](local-development.md), [test layers](../ENGINEERING_PLAYBOOK.md#test-layers)
and the [JSONB qualification procedure](qualification.md#native-jsonb-storage).
All PostgreSQL tests go through `scripts/test_postgres.py`, directly or through
the existing disposable-cluster harness. A failed role probe stops the run;
resolve its cause and applicable authorization before retrying. Never print
connection strings or substitute a target silently.

Create a new absolute work directory for each run. Ensure the temporary/build
filesystem has space; this session exhausted the small `/tmp` tmpfs and used a
disk-backed private cache instead. Never delete keys, backups or retained earlier
reader environments to make room. Freeze `src`, `tests` and `scripts` Python
bytes during a wrapper run. Source changes invalidate its byte-bound receipt.
Use worker counts appropriate to available RAM; two workers were used locally.

The optional `CRYPTALIS_JSONB_PREVIOUS_READER_PYTHON` must identify a genuine,
immutable v14 installation, distinct from the candidate installed environment.
Local JSONB runs execute that control. Hosted runners may explicitly skip it;
that skip does not qualify old-reader compatibility. Both fresh layouts verify
exact native wire bytes, tamper refusal, current edits/removal and an
import-denied restart. Their outer source cluster remains alive until cleanup;
no source-cluster-shutdown-before-adoption or production fencing claim follows.

Keep receipt archives immutable. Private role files, keys, raw backups/dumps,
local attachments and the earlier private handoff bundle are not repository
artifacts. Scoped Graphify navigation may help when available; confirm in source
and refresh after code edits without installing hooks or changing configuration.

For the next authorized slice, implement a bounded complete behavior, verify its
real native and installed lifecycle, update the owning contracts/status/ledger,
retain failures and receipts, then commit and push. Wait for the exact hosted
revision and inspect its evidence before claiming CI verification. Publishing
packages, production deployment and destructive external actions need their
own authorization.
