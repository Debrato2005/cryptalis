# Cryptalis engineering handoff

The installed-library preview and separate Smolink demonstration are delivered
within their recorded scope. The full product remains unfinished: all 34
objectives remain in the [objective ledger](BUILD_CHECKLIST.md), and all seven
production gates remain UNKNOWN. [Status](status.md) owns verification;
[compatibility](compatibility.md) owns admitted behavior. This file is the resume
route, not another product contract.

## Current stop point

The preview implementation/evidence base is
`0e56438100eb7295f7e0f2601cebea74f2d02ed6` on Cryptalis `main` and
`development/post-preview-20261101`. Subsequent bounded production slices are
recorded at the top of [current status](status.md), beginning with public-table
DELETE RETURNING on `development/native-dml-20261101` from `8a5d506`. The packaging work and reusable strict-TLS
qualification fix are integrated through [PR 3](https://github.com/Debrato2005/cryptalis/pull/3)
and [PR 4](https://github.com/Debrato2005/cryptalis/pull/4).
The frozen library, demonstration and original receipts remain unchanged.

CipherStash credentials are needed only to run CipherStash itself for the live
competitor comparison requested in point 25. Cryptalis and the Smolink integration
use an independent external provider, demonstrated with OpenBao. Continue library,
provider and application work using the existing native PostgreSQL oracles;
CipherStash access is not a prerequisite for that work.

Two external deliverables remain incomplete:

- Remote draft GitHub Release: local [payload](../release/draft-0.1.0a1.json) and
  [review notes](../release/notes-0.1.0a1.md) are prepared. The available connector
  has no release-create operation, and this environment denies direct GitHub API
  access. Recheck supported access when that capability changes.
- Equivalent CipherStash runtime comparison: the documented proxy setup needs its
  workspace/client credentials. None of the four required CS bindings is configured.
  [Primary-source comparison](https://github.com/Debrato2005/smolink/blob/269aed4bcfcbbf40ffea444f2e2a748013c862d4/cryptalis_demo/COMPETITIVE.md)
  is retained; no equivalent competitor execution or performance ranking is claimed.

These blockers are scoped to those deliverables. Broader native types, queries,
search, lifecycle, performance and deployment work remains active in the ledger.
Public package-index publication has no approval. The single-public-release policy
and independent human review requirements remain in force.

## Revisions and evidence

| Item | Exact saved identity / evidence |
|---|---|
| Frozen library | `v0.1.0a1`, `655d52271d90effb4df918a9547f61c89055fbc7`; preview branch `preview/smolink-20261101` |
| Frozen original-app demonstration | Smolink tag `cryptalis-demo-0.1.0a1-20261101-final`, `269aed4bcfcbbf40ffea444f2e2a748013c862d4` |
| Matched measurement code | Smolink `2a6622311359f470412c22c53907b5fe3623a370` |
| Maintenance measurement code / evidence | Smolink `e2c1be8f2001884d9e0bed14f3c24097590ff8b4` / `b84f54d2fde83105c3e208be1ef16af68dd54801` |
| Separate demo continuation | `demo/cryptalis-preview-followup-20261101`; [demo handoff](https://github.com/Debrato2005/smolink/blob/52b3d611cb7d7fca83e01f0b663e52c7515444c9/cryptalis_demo/HANDOFF.md) |
| Frozen package CI | [Run 41280665577](https://github.com/Debrato2005/cryptalis/actions/runs/41280665577), PR merge `ac6b86b`; [head-byte boundary](_reset/preview-hosted-boundary-20261101.json) |
| Strict-TLS tooling CI | [Run 41282107646](https://github.com/Debrato2005/cryptalis/actions/runs/41282107646), head `fb53e9f`, PR merge `e7ce82d`; [head-byte boundary](_reset/openbao-strict-tls-hosted-boundary-20261101.json) |
| Subsequent public-table DELETE RETURNING | Development head `75d095b`, PR 8; [run 41310161240](https://github.com/Debrato2005/cryptalis/actions/runs/41310161240), PR merge `fb65959`; [head-byte boundary](_reset/public-delete-returning-hosted-boundary-20261101.json) |

The subsequent [push-run follow-up](status.md#push-run-ci-follow-up) preserves two
failed push jobs that the corresponding PR passes did not expose. Its
[boundary](_reset/ci-push-followup-boundary-20261101.json) retains the native
catalog lock/drop reproduction, bounded assertion repair, cancellation guard
repair and sanitized-diagnostic controls. Check both push and PR runs when
resuming; the commit-specific PR helper filters out push events. The generic
GitHub workflow-runs collection exposes both.

Both hosted jobs pass for each run in the revision table. The separate push
failures above remain failures. Byte-bound receipts, explicit skips,
local Python 3.13 controls and artifact equality are in status and the
boundaries above. A documentation commit after those inputs is not a new runtime
verification. Earlier JSONB scope and evidence remain in [type history](history/types-2026-11.md)
and [compatibility](compatibility.md#jsonb-storage). The previous mixed handoff is
retained in [Git history](https://github.com/Debrato2005/cryptalis/blob/0e56438100eb7295f7e0f2601cebea74f2d02ed6/docs/handoff.md).

The separate [demo report](https://github.com/Debrato2005/smolink/blob/269aed4bcfcbbf40ffea444f2e2a748013c862d4/cryptalis_demo/REPORT.md)
retains original Swagger POST201, independent CF1 storage observation, current
edits, wrapping/payload rotations, source-stopped fresh restore, current-value
removal and an actual package-absent restart. Supplemental independent installed
application journeys cover search oracles, all three rotations and crash/resume
within their own public-provider fixture limits. Original Smolink application,
models, business queries and route handlers have zero changed files.

Keep the measured misses and limits visible:

- Point-read added p95 is 4.849 ms at concurrency 1, a MISS against 3 ms;
  concurrency 4 and 16 also miss. Destination equality/IN and search-key rotation
  remain outside this storage-only Smolink field profile.
- Destination bytes are 1.5114× native; observed total relation/index allocation
  is 2.5987×, including allocation history. No protected destination search index
  exists, so this does not qualify the indexed-storage target.
- [Actual local writer interruption](https://github.com/Debrato2005/smolink/blob/b84f54d2fde83105c3e208be1ef16af68dd54801/cryptalis_demo/evidence/writer-interruption-20261101/README.md)
  measures 4.071 s protect, 4.501 s wrapping rewrap and 12.169 s payload rotation
  from real-host stop through committed POST201. These are individual local
  observations, with lower-bound CPU and observed summed RSS, not production
  outage guarantees or repeated-tail evidence.

## What is pushed and what remains local

Both repositories contain the code, documentation and selected sanitized evidence.
The Git branches/tags above are pushed. [Package receipts](_reset/preview-package-20261101.tar.gz),
[hosted receipts](_reset/preview-hosted-receipts-20261101.tar.gz) and
[latest tooling receipts](_reset/openbao-strict-tls-hosted-receipts-20261101.tar.gz)
are retained in Cryptalis; application automation, screenshots and reports stay
in the separate Smolink repository and outside the library distribution.

The built distributions and preview kit are local prepared artifacts, not GitHub
Release assets or package-index uploads. [The kit manifest](../release/preview-kit-0.1.0a1.json)
binds the unchanged wheel/sdist to 27 guides and their documentation revision.
Verify hashes before installation or transfer.

| Machine-local location | Contents / handling |
|---|---|
| `/workspace/cryptalis` | Primary library checkout, `main` |
| `/workspace/cryptalis-production` | Separate development worktree, `development/post-preview-20261101` |
| `/workspace/smolink-preview` | Separate demo checkout and follow-up branch |
| `/workspace/scratch/cryptalis-preview-0.1.0a1-kit-c81e45a.tar.gz` | Complete prepared kit; SHA-256 `80b83e927f31da043184913ddbabc4e0a41e2e91582a0067d17c17f6a73e881f` |
| `/workspace/scratch/cryptalis-package-20261101/artifacts` | Inspected wheel/sdist, checksums and SBOM |
| `/workspace/scratch/smolink-preview-private` | Retained provider custody, role files, Project state and backups; private |
| `/workspace/scratch/smolink-writer-interruption-private-20261101` and its `-r2` sibling | Separate retained interruption-run custody; private |
| `/workspace/scratch/openbao-strict-tls-20261101` and its `-ready` sibling | Retained tooling-proof custody and private logs |

These paths describe this session, not prerequisites on another machine. Every
recorded local app/PostgreSQL/Redis/OpenBao run ended stopped; container shells
were retired after private-log retention. No run remains waiting for input.
Preserve required keys, wrappers, readers, state and backups. Current-data removal
did not authorize key retirement or backup destruction. Keep credentials, tokens,
raw dumps and private service/audit logs out of Git and public artifact archives.

## Resume implementation

1. Inspect the actual root, branch, status and remote; preserve unrelated work.
   Pull the selected branch normally. Continue on a development branch, preserving
   the frozen tags and existing receipt bytes.
2. Read [status](status.md), the affected [objective row](BUILD_CHECKLIST.md), its
   contract/procedure, [build order](build-guide.md), [decisions](decisions.md) and
   the [engineering playbook](../ENGINEERING_PLAYBOOK.md). Cross-cutting changes
   also require architecture, security, lifecycle and compatibility.
3. Follow the ledger's production critical path with bounded complete behaviors.
   Preserve all broader type/text/JSON/SQL, upgrade, migration, performance and
   deployment objectives plus the retained policy/audit/erasure research. Further
   unfinished features are not prerequisites for the delivered preview.
4. Reuse native PostgreSQL and installed-library application oracles. All
   PostgreSQL tests use `scripts/test_postgres.py`; a failed role probe stops the
   run until its cause and authorization are resolved. Never silently substitute
   a target or expose connection strings.
5. Use new absolute work directories; keep Python source stable during each
   wrapper run. Retain failures and skips. A previous-v14 JSONB reader control
   needs a genuine immutable older installation; a hosted skip is not a pass.
6. Verify, update the owning contract/status/ledger, commit and push each slice
   through normal Git workflow. Bind CI claims to the exact tested revision and
   inspect its receipts. Reuse verified fixes in main without permanent forks.

The original preview handoff update was documentation only. Subsequent
development changes have their own source-bound receipts in status. Frozen tags
and original preview evidence remain unchanged.
