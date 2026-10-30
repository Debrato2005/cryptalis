# Host context reference

[Documentation map](README.md) · [Current evidence](status.md)




The [operator walkthrough](walkthrough-migration.md) owns executable procedures.
This reference owns trusted factory/context inputs; the source definitions are
[cli_host.py](../src/cryptalis/cli_host.py). Host code is not sandboxed.
No context supplies implicit tenant, deployment, maintenance or destruction authority.

### Operational protection CLI

**IMPLEMENTED, bounded source and installed verification:** the initial workflow composes
existing Python operations. Public frozen `PlanningContext` and `ApplyContext` values
supply explicit host inputs. `--host-context MODULE:FACTORY` selects a trusted
synchronous zero-argument factory. There is no automatic context discovery or authority inference.

`PlanningContext` requires `engine`, `mapping`, `writers`, `search_reviews`, `keys`,
`runtime_role`, `target_id`, `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. `ApplyContext` requires `engine`,
`keys`, `pin` and `approval`. The factory supplies a fresh engine owned by
one CLI invocation. Accept only PostgreSQL/psycopg with `echo` False or None
and `hide_parameters` True. Dispose the engine on success and failure.
Host-code effects remain UNKNOWN.
Key resolvers must be synchronous, including callable objects. Recognized async
callables must fail context admission before command-managed database access.

Plan writes the existing immutable protection `MigrationPlan` artifact with exclusive
private output and atomic durable publication. Protection execution accepts protection plans only.
Resume and abort bind the requested operation before host loading. The default
target is PENDING. ACTIVE requires the supplied ACTIVATING host pin and maintenance
approval. The CLI cannot authenticate or infer host authority. Doctor's key-free
configuration tuple remains separate. Other lifecycle commands remain required future
work. No format, cryptographic or core protocol changes. See the
[status checkpoint](history/implementation-2026-10.md#operational-cli-protection-workflow-2026-10-24).
These dependencies do not supply host business authorization. No additional authority, workflow, or diagnostic service is required.

### Reverse and removal CLI

**IMPLEMENTED, bounded source and installed verification:** `plan --reverse SOURCE --out REVERSE` calls
existing reverse planning and persists its canonical artifact. The positional
manifest and `--reverse` are mutually exclusive. `apply REVERSE` and `rollback REVERSE`
share the existing reverse executor. `rollback` accepts only reverse artifacts.

| Trusted context | Required inputs |
|---|---|
| `ReversePlanningContext` | `engine`, `keys`, `source_pin`, `plaintext_runtime_role`, four measured costs/rates and explicit `restore` or None |
| `ReverseApplyContext` | `engine`, `keys`, `pin`, `approval`, `consent` |
| `RemovalContext` | `engine`, `pin`, `approval`, `consent`, `removal` |

The four measurements retain `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. The source pin names the ACTIVE
source. Execution and removal pins name the exact reverse operation and digest.
`consent` is `PlaintextApproval`. `removal` is `RemovalApproval`. An optional
`RestoreBinding` is explicit during planning and has no execution override.

Both execution spellings default to PLAINTEXT_PENDING. The host supplies the
PLAINTEXT_ACTIVATING pin before explicit PLAINTEXT_ACTIVE completion. UUID checks
precede host loading. Abort uses no keys and removes only pre-switch staging.
Removal requires PLAINTEXT_ACTIVE database state and the REMOVING host pin.
A terminal retry requires REMOVED authority and the same approvals. Removal
neither uninstalls the package nor deletes provider material. Existing engine,
publication, privacy and Doctor boundaries remain unchanged. See the
[verified checkpoint](history/implementation-2026-10.md#operational-cli-reverse-and-removal-2026-10-24).
Source and installed genuine fresh-target verification pass.

### Tenant-policy maintenance CLI

**IMPLEMENTED, bounded source and installed verification:** `tenants provision
plan|apply|activate|abort` reuses the maintenance tenant API and shared policy
transition runner. The trusted host supplies the approved typed UUID/Keyring;
there is no CLI-selected tenant/key authority. `TenantPlanningContext` carries
`engine`, `source_keys`, `source_pin`, `tenant_id`, `key_policy`,
`verify_rows_per_second` and `restore`. Distinct apply/activation contexts carry
`engine`, `keys`, `pin` and `approval`; abort carries `engine`, `source_keys`,
`source_pin` and `approval`. The existing engine and synchronous-resolver rules
apply. Apply retains the exact private successor durably before host loading or
database effects. Actual host publication and source-only cancel authority stay
external. See the [procedure](lifecycle.md#add-an-empty-tenant-policy-under-maintenance)
and [evidence](history/implementation-2026-10.md#tenant-policy-maintenance-cli-2026-10-28).

### Root-rewrap CLI

**IMPLEMENTED, bounded source and installed verification:** `keys rotate rewrap plan SOURCE --out P`
saves the existing proposal. `apply P --out A` saves exact `P.activation_plan`
before host loading and calls existing rewrap execution. It requires both source
and target key resolvers, including PENDING retry. `activate A` calls the shared
publication executor with target keys alone. `abort P` uses source keys and the
separately supplied source ACTIVE pin. Abort creates no target context.

| Trusted context | Required inputs |
|---|---|
| `RewrapPlanningContext` | `engine`, `source_keys`, `target_keys`, `source_pin`, `verify_rows_per_second`, `restore` |
| `RewrapApplyContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `RewrapActivationContext` | `engine`, `target_keys`, `pin`, `approval` |
| `RewrapAbortContext` | `engine`, `source_keys`, `source_pin`, `approval` |

Restore is an explicit binding or None. P retains its binding and lineage.
Apply requires successor PREPARED/PENDING authority bound to A. Activation requires
ACTIVATING/ACTIVE authority. Cancellation requires republished source ACTIVE authority
with writers stopped. An ACTIVE successor cannot be cancelled. Terminal ABORTED
retry preserves later source edits and refuses later supersession. Existing safe
engine, synchronous resolver, privacy and Doctor boundaries remain unchanged. See the
[verified checkpoint](history/implementation-2026-10.md#operational-cli-root-rewrap-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Payload-rotation CLI

**IMPLEMENTED, bounded source and installed verification:** `keys rotate payload` composes seven actions:
`plan SOURCE --out P`, `apply P`, `status ARTIFACT`, `seal P --out A`,
`switch P --activation A`, `activate A` and `abort P`.
All use an explicit trusted synchronous factory and the existing owned-engine contract.

| Trusted context | Required inputs |
|---|---|
| `PayloadPlanningContext` | `engine`, `source_keys`, `target_keys`, `source_pin`, four preparation measurements, `restore` |
| `PayloadApplyContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `PayloadStatusContext` | `engine`, `pin` |
| `PayloadSealingContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval`, `copy_rows_per_second`, `copy_wal_bytes_per_row` |
| `PayloadSwitchContext` | `engine`, `source_keys`, `target_keys`, `pin`, `approval` |
| `PayloadActivationContext` | `engine`, `target_keys`, `pin`, `approval` |
| `PayloadAbortContext` | `engine`, `source_keys`, `source_pin`, `approval` |

Preparation measurements retain `backfill_rows_per_second`, `verify_rows_per_second`,
`temporary_bytes_per_row` and `wal_bytes_per_row`. Restore is explicit None or an
existing binding. It enters only planning and stays embedded in P. Target keyrings
already contain the independent payload root. The CLI creates no root or provider.
P staging pins and A switch/publication pins bind distinct operation IDs and digests.

Apply stops at EXPANDED or BACKFILLED. Seal authenticates BACKFILLED shadows without
a new journal phase. Switch consumes externally retained exact P+A. First switch
uses both custody resolvers. A PENDING switch retry accepts both arguments but
uses target custody only after reciprocal proof. Activation is target-only. Abort
is source-only and refuses after switch. Key-free status dispatches P/A to existing
status APIs and reports NOT_PERFORMED verification. Copy, DDL, commit and publication
costs remain outside preparation chunk bounds. See the
[verified checkpoint](history/implementation-2026-10.md#operational-cli-payload-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Search-rotation CLI

**IMPLEMENTED, bounded source and installed verification:** prefix the same seven payload actions with
`keys rotate search`. Use exact `SearchPlanningContext`, `SearchApplyContext`,
`SearchStatusContext`, `SearchSealingContext`, `SearchSwitchContext`,
`SearchActivationContext` and `SearchAbortContext` types. Each requires the same
fields as its corresponding Payload context. Planning requires explicit restore
and four measurements. Sealing requires both copy measurements. Status is key-free,
activation has only target keys, and abort has only source keys/source ACTIVE pin.

P uses search-rotation/v1 or v2. A has kind `search_rotation`, transition/v4 or v7.
Validate `search_rotation_plan_digest`, reserved A UUID and artifact kind before host
loading. Keep P/A pins distinct. First switch uses both custody resolvers. Its
PENDING retry accepts both arguments but invokes only target custody after reciprocal
proof. Publication is target-only. Cancellation is source-only and refuses after switch.
Shared payload seal, durability and external artifact-retention rules apply unchanged.
Search rotation changes searchable CF1 nonces/terms while retaining exact payload
custody and storage-only CF1 bytes. No new core or cryptographic construction follows. The
[payload context table](#payload-rotation-cli) supplies the shared field contract.
See the [verified checkpoint](history/implementation-2026-10.md#operational-cli-search-rotation-2026-10-24).
Source and installed genuine adopted-target verification pass.

### Initialization CLI

**IMPLEMENTED, bounded source and installed verification:** `init --host-context MODULE:FACTORY --out DECLARATION`
accepts an exact frozen, repr-disabled `InitializationContext` with required
`engine`, `mapping`, `declaration: bytes`, `writers` and `search_reviews` fields,
plus optional `queries=()` containing at most 128 SELECT samples.
Use the existing fresh owned PostgreSQL/psycopg engine with safe logging and disposal.
Reject an existing output or symlink before host loading.

Apply the existing byte bound and strict parser before canonicalization. Reuse
`doctor.preflight` with no keys or application-row inspection. Publish canonical bytes
only after manifest_schema PASS and PASS for any supplied query samples. Use exclusive private publication with file/parent
fsync. Report SHA-256 of the exact saved canonical bytes.

Successful scope is `initialization`, with status UNKNOWN and the unchanged embedded
`doctor/v1` report with scope `pre_adoption`. Six unobserved checks and aggregate status remain UNKNOWN.
The artifact result has no transition phase or operation UUID. Compiler inspection
effects are NONE, while host-code effects remain UNKNOWN. No planning, key or
deployment authority follows.

`doctor --initialization-context MODULE:FACTORY` reuses this exact context and
inspection path. It writes no declaration artifact and accepts no plan, pin,
restore binding, separate connection file or second host context. The host must
return a fresh engine each time. Schema/query incompatibility exits 3; unavailable
inspection, cleanup or output exits 4; invalid inputs exit 2. A successful bounded
inspection exits 0 while aggregate and unobserved checks remain UNKNOWN.
Query samples are structurally inspected, never executed or included in output.
They do not establish complete route coverage or runtime authorization.
The existing `--pre-adoption` tuple-based form remains supported. See the
[verified checkpoint](history/implementation-2026-10.md#operational-cli-initialization-2026-10-24).
Source and installed initialization verification pass.

### Public key-policy status metadata

**IMPLEMENTED, bounded source and installed verification:** optional `status --key-policy-context
MODULE:FACTORY` accepts exact KeyPolicyStatusContext(operation_id, plan_digest,
policies). Admit protection/activation or reverse artifacts. Refuse preparation P
before host loading. Require exact native policy values, matching domain and the
complete pinned tenant-policy digest set. Bound metadata to 64 policies, 32
wrappers per policy and 16 MiB aggregate sealed bytes. Existing policy canonical
bytes and wrapper order remain unchanged.

Report public identities, selected generations and wrapper SHA-256 values. Emit
no wrapper bytes or keys. DIGEST_MATCH proves local agreement only. Host authority,
provider availability, material correctness, completeness and recovery remain
unqualified. Doctor, retained contexts and no-option status preserve their contracts.
See the [checkpoint](history/implementation-2026-10.md#pinned-public-key-policy-status-2026-10-24).

### Retained-backup status metadata

**IMPLEMENTED, bounded source and installed verification:** optional `status --host-context MODULE:FACTORY`
accepts exact frozen `RetainedObligationsContext(operation_id, plan_digest, records)` and
`RetainedBackupObligation(backup_id, source_plan, dump_sha256, reader_sha256, drill_sha256)`.
Admit exact source/predecessor lineage and restore bindings before database access.
Limit records to 64 and aggregate source bytes to 16 MiB. Reader/drill references
can be None. Contexts have no keys. Doctor and omitted-context status remain unchanged. See the
[source checkpoint](history/implementation-2026-10.md#declared-retained-backup-status-references-2026-10-24).
The [integrated checkpoint](history/implementation-2026-10.md#integrated-defensive-hardening-2026-10-24)
includes genuine fresh-cluster metadata controls. Declared references do not prove
file availability or recovery.

### Original HTTP operational qualification

**VERIFIED, bounded source and installed qualification:** join existing CLI workflows to the original
26-file HTTP/JWT/local-SMTP workload. Preserve all pinned source bytes. Use only the
existing `get_db` override and reload its full dependency/router graph after successors.
Run retained-user HTTP/password/inactive/Item-cascade controls after publication. Finish requests,
background mail and fixture SMTP work before maintenance. Reuse the existing five
process-recovery checkpoints. Product and helper bytes remain unchanged in this test-only join. See the
[qualification checkpoint](history/implementation-2026-10.md#original-http-operational-cli-journey-2026-10-24).
