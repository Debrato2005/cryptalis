# Product build checklist

This file is the product engineering ledger. It tracks the 34 product objectives
against the actual product source, tests, and evidence.
[Status](status.md) owns current capability claims. [Architecture](architecture/README.md),
[security](security.md), [lifecycle](lifecycle.md), and [compatibility](compatibility.md)
own their contracts. This file does not replace those owners.

## Status vocabulary

| Term | Meaning |
|---|---|
| SPECIFIED | The final product requires the behavior; it is not implemented. |
| IMPLEMENTED | Product source exists. Verification may be incomplete. |
| VERIFIED | Executed evidence supports the named behavior at the recorded revision and cell. |
| UNKNOWN | Required evidence is absent. This is not a pass. |
| BLOCKED | An external resource, decision, or approval is required. |

The first public release targets the full SRS and all 34 objectives with production qualification.
Internal development checkpoints preserve partial progress without reducing that scope.
Use the [competitive capability matrix](research/capability-matrix.md) and the
[release direction](decisions.md#comprehensive-first-public-release-2026-10-23) to choose complete E2E work.
Completed capabilities and real application journeys measure progress.
No objective is complete until its acceptance evidence and applicable gate pass.

## Current boundary

- The original authenticated tenant application now exercises the public CLI
  entrypoint after genuine fresh recovery, with an actual v16 successor and
  independently retained host publication. Both phases pass from the inspected
  installed wheel through latest-value package-free HTTP restart. The source
  fixture cell also passes both phases. See the
  [fresh CLI checkpoint](status.md#restored-tenant-cli-application-journey-2026-10-29).

- The integration combines reviewed reporting/scalars/INSERT/online work with
  continuation security and tenant lifecycle. Both persisted Date codecs remain
  explicit; real legacy ordinal backup recovery passes from source and wheel.
  The 45-module artifact and installed HTTP/fresh journeys pass. The whole source
  suite passes 2,993 test calls and eighteen subtests, with 75 explicit skips;
  GitHub CI passes for that checkpoint. All gates remain UNKNOWN. See the
  [combined boundary](status.md#consolidated-implementation-checkpoint-2026-10-29).

- Tenant maintenance now has operational plan/apply/activate/abort commands,
  host-only policy authority and durable successor retention before effects.
  The 96-check source matrix and two new integrated/installed journeys pass;
  three existing adopted-profile opt-ins skip. Source v15 is exercised; the
  later fresh CLI checkpoint above adds restored v16 application evidence. See the
  [checkpoint](status.md#tenant-policy-maintenance-cli-2026-10-28).

- The installed int4 keyword identifier now passes genuine fresh recovery in
  both layouts, exact CHECK restatement, latest-value removal and package-free
  native restart. The default-name source fresh control also passes. See the
  [fresh checkpoint](status.md#keyword-identifier-fresh-recovery-2026-10-28).

- PostgreSQL keyword-named protected columns now pass exact storage/search
  admission, both layouts and latest-value native exit. Integrated source,
  final installed identifier and affected search checks pass. Bounds,
  dependencies and explicit restored restatements remain enforced; no gate
  promotion follows. See the
  [checkpoint](status.md#postgresql-identifier-admission-correction-2026-10-28).

- Explicit maintenance tenant-policy addition now passes state/cancellation and
  old-reader controls, source/installed original HTTP first-write approval,
  all rotations, genuine fresh adoption and latest native exit. Old policy and
  ciphertext remain exact; the Python API retains O(N)/global-pause limits.
  COUNT remains separate unfinished work and all gates remain UNKNOWN. See the
  [checkpoint](status.md#maintenance-tenant-policy-provisioning-2026-10-28).

- Exact tenant type/pinned membership now refuses before host key lookup. The
  149-check source matrix and rebuilt installed tenant recovery pass. A separate
  129-check actual-SDK protocol bundle includes 22 SDK cases with transport denied.
  The warm 10k equality observation misses 3 ms; no performance fix is claimed.
  Further tenant/count work is preserved unverified after an account quota block.
  All seven gates remain UNKNOWN. See the
  [checkpoint](status.md#sdk-protocol-and-early-tenant-admission-checkpoint-2026-10-28).

- The authenticated tenant HTTP source/installed journeys pass genuine fresh
  recovery, all rotations, exact owner/admin page oracles, transactional cascades
  and HTTP reads of each latest Item after import-denied native restart. Explicit
  host integration and the unfinished dynamic-owner boundary are recorded.
  Runtime source/wheel binding, reproducible artifact inspection and both
  installed DATE layouts pass. The interrupted broad run remains incomplete;
  follow-up matrices retain their exact scope. All gates remain UNKNOWN. See the
  [checkpoint](status.md#verified-continuation-checkpoint-2026-10-28).

- The internal storage-only DATE candidate passes 31 frozen source checks and
  both genuine fresh-cluster layouts, with all three rotations alongside text,
  latest-value exit and old-reader refusal. Independent external DATE app,
  artifact/cost and human qualification remain pending. See the
  [checkpoint](status.md#date-storage-construction-and-lifecycle-2026-10-27).

- Attached SELECT functions now have finite native class/name/namespace/dispatch
  admission before keys or driver. Supported ordinary calls resolve explicitly
  in `pg_catalog`; native special syntax remains intact. The isolated 233-check
  adapter/native-clause/cancellation bundle and corrected scoped review pass.
  Arbitrary database functions remain unsupported and all gates UNKNOWN. See the
  [checkpoint](status.md#finite-native-select-functions-2026-10-27).

- Direct AWS/development rewrap now proves exact root recovery under unchanged
  context and stable target identity. The isolated 107-check protocol bundle and
  scoped agent review pass. One additional target unwrap is required. Live KMS
  and all production gates remain UNKNOWN. See the
  [checkpoint](status.md#direct-provider-rewrap-recovery-proof-2026-10-27).

- Resumed the audited remote checkpoint. The isolated release cell now pins and
  hash-verifies the build backend, including explicit isolation/configuration
  controls. Fifteen artifact controls and byte-identical wheel/sdist rebuilds pass.
  Runtime dependencies stay unchanged. This is bounded build evidence; controlled
  publication, provenance and all seven gates remain UNKNOWN. See the
  [checkpoint](status.md#resumption-and-frozen-build-backend-2026-10-27).
- Online capture has opt-in bounded crypto workers and adaptive row counts.
  Actual worker overlap, unchanged byte limits, atomic failure and authenticated
  resume pass. SQL execution remains serial. See the
  [worker checkpoint](status.md#parallel-crypto-and-adaptive-online-batches-2026-10-28).

- Mapped dictionary INSERT now returns native tuples, public columns and mapped
  entities. Paging, input ordering, identity/refresh, per-field prepared-input
  authentication and existing fault controls pass. See the
  [RETURNING checkpoint](status.md#tuple-and-entity-insert-returning-2026-10-28).

- Initial online capture now covers the admitted storage scalars as well as
  text. Native edits, interrupted resume, abort, fencing, role transfer and
  current-value removal pass. See the [online scalar checkpoint](status.md#online-capture-for-storage-scalars-2026-10-28).

- UUID-valued fields now pass both layouts, sync/async current-value storage,
  mixed interrupted rotations, retained-reader refusal and fresh-cluster native
  exit. A matched 10k cost profile records the fixed storage overhead and warm
  latency. See the [UUID checkpoint](status.md#native-uuid-value-storage-2026-10-28).

- Finite Date storage now passes native sync/async protection, all three mixed
  rotations, fresh-cluster recovery, retained-reader refusal and package-free
  native exit. Current Date/int2/int4/int8 profiles publish real column overhead
  and warm read costs; local integer storage admission accepts those costs.
  See the [typed scalar checkpoint](status.md#finite-date-storage-and-scalar-cost-decision-2026-10-28).
  Other scalar/structured types and their query operators remain incomplete.

- Native protected non-NULL counts and equality-backed distinct counts now have
  local PostgreSQL evidence. Distinct groups require one provable tenant scope.
  Public DISTINCT with encrypted filters also retains native behavior. The
  [assignment checkpoint](status.md#local-assignment-explanation-and-inspection-profile-2026-10-28)
  records the exact evidence and remaining aggregate limits. OBJ-QUERY-02 stays partial.

- Installed query preflight passes 40 focused controls and the original HTTP
  fresh-recovery journey. Twelve captured SELECT structures pass admission.
  An unsupported pattern refuses before migration. The reproducible artifact and
  package-free HTTP exit pass. Overall route coverage and all gates stay UNKNOWN. See the
  [checkpoint](status.md#installed-application-query-diagnostics-2026-10-24).


- Doctor now checks supplied SELECT structures before migration without keys,
  attachment or application-row reads. The original HTTP workload supplies twelve
  admitted structures and one diagnosed unsupported-pattern control. Source
  recovery and 72 affected controls pass. The installed checkpoint extends this evidence. See the
  [checkpoint](status.md#supplied-application-query-preflight-2026-10-24).


- The original 26-file HTTP application now completes genuine fresh restore,
  all three rotations, latest-value removal and package-free HTTP restart.
  The existing public-slot SQLModel profile also passes. The installed wheel
  stays unchanged. See the [checkpoint](status.md#original-http-application-fresh-recovery-2026-10-24)
  and [matrix](build-guide.md#automated-application-qualification-matrix).


- Three matched 10k integer profiles pass with unchanged installed product code.
  All six local point observations meet 3 ms added p95. Column-only storage
  measures 22.5×/11.75×/6.375× native; the indexed-column target is not evaluated.
  Cost approval and full admission remain pending. See the
  [observation](status.md#integer-storage-cost-observation-2026-10-24).

- The installed default/state candidate passes 367 affected checks. All six
  integer width/layout default journeys and a Boolean control pass fresh
  adoption and native exit. Artifact and reader checks pass. Full type admission
  remains pending. See the
  [checkpoint](status.md#integer-literal-default-installed-checkpoint-2026-10-24).

- Literal integer defaults and native valid-write ORM state pass 190 initial and
  96 current source controls. Genuine minimum-int64 root/payload rotation,
  restore/adoption and native exit pass with public slots. Old readers retain
  the exact default-free boundary. The installed checkpoint now extends this
  source evidence.
  See the [checkpoint](status.md#integer-defaults-and-orm-state-source-checkpoint-2026-10-24).

- The installed integer candidate passes 663 affected checks. All six integer
  width/layout fresh-cluster journeys and a Boolean control pass adoption,
  rotation and native removal. Reproducible artifact checks pass. Full type
  admission remains pending. See the
  [checkpoint](status.md#integer-installed-lifecycle-checkpoint-2026-10-24).

- Internal integer storage passes 233 source checks, including native plan timing,
  async writes, batch error order, rotations and real process recovery. Fresh int64
  public-slot and Boolean restore/removal controls pass. The later installed
  checkpoint extends this evidence. Full type admission remains pending. See the
  [checkpoint](status.md#integer-storage-source-checkpoint-2026-10-24).

- Native integer width/route failure timing is measured before protected admission.
  Nine initial controls pass under the default plan. Prepared generic plans can
  return zero rows for an unmatched overflow, as the newer checkpoint records. This admits
  no protected integer type. See the
  [oracle](status.md#native-integer-failure-oracle-2026-10-24).

- Public policy status and invalid SDK-return cleanup pass 168 source and 168
  installed checks. The reproducible current wheel passes 45-input/40-module/44-file
  verification. Genuine installed direct-generation export/restore passes 1/19 controls.
  See the [checkpoint](status.md#public-policy-status-installed-qualification-2026-10-24).

- Pinned public key-policy status passes 113 source checks, including 25 new controls.
  Generation metadata and retained backup references remain key-free after removal.
  Digest agreement does not qualify custody. See the
  [checkpoint](status.md#pinned-public-key-policy-status-2026-10-24).

- Invalid native-coroutine KMS responses are closed before the existing safe failure.
  The source protocol and actual-SDK local profile pass 55 checks. See the
  [checkpoint](status.md#invalid-kms-coroutine-response-cleanup-2026-10-24).

- Integrated defensive hardening passes 74 source and 357 installed tests, with one
  inherited fresh setup skip. Genuine installed export/restore pass one and 24 tests,
  with one generation-specific setup skip. Twelve installed local SDK cases also pass.
  Metadata references remain host declarations. See the
  [integrated checkpoint](status.md#integrated-defensive-hardening-2026-10-24).

- Synchronous KMS client admission rejects recognized async SDK methods before use.
  Source and installed protocol/SDK checks pass. Live AWS and release gates
  remain UNKNOWN. See the [checkpoint](status.md#synchronous-kms-sdk-admission-2026-10-24).

- Protected search rejects custom binary dispatch before rewrite and key resolution.
  Corrected source verification passes 185 native controls with no skips. Async
  SELECT admission precedes preparation. See the
  [checkpoint](status.md#exact-protected-search-expression-dispatch-2026-10-24).

- Retained-backup status passes 131 source tests, including 23 new controls.
  Integrated installed and fresh-cluster checks also pass. Metadata completeness,
  availability and recovery remain UNKNOWN. See the [checkpoint](status.md#declared-retained-backup-status-references-2026-10-24).

- The original 26-file HTTP operational join passes two source and two installed
  tests with no skips. Six HTTP boundaries, 24 loopback messages per journey,
  five actual SIGKILL/resume checkpoints and latest-value package-free HTTP exit pass.
  At `53fd91b`, all 218 Python hashes stay stable. The 217 prior files and historical
  artifact bytes remain unchanged. Two database/four application receipts bind the
  [final boundary](_reset/http-cli-final-boundary-20261024.json). No rebuild or current
  fresh-cluster/full-suite qualification is claimed. See the
  [verified checkpoint](status.md#original-http-operational-cli-journey-2026-10-24).

- Initialization CLI passes 94 focused source tests with four inherited genuine-fresh
  setup skips. The unchanged six-file application consumes its private canonical
  declaration through planning, the same five SIGKILL checkpoints and latest-value
  native exit. The affected-source suite passes 373 tests with no skips. Reproducible
  artifact checks pass. The actual wheel passes 467 tests with four inherited
  genuine-fresh setup skips, including the unchanged initialization/application journey.
  Three current database receipts retain 217 stable hashes in the
  [final boundary](_reset/init-cli-final-boundary-20261024.json). Prior search and
  fresh-cluster evidence retain `c612727`. See the
  [verified checkpoint](status.md#operational-cli-initialization-2026-10-24).

- Search CLI passes 79 focused source tests with four genuine-fresh setup skips.
  The unchanged six-file application passes five actual SIGKILL checkpoints,
  payload2/search2 publication, exact storage frames, original CRUD/search/uniqueness,
  Boolean values and latest-value native exit. The affected-source suite passes 449
  controls with no skips. Reproducible artifact checks pass. Genuine source export
  and separate-cluster restore pass one test each through v2/v7 and native exit.
  The actual wheel passes 528 tests with four genuine-fresh setup skips, including
  the unchanged five-checkpoint application. Installed genuine export/restore pass one
  test each. Seven current database receipts retain 216 stable hashes in the
  [final boundary](_reset/search-cli-final-boundary-20261024.json). Prior payload evidence
  stays at `f303a18`. See the
  [verified checkpoint](status.md#operational-cli-search-rotation-2026-10-24).

- Payload CLI passes 70 focused source tests with three genuine-fresh setup skips.
  The unchanged six-file application completes four actual SIGKILL checkpoints,
  source-only cancellation, authenticated identical resealing, target-only publication
  and latest-value native exit. Five earlier failed/incomplete runs retain their scope.
  The affected-source suite passes 492 controls with one direct-generation collection
  skip. Reproducible artifact checks pass. Genuine source export and separate-cluster
  restore pass one test each, including explicit-binding refusal and v2/v6 native exit.
  The actual wheel passes 562 tests with three genuine-fresh setup skips and one
  direct-generation collection skip, including the unchanged four-checkpoint application.
  Installed genuine export/restore pass one test each. Seven current database receipts
  retain 215 stable hashes in the [final boundary](_reset/payload-cli-final-boundary-20261024.json).
  Search CLI remains required next. See the
  [verified checkpoint](status.md#operational-cli-payload-rotation-2026-10-24).

- Root-rewrap CLI passes 54 corrected source tests with two genuine-fresh setup
  skips. The unchanged six-file application passes three actual SIGKILL checkpoints,
  source-only cancellation during target outage, exact-A resume, target-only activation
  and latest-value exit. Earlier parser and publication-exit failures remain historical.
  The affected-source suite passes 363 controls. Reproducible artifact checks pass.
  Genuine source export and separate-cluster restore pass one test each, including
  wrong-binding refusal before either resolver and latest-value native exit.
  The actual wheel passes 417 tests with two genuine-fresh setup skips, including
  the original application journey. Installed genuine export/restore pass one test
  each. Seven current database receipts retain 214 stable hashes in the
  [final boundary](_reset/rewrap-cli-final-boundary-20261024.json). Payload CLI remains
  required next, then search CLI. See the
  [verified checkpoint](status.md#operational-cli-root-rewrap-2026-10-24).

- The reverse/removal CLI passes 41 focused source tests with one genuine-fresh
  case skipped. The unchanged six-file application passes actual protection and
  reverse SIGKILL/resume, explicit plaintext publication, approved removal and
  latest-value package-free exit. The affected-source suite passes 260 existing
  CLI and native reverse controls. Genuine source export and separate-cluster
  restore pass one test each, including binding refusal before keys. Reproducible
  artifact checks pass. The actual wheel passes 301 tests, including the unchanged
  original application, with one genuine-fresh setup skip. Installed genuine
  export/restore pass one test each. Seven current database receipts retain 213
  stable hashes in the [final boundary](_reset/reverse-cli-final-boundary-20261024.json).
  Root-rewrap CLI remains required next, followed by payload/search CLI work. See the
  [verified checkpoint](status.md#operational-cli-reverse-and-removal-2026-10-24).

- The initial source implementation of plan/protection apply/resume/abort and
  explicit ACTIVE completion passes 14 CLI controls and one original application
  journey. The expanded candidate passes 21 and fails one async callable resolver
  admission control. Revised validation passes all 22 source tests. Existing affected
  CLI routes pass 189, and reproducible artifact checks pass. The actual installed
  wheel passes 211 controls, including the unchanged original application journey.
  Three current receipts bind 212 stable hashes in the
  [final boundary](_reset/operational-cli-final-boundary-20261024.json) at `4373e5e`.
  Reverse/removal source evidence follows in the new checkpoint above. The existing core APIs and production gates retain their boundaries.
  See the [operational CLI contract](status.md#operational-cli-protection-workflow-2026-10-24).

- Late expression-statistics refusal is REPRODUCED in two legacy native controls.
  The shared catalog guard now covers all layouts. The first expanded candidate
  passes 42 and fails one reverse-resume control. A separate first reverse-expansion
  control also fails. Revised guards pass 44 focused source controls, including
  both reverse failures and exact repair. The affected-source suite passes 536.
  The revised wheel passes 583 installed controls, the original three-field
  fresh-v6 journey and four legacy sequence/adoption controls. At `7f231fc`, seven
  database receipts bind 208 stable hashes. Earlier failed candidates remain
  historical. See the
  [final boundary](_reset/legacy-expression-statistics-final-boundary-20261024.json).
  Earlier application, full-suite and artifact evidence retain their
  recorded boundaries. See the
  [defensive checkpoint](status.md#legacy-expression-statistics-admission-2026-10-24).

- The unchanged three-field SQLModel application passes source and installed
  genuine fresh-v6 adoption, direct-binding search rotation and latest-value
  package-free exit. Recorded target public slots stay unchanged. Earlier full-suite
  and artifact evidence retain their exact boundaries. See the
  [application checkpoint](status.md#original-three-field-sqlmodel-fresh-adoption-2026-10-24)
  and [final boundary](_reset/sqlmodel-public-slots-final-boundary-20261024.json).

- The explicit public-slot layout is implemented as lock/v6 with restore/v3.
  The recorded focused profile passes 25 local/compiler/recovery controls.
  At `6cb926e`, source TEXT fresh-target profiles pass six each, with and without
  an owned sequence. The 4025210f8957 wheel passes release checks at that checkpoint.
  Earlier formats retain their default selection and DROP/RENAME behavior.
  Source VARCHAR and installed sequence-bearing TEXT also pass six each.
  The actual wheel passes 294 affected/application controls and one original
  three-field batched SQLModel lifecycle with 207 stable hashes. Installed VARCHAR,
  legacy sequence/adoption and original legacy application profiles also pass.
  The full source regression passes 2,503 tests plus 116 subtests, with 16 skips
  and 49 known warnings. See the
  [public-slot checkpoint](status.md#public-column-slot-preservation-2026-10-24)
  and [final boundary](_reset/public-slots-final-boundary-20261024.json).

- A native-only column identity oracle preserves original public attnums/order
  through forward/reverse ALTER TYPE USING staged values. It passes rollback,
  locking, metadata, sequence and native failure controls on one three-row table.
  Fixed public CF1-like bytes qualify no product layout or crypto. A versioned
  product layout and restored-slot authority were unimplemented at that checkpoint. See the
  [native oracle](status.md#native-column-identity-oracle-2026-10-24).

- Owned-sequence preservation passes 201 revised source controls, 269 installed
  affected/application controls and four fresh-target cases in each profile.
  Lock/v5 records the exact native inventory and preserves
  the same object through protection and removal. Restore/v2 maps new OIDs through
  direct generation and repeated adoption. Both original six-file SQLModel
  adoption paths pass with the installed wheel. The full source regression passes
  2,478 tests plus 116 subtests. Earlier failures remain in the
  [owned-sequence checkpoint](status.md#owned-sequence-preservation-and-restore-2026-10-24).

- Direct restore-binding payload/search planning now produces exact v2 proposals
  while retaining original source identity and unchanged v6/v7 activations.
  All 19 native controls pass, including refusal before providers, source-only
  cancellation, CLI/process/COMMIT recovery and a second real adoption.
  Source VARCHAR and installed TEXT each pass 19. Source and installed affected
  suites pass 606 and 68. The unchanged six-file SQLModel app passes direct
  search rotation in source/installed runs and its legacy installed path.
  Latest-value package-free exit passes. See the
  [direct-binding checkpoint](status.md#direct-restore-binding-generation-planning-2026-10-24).

- The unchanged six-file SQLModel template now passes genuine fresh-cluster
  adoption, root v5 and search v7 publication, original email search/uniqueness,
  latest-value removal and an import-denied native restart. Source and actual
  installed-wheel stages pass with 198 stable Python hashes and unchanged product
  bytes. This adds bounded CRUD evidence; HTTP and production email admission
  keep separate boundaries. See the
  [searchable adoption journey](status.md#original-searchable-sqlmodel-adoption-2026-10-24).

- Eleven adopted-search fresh-target controls pass mixed searchable/storage
  fields, current search/uniqueness, v7 publication and later v5/v6 successors
  through latest-value package-free exit, fault and collision rollback, process
  recovery and lost cutover COMMIT replies. Source VARCHAR also passes 11;
  source and installed affected suites pass 496 and 68. The final installed wheel
  passes 11 search and 17 adopted-root controls, plus the unchanged Smolink
  root/payload journey. The later original SQLModel adopted-search journey adds
  bounded application evidence. See the
  [adopted search checkpoint](status.md#search-rotation-after-adopted-lineage-2026-10-24).

- Payload rotation after an adopted rewrap passes 12 fresh-target controls each
  for source TEXT/VARCHAR and installed TEXT.
  Versioned v6 activation retains restore lineage through cancellation, process/
  COMMIT recovery and later v5 rewrap. The unchanged Smolink source and installed journeys also
  complete adopted payload generation 2 to 3, original ASGI/JWT/Redis work and
  latest-value package-free exit. The full primary run passes 2,430 tests plus
  18 subtests; the installed wheel passes 126 affected controls. See
  the [adopted payload checkpoint](status.md#payload-rotation-after-adopted-lineage-2026-10-24).

- The unchanged 38-file Smolink application now completes restored-target root
  rewrap cancellation without target custody, new v5 publication, original async
  HTTP/ASGI, JWT and ORM work with real Redis, and latest-value package-free exit.
  The actual installed wheel passes both source and fresh-target stages. Exact
  frames and native index identities remain unchanged. See the
  [Smolink adopted-target journey](status.md#smolink-adopted-target-rewrap-journey-2026-10-24).

- Root rewrap after genuine restore/adoption passes 17 controls each for local
  PostgreSQL 16 source TEXT/VARCHAR and installed-wheel TEXT profiles.
  Versioned proposals and successors preserve flat restore lineage,
  ciphertext and search indexes. Cancellation, process/COMMIT recovery, a
  second database adoption and latest-value package-free removal pass. The full
  primary run passes 2,430 tests plus 18 subtests. The actual installed wheel
  passes 103 affected/application controls. See the
  [adopted rewrap checkpoint](status.md#adopted-target-root-rewrap-2026-10-24).

- Separate Sessions match native behavior with 1/4/16 scheduled sync/async workers.
  A four-connection pool records checkout peaks of 1/4/4 and returns all connections.
  Cancellation on a one-connection pool rolls back the writer and releases a queued
  neighboring tenant. [Source Python 3.12](_reset/session-isolation-native-first-20261024.json)
  and the [unchanged installed Python 3.13 wheel](_reset/session-isolation-installed-20261024.json)
  each pass 13 controls. Multiprocessing, saturation and latency/resource budgets
  remain open. See the
  [bounded session checkpoint](status.md#bounded-session-pool-isolation-2026-10-24).

- The original SQLModel HTTP/JWT and local SMTP
  [journey](_reset/sqlmodel-http-complete-journey-physical-final-20261024.json) passes through
  native and attached operation, latest-value removal and an import-denied HTTP
  restart. All [26 pinned files](_reset/sqlmodel-http-journey-application-physical-final-20261024.json)
  stay unchanged. Native and attached mail phases each capture four localhost
  messages. User.email has fixture-only opaque UUID128 equality/uniqueness under
  explicit single tenancy. User.full_name and User.is_active also receive protection.
  Browser, deployment, external mail and HTML escaping remain unqualified.
  The full primary regression passes 2,422 tests plus 18 subtests. The actual
  installed wheel passes 134 affected/application controls. See the
  [HTTP checkpoint](status.md#original-sqlmodel-http-journey-2026-10-24).

- Boolean storage has typed CF1 descriptors and native sync/async controls.
  Both unchanged SQLModel profiles preserve defaults and latest False values.
  Mixed rotations and a fresh-cluster restore/removal journey pass.
  The first full run exposed outdated test clock names. All 43 affected
  lease controls pass after correction. The final full run passes 2,361 tests
  plus 18 subtests. The actual installed wheel passes 41 controls. See the [Boolean checkpoint](status.md#boolean-storage-checkpoint-2026-10-23).

- The combined search/Doctor checkpoint passes 2,322 primary tests plus 18
  subtests, with 174 stable Python hashes. Installed-wheel checks pass the
  searchable app, 27 CLI controls and both local SDK application journeys.
  The fixture-lifetime failure and its deterministic correction remain recorded.
  All seven production gates stay UNKNOWN. See the
  [installed integration](status.md#installed-searchable-application-integration-2026-10-23).

- The unchanged SQLModel application now exercises fixture-scoped encrypted email
  equality/IN/uniqueness and latest-value exit. Deterministic implicit default
  collation has bounded native admission. The pre-adoption CLI shares Python
  preflight and keeps host-code effects UNKNOWN. Separate local SDK evidence
  covers asynchronous Smolink. See [current status](status.md).

- Smolink now completes manifest preflight, committed-process interruption/resume,
  root rewrap, payload rotation, genuine fresh-cluster recovery and latest-value
  package-free exit. The SQLModel template also completes the pre-adoption Doctor
  journey. Source and actual installed-wheel runs verify these bounded
  storage-only application profiles. See the
  [recovery checkpoint](status.md#manifest-first-application-recovery-checkpoint-2026-10-23).

- Optional SQLModel 0.0.48 has bounded synchronous PostgreSQL bridge/template
  evidence. The SQLModel-absent full primary run passes 2,282 tests and 18
  subtests. The actual installed optional cell passes 14 controls. A current
  performance failure and unchanged-source follow-up remain separate, with cause
  UNKNOWN. See the
  [SQLModel checkpoint](status.md#optional-sqlmodel-template-checkpoint-2026-10-23).

- Native VARCHAR mapped dictionary UPDATE preserves the tested native assignment,
  error and zero-match behavior through a private per-group carrier. The combined
  primary regression passes 2,281 tests and 18 subtests. Current release and
  installed-wheel Python 3.13 application checks pass separately. See the
  [VARCHAR UPDATE checkpoint](status.md#native-varchar-mapped-update-checkpoint-2026-10-23).

- The installed wheel passes the pinned Smolink URL lifecycle on Python 3.13.12
  with exact runtime pins and binary psycopg. Product/runtime imports use the
  new disposable site. App/test dependencies use a read-only fallback. See the
  [installed Python 3.13 checkpoint](status.md#installed-wheel-python-313-checkpoint-2026-10-23).

- The local fork regression holds the keyring mutex while sync/async preparation
  refuses inherited keys. Fresh child and retained parent keys still work.
  Product crypto stays unchanged. See the
  [fork checkpoint](status.md#keyring-held-mutex-fork-checkpoint-2026-10-23).

- Wheel Python/dependency metadata now matches project declarations through standard
  packaging parsers, with duplicate-sensitive dependency comparison. The final
  suite passes 14 tests and 60 subtests. See the
  [metadata checkpoint](status.md#artifact-dependency-metadata-checkpoint-2026-10-23).

- The combined defensive source passes 2,250 tests and 18 subtests, with four
  skips, 48 existing warnings and 154 stable Python hashes. Current release,
  unchanged Smolink, all six 10k read targets and isolated storage pass separately.
  All seven production gates remain UNKNOWN. See the
  [combined defensive checkpoint](status.md#defensive-projection-and-delete-integration-checkpoint-2026-10-23).

- The earlier post-admission 10k profile at `3a21096` passes all six latency targets
  and 1.52483× isolated storage, with 150 stable Python hashes. This is warm
  synchronous TEXT evidence with public fixture keys. See the
  [earlier 10k checkpoint](status.md#post-admission-10k-profile-checkpoint-2026-10-23).

- Expanded entity/table SELECT admission now applies type, operation and owned-lineage
  rules to selected columns and descendants. Both final affected cells pass 284
  checks. Earlier native frame-exposure and benign mapped-expression failures stay
  recorded. See the
  [expanded SELECT checkpoint](status.md#expanded-select-projection-checkpoint-2026-10-23).

- Finite mapped DELETE preserves native results and transactions under exact
  tenant/record authority. Ordinary flush DELETE also refuses custom AST nodes.
  The scoped integration passes 55 checks. Both final flush bundles pass 65.
  The earlier alternate restart failure and its isolated correction stay separate.
  See the [DELETE checkpoint](status.md#mapped-delete-admission-checkpoint-2026-10-23).

- Historical checkpoint `351789e` reports 2,167 passes and two failures,
  with 18 passed subtests, four skips and 149 stable hashes. Its corrected
  early-refusal and unchanged CLI timeout controls pass in isolation.
  The original timeout cause stays UNKNOWN. The later combined defensive
  checkpoint supplies the full follow-up. See the
  [earlier combined checkpoint](status.md#combined-integration-checkpoint-2026-10-23).

- Scoped TEXT dictionary UPDATE now preserves native groups, NULL/omission,
  repeated IDs, zero matches and transactions under exact tenant/record proofs.
  Shared attachment checks also refuse identity variants before key resolution.
  Both affected cells pass 143 cases. See the
  [bulk UPDATE checkpoint](status.md#scoped-mapped-bulk-update-checkpoint-2026-10-23).

- Payload/search staging and paired-frame verification retry actual expiry
  once per row under both exact policies. Both 83-case cells pass, including
  20 new no-effects/recovery controls. Source-only and final checks retain
  terminal expiry. See the
  [rotation checkpoint](status.md#rotation-row-lease-recovery-checkpoint-2026-10-23).

- Planning rejects dialect-specific record/tenant type variants. Two native
  controls reproduce SQL-transformed UUIDs before the refusal fix. The corrected
  planning regression passes 105 cases. Attachment checks are separate. See the
  [identity checkpoint](status.md#identity-variant-planning-checkpoint-2026-10-23).

- Doctor/status inspection failures retain the public operation UUID and fixed
  remedies for known role/pin refusals. Seven new controls and the 128-case
  affected run pass, with read-only snapshots and private-value redaction.
  See the [diagnostic checkpoint](status.md#actionable-inspection-failures-checkpoint-2026-10-23).

- Restored-frame scans retry actual expiry once with exact retained-policy
  checks. Nine integrated scan/admission checks and ten public restore controls
  on each genuine TEXT/VARCHAR fresh cluster pass. Failed custody remains
  `KeyUnavailable` before effectful probes. See the
  [restore checkpoint](status.md#restored-frame-lease-recovery-checkpoint-2026-10-23).

- An optional AWS KMS SDK bridge pins the full key ARN, response algorithm
  and exact public context. Both protocol/integration runs pass 86 checks;
  the isolated actual-SDK profile and its integration pass 12 cases each.
  The current installed wheel passes one original SQLModel application journey
  with local SDK outage, authentication refusal and recovery controls.
  Live AWS custody and production provider qualification remain UNKNOWN.
  See the [provider checkpoint](status.md#optional-aws-kms-sdk-adapter-checkpoint-2026-10-23).
- Protection and decrypt-back now retry one unfinished row after key lease
  expiry, before SQL, progress or digest effects. Four previous-product controls
  fail; all 16 new controls pass. Existing primary checks pass 111 cases and
  the alternate cell passes 127. Provider failure, changed policy and a second
  expiry still stop the operation. The full primary run passes 2,034 tests
  and 18 subtests, with three skips, 48 existing warnings and 137 stable hashes.
  See the [lease checkpoint](status.md#bounded-row-lease-recovery-checkpoint-2026-10-23).
- A current pinned 10,000-row profile meets local added-p95 targets for point
  scalar, equality tuple and IN-20 tuple reads: 1.6294, 2.0107 and 2.5330 ms.
  Isolated name-column/equality-index storage measures 1.5248× native for
  unique 53-byte names. Both 136-file receipts stay stable. This warm synchronous
  TEXT cell uses public fixture keys and does not qualify entity, million-row,
  remote-provider or deployment performance by itself. The subsequent entity
  extension meets local targets at 1.2622/2.6119/2.8613 ms added p95 for
  point/equality/IN-20. Its separate receipts keep stable 136-file hashes.
  A separate 100k-row run also meets all six targets. Entity added p95 measures
  1.2667/1.7083/2.5670 ms and isolated storage measures 1.5296× native.
  The later prepared million-row run completes the full product transition.
  It meets all six read targets, with entity added p95 at
  2.4646/2.1569/2.5735 ms and isolated storage at 1.4372× native.
  Final 137-file hashes stay stable. Process CPU/elapsed/peak RSS are recorded
  separately from server resources.
  See the
  [current performance checkpoint](status.md#current-pinned-performance-checkpoint-2026-10-23).
- Mapped bulk INSERT now returns one direct protected scalar through native
  Row/scalar results and page handling. Exact prepared-input proofs reject
  changed frames, NULL presence or row context. Current/future page mutation,
  lease use, native error precedence, savepoint recovery and typed identity
  controls pass. The affected primary run passes 100 cases.
  The final alternate cell passes 103 cases, including TEXT/VARCHAR current-value
  removal and unchanged Smolink. Final 135-file hashes stay stable.
  The full primary regression passes 2,018 tests and 18 subtests, with three
  separate-environment skips and 48 existing warnings at that final bundle.
  Reproducible archives and all 36 installed files pass. See the
  [scalar RETURNING checkpoint](status.md#mapped-protected-scalar-returning-checkpoint-2026-10-23).
- The wrapper now records ordinary calls, subtests, setup, teardown and
  failed/skipped collection outcomes separately. Historical counters retain
  their original meaning. The focused reporter/preflight run passes 24 cases.
  The alternate cell also passes 24 cases. The full primary run passes
  1,978 tests and 18 subtests, with three separate-environment skips and
  48 existing warnings. All 132 Python hashes stay stable and match the worktree.
  This full run includes the final shared-driver buffer fix.
  See the [receipt checkpoint](status.md#test-receipt-checkpoint-2026-10-23).
- Implemented scope includes native text/VARCHAR storage, equality/IN,
  tenant uniqueness, sync/async attachment, maintenance protection,
  decrypt-back/removal, and separate root-rewrap, payload and search rotation.
  Payload/search preparation uses sealed activation and shared publication.
  Restore adoption uses the existing host-approved binding. Effective privilege,
  ancestry and metadata checks precede effectful restore probes or key work.
  Read-only Doctor repeats runtime attachment admission in one snapshot and
  reports six unobserved boundaries plus its aggregate result UNKNOWN.
  ACTIVE/PENDING status repeats effective privilege admission.
  CLI status also reads payload/search preparation with its own pin and source
  identity. Every recorded preparation keeps `runtime_metadata_matches: false`, NOT_PERFORMED and
  exit 3. Preparation status repeats effective privilege admission.
  Attached mapped dictionary INSERT now preserves bounded native grouping,
  NULLs, explicit typed context, uniqueness and transaction/savepoint behavior.
  Its final driver guard checks actual payload bytes and row context.
  The shared guard now captures native flush/read and RETURNING-page driver
  values before later cursor callbacks and checks them at final dispatch.
  First/unique effective callback order is required. Cursor observers must
  register on the engine after attachment and retain SQL and values.
  See the [current checkpoint](status.md#shared-driver-event-checkpoint-2026-10-23).
- The shared guard checkpoint passes 1,974 tests and 18 subtests in the broad
  primary run, with three separate-environment skips and 48 existing warnings.
  A subsequent exact-buffer fix passes 227 affected cases and 63 final
  alternate cases including the unchanged Smolink lifecycle. These final runs
  retain stable 131-file hashes. Reproducible archives and all 36 installed
  package files pass. The broad run predates only that narrow buffer fix and
  corrected attachment docstring. Fresh-cluster/full-alternate profiles retain
  their earlier revision boundaries.
- The bulk checkpoint passes the full primary regression: 1,953 tests and
  18 subtests, with three separate-environment skips and 48 existing warnings.
  Stronger final driver controls pass all 44 bulk cases at the final source
  bundle. The alternate Python 3.13 / SQLAlchemy 2.0.51 cell passes those cases
  plus the pinned unchanged Smolink lifecycle, 45 cases. Both final receipts
  retain stable 130-file hashes. Reproducible archives and all 36 installed
  package files pass. The full alternate cell and fresh-cluster profiles were
  not rerun for this route.
- The preparation-status checkpoint passes 369 affected CLI and rotation cases.
  Eight phase/purpose cases pass again with actual runtime credentials.
  Reproducible archives and all 36 installed package files pass, including CLI.
  The earlier Doctor checkpoint passes 88 focused cases plus two final cleanup controls.
  Search TEXT/VARCHAR backups each pass one export and 30 restore cases,
  including Doctor on an adopted runtime. Reproducible archives and all 36
  installed package files pass, including CLI startup and Doctor help.
  Full regression passes 1,887 tests and 18 subtests, with three separate-environment
  skips. Its 125 Python hashes belong to that earlier checkpoint.
  The prior search checkpoint passes 92 focused cases, including independent crypto,
  native search/uniqueness/current-value removal, mixed rotation lineage,
  lost COMMIT replies and SIGKILL recovery. Search TEXT/VARCHAR backups each
  pass one export and 29 restore cases. Older protection, rewrap and payload
  profiles also pass at the same Python hashes. Its earlier full regression passes
  1,869 tests and 18 subtests, with three separate-environment skips.
  Reproducible archives and all 36 installed package files pass, including CLI.
- Current execution uses local PostgreSQL 16 and Python 3.12.3 with SQLAlchemy
  2.1.3. The current bounded alternate/app rerun is recorded above. The earlier
  full alternate and [external adoption evidence](status.md#pinned-smolink-adoption-2026-10-22)
  retain their exact revision boundaries. Private-role probes and Git writes use scoped approved
  execution. Default sandbox restrictions remain in place.
- The import ledger and dated status checkpoints preserve earlier evidence.
  Reproducibility includes wheel RECORD, license metadata and an SBOM.
  Signing, publication identity and independent rebuild remain UNKNOWN.
  Other non-text types, advanced predicates, online migration, adopted-search qualification,
  production custody/retirement, authenticated host authority and independent
  review remain open. All seven qualification gates remain UNKNOWN.


Operator pause: development is stopped pending **Continue Cryptalis**. The [preservation audit](status.md#preservation-checkpoint-and-operator-pause-2026-10-24) retains the current verification, dependency finding and continuation point. All 34 objectives remain in scope. All seven production gates remain UNKNOWN.

## Objective ledger

Requirement text is abbreviated. The full definitions remain in the research
`CRYPTALIS_BUILD_CHECKLIST.md` and the final blueprint; no requirement is dropped.

| ID | Requirement (abbreviated) | Product status | Implemented mechanism and evidence | Open gap / next action |
|---|---|---|---|---|
| OBJ-SEC-01 | Encrypt before PostgreSQL; prove at SQL/driver boundaries | VERIFIED, bounded | `crypto/cf1.py`, `sqlalchemy.py`; slice 2/3 receipts in `docs/_reset`; real runtime-role tests | Broader writer/auth/provider boundaries; independent review |
| OBJ-SEC-02 | Bind tenant, field, row, generation; reject malformed/swapped frames | VERIFIED, bounded | CF1 AAD, descriptor binding, sync/async tamper tests | Collision assumptions and composition review |
| OBJ-SEC-03 | Authorization, result lineage, tenant isolation, parameterization | PARTIAL | Tenant-scoped sessions, requested-point checks, typed errors; expanded entity/table SELECT type, operation and owned-lineage admission; finite mapped DELETE binds compiled/final parameters to original tenant/record authority | Host authorization is external; audit remaining ORM routes |
| OBJ-SEC-04 | Detect plaintext bypass through ORM, bulk, SQL, COPY, jobs, logs | PARTIAL | Guarded attachment rejects raw SQL/COPY/opaque writes and unsafe engine logging before connect/key access; writer inventory at plan; effective runtime privilege refusal before restore probes/keys, repeated at planning, active admission, Doctor, ACTIVE/PENDING status, shared maintenance and host-phase-selected reverse execution | Complete route inventory; identity variants now refuse during planning; deployment enforcement is unverified |
| OBJ-SEC-05 | Isolate keys and bound nonces, leases and cache lifetime. Preserve fork safety | VERIFIED, bounded | `crypto/keys.py` checks policy, cache expiry and fork refusal. Local outage, revocation and lease drills pass on both SQLAlchemy cells. An actual Linux fork with the mutex held passes sync/async refusal in [main integration](_reset/keyring-held-mutex-fork-integration-20261023.json). Fresh child keys and retained parent keys still work | Remote cancellation, usage limits, production custody |
| OBJ-SEC-06 | Reduce equality/frequency/access leakage with documented trade-offs | SPECIFIED | Equality leakage is declared; no stronger profile admitted | Threat-model and benchmark a lower-leakage profile; six-gate admission |
| OBJ-SEC-07 | Independent red-team, crypto, adapter, provider, supply-chain review | BLOCKED | None | Assign independent reviewers; do not self-certify |
| OBJ-QUERY-01 | Exact equality, `IN`, scoped uniqueness, NULL logic, races | VERIFIED, bounded | `_sqlalchemy_search.py`, slice 4 receipt; native concurrency tests | Keep grammar reconciliation current |
| OBJ-QUERY-02 | Ordinary SQL correctness: NULL predicates, aliases, joins, projections | PARTIAL | Native sync/async controls; textual reference admission and simple negative/NULL predicates; expanded entity/table/descendant admission preserves authenticated outputs and safe public expressions. Bounded protected counts, tenant-scoped distinct counts, public count filters/windows and public DISTINCT with encrypted filters pass [installed controls](status.md#local-assignment-explanation-and-inspection-profile-2026-10-28) | Continue finite native-oracle matrix; general Boolean NOT, protected grouping and protected joins remain unadmitted |
| OBJ-QUERY-03 | Ordering, ranges, prefix/text search, aggregates, other types | PARTIAL | Bounded TEXT/VARCHAR, Boolean, signed integer, finite Date and UUID storage; non-NULL/distinct counts and authenticated DISTINCT reuse admitted representations. Current lifecycle/cost receipts retain their exact boundaries | Range/order/pattern profiles, other aggregates and structured JSON remain unadmitted. Refusal does not complete the objective |
| OBJ-QUERY-04 | INSERT/UPDATE/DELETE, bulk, RETURNING, triggers, cascades, savepoints | PARTIAL | Scoped tenant-column TEXT/VARCHAR dictionary UPDATE with native plan-sensitive VARCHAR assignment/errors, transaction/group semantics and exact ordered input proofs; ORM flush writes and attached sync/async mapped dictionary INSERT, with native scalar, direct-tuple and mapped-entity RETURNING, per-field prepared-input proof and native paging/identity/refresh; native NULL/grouping, typed context, errors and savepoints; exact driver/page/input-result checks; finite mapped TEXT/VARCHAR tenant/record DELETE with native results and transactions; custom DELETE AST refusal also covers ordinary flush; 55 scoped integration checks and both 65-case flush bundles pass | Qualify UPDATE/DELETE RETURNING, upserts, broader DML/defaults and each trigger/cascade effect separately |
| OBJ-QUERY-05 | Versioned compatibility corpus and read-only scanner | PARTIAL | Native-vs-attached tests and receipts; [supplied SELECT preflight](status.md#installed-application-query-diagnostics-2026-10-24) reuses runtime admission before migration and diagnoses original HTTP query structures without rows or keys | Complete automatic query/write route inventory and reconcile current revisions |
| OBJ-LIFE-01 | Deterministic plan/apply/verify with diagnostics | VERIFIED, bounded | `migration.py` plan/apply/verify; compiler inspection maps SQLAlchemy and direct psycopg errors to safe SQLSTATE; slice 5 receipts; read-only Doctor/status failure controls preserve operation identity, safe known remedies and UNKNOWN observations | Broader schema and failure boundaries |
| OBJ-LIFE-02 | Resumable, atomic, byte-bounded backfill with verification | VERIFIED, bounded | Journal, advisory lock, chunks, crash/resume tests; one expiry-specific local row retry with policy checks and atomic failure controls in protection/decrypt-back | Exact memory/WAL bounds remain host inputs |
| OBJ-LIFE-03 | Near-zero-downtime migration with capture and catch-up | PARTIAL | [Bounded initial capture](status.md#bounded-online-initial-protection-2026-10-24), [tenant-scoped lifecycle](status.md#tenant-scoped-online-lifecycle-2026-10-24), row-lock backfill, durable catch-up fence and reversible role transfer; unchanged [original HTTP online journey](status.md#original-http-application-online-adoption-2026-10-24) and [genuine fresh recovery with all rotations](status.md#original-online-http-fresh-recovery-2026-10-24) pass from source and installed wheel | Production pause measurement, deployment fencing, future type coverage and independent review |
| OBJ-LIFE-04 | Parallel/adaptive migration without lost or duplicate work | PARTIAL | Bounded online crypto workers, one transactional SQL writer, ordered results, adaptive row counts within approved row/byte limits; actual four-thread overlap, atomic worker failure, unchanged-byte resume and full authentication pass in the [worker checkpoint](status.md#parallel-crypto-and-adaptive-online-batches-2026-10-28) | Worker-scaling/resource measurements and multiple database executors remain unqualified |
| OBJ-LIFE-05 | Decrypt-back current edits; preserve schema behavior; package-free exit | VERIFIED, bounded | `deprotection.py` implements `cryptalis.reverse/v1`: staged plaintext, verified backfill, transactional switch, recorded constraint/index/collation restoration, guarded activation, approved removal, and terminal-state assertions; seven lifecycle cases pass on both profiles; an independent three-model application completes protect/search/modify/decrypt-back/remove and a package-free restarted process performs native CRUD; the same reverse completes on an adopted restored cluster with the binding; lock v2 captures and restores protected-column comments, statistics targets, storage, compression, options, column grants, constraint/index comments and extended statistics; grants are applied to the ciphertext column at protection; [lock/v5 owned-sequence preservation](status.md#owned-sequence-preservation-and-restore-2026-10-24) records 81 focused source passes and four restore/v2 fresh-target cases at the initial checkpoint; its revised query passes 201 source and 269 installed controls after 19 initial read-only statement failures; revised source/installed fresh profiles each pass four; the full source regression passes 2,478 tests plus 116 subtests; native catalogs verify captured metadata through fresh-cluster restore and adopted removal; terminal removal refuses late metadata drift and retains the journal on failed retirement; the [explicit v6/v3 public-slot layout](status.md#public-column-slot-preservation-2026-10-24) passes source/installed fresh profiles, the original three-field one-database lifecycle and 2,503 full-source tests plus 116 subtests | Original three-field fresh-v6/direct-binding journey, broader external application scope, retained-native |
| OBJ-LIFE-06 | Rollback, restore, stale pin refusal, RPO/RTO, disaster drills | PARTIAL | Older-snapshot and stale-pin refusals; reverse abort, pin/state ordering, corrupt-frame and disabled-guard refusals; isolated-cluster plaintext and protected restore with frame recovery and loud authority refusal; `cryptalis.restore/v1` adoption issues a binding after approval, frame authentication, schema comparison, and behavioral probes; the adopted cluster then attaches, reverses, and removes; local provider outage/revocation/lease drills keep the committed prefix and fail closed; restored-frame expiry recovery passes exact-policy, no-effects refusal and genuine fresh-cluster TEXT/VARCHAR controls; pinned unchanged Smolink now passes committed-process interruption/resume, root rewrap, payload rotation, genuine fresh-cluster adoption and latest-value package-free exit | Host-authenticated fencing/quarantine, RPO/RTO measurement |
| OBJ-LIFE-07 | Three separate rotation workflows | PARTIAL | Payload/search pure row-step expiry recovery passes 20 new native controls inside both 83-case cells; source-only observations and outer lease checks remain terminal. The [11 adopted-search controls](status.md#search-rotation-after-adopted-lineage-2026-10-24) pass mixed-field publication, later v5/v6 successors, faults, process/COMMIT recovery and current-value exit; source VARCHAR and installed TEXT each pass 11, and source/installed affected suites pass 496/68; the [unchanged original SQLModel journey](status.md#original-searchable-sqlmodel-adoption-2026-10-24) now verifies adopted root/search publication, original search controls and latest-value exit from source and installed wheel. [Direct restore-binding generation planning](status.md#direct-restore-binding-generation-planning-2026-10-24) passes 19 controls each for source TEXT/VARCHAR and installed TEXT, including refusal before providers, cancellation, CLI/process/COMMIT recovery and a second real adoption; source/installed affected suites pass 606/68, and the unchanged SQLModel direct source/installed and legacy installed journeys pass through latest-value exit. [Adopted payload rotation](status.md#payload-rotation-after-adopted-lineage-2026-10-24) passes 12 controls each for source TEXT/VARCHAR and installed TEXT, plus the unchanged Smolink journey through generation-3 publication and latest-value exit. Root-rewrap after adopted restore now passes 17 genuine fresh-target controls, including cancellation, actual process/COMMIT recovery and a second database adoption; [pinned unchanged Smolink](status.md#smolink-adopted-target-rewrap-journey-2026-10-24) also passes adopted-target cancellation without target custody, new v5 publication, original async workload and latest-value package-free exit; successor cutover and shared activation, byte preservation, exact lineage, pending retry/cancellation, process/COMMIT recovery and repeated-rewrap decrypt-back/removal; source-pinned payload planning, durable shadows, source-only cancellation, immutable sealed target proof, atomic cutover/shared publication, mixed custody lineage/current-value removal and native process/COMMIT recovery; fresh-cluster TEXT/VARCHAR payload-backup adoption after later edits, independent selected-generation decoding and old-generation refusal; sealed search reindex, one active namespace with retained readers, native uniqueness/rollback, mixed search/payload/rewrap/search lineage and fresh-cluster search backups | External provider/authority qualification |
| OBJ-LIFE-08 | Production KMS with outage/revocation/cost evidence | BLOCKED | Local development provider plus optional exact-context AWS KMS SDK bridge. 86 protocol/CF1 checks and 12 isolated actual-SDK cases. current installed-wheel original SQLModel application passes local SDK outage, authentication refusal and recovery. unchanged asynchronous Smolink also passes local SDK expiry/outage/authentication recovery and latest-value package-free exit; no live AWS qualification | Authorized provider account and independent review |
| OBJ-LIFE-09 | Install, upgrade, decommission, clean uninstall | PARTIAL | Importable package; approved in-database removal retires reverse-owned objects after decrypt-back; a package-free restarted application process performs native CRUD | Versioned upgrade/removal and broader external application evidence |
| OBJ-DX-01 | Minimal model/query changes; one manifest and one attach | IMPLEMENTED | `compile_protection`, `attach`, CLI inspection, bounded ACTIVE Doctor, read-only protection, payload/search preparation and reverse `status`; [initial operational CLI](status.md#operational-cli-protection-workflow-2026-10-24) source and installed controls and the unchanged original application pass plan/apply/resume with explicit host publication; [reverse/removal source controls](status.md#operational-cli-reverse-and-removal-2026-10-24) include dual process interruption and latest-value exit | Broader status coverage |
| OBJ-DX-02 | Read-only `cryptalis doctor` with explicit UNKNOWN results | PARTIAL | ACTIVE runtime Doctor and shared Python diagnostic use one read-only repeatable snapshot for exact plan/pin/restore, runtime identity, target, lineage, effective privileges and schema; six unobserved boundaries and aggregate UNKNOWN; native refusal, no-key, cleanup and output evidence; Python preflight reuses the read-only compiler for manifest/schema diagnostics with no application rows or keys. Schema PASS leaves aggregate/unobserved checks UNKNOWN; CLI uses an explicit trusted host factory with host-code effects UNKNOWN and 135 native regression cases | Broader query/write route inventory, key/provider diagnostics and operational prerequisites |
| OBJ-DX-03 | Real FastAPI/SQLModel app plus a second independent app | PARTIAL | 38 original Python files stay unchanged. Pinned Smolink 498d24b runs its original FastAPI app without source/model/query edits. HTTP URL creation/refusals, real Redis, ORM CRUD and protect/decrypt-back/remove pass. A fresh import-denied process passes native CRUD. Protection covers only Url.destination. Installed Python 3.13 uses exact runtime pins and binary psycopg, with a read-only app/test fallback. The three-model application retains separate evidence. The earlier optional SQLModel 0.0.48 profile passes pinned unchanged template 0.10.0 CRUD/protection/removal with User.full_name only. Native exec/AutoString controls and package-free restart pass in the [bounded SQLModel profile](status.md#optional-sqlmodel-template-checkpoint-2026-10-23). The unchanged template additionally exercises fixture-only encrypted User.email equality/IN/global uniqueness in explicit single tenancy, with current-value exit. Both pinned profiles now use manifest preflight in source and current installed-wheel runs. The [Smolink recovery journey](status.md#manifest-first-application-recovery-checkpoint-2026-10-23) adds real interruption/resume, rotations and fresh-cluster latest-value exit. The original HTTP/JWT/user/item routes and local SMTP journey now pass with 26 unchanged pinned files. User.email has fixture-only opaque UUID128 equality/uniqueness under explicit single tenancy. User.full_name and User.is_active also receive protection. Native and attached mail phases each capture four messages. Latest-value removal and an import-denied original HTTP restart pass in the [HTTP journey](status.md#original-sqlmodel-http-journey-2026-10-24). The separate [six-file searchable adoption journey](status.md#original-searchable-sqlmodel-adoption-2026-10-24) now passes genuine restore/adoption, root v5, search v7, original email equality/IN/uniqueness and latest-value removal/import-denied restart in source and installed-wheel runs. Its [direct-binding variant](status.md#direct-restore-binding-generation-planning-2026-10-24) also passes source/installed search rotation and latest-value exit without an intermediate rewrap, while the legacy installed route remains verified | Broader protected fields and application suites, remaining SQLModel paths, browser/deployment operation and external mail |
| OBJ-DX-04 | Normal ORM identity, loading, sessions, pooling, async | PARTIAL | Bounded sync/async adapter and search tests. [Current identity/DELETE controls](_reset/http-uuid-delete-physical-final-20261024.json) cover native UUID lookup, cache reuse, errors/rollback and finite unprotected mapped DELETE. The original HTTP journey retains native ORM identity and authorization behavior. Separate-session sync/async 1/4/16 profiles also preserve tenant values, rollback and pool reuse. One-connection cancellation releases a queued neighboring tenant. Source and installed-wheel [controls](status.md#bounded-session-pool-isolation-2026-10-24) pass | Broader loading, pool invalidation, concurrent workload and framework coverage |
| OBJ-DX-05 | Complete quickstart, threat model, leakage, recovery docs | PARTIAL | README, architecture, security, lifecycle, walkthroughs; [professor guide](professor-guide.md) with architecture/search/lifecycle diagrams and measured performance graphs; [local commands](local-development.md) | Keep docs tied to admitted APIs and evidence |
| OBJ-PERF-01 | Continuous native vs protected latency/resource measurements | PARTIAL | Revision-pinned 10k/100k/1m scalar/tuple and full-entity profiles with matched runtime roles, full migration/ACTIVE attach, raw paired samples, isolated storage and 100k/1m process CPU/RSS; historical million-row receipts retain prior source boundaries | Larger scale, cold/concurrent/tail/WAL/provider measurements |
| OBJ-PERF-02 | Profile-guided optimization without security loss | PARTIAL | Membership projection correction on 2026-10-09; per-inspection lineage reuse with a paired target/candidate CPU benchmark, native-lineage controls and an explicit early-match cost increase in the [assignment profile](professor-guide.md#query-inspection-optimization) | Continue whole-path profiling; no unverified speed claims |
| OBJ-PERF-03 | Multithreading/multiprocessing/async at 1/4/16/saturation | PARTIAL | Bounded functional isolation for separate Sessions across 1/4/16 scheduled threads/tasks. Native and attached checkout peaks are 1/4/4 with pool size four. Queued-tenant cancellation, rollback and pool reuse pass in source and installed-wheel profiles. [Source observations](_reset/session-isolation-native-first-20261024.xml) and [installed observations](_reset/session-isolation-installed-20261024.xml) record the peaks | Multiprocessing, saturation, latency/resource budgets and broader workload qualification |
| OBJ-PERF-04 | Added p95 targets and growth path | PARTIAL | Revision-pinned 10k/100k/1m warm scalar/tuple and full-entity reads meet local 3ms/8ms targets; isolated column plus equality index measures 1.5248x/1.5296x/1.4372x for 53-byte names | Current latency failure and unchanged-source follow-up need causal classification. Larger scale/remote-provider/concurrent qualification and write/pause budgets remain open |
| OBJ-OPS-01 | Reproducible wheel/sdist, SBOM, provenance, reviewers | PARTIAL | `pyproject.toml`, `uv.lock`, `scripts/release_check.py`; [2026-10-21 receipt](_reset/release-check-20261021.json) shows identical repeat-build hashes, verified wheel `RECORD`, license metadata, CycloneDX 1.5 SBOM, and clean-venv import/CLI; the [combined defensive source receipt](_reset/defensive-projection-delete-release-20261023.json) binds 33 wheel modules and 37 installed-file checks to its 38-file source bundle; [dependency metadata controls](_reset/artifact-dependency-metadata-green2-20261023.json) compare wheel Python/dependency declarations with project metadata through standard parsers; the [current recovery release](_reset/doctor-recovery-release-20261023.json) verifies repeat archives, CLI, 36 product modules and 40 installed files against 41 current source hashes | Independent rebuild, signed provenance, vulnerability scan, publication identity, upgrade/uninstall matrix, independent review |
| OBJ-OPS-02 | Recoverable source/evidence and traceability | PARTIAL | Git history and `docs/_reset` receipts | Durable archive and fresh restore |
| OBJ-RESEARCH-01 | Source-backed comparative research with repeatable evidence | ONGOING | Research repository provenance; source-access and fallback rules in `AGENTS.md` | Preserve failed alternatives and provenance links |
| OBJ-RESEARCH-02 | One coherent working candidate that passes all gates | PARTIAL | Implemented scope above | Continue integration; all seven gates UNKNOWN |

## Import ledger

Boolean storage: typed descriptors and lock/v4 reuse CF1 and the common lifecycle.
The [current checkpoint](status.md#boolean-storage-checkpoint-2026-10-23) records
native controls, unchanged SQLModel journeys, mixed rotations, fresh-cluster
recovery and the final full regression. No production gate passes.

| Date | Research reference | Mechanism | Product files | Evidence | Status |
|---|---|---|---|---|---|
| 2026-10-23 | Search rotation and retained readers | Immutable search P/v1 and activation v4, fresh authenticated terms under unchanged payload custody, shared atomic cutover and one query namespace | Rotation planner, common generation engine, search crypto preparation and bound adapter admission | 92 focused cases, real COMMIT/SIGKILL recovery; [native](_reset/search-rotation-native-first-20261023.json); search TEXT/VARCHAR each one export and 29 restore cases; [backup](_reset/fresh-cluster-restore-20261023-11.json); 36 installed files and CLI startup | VERIFIED for listed local controls; [full regression](_reset/search-rotation-full-20261023.json) passes 1,869 plus 18 subtests; production custody/authority/retirement and seven gates remain unqualified or UNKNOWN |
| 2026-10-23 | Reverse runtime boundary | Host-pin-selected effective privileges before staging/publication/retirement, plaintext planning, actual absent-journal REMOVED exception | Shared reverse plan/state admission and native role/grant controls | 19 initial failures, 20 passing controls; [native](_reset/reverse-runtime-first-20261023.json); full 1,809 plus 18 subtests; [full](_reset/reverse-runtime-full-20261023.json); TEXT/VARCHAR each one export and 28 restore cases; [recovery](_reset/fresh-cluster-restore-20261023-9.json); reproducible archives and 35 installed files with CLI startup | VERIFIED for recorded privilege observations and preserved native edits; production credential retirement, host authority and seven full gates remain unqualified or UNKNOWN |
| 2026-10-23 | Payload-backup recovery and runtime admission | Current ACTIVE backup values, exact source/P/A proof and generation, effective native privilege checks before probes/keys | Restore and shared migration admission, native fresh-cluster profiles | TEXT/VARCHAR each one export and 28 restore cases; older rewrap/VARCHAR 26 plus one skip; seven ordinary refusal controls; [recovery](_reset/fresh-cluster-restore-20261023-6.json); full 1,789 plus 18 subtests; [full](_reset/restore-runtime-full-20261023.json); 35 installed files and CLI startup | VERIFIED for recorded local controls; adopted-target rotation, search reindex and all seven gates remain open or UNKNOWN |
| 2026-10-23 | Sealed payload cutover | Deterministic host-pinned A, repeated paired checks, atomic public-frame copy and guard/lineage exchange, target-only retry and shared publication | `rotation.seal_payload_rotation`, `switch_payload_rotation`, migration v3 admission and bounded publication verifier | 37 final native lifecycle/adversarial/recovery cases; [native](_reset/payload-cutover-final-native-20261023.json); independent copy wall/WAL interval observations; full regression 1,782 plus 18 subtests; [full](_reset/payload-cutover-full-20261023.json); 35 installed package files and CLI startup | VERIFIED for named local controls; search reindex, fresh-cluster payload-backup qualification and seven full gates remain open or UNKNOWN |
| 2026-10-23 | Payload staging and cancellation | Immutable P shadows, locked atomic progress, preserved source frames/indexes, authenticated resume and source-only abort | `rotation.apply_payload_rotation`, `status_payload_rotation`, `abort_payload_rotation`, shared maintenance mechanics | 26 native execution/recovery cases, including multi-table/tenant, actual COMMIT reply loss, SIGKILL/fresh restart and rollback after native writes; [recovery](_reset/payload-stage-recovery-20261023.json), full regression 1,745 plus 18 subtests; [full](_reset/payload-stage-full-20261023.json), 34 installed package files and CLI startup | VERIFIED for named controls; sealed A, cutover/publication and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Payload-generation preparation | Source-pinned read-only proposal, exact retained roots/wrappers, one new independent monotonic payload root, unchanged search custody, whole-row logical budget and measured costs | `rotation.plan_payload_rotation`, `PayloadRotationPlan`, shared proposal validation and native controls | 163 focused planner/root-rewrap/crypto controls; full regression 1,719 plus 18 subtests; final matching-preparation-pin refusal; [focused](_reset/payload-plan-focused-20261023.json), [full](_reset/payload-plan-full-20261023.json), [final](_reset/payload-plan-final-admission-20261023.json) | VERIFIED for named read-only controls; staged/sealed payload execution and seven full gates remain SPECIFIED or UNKNOWN |
| 2026-10-23 | Pending root-custody cancellation | Source ACTIVE host authority, exact pending/proposal checks, atomic guard release/source restoration/ABORTED marker, target-outage recovery | `rotation.abort_rewrap`, native cancellation controls and public-fixture worker | 177 expanded lifecycle cases; final 52 cancellation/cutover cases including multi-table tenants, post-DDL rollback, terminal COMMIT loss and independent process retry; [final](_reset/rewrap-abort-final-20261023.json) | VERIFIED for named local controls; adopted-restore cancellation, full rotation and seven gates remain open or UNKNOWN |
| 2026-10-23 | Native root-custody cutover | Immutable transition/v2 successor, shared executor/guards/activation, exact predecessor admission | Migration, rotation, reverse inventory and native recovery worker | 165 focused lifecycle cases; 60 expanded recovery/planner cases including terminal COMMIT-reply loss and fresh-process activation; full regression 1,647 plus 18 subtests; rewrapped text/VARCHAR each pass one export and 15 fresh-cluster restore cases; [full](_reset/rewrap-execution-full-20261023.json), [recovery](_reset/rewrap-execution-recovery-20261023.json), [backup](_reset/fresh-cluster-restore-20261023-2.json) | VERIFIED for named local controls; complete rotation and all seven gates remain incomplete or UNKNOWN |
| 2026-10-23 | Scoped environment recovery and development diagnosis | Existing wrapper diagnoses Git/socket restrictions, private test provenance, tools, PG16 and restricted roles; supported approval supplies the required execution path | `scripts/test_postgres.py`; native diagnostic and source-evidence controls | Full suite: 1,620 tests plus 18 subtests, three skips; after final diagnostic guard: 76 focused checks; [full](_reset/environment-rewrap-full-20261023.json), [final](_reset/development-preflight-final-20261023.json) | VERIFIED in local cell; no service/credential/mount/policy changes; target authorization and all gates UNKNOWN |
| 2026-10-23 | Inactive root-rewrap admission | Read-only snapshot proposal with exact retained-root comparison, frame authentication and digest-only observations | `src/cryptalis/rotation.py`; standalone protocol and native controls | 35 native planner cases within 55 planner/provider checks; later full/focused regression above; five offline protocol groups; [native](_reset/rewrap-plan-native-green-20261023.json) | VERIFIED for named read-only observations; active rotation and all gates remain incomplete or UNKNOWN |
| 2026-10-22 | Typed numeric API admission | Share finite-number and representable-duration checks across protection, reverse and maintenance approval | Migration, reverse and native rate controls | Ten initial raw overflows; 119 focused native tests pass, including fractional rates and full transitions; reproducible artifacts and 32-file installed-wheel check pass; [focused](_reset/numeric-admission-focused-20261022.json) | VERIFIED for public numeric admission and unchanged native effects; earlier full/fresh runs are separate evidence; all gates UNKNOWN |
| 2026-10-22 | Exact restored frame policy | Admit only known PG16 forms of declared CF1 checks; bind older restatements to source fields; compare constraint identities by schema, table and name | Search storage, restore binding and fresh-cluster fixtures | Four initial false acceptances; 172 focused controls pass; text and VARCHAR each pass one export and 15 restore cases, including a same-name incoming FK; pinned Smolink and 1,567 full tests plus 18 subtests pass; [full](_reset/frame-policy-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-27.json) | VERIFIED for named local controls and exact policy forms; general SQL equivalence is not admitted; all gates UNKNOWN |
| 2026-10-22 | Host artifact input admission | Reuse offline compiler lock and catalog structure checks; require safe estimate values and reverse snapshot maps before connection | Compiler, migration, reverse and native plan/CLI controls | 14 initial failures; 138 first focused and 64 final focused tests pass, including 24 admission controls and legacy v1/v2 artifacts; 1,567 full tests and 18 subtests pass; [full](_reset/plan-admission-full-final-sa21-20261022.json), [focused](_reset/plan-admission-final-focused-20261022.json) | VERIFIED for named structural checks and input diagnosis; no host authentication or live semantic claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound staged catalog | Derive protection shadows from the source lock and reverse staging from the host-pinned protected snapshot plus native source types; retain journal continuity | Migration, reverse metadata documentation, native staged-schema controls | 24 initial false acceptances; 175 focused and 1,543 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-schema-full-sa21-20261022.json) | VERIFIED for recorded catalog facts before paused progress; no freshness or value-verification claim; all gates UNKNOWN |
| 2026-10-22 | Host-bound paused writer fence | Share the host-derived guard check across protection and reverse paused operations and plaintext publication; retain journal continuity checks | Migration, reverse, native guard controls and revised crash/marker fault tests | 18 initial failures; 22 adversarial cases, two native fault controls, and 1,519 full tests plus 18 subtests pass; pinned Smolink and both fresh-cluster paths pass; [full](_reset/paused-guard-full-sa21-20261022.json) | VERIFIED for guard admission before progress; staged catalog admission is a separate later slice; all gates UNKNOWN |
| 2026-10-22 | Host-bound protected catalog | Derive the protected catalog from the source lock; inspect generated frame checks, equality indexes and pending guards; retain explicit restore restatement admission | Compiler, migration, search, reverse and restore modules; native adversarial and fresh-cluster tests | 14 initial false acceptances; 89 lifecycle, 219 expanded and 1,497 full tests plus 18 subtests pass; pinned Smolink passes; each text/VARCHAR fresh cluster passes one export and ten restore cases; [full](_reset/active-contract-full-sa21-20261022.json) | VERIFIED for recorded catalog facts and declared CF1 objects; no key/value or transitive function evidence; all gates UNKNOWN |
| 2026-10-22 | Verification source stability | Capture starting Python hashes and Git revision; compare final bytes; refuse success on changes while retaining the original pytest outcome | `scripts/test_postgres.py`, `tests/test_postgres_evidence.py` | Eight RED controls; 12 source-gate controls, ten real CLI tests, 1,459 full tests plus 18 subtests, pinned Smolink and both fresh-cluster paths pass; [focused](_reset/evidence-stability-final-focused-20261022.json) | VERIFIED for two-observation source admission; no full execution attestation; all gates UNKNOWN |
| 2026-10-22 | Reverse operational status | Read-only snapshot of decrypt-back phases, source identity, counters, native metadata and terminal removal; existing CLI dispatches by artifact format | `deprotection.py`, `migration.py`, `cli.py`; native status/CLI and fresh-cluster tests | 81 focused, 41 adversarial, seven final metadata controls, and 1,447 full tests plus 18 subtests pass; [focused](_reset/reverse-status-green-20261022.json), [adversarial](_reset/reverse-status-adversarial-20261022.json); removed counters remain unavailable | VERIFIED for named local checks; no key/value/provider verification or deployment authority; full gates UNKNOWN |
| 2026-10-22 | Pinned Smolink lifecycle and adoption corrections | Canonical catalog deparsing with restored caller settings and preserved SQLSTATE; invalidate warmed mapper flush caches at attachment | Compiler, adapter, native regressions, and pinned external app/workload tests | RED: native search-path and DML cache controls; initial full run found eight read-only route assertions. GREEN: 154 focused, 1,405 full plus 18 subtests, and the original app lifecycle on two Python 3.13 SQLAlchemy cells; [SA 2.0](_reset/smolink-final-sa20-20261022.json), [SA 2.1](_reset/smolink-final-sa21-20261022.json) | VERIFIED for storage-only Url.destination and the named alternate cells; all full gates UNKNOWN |
| 2026-10-22 | Native VARCHAR type admission | Lock v3 and pg-varchar/v1; native character limits, pending/refresh and failure-state parity; exact query binds; native type restoration; strict reader and transform admission | Compiler, adapter, search and reverse modules; native VARCHAR and fresh-cluster tests | RED: 27 initial cases; reader, rollback-state and hidden-transform controls. GREEN: 179 focused plus 18 subtests, 1,402 full plus 18 subtests, each text/VARCHAR fresh-cluster path passes one export and seven restore cases; [full](_reset/varchar-full-sa21-20261022.json), [VARCHAR restore](_reset/fresh-cluster-restore-20261022-8.json), [release](_reset/varchar-release-20261022.json) | VERIFIED, bounded local cell; external-app adoption remains open; all gates UNKNOWN |
| 2026-10-22 | Fractional measured-rate artifact correction | Share bounded JSON structure checks; admit decimals only at measured throughput paths, including embedded source plans | `src/cryptalis/manifest/parser.py`; `src/cryptalis/migration.py`; `src/cryptalis/deprotection.py`; `tests/test_transition_rates.py` | RED: 3 lifecycle failures. GREEN: 157 focused, 1,363 full tests plus 18 subtests, one export and seven restore cases, repeat release builds and 32 installed-file comparisons; [full](_reset/transition-rates-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-6.json), [release](_reset/transition-rates-release-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Local operational-status slice | Read-only repeatable-read snapshot, committed progress, host pin comparison, safe CLI inputs and diagnostics | `src/cryptalis/migration.py`; `src/cryptalis/cli.py`; status and fresh-cluster tests | RED: missing API/command and malformed plan boundaries. GREEN: 1,351 full tests plus 18 subtests, one export and seven restore cases, eleven release groups and 32 installed-file comparisons; [full](_reset/status-full-sa21-20261022.json), [restore](_reset/fresh-cluster-restore-20261022-5.json), [release](_reset/status-release-20261022.json) | VERIFIED, bounded local cell; no data verification or provider admission; all gates UNKNOWN |
| 2026-10-22 | Native metadata backup/recovery and terminal removal | Lock v2 catalog comparison before journal retirement and during terminal checks; safe missing-journal inspection; native backup metadata assertions | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py`; fresh-cluster qualification modules | RED: 6 drift cases, then 3 terminal retries. GREEN: 22 focused, 1,322 full plus 18 subtests, 1 export and 7 restore; [full](_reset/removal-metadata-full-sa21-20261022.json), [fresh cluster](_reset/fresh-cluster-restore-20261022-4.json), [negative control](_reset/fresh-cluster-metadata-control-20261022.json) | VERIFIED, bounded local cell; all gates UNKNOWN |
| 2026-10-22 | Installed-artifact identity audit | Compare installed bytes with the current wheel, refuse stale package files, isolate bytecode caches, and suppress raw child failure output | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 4 accepted artifact mutations, stale bytecode execution, and startup diagnostic exposure. GREEN: 11 test groups and actual offline uv install, 32 matched files, isolated CLI; [receipt](_reset/release-install-binding-20261022.json). No dependency or PostgreSQL qualification | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-22 | Local artifact-integrity audit | Complete wheel RECORD coverage and strict wheel/sdist member inspection | `scripts/release_check.py`; `scripts/test_release_check.py` | RED: 25 failures and 4 errors. Review RED: 7 further failures. GREEN: 10 test groups, valid controls, matching offline repeat builds, SBOM; [receipt](_reset/release-integrity-20261022.json). PostgreSQL preflight failed, exit 2; full suite unrun | VERIFIED, offline local cell; all gates UNKNOWN |
| 2026-10-21 | Local release-artifact slice | Reproducible wheel/sdist build, wheel `RECORD` verification, archive-member inspection, MIT license metadata, CycloneDX 1.5 SBOM, clean-venv import and CLI smoke | `pyproject.toml`; `scripts/release_check.py` | GREEN: two builds matched; wheel and sdist hashes recorded; clean venv imported the installed package and started the CLI; [receipt](_reset/release-check-20261021.json) | VERIFIED, local cell; G-RELEASE UNKNOWN |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/deprotection.py` (retained-native) | Reverse lifecycle evaluated; product implements an in-place `cryptalis.reverse/v1` variant for the admitted transition format, with journal/pin/approval checks, verified chunked backfill, transactional switch, and approved removal | `src/cryptalis/deprotection.py`; `tests/test_deprotection.py` | GREEN: 7 focused and 1,299 full SA2.1; 7 focused and 1,271 passed + 28 skipped full SA2.0 | VERIFIED, bounded, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_payload_rotation.py`; test `test_payload_rotation_preparation.py` (native staging oracle omitted; product uses the in-place layout) | Inactive bounded payload-generation transform with exact source decode, target reseal, identity/header preservation, and lease recheck | `src/cryptalis/crypto/_payload_rotation.py`; `tests/test_payload_rotation_preparation.py` | GREEN: 40 focused SA2.1, 1,292 full SA2.1, 90 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/manifest/compiler.py` direct-driver catch | Map direct psycopg inspection errors to `InspectionUnavailable` with safe SQLSTATE | `src/cryptalis/manifest/compiler.py` | GREEN: 61 focused each profile; 1,292 full SA2.1; 1,264 passed + 28 skipped full SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/crypto/_rewrap.py`; test `test_rewrap_preparation.py` | Inactive rewrap candidate over every admitted root with target identity checks and no partial result | `src/cryptalis/crypto/_rewrap.py`; `tests/test_rewrap_preparation.py` | GREEN: 16 focused, 1,252 full SA2.1, 54 focused SA2.0 | VERIFIED, internal, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/_sqlalchemy_search.py` negative-predicate hunks; test `test_sqlalchemy_negative_predicates.py`; updated search grammar test | Simple `!=`, `NOT IN`, and NULL presence with native truth and outer-join tenant-guard preservation | `src/cryptalis/_sqlalchemy_search.py`; `tests/test_sqlalchemy_negative_predicates.py`; `tests/test_sqlalchemy_search.py` | RED: 57 failed, 2 passed. GREEN: 366 focused SA2.1, 1,236 full SA2.1, 202 focused SA2.0 | VERIFIED, local cell |
| 2026-10-19 | `debgh-workspace/cryptalis-research-lab` branch `accel/integration-s20-20261014`, commit `15cf040`; `candidate/src/cryptalis/sqlalchemy.py::UnsafeEngineLogging`; test `test_attachment_engine_preflight.py` | Refuse unsafe query echo or parameter hiding before connection or key access | `src/cryptalis/sqlalchemy.py`; `tests/test_attachment_engine_preflight.py` | RED: 12 unsafe-setting subtests reached `do_connect`. GREEN: 307 focused SA2.1, 1,177 full SA2.1, 143 focused SA2.0 | VERIFIED, local cell |

## Seven gates

| Gate | Status | Required evidence |
|---|---|---|
| G-ADAPTER | UNKNOWN | Complete admitted matrix; unsupported-route coverage; real app; independent review |
| G-CRYPTO | UNKNOWN | Independent composition, nonce, context, and key-lifetime review |
| G-QUERY | UNKNOWN | Semantics and leakage admission for every claimed profile |
| G-LIFECYCLE | UNKNOWN | Fresh-cluster restore, upgrade/rollback, rotation, removal |
| G-PROVIDER | UNKNOWN | Real authorized KMS custody, outage, revocation, and cost evidence |
| G-POLICY | UNKNOWN | Authenticated deployment policy, stale-worker fencing, quarantine |
| G-RELEASE | UNKNOWN | SBOM, provenance, clean build/install, independent reviews |

## Next critical path

1. Qualify external retained inventory and recovery obligations. Installed and
   fresh-target metadata checks pass. Keep journal observations separate from external
   obligations. An empty journal does not prove that external obligations are absent.
   The [original HTTP operational join](status.md#original-http-operational-cli-journey-2026-10-24)
   now has bounded source and installed evidence.
2. Retain the current removal contract while evaluating the unresolved retained-native
   alternative separately. Backup obligations remain open.
   Lock v2 captures and restores comments,
   statistics targets, storage, compression, options, column grants, constraint and
   index comments, and extended statistics. Lock/v5 adds bounded owned-sequence
   preservation and source fresh recovery. See the [metadata research note](research/metadata-preservation-and-format-evolution.md)
   and the [lock v2 proposal](research/lock-v2-metadata-proposal.md).
3. Use the competitive matrix to select high-value missing capabilities and complete
   independent application journeys. Preserve native PostgreSQL correctness oracles
   and required focused security checks.
4. Extend the fresh-cluster range with multi-table, fault, and provider-outage drills.
5. Keep every external review and provider item explicitly UNKNOWN; review the
   [lab reconciliation](research/lab-reconciliation-2026-10-19.md) for refused-metadata
   signals, without adopting lab code.
