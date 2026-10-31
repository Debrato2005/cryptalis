# Repository instructions

Cryptalis is an unqualified research prototype targeting the
[product requirements](docs/requirements.md) and all 34 objectives. Follow KISS:
do not overengineer. Read [current status](docs/status.md) before claiming capability.
SUPPORTED is admitted design scope; VERIFIED is revision-bound evidence. Neither
is production qualification. Missing security evidence is UNKNOWN.

## Deterministic reading path

Start with the [documentation map](docs/README.md), current status and the affected
[objective row](docs/BUILD_CHECKLIST.md#objective-ledger). Read its contract owner
and procedure. Cross-cutting changes require architecture, security, lifecycle
and compatibility. Read [decisions](docs/decisions.md), [build order](docs/build-guide.md)
and the [engineering playbook](ENGINEERING_PLAYBOOK.md) before implementation.
History, research and graph relationships are evidence/navigation, not alternate
current contracts. Verify claims in current source and exact receipts.

## Work boundaries

Inspect the actual working directory and Git status. Preserve unrelated work.
Use the current checkout root; do not assume a workstation-specific path.
Current user instructions determine authorization. When implementation and
commit/push are authorized, continue through verified slices and push each one;
do not resurrect old human-only, one-file, one-slice or operator-pause rules.
Do not publish packages, deploy production, force-push, delete keys/backups or
perform other destructive external actions without their own authorization.

A documentation-only phase changes documentation, not executable files. After
it is committed, an authorized implementation phase may change source/tests.
Current internals are not preservation requirements: replace unjustified code
when the final contract requires it, while preserving behavior and evidence.

## Verification and security

Follow the [test layers](ENGINEERING_PLAYBOOK.md#test-layers) and
[explicit failure policy](ENGINEERING_PLAYBOOK.md#fail-loudly-and-explicitly).
Prefer real end-to-end/integration behavior and native PostgreSQL oracles.
Use focused units for crypto vectors, parsers, protocols and deterministic failure
properties; do not test private layout or inflate counts.

Run PostgreSQL tests only through `scripts/test_postgres.py`. It freshly loads
private role files, probes the configured target and binds source/runtime bytes.
A failed probe stops the run; do not repeat it or substitute a database without
resolving the cause and applicable authorization. Use the existing diagnostic
mode and [local setup](docs/local-development.md). Do not expose connection strings.

Reject unsupported behavior with typed errors. Never bypass encryption, return
unauthenticated/plaintext fallback results or claim success without evidence.
Keep partial progress, cleanup failure, skips and unavailable observations visible.
Advanced capabilities retain [admission](docs/compatibility.md#capability-admission)
and explicit leakage opt-in. Independent human review and the
[release gate](ENGINEERING_PLAYBOOK.md#release-gate) cannot be replaced by AI review.
Use installed security/style skills when applicable; unavailable optional tooling
must not block independently authorized work. Write plain, precise prose.

## Source access and tooling

Use local Git and file reads for this repository; prefer official source/API
checkouts and raw files for external code. Preserve sources, retrieval failures,
licenses and evidence boundaries. [Research](docs/research/README.md) routes the
existing material. Do not bypass authentication or network policy.

Run Linux commands directly in Linux/WSL. Do not wrap them in Windows shells.
Do not change sandbox permissions for ordinary commands or repeat an unchanged
WSL transport failure. Use supported approval only when a required action is
actually blocked and existing session authorization is insufficient.

When `graphify-out/graph.json` exists and Graphify is available, use scoped
query/path/explain for navigation, confirm findings in source and refresh after
code changes. Do not install its global hook or change Codex configuration.
Never execute graph-derived database commands. If the graph is absent, use
source search directly. An explicit `/graphify` request requires its instructions.

## Documentation upkeep

The [owner map](docs/README.md#document-owners) defines where each fact belongs.
Update current status and the objective ledger in place; put dated observations
in history and preserve machine receipts. Map normative requirements before
merging/deleting prose. Check repository links and anchors after moves. Keep
historical reviewer content and scope intact; routing changes are not new reviews.
