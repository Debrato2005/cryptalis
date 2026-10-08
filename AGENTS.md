# Repository instructions

Cryptalis contains a research foundation and a final intended architecture.
Read the [status](docs/status.md) before claiming any runtime capability.
A document is not executable evidence. SUPPORTED selects design scope, not current production support.
Use SPECIFIED / IMPLEMENTED / VERIFIED with the exact evidence boundary. Do not describe spike code as product code.
Architecture drives code. Current source/APIs/modules/tests/schemas/commands are not preservation requirements.
Authorized implementation may refactor, replace, merge or remove them when the final contract requires it.
A documentation-only task still leaves executable files unchanged.

## Deterministic reading path

1. Read [README](README.md) and [canonical architecture](docs/architecture/README.md).
2. Read [security](docs/security.md), then [lifecycle](docs/lifecycle.md).
3. Read [compatibility](docs/compatibility.md), then [status](docs/status.md).
4. Read the [approved decisions](docs/decisions.md#approved-scope-decisions-2026-10-08), then the [ordered build slices](docs/build-guide.md#ordered-build-slices).
5. Read [engineering playbook](ENGINEERING_PLAYBOOK.md) before implementation.

Use the [ownership map](docs/architecture/README.md#documentation-ownership) for the contract being changed.
Research files are external evidence, not alternate specifications.
The [traceability record](docs/research/reset-traceability.md) explains replaced constraints. Git preserves historical wording.

## Work boundaries

Preserve existing local work. Inspect current Git status and repository truth before a continuation.
Do not install, commit, push, reset or revert without authorization.
Documentation assistance may edit Markdown directly.
The human builder normally types source, tests, migrations, build configuration, containers and CI files.
Use one explained file at a time unless the user explicitly authorizes another workflow.
The [manual workflow](ENGINEERING_PLAYBOOK.md#manual-workflow) defines each RED/GREEN slice.
Implement one build slice per run, in the approved order. Each slice requires real PostgreSQL 16 tests before the next.
Advanced range/order/prefix/text work requires all seven slices, then [six-gate admission](docs/compatibility.md#capability-admission) and leakage opt-in.

Nothing important may fail silently.
Follow the [explicit failure policy](ENGINEERING_PLAYBOOK.md#fail-loudly-and-explicitly).
Use typed failures, safe remedies, partial-progress states and meaningful failure-path evidence.
Missing security evidence is UNKNOWN. Do not convert it to PASS.
Do not repair a failed literal read-only command or continue adjacent work without authorization.

Use the [testing policy](ENGINEERING_PLAYBOOK.md#test-layers).
Prefer observable end-to-end and integration behavior.
Focused unit tests must uniquely protect deterministic, cryptographic, parser, protocol or state-machine properties.
Do not create tests for every function, private structure, import or coverage count.

Use the installed security-best-practices skill for secure defaults and relevant Python host-adapter reviews.
Use security-threat-model when the user requests threat modeling.
Extend [docs/security.md](docs/security.md) rather than create a competing threat specification.
Skills and AI review do not replace executable evidence or independent human security review.
Require the [release gate](ENGINEERING_PLAYBOOK.md#release-gate) before any production-readiness claim.

Use ASD-STE100-inspired prose. Apply STE-flavored mode to explanations and strict mode to procedures, diagnostics and safety instructions.
Preserve necessary terminology, qualifiers, uncertainty, math and implementation precision.
Use the installed asd-ste100 skill for substantial prose. Layer 1 governs writing. Layer 2 is optional reply guidance.

## Shell execution in WSL

Before the first repository command, check the executor environment and working directory.
If the executor runs in Linux or WSL, run Linux commands directly with the Linux shell.
Use `/home/debrato/Projects/cryptalis` as the working directory.
Do not wrap Linux commands with `wsl.exe`, `cmd.exe` or `powershell.exe`.
Do not repeat an unchanged command after `UtilBindVsockAnyPort: socket failed 1`.
Do not change sandbox permissions to make ordinary Linux repository commands work.
For required Windows commands, request approval after a sandbox-related failure.
A failure before process creation has no command exit status.
