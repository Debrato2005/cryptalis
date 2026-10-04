# Repository instructions

Cryptalis contains documentation, research specifications, initial manifest decoding, canonical
output, identity-header validation, parent-link validation, structural field-format digests,
offline terminal inspection, and private candidate F1 envelope parsing.
Treat other APIs, commands, packages, and security properties as proposed until the [capability
checklist](docs/backend-build-checklist.md) links the required executable evidence.

Preserve the default manual learning workflow in the [engineering playbook](ENGINEERING_PLAYBOOK.md). AI
assistance may edit documentation directly. The human builder normally types source, tests, migrations,
build configuration, containers, and CI files, one explained file at a time.

**Nothing important may fail silently.** Follow the [explicit failure policy](ENGINEERING_PLAYBOOK.md#fail-loudly-and-explicitly).
Use explicit failure channels, safe actionable diagnostics, and failure-path evidence. Documentation alone does not close implementation gaps.

Follow the [testing policy](ENGINEERING_PLAYBOOK.md#test-layers). Prefer end-to-end and integration
checks of observable behavior. Do not generate unit tests for each function or to increase coverage.
Use focused unit tests when they uniquely protect cryptographic or security logic, deterministic algorithms,
parsers, state machines, protocols, or difficult edge cases. Each test must protect a meaningful property
or regression and remain valid across reasonable internal refactors.

Use the installed `security-best-practices` skill for secure defaults and relevant Python host-adapter reviews.
Use `security-threat-model` when threat modeling is requested. Extend the canonical threat model rather than creating a competing specification.
Require the [release gate](ENGINEERING_PLAYBOOK.md#release-gate) before making production-readiness claims.
Skills and AI review do not replace executable capability evidence or independent security review.

Use the [architecture ownership map](docs/architecture/README.md#documentation-ownership) to
find canonical contracts. Preserve existing local work. Do not create competing specifications.

Use ASD-STE100-inspired writing for human-readable technical prose. Use STE-flavored mode for
normal explanations and documentation. Use strict mode for procedures, instructions,
troubleshooting, error text, and safety-critical content. Preserve necessary technical
terminology, identifiers, uncertainty, qualifiers, mathematical meaning, scientific meaning, and
implementation precision.

Prefer clarity over mechanical simplification. Use the installed `asd-ste100` skill when
substantial prose is created or revised. Layer 1 is the primary writing system. Layer 2
reply-shaping rules are optional guidance, not repository-writing requirements.
