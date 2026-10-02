# Historical pause handoff

Historical checkpoint: 2026-10-01, Asia/Calcutta. The user requested a graceful stop because of the session limit. The goal was paused at that checkpoint. The user subsequently requested resume; the review findings
and remaining work below are archival. Current dispositions belong to [the claims audit](documentation-claims-audit.md),
and current implementation state belongs to [the checklist](backend-build-checklist.md). This file
does not define architecture or report present goal status.

## Scope and authority

Read the original 98-section directive at `C:\Users\Debrato\.codex\attachments\0bd78fd6-5a32-4c1f-bb66-3c5798ddfac8\pasted-text-1.txt` before resuming. The current local worktree is authoritative. Documentation only: do not implement source, tests, migrations, build or CI scaffolding; do not commit or push. Existing user edits were present before this session and must be preserved. Initial branch main; HEAD and origin/main were cc54ee894e1cdfb66245ddc69cc9286e3d6eea60 when inspected. Recheck current state on resume.

## Work saved

The ownership split and documentation draft are in place:

- `docs/architecture/manifest-context-api.md`: manifest canonicalization, trusted context, public API/CLI/configuration, module boundaries and research gates.
- `docs/architecture/orm-schema-migration.md`: SQLAlchemy semantics, async alternatives, schema and migration contracts and experiments.
- `docs/architecture/crypto-search-lifecycle.md`: proposed envelope, search leakage, key hierarchy, provider/cache/lifecycle contracts and experiments.
- `docs/architecture/assurance-evidence.md`: verification, pentest, safety, evidence and research gates.
- `docs/research/orm-platform-evidence.md`, `crypto-provider-evidence.md`, `assurance-tool-evidence.md`: primary-source evidence ledgers.
- README, architecture hub, build checklist, build guide, research philosophy and prior-art were rewritten around these owners. ENGINEERING_PLAYBOOK was updated. Historical adversarial hardening received a supersession notice. Assurance research was consolidated by its agent.

These are documentation proposals and researched contracts, not implemented or experimentally validated behavior. No source implementation, runtime tests, commit or push was performed. Fresh git status at stopping confirmed only Markdown changes/new documentation directories. Initial user edits included the eight modified existing files plus untracked adversarial hardening and documentation claims audit; do not mistake those for newly created session work.

## Outstanding integration corrections from second-pass review

The findings below were reported by first-party research agents. They remain unresolved and must not be described as an independent external audit.

1. Specify a concrete external deny / database commit / plaintext release fencing protocol. A precommit epoch check races COMMIT; a lease check races suspension followed by output. Define linearization points, DB transaction fence serialization, external-deny ordering, worker drain/ack conditions and restore authority. Otherwise explicitly classify the mechanism OPEN and block bounded physical completion claims. Expiry alone proves no new authorization after expiry, not zero post-receipt output.
2. Define the exact immutable field-format descriptor fields and domain-labeled hash bytes, historical storage and compatibility allowlist. The full current manifest hash must not silently replace original creation policy in AAD.
3. Add decrypted normalized predicate verification to ORM QueryPlan/comparator semantics. Authentic rows with swapped unauthenticated equality terms must not become wrong-predicate results. Include tampered-term LIMIT/IN fixtures and failure semantics.
4. Align uniqueness rotation with fence-before-target-backfill. Crypto currently permits U-only writes until after V coverage, risking stale V; ORM requires all writers dual before backfill. Alternatively specify a target invalidation/rescan journal with a proof.
5. Clarify migration OBSERVE: legacy authoritative writes versus explicitly permitted atomic plaintext rollback-mirror writes; define observation start and loss of rollback ability. VERIFY must require full streaming crypto/source comparison and independently stratified sampling, not sampling alone.
6. Align public compile_schema / plan_migration signatures with the shared API owner; label internal helpers and DTO aliases explicitly.
7. Align cold-key behavior: cold writes fail before protected DML; reads may fetch bounded authorized hidden ciphertext rows before warming, but release no logical/plaintext values before authenticated decode. Keep this async profile gated on cancellation and two-phase fixtures.
8. Use one logical IN limit (ORM 1,000; crypto currently 1,024), and separately bound dual-generation physical bind expansion.
9. Align ORM payload limits with the F1 encoded-value limit: 1 MiB encoded with a five-byte scalar frame means at most 1,048,571 content bytes for that frame. Define leading U+FEFF handling: encoder adds no BOM versus rejection of valid string content.
10. Link SQL-NULL substitution integrity limits from crypto, not only nullness leakage; stronger claims require encrypted-null or authenticated presence.
11. Define distributed reservation/CAS and restore semantics for generation derivation/byte budgets, or mark enforcement OPEN.
12. Define trusted requested-resource identity comparison with authenticated record UUID. Test substitution of ciphertext plus subject/key/record metadata while retaining requested relational PK; mutable database ownership alone is insufficient.
13. Disambiguate crypto envelope codec entry ID/version, tuple encoder tag numbers and integer widths before freezing candidate bytes.
14. Repair crypto's assurance-owner link to architecture/assurance-evidence.md. Align assurance CLI inspect/compare/attest with shared inspect/validate/export or explain distinct proposed commands.
15. Add canonical error mappings for cold material, invalid type/size, ambiguous commit, uniqueness collision and index inconsistency. Define evidence duration units/decimal-string encoding under the no-floats JCS profile.
16. Explain crypto 20% overhead / 5 ms event-loop lag versus ORM 25% / 10 ms targets by workload and integration applicability.

## Required unfinished verification and deliverables

- Read the completed assurance contract and all three research ledgers in full; root already read ORM and crypto normative contracts but their ledgers still need integration review.
- Assurance agent reached its usage limit before completing the final adversarial review; ORM review delivered findings before hitting the limit. Crypto review finished. No agent remains actively working.
- Finish docs/documentation-claims-audit.md: current W1-W5 closure evidence, all 98 directive requirements mapped to authoritative documentation/evidence, claim classifications, second-review findings and resolutions. Do not declare closure until actually verified.
- Run documentation link/anchor/fence checks and git diff --check after corrections. Use a temporary/ad hoc checker, not executable scaffolding committed to this docs-only repository. Record actual commands and results in the audit. Confirm no non-documentation changes and preserve original user edits.
- Final response requested by the original directive: verdict, all changed files, decisions, research, W closures, gates, validation, implementation truth, Git state. The full objective remains unfinished.

## Environment notes

Normal Windows sandbox exec/apply_patch calls failed with a helper setup error during the session. Escalated exec_command calls were auto-approved for authorized documentation work and worked. PowerShell single-quoted here-strings with Set-Content wrote Markdown safely. WSL Ubuntu commands worked. Keep commands under the Windows command-size limit. No escalation rejection occurred. No relevant memory file was available; do not add memory citations based on this handoff.
