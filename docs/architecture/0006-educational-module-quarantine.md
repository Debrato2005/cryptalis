# ADR-0006 — Educational module quarantine

**Status:** Deferred
**Contract:** [AD-7](../../README.md#ad-7--the-educational-module-is-quarantined-from-the-production-path)
**Source:** None in this repository. Add source materials and their usage constraints before
activating this record.
(the educational module is a syllabus bolt-on, not a design principle)

## Problem

This repository serves two masters. The product is a security tool whose entire value rests on
shipping only modern, correctly-used cryptography. The course requires implementing Caesar and
Vigenère ciphers, DES and 3DES, ECB mode, textbook RSA, ElGamal, Rabin, MD5, and SHA-1 — primitives
that are broken, obsolete, or unsafe by construction, several of which are deliberately implemented
in their weakest textbook form so that they can be attacked.

Both requirements are legitimate. The failure mode is obvious and would be fatal to the project's
credibility: a reviewer finds `des.py` and `md5_collision.py` in a tool that claims to be an
encryption gateway, and stops reading.

## Constraints

- No educational requirements or source materials are present, so no specific lab scope is a project
  commitment.
- The lab work must be *visible* — it is coursework and, in interviews, an asset ("here is why we
  don't ship these").
- `capstone-final-decision.md` §3 is explicit that this module is a weekend of work, not a design
  driver. It must not shape the product's architecture.
- Enforcement must survive a tired developer at week 14. A comment is not enforcement.

## Decision

**A top-level `educational/` directory, isolated by an automated test, excluded from the package,
and labelled in every file.**

### Isolation

- `educational/` imports nothing from `src/`, `sdk/`, or `cli/`.
- Nothing in `src/`, `sdk/`, or `cli/` imports `educational/`.
- `tests/boundary/test_educational_quarantine.py` enforces both directions and additionally asserts
  that `educational/` is absent from the built distribution. This test is created in Milestone 0.3,
  before any lab code exists, so the boundary is armed from the start rather than retrofitted.
- Duplication between `educational/` and `core/crypto/` is **accepted**. Sharing a helper across the
  boundary would be the first crack; a duplicated 20-line helper is cheaper than that risk.

### Labelling

Every module opens with a header stating the lab exercise it implements, that it is intentionally
insecure or obsolete, and that it must never be used in production. The directory has its own README
saying the same thing at the top, so a browsing reviewer sees it before any code.

### Packaging and tooling

Excluded from the installed package and from coverage requirements. **Not** excluded from linting or
type checking — it is still code in the repository, and sloppiness there is visible too.

### Demonstrations, not just implementations

Each lab ships with the attack, because the attack is the point:

- Classical ciphers with brute-force and known-plaintext breaks (Lab 1).
- Block modes including an ECB pattern-leakage artifact (Lab 2).
- RSA, ElGamal, Diffie–Hellman with a performance comparison (Lab 3).
- Rabin, ECC/ECDH/ECDSA, and a weak-prime factorization exercise recovering a key from poorly chosen
  primes (Lab 4).
- The manual's custom hash function (initial value 5381, multiply by 33, add the character's ASCII
  value, bit mixing, 32-bit mask), a socket client/server integrity demonstration, and an
  MD5 / SHA-1 / SHA-256 timing-and-collision study over a generated dataset of 50–100 random strings
  (Lab 5).
- Digital signature creation and verification with the manual's supplied RSA key pair (Lab 6).

MD5 and SHA-1 collision work uses published collision pairs; the module does not attempt to generate
novel collisions.

### Course rules apply here and only here

The manuals instruct students to implement exercises individually and to avoid LLM assistance, and
prohibit plagiarism. Those rules govern how `educational/` is produced, independently of how the
product code is built. This is recorded in the
[playbook](../../ENGINEERING_PLAYBOOK.md#working-on-the-educational-module) so it cannot be
overlooked when the module is finally written in Milestone 9.

## Alternatives rejected

| Alternative | Why rejected |
|---|---|
| A separate repository for lab work | Cleanest isolation, but the coursework and the capstone are evaluated together, and the connection between "what we don't ship" and "what we ship" is an asset worth keeping visible. |
| Lab code inside `core/crypto/` behind a flag | The exact failure this ADR exists to prevent. A flag is one refactor away from being ignored. |
| A `legacy/` or `crypto_extras/` name | Ambiguous names invite accidental use. `educational/` cannot be misread. |
| Documentation-only quarantine (a README warning) | Not enforcement. Nothing fails when it is violated. |
| Skipping the module and dropping the syllabus items | Not available — they are course requirements. |
| Placing it last in the roadmap and treating it as optional | It *is* scheduled last (Milestone 9), but treating it as optional risks it landing rushed and unlabelled. It is scheduled, scoped, and tested like everything else. |

## Data flow

None. `educational/` is not part of any request path in the system. It is invoked directly by its own
tests and by a developer running scripts. That is the entire point, and the boundary test is what
keeps it true.

## Error and security behaviour

- Code in `educational/` **is not secure and does not claim to be.** Weak parameters, textbook
  constructions, and predictable keys are intentional.
- It never handles real key material, never connects to the gateway's database, and never reads the
  KEK or any production configuration.
- Its socket demonstrations bind to localhost with synthetic data only.
- The risk this ADR manages is not "an attacker exploits `educational/`" — it is "a developer or an
  adopter imports it by accident, or a reviewer mistakes it for product code." Both are addressed by
  the import test, the packaging exclusion, and the labelling, in that order of strength.

## Testing strategy

- `tests/boundary/test_educational_quarantine.py` — bidirectional import isolation and packaging
  exclusion. **Never skipped, never marked `xfail`.**
- Per-lab tests that assert the *weakness*, not only the algorithm: a brute-force break recovers the
  key; ECB output preserves visible structure; the weak-prime modulus factors; MD5 collides on the
  published pair while SHA-256 does not.
- Lab tests run in CI alongside everything else, so the module cannot rot silently.

## Deferred

- A rendered write-up of the cryptanalysis results, useful for the demo and for interviews, produced
  after Milestone 9 rather than alongside it.
- Benchmark integration: lab timing comparisons (DES vs. AES, RSA vs. ECC) could feed the Milestone 8
  harness, but the harness is built for the product path first and the two are only merged if it
  costs nothing.
- Additional syllabus topics if lab requirements change — the directory structure is per-lab, so
  adding one is additive.
