# Capstone: Final Decision

**Verdict: build CipherShield's plan with Cryptalis's encryption model.**
Not a new project — a two-line change to the plan you already have.

---

## 1. CipherShield vs Cryptalis: the actual difference

They are ~80% the same project. Both have field-level encryption, KEK/DEK envelope
key management, ABAC-gated access, a tamper-evident audit log, and Smolink as the
demo backend.

The only real fork is **when encryption happens**:

| | CipherShield | Cryptalis |
|---|---|---|
| Encrypts | On the way **out** (API response) | On the way **in** (before DB write) |
| Database holds | Plaintext | Ciphertext |
| Protects against | Leakage into logs / APM / caches | DB breach, stolen backup, rogue DBA |
| Integration | HTTP proxy, no app changes | SDK call in the data layer |
| Crypto-shredding possible? | No | Yes |

---

## 2. Why the write-time model wins

1. **It answers the question everyone asks.** "What if your database is breached?"
   → they get ciphertext. CipherShield has no answer, because the plaintext is
   still sitting in Postgres.

2. **CipherShield's core claim has a cheap counter.** The pitch — "plaintext never
   reaches the logging pipeline" — is largely solved by field redaction in a
   structured logger. Same failure mode as the role-masking pitch that was already
   killed by the "a JWT-scoped Pydantic model does this for free" objection.

3. **Crypto-shredding is the single best feature in either document.** Per-subject
   keys mean "delete my data" = destroy one key + emit a signed erasure
   certificate. GDPR Art. 17 / India DPDP. Demoable in 20 seconds. Requires
   encrypt-at-rest, so CipherShield architecturally cannot do it.

4. **It removes the biggest build risk.** The nested `click_events[]` JSON
   re-serialization problem (flagged as highest-risk, Week 9 fallback) largely
   disappears when encryption happens on write instead of on response.

---

## 3. Where the Cryptalis document is wrong — do NOT adopt it wholesale

- **8-month roadmap vs. your 14–16 weeks.** Crypto-shredding lands Month 4, KMS
  Month 5, Merkle checkpoints Month 6. You would ship the MVP and none of the
  differentiators.
- **Overstates the market gap.** Acra Community Edition is Apache-2.0, free for
  commercial use, encrypts each field with unique keys, and its release notes show
  KMS flags including AWS KMS master-key wrapping. "KMS is Enterprise-only" is not
  accurate. What *is* accurate: CE 0.96.0 (Sept 2024) is the last release, so it
  is genuinely stale.
- **It strawmanned CipherShield.** It scored "a vague crypto gateway/toolkit" —
  not your actual, specified project. Treat the 8.85-vs-5.65 scoring table as
  false precision.
- **Verify its citations.** "US EO 14412" and the prior-art repo
  "quantakrypto/pqc-tools" (cited to reject the PQC idea) should be confirmed
  before any decision rests on them.
- **The educational module is syllabus bolt-on.** Include it if the lab requires
  it, but it is a weekend of work, not a design principle.

---

## 4. What actually changes in your plan

**Keep everything:** 14–16 week timeline, Smolink as the real protected backend,
ABAC role table, fail-closed default, hash-chained + Merkle audit log with ECDSA
checkpoints, k6 benchmarks with published p50/p95/p99, two-repo structure, demo
script.

**Change two things:**

1. **Move the encryption boundary to write time.** Encrypt fields as they enter
   Postgres via an SDK call in Smolink's data layer, not as they leave the API.
   Cost: you lose the "zero code changes to Smolink" line. You had already
   accepted additive Smolink changes (JWT claims, `team_id`), so this is a smaller
   concession than it sounds.

2. **Scope DEKs per data subject and add crypto-shredding around Week 11**,
   alongside or in place of part of the audit-log week. Cheap once per-record DEKs
   exist. Highest-value interview moment in the whole project.

### Revised demo script

1. Write a link via Smolink → `SELECT` the row → `destination_url` and
   `ip_address` are ciphertext in the database.
2. Authorized role decrypts through policy; analytics/team role is denied and the
   denial is audited.
3. Tamper with a ciphertext byte → AEAD rejects it.
4. Crypto-shred a subject → prior data permanently undecryptable + signed erasure
   certificate.
5. Tamper with an audit row → `/audit/verify` detects the break.
6. Benchmark graph: baseline Smolink vs. Smolink + encryption, p99 overhead.

---

## 5. Interview answers to have ready

- What's your trust boundary?
- Why AES-GCM and not CBC? How do you guarantee nonce uniqueness?
- What is your AAD, and what attack does it stop?
- What happens to a field not registered in the schema policy? (Fail closed.)
- What if the DB is fully compromised? What if a DEK is? What if the KEK is?
- How does crypto-shredding actually erase data, and how do you prove it to an
  auditor?
- How do you rotate keys without re-encrypting everything?
- Why not just use Acra or Vault Transit?
- What does this **not** protect against? (Live host compromise with keys in
  memory. Say it plainly.)

---

## 6. The meta-point

Three AI-generated research documents have now named three different winners —
EnveDrop, CipherShield, Cryptalis — each confidently dismissing the last. A fourth
prompt will produce a fourth name, equally well-argued.

With ~14 weeks left, the value of a better project choice is now far below the cost
of another week spent choosing.

**Stop researching. Start Week 1 on Monday.**
