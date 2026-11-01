# Published sorting attack: source and experiment design

Research date: **2026-11-01**. This note records primary-source research and a
proposed experiment for requirement 15 and **OBJ-QUERY-03**. It records no executed
attack or recovery result. [Status](../status.md) owns verification claims;
[security](../security.md#capability-leakage) owns leakage and threat boundaries.

## Primary source and retrieval

Muhammad Naveed, Seny Kamara and Charles V. Wright, *Inference Attacks on
Property-Preserving Encrypted Databases*, ACM CCS 2015, DOI
[10.1145/2810103.2813651](https://doi.org/10.1145/2810103.2813651).
The [Microsoft Research publication page](https://www.microsoft.com/en-us/research/publication/inference-attacks-property-preserving-encrypted-databases/)
uses “Against” in its title; the PDF uses “on”. The publication is October 2015;
the canonical PDF's hosting path does not establish a 2017 publication date.

Both direct HTTPS downloads succeeded on the research date and contain identical
bytes. The initial built-in web PDF fetch timed out; direct retrieval resolved
that observation. The [author's publication index](https://www.senykamara.com/papers/)
links the Brown mirror. Page references below mean the **13-page PDF's page
positions**, starting at its title page, rather than inferred proceedings pages.

| Source | Temporary research copy | Bytes | SHA-256 |
|---|---|---:|---|
| [Canonical Microsoft PDF](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf) | `/tmp/cryptalis-naveed-2015-msresearch.pdf` | 644238 | `06cb2cae43f5edee9f5e80bdfcad9c87c80eee76cd6720b1d893f51e4b34e775` |
| [Author-linked Brown PDF](https://cs.brown.edu/people/seny/pubs/edb.pdf) | `/tmp/cryptalis-naveed-2015-research.pdf` | 644238 | `06cb2cae43f5edee9f5e80bdfcad9c87c80eee76cd6720b1d893f51e4b34e775` |

The first page reserves owner/author copyright and ACM publication rights. It
permits specified personal/classroom copies and credited abstraction, not
unrestricted redistribution. Preserve notices in private caches; no PDF is vendored.

## Exact published mechanism

[Section 4.2, PDF page 5](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf#page=5)
uses passive snapshots. [Section 6.1, page 7](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf#page=7)
matches sorted unique ciphertext ranks to a known, fully covered domain, without
frequency samples. Section 6 includes ORE. [Section 8, pages 9–10](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/02/edb.pdf#page=9)
measures density rather than implementing sorting. Section 9 scores recovered
cells; section 6.2's cumulative attack is different.

## Proposed native int2 experiment

Use the complete native PostgreSQL `smallint` domain, **-32768 through 32767**,
so the known domain comes from the public type contract rather than the target
plaintext or a hand-picked subset. Include duplicates and SQL NULLs. Shuffle
placement privately and use unrelated random application-assigned UUID row IDs;
neither row order nor IDs may encode values. Fix and record the fixture design
and generator version before scoring. An auxiliary frequency dataset is not an
input to this experiment.

The application creates the native table and obtains PostgreSQL ground truth,
then protects it through the actual compiler, migration and application path.
Use the existing CF1 order representation and generated index, with explicit
order leakage acceptance. No replacement encoding or attacker-specific token
generation establishes the result. The physical term is the 32 bytes selected
by `pg_catalog.substring(payload, 15, 32)`, where `payload` means the actual
protected column in the selected storage layout. Confirm that extraction against
the compiled field before executing the experiment.

### Honest refusal and adversarial host assertion

This domain is enumerable. First supply an honest small-domain review and
observe ordinary planning refusal, retaining the typed outcome and evidence
about deployment/key effects. Do not weaken that refusal for this experiment.

The subsequent attack setup must explicitly model a **deliberately false host
domain classification**, recording that the synthetic enumerable domain was
classified as nonenumerable to study the residual trusted-host assertion risk.
The resulting deployment is an adversarial fixture, not healthy domain admission.
An acknowledgment of leakage does not make that classification true. Do not
reuse a fixture statement claiming these values actually are nonenumerable.
The ordinary [small-domain contract](../compatibility.md#query-semantics)
and [admission requirements](../compatibility.md#capability-admission) remain in
force.

### Attacker and scorer isolation

Run the attacker in a separate process. Its inputs are only dump-visible opaque
row IDs, tenant, search generation and extracted order terms, plus the independent
public int2 domain. Do not pass plaintext, ground truth, keys, provider handles,
application objects, database credentials or query observations. Remove inherited
credential inputs and use explicit serialized inputs. The attacker must not
import Cryptalis or invoke an attached reader or term-generation API.

Obtain the distinct term order with native PostgreSQL bytea ordering and apply
the published rank assignment independently. Partition by tenant, field and
search generation; terms from different partitions are not comparable. Carry
row IDs only to join predictions back to the scorer. The scorer alone holds the
native PostgreSQL plaintext oracle. Exclude SQL NULLs from the non-NULL recovery
denominator and report their already visible presence separately.

Report row and distinct-value recovery with explicit denominators, domain
coverage, abstentions or inapplicability, elapsed time, observer inputs and
source/runtime/artifact hashes. Coverage checks are experiment observations,
not extra attacker knowledge of individual plaintext assignments. Preserve
failures, skips and cleanup limitations in exact receipts. No such result is
claimed by this design note.

### Controls and interpretation

- **Search rotation:** repeat independently on the new generation. Record term
  replacement and recovery separately. Rotation preserves the order leakage
  needed by this attack; changed bytes do not imply mitigation. Stable visible
  row IDs can also retain previously recovered labels across snapshots.
- **Payload rotation (future extension):** observe whether the search terms
  remain unchanged and repeat inference without granting payload keys. The
  initial profile does not execute this additional attack phase.
- **Sparse population:** remove the minimum domain value while retaining the
  original known domain. Report reduced density and the sorting guarantee's
  inapplicability. Do not present a partial rank heuristic as the published
  cumulative attack.
- **Randomized storage only:** use the same known domain and multiplicities in
  a separate snapshot. Repeated equal plaintexts need not form ciphertext
  classes, so this sorting algorithm's correspondence is absent. Report that
  limit rather than inventing zero recovery or a security-pass result. Any
  supplementary rank heuristic needs its own label and observed chance baseline.

An observed key-lease expiry is a lifecycle failure, not an attack result. A
profile may resume once only after attributing the escaping error to expiry,
inspecting the same saved operation as BACKFILLED with verification NOT_PERFORMED,
and comparing full public frame bytes, row IDs, tenant and NULLs. Retain the
failure and the inspection. Unknown causes, cleanup failures, changed frames or
another resume failure must remain failures. Diagnostic exception-context
inspection in the profile is not a public expiry API or a generic retry policy.

Successful execution would reproduce the paper's sorting mechanism against
current physical order terms. It would not reproduce the hospital datasets or
their recovery percentages. Larger real-data studies, low-density cumulative
attacks, prefix-specific published attacks, approved costs and independent human
cryptographic review remain open. AI research or a successful synthetic attack
cannot promote any of the seven production gates.
