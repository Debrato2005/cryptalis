# Native order-term sorting attack evidence

Requirements 4, 5 and 15 and OBJ-QUERY-03 require evidence about dump-visible
order leakage. Implement the published Naveed/Kamara/Wright CCS2015 §6.1
sorting algorithm against actual CF1 order terms stored by the product on
PostgreSQL 16. This is assurance work, not a new representation or admission.

The synthetic target covers the complete signed int2 domain, with duplicates,
NULLs, private shuffled placement and unrelated random row IDs. Random provider
material stays with the application. A separate attacker process receives only
dump-visible terms/opaque row IDs and the independently known codec domain.
Native PostgreSQL supplies ground truth only to the scorer.

The enumerable-domain review must reject an honest declaration. Any subsequent
leak experiment explicitly models a deliberately false host domain attestation;
it must not weaken that refusal or describe the configuration as healthy admission.
Repeat after search rotation. Report storage-only and sparse-population controls
as outside the sorting algorithm's assumptions, without a security-pass claim.

- [x] Confirm the primary algorithm, license/provenance and exact assumptions.
- [x] Implement the native lifecycle and isolated attacker profile.
- [x] Run source and inspected installed-wheel E2Es with identical source bytes.
- [x] Record recovery denominators, controls, failures and exact receipts.
- [x] Update contract/status/ledger and refresh navigation.

Delivery follows comparison of all 316 recorded Python files and unchanged
package build inputs with the commit, then push. The
[exact boundary](../../_reset/order-sorting-boundary-20261101.json) retains the
initial failure, narrower earlier tenant comparison and final source/installed
evidence. This engineering checkpoint does not complete the product goal.

No hospital dataset or real-world recovery percentage is reproduced. The
low-density cumulative attack, prefix attacks, human review, performance and
all seven production gates remain separate requirements.
