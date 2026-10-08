# Primary research and design comparison

Sources accessed 2026-10-06 UTC during the revamp. These dated comparisons are INTERNAL ONLY research, not Cryptalis compatibility evidence.
SPECIFIED: the approved public scope is text storage, equality/IN, and tenant-scoped uniqueness.
Range/order/prefix/text-search mechanisms below remain UNSUPPORTED BY DESIGN as public capabilities until [admission](compatibility.md#capability-admission).
No competitor was installed, audited, benchmarked, or reproduced end to end.
[Decisions](decisions.md) owns choices. [Compatibility](compatibility.md) owns query admission and local measurements.

## Systems

| System / primary source | Relevant mechanism and integration | Decision and evidence limit |
|---|---|---|
| [CipherStash EQL](https://github.com/cipherstash/encrypt-query-language), [text reference](https://cipherstash.com/docs/reference/eql/text) | Client emits payload and capability terms. Current EQL uses domains/functions; full HMAC equality, native byte-order OPE, and probabilistic text match are distinct mechanisms | Separate capability representations are useful. Custom DB types/operators violate this task's stock rule. EQL text match is not exact LIKE. Published features are not our support |
| [CipherStash cryptography](https://cipherstash.com/docs/security/cryptography), [CLLW crate](https://docs.rs/cllw-ore/latest/cllw_ore/) | Native-order OPE allows ordinary lexical byte comparison. Block ORE instead needs its comparator. Source/license and leakage differ | OPE is a viable stock bytea research path; do not call ordering impossible. Binding, license, vectors, leakage attacks and costs remain unqualified |
| [Acra searchable encryption](https://docs.cossacklabs.com/acra/security-controls/searchable-encryption/) | Client/proxy HMAC prefix plus authenticated encrypted block; query rewriting supplies exact equality | Packed term/payload is useful. Proxy parsing adds deployment and coverage burden. It does not give arbitrary LIKE or prove SQLAlchemy behavior |
| [CipherSweet security](https://ciphersweet.paragonie.com/security), [FAQ](https://ciphersweet.paragonie.com/faq) | Randomized authenticated fields plus purpose-separated truncated blind indexes. Application postprocessing removes deliberate false positives | Truncation is a different leakage/semantics trade-off. It cannot silently preserve our LIMIT, uniqueness or exact-query contract. Full terms disclose equality classes |
| [MongoDB Queryable Encryption](https://www.mongodb.com/docs/manual/core/queryable-encryption/fundamentals/encrypt-and-query/), [driver specification](https://github.com/mongodb/specifications/blob/master/source/client-side-encryption/client-side-encryption.md) | Driver transformations and structured metadata collections support operator-specific bounded equality/range/text protocols. Parameters constrain domains and expansion | Range/text can be useful without plaintext SQL. Metadata/write cost and version-specific driver support matter. No PostgreSQL portability or blanket current-version claim follows |
| [AWS Database Encryption SDK beacons](https://docs.aws.amazon.com/database-encryption-sdk/latest/devguide/beacons.html) | Client field encryption with truncated/partitioned HMAC beacons. Frequency, collision and candidate planning are explicit | Keep leakage and costs visible. Beacons are not full-width uniqueness and do not establish PG support |
| [AWS KMS concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html), [data-key caching](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html) | Mature external key authority and cached plaintext data material can avoid a network operation for each warm field | Wrap two roots and derive locally. Exact IAM/context/outage/cache lifetime still needs adapter tests. Provider key disable does not recall cached keys |
| [Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit), [API](https://developer.hashicorp.com/vault/api-docs/secret/transit) | Key versions, data keys, rotate/rewrap, minimum versions and deletion controls | Rewrap need not rewrite data. Vault is a separate custody profile, not an interchangeable tested substitute |
| [GCP envelope encryption](https://docs.cloud.google.com/kms/docs/envelope-encryption) | External KEK wraps locally used data keys | Relevant provider model. No live GCP observation or deletion/restore claim |
| [Tink client-side encryption](https://developers.google.com/tink/client-side-encryption), [wire format](https://developers.google.com/tink/wire-format?hl=en) | Encrypted keysets and envelope AEAD have different RPC and key-lifetime behavior. Keysets retain old decrypt readers | Reuse mature key-management concepts. Per-message envelope RPC is not the selected warm path. Tink does not prove our adapters |
| [SQLAlchemy public custom types](https://docs.sqlalchemy.org/en/20/core/custom_types.html), [type API](https://docs.sqlalchemy.org/en/20/core/type_api.html) | TypeDecorator/comparator and outermost column_expression are public. Session and compiler APIs supply separate statement/state boundaries | A scalar decorator alone lacks row context and async provider orchestration. Native mapper/history should remain. Full public-hook coverage requires an application oracle |
| [psycopg 3 COPY](https://www.psycopg.org/psycopg3/docs/basic/copy.html) | Driver COPY is an independent data path | Inventory or reject it. ORM events alone cannot protect a separate driver |
| [PostgreSQL expression indexes](https://www.postgresql.org/docs/16/indexes-expressional.html), [GIN](https://www.postgresql.org/docs/16/gin-builtin-opclasses.html), [advisory locks](https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS), [transactions](https://www.postgresql.org/docs/16/sql-begin.html) | Built-in bytea/array classes index client terms. Transactions cover chunk plus marker. Advisory locks coordinate cooperating sessions | Reuse native behavior. Locks do not fence external provider effects or unknown writers. A lost COMMIT reply remains ambiguous until inspected |
| [Rails Active Record Encryption](https://guides.rubyonrails.org/v8.1/active_record_encryption.html) | Normal attribute API, deterministic query/uniqueness option, previous schemes and read compatibility | Transparent attributes need explicit equivalence and retained readers. Deterministic payload is not our randomized payload default |
| [Lockbox](https://github.com/ankane/lockbox), [blind_index](https://github.com/ankane/blind_index) | Normal model queries with separate indexes, staged backfill and rotation. Leakage and chosen-input attacks are documented | Retain familiar syntax and migration visibility. Mutable-name key derivation complicates renames. Online dual-write rotation is not proof of our maintenance engine |
| [pyope](https://github.com/tonyo/pyope) | Python implementation of a different published OPE family | An alternative research implementation, not a selected audited dependency. It does not remove order-inference attacks |

## Query construction comparison

| Construction | Exact useful behavior | Reason for selection or rejection |
|---|---|---|
| Full HMAC term | Equality/membership and race-safe indexed uniqueness under collision-resistance/intact-index assumptions | Select for the approved equality scope. Do not disguise frequency leakage or claim unconditional collision detection |
| Packed term/payload | Same equality with a built-in substring expression index | Select default physical option. Generated/separate terms remain compiler choices for constraints |
| Truncated beacon/Bloom | Candidate membership with deliberate false positives | Reject transparent exact predicates and UNIQUE. Never hide postfilter/refill behavior |
| Coarse buckets | Range candidates needing boundary checks | Reject exact public comparisons unless a different explicit contract proves complete results |
| Full keyed binary-tree path | Exact finite-domain interval membership without a boundary postfilter | Retain INTERNAL ONLY range candidate. It leaks structure and expands writes. No ordering claim |
| Native-byte OPE | Exact byte-order comparisons after a qualified order codec | Retain viable research path. Complete order leakage, license and independent review block admission |
| Custom-comparator ORE | Published order comparisons | Reject database mechanism under stock rule. It needs an excluded operator/type |
| Complete prefix arrays | Exact qualified literal prefix | Retain INTERNAL ONLY prefix candidate with length bounds and opt-in. Not arbitrary LIKE/ILIKE |
| Ngrams/trigrams/Bloom text | Candidate containment, not exact substrings/phrase/regex | Reject transparent claims. The local counterexample proves a semantic mismatch |
| Structured range/text encryption | Richer exact protocols can exist | [Rich-query research](https://eprint.iacr.org/2015/927) refutes blanket impossibility. Metadata/client-round costs and state enlarge the selected small library |
| Encrypted inverted index | Frozen token grammar; positions/ranking need more data | Explicit API research. Avoid reproducing a search engine or silently exporting plaintext |

## Leakage and algorithm evidence

[AES-GCM-SIV RFC 8452](https://www.rfc-editor.org/info/rfc8452/) and the [cryptography AEAD API](https://cryptography.io/en/stable/hazmat/primitives/aead/)
supply primitive behavior and implementation requirements. They do not qualify our KDF/AAD/search composition or aggregate usage bounds.
AES-GCM and ChaCha20-Poly1305 require disciplined nonce uniqueness. Extended-nonce alternatives have different portability/dependency costs.
The installed AESGCMSIV implementation and existing local experience support retaining it as a candidate, with fresh OS nonces and independent review.

[Naveed et al., CCS 2015](https://www.microsoft.com/en-us/research/publication/inference-attacks-property-preserving-encrypted-databases/)
shows frequency/sorting inference against property-preserving databases. Our experiments apply frequency ranking to our full-term/array equivalence classes.
The measured synthetic rates do not generalize to customer distributions.
[Range structure and volume attacks](https://eprint.iacr.org/2022/090) explain why hiding node labels does not make range arrays opaque.
That paper's structural attack and a sorting attack against an implemented order representation remain unexecuted here.
No ORAM/PIR, forward/backward privacy or query-obliviousness claim is made.

## Deployment portability

No selected capability needs an extension, so the adopted extension list is empty.
These provider pages were inspected for extension policy rather than treated as executed compatibility evidence:
[RDS](https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-extensions.html),
[Aurora](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraPostgreSQLReleaseNotes/AuroraPostgreSQL.Extensions.html),
[Cloud SQL](https://docs.cloud.google.com/sql/docs/postgres/extensions?hl=en),
[Azure](https://learn.microsoft.com/en-us/azure/postgresql/extensions/concepts-extensions-versions),
and [Supabase](https://supabase.com/docs/guides/database/extensions).
The Neon pg_trgm documentation fetch failed in this environment. No all-provider pg_trgm allowance is therefore asserted.
No adopted mechanism depends on that allowance. Every real service remains UNKNOWN until the identical suite runs there.

## Developer pain and evidence limits

The [CipherSweet maintainer issue](https://github.com/paragonie/ciphersweet/issues/39) records confusion about index choice, not defect prevalence.
Its dated FAQ observation explains why deliberate false-positive indexes require application postprocessing.
The EQL troubleshooting documentation records a native-semantics fallback risk from untyped query operands and index recreation after upgrades.
Those are scenarios for typed-bind, query-equivalence and migration tests, not claims that every encrypted database has those defects.
Blind Index documents explicit case-insensitive equivalence, unique database indexes, migration and rotation costs.
These primary reports support plan-time compatibility review and a real package-free exit test.

Earlier [integration/search evidence](research/reset-integration-search-evidence.md), [crypto/authority evidence](research/reset-crypto-authority-evidence.md),
[leakage research](research/reset-leakage-semantics-evidence.md), and [operations/release evidence](research/reset-operations-release-evidence.md)
remain dated archives. Their old scope exclusions and control-plane choices are superseded.
No community report, vendor benchmark, AI review, document or narrow spike supplies a production audit.
