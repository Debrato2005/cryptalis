# Exact text prefix implementation

Requirement 5 and OBJ-QUERY-03 need useful text search. Implement native
terminal-prefix LIKE/startswith on exact UTF8 TEXT/VARCHAR, with explicit
prefix leakage acceptance and min/max Unicode prefix lengths. Source values
are not truncated; queries outside declared prefix bounds refuse. Interior
wildcards, case-insensitive matching, fulltext and substring remain obligations.
This is an INTERNAL ONLY synthetic prototype. Ordinary intent, saved artifacts
and retained runtime/crypto use must refuse before effects. Completing this
engineering plan does not complete capability admission or requirement 5.

Use full domain-separated HMACs in a fixed-size authenticated CF1 header:
existing equality term at byte14, followed by sorted ASCII hex slots, one for
equality plus one per declared prefix length. Reserved padding fills unused
slots. Flag5, context/v3, lock/v14 and pg-text-prefix/v1 distinguish the format.
This keeps existing constant growth/budgets and one-column storage. Native GIN
uses immutable substring/encode-escape/string_to_array; no new primitive,
provider, extension or executor. Costs can exceed the 2× storage target and must
be measured honestly. Existing six capability-admission gates and
independent review remain required and UNKNOWN.

- [x] Native PostgreSQL query/escape/NULL oracle first; retain baseline refusal.
- [x] Implement declaration/reader/framing, full-header authentication and indexed rewriting.
- [x] Preserve both indexes, metadata, byte bounds and headers across the full lifecycle.
- [x] Verify source/installed, both fresh layouts, old reader, native exit and failure controls.
- [x] Record exact sources, leakage, costs, failures and receipts; review and refresh graph.

Delivery follows comparison of all recorded Python/build-input hashes with the
commit, then push. [Exact evidence](../../_reset/prefix-boundary-20261101.json)
retains 704 source passes and 11 skips, 144 installed passes, both fresh layouts
and the 13.1527× post-maintenance storage MISS. No capability admission follows.

Primary sources: [PG16 LIKE](https://www.postgresql.org/docs/16/functions-matching.html#FUNCTIONS-LIKE),
[PG16 GIN](https://www.postgresql.org/docs/16/gin-builtin-opclasses.html),
[SQLAlchemy startswith](https://docs.sqlalchemy.org/en/21/core/sqlelement.html#sqlalchemy.sql.expression.ColumnOperators.startswith).
Installed SQLAlchemy2.1.3 and PG16 catalog/source observations take precedence
over a different live documentation version. Native E2Es decide actual behavior.
