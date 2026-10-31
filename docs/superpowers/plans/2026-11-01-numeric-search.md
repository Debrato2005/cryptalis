# Numeric equality search plan

Reuse packed CF1 and full HMAC terms for finite native NUMERIC equality, IN and
tenant-scoped uniqueness. Canonicalize only search bytes: trim coefficient
trailing zeroes and adjust the decimal exponent, with one zero token. Keep
authenticated stored scale unchanged. Pin the normalizer/reader and lock/v13
only for numeric search; older storage locks retain their bytes.

- [x] Add native PostgreSQL query/write/uniqueness oracles and observe refusal.
- [x] Implement canonical terms, original bind semantics, compiler/reader and profile transitions.
- [x] Verify NULL, aliases/counts, races, all rotations, online writes and both exits.
- [x] Verify installed/fresh recovery/older reader; preserve failures and exact receipts.
- [x] Update current contracts and ledger, review, refresh graph, commit and push.

Numeric order/arithmetic, nonfinite values, broader coercions and production
qualification remain required work. No production gate changes.
