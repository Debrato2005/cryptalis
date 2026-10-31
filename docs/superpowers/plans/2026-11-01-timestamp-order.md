# Timestamp range and ordering implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan inline.

**Goal:** Apply the existing explicit `order` capability to admitted naive timestamps.

**Architecture:** Reuse the signed eight-byte timestamp codec and the existing CLWW order representation. Require the same leakage opt-in and a new `pg-timestamp-order/v1` reader tag; storage-only timestamps keep their existing bytes and behavior.

**Tech stack:** Existing CF1, PostgreSQL 16 B-trees and SQLAlchemy.

**Spec:** Requirements 5/6 and `docs/compatibility.md#order-search`.

- [x] Extend the existing native Invoice oracle with a timestamp field, microsecond boundaries, ranges, sorts, paging and current edits.
- [x] Observe its current admission failure, then extend only codec/compiler admission and reader validation.
- [x] Verify native sync/async behavior, rotations, search enable/disable, removal, source-role capture, an older-reader refusal and installed-package behavior.
- [x] Update current contracts and bounded evidence, refresh the local graph, commit and push.

Order/equality/frequency leakage remains explicit. No ordering is enabled by default; timestamp timezone support and broader precisions remain separate work. Production qualification remains UNKNOWN.
