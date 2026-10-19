# Layout evaluation: in-place v1 compared with retained-native research

Status: decision support. This file is not a contract. Promotion of a new
layout requires a versioned architecture amendment and human approval.

Date: 2026-10-19. Author: implementation agent. Evidence: current source,
six local commits, 2026-10-19 receipts, and the research tree in
`/tmp/opencode/research-s20/candidate`.

## Question

Which layout gives the safest complete decrypt-back and removal path for the
current product:

- `cryptalis.transition/v1` in-place: at switch, drop the original column and
  rename the CF1 payload column to the original name.
- Retained-native research: at switch, keep the original column and write
  NULL, an empty string or filler. Drop original constraints and indexes.
  Keep the CF1 payload in a companion bytea column.

## Findings

| Criterion | In-place v1 | Retained-native |
|---|---|---|
| Plaintext in the original public column after protection | None. The column is gone. | None. The column holds NULL, `''` or filler. |
| Native read of the original column while protected | Fails loudly. The type is bytea, not text. | Returns filler silently. A stale reader can write wrong data without an error. |
| Physical column order and identity | Not restored. `attnum` follows the payload column. | Preserved. The original slot stays. |
| Original constraints and indexes | Dropped at switch. Reverse restores them from `field.original`. | Dropped at switch. Reverse restores them from `field.original`. |
| Comments, statistics targets, storage, compression | Not captured by the compiler lock. Lost at switch. | Not captured by the compiler lock. Lost at switch. |
| Existing encrypted databases and backups | The only admitted format. | No admitted upgrade path. A new format strands v1 artifacts without an explicit converter. |
| Crash recovery and resume | Journaled phases with committed chunks and 2026-10-19 friction tests. | Research tests exist. The product port is incomplete. |
| Switch cost | Metadata only: DROP COLUMN and RENAME COLUMN. | Metadata only: constraint and index drops, one UPDATE per row. |
| Reverse machinery | This slice adds `cryptalis.reverse/v1`. | Research `deprotection.py` depends on modules the product does not contain. |

## Decision

Keep `cryptalis.transition/v1` as the only admitted protection format.
Implement `cryptalis.reverse/v1` for it now. Do not promote the
retained-native format.

Reasons:

1. Existing v1 databases need a recovery path first. A new format does not
   help them.
2. Retained-native leaves a silent wrong value in the public column. The
   repository rule says: nothing important may fail silently.
3. One format plus one reverse module is less machinery than two formats,
   a converter and a cutover procedure.

## Known gaps to record in the removal evidence

- In-place reverse cannot restore the physical column order. Applications
  that rely on positional `SELECT *` output must adjust. Retained-native
  does not have this gap.
- The compiler lock does not record comments, statistics targets, storage
  or compression settings. Neither layout can restore them. A later
  transition-format revision can record them.
- A retained-native decision requires an architecture amendment. Its one
  material advantage is the original column slot. Its one material risk is
  the silent filler value.
