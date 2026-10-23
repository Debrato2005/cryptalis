# Research evidence index

[Revamp evidence](revamp-evidence.md) records the current simplified architecture's experiments, decisions and incomplete goal requirements.
[Prior art](../prior-art.md) links current primary sources. [Status](../status.md) owns runtime claims.

[Metadata preservation and lock evolution](metadata-preservation-and-format-evolution.md)
records verified catalog gaps and format-evolution options. It is research evidence, not an
approved format or contract.
[Lab reconciliation](lab-reconciliation-2026-10-19.md) records the external lab state,
the seven held S16 assertions and the product-side signals. It adopts no lab code or claim.
[Lock v2 metadata proposal](lock-v2-metadata-proposal.md) requests a format decision for
capturing and restoring refused metadata. It is proposed, not approved, and changes no
behavior.

[Performance checkpoint](performance-checkpoint.md) records the approved identity-only membership correction, measured limits and future proposals.
Its byte-budget and online designs require separate review; they are not lifecycle contracts or implemented features.

All reset, hardening, cryptographer-packet and council-review-1/2 files are **historical evidence of replaced contracts**.
Their old AWS authority, mirror, mapper, query-scope, gate counts and production assumptions do not define the current architecture.
Historical links and stored source hashes describe their original review context. They do not certify the rewritten owners.
Verbatim reviewer text and historical preservation receipts remain unchanged.

The new owner map and revamp dispositions identify retained essentials and deliberately removed mechanisms.
Git and the preserved baseline contain the replaced wording. No old evidence file is an alternate current specification.

## Local research extraction

Use built-in web search to find primary sources, direct downloads for files and
local Crawl4AI for page Markdown. This is development tooling outside the
Cryptalis runtime. Paid services and LLM extraction stay disabled. Ordinary
HTTP is the default; use browser rendering only for required JavaScript content.
Do not bypass authentication, bot challenges or access controls.

The current machine uses the official pinned Crawl4AI 0.9.5 source archive in
`.research-tools/source/`, with its complete license retained. Its SHA-256 is
`7546c104b59c9849233d3788856308d6438e4e479023ff933ca4a5f66264ad7d`.
The isolated environment, browser files, package state and extraction cache live
under ignored `.research-tools/`. They do not change project runtime dependencies.
The helper is [research_extract.py](../../tools/research_extract.py).
The [setup receipt](../_reset/local-research-extraction-20261023.json) records
the installed inventory, source hashes, failed setup attempts and successful
HTTP, browser, cache and local JavaScript checks.

```console
.research-tools/crawl4ai-0.9.5/bin/python tools/research_extract.py https://www.postgresql.org/docs/16/collation.html --expect "same byte sequence"
```

The helper checks HTTP status, final URL, title and a required passage. It caches
HTML, Markdown, source links, retrieval time and content hashes. A second call
reuses the verified Markdown without another request. Use `--refresh` for an
explicit new retrieval. Add `--render` when the source requires JavaScript.
Python dotenv loading, LLM extraction, model-cost network refresh and LiteLLM
telemetry are disabled. The base upstream package includes SDK dependencies;
installation does not authorize model calls or a hosted service.

Installation uses the official [v0.9.5 source](https://github.com/unclecode/crawl4ai/tree/v0.9.5)
in a separate virtual environment. Chromium is installed only in the local
research browser cache. Preserve the [upstream license](https://github.com/unclecode/crawl4ai/blob/v0.9.5/LICENSE)
and its attribution when reproducing this setup. No global Codex configuration
or Graphify hook is required.

This product includes software developed by UncleCode (https://x.com/unclecode)
as part of the Crawl4AI project (https://github.com/unclecode/crawl4ai).
