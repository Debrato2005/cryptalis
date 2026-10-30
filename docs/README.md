# Cryptalis documentation

Cryptalis is a manifest-first application encryption system for PostgreSQL.
The current implementation has bounded verification and is **not production-security-qualified**.
Use this page to find the owner of a question; use [status](status.md) for current evidence.

## Choose a route

| I need to… | Read / run |
|---|---|
| Trace the primary requirements | [20-point SRS and objective mapping](requirements.md) → [34-objective ledger](BUILD_CHECKLIST.md) |
| Understand the project | [Repository overview](../README.md) → [architecture](architecture/README.md) |
| Declare protected data | [Manifest reference](manifest.md) → [supported operations](compatibility.md#full-capability-matrix) |
| Integrate an application | [Shared application configuration](application.md) → [SQLAlchemy/SQLModel attachment](walkthrough-sqlalchemy.md) → [search examples](walkthrough-search.md) |
| Protect, rotate, recover or remove data | [Operator walkthrough](walkthrough-migration.md), with [host context inputs](host-contexts.md) |
| Configure external key custody | [OpenBao setup, AppRole and diagnosis](openbao.md), [Google KMS setup and qualification](google-kms.md), [provider contract](security.md#key-hierarchy-and-providers) |
| Diagnose adoption or runtime issues | [Static Python route inventory](walkthrough-migration.md#inventory-python-code-routes), [Doctor before adoption](walkthrough-migration.md#diagnose-before-adoption), [ACTIVE diagnosis](walkthrough-migration.md#diagnose-an-active-deployment), [cold-provider checks](openbao.md) |
| Run tests or a local demonstration | [Local development](local-development.md) → [optional qualification profiles](qualification.md) |
| See what is verified or missing | [Current status](status.md) → [34-objective ledger](BUILD_CHECKLIST.md) |
| Continue implementation | [Build sequence](build-guide.md) → [engineering playbook](../ENGINEERING_PLAYBOOK.md) |
| Review security or a design choice | [Security](security.md), [lifecycle](lifecycle.md), [decisions](decisions.md) |
| Find a past result or source | [History](history/README.md), [research index](research/README.md), [prior art](prior-art.md) |
| Present the system | [Illustrated guide](professor-guide.md); measurements retain their recorded revision |

## Document owners

| Owner | Defines |
|---|---|
| [Requirements](requirements.md) | Primary SRS obligations and their mapping to all 34 objectives |
| [Architecture](architecture/README.md) | Components, data flow and division between library, host and provider |
| [Manifest](manifest.md) | Declaration syntax, compiler inputs and generated-lock structure |
| [Security](security.md) | Trust boundaries, cryptography, keys, leakage and failure guarantees |
| [Compatibility](compatibility.md) | Exact admitted operations/types/platforms, semantic promises and performance targets |
| [Lifecycle](lifecycle.md) | Migration/rotation/restore/removal state and authority contracts |
| [Application configuration](application.md) | Shared key-free intent, protection/capture, tenant onboarding, active-field changes, attachment, rotations and removal API |
| [Host contexts](host-contexts.md) | Explicit trusted inputs to the operational CLI |
| [Walkthroughs](walkthrough-migration.md) | Procedures and examples that use those contracts |
| [Status](status.md) | Latest executable verification and seven production-gate requirements |
| [Objective ledger](BUILD_CHECKLIST.md) | All 34 requirements, implementation state, remaining gap and next action |
| [Build guide](build-guide.md) | Dependency order and deciding acceptance tests |
| [Decisions](decisions.md) | Governing choices and unresolved trade-offs |
| [Engineering playbook](../ENGINEERING_PLAYBOOK.md) | Work authorization, verification, review and release policy |
| [Local development](local-development.md) / [qualification](qualification.md) | Environment setup, commands and optional verification cells |
| [History](history/README.md) / [research](research/README.md) | Revision-specific evidence and external sources; not alternate current contracts |

## Reading before a change

Read current status and the affected objective row, then the relevant contract
owner and its procedure. For cross-cutting changes, read architecture, security,
lifecycle and compatibility before the build guide and engineering playbook.
Follow current user authorization; historical pauses and workstation paths are
not current operating instructions.

Update the owner of a changed fact. Link to it from other pages instead of
copying the rule, test totals or checkpoint narrative. Keep machine receipts
immutable. New historical evidence belongs in history; current status is updated
in place. No document or passing test count alone qualifies a release.
