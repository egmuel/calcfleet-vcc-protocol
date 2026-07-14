# Roadmap

VCC is an **experimental open protocol**. This roadmap is organized by phase,
not by date, and every item is labeled honestly:

- **Shipped** — in this repository, runnable today, covered by conformance.
- **Designed** — a written design exists (ADR or spec section); no code here yet.
- **Idea** — direction we believe in; no committed design.

Public claims escalate only when the objective adoption gates in
[`spec/governance.md`](spec/governance.md) are met — *experimental* →
*interoperable* → *pilot-ready* → *standardization candidate* — and never
before.

## Now

The current phase has one goal: make the verifier layer boring, multi-language,
and attack-resistant.

| Item | Status |
|---|---|
| v0.2 data model, spec, and JSON Schemas (envelope, statement, keyset, manifests) | **Shipped** |
| Two independent L1 verifiers — TypeScript and Python, written separately | **Shipped** |
| Cross-language conformance: both verifiers match the pinned reference outcome on all 32 checks, with JCS byte-for-byte parity | **Shipped** |
| Conformance corpus: 4 golden receipts + 24 negative vectors, each pinning the axis that must fail | **Shipped** |
| 4 formula packs with golden receipts: `personal-loan-calculator`, `compound-interest-calculator`, `home-affordability-calculator`, `tiered-commission-calculator` | **Shipped** |
| Standalone L2 reproduction (offline, local-allowlist-only, ADR-005) for `compound-interest-calculator@1.0.0` | **Shipped** |
| Runnable examples — download → verify → break → reproduce ([`examples/`](examples/)) | **Shipped** |
| L2 local packages for the other three formulas (today they correctly fail closed as `formula-unavailable`) | In progress |
| Growing the negative-vector corpus as new attack shapes are found | Ongoing |

## Next

Everything here is **designed, not shipped**. The designs are additive on
purpose: none of them changes the signed bytes of existing receipts, so the
golden vectors keep verifying unchanged.

| Item | Status | Notes |
|---|---|---|
| **Input provenance, phase 1** — a *detached*, signed provenance envelope indexed by receipt id (`signed-source-receipt`, `system-of-record`, `human-approval`, `upstream-vcc-receipt`, `asserted-by-issuer`) | **Designed** | Provenance proves *"this input came from signed source S"* — never *"S told the truth"*. It stays a separate axis, never folded into trust. |
| **Input provenance, phase 2** — optional `evidence.inputProvenance` field in the statement | **Designed** | JCS omits absent optional keys, so receipts that don't use it stay byte-identical. |
| **Chained receipts** — the output of one receipt used as a verified input of another, protected by content-addressed ids | **Designed** | The path toward the reserved `pipeline/v0.2` statement type. |
| **Custom formula packs, Tier-0 (L1-only)** — third parties register their own versioned formulas and issue receipts against them, with no reproduction promise yet | **Designed** | Reproduction (Tier-1/2, portable deterministic modules) comes later. |
| Examples for insurance, usage-based pricing, and AI-agent calculations | Blocked, honestly | Added **only when real formula packs exist** for those domains. No placeholder directories, no synthetic demos. |

## Later

Directions, not commitments.

| Item | Status |
|---|---|
| **Operational transparency log** — an append-only, Merkle-anchored log of issued receipts operated as production infrastructure (an MVP demo exists on the reference implementation; it is not load-bearing and this repo does not depend on it) | **Idea** |
| **Federated issuers** — multiple independent issuers with their own keysets, discoverable and revocable, without any central registry | **Idea** |
| **Formal governance** — moving beyond the current lightweight [`GOVERNANCE.md`](GOVERNANCE.md) as (and only if) independent implementations and adopters appear | **Idea** |
| **Portable L2 modules** — digest-addressed, sandboxed deterministic formula packages (e.g. WASM) so reproduction stops requiring per-language reimplementation | **Idea** (extension point recorded in ADR-005) |
| spec v0.3 — only when an accumulated set of additive changes justifies a version bump | **Idea** |

## What would change this roadmap

- An **independent implementation** by someone we've never talked to — the
  strongest possible signal, and the trigger for broadening governance.
- A **real counterparty dispute** resolved (or not) with a receipt — field
  evidence beats design documents.
- A **cryptographic or canonicalization break** reported through
  [`SECURITY.md`](SECURITY.md) — that preempts everything else.
