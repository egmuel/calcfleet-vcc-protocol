# VCC Governance — normative notes

Companion to the repository-level [`GOVERNANCE.md`](../../GOVERNANCE.md). This
document holds the normative wording referenced by the protocol pages
(`/protocol`, `/protocol/governance`). It supersedes nothing in the code; it
describes process.

## 1. Change process

1. A problem or proposal is raised (issue or draft ADR).
2. It is written as an ADR under `docs/adr/` using the decision-record template
   (Problem / Proposal / Alternatives / Security implications / Privacy
   implications / Compatibility / Decision).
3. Security- and privacy-affecting changes require an explicit section; they are
   not merged without one.
4. Accepted ADRs update the specification text and, where relevant, the JSON
   Schema, test vectors and conformance corpus together (no drift).

## 2. IP policy

- Contributions to the **code** are accepted under Apache-2.0 (inbound = outbound).
- Contributions to the **specification text** are accepted under CC-BY-4.0.
- The Apache-2.0 patent grant protects independent implementers.

## 3. Protocol adoption gates

Public claims change only when objective gates are met (master doctrine §50):

| Level | Requires | Allowed claim |
|---|---|---|
| **Experimental** (current) | public spec, schema, reference verifier, test vectors, reference implementation, security considerations | "experimental open protocol" |
| Interoperable | ≥2 independent verifiers, ≥1 independent issuer, cross-language conformance, public interop report, no mandatory CalcFleet dependency | "interoperable open protocol" |
| Pilot-ready | ≥3 external orgs, ≥2 use cases, documented dispute/review workflow, security review, key + receipt lifecycle tested | "being piloted in real business workflows" |
| Standardization candidate | independent governance participation, several interoperable implementations, public change process, stable core, external adoption, conformance suite, operational experience | "candidate for broader standardization" |

We do not use "standard" as a fait accompli before a formal process.

## 4. Deprecation policy

- Breaking changes to the core data model bump the minor version while `v0.x`.
- A deprecated field or profile is marked in the changelog with a migration
  note and kept readable by verifiers for at least one minor version.
- Receipts already issued remain verifiable at L1 (signature/integrity) even if
  a formula package is later superseded; reproduction (L2) availability is
  reported honestly (resolvable / archived / mirror / unavailable).

## 5. Neutrality test

Before any release, we check: **can an independent party implement and verify a
VCC without calling CalcFleet services?** Where the answer is "not yet" (e.g. a
formula package resolvable only via CalcFleet), the dependency is declared and a
mirror/export path is documented, per the vendor-independence requirement.
