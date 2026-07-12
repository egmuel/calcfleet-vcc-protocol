# VCC Governance

This document describes how the **VCC (Verifiable Calculation Certificate)**
experimental open protocol is governed. It is deliberately lightweight: VCC is
early, and the goal of publishing governance now is to make the "open" claim
substantiable — anyone can implement the protocol without CalcFleet's services.

## Status

VCC is an **experimental open protocol**. CalcFleet is its **first reference
implementation**. This is not a mature or ratified standard. Claims escalate
only when objective adoption gates are met (see the protocol adoption gates in
`docs/vcc/governance.md`).

## Licensing

- **Code** (reference implementation, verifier, schemas, test vectors):
  Apache-2.0 — see [`docs/vcc/LICENSE-CODE`](docs/vcc/LICENSE-CODE). Includes a
  patent grant so third parties can implement the protocol safely.
- **Specification text**: CC-BY-4.0 — see
  [`docs/vcc/LICENSE-SPEC`](docs/vcc/LICENSE-SPEC).

## Neutrality (load-bearing)

The protocol **must be implementable without using CalcFleet's commercial
services**. Any part of the protocol that cannot currently be implemented
independently is declared experimental, with a documented path to fix it. This
is a condition for adoption, not a courtesy.

## Decision process

Normative changes are recorded as **ADRs** (Architecture/Any Decision Records)
under `docs/adr/`. Each decision record states:

```
Problem
Proposal
Alternatives
Security implications
Privacy implications
Compatibility
Decision
```

## Versioning & deprecation

- The protocol uses **SemVer**. The current data model is `v0.x` (unstable
  core; breaking changes allowed with a changelog entry).
- Formula packages and receipts carry their own versions; a formula change is a
  version change (a receipt pins the exact formula version it used).
- Deprecations are announced in the changelog with a migration note; nothing is
  silently removed.

## Maintainers

Maintained by CalcFleet during the reference-implementation phase. As
independent implementations appear, governance is expected to broaden — this is
tracked in the roadmap. Contact: **privacy@calcfleet.com**.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability reporting process.
