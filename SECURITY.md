# Security Policy

CalcFleet operates the reference implementation of the VCC (Verifiable
Calculation Certificate) experimental open protocol, plus the calculator
site, API and MCP server.

## Reporting a vulnerability

Please report suspected security issues privately to **privacy@calcfleet.com**
(a dedicated security inbox is being set up; this address is monitored in the
meantime). Include:

- a description of the issue and its impact;
- steps to reproduce, or a proof of concept;
- affected surface (site, API, MCP, VCC issuance/verification, verifier).

Please do **not** open a public issue for undisclosed vulnerabilities.

## Coordinated disclosure

- We aim to acknowledge reports within a reasonable time and to keep you
  informed while we investigate.
- We ask for a reasonable disclosure window so a fix can ship before details
  are made public.
- We will credit reporters who wish to be credited, once a fix is available.

## Scope

In scope:

- signature verification and canonicalization of VCC receipts;
- the algorithm allowlist (Ed25519 only — no algorithm downgrade path);
- key handling and the separation between the **test issuer** and any future
  **production issuer** (a test-key receipt carries no production assurance);
- API/MCP input validation, rate limiting and abuse prevention;
- privacy of receipts and of the transparency log (no sensitive inputs are
  published).

Out of scope / known limitations (documented, not hidden):

- VCC is **experimental**. A valid signature establishes integrity and
  attribution to a key — not that the inputs are true, the formula is
  appropriate, or the output is suitable for a particular decision.
- We do not claim compliance with any specific security certification
  (no SOC 2, no ISO 27001) — see `/security`.

## No blockchain

The transparency log is an append-only, Merkle-root log. It does not use a
blockchain and does not publish sensitive inputs.
