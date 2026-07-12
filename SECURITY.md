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
- privacy handling of receipts. Note: a VCC is a **bearer document** that
  contains **every declared numeric input** in the clear. Even without a name or
  email, those numbers can be sensitive in context (loan amounts, income, age,
  medical figures). There is **no** selective disclosure, redaction, or
  encryption yet, so a VCC must be treated as potentially sensitive and shared
  only deliberately.

Out of scope / known limitations (documented, not hidden):

- VCC is **experimental**. A valid signature establishes integrity and
  attribution to a key — not that the inputs are true, the formula is
  appropriate, or the output is suitable for a particular decision.
- We do not claim compliance with any specific security certification
  (no SOC 2, no ISO 27001) — see `/security`.

## No blockchain

External timestamping (RFC 3161) and a transparency log are a **documented but
currently unimplemented** extension point (see `spec/spec-v0.2.md` §9). VCC does
**not** use a blockchain, tokens, or any distributed ledger, and there is no
plan to. Because a VCC carries all declared numeric inputs in the clear (see
Scope above), any such log, if it ships, must be designed so it does not itself
publish sensitive inputs.
