# ADR-007 — Privacy model: certificates shareable by construction

Status: **Accepted** (2026-07-11)

## Context

Certificates are meant to be posted publicly (forums, PRs, AI-agent transcripts). They must not leak who asked. GDPR posture of the site is minimal-data; VCC must not regress it.

## Decision

1. **Privacy by construction**: a formula is certifiable only if every input field is numeric, boolean, or a closed enum (checked by the registry gate against the input JSON Schema). Free-text input fields disqualify a formula from certification in v0.2. All three pilots are all-numeric.
2. `context` (requestContext) allows exactly two fields:
   - `surface`: enum `api | web | mcp | graph`;
   - `requestId`: optional, opaque, `^[A-Za-z0-9_-]{8,64}$` — generated server-side (random), never taken from user input, never an email/IP/user-agent by pattern-check.
3. **Privacy guard** (`src/lib/vcc/privacy.ts`) runs on the *complete* statement before signing and rejects:
   - forbidden key names anywhere (case/format-insensitive): `email`, `e_mail`, `ip`, `ipAddress`, `userAgent`, `name`, `firstName`, `lastName`, `phone`, `address`, `ssn`, `taxId`, `prompt`, `sessionId`, `cookie`, `authorization`, `token`, `password`, `secret`, `advertisingId`, …;
   - string values matching PII patterns: email regex, IPv4/IPv6, E.164 phone-like, JWT-shaped (`xxx.yyy.zzz` base64url triplets), long free text (> 200 chars outside allowlisted fields);
   - any statement field not in the schema (Zod strict objects — unknown keys are rejected, so PII can't ride in extra fields).
4. Issuance **fails closed**: guard violation ⇒ no certificate (calc result still returned).
5. Nothing user-identifying is logged with certificates; metrics use the opaque requestId only.

## Alternatives considered

- Redaction (strip PII, then sign): rejected — silent mutation of what the user sent is worse than refusing; and "sanitized" PII detection is unwinnable. Fail-closed is honest.
- Salted-hash of user id for dedup/abuse: rejected for v0.2 — hashes of identifiers are still personal data under GDPR; no product need identified.
- Allowing arbitrary `context` keys with a blocklist: blocklists lose; schema allowlist (strict Zod) wins.

## Consequences

- A shared certificate reveals: formula, version, inputs (numbers), outputs, timestamps, issuer — and nothing about the requester beyond an opaque id that only CalcFleet's own logs could correlate.
- Future formulas with text inputs (e.g. labels in recipe scaler) need either input-schema tightening or a v0.3 privacy review before certification.

## Risks

- Numeric inputs can themselves be sensitive in context (a salary is a number). Mitigation is user-side disclosure choice: certificates are issued only when explicitly requested (`certify=1`), documented in `docs/vcc/privacy.md`, and never stored unless the store flag is on.
