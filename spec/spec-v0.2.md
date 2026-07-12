# Verifiable Calculation Certificates — Spec v0.2 (as implemented)

This document describes the format **actually implemented** in this repository (`src/lib/vcc/`), not an aspirational one. Normative words (MUST/SHOULD) bind implementations of v0.2.

## 1. What a VCC proves — and what it does not

A VCC proves: **who issued it** (signature + key discovery), **which formula+version** ran (manifest digest), **which validated inputs** were used, **which outputs** were produced, **which versioned datasets** were consumed (digests), **which numeric rules** applied (`vcc-decimal-v1`), **that nothing changed after signing** (DSSE over canonical bytes), and — when the verifier holds the same formula version — **that re-execution reproduces the outputs** (L2).

A VCC does **not** claim: that inputs are true; that the formula is legally/economically appropriate for a purpose; that the result is advice or a decision; regulatory compliance; or that a valid signature equals an independent audit. Interfaces MUST NOT collapse authenticity, trust and reproducibility into a single "verified" boolean.

## 2. Statement (semantic layer)

Media type: `application/vnd.vcc.statement+json;version=0.2`. Schema: `src/lib/vcc/schemas.ts` (Zod, strict — unknown fields rejected). Shape:

```json
{
  "specVersion": "0.2",
  "type": "https://calcfleet.com/vcc/statement/calculation/v0.2",
  "subject": { "id": "urn:vcc:calculation:sha256:<hex64>", "kind": "deterministic-calculation" },
  "issuer": {
    "id": "https://calcfleet.com",
    "name": "CalcFleet",
    "keyDiscovery": "https://calcfleet.com/.well-known/vcc-issuer.json"
  },
  "formula": {
    "id": "urn:vcc:formula:personal-loan-calculator",
    "slug": "personal-loan-calculator",
    "version": "1.0.0",
    "digest": { "algorithm": "sha-256", "value": "<hex64>" },
    "registry": "https://calcfleet.com/vcc/registry/personal-loan-calculator/1.0.0",
    "visibility": "open"
  },
  "calculation": {
    "inputs":  { "principal": { "type": "money", "value": "20000.00", "scale": 2, "unit": "USD" }, "…": "…" },
    "outputs": { "monthlyPayment": { "type": "money", "value": "386.66", "scale": 2, "unit": "USD" }, "…": "…" },
    "numericProfile": "vcc-decimal-v1"
  },
  "datasets": [
    { "id": "urn:vcc:dataset:<name>", "name": "…", "version": "…",
      "digest": { "algorithm": "sha-256", "value": "<hex64>" }, "mediaType": "application/json" }
  ],
  "evidence": {
    "sources": [ { "label": "…", "url": "https://…" } ],
    "testsDigest": { "algorithm": "sha-256", "value": "<hex64>" }
  },
  "engine": {
    "name": "calcfleet-engine", "version": "0.1.0",
    "commit": "<git sha or \"unknown\">", "runtimeProfile": "node-deterministic-v1"
  },
  "attestation": {
    "type": "execution",
    "claims": ["inputs-received", "formula-executed", "numeric-profile-applied", "output-produced"]
  },
  "issuedAt": "2026-07-11T14:02:11Z",
  "context": { "surface": "api", "requestId": "<opaque, optional>" }
}
```

Digest values are lowercase hex (64 chars for sha-256); the algorithm is always explicit.

The `attestation` block (added v0.2, spec master §42–43; full rationale in `data-model.md`) states **what the issuer attests to** and is part of the signed statement. `type` is the receipt category — `execution` | `reproduction` | `review` (§43); CalcFleet emits only `execution`. `claims` are facts the issuer *performed* (`datasets-used` appears only when datasets were referenced), never claims about the world (inputs are true, formula is appropriate) — those are explicitly **not** attested.

## 3. Numeric profile `vcc-decimal-v1`

Every numeric leaf under `calculation.inputs`/`calculation.outputs` is a typed value:

```json
{ "type": "integer|decimal|percent|ratio|money|duration", "value": "<canonical decimal string>", "scale": <int ≥ 0>, "unit": "<optional>" }
```

- `value` grammar: `-?(0|[1-9][0-9]*)(\.[0-9]{scale})?` — the fraction part is present iff `scale > 0` and has exactly `scale` digits. No scientific notation. `-0` normalizes to `0`.
- Quantization from engine doubles: exact shortest-decimal (ES `Number::toString`) → BigInt half-even at declared scale. `NaN`/`±Infinity` MUST abort issuance.
- `percent` = percentage points (`"6.10"` means 6.10%); `ratio` = dimensionless fraction. The formula manifest's numeric dictionary declares which; readers MUST NOT guess.
- `money` carries `unit` = ISO-4217 code. `duration` carries `unit` ∈ `months|years`.
- String outputs (closed enums, e.g. `bindingConstraint`) appear as plain JSON strings; booleans as JSON booleans. Anything else is rejected at issuance.

## 4. Canonicalization & content addressing

- Canonical bytes = **RFC 8785 (JCS)** of the statement (UTF-8, sorted keys by UTF-16 code units, ES number/string serialization). Implementation: `src/lib/vcc/canonicalize.ts` (rejects non-finite numbers, undefined, non-plain objects).
- **Certificate id**: `subject.id = "urn:vcc:calculation:sha256:" + hex(sha256(JCS(statement with subject.id ABSENT)))`. The id therefore covers everything, including `issuedAt` — re-issuing the same calculation later yields a different certificate id by design (the id names *this issuance*). Verifiers MUST recompute and compare (`intact`).

## 5. Envelope (cryptographic layer)

DSSE v1. `payload` = standard base64 of the JCS statement bytes; `payloadType` as in §2; signature = Ed25519 over `PAE(payloadType, payload)`:

```
"DSSEv1" || SP || ASCII(len(payloadType)) || SP || payloadType || SP || ASCII(len(payload)) || SP || payload
```

```json
{ "payloadType": "application/vnd.vcc.statement+json;version=0.2",
  "payload": "<base64>",
  "signatures": [ { "keyid": "2026-07-a", "sig": "<base64 of 64-byte Ed25519 sig>" } ] }
```

An envelope MAY carry **1..4 signatures with unique `keyid`s**. Verification evaluates **every** signature: `checks.signature` is true iff there is ≥1 signature **and** every signature verifies over the DSSE PAE with a known Ed25519 key (`keyKnown`/`algorithmSupported` are likewise the AND across all signatures). This forbids a bogus signature riding along a valid one and forbids ignoring a valid second signature when the first is invalid. The **primary (first)** signature's key drives `issuerKeyStatus` and `keyValidAtIssuance`; additional signatures are countersignatures (e.g. an auditor's — see `trust-model.md`).

The **envelope is the canonical certificate**. API responses include a parsed `statement` for convenience; verifiers MUST derive the statement from `payload` (ADR-001).

## 6. Key discovery & trust

`GET /.well-known/vcc-issuer.json`:

```json
{ "issuer": "https://calcfleet.com",
  "keys": [ { "keyId": "2026-07-a", "algorithm": "ed25519",
              "publicKey": "<base64 raw 32-byte key>",
              "status": "active|retired|revoked|compromised",
              "validFrom": "…", "validUntil": null } ] }
```

Verification results separate these axes:

```json
{ "cryptographicValidity": true, "issuerIdentityBound": true,
  "keyValidAtIssuance": true, "issuerKeyStatus": "active",
  "certificateStatus": "valid", "trustedAtVerificationTime": true }
```

`cryptographicValidity` is the AND of the nine per-check booleans (`envelopeSchema`, `payloadType`, `payloadDecodes`, `statementSchema`, `canonicalization`, `statementId`, `keyKnown`, `algorithmSupported`, `signature`) and covers **signature + integrity only**. Two further axes are reported alongside it and are deliberately **separate** from it:

- **`issuerIdentityBound`** (bool): true iff `keyset.issuer === statement.issuer.id`. A signature validly made by a keyset that is **not** bound to the claimed issuer proves the bytes were signed by *some* key, but nothing attributable to the named issuer — so this cannot be folded into `cryptographicValidity`.
- **`keyValidAtIssuance`** (bool): true iff the signing key's window covered the statement's `issuedAt` (`validFrom <= issuedAt` **and** (`validUntil === null` **or** `issuedAt <= validUntil`)). A historical receipt signed inside the window keeps its `cryptographicValidity` even after the key later expires; a signature made **outside** the window is flagged here without disturbing the timeless math. Timestamps are fixed-width UTC, so a lexicographic compare is a chronological one.

The L1 result also carries **`signatureResults`**: one `{ keyid, keyKnown, algorithmSupported, valid }` per envelope signature, in envelope order (see §5 on multi-signature envelopes).

A cryptographically valid signature is **not** described as "trusted" unless it is also identity-bound, was made while the key was valid, and key status and certificate status allow it at verification time:

```
trustedAtVerificationTime =
  cryptographicValidity ∧ issuerIdentityBound ∧ keyValidAtIssuance
    ∧ issuerKeyStatus === "active" ∧ (certificateStatus ∈ {valid, unknown})
```

## 7. Verification levels

**L1 (authenticity + integrity, offline-capable)** — `verifyVccEnvelope(envelope, keys)`: envelope schema → payloadType → base64 decode → statement schema (strict) → JCS re-canonicalization must equal payload bytes → subject.id recomputation → Ed25519 over PAE for **every** signature with the keyset entry matching each `keyid` → algorithm check → `issuerIdentityBound` (keyset issuer vs `statement.issuer.id`) → `keyValidAtIssuance` (signing key window vs `issuedAt`) → key/certificate status when available. Requires no network when the caller supplies the keyset. Never throws on untrusted input: any internal error yields a well-formed all-false result.

**L2 (reproducibility, local allowlist)** — `reproduceVccCalculation(statement, registry)`: formula resolved **only** from the local registry; manifest digest compared before execution; datasets checked by digest; inputs decoded, schema-revalidated, re-executed, outputs re-normalized and diffed. Status: `match | mismatch | not-reproducible | formula-unavailable | dataset-unavailable | unsupported-profile | execution-failed`. `formula-unavailable` is not an L1 failure.

Summary object (`POST /api/v1/verify`): `{ authentic, intact, reproducible, trusted }` — four booleans, never one.

## 8. HTTP surface

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/tools/{slug}?certify=1` | existing calc + `certificate: { statement, envelope }` (additive; absent flag ⇒ byte-compatible legacy response) |
| `POST /api/v1/verify` | body `{ envelope }` or `{ certificate: { envelope } }` → `{ l1, l2, summary }` |
| `GET /api/v1/certificates/{id}` / `…/status` | stored envelope / status (404 + reason when store disabled) |
| `GET /vcc/registry/{slug}/{version}` | Formula Package Manifest (public, immutable) |
| `GET /.well-known/vcc-issuer.json` | keyset (cacheable, 1h) |
| `GET /verify/{id}` | public verification page (id = hex64; full URN shown on page) |

Certification requested but unavailable ⇒ HTTP 200 with `certificate: null` + `certificateReason` (`vcc-disabled | not-certifiable | signer-unavailable | privacy-rejected | …`); the calculation result is never blocked by certification problems.

## 9. Non-goals & extension points (v0.2)

No blockchain/tokens/ZK; no remote or third-party formula execution; no marketplace; no regulatory claims; no trust scores; no external timestamping (RFC 3161/transparency log = documented extension point); no graph pipeline certificates yet (`https://calcfleet.com/vcc/statement/pipeline/v0.2` reserved; per-node VCC + edges + rootDigest as in the master plan — lands after pilot stabilization). Dataset-reading formulas (ai-pricing) certify only after their Dataset Manifests ship in statements (infra present, formulas gated off).

## 10. Feature flags

`VCC_ENABLED` (master), `VCC_SIGNING_KEY` (base64 PKCS#8 DER Ed25519), `VCC_KEY_ID`, `VCC_ISSUER_URL` (default `https://calcfleet.com`), `VCC_STORE_ENABLED`, `VCC_L2_ENABLED`, `VCC_ALLOW_TEST_KEY` (preview only). Production build and tests never require the production key.
