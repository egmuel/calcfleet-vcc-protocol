# VCC Issuer Guide

**Who this is for.** The operator of the CalcFleet deployment (today: one person, Vercel + GitHub) who turns certificate issuance on, holds the signing key, and answers for what gets signed. Verifier-side behavior is in the [verifier guide](./verifier-guide.md); key ceremonies are in the [key rotation runbook](./key-rotation.md); design rationale in [ADR-004](../adr/ADR-004-key-management.md).

## Environment flags

All flags are read from `process.env` at call time (`src/lib/vcc/constants.ts`); nothing is cached, and neither the build nor the test suite ever requires the production key.

| Variable | Type | Meaning |
|---|---|---|
| `VCC_ENABLED` | `1`/`true` | Master switch. Off ⇒ `certify=1` returns `certificate: null` with reason `vcc-disabled`. Calculations are never affected. |
| `VCC_SIGNING_KEY` | base64 string | The Ed25519 **private** key as single-line standard base64 of PKCS#8 DER. Server-only. Never in the repo, never in a preview environment. |
| `VCC_KEY_ID` | string | Human-friendly id of the signing key (e.g. `2026-07-a`). Must match an `active` entry in the published keyset, or signing refuses. |
| `VCC_ISSUER_URL` | URL | Issuer origin used in statements and discovery URLs. Defaults to `https://calcfleet.com`. |
| `VCC_STORE_ENABLED` | `1`/`true` | Persist issued envelopes to the KV certificate store. Off ⇒ stateless issuance (see below). |
| `VCC_L2_ENABLED` | `1`/`true` | Allow the verify endpoint/page to attempt L2 reproduction. |
| `VCC_ALLOW_TEST_KEY` | `1`/`true` | **Preview-only.** Lets `VERCEL_ENV=preview` sign with the published, clearly-labeled test key (status ≠ active in the keyset, so verifiers can tell). Never set in production. |
| `VCC_DEV_TRUST_ENV_KEY` | `1`/`true` | **Local-dev-only.** Relaxes the published-keyset self-check so a locally generated key can sign on `localhost`. Never set on Vercel. |

## Go-live checklist

1. **Generate the keypair offline**, on a trusted machine — not in a Vercel shell, not in CI:

   ```bash
   node -e '
   const { generateKeyPairSync } = require("node:crypto");
   const { privateKey, publicKey } = generateKeyPairSync("ed25519");
   const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
   const spki  = publicKey.export({ format: "der", type: "spki" });
   console.log("VCC_SIGNING_KEY=" + pkcs8.toString("base64"));
   console.log("publicKey (raw 32B, for issuer-keys.ts): " + spki.subarray(spki.length - 32).toString("base64"));
   '
   ```

2. **Publish the public half**: add an entry to `PRODUCTION_KEYS` in `src/lib/vcc/issuer-keys.ts` — `keyId`, `algorithm: "ed25519"`, the raw-32-byte base64 public key, `status: "active"`, `validFrom`. Commit and deploy. Public keys are safe in the repo; the git history is the rotation audit trail.
3. **Set env on Vercel — production scope only, never preview**: `VCC_SIGNING_KEY`, `VCC_KEY_ID`, `VCC_ENABLED=1` (plus `VCC_STORE_ENABLED` / `VCC_L2_ENABLED` as desired).
4. **Verify discovery**: `curl https://calcfleet.com/.well-known/vcc-issuer.json` must list your `keyId` as `active`.
5. **Smoke test**: issue a certificate with `?certify=1`, then verify it offline per the [quickstart](./quickstart.md#4-verify-offline-the-point-of-the-whole-exercise). The issuance pipeline already self-verifies (L1) before returning anything, so a returned certificate is a verified certificate.

## Fail-safe behaviors

The invariant everywhere: **certification problems never block or alter calculation results.**

- **Missing/malformed key in production** ⇒ issuance is disabled with an explicit reason; `certify=1` responses carry `certificate: null` + `certificateReason: "signer-unavailable"`. The calc result is returned normally. The startup validation decodes the key, asserts Ed25519, and runs a sign+verify self-test.
- **Sign-time self-check** ⇒ the signer's derived public key must equal the published keyset entry for `VCC_KEY_ID` *and* that entry must be `active`; otherwise it refuses to sign. This prevents signing with a key the world cannot validate, and signing with retired keys.
- **Preview deployments never sign** unless `VCC_ALLOW_TEST_KEY=1`, and then only with the published test key that verifiers can identify as untrusted.
- **No flag** ⇒ the `/api/v1/tools/{slug}` response is byte-compatible with the legacy contract (the RapidAPI listing depends on this).

## What gets refused

Issuance is fail-closed. The API maps internal `VccError` codes (`src/lib/vcc/errors.ts`) to the public `certificateReason` string:

| Refusal | Internal code(s) | `certificateReason` |
|---|---|---|
| VCC disabled by flag | — | `vcc-disabled` |
| Formula has no manifest / not in the certifiable registry | `formula-not-certifiable`, `manifest-missing` | `not-certifiable` |
| Input fails the tool's Zod schema | `schema-invalid` | (request is a normal 400 — no calculation, no certificate) |
| Statement fails the strict statement schema | `schema-invalid` | `not-certifiable` |
| Privacy guard violation (forbidden key, PII-shaped string, free text) | `privacy-violation` | `privacy-rejected` |
| Manifest digest drift vs. committed registry | `manifest-drift`, `digest-mismatch` | `not-certifiable` |
| Numeric leaf without a dictionary rule, non-finite number, precision loss | `numeric-rule-missing`, `non-finite-number`, `numeric-precision-loss` | `not-certifiable` |
| Signer missing, key invalid, key not published, key not active | `signer-unavailable`, `key-invalid`, `key-not-published`, `key-not-active` | `signer-unavailable` |
| Dataset referenced but missing/undigested | `dataset-missing` | `not-certifiable` |

The reason list is open-ended by spec (`vcc-disabled | not-certifiable | signer-unavailable | privacy-rejected | …`); treat unknown values as "no certificate, calc still valid".

## Store on/off semantics

Storage ([ADR-006](../adr/ADR-006-certificate-storage.md)) is optional and orthogonal to issuance:

| | `VCC_STORE_ENABLED=1` | store off |
|---|---|---|
| Issuance | works; envelope persisted under `vcc:cert:<idHex>` after full L1 self-verification, 64 KB cap | works, stateless |
| `GET /api/v1/certificates/{id}` | serves the stored envelope | 404 with reason `store-disabled` |
| `…/status` | serves status (`valid` default; separate key `vcc:status:<idHex>`) | 404 with reason |
| `/verify/{id}` page | loads the certificate by id | falls back to paste-a-certificate verification |

The store is append-only at the application level: `put` on an existing id with identical bytes is an idempotent `already-exists`; different bytes is a hard error (`store-overwrite-refused`) and is logged as a corruption/collision attempt. Status changes never delete the envelope — revocation preserves history. Backend selection follows the existing KV pattern (`KV_REST_API_URL`/`KV_REST_API_TOKEN`, in-memory fallback in dev — volatile, surfaced as such).

## Observability

Log **codes, never content** ([ADR-004 §8](../adr/ADR-004-key-management.md)):

- Do log: `VccErrorCode` values, `certificateReason` counts, key **id** (never material), payload sizes, store outcomes (`stored` / `already-exists` / refused), L2 statuses.
- Never log: private keys, full signatures, envelope payloads, statement contents, or anything correlating a certificate to a requester beyond the opaque `requestId` ([privacy profiles](./privacy-profiles.md)).
- Useful steady-state signals: rate of `signer-unavailable` (should be zero in healthy prod), rate of `privacy-rejected` (spikes may indicate probing — see [threat model](./threat-model.md) T13), certified share of API calls.

If you rotate or lose a key, stop here and follow the [key rotation runbook](./key-rotation.md) — including its compromise procedure and the 1-hour keyset cache window.
