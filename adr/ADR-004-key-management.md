# ADR-004 — Key management

Status: **Accepted** (2026-07-11)

## Context

The private key must exist only in the server runtime (Vercel env). The repo is public-reviewable; the client bundle must never contain key material. There is no KMS today.

## Decision

1. Interface:
   ```ts
   interface VccSigner {
     keyId(): Promise<string>;
     algorithm(): "ed25519";
     sign(payload: Uint8Array): Promise<Uint8Array>;
     publicKeyRaw(): Promise<Uint8Array>; // for self-check against the published keyset
   }
   ```
2. **EnvSigner** (v0.2 default): `VCC_SIGNING_KEY` = single-line standard base64 of a **PKCS#8 DER Ed25519 private key**; `VCC_KEY_ID` = human-friendly id (`2026-07-a`). Parsed once at first use; startup validation = decode, assert Ed25519, sign+verify a self-test message. Malformed/absent key in production ⇒ issuance disabled with explicit reason (calc responses unaffected).
3. **KmsSigner**: interface-compatible stub (`src/lib/vcc/keys.ts`) that throws `VccError("kms-not-configured")` — the seam is in place; wiring a real KMS/HSM is P1 pre-enterprise.
4. **Key discovery**: `GET /.well-known/vcc-issuer.json` serves the committed **public** keyset (`src/lib/vcc/issuer-keys.ts`; public keys are safe in-repo). Statuses: `active` | `retired` | `revoked` | `compromised`, with `validFrom`/`validUntil`. Cache: `s-maxage=3600, stale-while-revalidate=86400` — short enough that a compromise flip propagates within an hour.
5. **Sign-time self-check**: the signer's derived public key must equal the published key for `VCC_KEY_ID` **and** that key must be `active`; otherwise refuse to sign. Prevents "signing with a key the world can't validate" and signing with retired keys.
6. **Environments**: production requires the real key (else disabled-with-reason); `VERCEL_ENV=preview` never signs unless `VCC_ALLOW_TEST_KEY=1` with the documented test key (test keys are published in the keyset with status ≠ active so verifiers can identify them as untrusted). Tests use a deterministic committed test keypair, clearly labeled.
7. Verification result **separates trust axes** (never a single boolean): `cryptographicValidity`, `issuerKeyStatus`, `certificateStatus`, `trustedAtVerificationTime` (= valid ∧ key active ∧ cert valid).
8. No logging of private keys, full signatures, or payloads; log only key **id**, sizes, and failure reasons.

## Alternatives considered

- Raw 32-byte seed in env: fewer parsing failure modes but ambiguous encodings in the wild; PKCS#8 DER is what `node:crypto` emits/consumes natively and self-describes the algorithm.
- Fetching the keyset from KV/DB: mutable trust root, worse cacheability, new failure mode. Git-committed public keyset gives reviewable rotation history.
- JWKS format: fine, but DSSE ecosystems use simple keyid+raw key lists; we publish base64 raw public key + explicit `algorithm` field.

## Consequences

- Rotation = add new key to keyset (active), deploy, set env to new key, mark old `retired` (see `docs/vcc/key-rotation.md`). Old certificates keep verifying (crypto validity) while `trustedAtVerificationTime` reflects current status.

## Risks

- Vercel env is a single point of compromise until KMS lands (threat model T2); mitigations: status `compromised` propagation ≤ 1h, cert status `issuer-key-compromised`, small blast radius (only pilot formulas certifiable).
