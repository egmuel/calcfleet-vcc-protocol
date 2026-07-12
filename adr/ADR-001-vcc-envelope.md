# ADR-001 — VCC envelope: DSSE + Ed25519, envelope is the single canonical representation

Status: **Accepted** (2026-07-11)

## Context

VCC v0.2 needs a signature envelope that is interoperable, offline-verifiable, and does not reinvent attestation. The repo has zero crypto dependencies today; Node ≥ 20 ships Ed25519 in `node:crypto`.

## Decision

1. **DSSE** (Dead Simple Signing Envelope, in-toto spec) is the envelope. Signed material is `PAE(payloadType, payload)`:
   `"DSSEv1" SP len(type) SP type SP len(body) SP body`, lengths = ASCII decimal byte counts.
2. `payloadType = "application/vnd.vcc.statement+json;version=0.2"`.
3. `payload` = **standard base64** (padded) of the **RFC 8785 (JCS) canonical bytes** of the statement. Emitting canonical bytes inside the payload makes byte-equality checks and content addressing trivial; verifiers MUST still re-canonicalize and compare (defense against non-canonical payloads).
4. Algorithm: **Ed25519** only in v0.2 (`algorithm: "ed25519"` in key discovery). `sig` = standard base64 of the raw 64-byte signature. Multiple signatures allowed; v0.2 issues one.
5. **Single canonical representation**: the envelope is the certificate. The API response also returns a parsed `statement` object as a *convenience view*; stores persist **only the envelope**; verifiers MUST derive the statement from `envelope.payload` and, if a sibling `statement` is present, MAY check it matches but MUST NOT trust it.
6. Signing/verification via `node:crypto` (`sign(null, data, key)` / `verify`). No new dependencies.

## Alternatives considered

- **JWS/JWT**: header mutability, alg-confusion history, base64url-in-three-parts; DSSE's PAE is simpler and is the supply-chain-attestation standard (in-toto/sigstore).
- **W3C Verifiable Credentials + Data Integrity**: heavy JSON-LD processing, canonicalization complexity (RDF), overkill for a calculation receipt. Revisit if ecosystem demand appears.
- **Raw signature over JCS bytes (no envelope)**: loses payloadType binding (type-confusion risk) and multi-sig support.
- **secp256k1/ECDSA**: nondeterministic signatures unless RFC 6979; Ed25519 is deterministic and in Node stdlib.

## Consequences

- Offline L1 verification requires only: envelope JSON, issuer public key, a JCS implementation, SHA-256, Ed25519 — all standard.
- Duplicated-statement ambiguity is eliminated by rule 5.
- Browser verification (future SDK) can use WebCrypto Ed25519 (Chrome 137+/Firefox/Safari, Node ≥ 20) — no bundled crypto.

## Risks

- DSSE payload is base64 (not human-readable in transit) — mitigated by the convenience view and `vcc inspect`.
- Single-alg lock-in: `algorithm` is explicit in keys and envelope verification rejects anything ≠ ed25519, so adding an alg later is a spec bump, not a breaking ambiguity.
