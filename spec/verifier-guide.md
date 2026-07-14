# VCC Verifier Guide

**Who this is for.** A third party — auditor, integrator, counterparty, or tool author in any language — who receives a CalcFleet certificate and wants to check it without trusting CalcFleet's servers, or CalcFleet at all beyond its published key. Everything here is implementable from the [spec](./spec-v0.2.md) with standard primitives: JSON, RFC 8785, SHA-256, Ed25519.

## Trust model: what L1 proves — and what it does not

A passing L1 verification proves: **who issued** the certificate (signature + key discovery), **which formula+version** was claimed (manifest digest), **which validated inputs** and **which outputs** the statement binds, **which versioned datasets** were referenced (digests), **which numeric rules** applied (`vcc-decimal-v1`), and **that nothing changed after signing** (DSSE over canonical bytes). With L2 on top: that re-executing the same formula version reproduces the outputs.

It does **not** prove: that the inputs are true; that the formula is legally or economically appropriate for any purpose; that the result is advice or a decision; regulatory compliance of any kind; or that a valid signature equals an independent audit. Your UI MUST NOT collapse authenticity, trust and reproducibility into a single "verified" boolean ([spec §1](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not)).

## Offline L1 recipe

Precondition: you fetched `https://calcfleet.com/.well-known/vcc-issuer.json` **earlier, over TLS, and pinned it** (committed it to your repo, stored it in your trust store — anything but re-fetching at verification time). Verification then requires **no call to CalcFleet whatsoever**.

1. **Parse the envelope** strictly: exactly `{ payloadType, payload, signatures[] }`, unknown fields rejected. `payloadType` must be the literal `application/vnd.vcc.statement+json;version=0.2` — anything else is a different format, not an older VCC.
2. **Decode `payload`** from standard base64 (padded; reject non-canonical base64). The decoded bytes are the UTF-8 statement JSON — the DSSE body.
3. **Parse and validate the statement** against the strict schema (spec §2): unknown fields anywhere are a failure, not a warning.
4. **Re-canonicalize** the parsed statement with RFC 8785 (JCS) and compare byte-for-byte with the decoded payload. Mismatch ⇒ the payload was not canonical ⇒ reject. Never trust a sibling `statement` object shipped next to the envelope; derive everything from `payload` ([ADR-001](../adr/ADR-001-vcc-envelope.md)).
5. **Recompute `subject.id`**: remove `subject.id` from the statement, JCS-canonicalize the remainder, SHA-256 it, and check `subject.id === "urn:vcc:calculation:sha256:" + hex`. This is the `intact` check; the id names *this issuance* (it covers `issuedAt` by design).
6. **Build the PAE** (pre-authentication encoding) over the payload type and the decoded body bytes:

   ```
   PAE(type, body) = "DSSEv1" || SP || ASCII(len(type)) || SP || type
                            || SP || ASCII(len(body)) || SP || body
   ```

   where `SP` is a single space (0x20), `len()` is the byte count in ASCII decimal, and `body` is the decoded payload from step 2.
7. **Verify Ed25519** for **every** entry in `signatures[]` — not just the one you care about. An envelope carries 1..4 signatures with unique `keyid`s; the signature check passes iff there is ≥1 signature **and** every one verifies with a known key. For each: look up `keyid` in your pinned keyset, require `algorithm === "ed25519"` (strict literal — no negotiation, no fallback), base64-decode `sig` to raw 64 bytes, verify over the PAE bytes. A bogus signature riding alongside a valid one MUST fail the envelope; a valid countersignature MUST NOT be ignored because the primary failed. The **primary (first)** signature's key is the issuer's — it drives key status and the issuance-time window check.
8. **Bind the identity and the issuance window.** Check `issuerIdentityBound` — your keyset's `issuer` must equal the statement's `issuer.id`; a valid signature by a keyset bound to a *different* issuer proves nothing about the named one. Check `keyValidAtIssuance` — the primary key's `validFrom/validUntil` must cover `issuedAt` (`validFrom <= issuedAt` and (`validUntil === null` or `issuedAt <= validUntil`)); timestamps are fixed-width UTC so a string compare is a chronological one. A receipt signed inside the window stays authentic even after the key later expires.
9. **Apply key status** from your pinned keyset, and certificate status if you have it (see below). Only now decide `trustedAtVerificationTime`.

Steps 1–7 give `cryptographicValidity`. Steps 8–9 are deliberately separate:

```
trustedAtVerificationTime =
  cryptographicValidity ∧ issuerIdentityBound ∧ keyValidAtIssuance
    ∧ issuerKeyStatus === "active" ∧ (certificateStatus ∈ {valid, unknown})
```

## Key-status semantics

The keyset entry for a `keyId` carries `status`:

| Status | Meaning for you |
|---|---|
| `active` | The issuer currently signs with it. Trustable. |
| `retired` | Rotated out in good standing. Old signatures remain honest history; do not expect new ones. |
| `revoked` | The issuer disowns future reliance on this key. Treat signatures as unverifiable claims. |
| `compromised` | The key may have signed things the issuer never intended. Signatures prove nothing about the issuer's intent, only about possession of the key. |

This is why **"cryptographically valid" ≠ "trusted now"**: the math is timeless, but keys live in the world. A signature made with a now-`compromised` key still verifies mathematically forever — the *meaning* of that verification changed. Report both facts separately; never let one overwrite the other.

Refresh your pinned keyset periodically (the endpoint caches for 1 hour server-side) — a stale pin delays your awareness of compromise flips, which is your risk to manage.

## Certificate-status semantics

If you can reach the issuer's store (`GET /api/v1/certificates/{id}/status`) or otherwise learn a status:

| Status | Meaning |
|---|---|
| `valid` | Default; nothing adverse recorded. |
| `superseded` | A newer certificate exists for the same purpose; this one is history, not error. |
| `withdrawn` | The issuer no longer stands behind this issuance. |
| `disputed` | Correctness is contested; treat with caution pending resolution. |
| `issuer-key-compromised` | Issued in a window during which the signing key is considered compromised. |

Revocation **never deletes history**: the envelope stays retrievable next to its status. A status is issuer metadata about a certificate, not a modification of it — the signed bytes are immutable. When you cannot learn a status (offline, store disabled), it is `unknown`, which is honest, not fatal.

## L2: what "match" does and does not prove

L2 (`reproduce` in the CLI, or the online verify with L2 enabled) resolves the formula **only from the verifier's local, statically-imported registry** — never from anything the certificate names ([ADR-005](../adr/ADR-005-l2-reproduction.md)). It checks the statement's formula digest against the local manifest **before** executing, checks dataset digests, decodes the typed inputs, re-validates them against the input schema, re-runs the pure calc, re-normalizes outputs through `vcc-decimal-v1`, and diffs.

`match` proves: *this exact published formula version, run on the certified inputs, yields the certified outputs at the declared scales.* It does not prove the formula is correct, appropriate, or that the issuer ran that code at issuance time — it proves the claim is *reproducible by you*. `formula-unavailable` means your registry lacks that slug+version; it is a reproducibility outcome, never an authenticity failure.

**Reading `differences[]`**: each entry is `{ path, expected, actual }` — `path` is the dotted output path (arrays as `[]`-indexed), `expected` is the certified canonical value, `actual` what your re-run produced. Because comparison happens on canonical typed values at declared scales, two doubles that quantize identically compare equal — the declared scale *is* the certified resolution ([ADR-002](../adr/ADR-002-numeric-semantics.md)).

## The four booleans

Surface all four from `summary`, separately: `authentic` (signature from the issuer's key), `intact` (bytes unchanged; id recomputes), `reproducible` (L2 matched; `null` if not attempted), `trusted` (authentic ∧ issuer-identity-bound ∧ key-valid-at-issuance ∧ key active ∧ certificate status permits, at *your* verification time). The underlying L1 result exposes the per-axis booleans (`issuerIdentityBound`, `keyValidAtIssuance`) and a `signatureResults[]` array of `{ keyid, keyKnown, algorithmSupported, valid }` in envelope order, so a multi-signature envelope can be surfaced signature-by-signature. One-word "verified" badges are the forbidden UI pattern.

## Security notes — verifying hostile input

A verifier processes bytes it did not produce. The reference implementation hardens accordingly, and a conforming verifier in any language SHOULD do the same:

- **Never throw on untrusted input.** Any internal error while verifying is caught and turned into a well-formed **all-false** result — a malformed or adversarial envelope produces a clean "everything false", never an exception or a crash the caller must handle.
- **Bound the input before validating it.** The statement is walked iteratively (no recursion) to cap **nesting depth at 64** and **node count at 20000** *before* schema validation, so a deeply-nested or enormous JSON object cannot exhaust the stack or CPU.
- **Reject non-canonicalizable strings.** UTF-16 lone surrogates cannot be canonicalized deterministically and are rejected rather than silently coerced.
- **Read the keyset defensively.** A malformed or hostile keyset must not be able to throw the verifier off its all-false path.
- **URLs must be safe https, and you MUST still block at connect time.** Every URL in a statement (`issuer.id`, `keyDiscovery`, `formula.registry`, `sources.url`) and the keyset's `issuer` must be **https only**, a **registrable DNS host**, with **no IP literals, no `localhost`, no userinfo**. This is string-level validation only — it **cannot** stop DNS rebinding. If you *fetch* any of these URLs (e.g. to refresh a keyset or resolve a registry), your fetcher MUST independently block **private / loopback / link-local ranges at connect time**. Do not treat URL-shape validation as a substitute for network egress control.
- **Timestamps are real calendar dates.** `issuedAt` and key windows are validated as actual UTC dates (not merely pattern-matched), and fixed-width so lexicographic order equals chronological order.
- **Typed-value and cross-field invariants are enforced.** Unit rules bind to type (`money` = ISO-4217, `duration` = a time unit, `percent` = `"%"`-style percentage points, `ratio` = no unit); cross-field invariants require `formula.id === urn:vcc:formula:<slug>`, the `datasets-used` claim ↔ non-empty `datasets[]` **biconditional**, the required claims for the attestation type, and **non-empty inputs and outputs**. A statement that violates any of these fails validation, not just verification. The attestation rules apply only when the block is present: `attestation` is **additive** (§42) — verifiers MUST accept statements that omit it (issued before its introduction), and issuers SHOULD always include it.

## Interop notes

- **Canonicalization**: RFC 8785 (JSON Canonicalization Scheme). Keys sorted by UTF-16 code units, ES number/string serialization, UTF-8 output. Non-finite numbers cannot occur in a valid statement.
- **PAE**: as defined inline above — DSSE v1, in-toto convention. The signed material is the PAE bytes, not the bare payload.
- **base64**: `payload`, `sig`, and keyset `publicKey` all use **standard** base64 with padding (`+`, `/`, `=`) — not base64url. Public keys are raw 32-byte Ed25519; signatures raw 64-byte.
- **Digests**: always `{ "algorithm": "sha-256", "value": "<64 lowercase hex chars>" }` — the algorithm is explicit everywhere, and `sha-256` is the only v0.2 value.
- **Numbers**: every numeric leaf in `calculation` is a typed value object with a canonical decimal string (`-?(0|[1-9][0-9]*)(\.[0-9]{scale})?`, no exponent, no `-0`). Parse with a decimal type or as strings; never round-trip through binary floats before comparing.
- **Timestamps**: `issuedAt` is seconds-precision UTC, single representation (`YYYY-MM-DDTHH:MM:SSZ`).

For issuing-side behavior see the [issuer guide](./issuer-guide.md); for rotation timing that affects your pins see [key rotation](./key-rotation.md); for the attack catalogue see the [threat model](./threat-model.md).
