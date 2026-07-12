# VCC Assurance Model — assurance vector & verification states (§31.7, §30)

Status: **Draft v0.3-track** · 2026-07-12 · Formalizes the assurance surface already shipped in VCC v0.2 (`docs/vcc/spec-v0.2.md` §6–§7, `src/lib/vcc/verify-l1.ts`, `verify-l2.ts`). No code or format change; this document defines the 9-axis assurance vector of §31.7 and maps it onto the 6/9 axes the reference implementation computes today, restates the 9 verification states of §30, and states precisely what a signature proves and does not prove (§3.21/§3.22).

Source of truth for status claims: the internal VCC standard-readiness audit (§31.7, §30, §7).

---

## 1. The problem the assurance model solves

A single "Verified ✓" is a lie of omission. A receipt can have an impeccable signature and still be irreproducible; it can reproduce perfectly and still be signed by a compromised key; the formula can be resolvable and still be economically wrong. The assurance model exists so that **every distinct thing a receipt could assure is reported as its own axis**, and so that interfaces "MUST NOT collapse authenticity, trust and reproducibility into a single boolean" (`spec-v0.2.md` §1, `VccVerifyResult.tsx:3-7`). This is VCC's central design invariant, and the reference implementation honors it.

The assurance vector is the machine-readable form of that invariant; the §30 verification states are its human-readable form.

## 2. The assurance vector — 9 axes (§31.7) mapped to the 6/9 shipped

Each axis answers one independently-falsifiable question. Status: **FATTO** (computed and reported today), **PARZIALE** (partially computed), **MANCANTE** (no representation).

| # | Axis (§31.7) | Question it answers | Status | Evidence / shipped field |
|---|---|---|---|---|
| 1 | **Signature** | Does the Ed25519 signature verify over the canonical payload? | **FATTO** | `checks.signature` + `cryptographicValidity`; summary `authentic` (`verify-l1.ts:114-134`) |
| 2 | **Issuer identity** | Is the signing key a known key of the declared issuer? | **FATTO** (single issuer) | `checks.keyKnown` vs published keyset; `issuer.id/keyDiscovery` |
| 3 | **Key status** | Is that key active / retired / revoked / compromised now? | **FATTO** | `issuerKeyStatus` ∈ {active,retired,revoked,compromised,unknown} (`verify-l1.ts:44,120`) |
| 4 | **Formula resolvability** | Can the exact formula package be resolved and does its digest match? | **FATTO** | L2 `formulaAvailable`+`formulaDigestMatch`; `formula-unavailable` never conflated with an L1 failure (ADR-005 §5) |
| 5 | **Dataset resolvability** | Can each declared dataset snapshot be resolved by digest? | **FATTO** | L2 `datasetsAvailable`+`datasetsDigestMatch`; `dataset-unavailable` state (ADR-005 §2) |
| 6 | **Reproduction** | Did re-execution reproduce every certified output? | **FATTO** | L2 7-state status + `differences[]` field-by-field (`verify-l2.ts`) |
| 7 | **Runtime attestation** | Is there proof of *how/where* the runtime ran (TEE / provenance)? | **MANCANTE** | Only the self-declared `runtimeProfile` string; no attestation, not even an extension point |
| 8 | **Auditor review** | Did an independent auditor review and countersign? | **MANCANTE** (mechanism present) | No auditor role and no axis yet, but the verifier now evaluates every signature on a multi-signature envelope, so the countersignature slot the axis needs already verifies (see `trust-model.md` §2.9; ADR-001 §4) |
| 9 | **Policy compliance** | Was a business/regulatory policy evaluated? | **MANCANTE** | No "policy evaluated / not evaluated" state anywhere (this is the §30 gap below) |

**6 of 9 axes ship.** The three missing axes are exactly the three that require *other parties* (a runtime attester, an auditor, a policy authority) — i.e. they are blocked on the role de-fusion in `trust-model.md`, not on cryptography.

### 2.1 The vector is not yet declaratively extensible

Today the axes are fields on `VccL1VerificationResult`/`VccL2VerificationResult`/`VccVerifySummary` (`types.ts:199-257`) and rows in the verify UI. Adding axis 7/8/9 means changing those types and the UI — **not** appending an element to a versioned vector. A standard-track improvement is to define the assurance vector as an explicit versioned list of `{ axis, status, evidence }` so new axes are additive. Recorded here as the structural gap (audit §31.7 "Nota architetturale"); no v0.2 code change.

## 3. What a signature proves — and what it does NOT (§3.21 / §3.22)

This section is normative and MUST be reflected verbatim in intent on any surface that renders a receipt.

### 3.1 A valid VCC signature **proves**

1. **Origin**: the statement was signed by the private key whose public half is published for `keyid` in the issuer's keyset (axis 1 + 2) — *and* that keyset is bound to the claimed issuer (`issuerIdentityBound`: `keyset.issuer === statement.issuer.id`). A valid signature by a keyset **not** bound to the named issuer is reported separately and proves origin for no one.
2. **Integrity**: not one byte of the statement changed after signing — the payload is the RFC 8785 (JCS) canonical form and `subject.id` is its SHA-256 (axes: `intact`; `verify-l1.ts:92-112`).
3. **Binding**: the receipt names *which* formula version, *which* validated inputs, *which* outputs, *which* dataset versions, and *which* numeric profile were involved (statement fields, all covered by the signature).
4. **Reproducibility — only when axis 6 says so and only "by whoever re-ran it"**: that re-executing the *pinned formula version* on the *same inputs* yields the *same outputs under the declared numeric profile* (`spec-v0.2.md` §7; §7 definition of "Reproducible").

### 3.2 A valid VCC signature does **NOT** prove (§3.21, §3.22)

1. **Not truth of inputs** — a signed salary of `1000000.00` is not evidence the salary is real (T6/T19 accepted; `spec-v0.2.md` §1).
2. **Not correctness of the formula** — reproducibility (§3.22) means "same code, same result", never "the formula is the right formula" or "the math is economically/legally appropriate". `verifier-guide.md` §L2 states this explicitly.
3. **Not fitness for purpose / not advice / not a decision** — a receipt is not consulting, not a regulatory certification, not accreditation (§3.24; limits blockquote on every surface, `VccVerifyResult.tsx:293-299`).
4. **Not an independent audit** — "a valid signature ≠ an independent audit" (`spec-v0.2.md` §1); axis 8 is precisely what is missing.
5. **Not "trusted" by itself** — cryptographic validity is separated from trust: a signature over a compromised key still verifies cryptographically but is not `trustedAtVerificationTime` (ADR-004 §7).

### 3.3 Naming discipline

Because of §3.2, the standard-track UI term is **calculation receipt** (§29), and no surface may present a bare, unqualified "Verified" (§3.9). The receipt proves *checkable provenance and integrity*, and *conditionally* reproducibility — never proof-of-correctness. The word "proof" without that qualifier is a §3.22 risk (audit §5.7).

## 4. The nine /verify states (§30, §7)

The master requires nine separately-rendered states. Below: each state, its shipped mapping, and the divergence to resolve (all divergences are presentation/spec-level; the underlying checks exist unless marked MANCANTE).

| # | State (§30) / §7 alias | Shipped? | Backing check | Note / divergence |
|---|---|---|---|---|
| 1 | Document well-formed (*Statement well-formed*) | Computed, not surfaced as a distinct state | `checks.envelopeSchema/payloadDecodes/statementSchema` | Folded into "Intact / Altered or malformed" — should be its own state |
| 2 | Signature valid | **FATTO** | `checks.signature` | Row "Signature → valid Ed25519 signature" |
| 3 | Issuer identity resolved (*Issuer identified*) | PARZIALE | `checks.keyKnown` | Shown as key-id known/unknown, not framed resolved/unresolved |
| 4 | Signing key active **at signing time** (*Key active*) | **FATTO** | `keyValidAtIssuance` + `issuerKeyStatus` | `issuedAt` is now compared to the signing key's `validFrom/validUntil` (`keyValidAtIssuance`), reported separately from current `issuerKeyStatus`. A receipt signed inside the window keeps its signature validity even after the key later expires |
| 5 | Statement intact | **FATTO** | canonicalization + `statementId` | Badge "Intact" + integrity rows |
| 6 | Formula package resolved (*Formula resolved*) | PARZIALE | L2 `formulaAvailable`/digest | No L1-side "manifest fetched & digest matches" shown when L2 is off |
| 7 | Dataset snapshot resolved (*Dataset resolved*) | PARZIALE | L2 dataset checks | Same as #6; digests shown, resolution state implicit |
| 8 | Independent reproduction passed (*Result reproduced*) | PARZIALE | L2 `status=match` | Re-execution runs on the **issuer's own server** → it is re-execution, not *independent* (audit §3, §31.9). Honest wording required |
| 9 | Business policy not evaluated (*Policy evaluated*) | **MANCANTE** | — | No policy state in UI, API, types or spec. This is assurance axis 9 |

**Compliant strength to preserve**: there is *no* single "Verified" anywhere (deliberate, `verify/page.tsx:48-49`). The §30 ordering (Issuer → Calculation → Formula → Inputs → Output → Signature → Key status → Reproduction → Datasets → Policy → Limitations) is not yet the render order (signature currently precedes content; inputs/outputs sit in collapsed `<details>`); that is a UI reorder, not a format change.

## 5. One divergence worth a spec decision (not a code hotfix)

1. **`authentic` currently subsumes `intact`.** `cryptographicValidity = every(9 checks)`, which includes schema + canonicalization + id (`verify-l1.ts:136`). So `authentic` fails on pure *integrity/format* defects too — the axes are separated *in presentation* but not *orthogonal in computation* (audit §4.2). §7 wants "Signature valid" and "Statement intact" independent. Resolution: report `signatureVerifies` (axis 1) separately from the integrity checks, keeping `authentic` as their conjunction for the summary.

**Resolved since the first draft**: *"key active at signing time" is now computed* — the verifier compares `issuedAt` to the signing key's `validFrom/validUntil` window and reports `keyValidAtIssuance` as a top-level axis, making state #4 truthful (a verifier addition, not a format change). *Issuer-identity binding is now an explicit axis* — `issuerIdentityBound` (keyset issuer === `statement.issuer.id`) is computed separately from `cryptographicValidity`, so a valid signature by a keyset not bound to the claimed issuer no longer reads as trust in that issuer.

## 6. What this document is NOT

It does not define the trust *policy* (that is `trust-model.md` §2.7-2.8), the key *lifecycle* (`key-rotation.md`, ADR-004, §31.5), or privacy assurance (`privacy-profiles.md`, §31.6). It defines only: the nine assurance axes, their shipped mapping, the nine verify states, and the exact proof boundary of a signature.
