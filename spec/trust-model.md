# VCC Trust Model — separated roles (§31.4)

Status: **Draft v0.3-track** · 2026-07-12 · Formalizes and extends what VCC v0.2 already builds (`docs/vcc/spec-v0.2.md` §6, `docs/adr/ADR-004-key-management.md`). This document does **not** change code or the shipped format; it names the roles the master prompt §31.4 requires, maps each to what exists today, and marks what is implicit or missing.

Source of truth for status claims: the internal VCC standard-readiness audit (§31.4).

---

## 1. Why separate roles

A VCC is only as trustworthy as the answer to "who is being trusted for *what*". Today CalcFleet plays **every** role at once. That is fine for a first reference implementation, but a standard MUST let a verifier reason about each responsibility independently: the party that *wrote the formula* is not necessarily the party that *ran it*, nor the party that *signed the receipt*, nor the party that *vouches for the issuer*. Collapsing them hides exactly the substitution attacks a receipt is supposed to make visible.

This document names the eight roles of §31.4, defines each, and marks its status:

- **FATTO** — the role exists as a distinct, checkable concept in the shipped code/spec.
- **IMPLICITO** — the responsibility exists but is fused into CalcFleet with no separate identity, digest, or attestation a verifier can name.
- **MANCANTE** — no representation at all; adding it is a v0.3+ design task.

The trust axes that VCC v0.2 *does* separate — `cryptographicValidity`, `issuerKeyStatus`, `certificateStatus`, `trustedAtVerificationTime` (`spec-v0.2.md` §6, `verify-l1.ts:136-153`, ADR-004 §7) — are the seed of this model, not a replacement for it.

## 2. The eight roles

### 2.1 Formula publisher — **IMPLICITO**

*Defines and versions the calculation itself (the formula package): source, schemas, numeric dictionary, tests.*

- **What exists**: the Formula Package Manifest (`VccFormulaManifest`, ADR-003) *is* the publisher's artifact — it pins `implementationDigest`, `inputSchemaDigest`/`outputSchemaDigest`, `numericDictionary`, `outputProjection`, versioned per `slug@version` and gate-verified in CI (`vcc:registry:verify`). A statement's `formula.digest` binds the receipt to exactly that manifest (`spec-v0.2.md` §2, ADR-003).
- **Why implicit**: the manifest has **no publisher identity field**. The formula is authored, digested and served by CalcFleet; the receipt cannot say "formula published by X, signed by Y". See `formula-package.md` for the manifest itself.
- **Gap to close (v0.3)**: add a `publisher` reference (id + optional key) to the manifest so a third-party formula author becomes nameable and, eventually, co-signable.

### 2.2 Dataset publisher — **IMPLICITO**

*Publishes and versions the reference data a formula consumes.*

- **What exists**: the Dataset Manifest (`VccDatasetManifest`, `datasets.ts`) with `id`, `version`, `digest`, `sources[]`, `retrievedAt`, `effectiveFrom/To`, `license` — committed and CI-gated against drift. See `dataset-manifest.md`.
- **Why implicit**: `sources[]` records *upstream provenance* (BLS, Damodaran, vendor pricing pages) but there is **no dataset-publisher identity separate from the issuer**. CalcFleet ingests, snapshots and digests; the upstream author does not sign anything. No pilot formula consumes a dataset yet, so the role is currently unexercised in production receipts.
- **Gap to close**: a `publisher` field distinct from `sources[]` (who *snapshotted and vouches for* this version, vs. where the numbers came from).

### 2.3 Runtime operator — **IMPLICITO**

*Runs the formula on inputs and produces the outputs the receipt certifies.*

- **What exists**: the `engine` block — `name`, `version`, `commit`, `runtimeProfile: "node-deterministic-v1"` (`spec-v0.2.md` §2, `constants.ts`) — is the runtime operator's self-attestation. L2 re-execution (`verify-l2.ts`, ADR-005) lets a holder of the same code re-run and diff field-by-field.
- **Why implicit**: `runtimeProfile` is a **self-declared string**, not an attestation (no TEE/provenance — this is the missing "Runtime attestation" assurance axis, see `assurance-model.md` §2). L2 today runs on the **same server as the issuer** (`verify/[id]/page.tsx`), so "runtime operator" and "issuer" are the same party; independent runtime operators require the extractable SDK + published JSON Schema (audit §31.9).
- **Gap to close**: runtime attestation axis; independent (WASM or SDK-based) executors so re-execution is genuinely third-party.

### 2.4 Issuer — **FATTO**

*Signs the statement and publishes the key discovery document that lets anyone check the signature.*

- **What exists (this is the strongest-modeled role)**: DSSE + Ed25519 signature over `PAE(payloadType, JCS(statement))` (ADR-001); `issuer.id`/`issuer.name`/`issuer.keyDiscovery` in the statement; the well-known keyset at `/.well-known/vcc-issuer.json` with per-key `keyId`, `status`, `validFrom`, `validUntil` (`issuer-keys.ts`, ADR-004). Verification separates `cryptographicValidity` from `issuerKeyStatus` (`verify-l1.ts`).
- **Limit**: exactly **one** issuer (`https://calcfleet.com`, key `2026-07-a` active). The model is single-issuer; multi-issuer needs the trust registry (§2.8).
- **Key lifecycle for this role**: `docs/vcc/key-rotation.md`, ADR-004, and `master-prompt §31.5` — active/retired/revoked/compromised with ≤1h compromise propagation; KMS/HSM is a stub (T2 open-P1).

### 2.5 Auditor — **MANCANTE**

*An independent party that reviews the formula/dataset/runtime and countersigns an attestation of that review.*

- **What exists**: no auditor *identity* and no "auditor review" assurance axis yet, so v0.2 still issues exactly one signature. But the verifier now **evaluates multi-signature envelopes** (see §2.9): a countersignature is no longer merely tolerated by the schema — it is verified, and a bogus one fails the whole envelope. The mechanism the auditor role needs is therefore in place; what is missing is the auditor *identity* and the axis that consumes the countersignature.
- **Why it matters**: without it, "a valid signature ≠ an independent audit" (`spec-v0.2.md` §1) is stated as a *disclaimer* rather than backed by a *role* that could supply the missing assurance.
- **Gap to close (v0.3)**: define an auditor attestation predicate + the "Auditor review" axis (`assurance-model.md` §2), consuming the countersignature slot that §2.9 already verifies; keep it strictly separate from the issuer signature (an issuer MUST NOT self-audit).

### 2.9 Multi-signature semantics — **FATTO (verification)**

*How the verifier treats an envelope carrying more than one signature.*

- An envelope MAY carry **1..4 signatures with unique `keyid`s**. Verification evaluates **every** signature over the DSSE PAE; `checks.signature` is true iff there is ≥1 signature **and** every signature verifies with a known Ed25519 key (`keyKnown`/`algorithmSupported` are likewise the AND across all signatures, and `signatureResults[]` reports each `{ keyid, keyKnown, algorithmSupported, valid }` in order). This forbids two failure modes at once: a **bogus signature riding along a valid one**, and a **valid second signature being silently ignored when the first is invalid**.
- The **primary (first)** signature's key is the issuer's and drives `issuerKeyStatus` and `keyValidAtIssuance`. Additional signatures are **countersignatures** (e.g. an auditor's co-signature over the same statement) — the seat the Auditor role (§2.5) will occupy.
- Storage of multi-signature envelopes is governed by "verified-superset-wins" — see `ADR-006`.

### 2.6 Holder — **IMPLICITO (documented, not modeled)**

*The party that possesses a receipt and chooses whether/where to share it.*

- **What exists**: treated correctly in prose — receipts are shareable-by-construction, issued only on explicit `certify=1`, privacy-by-construction so a shared receipt reveals no requester identity (ADR-007, `privacy-profiles.md`). The holder's disclosure choice is the actual privacy control.
- **Why implicit**: the holder is **not a party in the format** — no holder binding, no holder key, no selective-disclosure (the missing privacy profiles, audit §31.6). A receipt is bearer-style: whoever has the bytes can present it.
- **Gap to close**: only if/when `encrypted-to-recipient` or `selective-disclosure` privacy profiles land (out of scope for v0.2; see `privacy-profiles.md`).

### 2.7 Verifier — **FATTO (single hard-wired policy)**

*Checks a receipt and decides whether to accept it, under a chosen trust policy.*

- **What exists**: a complete, offline-capable verifier (`verify-l1.ts` requires no network when given the keyset; L2 in `verify-l2.ts`), the public `/verify` and `/verify/{id}` surfaces, `POST /api/v1/verify`, and the reference CLI (`scripts/vcc/vcc-cli.ts`). The verifier-guide gives an 8-step L1 recipe implementable by third parties.
- **Divergence from §7**: the trust policy is **single and hard-wired** — `trustedAtVerificationTime = cryptographicValidity ∧ issuerIdentityBound ∧ keyValidAtIssuance ∧ issuerKeyStatus === "active" ∧ certificateStatus ∈ {valid, unknown}` (`verify-l1.ts`). The two axes beyond `cryptographicValidity` matter here: `issuerIdentityBound` (the signing keyset is bound to the claimed `statement.issuer.id`, so a valid signature by an *unrelated* keyset is trusted for nothing) and `keyValidAtIssuance` (the signature was made inside the key's `validFrom/validUntil` window — this is state #4, "key active at signing time", now truthfully computed; see `assurance-model.md`). The §7 definition ("accepts the issuer identity and key **under a selected trust policy**") requires a *selectable* policy; today the verifier cannot be told "reject unknown certificate status" or "trust only issuer X". "Unknown status does not block trust" is itself an undeclared policy choice (reasonable, but not surfaced as one).
- **Gap to close**: a policy parameter on the verify API/CLI + a named default policy; this is the verifier-side half of the trust registry.

### 2.8 Trust registry — **MANCANTE**

*The authority that tells a verifier which issuers (and their keys) to trust, and under what policy.*

- **What exists**: nothing beyond the single issuer's own keyset. There is no notion of multiple issuers, no registry a verifier consults, no selectable trust policy. The keyset at `/.well-known/vcc-issuer.json` is issuer-self-served (issuer honesty is checkable only via offline verification + public golden vectors, T21 accepted).
- **Why it is the structural gap**: every multi-party feature above (independent formula/dataset publishers, auditors, independent runtime operators) ultimately needs *someone the verifier trusts to say who is who*. This is the master's principal trust-chapter lacuna (audit §31.4).
- **Gap to close (v0.3+)**: define (a) a trust-policy object the verifier selects, (b) a registry format listing accepted issuers/keys with status, and (c) the relationship to an external timestamp/transparency log (already a documented extension point, `spec-v0.2.md` §9).

## 3. Role → responsibility → status matrix

| Role (§31.4) | Responsibility | Status | Where it lives today | Nameable gap |
|---|---|---|---|---|
| Formula publisher | Version the formula package | IMPLICITO | `VccFormulaManifest`, ADR-003 | No publisher identity in manifest |
| Dataset publisher | Version reference data | IMPLICITO | `VccDatasetManifest`, `datasets.ts` | Publisher ≠ upstream `sources[]` |
| Runtime operator | Execute & produce outputs | IMPLICITO | `engine` block; L2 re-run | Self-declared; no attestation; not independent |
| Issuer | Sign + publish key discovery | **FATTO** | ADR-001/004, keyset | Single issuer only |
| Auditor | Independent review + countersign | MANCANTE (mechanism FATTO) | — (multi-sig verified, §2.9) | Auditor identity + review axis |
| Holder | Possess & disclose receipt | IMPLICITO | ADR-007, `privacy-profiles.md` | Not a format party; no selective disclosure |
| Verifier | Accept under a trust policy | **FATTO** (fixed policy) | `verify-l1.ts`, `/verify`, CLI | Policy hard-wired, not selectable |
| Trust registry | Say who to trust | MANCANTE | — (single keyset) | Whole role — principal gap |

## 4. What CalcFleet is today

CalcFleet is **simultaneously formula publisher, dataset publisher, runtime operator and issuer**, and it also hosts the reference verifier. Four of the eight roles collapse into one legal entity; the spec does not yet name them apart. This is honest for a "first reference implementation" (the prescribed framing, §31), but the standard-readiness path is precisely the **de-fusion** of these roles — starting from the one axis-separation VCC already gets right (the four verification axes) and extending it to party-level identity.

## 5. Relationship to the other four documents

- **Issuer key lifecycle** (§31.5) → `key-rotation.md`, ADR-004; this document references it, does not restate it.
- **What the issuer's signature proves / does not prove** → `assurance-model.md` §3.
- **Formula-publisher artifact** → `formula-package.md`.
- **Dataset-publisher artifact** → `dataset-manifest.md`.
- **Holder disclosure & privacy** → `privacy-profiles.md`, ADR-007 (privacy profiles beyond "full" are audit §31.6, out of scope here).

## 6. Non-goals (v0.2 → v0.3 boundary)

No blockchain trust root, no trust *scores*, no marketplace of issuers, no automatic cross-issuer trust. The trust registry, when it lands, is an explicit verifier-selected policy — never an implicit global "trusted" flag (that would re-collapse exactly the axes §30 forbids collapsing).
