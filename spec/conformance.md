# VCC Conformance Suite (§21)

Status: **Built (v0.2)** · Data: 2026-07-12 · Isola VCC, sotto-blocco G.
Fonti: [verifier-guide](./verifier-guide.md), [assurance-model §5.1](./assurance-model.md).

> This page documents the **conformance corpus** and the `vcc test` runner. A verifier is **VCC-v0.2 conformant** if, given the published corpus, it produces the pinned outcome on every **positive** vector (accept) and every **negative** vector (reject on the exact axis under test).
>
> The badge **"VCC conformance tests passed"** is a **technical** signal only. It is **NOT** a legal certification (§21). Anyone can run the suite; passing it means the corpus behaved as pinned, nothing more.

---

## 1. What the suite is

Two self-describing, language-agnostic JSON corpora, signed with the **public** test key (`src/lib/vcc/vectors/test-key.json` — the private half is committed on purpose for reproducibility, so a certificate signed with it proves nothing):

| Corpus | Location | Each vector carries |
|---|---|---|
| **Positive** (golden) | `src/lib/vcc/vectors/*.json` | envelope + statement + expected `{l1.cryptographicValidity, l2.status}` |
| **Negative** | `src/lib/vcc/vectors/negative/*.json` | envelope + `case` (§21 axis) + `tampering` (prose) + `derivedFrom` + expected outcome |

Every **negative** vector is **derived from a golden positive by exactly ONE tampering** (base: `personal-loan-calculator.json`), regenerated reproducibly by `scripts/vcc/generate-negative-vectors.ts` (`npm run vcc:conformance:gen`). No vector is hand-authored. `negative/index.json` enumerates the set; `conformance.test.ts` pins that the index and the directory agree, so drift breaks CI.

---

## 2. §21 axes — coverage

The §21 list, and where each axis stands in **this** engine:

| §21 axis | Vector(s) | Expected outcome | Evaluated? |
|---|---|---|---|
| valid receipts | 4 positives | L1 `cryptographicValidity=true`, L2 `status=match` | **yes** |
| invalid signature | `invalid-signature`, `wrong-signature-payload`, `unknown-key`, `unsupported-algorithm` | L1 `signature` / `keyKnown` / `algorithmSupported` = false | **yes** |
| modified payload | `modified-payload-output`, `modified-payload-input`, `injected-extra-field`, `wrong-payload-type` | L1 `statementId`+`signature` / `statementSchema` / `envelopeSchema` = false | **yes** |
| unknown formula | `unknown-formula` | L1 tamper detected; L2 `status=formula-unavailable` | **yes** |
| wrong formula digest | `wrong-formula-digest` | L1 tamper detected; L2 `status=mismatch` (digest pre-check refuses to execute) | **yes** |
| canonicalization mismatch | `canonicalization-mismatch` | L1 `canonicalization`+`signature` = false | **yes** |
| unsupported profile | `unsupported-profile` | L2 `status=unsupported-profile` (L1 also fails: unsigned tamper) | **yes** |
| revoked key | `revoked-key`, `withdrawn-certificate` | L1 `cryptographicValidity=true`, `trustedAtVerificationTime=false` | **yes** |
| rounding mismatch | — | see §3 | **not yet** (see below) |
| dataset mismatch | — | see §3 | **not yet** (pilots have no dataset ref) |
| expired key | — | see §3 | **not yet** (no key-expiry field in the model) |
| reproduction mismatch | (covered indirectly) | L2 `status=mismatch` on a doctored output | partial (in-code; see §3) |

**Two orthogonal axes** (assurance-model §5.1). L1 separates *authenticity/integrity* from *trust*: a **revoked key** or **withdrawn certificate** leaves the cryptography valid (`cryptographicValidity=true`) but withholds trust (`trustedAtVerificationTime=false`). The revoked/withdrawn vectors pin exactly that — they are **not** signature failures.

---

## 3. Honestly "not yet evaluated"

We do **not** fake a capability the engine lacks. These §21 axes have **no negative vector** yet, with the concrete reason:

- **rounding mismatch** — the numeric profile (`vcc-decimal-v1`) rounding is pinned *in code* (`numeric.test.ts`, golden vectors). A portable rounding corpus needs the value grammar to be **normative outside the code** (conformance-plan §4.8, isola VCC-A). Until then a rounding vector would test the reference impl against itself, not the standard.
- **dataset mismatch** — the four pilot statements carry `datasets: []`. L2 *does* distinguish `dataset-unavailable` from digest-drift `mismatch` (exercised in `reproduction.test.ts`), but no **published golden** references a dataset, so no negative vector derives from one. When a dataset-bound pilot ships, add `dataset-digest-drift.json` here.
- **expired key** — the key model has `status` (`active`/`retired`/`revoked`/`compromised`) but **no expiry timestamp**; there is no "expired" state to assert. `retired`/`revoked` already gate trust (`revoked-key` vector). An expiry axis needs a spec change first.
- **reproduction mismatch** — covered **in code** (`reproduction.test.ts`: doctored output → `status=mismatch` with a field-level diff), but not yet serialized as a standalone negative vector because a re-signed mismatching statement requires a distinct issuance path. The `wrong-formula-digest` vector pins the closest published `L2 status=mismatch`.

This list is the honest backlog; each item names its unblocking prerequisite.

---

## 4. Running `vcc test`

```bash
npm run vcc:test           # human-readable
npm run vcc:conformance    # same thing (alias)
npm run vcc:test -- --json # machine-readable report
```

Exit code: **0** iff every vector matches its pinned outcome, **1** otherwise. The runner (`scripts/vcc/conformance.ts`) loads both corpora, verifies each envelope with the public test keyset (applying per-vector keyset variants for revoked/wrong-algorithm and the certificate status for withdrawn), and compares against the expected outcome. Sample output:

```text
VCC conformance suite (§21)

  [PASS] positive personal-loan-calculator  (valid receipts)
  ...
  [PASS] negative revoked-key  (revoked key)
  [PASS] negative wrong-formula-digest  (wrong formula digest)

18/18 vectors conformant (4 positive, 14 negative).

VCC conformance tests passed (technical badge — NOT a legal certification).
```

The same assertions run under `npm test` (`src/lib/vcc/conformance.test.ts`), so the CI gate covers the corpus too.

---

## 5. For an independent implementation

The corpus is **JSON, not TypeScript**. A Python/Rust verifier declares conformance by reproducing these rules on the same files:

1. **Positives** — for each `vectors/*.json` (skip `test-key.json`): decode the DSSE envelope, verify the Ed25519 signature over the JCS-canonical PAE with the public test key, confirm `cryptographicValidity == expected.l1.cryptographicValidity` and (if L2 is implemented) `reproduce().status == expected.l2.status`.
2. **Negatives** — for each `vectors/negative/*.json` (skip `index.json`): apply the vector's `expected.keyset` variant (`revoked` → key status `revoked`; `wrong-algorithm` → algorithm `rsa`) and `expected.certificateStatus`, then verify. Assert every name in `expected.l1FailedChecks` is `false`; assert `cryptographicValidity`, `trustedAtVerificationTime`, and (leniently-decoded) L2 `status` match wherever the vector pins them. A rejected vector MUST also surface at least one error string, and MUST NEVER throw.
3. Report `{ vector, expected, actual, pass }` and exit non-zero on any divergence (mirrors `runner-contract.md` in conformance-plan §4.5).

The verification recipe each vector pins is the 8-step L1 procedure in the [verifier-guide](./verifier-guide.md); the L2 gates are in [assurance-model](./assurance-model.md) / verify-l2. No CalcFleet commercial service is required to run any of this (governance §22 neutrality).

---

## 6. Regenerating the corpus

```bash
npm run vcc:conformance:gen   # rewrites src/lib/vcc/vectors/negative/*.json + index.json
```

Only after an **intentional** format change. `conformance.test.ts` pins the outcomes, so regeneration is always an explicit, reviewed act — a vector whose tampering the engine does not actually catch turns the suite RED, which is the point.
