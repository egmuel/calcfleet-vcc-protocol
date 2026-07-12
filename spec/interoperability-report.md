# VCC Interoperability Report — cross-language verifier conformance (§50)

Status: **Interoperable gate MET (v0.2, offline L1)** · Date: 2026-07-12
Sources: [conformance suite §21](./conformance.md),
[assurance-model §5.1](./assurance-model.md).

> The **"Interoperable"** gate (§50) requires **≥2 independent verifiers** that
> agree, **cross-language conformance** on the published corpus, and this public
> report. This document records the actual result.

---

## 1. The two independent verifiers

| # | Verifier | Language | Location | Role |
|---|----------|----------|----------|------|
| 1 | Reference | TypeScript / Node | `src/lib/vcc/verify-l1.ts` | authoritative |
| 2 | Independent | Python | `sdk/python/vcc_verifier.py` | second implementation |

The Python verifier is **from scratch**, not a transpile: it re-derives the JCS
(RFC 8785) canonicalization, the DSSE Pre-Authentication Encoding, the strict
v0.2 schema, the content-addressed statement id, and Ed25519 verification
independently. It shares **no code** with the reference and imports **nothing**
from CalcFleet.

**Vendor-independence (§49) — verified:**

- **Offline.** No `socket`/`http`/`urllib`/`requests`/`ssl`, no `urlopen`, no
  network I/O anywhere in `vcc_verifier.py` / `conformance_runner.py`. It reads
  only local JSON files and the caller-supplied keyset.
- **Standalone.** No import of `src/lib/vcc/*` or any CalcFleet module.
- **Minimal trust base.** Python stdlib + `cryptography` (Ed25519 only). No
  connection to calcfleet.com is required or made.

---

## 2. What "the same result" means here

Both verifiers implement **L1** (authenticity + integrity), reporting the same
nine per-check booleans and the same projected axes
(`cryptographicValidity`, `signatureValid`, `statementIntact`,
`trustedAtVerificationTime`). The Python runner asserts, per vector, that its
result matches the **outcome pinned for the TS reference** in
`src/lib/vcc/conformance.test.ts`:

- **positive** vectors → `cryptographicValidity=true`, empty errors,
  `trustedAtVerificationTime=true`;
- **negative** vectors → the exact `l1FailedChecks` are `false`, and the pinned
  `l1CryptographicValidity` / `l1TrustedAtVerificationTime` hold.

L2 (reproduction: formula digest, re-execution) is **not** part of the offline
L1 verifier and is out of scope for this cross-language check; the negative
vectors that also pin an `l2Status` are still checked here on their **L1** axes.

---

## 3. Result — full corpus

Environment: Python 3.12.3, `cryptography` 49.0.0 (TS reference: Node v22.18.0).
Command: `sdk/python/.venv/bin/python sdk/python/conformance_runner.py`.

```
[JCS] compound-interest-calculator.json   PASS
[JCS] home-affordability-calculator.json  PASS
[JCS] personal-loan-calculator.json       PASS
[JCS] tiered-commission-calculator.json   PASS
[POS] compound-interest-calculator.json   PASS
[POS] home-affordability-calculator.json  PASS
[POS] personal-loan-calculator.json       PASS
[POS] tiered-commission-calculator.json   PASS
[NEG] canonicalization-mismatch.json      PASS
[NEG] injected-extra-field.json           PASS
[NEG] invalid-signature.json              PASS
[NEG] modified-payload-input.json         PASS
[NEG] modified-payload-output.json        PASS
[NEG] revoked-key.json                    PASS
[NEG] unknown-formula.json                PASS
[NEG] unknown-key.json                    PASS
[NEG] unsupported-algorithm.json          PASS
[NEG] unsupported-profile.json            PASS
[NEG] withdrawn-certificate.json          PASS
[NEG] wrong-formula-digest.json           PASS
[NEG] wrong-payload-type.json             PASS
[NEG] wrong-signature-payload.json        PASS
MATCH: 22/22 checks match the pinned (TS reference) outcome
JCS byte-for-byte parity with TS on all positives: True
```

**Summary:** 4 positive + 14 negative vectors (18/18), plus 4 JCS byte-parity
checks → **22/22 match**. The Python verifier and the TS reference agree on
**every** committed vector, on **every** axis pinned for it.

---

## 4. The load-bearing check: JCS byte-for-byte parity

Interoperability lives or dies on canonicalization: if two verifiers canonicalize
the same statement to different bytes, they disagree on the payload↔statement
binding and on the statement id, and the whole chain breaks. Each positive
vector carries the **TS-produced** canonical string (`canonicalStatement`) and
its sha-256. The Python JCS output was compared against both:

| Positive vector | Python JCS == TS `canonicalStatement` | canonical sha-256 == pinned | statementId == `subject.id` |
|---|---|---|---|
| compound-interest-calculator | yes | yes | yes |
| home-affordability-calculator | yes | yes | yes |
| personal-loan-calculator | yes | yes | yes |
| tiered-commission-calculator | yes | yes | yes |

Byte-for-byte identical on all four. Additionally, `sdk/python/test_jcs.py`
pins JCS output for the divergence-prone edge cases (UTF-16 key ordering, ES
number ToString incl. `-0`→`"0"` and integral-float `.0` drop, minimal string
escaping, unicode passthrough, rejection of NaN/Infinity): **21/21 pass**.

---

## 5. Honest scope and limits (§50 honesty)

- **Gate met for offline L1.** ≥2 independent verifiers, cross-language, full
  agreement on the published corpus, byte-identical JCS. This is exactly the
  §50 "Interoperable" criterion for L1.
- **L2 not cross-verified.** The second verifier implements L1 only. L2
  (reproduction) parity across languages is a separate, later gate; the
  `l2Status` axes of the corpus remain covered by the TS suite. This report does
  **not** claim L2 interoperability.
- **Corpus scope.** The corpus is what the TS suite pins today (4 pilots, 14
  negatives). §21 axes not yet in the corpus (rounding, dataset, expired key)
  are neither claimed nor tested here — see `conformance.md §3`.
- **Reproducibility.** Anyone can re-run: create the venv, install
  `cryptography`, run `conformance_runner.py`. The committed test key is public,
  so the whole check runs with no secrets and no network.

---

## 6. Verdict

**Interoperable gate (§50): MET for offline L1 verification.** Two independent
verifiers (TypeScript reference + independent Python) produce identical results
on 22/22 checks over the published conformance corpus, with byte-for-byte JCS
agreement. Extend to L2 when a second-language reproduction path lands.
