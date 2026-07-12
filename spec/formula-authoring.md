# Making a Formula Certifiable

**Who this is for.** A CalcFleet contributor adding formula #4 (and beyond) to the certifiable registry. Three pilots exist (`personal-loan-calculator`, `compound-interest-calculator`, `home-affordability-calculator`); this is the recipe they followed. Identity rules live in [ADR-003](../adr/ADR-003-formula-identity.md), numeric rules in [ADR-002](../adr/ADR-002-numeric-semantics.md).

## Prerequisites (hard gates)

A tool qualifies only if **all** of these hold:

1. **Pure calc** — `src/tools/<dir>/calc.ts` exports a pure function: no I/O, no clock, no network, no unseeded randomness (the factory convention already enforces this; the audit verified all 121 calcs pure).
2. **Input schema is privacy-safe** — every Zod input field is numeric, boolean, or a closed enum. One free-text field disqualifies the formula in v0.2 ([ADR-007](../adr/ADR-007-privacy-model.md)).
3. **Tests exist** — `calc.test.ts` with hand-verifiable numbers (its digest goes into the manifest as `testsDigest`).
4. **Sources declared** — the tool `config.ts` carries real `sources` (label + URL); they are copied into the manifest and every statement's `evidence`.

## Write the formula pack

Create `src/lib/vcc/formulas/<dir>.ts` exporting a `VccFormulaPack` (see `src/lib/vcc/types.ts`), and register it in `formulas/index.ts` — static import only; this registry *is* the L2 allowlist ([ADR-005](../adr/ADR-005-l2-reproduction.md)). The pack declares:

- **`outputSchema`** — a new Zod schema for the calc's output (tools historically have only TypeScript interfaces; the certificate needs runtime validation). Make it strict and exact.
- **Numeric dictionaries** (`inputRules` / `outputRules`) — one entry per numeric leaf, keyed by dotted path with `[]` for array elements (`yearlyTable[].balance`). Each rule is `{ type, scale, unit? }` where `type` ∈ `integer | decimal | percent | ratio | money | duration`. The dictionary — not the reader — decides whether `6.1` is a percent or a ratio. **A numeric leaf without a rule aborts issuance, fail-closed.**
- **`outputProjection`** — the top-level output keys that go into certificates. Tradeoff: everything you project is certified and counts against the 64 KB envelope cap; everything you omit is *not certified at all* (never silently truncated — the projection is declared in the manifest and digested). Example: `personal-loan-calculator` projects `monthlyPayment`, `totalInterest`, `totalPaid`, `originationFee`, `nominalAprPct`, `effectiveAprPct` and **excludes `schedule`** (up to 600 rows would dwarf the certificate); `compound-interest-calculator` includes its bounded yearly table (≤ 80 rows) in full. Decide per formula which claims are worth certifying.
- **`sampleInput`** — one schema-valid example input, used by golden vectors, demos, and tests.
- **`execute`** — the thin wrapper that runs the existing pure calc on schema-validated input. Do not reimplement the calc; do not modify it either.

## Choosing scales

Two different jobs, two different postures:

| Side | Job | Guidance |
|---|---|---|
| **Inputs** | Lossless record of what the user asked | Be generous. A rate entered as `7.375` must survive exactly — give percent inputs scale 4, money inputs scale 2, integer counts scale 0. If quantizing an input would lose digits the user typed, issuance fails with `numeric-precision-loss` — that is the correct outcome; raise the scale. |
| **Outputs** | Certified resolution of the result | Match the calc's own rounding. The factory rounds money to 2 decimals at output ⇒ money outputs get scale 2. The declared scale defines what L2 compares at: two doubles that quantize to the same string are *equal by definition*. Declaring more output digits than the formula meaningfully produces just certifies float noise. |

Quantization at the statement boundary is half-even in BigInt arithmetic, applied to the exact shortest-decimal form of the double — documented as distinct from the formula-internal `round2` ([ADR-002](../adr/ADR-002-numeric-semantics.md)). Never touch the calc's internal rounding.

## Build and commit the manifest

```bash
npm run vcc:registry:build
```

This deterministically generates `src/data/vcc/registry/<slug>/<version>.json` — the Formula Package Manifest: entrypoint, input/output schema digests (JCS of the JSON Schema), implementation digest (utf8-lf source bytes), tests digest, dependencies, datasets, sources, numeric dictionary, output projection. **Commit it.** The manifest is the formula's identity document; its digest is what statements carry as `formula.digest`, and it is served publicly at `/vcc/registry/<slug>/<version>`.

## Version-bump discipline

The manifest digest covers the implementation *and* the schemas *and* the dictionary *and* the projection. Therefore:

> Any change to the calc source (including comments/formatting), the input or output schema, a dictionary entry, or the projection ⇒ **bump the version** and regenerate the manifest.

The CI gate makes this non-optional:

```bash
npm run vcc:registry:verify
```

fails when a committed `slug+version` no longer matches the recomputed digests (drift), when a certifiable formula lacks a version/schema/profile/dictionary, or when a calc imports a dataset module without declaring it. Cosmetic-edit-forces-bump is the accepted cost of identity ([ADR-003](../adr/ADR-003-formula-identity.md)); the reverse — changed semantics under an unchanged version — is what the gate makes impossible.

## Datasets

If the calc reads anything from `src/data/*` (today: five AI-economics calcs import `@/data/ai-pricing`), the formula must declare a **Dataset Manifest**: id (`urn:vcc:dataset:<name>`), name, version, content digest, mediaType, sources, retrieval and effective dates, license (`VccDatasetManifest` in `types.ts`). The statement then lists the dataset with its digest, and L2 refuses to run if the local dataset bytes do not match (`dataset-unavailable`).

The ai-pricing snapshot is the worked example: versioned (`AI_PRICING_VINTAGE`), every entry source-attributed, manifest infra in `src/lib/vcc/datasets.ts` with a 1-byte-change test. Dataset-reading formulas certify only after their manifests ship in statements (infra present, formulas gated off — spec §9).

**Live-data formulas are NOT certifiable, ever.** A certificate binds a calculation to digested, versioned facts; a fetch at calc time has no digest, no version, and no reproducibility. Anything touching FRED/EIA-style live feeds stays in the UI layer (where it already lives) and out of the certifiable registry. This is a permanent rule, not a v0.2 gap.

## Checklist (compressed)

1. Confirm the four prerequisites (pure, privacy-safe inputs, tests, sources).
2. Author `outputSchema` + numeric dictionaries + `outputProjection` + `sampleInput` in a new formula pack; register it in `formulas/index.ts`.
3. `npm run vcc:registry:build`; commit the manifest under `src/data/vcc/registry/`.
4. `npm test` and `npm run vcc:registry:verify` green.
5. Issue against a local dev server with `?certify=1`; run `npm run vcc -- reproduce` on the result and expect `match` ([quickstart](./quickstart.md)).
6. From now on, any change to the formula's identity surface ⇒ version bump + rebuild, or CI stops you.
