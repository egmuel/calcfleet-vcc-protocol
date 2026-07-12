# VCC Formula Package (§31.2)

Status: **Draft v0.3-track** · 2026-07-12 · Formalizes the **Formula Package Manifest already shipped** (`docs/adr/ADR-003-formula-identity.md`, `src/lib/vcc/types.ts` `VccFormulaManifest`, manifests under `src/data/vcc/registry/<slug>/<version>.json`, CI version-gate `vcc:registry:verify`) and specifies the fields §31.2 requires beyond a file hash. No code change; fields not yet in the manifest are marked **MANCANTE / P1** and defer to the ADR where already decided.

Source of truth: `docs/site-audit/vcc-standard-readiness-audit.md` §31.2.

---

## 1. Why a hash of the file is not enough

`slug` is mutable identity — the code behind it can change. A raw source hash is brittle (line endings, comments, formatting flip it) and, worse, it does not capture the *dependencies, schemas, numeric rules, and datasets* that also determine the output. §31.2 therefore requires a **package**, not a hash: Source, Lockfile, Dependencies, Runtime, Compiler, Configuration, Schemas, Test vectors, Build recipe, Digest, License. This document maps each onto the shipped Formula Package Manifest and marks what is still missing.

## 2. The shipped Formula Package Manifest

Generated deterministically by `scripts/vcc/build-formula-registry.ts`, committed at `src/data/vcc/registry/<slug>/<version>.json`, typed as `VccFormulaManifest` (`types.ts:261-282`), and served immutably at `GET /vcc/registry/{slug}/{version}` (`spec-v0.2.md` §8). A statement's `formula.digest` = SHA-256 of the JCS bytes of the manifest **minus** its own `digest` field — the manifest is the identity document (ADR-003).

Real shipped example (`src/data/vcc/registry/personal-loan-calculator/1.0.0.json`, elided):

```json
{
  "slug": "personal-loan-calculator",
  "version": "1.0.0",
  "entrypoint": "src/tools/personal-loan/calc.ts#calcPersonalLoan",
  "inputSchemaDigest":  { "algorithm": "sha-256", "value": "e6dee2…" },
  "outputSchemaDigest": { "algorithm": "sha-256", "value": "5aa5ad…" },
  "implementationDigest": { "algorithm": "sha-256", "value": "e7055f…" },
  "testsDigest": { "algorithm": "sha-256", "value": "cd6a71…" },
  "dependencies": [ { "name": "zod", "version": "4.4.3" } ],
  "datasets": [],
  "sources": [],
  "numericProfile": "vcc-decimal-v1",
  "numericDictionary": { "inputs": { "principal": { "type": "money", "scale": 2, "unit": "USD" }, "…": "…" },
                         "outputs": { "monthlyPayment": { "type": "money", "scale": 2, "unit": "USD" }, "…": "…" } },
  "outputProjection": ["monthlyPayment", "totalInterest", "totalPaid", "originationFee", "nominalAprPct", "effectiveAprPct"]
}
```

### 2.1 The CI version-gate (the reason identity is trustworthy)

`npm run vcc:registry:verify` (CI, `.github/workflows/ci.yml`) recomputes every digest from source on each push. Rule: **same `slug+version` ⇒ identical digest**; any drift fails the build, forcing an explicit decision (bump the version, regenerate) instead of a silent identity change. Missing version/schema/profile/dictionary fails; a calc that imports a dataset module but does not declare it in `datasets[]` fails (ADR-003 §Decision, `scripts/vcc/verify-formula-versions.ts`). This is what turns "the manifest" into "the digested, immutable package".

## 3. §31.2 field-by-field

| §31.2 field | Manifest mapping | Status | Note |
|---|---|---|---|
| **Source** | `implementationDigest` = SHA-256 of calc module normalized `utf8-lf-v1` (UTF-8, BOM stripped, CRLF/CR→LF) | **FATTO** | Comments/formatting change it — accepted; the gate turns drift into a version decision (ADR-003). AST-normalization rejected as unauditable for v0.2 |
| **Schemas** | `inputSchemaDigest` + `outputSchemaDigest` = SHA-256 of JCS bytes of the JSON Schema from `z.toJSONSchema` | **FATTO** | Input schema = the tool's existing Zod schema; output schema authored in the pack |
| **Test vectors** | `testsDigest` = SHA-256 of `calc.test.ts` (utf8-lf) + committed golden vectors (`vectors/*.json`) | **FATTO** | `testsDigest` proves *which* suite, not correctness |
| **Digest** | `formula.digest` in statements = SHA-256 of JCS(manifest − digest) | **FATTO** | `publishedAt` deliberately excluded from the manifest (kept in git) so generation is timestamp-free/reproducible |
| **Dependencies** | `dependencies[] = {name, version}`, direct deps at the locked version from `package-lock.json` | **PARZIALE** | Direct deps recorded; **transitive deps not digested** (see §4.1) |
| **Datasets** (adjunct) | `datasets[]` = dataset-manifest ids consumed | **FATTO (infra)** | Empty for pilots; the gate fails on undeclared dataset imports. See `dataset-manifest.md` |
| **Numeric rules** (adjunct) | `numericDictionary` + `numericProfile` + `outputProjection`, all digested | **FATTO** | Changing what is certified or how numbers are typed = a version change (ADR-003) |
| **Lockfile** | — | **MANCANTE (P1)** | Direct-dep versions only; no locked transitive slice (see §4.1) |
| **Runtime** | `engine.runtimeProfile: "node-deterministic-v1"` in the statement (not the manifest) | **MANCANTE (in manifest)** | Self-declared string; no runtime digest/attestation (also assurance axis 7, `assurance-model.md` §2) |
| **Compiler** | — | **MANCANTE** | No tsconfig/compiler version/target digested |
| **Configuration** | — | **MANCANTE** | No build-config digest in the manifest |
| **Build recipe** | Deterministic generator script exists | **MANCANTE (in manifest)** | Reproducible in practice, but the manifest carries no `{command, toolchain, environment}` recipe |
| **License** | — | **MANCANTE** | No `license` field on the Formula Manifest (it exists on `VccDatasetManifest`); and the repo has no root LICENSE at all (audit §31.10) |

## 4. The four real gaps (and where each is already decided)

### 4.1 Lockfile / transitive dependencies — **P1**

Direct dependencies are pinned (`zod@4.4.3` in the example); **transitive** dependencies are not digested. ADR-003 §Risks records this as "Full lockfile-slice digesting = P1"; threat model T17 is **open-P1**, T18 "accepted". The seam is the existing `dependencies[]` array — the fix is to add a digest over the relevant `package-lock.json` slice, not a redesign. Blocks enterprise reliance, not SDK/conformance work (audit §6).

### 4.2 Runtime / Compiler / Configuration — **MANCANTE**

Only the string `runtimeProfile: "node-deterministic-v1"` exists (`constants.ts`, statement `engine` block). To satisfy §31.2 the manifest should additionally digest: Node/engine version + flags, TypeScript compiler version + `tsconfig` (target/module/strictness), and any build configuration that affects the emitted calc. This overlaps the **Runtime attestation** assurance axis (`assurance-model.md` §2) — a self-declared profile is the floor; an attestation is the ceiling.

### 4.3 Build recipe — **MANCANTE (in manifest)**

Generation is deterministic via `build-formula-registry.ts`, but the manifest does not embed a reproducible recipe. Proposed: a `buildRecipe` block `{ generator, command, toolchainDigest }` so a third party can regenerate the manifest and confirm the digest independently — the precondition for an independent formula publisher (`trust-model.md` §2.1).

### 4.4 License — **MANCANTE (and blocking)**

The Formula Manifest has no `license` field, and — more fundamentally — the repository has **no root LICENSE** (audit §31.10). Without a license, no third party may legally implement a verifier or reuse the vectors, which blocks the entire independent-implementations track before it is even a technical question. `VccDatasetManifest` already has a `license` field (`dataset-manifest.md`); the Formula Manifest should gain the same, and the repo/spec-space needs an actual license (Apache-2.0 proposed in audit §6 for the IP grant).

## 5. Proposed v0.3 manifest additions (additive, digest-versioned)

To close §31.2 without breaking existing receipts, add these fields to `VccFormulaManifest` — each becomes part of the digested identity, so adopting them is a version bump, never a silent change:

```jsonc
{
  "license": "Apache-2.0",                     // §4.4
  "lockfileDigest": { "algorithm": "sha-256", "value": "…" },   // §4.1 transitive slice
  "runtime": { "engine": "node", "version": "…", "profile": "node-deterministic-v1",
               "compiler": { "name": "typescript", "version": "…", "configDigest": {"…":"…"} } }, // §4.2
  "buildRecipe": { "generator": "scripts/vcc/build-formula-registry.ts", "command": "npm run vcc:registry:build",
                   "toolchainDigest": { "algorithm": "sha-256", "value": "…" } },  // §4.3
  "publisher": { "id": "https://calcfleet.com", "name": "CalcFleet" }  // trust-model §2.1
}
```

## 6. What this document is NOT

It does not restate the numeric dictionary semantics (`numeric-profiles.md`), the dataset manifest (`dataset-manifest.md`), or the envelope/signature (ADR-001, `assurance-model.md`). It formalizes only the formula *package*: what identifies a formula version, what the manifest carries today, and the exact §31.2 fields still to add.
