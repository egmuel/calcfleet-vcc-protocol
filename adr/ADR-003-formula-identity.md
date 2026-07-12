# ADR-003 — Formula identity: manifest, digests, version gate

Status: **Accepted** (2026-07-11)

## Context

`slug` alone is mutable identity: the implementation behind it can change. A raw source hash is brittle (line endings, comments, formatting). VCC needs "which formula, exactly?" to be answerable and CI-enforceable.

## Decision

Each certifiable formula gets a **Formula Package Manifest**, generated deterministically by `scripts/vcc/build-formula-registry.ts` and committed at `src/data/vcc/registry/<slug>/<version>.json`:

```json
{
  "slug": "personal-loan-calculator",
  "version": "1.0.0",
  "entrypoint": "src/tools/personal-loan/calc.ts#calcPersonalLoan",
  "inputSchemaDigest":  { "algorithm": "sha-256", "value": "<hex of JCS(JSON Schema)>" },
  "outputSchemaDigest": { "algorithm": "sha-256", "value": "<hex of JCS(JSON Schema)>" },
  "implementationDigest": { "algorithm": "sha-256", "value": "<hex of utf8-lf source bytes>" },
  "testsDigest": { "algorithm": "sha-256", "value": "<hex of utf8-lf calc.test.ts bytes>" },
  "dependencies": [],
  "datasets": [],
  "sources": [ { "label": "...", "url": "..." } ],
  "numericProfile": "vcc-decimal-v1",
  "numericDictionary": { "<path>": { "type": "money", "scale": 2, "unit": "USD" } },
  "outputProjection": ["monthlyPayment", "totalInterest", "..."]
}
```

- **implementationDigest**: SHA-256 over the calc module source normalized as `utf8-lf-v1` (UTF-8, BOM stripped, CRLF/CR→LF). Comments/formatting *do* change it — accepted trade-off: the CI **version gate** (`vcc:registry:verify`) turns any drift into an explicit decision (bump version, regenerate manifest) instead of a silent identity change. AST-level normalization was rejected as unauditable complexity for v0.2.
- **Schema digests**: SHA-256 of the JCS canonical bytes of the JSON Schema produced by `z.toJSONSchema` (input schema = the tool's existing Zod schema; output schema = new Zod schema authored in the formula pack).
- **testsDigest**: proves *which* suite was associated, not correctness.
- **numericDictionary + outputProjection are part of the manifest**, hence part of the digested identity: changing what is certified or how numbers are typed is a version change. Dictionary keys are dotted paths with `[]` for array elements (`yearlyTable[].balance`).
- **formula.digest in statements** = SHA-256 of the JCS bytes of the manifest itself minus the `digest` field (the manifest is the identity document). `publishedAt` is deliberately **excluded from the manifest** (kept in git history) so generation is timestamp-free and reproducible.
- Rules enforced by `scripts/vcc/verify-formula-versions.ts` (CI): same `slug+version` ⇒ identical digest; missing version/schema/profile/dictionary ⇒ fail; a formula whose calc imports a dataset module must declare it in `datasets` ⇒ else fail.

## Alternatives considered

- Hash of bundler output: nondeterministic across bundler versions, opaque to review.
- Behavioral identity (golden-vector hash only): can't distinguish implementations that agree on the vector set; kept as *complementary* evidence (`testsDigest` + golden vectors), not identity.
- Central `versions.ts` map instead of per-version JSON files: loses immutability-by-file and easy public serving (`/vcc/registry/{slug}/{version}`).

## Consequences

Cosmetic edits to a pilot calc file now require a version bump + `npm run vcc:registry:build`. That is the intended cost of identity.

## Risks

- Human bumps version but semantics unchanged (noise) — acceptable; the reverse (changed semantics, same version) is what the gate makes impossible.
- Transitive dependency drift (zod version) is not captured in v0.2 digests; recorded as `dependencies` entries with the locked version from `package-lock.json` for review. Full lockfile-slice digesting = P1.
