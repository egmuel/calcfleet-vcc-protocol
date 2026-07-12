# VCC Dataset Manifest (§24, §31)

Status: **Draft v0.3-track** · 2026-07-12 · Formalizes the versioned Dataset Manifest already shipped as infrastructure (`src/lib/vcc/datasets.ts` → `VccDatasetManifest`, committed under `src/data/vcc/registry/datasets/<name>/<version>.json`) and specifies the full field set §24 requires for the Dataset Registry, mapped onto the benchmark datasets already present in `src/data/benchmarks/`. No code change; fields not yet in the shipped manifest are marked **MANCANTE**.

Source of truth: the internal VCC standard-readiness audit (§31.2/§31) and `src/lib/vcc/datasets.ts`.

---

## 1. Why datasets need a manifest

"A formula whose dataset is not versioned cannot be fully reproducible" (master §24). If a receipt says "computed against BLS median earnings" but cannot say *which snapshot*, L2 reproduction is impossible and the receipt over-claims. A **Dataset Manifest** makes each snapshot an identifiable, digested, time-bounded artifact so a formula can bind to exactly the data it consumed — and a verifier can resolve that snapshot by digest (assurance axis "Dataset resolvability", `assurance-model.md` §2).

## 2. The shipped Dataset Manifest

Typed as `VccDatasetManifest` (`types.ts:315-326`), derived **deterministically from the very module the calcs import** (`datasets.ts`), and committed at `src/data/vcc/registry/datasets/<name>/<version>.json`. The CI gate fails if the committed manifest ever drifts from the in-repo data (dataset changed without a vintage bump). No pilot formula consumes a dataset yet — this is proven infrastructure the AI-economics formulas will use on migration (`datasets.ts` header).

Real shipped example (`src/data/vcc/registry/datasets/ai-pricing/2026-07.json`):

```json
{
  "id": "urn:vcc:dataset:ai-pricing",
  "name": "ai-pricing",
  "version": "2026-07",
  "digest": { "algorithm": "sha-256", "value": "e437c2c2…838617" },
  "mediaType": "application/json",
  "sources": [
    { "label": "OpenAI API pricing", "url": "https://developers.openai.com/api/docs/pricing" },
    { "label": "Anthropic pricing", "url": "https://platform.claude.com/docs/en/docs/about-claude/pricing" },
    { "label": "Google Gemini API pricing", "url": "https://ai.google.dev/gemini-api/docs/pricing" }
  ],
  "retrievedAt": "2026-07-07T00:00:00Z",
  "effectiveFrom": "2026-07-01T00:00:00Z",
  "effectiveTo": null,
  "license": null
}
```

The `digest` is over the JCS bytes of a fixed canonical content object (`aiPricingCanonicalContent()`, `datasets.ts`) — documented so third parties can recompute it from the published source. A statement references a dataset via `VccDatasetRef` (`id, name, version, digest, mediaType`), a strict subset of the manifest; L2 checks the referenced digest against the resolvable snapshot before executing (ADR-005 §2).

## 3. §24 field-by-field

The master (§24) requires thirteen fields on each Dataset Registry entry. Mapping to `VccDatasetManifest`:

| §24 field | Manifest field | Status | Note |
|---|---|---|---|
| Dataset ID | `id` (`urn:vcc:dataset:<name>`) | **FATTO** | |
| Version | `version` (e.g. `"2026-07"`) | **FATTO** | Vintage-style; a bump is required on any content change (CI gate) |
| Publisher | — | **MANCANTE** | No publisher identity distinct from `sources[]` — see `trust-model.md` §2.2 |
| Source | `sources[] = {label, url}` | **FATTO** | Upstream provenance (multiple URLs supported) |
| License | `license` (string \| null) | **PARZIALE** | Field exists; `null` today (ai-pricing). MUST be populated per source's terms before public serving |
| Effective period | `effectiveFrom` + `effectiveTo` (null = current) | **FATTO** | |
| Retrieved at | `retrievedAt` (ISO) | **FATTO** | |
| Transformation steps | — | **MANCANTE** | No record of how upstream was normalized into the snapshot (see §4.1) |
| Digest | `digest` = SHA-256 of JCS(canonical content) | **FATTO** | Recomputable from published source |
| Update cadence | — | **MANCANTE** | No declared refresh cadence (see §4.2) |
| Deprecated at | — | **MANCANTE** | No deprecation timestamp (see §4.3) |
| Replaced by | — | **MANCANTE** | No successor pointer (see §4.3) |
| mediaType (adjunct) | `mediaType` | **FATTO** | `application/json` |

**7 of 13 fields ship**; the six missing are lifecycle/provenance metadata, all additive.

## 4. The missing fields (additive, no format break)

### 4.1 Transformation steps — **MANCANTE**

The manifest records *where* data came from (`sources[]`) and *what bytes* it is now (`digest`), but not *what was done in between*. For `ai-pricing` the transformation is "read vendor pages, tabulate into fixed keys" (`aiPricingCanonicalContent()`); for the benchmark tables it is the ingestion script (§5). Proposed: a `transformation` field — either a prose step list or a digest of the ingestion script — so the path from upstream to snapshot is auditable. This is also what a distinct *dataset publisher* would attest (`trust-model.md` §2.2).

### 4.2 Update cadence — **MANCANTE**

No declared refresh interval. `ai-pricing` is monthly-vintage by convention; the benchmark tables are quarterly (BLS) / annual (Damodaran) upstream. Proposed: a `cadence` field (`"monthly" | "quarterly" | "annual" | "irregular"`) so consumers know how stale a snapshot may be relative to its `effectiveFrom`.

### 4.3 Deprecation lifecycle (`deprecatedAt` + `replacedBy`) — **MANCANTE**

There is no way to mark a snapshot superseded and point to its successor. Proposed: `deprecatedAt` (ISO, null while current) + `replacedBy` (the successor dataset `id@version`, null otherwise). This lets the Dataset Registry present a changelog and lets a verifier note that a receipt used a since-superseded snapshot — without invalidating it (the historical fact stands, mirroring certificate-status semantics in ADR-006 §5).

## 5. The datasets already present in `src/data/benchmarks/` (not yet manifested)

Three snapshot tables exist as versioned static modules (`BenchmarkTable`, `src/data/benchmarks/types.ts`), emitted by hand-run ingestion scripts, **no runtime fetch** (`types.ts` header). They already carry most of a manifest's provenance in their `source` object — but they are **not yet VCC Dataset Manifests** and are not committed under `registry/datasets/`. They are the immediate candidates for manifesting.

| Module | `id` | Version (`vintage`) | Upstream `source.url` | `retrievedAt` | Cadence (implied) |
|---|---|---|---|---|---|
| `damodaran-margins-2026.ts` | `damodaran-gross-margin-2026` (+ other metrics) | Jan 2026 vintage | stern.nyu.edu Damodaran margin dataset | 2026-07-06 | annual |
| `bls-median-earnings-2026.ts` | `bls-median-weekly-earnings-2026` | `2026 Q1` | BLS public API v2, series LEU0252881500 | 2026-07-06 | quarterly |
| (ai-pricing, already manifested) | `urn:vcc:dataset:ai-pricing` | `2026-07` | vendor pricing pages | 2026-07-07 | monthly |

The benchmark modules already embed `source: { name, url, vintage, retrievedAt }` and a `methodologyNote` (`types.ts:37-39`) — nearly a manifest minus `id`/`digest`/`effective period`/`license`/lifecycle. **Field mapping** to close the gap:

- `BenchmarkTable.id` → manifest `name`, and `urn:vcc:dataset:<id>` → manifest `id`;
- `source.url` → `sources[].url`, `source.name` → `sources[].label`;
- `source.vintage` → `version`; `source.retrievedAt` → `retrievedAt`;
- `methodologyNote` → seed of `transformation` (§4.1);
- **new**: `digest` (JCS of the table's canonical content, same recipe as `datasets.ts`), `effectiveFrom/To`, `license` (BLS = public domain; Damodaran = check terms), `cadence`, `deprecatedAt`/`replacedBy`.

Manifesting these is the deterministic-derivation pattern `datasets.ts` already proves — no new mechanism, and it is the precondition for certifying any formula that reads a benchmark (e.g. margin/earnings-driven tools) with real dataset resolvability.

## 6. Proposed v0.3 `VccDatasetManifest` shape (additive)

```jsonc
{
  "id": "urn:vcc:dataset:bls-median-weekly-earnings",
  "name": "bls-median-weekly-earnings-2026",
  "version": "2026-Q1",
  "publisher": { "id": "https://calcfleet.com", "name": "CalcFleet" },  // §3 Publisher
  "digest": { "algorithm": "sha-256", "value": "…" },
  "mediaType": "application/json",
  "sources": [ { "label": "BLS CPS series LEU0252881500", "url": "https://api.bls.gov/…" } ],
  "license": "public-domain",                    // §4 populate
  "retrievedAt": "2026-07-06T00:00:00Z",
  "effectiveFrom": "2026-01-01T00:00:00Z",
  "effectiveTo": null,
  "transformation": "BLS public API v2 → single national median, gross weekly, NSA",  // §4.1
  "cadence": "quarterly",                         // §4.2
  "deprecatedAt": null,                           // §4.3
  "replacedBy": null                              // §4.3
}
```

Every added field becomes part of the digested identity or the registry changelog; adopting them is a versioned change, never a silent reinterpretation of an existing snapshot.

## 7. What this document is NOT

It does not define how a formula *binds* to a dataset (that is the formula manifest's `datasets[]`, `formula-package.md`), how L2 *checks* dataset digests (ADR-005), or the dataset-publisher *role* separation (`trust-model.md` §2.2). It formalizes only the manifest: its shipped fields, the six §24 fields still to add, and the mapping onto the benchmark data already in the repo.
