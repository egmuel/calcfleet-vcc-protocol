# VCC Data Model — receipt fields and the `attestation` block

> Companion to `spec-v0.2.md` §2 (the wire shape) and the master prompt §15
> (data model), §42 (issuer attestation), §43 (receipt types). This doc records
> the **normative meaning** of each receipt field and the rationale for the
> `attestation` block added in v0.2. The core is v0.x and instrumentally
> unstable; breaking changes are allowed with a changelog entry here.

## Source of truth

- Static shapes: `src/lib/vcc/types.ts` (`VccStatement`).
- Runtime validation: `src/lib/vcc/schemas.ts` (Zod, strict — unknown keys rejected everywhere). This is the authoritative schema.
- Portable JSON Schema (attestation slice): `src/lib/vcc/schema.ts` (`VCC_ATTESTATION_JSON_SCHEMA`, Draft 2020-12) for third parties that cannot run the Zod schema. A full standalone JSON Schema of the whole statement is tracked in `conformance-plan.md`.
- Golden vectors pin the bytes: `src/lib/vcc/vectors/*.json` (regenerate with `npm run vcc:vectors` — never by hand; `vectors.test.ts` fails on drift).

## Field map (master §15 → statement)

| §15 field | Statement location | Notes |
|---|---|---|
| Protocol version | `specVersion` = `"0.2"` | |
| Statement ID | `subject.id` = `urn:vcc:calculation:sha256:<hex64>` | Content-addressed over JCS(statement) with `subject.id` absent. Names an *issuance*, not a formula+input pair. |
| Calculation ID | fused into `subject.id` | v0.2 does not carry a separate calculation id (audit §1). |
| Formula ID / version | `formula.id` / `formula.version` | |
| Formula package digest | `formula.digest` | SHA-256 of the manifest (ADR-003), not raw source. |
| Normalized inputs / Output | `calculation.inputs` / `calculation.outputs` | Typed decimal values (`vcc-decimal-v1`). |
| Numeric profile | `calculation.numericProfile` | |
| Dataset references | `datasets[]` | Empty for the pilots. |
| Issuer / Issued at | `issuer` / `issuedAt` | Seconds-UTC. |
| Key ID / Signature | `envelope.signatures[].keyid` / `.sig` | Ed25519 over the DSSE PAE. |
| Runtime profile | `engine.runtimeProfile` | Self-declared string (assurance axis 7 still open). |
| **Issuer attestation** | **`attestation` (new v0.2)** | See below. |
| Reproduction evidence | — | Not a receipt field in v0.2; L2 is a verifier-side result. |
| Policy results | — | Not present in v0.2. |

## `attestation` — what the issuer attests to (§42, §43)

```jsonc
"attestation": {
  "type": "execution",
  "claims": ["inputs-received", "formula-executed", "numeric-profile-applied", "output-produced"]
}
```

It sits between `engine` and `issuedAt` in the statement and is **part of the
signed, content-addressed payload** — changing it changes the receipt id and
invalidates the signature. Before v0.2 these facts were only *implicit* in the
statement's semantics; the block makes them a machine-readable list a verifier
can name.

### `type` — receipt type (§43)

Names *who attests to what*, so the three categories are never collapsed under
one badge:

- `execution` — the issuer ran the declared calculation with the declared elements (§43.1). **The only type CalcFleet emits.**
- `reproduction` — a third party re-ran the declared calculation and matched, or documented the divergence (§43.2). **Defined, not emitted** by CalcFleet — today L2 reproduction is a verifier-side result, not a signed receipt.
- `review` — an auditor / reviewer / policy engine evaluated the formula, dataset, policy or methodology (§43.3). **Defined, not emitted.**

`reproduction` and `review` are in the schema so verifiers can round-trip
receipts issued by *other* parties; CalcFleet does not force-issue them.

### `claims` — what the issuer, as issuer of an execution receipt, attests to

Each claim is a fact the pipeline **performed** (`src/lib/vcc/issue.ts`,
`executionAttestation`):

- `inputs-received` — received the declared normalized inputs.
- `formula-executed` — executed the declared formula package.
- `datasets-used` — used the declared dataset snapshots. **Present only when `datasets.length > 0`**, so a receipt never claims to have used data it did not (the pilots reference no datasets and therefore omit this claim).
- `numeric-profile-applied` — applied the declared numeric profile.
- `output-produced` — produced the declared output.

Claims are ordered, non-empty, and duplicate-free (enforced by the schema).

### What the issuer does **not** attest to (§42)

The block does not — and by design must not — assert that the inputs are true,
that nobody lied, that the source is correct, that the formula is legally
appropriate, that the dataset is scientifically valid, that the decision is
fair, that the result satisfies any regulation, or that the issuer must be
trusted by every verifier. Those live as UI/spec copy (`NOT_PROVES`), not as
positive claims, and are the reason `claims` only ever lists performed facts.

## Changelog

- **v0.2 (this change)** — additive: introduced the top-level `attestation`
  block (`type` + `claims`) with receipt types `execution` | `reproduction` |
  `review` (only `execution` emitted). Changed the signed statement content →
  golden vectors regenerated with `npm run vcc:vectors`; formula manifests and
  digests unaffected (attestation is a statement field, not a manifest field).
  No cryptography change (Ed25519 / JCS / DSSE unchanged).
