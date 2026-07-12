# @calcfleet/vcc-verifier — TypeScript (independent, offline)

A **standalone** Verifiable Calculation Certificate (VCC v0.2) **L1 verifier**,
in TypeScript. It runs on **Node 22+ and in the browser** on Web Platform crypto
(`crypto.subtle`), so anyone can verify a receipt **offline**.

- **Offline by design** (spec §49 vendor-independence). It makes **no network
  calls** and imports **no CalcFleet site code** (nothing from `src/app`,
  `src/tools`, or `@/…`): the JCS canonicalizer, the strict schemas, the DSSE
  PAE, and the L1 logic are all vendored inside `src/` here. The caller supplies
  the issuer keyset (from the published `/.well-known/vcc-issuer.json` or the
  committed `vectors/test-key.json`).
- **Reference:** the site's `src/lib/vcc/verify-l1.ts` stays authoritative; this
  package is adapted from `src/lib/vcc/verify-client.ts` (the browser L1) and is
  the TypeScript peer of `sdk/python/`. Its job is to give the **same L1 result
  on every conformance vector** as the reference.

## What L1 checks

The same nine per-check booleans the reference reports:

| # | check | meaning |
|---|-------|---------|
| 1 | `envelopeSchema` | DSSE envelope shape, strict (no extra keys) |
| 2 | `payloadType` | bound to `application/vnd.vcc.statement+json;version=0.2` |
| 3 | `payloadDecodes` | strict standard base64 within the 64 KiB cap |
| 4 | `statementSchema` | v0.2 statement shape, strict |
| 5 | `canonicalization` | payload bytes **are** the JCS (RFC 8785) form of the statement |
| 6 | `statementId` | `subject.id` == sha-256 of the statement **without** `subject.id` |
| 7 | `keyKnown` | signature `keyid` is in the supplied keyset |
| 8 | `algorithmSupported` | key algorithm is `ed25519` |
| 9 | `signature` | Ed25519 verifies over the DSSE PAE |

It projects the two orthogonal axes exactly as the reference does:
`signatureValid` (axis 1) and `statementIntact` (axes 3–6), plus
`trustedAtVerificationTime` (crypto valid **and** key `active` **and**
certificate status `valid`/`unknown`). It never throws on untrusted input —
every outcome is a `VccL1VerificationResult` with the per-check booleans and an
`errors` list.

## Dependencies

Node 22+ (for `crypto.subtle` Ed25519 and native TypeScript stripping) and a
single runtime dependency, **`zod`** (pinned to `4.4.3`, matching the site) for
strict schema validation. `typescript` and `@types/node` are dev-only.

```bash
npm install
```

## Run

```bash
# Cross-language conformance: this verifier's result vs the pinned reference
# outcome on the committed corpus (../../src/lib/vcc/vectors/). Exit 0 iff all
# vectors match. Type-checks first, then runs the runner.
npm run conformance

# Type-check / emit the library only.
npm run build
```

The conformance runner reads the corpus at a path **relative to this package**
(`../../src/lib/vcc/vectors`), so it works from a checkout of the protocol repo.
It requires no build step: it strips types at runtime via `node
--experimental-strip-types`.

## Use as a library

```ts
import { verifyVccEnvelope } from "@calcfleet/vcc-verifier";

const envelope = JSON.parse(await readFile("certificate.json", "utf8")); // DSSE envelope
const keyset = JSON.parse(await readFile("vcc-issuer.json", "utf8")).keyset; // published keyset

const res = await verifyVccEnvelope(envelope, keyset);
console.log(res.cryptographicValidity, res.trustedAtVerificationTime);
console.log(res.checks); // per-axis booleans
console.log(res.errors); // human-readable failures, if any
```

An optional `{ certificateStatus }` third argument feeds the trust projection
(`valid` / `withdrawn` / …) exactly as the reference does; omit it and the status
is treated as `unknown`.

## Files

- `src/verify.ts` — the L1 verifier: strict base64, DSSE PAE, Ed25519 via
  WebCrypto, sha-256 identity, and the L1 result projection.
- `src/canonicalize.ts` — RFC 8785 (JCS) canonicalization.
- `src/schemas.ts` — the strict Zod schemas (`envelopeSchema`, `statementSchema`,
  `issuerKeySetSchema`).
- `src/constants.ts`, `src/types.ts` — the frozen v0.2 constants and shapes.
- `src/index.ts` — public entry point.
- `conformance-runner.ts` — loads the repo corpus and asserts result == pinned
  reference outcome on every positive and negative vector, plus JCS byte-parity.
