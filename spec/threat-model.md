# VCC Threat Model

**Who this is for.** Security reviewers, integrators deciding how much weight to put on a CalcFleet certificate, and the operator prioritizing hardening work. Each threat below names the asset, the attacker, the vector, the impact, the mitigation (with the ADR or mechanism that implements it), the residual risk, and a status: **mitigated**, **accepted** (known residual, deliberately carried), or **open-P1** (real gap, scheduled). Out of scope here — because they are not security properties of the format: whether inputs are truthful, and whether a formula is appropriate for a purpose ([spec §1](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not)).

Assets, in rough order of blast radius: the signing key; certificate integrity; formula identity; the verifier's machine (L2 runs code); requester privacy; the issuer's honesty being checkable.

## Index

| # | Threat | Primary asset | Status |
|---|---|---|---|
| T1 | Certificate tampering | Certificate integrity | mitigated |
| T2 | Signing-key theft via env compromise | Signing key | **open-P1** (KMS) |
| T3 | Signing with the wrong formula or version | Formula identity | mitigated |
| T4 | Formula changed without a version bump | Formula identity | mitigated |
| T5 | Dataset substitution | Formula identity | mitigated |
| T6 | Replay of a valid certificate in a misleading context | Relying parties | accepted |
| T7 | Duplicate or parallel issuance | Store integrity | mitigated |
| T8 | Statement-ID logical collision | Certificate identity | mitigated |
| T9 | Numeric ambiguity | Meaning of results | mitigated |
| T10 | Version downgrade presentation | Relying parties | mitigated |
| T11 | Unknown-algorithm confusion | Verification soundness | mitigated |
| T12 | Compromised key discovery / cache poisoning | Trust root | mitigated |
| T13 | PII injection | Requester privacy | mitigated |
| T14 | DoS on issuance or verification | Availability | mitigated |
| T15 | Oversized certificates | Verifier resources | accepted |
| T16 | Malicious formula execution via certificate | Verifier's machine | mitigated (by construction) |
| T17 | Supply-chain compromise | Formula identity, key | **open-P1** (transitive digests) |
| T18 | Dependency drift changing results | Reproducibility | accepted |
| T19 | False compliance claims by third parties | Relying parties | accepted |
| T20 | Private key in bundle or logs | Signing key | mitigated |
| T21 | Operator store rollback | Issuer accountability | accepted |

## Threats

### T1 — Certificate tampering

**Asset** certificate integrity. **Attacker** anyone relaying a certificate. **Vector** edit statement fields (outputs, version, `issuedAt`) after issuance. **Impact** forged claims under CalcFleet's signature. **Mitigation** DSSE Ed25519 over the PAE of the JCS-canonical payload, plus the content-addressed `subject.id` recomputed at L1 ([spec §4–5](./spec-v0.2.md#4-canonicalization--content-addressing), [ADR-001](../adr/ADR-001-vcc-envelope.md)); any byte change breaks both the signature and the id, and verifiers derive the statement from `payload`, never from a sibling object. **Residual** the strength of Ed25519/SHA-256. **Status** mitigated.

### T2 — Signing-key theft via env compromise

**Asset** the signing key. **Attacker** anyone who reads the Vercel production env (platform breach, token leak, malicious integration). **Vector** exfiltrate `VCC_SIGNING_KEY`; sign arbitrary statements offline. **Impact** certificates indistinguishable from genuine ones until the key is flagged. **Mitigation** status `compromised` propagates ≤ 1 h via the keyset cache ([ADR-004](../adr/ADR-004-key-management.md)); certificate status `issuer-key-compromised` for the affected window; small blast radius (only pilot formulas certifiable); the [compromise procedure](./key-rotation.md#compromise-procedure). **Residual** the env remains a single point of compromise until a KMS/HSM signer is wired — the interface and stub exist (`src/lib/vcc/keys.ts`). **Status** **open-P1** (KMS adapter before any enterprise reliance).

### T3 — Signing with the wrong formula or version

**Asset** formula identity. **Attacker** none required — this is an integrity bug class. **Vector** issuance binds a statement to a manifest that does not describe the code that ran. **Impact** certificates attesting the wrong computation. **Mitigation** the statement carries the manifest digest resolved from the committed registry; issuance fails on `manifest-drift`/`digest-mismatch` ([issuer guide](./issuer-guide.md#what-gets-refused)); L2 compares the statement digest to the local manifest **before** executing ([ADR-005](../adr/ADR-005-l2-reproduction.md)). **Residual** none identified beyond T4. **Status** mitigated.

### T4 — Formula changed without a version bump

**Asset** formula identity. **Attacker** a careless (or pressured) maintainer. **Vector** edit `calc.ts`, schemas, dictionary or projection and ship under the same version. **Impact** "version 1.0.0" silently meaning two different computations — the exact failure VCC exists to prevent. **Mitigation** the CI drift gate `npm run vcc:registry:verify` recomputes every digest from source on every push; same slug+version with different digests fails the build ([ADR-003](../adr/ADR-003-formula-identity.md)). **Residual** an attacker who can merge to main *and* alter CI — that is repository compromise, T17's territory. **Status** mitigated.

### T5 — Dataset substitution

**Asset** formula identity (data half). **Attacker** operator error or a poisoned data update. **Vector** change dataset contents without a vintage bump, or run L2 against different data. **Impact** certified results that silently depend on other numbers. **Mitigation** dataset manifests are digested (JCS of the exact exports the calcs import, `src/lib/vcc/datasets.ts`); statements carry the digest; L2 refuses on mismatch (`dataset-unavailable`) ([ADR-005](../adr/ADR-005-l2-reproduction.md)); CI fails when the snapshot drifts without a vintage bump. Today no dataset-reading formula is certifiable at all (gated off, [spec §9](./spec-v0.2.md#9-non-goals--extension-points-v02)). **Residual** none while gated; the machinery is exercised before wave 2. **Status** mitigated.

### T6 — Replay of a valid certificate in a misleading context

**Asset** relying parties' judgment. **Attacker** whoever presents the certificate. **Vector** take a genuine certificate ("loan X costs Y") and present it as evidence for a different claim, a different person, or a current fact years later. **Impact** true math, false narrative. **Mitigation** a VCC binds calculation + issuance time (`issuedAt` is inside the signed, id-covered bytes) — it never binds the presenter's claims; the limits text everywhere states this, and the four-axis result resists "verified ⇒ true" readings ([spec §1](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not)). **Residual** inherent to any portable receipt: the format cannot police the sentence uttered next to it. Relying parties must read the statement, not the presenter's summary. **Status** accepted.

### T7 — Duplicate or parallel issuance

**Asset** store integrity. **Attacker** none required — concurrency and retries. **Vector** the same calculation certified twice, racing writes to the same id. **Impact** conflicting stored artifacts. **Mitigation** ids are content-addressed, and the store is idempotent: `put` with identical bytes ⇒ `already-exists`; different bytes at the same id ⇒ hard error, logged as corruption/collision, never a silent overwrite ([ADR-006](../adr/ADR-006-certificate-storage.md)). Re-certifying the same inputs later yields a *different* id by design (`issuedAt` is covered) — parallel issuance is not an anomaly, just two receipts. **Residual** none identified. **Status** mitigated.

### T8 — Statement-ID logical collision

**Asset** certificate identity. **Attacker** someone crafting a statement whose id equals another's. **Vector** exploit canonicalization ambiguity (key order, number formats, Unicode) to make two semantically different statements canonicalize identically, or find a hash collision. **Impact** id-based lookups serving the wrong certificate. **Mitigation** RFC 8785 (JCS) leaves no serialization freedom — one statement, one byte sequence ([spec §4](./spec-v0.2.md#4-canonicalization--content-addressing)); the id is SHA-256 over those bytes; the store treats different-bytes-at-same-id as a hard error and logs it as an attempted collision ([ADR-006](../adr/ADR-006-certificate-storage.md)). **Residual** SHA-256 collision resistance. **Status** mitigated.

### T9 — Numeric ambiguity

**Asset** the meaning of results. **Attacker** none required; also exploitable for misrepresentation. **Vector** the classic traps: is `6.1` a percent or a ratio? Is `-0` zero? Does `1e2` equal `100`? Locale decimal commas? **Impact** the same certified bytes read as different quantities by different consumers. **Mitigation** killed by `vcc-decimal-v1` ([ADR-002](../adr/ADR-002-numeric-semantics.md), [spec §3](./spec-v0.2.md#3-numeric-profile-vcc-decimal-v1)): every numeric leaf is a typed value with a canonical decimal grammar — no exponents, `-0` normalized to `0`, exact scale — and the manifest's numeric dictionary declares percent vs. ratio; readers MUST NOT guess. Non-finite numbers abort issuance. **Residual** none identified. **Status** mitigated.

### T10 — Version downgrade presentation

**Asset** relying parties. **Attacker** a presenter holding an old certificate. **Vector** present a certificate issued against formula version 1.0.0 as if it reflected today's 1.2.0 behavior. **Impact** decisions based on superseded semantics. **Mitigation** the version and manifest digest are inside the signed statement — a certificate cannot *claim* a different version than it was issued for; per-version manifests are public and immutable (`/vcc/registry/{slug}/{version}`, [ADR-003](../adr/ADR-003-formula-identity.md)); L2 pins the exact version; the store can mark old certificates `superseded` ([verifier guide](./verifier-guide.md#certificate-status-semantics)). **Residual** a consumer who ignores the version field they are shown — a presentation-layer duty verifier UIs carry. **Status** mitigated.

### T11 — Unknown-algorithm confusion

**Asset** verification soundness. **Attacker** a certificate forger. **Vector** the classic JWT `alg` family of attacks: smuggle `none`, an HMAC downgrade, or an attacker-chosen algorithm into verification. **Impact** signature checks that pass without proving anything. **Mitigation** there is no algorithm field to negotiate in the envelope; verification requires the keyset entry's `algorithm` to be the strict literal `ed25519` — no fallback, no negotiation ([verifier guide](./verifier-guide.md#offline-l1-recipe), step 7; [ADR-004](../adr/ADR-004-key-management.md)). Anything else fails. **Residual** none identified. **Status** mitigated.

### T12 — Compromised key discovery / cache poisoning

**Asset** the trust root. **Attacker** a network position or cache-layer attacker. **Vector** serve a forged `/.well-known/vcc-issuer.json` so victims trust attacker keys. **Impact** forged certificates verify for poisoned clients. **Mitigation** the keyset is served only over TLS with HSTS (site-wide security headers); the 1-hour cache bounds poisoning persistence at the CDN layer; the documented verifier posture is **fetch once over TLS, pin, verify offline** — a pinned verifier is immune to fetch-time attacks entirely ([verifier guide](./verifier-guide.md#offline-l1-recipe)); the committed keyset in the public repo is an independent cross-check. **Residual** a verifier that re-fetches over a compromised channel at verification time; their pin discipline is their risk to manage. **Status** mitigated.

### T13 — PII injection

**Asset** requester privacy. **Attacker** a probing client, a buggy integration, or a future careless formula. **Vector** get personal data into a signed, shareable certificate — via input values, context fields, or new statement fields. **Impact** PII laundered into a document designed to be posted publicly. **Mitigation** three fail-closed layers ([ADR-007](../adr/ADR-007-privacy-model.md)): certifiable formulas accept only numeric/boolean/closed-enum inputs; the strict statement schema rejects unknown fields anywhere; the privacy guard rejects forbidden key names and PII-shaped values (email/IP/phone/JWT patterns, unexpected URLs, free text > 200 chars) on the complete statement before signing. Violation ⇒ `privacy-rejected`, no certificate, calc unaffected. **Residual** numeric inputs can be sensitive in context — even without a name or email, a VCC is a bearer document carrying every declared numeric input in the clear (amounts, income, age, medical figures), and there is no selective disclosure, redaction, or encryption yet; treating a VCC as potentially sensitive and choosing when to share it is a disclosure decision that belongs to the user ([privacy profiles](./privacy-profiles.md)). **Status** mitigated.

### T14 — DoS on issuance or verification

**Asset** availability. **Attacker** anyone with a request loop. **Vector** flood `certify=1` or `POST /api/v1/verify` (deliberately unauthenticated), or send pathological payloads. **Impact** burned compute, degraded service. **Mitigation** per-IP rate limits on the verify endpoint and the existing API gates on tool routes; a 256 KB request-body cap and bounded envelope-unwrap depth in the verify route; strict schemas bound structure; the 64 KB certificate cap ([ADR-006](../adr/ADR-006-certificate-storage.md)) and the L2 wall-clock guard bound per-request work; `maxDuration` caps function runtime. Verification is also *designed* to move off-server: offline L1 costs CalcFleet nothing. **Residual** rate-limit tuning under real load is untested (tracked P1 in the implementation plan). **Status** mitigated.

### T15 — Oversized certificates

**Asset** verifier resources. **Attacker** a hostile issuer or forger targeting third-party verifiers. **Vector** feed enormous or degenerate envelopes to verification code. **Impact** memory/CPU exhaustion in verifiers. **Mitigation** the 64 KB canonical-size cap on issued/stored certificates; strict, padded standard base64 (non-canonical encodings rejected); strict statement schema; the L2 wall-clock guard (2000 ms). **Residual — accepted**: the L2 timeout is *cooperative* (checked between runs, not preemptive) because synchronous CPU-bound JS cannot be preempted; schema-bounded inputs make a pathological run theoretical ([ADR-005](../adr/ADR-005-l2-reproduction.md)). **Status** accepted.

### T16 — Malicious formula execution via certificate

**Asset** the verifier's machine. **Attacker** a crafted certificate. **Vector** get the verifier to execute attacker-chosen code during L2 — by naming a module, URL, or blob to run. **Impact** remote code execution. **Mitigation** impossible by construction: L2 resolves executors **exclusively** from the local, statically-imported allowlist (`src/lib/vcc/formulas/index.ts`); the certificate contributes only a lookup key (slug, version) and expected digests; nothing from a certificate is ever evaluated, imported, fetched, or `eval`ed, and there is deliberately no plugin surface ([ADR-005](../adr/ADR-005-l2-reproduction.md)). Unknown slug+version ⇒ `formula-unavailable`, not execution. **Residual** none — the vector does not exist in this design. **Status** mitigated (by construction).

### T17 — Supply-chain compromise

**Asset** formula identity and, transitively, everything the build touches. **Attacker** a compromised dependency or registry. **Vector** malicious package version alters calc behavior, canonicalization, or exfiltrates the env at build/run time. **Impact** wrong results certified as right; possible key theft (feeds T2). **Mitigation** `npm ci` against the committed lockfile everywhere including CI; the VCC core deliberately adds **zero runtime dependencies** (Ed25519 via `node:crypto`); direct deps (zod) are pinned in formula manifests with the locked version from `package-lock.json` and cross-checked by the CI gate ([ADR-003](../adr/ADR-003-formula-identity.md)). **Residual** transitive dependencies are not digested into formula identity — full lockfile-slice digesting is the gap. **Status** **open-P1**.

### T18 — Dependency drift changing results

**Asset** reproducibility. **Attacker** none — entropy. **Vector** a legitimate dependency upgrade (e.g. zod parsing/coercion nuances) changes validated inputs or outputs while calc source — and therefore the manifest digest — stays identical. **Impact** L2 `mismatch` between certificates issued before and after the upgrade; semantic drift under a stable version. **Mitigation** direct dependency versions recorded in manifests for review ([ADR-003](../adr/ADR-003-formula-identity.md)); golden vectors and the 2300+ test baseline run on every push, so a behavior change surfaces as test failures before deploy; upgrades that change behavior warrant version bumps. **Residual** shares T17's gap — transitive drift is reviewable but not digested. **Status** accepted (residual tracked under T17's open-P1).

### T19 — False compliance claims by third parties

**Asset** relying parties; CalcFleet's name. **Attacker** whoever brandishes a certificate. **Vector** "this is CalcFleet-certified, therefore audited / regulator-approved / financial advice you can rely on." **Impact** misplaced reliance the format never promised. **Mitigation** the limits text everywhere — spec ([§1](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not)), quickstart, verify page — states what a VCC is not; interfaces are forbidden to collapse the axes into one "verified" boolean, which is the badge such claims feed on. **Residual** speech cannot be technically prevented; the countermeasure is that the artifact itself, read honestly, contradicts the claim. **Status** accepted.

### T20 — Private key in bundle or logs

**Asset** the signing key. **Attacker** anyone reading public assets or log storage. **Vector** the key leaks into the client JS bundle, build output, or application logs. **Impact** silent key compromise (becomes T2 without the telemetry). **Mitigation** key material is touched only in server-only modules; CI greps `.next/static` for `VCC_SIGNING_KEY` on every build and fails on a hit (`.github/workflows/ci.yml`); the logging policy forbids private keys, full signatures, and payloads — key **id**, sizes, and failure codes only ([ADR-004](../adr/ADR-004-key-management.md), [issuer guide](./issuer-guide.md#observability)); the keygen script prints once and writes nothing. **Residual** platform-level log capture outside the app's control — part of T2's env-trust problem. **Status** mitigated.

### T21 — Operator store rollback

**Asset** issuer accountability. **Attacker** the operator (or whoever controls the KV) — the honest-issuer assumption inverted. **Vector** delete or rewrite stored certificates/statuses to unmake inconvenient history. **Impact** the public record no longer shows what was issued. **Mitigation — and honest limitation**: append-only is an *application* invariant, not a storage guarantee; KV is operator-mutable, and the store is deliberately **not** a transparency log ([ADR-006](../adr/ADR-006-certificate-storage.md)). What bounds the damage: certificates are self-contained and verify offline, so copies held by users keep proving issuance regardless of the store; deletion can hide, but cannot forge. A real transparency log (git-committed certificate log, external RFC 3161 timestamping) is the documented extension point ([spec §9](./spec-v0.2.md#9-non-goals--extension-points-v02)). **Residual** full — within the stated trust model. **Status** accepted (extension point, P2).

## Reading this catalogue

The two **open-P1** items share a root: v0.2 trusts its platform (Vercel env, npm's transitive graph) more than an enterprise-grade issuer should. Both have their seams already in place — the `VccSigner` interface for KMS, the manifest `dependencies` field for lockfile-slice digests — so closing them changes wiring, not format. Everything marked **accepted** is a limitation the documentation states out loud rather than papers over; if a residual risk here surprises a relying party, that is a documentation bug — report it.
