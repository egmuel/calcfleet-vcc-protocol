# ADR-005 — L2 reproduction: local allowlisted formulas only

Status: **Accepted** (2026-07-11)

## Context

L2 answers "does re-running the formula reproduce the outputs?". Executing anything *named by the certificate* is remote-code execution by construction. `node:vm` is not a security boundary.

## Decision

1. `reproduceVccCalculation(statement, registry)` resolves the executor **exclusively** from the local, statically-imported formula pack registry (`src/lib/vcc/formulas/`). The certificate contributes only the lookup key (`slug`, `version`) and the expected digests. Nothing from the certificate is ever evaluated, imported, fetched, or `eval`ed.
2. Pre-execution checks, each with its own result state (no conflation):
   - slug+version in local allowlist → else `formula-unavailable`;
   - statement's `formula.digest` equals the local manifest digest → else `mismatch` on `formulaDigestMatch` (report, do **not** execute);
   - numeric profile supported → else `unsupported-profile`;
   - all referenced datasets available locally with matching digests → else `dataset-unavailable` / dataset digest mismatch.
3. Execution: typed inputs from the statement are decoded to plain numbers (exact: canonical decimal string → double is round-trip-safe at declared scales), re-validated with the formula's input schema, run through the same pure calc, outputs re-normalized via `vcc-decimal-v1` + the manifest's dictionary/projection, and compared **field-by-field on canonical typed values**, producing a diff list.
4. Sandbox posture: the calcs are the repo's own pure functions (grep-verified: no net, no clock, no randomness beyond seeded PRNG); a wall-clock guard (default 2000 ms) aborts pathological runs (schema bounds make this theoretical). No network/random/clock is injectable — there is deliberately **no plugin surface**.
5. `formula-unavailable` is a *reproducibility* outcome, never an L1 (authenticity/integrity) failure. Result states: `match` | `mismatch` | `not-reproducible` | `formula-unavailable` | `dataset-unavailable` | `unsupported-profile` | `execution-failed`.

## Alternatives considered

- `node:vm` sandboxing of certificate-referenced code: explicitly forbidden by the spec (vm ≠ security boundary).
- Container/isolate execution service: right answer for third-party formulas — out of scope v0.2, extension point documented.
- WASM-compiled formulas with digest-addressed modules: promising for cross-issuer L2; deferred (P2), noted in migration plan.

## Consequences

- L2 works offline and in CI with zero infrastructure.
- Third parties can only L2-reproduce if they run our published code at the pinned version — which is exactly the trust statement L2 makes.

## Risks

- Local registry and published manifests could drift → CI gate recomputes digests from source on every push.
- Timeout enforcement for synchronous CPU-bound code is cooperative (checked between scenario runs, not preemptive); acceptable given schema-bounded inputs (documented residual risk in threat model T15).
