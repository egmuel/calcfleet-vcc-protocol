# ADR-002 — Numeric semantics: profile `vcc-decimal-v1`

Status: **Accepted** (2026-07-11)

## Context

Calc functions produce IEEE-754 doubles (factory convention: accumulate unrounded, `round2` at output). Raw JSON numbers are portable only if every consumer parses doubles identically, and they carry no unit/scale/rounding semantics. `6.1` could be a percent or a ratio. Certificates must be unambiguous and reproducible byte-for-byte.

## Decision

Every numeric leaf in `calculation.inputs` / `calculation.outputs` is a **typed value object**, never a bare JSON number:

```json
{ "type": "decimal", "value": "2137.50", "scale": 2, "unit": "USD" }
```

- `type`: `integer` | `decimal` | `percent` | `ratio` | `money` | `duration` — declared per field by the formula's **numeric dictionary** (part of the Formula Manifest, hence digested). `percent` means percentage points (6.1 ⇒ 6.1%); `ratio` means the dimensionless fraction (0.061). The dictionary, not the reader, decides.
- `value`: canonical decimal string: optional `-`, integer part with no leading zeros (except `0`), `.` + exactly `scale` fractional digits when `scale > 0`. **No scientific notation, ever.** Negative zero normalizes to positive zero.
- `scale`: fixed decimal places (declared per field). `unit` (and it doubles as currency for `money`, e.g. `"USD"`) present when declared.
- `roundingMode`: quantization at the statement boundary uses **half-even**, declared once in the profile; fields may override in their dictionary entry (none of the pilots do).

Conversion pipeline (no float re-entry):

1. Double → exact shortest decimal string via ECMAScript `Number::toString` (fully specified, shortest-round-trip; identical across conforming engines).
2. Exponent forms expanded, then quantization to `scale` in **BigInt** arithmetic with half-even.
3. Reject `NaN`, `Infinity`, `-Infinity`, non-numbers; reject any numeric leaf not covered by the dictionary (**fail-closed**: every certified number has declared semantics).

Statement-level numbers outside `calculation` (e.g. `scale` itself) are plain JSON integers, safe under JCS (ES serialization).

The profile is named **`vcc-decimal-v1`** in `calculation.numericProfile` and in each Formula Manifest.

## Alternatives considered

- **Bare JSON numbers + JCS**: canonical but semantically ambiguous (percent/ratio, currency, scale) and fragile the moment a non-JS verifier parses into binary floats and re-serializes differently.
- **Adopt decimal.js / big.js**: unnecessary runtime dependency; quantization of an exact decimal string needs only BigInt (stdlib). Factory rule: no deps when stdlib suffices.
- **Rewrite calc functions in decimal arithmetic**: out of scope; would silently change documented financial formulas (forbidden). The certificate certifies what the engine actually computes, with its float semantics made explicit and portable.

## Consequences

- Certificates are self-describing: every number carries type/scale/unit.
- Statement-side quantization (half-even) is a *presentation-boundary* rule and is documented as distinct from formula-internal `round2` (half-up-magnitude for positives). Golden vectors pin the exact behavior.
- Verifiers never need float math for L1; L2 re-runs the engine and re-normalizes through the same pipeline before comparing.

## Risks

- A field added to a formula's output without a dictionary entry breaks issuance (by design). CI's registry gate catches it before deploy.
- Doubles that differ but quantize to the same decimal string compare equal at L2 — intended: the declared scale defines the certified resolution.
