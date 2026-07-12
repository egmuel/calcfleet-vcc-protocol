# VCC Numeric Profiles (§31.1)

Status: **Draft v0.3-track** · 2026-07-12 · Formalizes the numeric profile `vcc-decimal-v1` **already implemented and tested** (`src/lib/vcc/numeric.ts`, `docs/adr/ADR-002-numeric-semantics.md`, `spec-v0.2.md` §3) and defines the additional profiles §31.1 enumerates. Normative words (MUST/SHOULD/MUST NOT) bind conforming implementations. This document does not modify code; profiles beyond `vcc-decimal-v1` are **specified, not yet implemented**.

Source of truth for what ships today: the internal VCC standard-readiness audit (§31.1).

---

## 1. Why numeric profiles exist

A raw JSON number in a receipt is ambiguous and non-portable: `6.1` might be a percent or a ratio; a currency amount has a scale and a rounding rule the bare number does not carry; and a non-JS verifier that parses into binary floats and re-serializes will produce different bytes, breaking content addressing (ADR-002 §Context). A **numeric profile** is the named contract that removes all ambiguity: it fixes the value grammar, the type vocabulary, the rounding mode, and the forbidden values, so that every certified number is *self-describing* and *byte-reproducible*.

Every numeric leaf under `calculation.inputs`/`calculation.outputs` is a **typed value object**, never a bare number (ADR-002 §Decision):

```json
{ "type": "decimal", "value": "2137.50", "scale": 2, "unit": "EUR" }
```

`calculation.numericProfile` names the profile in force; the Formula Package Manifest's `numericDictionary` declares, per dotted field path, the `type`/`scale`/`unit` (`formula-package.md`). **Readers MUST NOT guess** type or scale — the dictionary, not the reader, decides (`spec-v0.2.md` §3).

## 2. Profile `vcc-decimal-v1` — the shipped, normative profile

Fully implemented in `src/lib/vcc/numeric.ts` and pinned by golden vectors (`numeric.test.ts`, `vectors/*.json`). This section is descriptive of what binds today.

### 2.1 Type vocabulary

`type` ∈ `integer | decimal | percent | ratio | money | duration`.

| type | meaning | unit |
|---|---|---|
| `integer` | whole number; a non-integral value at an `integer` field aborts issuance (`numeric-precision-loss`) | none |
| `decimal` | fixed-scale decimal | optional |
| `percent` | **percentage points** — `"6.10"` means 6.10% | `"%"` by convention |
| `ratio` | dimensionless fraction — `0.061` | none |
| `money` | monetary amount | ISO-4217 code, e.g. `"USD"` |
| `duration` | time span | `months` \| `years` |

`percent` vs `ratio` is **decided by the dictionary, never inferred** (this closes threat T9). String outputs (closed enums) appear as plain JSON strings; booleans as JSON booleans; anything else is rejected at issuance (`spec-v0.2.md` §3).

### 2.2 Value grammar (normalization)

`value` grammar: `-?(0|[1-9][0-9]*)(\.[0-9]{scale})?`.

- integer part has no leading zeros except the single `0`;
- the fraction is present **iff** `scale > 0` and has **exactly** `scale` digits;
- **no scientific notation, ever**;
- negative zero normalizes to positive `0` (never `-0`, never `-0.00`).

This is the canonical, byte-stable form; it is what makes JCS content addressing hold across implementations.

### 2.3 Quantization (rounding)

- Engine doubles → **exact shortest-decimal** string via ECMAScript `Number::toString` (fully specified, shortest-round-trip; `doubleToDecimalString`, `numeric.ts:28`).
- Exponent forms are expanded to plain positional notation with pure string ops (no float re-entry).
- Then quantized to the declared `scale` in **BigInt** arithmetic with **ROUND_HALF_EVEN** (`quantizeDecimalString`, `numeric.ts:69`).
- `roundingMode` is declared **once at the profile level** (half-even). The dictionary *may* override per field, but none of the pilots do (ADR-002 §Decision). See §2.6 for the reconciliation with the master's per-field example.

### 2.4 Forbidden values

- `NaN`, `+Infinity`, `-Infinity`, and non-numbers **MUST abort issuance** (`non-finite-number`; `numeric.ts:29,120`). They are never emitted, never coerced.
- **Fail-closed**: a numeric leaf with no dictionary rule aborts issuance (`numeric-rule-missing`, `numeric.ts:166`) — every certified number has declared semantics or there is no certificate.
- For `mode: "input"`, a value finer than the declared scale is **refused, not silently rounded** (`numeric-precision-loss`, `numeric.ts:132`): a receipt must never claim an input the calc did not actually use.

### 2.5 Scale bounds (the de-facto overflow rule, today)

`scale` MUST be an integer in `[0, 12]` (`quantizeDecimalString`, `numeric.ts:73`). Magnitude is otherwise bounded only implicitly by the tool's Zod input schema and the 64 KB canonical-JSON cap (ADR-006 §4). The profile itself does not yet declare a magnitude/precision ceiling — see §4 (overflow) for the normative rule proposed for the profile spec.

### 2.6 Reconciliation with the master's JSON shape

The master example (§31.1) uses `dataType` and an inline `roundingMode` per value:

```json
{ "value": "2137.50", "dataType": "decimal", "scale": 2, "unit": "EUR", "roundingMode": "half-even" }
```

The shipped shape uses `type` (not `dataType`) and declares `roundingMode` **once per profile** rather than per value (ADR-002 §Decision). These are **the same semantics in different forms**. Reconciliation is a spec/naming decision for v0.3, **not** a code change:

- keep `type` as the field name (matches `VccTypedValue`, `spec-v0.2.md`), document `dataType` as the master's alias;
- keep profile-level `roundingMode` as the default; allow per-field override in the dictionary (already supported) for the rare field that needs it. No pilot requires the inline form.

## 3. The additional profiles §31.1 enumerates (specified, not implemented)

§31.1 lists more than `vcc-decimal-v1` covers. Each is defined here as a **future normative profile or an extension of the dictionary**, with an explicit build/no-build note. None ships in v0.2.

### 3.1 `integer` — covered

Already a `type` in `vcc-decimal-v1` (scale 0, integrality enforced). No separate profile needed.

### 3.2 `currency` — covered

Realized as `type: "money"` + ISO-4217 `unit`. The master's "currency" is `money`. No separate profile; keep the ISO-4217 constraint normative.

### 3.3 `percentage` — covered

Realized as `type: "percent"` (percentage points). Distinct from `ratio` by dictionary declaration. No separate profile.

### 3.4 `rational` — **MANCANTE (new profile: `vcc-rational-v1`)**

Exact fractions with no decimal rounding, for formulas where a repeating decimal must not be quantized (e.g. exact interest fractions). Proposed leaf shape:

```json
{ "type": "rational", "numerator": "1", "denominator": "3" }
```

- both integers, canonical (denominator > 0, `gcd(num,den) = 1`, sign on numerator);
- no `scale` (exactness is the point); rounding happens only when *rendered*, and rendering is out of the certified surface.

Rationale for a separate profile, not a `vcc-decimal-v1` type: it changes the value grammar (two integers, not one decimal string) and the equality rule (fraction equality, not byte equality of a quantized string). ADR-002 deliberately excluded it; adding it is a v0.3 decision.

### 3.5 `scientific` — **MANCANTE (new profile: `vcc-scientific-v1`); default answer is "do not"**

`vcc-decimal-v1` bans scientific notation *by design* ("No scientific notation, ever", ADR-002). For quantities where positional notation is impractical (very large/small magnitudes in scientific/engineering calcs), a distinct profile could allow a canonical mantissa+exponent form:

```json
{ "type": "scientific", "mantissa": "6.022", "exponent": 23, "sigfigs": 4 }
```

with a canonical mantissa (`1 ≤ |mantissa| < 10`, exactly `sigfigs` significant digits) and integer exponent. **This is a new profile, not an extension** of `vcc-decimal-v1`; CalcFleet's financial/practical tools do not need it, so it is specified but not prioritized.

### 3.6 `date` / `day-count` — **MANCANTE (dictionary + optional profile)**

`vcc-decimal-v1`'s `duration` covers only `months|years` (`spec-v0.2.md` §3); it has **no calendar dates and no day-count conventions**. Financial formulas that depend on accrual conventions (30/360, ACT/365, ACT/ACT, ACT/360) cannot yet be certified faithfully. Proposed:

- a `date` typed value carrying an ISO-8601 **calendar date** (`"2026-07-12"`, day resolution) as a canonical string;
- a `dayCountConvention` field in the formula's numeric dictionary (one of the named conventions), digested as part of formula identity so a convention change is a version change.

This is largely a **dictionary + manifest** extension (goes in `formula-package.md`'s numeric dictionary), with a small typed-value addition — not a wholesale new profile. Required before any date-sensitive financial pilot can be certified.

### 3.7 `units` (non-monetary) — **PARZIALE**

`unit` exists on `money` (ISO-4217) and `duration` (`months|years`), but there is **no registry/vocabulary** for general units (kWh, kg, m², mi). Practical/home calculators (concrete, flooring, electricity) would need a named unit vocabulary so `unit` is validated, not free-text. Proposed: a small controlled unit vocabulary referenced by the profile, with units declared in the dictionary and digested. Additive to `vcc-decimal-v1`.

## 4. Overflow — the normative rule to add (§31.1)

`vcc-decimal-v1` today bounds only `scale ∈ [0,12]` and relies on input-schema + 64 KB caps for magnitude (§2.5). §31.1 asks for an explicit overflow rule. Proposed normative addition to the profile spec (no code change until adopted):

- declare a **maximum total significant digits** (proposal: 34, aligning with IEEE 754-2008 decimal128) and a **maximum scale** (already 12);
- a value exceeding either MUST **abort issuance** with a typed error (fail-closed, consistent with §2.4) — never wrap, never saturate, never lose precision silently;
- L2 comparison already treats "different doubles that quantize equal" as equal at the declared scale (ADR-002 §Risks) — the certified resolution *is* the scale, and overflow is a hard refusal above it.

## 5. Summary table

| §31.1 item | Profile / mechanism | Status |
|---|---|---|
| decimal | `vcc-decimal-v1` `type:"decimal"` | **FATTO** |
| integer | `vcc-decimal-v1` `type:"integer"` | **FATTO** |
| currency | `vcc-decimal-v1` `type:"money"` + ISO-4217 | **FATTO** |
| percentage | `vcc-decimal-v1` `type:"percent"` | **FATTO** |
| units (monetary/duration) | `unit` on `money`/`duration` | **FATTO** |
| units (general) | unit vocabulary | PARZIALE — no registry |
| normalization | value grammar, `-0→0`, no sci-notation | **FATTO** |
| NaN/Infinity forbidden | fail-closed abort | **FATTO** |
| rational | `vcc-rational-v1` | MANCANTE (specified) |
| scientific | `vcc-scientific-v1` (default: avoid) | MANCANTE (specified) |
| date / day-count | `date` typed value + dictionary convention | MANCANTE (specified) |
| overflow | max sig-digits + max scale, fail-closed | MANCANTE (rule proposed) |

`vcc-decimal-v1` is complete and binding; everything in §3–§4 is a *specification for v0.3+*, written so that adopting it is an additive, digest-versioned change — never a silent reinterpretation of existing receipts.
