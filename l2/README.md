# L2 — Reproducible Calculation (standalone, offline)

This directory is a **self-contained, independently-runnable L2 verifier** for VCC
calculation statements. It exists so the "reproducible calculation" value
proposition can be demonstrated in the open — outside the private CalcFleet
monorepo — with no network, no third-party dependencies, and Python stdlib only.

## What L1 and L2 each prove

| Layer | Question it answers | Where |
|---|---|---|
| **L1** | *Is this receipt authentically signed and byte-intact?* | `verifiers/typescript`, `verifiers/python` |
| **L2** | *Do the declared outputs actually follow from the declared inputs under this formula?* | **here (`l2/`)** |

L1 is authenticity + integrity. L2 is **reproducibility**: given the statement's
inputs and a locally-installed implementation of the named formula, re-run the
deterministic calculation and check that the recomputed outputs equal the
certificate's declared outputs — field by field, on canonical typed values
(`type`, `value`, `scale`, `unit`). The two layers are independent and
complementary; a receipt can be L1-valid but L2-non-reproducible (tampered
outputs), or L2-reproducible but L1-invalid (bad signature).

## The security property: local allowlist only (ADR-005)

The single most important design decision: **the formula is resolved *only* from a
static, local allowlist** ([`registry.py`](./registry.py)), keyed by the
certificate's `(slug, version)`.

- The certificate contributes **only the lookup key**. Its `formula.registry` URL
  (or any other certificate field) is **never** fetched, imported, downloaded,
  `eval`-ed, or executed.
- Executing anything *named by the certificate* would be **remote code execution
  by construction** — a hostile certificate could point at attacker-controlled
  code and the verifier would run it. Language sandboxes (`node:vm`, etc.) are
  explicitly **not** security boundaries, so we don't rely on them; we simply never
  load foreign code.
- A `(slug, version)` not in the allowlist yields `formulaFound = false`
  (`formula-unavailable`) — a *reproducibility* outcome, never an L1
  authenticity/integrity failure. **Nothing is executed** for an unknown formula.
- There is deliberately **no plugin surface, no dynamic discovery, no network
  path**. Adding a formula is a reviewed act: add an allowlist entry and ship the
  package under `registry/<slug>/<version>/`.

Everything is offline and deterministic: arithmetic uses `decimal.Decimal` at high
working precision, values are accumulated unrounded, and quantization to the
declared scale happens **only at the output boundary** with banker's rounding
(`ROUND_HALF_EVEN`), matching the `vcc-decimal-v1` numeric profile.

## Layout

```
l2/
├── l2_verify.py        # standalone L2 verifier (never throws on hostile input)
├── registry.py         # LOCAL allowlist: (slug, version) -> local package path
├── test_l2.py          # runnable tests (reproduce / tamper / unknown / hostile)
├── README.md           # this file
└── registry/
    └── compound-interest-calculator/
        └── 1.0.0/
            ├── formula.py     # pure, deterministic compound-interest calc
            └── manifest.json  # local formula manifest (id, slug, version, I/O)
```

## How to run

```bash
cd l2
python test_l2.py          # runs the full test suite; exit 0 on success
```

Verify a single statement or vector from the CLI:

```bash
cd l2
python l2_verify.py ../vectors/compound-interest-calculator.json
# -> {"formulaFound": true, "reproduced": true, "mismatches": [], ...}  (exit 0)
```

`verify_l2(payload)` accepts either a full vector object (`{ "statement": ... }`)
or a bare statement, and returns:

```python
{
  "formulaFound": bool,   # was (slug, version) in the local allowlist?
  "reproduced":   bool,   # recomputed outputs == declared outputs (exact)?
  "mismatches":   [ ... ],# per-field diffs {path, declared, recomputed} when not
  "slug":         str | None,
  "version":      str | None,
  "error":        str | None,   # populated on malformed/hostile/unavailable input
}
```

## Worked example (the golden vector)

`vectors/compound-interest-calculator.json` — monthly compounding, contributions
at end of month (`balance = balance * (1 + annualRate/12) + monthlyContribution`):

| Inputs | | Outputs (reproduced exactly) | |
|---|---|---|---|
| initialPrincipal | `10000.00 USD` | finalBalance | `59163.80 USD` |
| monthlyContribution | `250.00 USD` | totalContributed | `40000.00 USD` |
| annualRatePct | `6.0000 %` | totalInterest | `19163.80 USD` |
| years | `10.00 years` | yearlyTable | 10 rows (yr 1 balance `13700.67`, … yr 10 `59163.80`) |

L2 re-runs the local `formula.py` on these inputs and reproduces every declared
output string bit-for-bit, including all 10 yearly-table rows.

## Honest coverage status

- **Implemented:** one reference formula end-to-end —
  `compound-interest-calculator@1.0.0`. Its L2 reproduction of the golden vector is
  proven by `test_l2.py`.
- **Not yet implemented:** local packages for the other pilot formulas
  (`personal-loan-calculator`, `home-affordability-calculator`,
  `tiered-commission-calculator`). Their vectors exist under `vectors/`, but this
  standalone L2 does **not** ship their implementations yet, so `verify_l2` returns
  `formulaFound = false` (`formula-unavailable`) for them. This is the correct,
  fail-closed behavior — never a false "reproduced" — and adding each is future
  work: drop a `registry/<slug>/<version>/formula.py` + `manifest.json` and one
  allowlist entry.
- **Manifest scope:** `manifest.json` here documents the *local* Python
  reproduction. The statement's `formula.digest` refers to CalcFleet's canonical
  (TypeScript) manifest and is **not** recomputed by this standalone L2; lookup is
  by `(slug, version)` against the local allowlist only. Cross-implementation digest
  agreement (WASM / digest-addressed modules) is a documented extension point
  (ADR-005 "Alternatives considered").

See [`adr/ADR-005-l2-reproduction.md`](../adr/ADR-005-l2-reproduction.md) for the
full L2 design and [`spec/formula-package.md`](../spec/formula-package.md) /
[`spec/formula-authoring.md`](../spec/formula-authoring.md) for the formula-package
model.
