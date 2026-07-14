# Compound interest — the full story: verify AND reproduce

## The scenario

A saver puts down **$10,000**, adds **$250/month** for **10 years** at **6%**
annual, compounded monthly, contributions at end of month. The projection says
**$59,163.80**. Two years from now, with the original tool long since
redeployed, can anyone still show that number follows from those inputs?
`receipt.json` pins `compound-interest-calculator@1.0.0` — and this is the one
formula the standalone [`l2/`](../../../l2/) registry implements, so you can
go beyond signature checking and **re-run the math locally**.

Certified outputs: `finalBalance = 59163.80 USD`,
`totalContributed = 40000.00 USD`, `totalInterest = 19163.80 USD`, plus a
10-row `yearlyTable` (year 1: `13700.67`, … year 10: `59163.80`).

## Verify (L1, offline, both verifiers)

From the repository root (one-time setups in
[`../../README.md`](../../README.md)):

```bash
node examples/verify-receipt.mjs \
  examples/finance/compound-interest/receipt.json vectors/test-key.json
```

```bash
verifiers/python/.venv/bin/python examples/verify_receipt.py \
  examples/finance/compound-interest/receipt.json vectors/test-key.json
```

Expected: all axes true (`signatureValid`, `statementIntact`,
`cryptographicValidity`, `trustedAtVerificationTime`), exactly as in the
[commissions example](../../commissions/tiered-commission/README.md).

## Reproduce (L2, offline, Python stdlib only)

```bash
python3 l2/l2_verify.py examples/finance/compound-interest/receipt.json
```

Actual output:

```json
{
  "formulaFound": true,
  "reproduced": true,
  "mismatches": [],
  "slug": "compound-interest-calculator",
  "version": "1.0.0",
  "error": null
}
```

L2 re-executed the locally-installed formula (`l2/registry/…/formula.py` —
resolved **only** from the local allowlist; nothing named by the receipt is
ever fetched or executed, see ADR-005) on the receipt's inputs, and every
declared output matched bit-for-bit, including all 10 yearly-table rows.

## Break it (L2 edition)

Move the declared final balance by **one cent** and re-run reproduction:

```bash
python3 - <<'EOF'
import json
r = json.load(open("examples/finance/compound-interest/receipt.json"))
r["statement"]["calculation"]["outputs"]["finalBalance"]["value"] = "59163.81"  # one cent off
json.dump(r, open("receipt.l2-tampered.json", "w"), indent=2)
print("wrote receipt.l2-tampered.json with finalBalance 59163.80 -> 59163.81")
EOF

python3 l2/l2_verify.py receipt.l2-tampered.json
```

Actual output:

```json
{
  "formulaFound": true,
  "reproduced": false,
  "mismatches": [
    {
      "path": "outputs.finalBalance",
      "declared":   { "type": "money", "value": "59163.81", "scale": 2, "unit": "USD" },
      "recomputed": { "type": "money", "value": "59163.80", "scale": 2, "unit": "USD" }
    }
  ],
  "slug": "compound-interest-calculator",
  "version": "1.0.0",
  "error": null
}
```

Which axis fell, and why: this is the **reproducibility** axis, independent of
L1 — the dispute stops being an argument and becomes a field-level diff. (Note
that this edit touched only the convenience-view `statement`, so L1 on the
envelope would still pass; L1 and L2 answer different questions, and that is
the point.) Clean up with `rm receipt.l2-tampered.json`.

## What this receipt does NOT prove

It does not prove the saver will actually earn 6% for ten years, or that
monthly compounding is the right model for any real account — only that these
outputs follow from these inputs under `compound-interest-calculator@1.0.0`.
Input truth and model suitability are explicitly out of scope
([`../../../spec/assurance-model.md`](../../../spec/assurance-model.md)); it is
signed with the public test key, so it attests mechanics, not the world.
