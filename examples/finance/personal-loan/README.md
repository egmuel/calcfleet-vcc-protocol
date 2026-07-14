# Personal loan — a quote that has to survive the paperwork

## The scenario

A borrower is quoted a **$20,000** loan at **7.5%** nominal over **60 months**
with a **1%** origination fee. The lender's letter says the monthly payment is
**$400.76** and the *effective* APR — the rate after the fee is priced in — is
**7.92%**, not 7.5%. When the borrower challenges the quote later, the question
is which amortization formula produced these numbers. `receipt.json` pins
`personal-loan-calculator@1.0.0` to these inputs and outputs.

Certified outputs: `monthlyPayment = 400.76 USD`, `totalInterest = 4045.54 USD`,
`totalPaid = 24045.54 USD`, `originationFee = 200.00 USD`,
`nominalAprPct = 7.5000 %`, `effectiveAprPct = 7.9200 %`.

## Verify (offline, both verifiers)

From the repository root (one-time setups in
[`../../README.md`](../../README.md)):

```bash
node examples/verify-receipt.mjs \
  examples/finance/personal-loan/receipt.json vectors/test-key.json
```

```bash
verifiers/python/.venv/bin/python examples/verify_receipt.py \
  examples/finance/personal-loan/receipt.json vectors/test-key.json
```

Expected: all axes true, exactly as in the
[commissions example](../../commissions/tiered-commission/README.md) —
`signatureValid`, `statementIntact`, `cryptographicValidity`,
`trustedAtVerificationTime` all `true`, `certificateStatus: unknown` (offline).

## Break it

This time corrupt the **signature** instead of the payload — one character:

```bash
python3 - <<'EOF'
import json
r = json.load(open("examples/finance/personal-loan/receipt.json"))
sig = r["envelope"]["signatures"][0]["sig"]
r["envelope"]["signatures"][0]["sig"] = sig[:-3] + ("A" if sig[-3] != "A" else "B") + sig[-2:]
json.dump(r, open("receipt.badsig.json", "w"), indent=2)
print("wrote receipt.badsig.json with one corrupted signature character")
EOF

node examples/verify-receipt.mjs receipt.badsig.json vectors/test-key.json
```

Actual output:

```
axes:
  signatureValid            : false
  statementIntact           : true
  issuerIdentityBound       : true
  keyValidAtIssuance        : true
  issuerKeyStatus           : active
  certificateStatus         : unknown
  cryptographicValidity     : false
  trustedAtVerificationTime : false
checks: {"envelopeSchema":true,"payloadType":true,"payloadDecodes":true,"statementSchema":true,"canonicalization":true,"statementId":true,"keyKnown":true,"algorithmSupported":true,"signature":false}
errors: ["an Ed25519 signature does not verify"]
```

Which axis fell, and why: only `signatureValid`. `statementIntact` stays
**true** — the statement really is untampered; it is the *attribution* that
failed. This is precisely why VCC never collapses verification into one
boolean: "the numbers are intact but the signature doesn't verify" and "the
signature is fine but the numbers were edited" are different situations that
demand different responses. Clean up with `rm receipt.badsig.json`.

## What this receipt does NOT prove

It does not prove the borrower qualifies, that 7.5% was the right rate to
offer, or that the loan is suitable — only that this formula version, on these
declared inputs, produced these outputs. Signed with the public test key, it
proves nothing about any real lender. L2 note: `personal-loan-calculator` is
not yet in the standalone [`l2/`](../../../l2/) allowlist, so reproduction
fails closed as `formula-unavailable`.
