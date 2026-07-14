# Home affordability — why the envelope is the certificate

## The scenario

A buyer earning **$8,000/month gross**, with **$500/month** of other debts and
**$60,000** down, asks what house they can afford at **6.5%** over **30
years**, under standard **28% / 36%** DTI limits. The broker's answer: a
maximum payment of **$2,240** (front-end constrained), supporting a
**$354,392.24** loan and a **$414,392.24** price. When that ceiling is later
questioned, `receipt.json` pins `home-affordability-calculator@1.0.0` to
exactly these inputs, limits and outputs.

Certified outputs: `maxFrontEndPayment = 2240.00 USD`,
`maxBackEndPayment = 2380.00 USD`, `maxPayment = 2240.00 USD` (binding
constraint: front-end), `maxLoan = 354392.24 USD`, `maxPrice = 414392.24 USD`.

## Verify (offline, both verifiers)

From the repository root (one-time setups in
[`../../README.md`](../../README.md)):

```bash
node examples/verify-receipt.mjs \
  examples/housing/home-affordability/receipt.json vectors/test-key.json
```

```bash
verifiers/python/.venv/bin/python examples/verify_receipt.py \
  examples/housing/home-affordability/receipt.json vectors/test-key.json
```

Expected: all axes true, exactly as in the
[commissions example](../../commissions/tiered-commission/README.md).

## Break it — the lesson this example exists for

Edit the **human-readable `statement` view** — inflate `maxPrice` to a million
dollars — and *don't* touch the envelope:

```bash
python3 - <<'EOF'
import json
r = json.load(open("examples/housing/home-affordability/receipt.json"))
r["statement"]["calculation"]["outputs"]["maxPrice"]["value"] = "999999.99"
json.dump(r, open("receipt.view-tampered.json", "w"), indent=2)
print("wrote receipt.view-tampered.json with maxPrice edited ONLY in the convenience view")
EOF

node examples/verify-receipt.mjs receipt.view-tampered.json vectors/test-key.json
```

Actual output:

```
axes:
  signatureValid            : true
  statementIntact           : true
  issuerIdentityBound       : true
  keyValidAtIssuance        : true
  issuerKeyStatus           : active
  certificateStatus         : unknown
  cryptographicValidity     : true
  trustedAtVerificationTime : true
checks: {"envelopeSchema":true,"payloadType":true,"payloadDecodes":true,"statementSchema":true,"canonicalization":true,"statementId":true,"keyKnown":true,"algorithmSupported":true,"signature":true}
```

**Everything still passes — and that is correct.** The `statement` field in a
receipt file is a parsed convenience view for humans; the signed truth is the
base64 `envelope.payload`, and conformant verifiers derive the statement from
it, ignoring the view entirely
([ADR-001](../../../adr/ADR-001-vcc-envelope.md)). The operational rule this
teaches: **never read numbers from the convenience view — decode them from the
verified payload.** Any consumer that displays the view without re-deriving it
can be lied to while the certificate stays valid. (Tamper the *payload* instead
and `statementId` + `signature` fall — see the
[commissions example](../../commissions/tiered-commission/README.md).) Clean up
with `rm receipt.view-tampered.json`.

## What this receipt does NOT prove

It does not prove the buyer's income or debts are real, that a lender would
approve this loan, or that 28/36 are the right limits for them — only that
these outputs follow from these declared inputs under
`home-affordability-calculator@1.0.0`. It is signed with the public test key,
so it proves mechanics, not the world. L2 note: this formula is not yet in the
standalone [`l2/`](../../../l2/) allowlist, so reproduction fails closed as
`formula-unavailable`.
