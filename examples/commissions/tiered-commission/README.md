# Tiered commission — a disputed payout

## The scenario

A sales rep closed **$84,300** in Q2 revenue. The comp plan pays **5%** up to a
**$25,000** threshold and **7%** above it, minus a **$250** clawback
adjustment. Finance pays **$5,151.00 net**; the rep's own spreadsheet says the
number should be higher. Six months later nobody can say which version of the
plan was applied — this is the dispute `receipt.json` exists to end: it pins
`tiered-commission-calculator@1.2.0` (by version *and* digest) to these exact
inputs and outputs, signed at issuance time.

Certified outputs: `grossCommission = 5401.00 USD`, `adjustment = -250.00 USD`,
`netCommission = 5151.00 USD`, `effectiveRatePct = 6.1100 %`.

## Verify (offline, both verifiers)

From the repository root. TypeScript (one-time build:
`cd verifiers/typescript && npm ci && npm run build`):

```bash
node examples/verify-receipt.mjs \
  examples/commissions/tiered-commission/receipt.json vectors/test-key.json
```

Python (one-time setup: `python3 -m venv verifiers/python/.venv &&
verifiers/python/.venv/bin/pip install -r verifiers/python/requirements.txt`):

```bash
verifiers/python/.venv/bin/python examples/verify_receipt.py \
  examples/commissions/tiered-commission/receipt.json vectors/test-key.json
```

Expected output (TypeScript; the Python verifier prints the same axes):

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

Note the axes: there is no single `verified` boolean. `certificateStatus` is
`unknown` because offline verification has no revocation-store access — that is
reported honestly, not hidden.

## Break it

Give the rep the raise inside the signed payload — change `netCommission` from
`5151.00` to `6151.00` and re-encode:

```bash
python3 - <<'EOF'
import base64, json
r = json.load(open("examples/commissions/tiered-commission/receipt.json"))
st = json.loads(base64.b64decode(r["envelope"]["payload"]))
st["calculation"]["outputs"]["netCommission"]["value"] = "6151.00"   # was 5151.00
r["envelope"]["payload"] = base64.b64encode(
    json.dumps(st, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
).decode()
json.dump(r, open("receipt.tampered.json", "w"), indent=2)
print("wrote receipt.tampered.json with netCommission 5151.00 -> 6151.00")
EOF

node examples/verify-receipt.mjs receipt.tampered.json vectors/test-key.json
```

Actual output:

```
axes:
  signatureValid            : false
  statementIntact           : false
  issuerIdentityBound       : true
  keyValidAtIssuance        : true
  issuerKeyStatus           : active
  certificateStatus         : unknown
  cryptographicValidity     : false
  trustedAtVerificationTime : false
checks: {"envelopeSchema":true,"payloadType":true,"payloadDecodes":true,"statementSchema":true,"canonicalization":true,"statementId":false,"keyKnown":true,"algorithmSupported":true,"signature":false}
errors: ["subject.id does not match the statement content","an Ed25519 signature does not verify"]
```

Which axes fell, and why: the tampered statement is still perfectly
well-formed JSON — `statementSchema` and even `canonicalization` stay `true`.
What catches the edit is content addressing (`statementId`: the statement no
longer hashes to its own `subject.id`) and the Ed25519 `signature`. Both
verifiers (TS and Python) report the identical failure. Clean up with
`rm receipt.tampered.json`.

## What this receipt does NOT prove

It does **not** prove the $84,300 revenue figure is true — only that this
formula version ran on that declared figure. Input truth is out of scope for
an execution receipt (input *provenance* is a designed, future layer — see
[`../../../ROADMAP.md`](../../../ROADMAP.md)). It also proves nothing about the
world at all when signed, as here, with the public test key. L2 note: the
standalone [`l2/`](../../../l2/) registry does not yet package this formula, so
reproduction fails closed as `formula-unavailable` — never a false "reproduced".
