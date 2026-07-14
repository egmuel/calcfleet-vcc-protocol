# Examples — download, verify, break, reproduce

Every example in this directory is a **real signed receipt** (`receipt.json`):
a `{ statement, envelope }` pair taken from the conformance corpus, signed with
the **public test key** committed at [`../vectors/test-key.json`](../vectors/test-key.json).
Because the test key's private half is public by design, these receipts prove
nothing about the world — they exist so you can hold the protocol in your
hands: verify a receipt offline, tamper with it and watch exactly which axis
falls, and re-run the formula locally.

## The whole loop in four commands

```bash
# 1 — download
git clone https://github.com/egmuel/calcfleet-vcc-protocol.git
cd calcfleet-vcc-protocol
(cd verifiers/typescript && npm ci && npm run build)   # one-time build

# 2 — verify (offline: no network call is made or needed)
node examples/verify-receipt.mjs \
  examples/commissions/tiered-commission/receipt.json vectors/test-key.json

# 3 — break it (tamper one output inside the signed payload, re-verify)
#     → statementId and signature fall; see the per-example READMEs
# 4 — reproduce (L2: re-run the formula locally, diff the outputs)
python3 l2/l2_verify.py examples/finance/compound-interest/receipt.json
```

Verification prints **separate axes** (signature, integrity, key status,
trust) — there is deliberately no single `verified` boolean anywhere in VCC.

## The examples

| Example | Formula pack | What it demonstrates |
|---|---|---|
| [`commissions/tiered-commission/`](commissions/tiered-commission/) | `tiered-commission-calculator@1.2.0` | The core use case: a disputed commission payout. Verify with both verifiers; tamper an output and watch `statementId` + `signature` fall. |
| [`finance/personal-loan/`](finance/personal-loan/) | `personal-loan-calculator@1.0.0` | A loan quote with fee-adjusted effective APR. Corrupt the signature and watch `signatureValid` fall while `statementIntact` holds — the axes are independent. |
| [`finance/compound-interest/`](finance/compound-interest/) | `compound-interest-calculator@1.0.0` | The full story: L1 verification **plus** L2 reproduction (this is the one formula the standalone `l2/` registry implements). Tamper a declared output by one cent and get a field-level diff. |
| [`housing/home-affordability/`](housing/home-affordability/) | `home-affordability-calculator@1.0.0` | Why **the envelope is the certificate**: edit the human-readable `statement` view and verification still passes — verifiers only trust what is derived from `envelope.payload`. |

## Verifying a receipt (both verifiers)

Two helper scripts wrap the repo's two independent L1 verifiers for a single
receipt file. Both are offline; both print the same axes; both exit 0 iff
`cryptographicValidity`.

**TypeScript** (Node 22+; build once as above):

```bash
node examples/verify-receipt.mjs <receipt.json> vectors/test-key.json
```

**Python** (3.10+; one-time setup:
`python3 -m venv verifiers/python/.venv && verifiers/python/.venv/bin/pip install -r verifiers/python/requirements.txt`):

```bash
verifiers/python/.venv/bin/python examples/verify_receipt.py <receipt.json> vectors/test-key.json
```

For a real receipt from a real issuer, replace `vectors/test-key.json` with the
issuer's published keyset (e.g. `https://<issuer>/.well-known/vcc-issuer.json`),
fetched once and pinned.

## What these receipts do NOT prove

A valid signature proves **integrity** (nothing changed since signing) and
**attribution** (that key signed it). It does **not** prove the inputs were
true, the formula was appropriate, or the output is advice. And receipts signed
with the committed **test key** prove nothing at all beyond mechanics — the
private half is public on purpose. See
[`../spec/trust-model.md`](../spec/trust-model.md) and
[`../spec/assurance-model.md`](../spec/assurance-model.md).

## Domains not covered yet (honestly)

There are no examples for **insurance**, **usage-based pricing**, or
**AI-agent calculations**, because no real formula packs exist for those
domains yet — only the four packs above are packaged and pinned by golden
vectors. Examples get added when the packs are real, not before
(see [`../ROADMAP.md`](../ROADMAP.md)). No placeholder directories, no
synthetic demos.
