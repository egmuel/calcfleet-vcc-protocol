# Vision

## A spreadsheet is not evidence

Every day, organizations move money on the strength of numbers nobody can
defend: a commission payout, a loan quote, an affordability ceiling, a usage
bill. When one of those numbers is disputed — by a sales rep, a customer, a
counterparty, an auditor — the question is never just *"is the number right?"*
It is *"which formula, at which version, on which inputs, produced this
number?"*

Today the answer usually does not exist. The spreadsheet has been edited since.
The pricing engine was redeployed twice. The person who built the model left.
The two parties re-run "the same" calculation and get different answers, and
there is no independent way to tell whose arithmetic ran on what. The
calculation happened; its provenance did not survive it.

Software and AI systems now emit financially consequential numbers at a rate no
human review process can match. The numbers are almost always *arithmetically*
correct — that is not the problem. The problem is that they are **unprovable**:
disconnected from the versioned formula and the exact inputs that produced
them, the moment they leave the system that computed them.

## What VCC makes possible

VCC is **portable calculation evidence**: a small, signed receipt that travels
with a number and can be checked by anyone, offline, without trusting the
issuer's servers.

A receipt binds together, in one content-addressed, Ed25519-signed statement:

- **the formula** — named, versioned, digest-pinned. Not "our commission
  logic", but `tiered-commission-calculator@1.2.0`, exactly;
- **the inputs and outputs** — as typed decimal values (`money`, `percent`,
  `ratio`) under a declared numeric profile, so no reader ever guesses units
  or rounding;
- **the issuer and the moment** — who signed it, with which key, when.

From that, two independent things become checkable:

1. **L1 — integrity and attribution.** Anyone with the issuer's published
   keyset can verify, offline, that the receipt is byte-intact and was signed
   by that key. Two independent verifiers (TypeScript and Python) agree on
   every conformance vector.
2. **L2 — reproduction.** Anyone with a local implementation of the named
   formula version can re-run it on the receipt's inputs and compare outputs,
   field by field. A dispute about a number becomes a diff.

Verification results are always reported as **separate axes** — signature,
integrity, key status, reproducibility. There is deliberately no single
`verified: true` anywhere in the protocol, because collapsing those axes into
one word is how verification UIs lie.

## What VCC is not

- **Not a blockchain.** There is no chain, no token, no consensus, no gas. A
  receipt is a JSON file you can email, and verification is a local
  computation.
- **Not a claim that the inputs are true.** A valid receipt proves *which*
  inputs the formula ran on — not that those inputs were honest, accurate, or
  appropriate. Input provenance is a distinct, explicitly future layer (see
  [`ROADMAP.md`](ROADMAP.md)); until it ships, nobody should pretend
  otherwise.
- **Not an accepted standard.** VCC is an **experimental open protocol** with
  one reference implementation. The claim escalates only when the objective
  adoption gates in [`spec/governance.md`](spec/governance.md) are met — and
  never before.
- **Not advice, audit, or compliance.** A receipt proves the issuance and
  integrity of one calculation. It is not a license, an approval, or a
  substitute for professional judgment.

## Three questions

The economics of the protocol reduce to three questions, in order:

1. **Does this number need a VCC?** Most numbers do not. A receipt earns its
   place only where a number crosses a trust boundary — between employer and
   employee, seller and buyer, system and auditor — and someone may later
   dispute it.
2. **How expensive is an unprovable calculation?** Count the shadow
   accounting, the clawback fights, the audit hours, the settlements paid
   because provenance could not be shown. That cost, not cryptography, is the
   case for calculation evidence.
3. **Could you reproduce this number in two years?** After the engine is
   rewritten, the team has turned over, and the spreadsheet is gone. If the
   answer must be yes, the formula must be versioned, the inputs must be
   pinned, and the receipt must outlive the system that issued it. That is the
   property VCC exists to provide.

If those three questions matter for a number you produce or consume, start
with [`examples/`](examples/): download a signed receipt, verify it, break it,
reproduce it.
