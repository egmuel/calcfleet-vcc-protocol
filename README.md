# VCC — Verifiable Calculation Certificate

**An experimental open protocol for portable, reproducible calculation receipts.**

A VCC is a signed receipt for a calculation. It records *which formula ran, at
which version, on which normalized inputs, under which numeric rules, producing
which output* — content-addressed and signed, so anyone can check its integrity
and provenance **offline**, without trusting the issuer's servers.

> VCC is **experimental**. This is not a mature or ratified standard.
> [CalcFleet](https://calcfleet.com) is its **first reference implementation** —
> but the point of this repository is that you can implement and verify VCC
> **without** CalcFleet's services.

## What a valid receipt proves — and does not

A valid signature establishes **integrity** (the receipt was not altered) and
**attribution** to a key. It does **not** by itself establish that the inputs
are true, the formula is appropriate, or the output is suitable for a particular
decision. See [`spec/trust-model.md`](spec/trust-model.md) and
[`spec/assurance-model.md`](spec/assurance-model.md).

## Repository layout

| Path | What |
|---|---|
| [`spec/`](spec/) | The normative specification: data model, numeric profiles, formula packages, dataset manifests, assurance & trust models, privacy profiles, conformance, security/threat model, governance, the interoperability report, and integration guides. |
| [`adr/`](adr/) | Architecture Decision Records — the decision log (§ envelope, numeric semantics, formula identity, key management, L2 reproduction, storage, privacy). |
| [`schema/`](schema/) | The portable JSON Schema for the receipt. |
| [`vectors/`](vectors/) | Conformance test vectors: 4 valid golden receipts + 15 negative cases (invalid signature, modified payload, wrong digest, unknown formula, revoked key, …), each pinning the axis that must fail. |
| [`verifiers/typescript/`](verifiers/typescript/) | Reference verifier in TypeScript (offline, WebCrypto). |
| [`verifiers/python/`](verifiers/python/) | An **independent** verifier in Python (from scratch, offline). |

## Two independent verifiers (why it matters)

The protocol ships **two independent verifier implementations** — TypeScript and
Python — that agree, byte-for-byte, on every vector. This is the concrete
evidence behind the "interoperable" direction: the JSON canonicalization
(JCS / RFC 8785) and the Ed25519 signature check produce identical results
across two languages written independently. See
[`spec/interoperability-report.md`](spec/interoperability-report.md).

## Quick start — verify a receipt offline

**TypeScript**
```bash
git clone https://github.com/egmuel/calcfleet-vcc-protocol.git
cd calcfleet-vcc-protocol/verifiers/typescript
npm ci
npm run conformance     # verifies every vector, offline
```

**Python**
```bash
cd calcfleet-vcc-protocol/verifiers/python
pip install -r requirements.txt
python conformance_runner.py    # same corpus, independent implementation
```

Both run with your network disconnected: a receipt never leaves your machine.
Reproduction (L2) additionally needs the formula package and any dataset
snapshots to be resolvable — publish or mirror them so verification carries no
mandatory dependency on any single vendor.

## Adoption levels

These are **integration levels**, not certifications (there is no formal
certification process):

- **L1 — Receipt consumer**: verify receipts (this repo is enough).
- **L2 — Issuer**: produce receipts.
- **L3 — Formula publisher**: publish versioned formula packages.
- **L4 — Governance**: operate policy and a registry.

See [`spec/governance.md`](spec/governance.md) for the adoption gates: the public
claim only escalates from *"experimental open protocol"* to *"interoperable"* /
*"pilot-ready"* / *"standardization candidate"* when the objective conditions
for each are met — and never before.

## Licensing

- **Code** (verifiers, schemas, test vectors): **Apache-2.0** — see [`LICENSE`](LICENSE)
  (includes a patent grant so you can implement the protocol safely).
- **Specification text**: **CC-BY-4.0** — see [`LICENSE-SPEC`](LICENSE-SPEC).

## Governance & security

- Governance, neutrality requirement, versioning and change process:
  [`GOVERNANCE.md`](GOVERNANCE.md).
- Report a vulnerability: [`SECURITY.md`](SECURITY.md).

Independent implementations are welcome — that is the entire purpose of
publishing this under an open license.
