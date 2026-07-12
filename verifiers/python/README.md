# VCC L1 verifier — Python (independent, offline)

A **standalone** Verifiable Calculation Certificate (VCC v0.2) **L1 verifier**,
written from scratch in Python. It is the **second independent verifier**
required by the "Interoperable" gate (master spec §50): a from-scratch
implementation, in a different language from the TypeScript reference, that
produces the **same result on every conformance vector**.

- **Offline by design** (§49 vendor-independence). It reads only local files,
  imports **no CalcFleet code**, and makes **no network calls**. The caller
  supplies the issuer keyset (from the published
  `/.well-known/vcc-issuer.json` or the committed `vectors/test-key.json`).
- **Reference:** the TS verifier `src/lib/vcc/verify-l1.ts` stays authoritative;
  this Python module is a fully independent second implementation, not a port of
  its runtime (it re-derives JCS, DSSE PAE, the schema, and the identity rule).

## What L1 checks

The same nine per-check booleans the TS reference reports:

| # | check | meaning |
|---|-------|---------|
| 1 | `envelopeSchema` | DSSE envelope shape, strict (no extra keys) |
| 2 | `payloadType` | bound to `application/vnd.vcc.statement+json;version=0.2` |
| 3 | `payloadDecodes` | strict standard base64 within the 64 KiB cap |
| 4 | `statementSchema` | v0.2 statement shape, strict |
| 5 | `canonicalization` | payload bytes **are** the JCS (RFC 8785) form of the statement |
| 6 | `statementId` | `subject.id` == sha-256 of the statement **without** `subject.id` |
| 7 | `keyKnown` | signature `keyid` is in the supplied keyset |
| 8 | `algorithmSupported` | key algorithm is `ed25519` |
| 9 | `signature` | Ed25519 verifies over the DSSE PAE |

It projects the two orthogonal axes exactly as the reference does:
`signatureValid` (axis 1) and `statementIntact` (axes 3–6), plus
`trustedAtVerificationTime` (crypto valid **and** key `active` **and** certificate
status `valid`/`unknown`). It never raises on untrusted input — every outcome is
an `L1Result` with the per-check booleans and an `errors` list.

## Dependencies

Python 3.10+ and a single non-stdlib package, `cryptography` (Ed25519 only).

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Run

```bash
# Cross-language conformance: Python result vs the pinned TS-reference outcome
# on the committed corpus (src/lib/vcc/vectors/). Exit 0 iff all match.
.venv/bin/python conformance_runner.py

# JCS (RFC 8785) edge-case self-tests (ordering, numbers, escaping, unicode).
.venv/bin/python test_jcs.py
```

## Use as a library

```python
import json
from vcc_verifier import verify_vcc_envelope

envelope = json.load(open("certificate.json"))          # a DSSE envelope
keyset   = json.load(open("vcc-issuer.json"))["keyset"]  # published keyset

res = verify_vcc_envelope(envelope, keyset)
print(res.cryptographicValidity, res.trustedAtVerificationTime)
print(res.checks)   # per-axis booleans
print(res.errors)   # human-readable failures, if any
```

## Files

- `vcc_verifier.py` — the verifier: JCS canonicalization, strict schema, DSSE
  PAE, Ed25519, sha-256 identity, and the L1 result projection.
- `conformance_runner.py` — loads the repo corpus and asserts Python == pinned
  TS outcome on every positive and negative vector, plus JCS byte-parity.
- `test_jcs.py` — JCS edge-case self-tests.
- `requirements.txt` — `cryptography`.

See `docs/vcc/interoperability-report.md` for the cross-language result.
