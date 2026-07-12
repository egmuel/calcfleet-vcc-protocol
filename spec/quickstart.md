# VCC Quickstart

**Who this is for.** A developer with `curl` and Node who wants to issue a Verifiable Calculation Certificate (VCC) from CalcFleet and verify it — online in one request, or fully offline with the bundled CLI. No account, no SDK, no blockchain. For the full format see the [spec](./spec-v0.2.md); for third-party verification internals see the [verifier guide](./verifier-guide.md).

## What you get

A VCC is a signed, tamper-evident receipt for one deterministic calculation: which formula version ran, on which validated inputs, producing which outputs, at what time, issued by whom. It does **not** claim the inputs are true, that the result is advice, or any form of regulatory compliance — see [What a VCC proves — and what it does not](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not).

## 1. Issue a certificate

Add `?certify=1` to any certifiable tool endpoint. Without the flag the response is byte-identical to the legacy API.

```bash
curl -X POST "https://calcfleet.com/api/v1/tools/personal-loan-calculator?certify=1" \
  -H "content-type: application/json" \
  -d '{"principal":20000,"annualRatePct":7.5,"termMonths":60,"originationFeePct":1}'
```

Access note: in production the `/api/v1` surface sits behind the RapidAPI proxy and requires the `x-rapidapi-proxy-secret` header (requests routed through RapidAPI carry it automatically; direct calls without it get 403). On a local dev server (`npm run dev`) the route is open — the same `curl` works against `http://localhost:3000` with no header.

## 2. Response anatomy

```jsonc
{
  "result": { /* the calculation result, unchanged from the legacy response */ },
  "provenance": { /* the existing provenance declaration */ },
  "certificate": {
    "statement": {
      // Convenience view — human-readable, NOT the thing you verify.
      "specVersion": "0.2",
      "type": "https://vcc.dev/statement/calculation/v0.2",
      "subject": { "id": "urn:vcc:calculation:sha256:<hex64>", "kind": "deterministic-calculation" },
      "issuer": { "id": "https://calcfleet.com", "name": "CalcFleet", "keyDiscovery": "https://calcfleet.com/.well-known/vcc-issuer.json" },
      "formula": { "slug": "personal-loan-calculator", "version": "1.0.0", "digest": { "algorithm": "sha-256", "value": "<hex64>" }, "...": "..." },
      "calculation": {
        "inputs":  { "principal": { "type": "money", "value": "20000.00", "scale": 2, "unit": "USD" }, "...": "..." },
        "outputs": { "monthlyPayment": { "type": "money", "value": "<...>", "scale": 2, "unit": "USD" }, "...": "..." },
        "numericProfile": "vcc-decimal-v1"
      },
      "issuedAt": "2026-07-11T14:02:11Z",
      "...": "..."
    },
    "envelope": {
      // The canonical certificate. Store and share THIS.
      "payloadType": "application/vnd.vcc.statement+json;version=0.2",
      "payload": "<base64 of the canonical statement bytes>",
      "signatures": [{ "keyid": "2026-07-a", "sig": "<base64 Ed25519 signature>" }]
    }
  }
}
```

Two things to internalize:

- **The envelope is the certificate.** The `statement` object is a parsed convenience view; verifiers always derive the statement from `envelope.payload` ([ADR-001](../adr/ADR-001-vcc-envelope.md)). Save the whole `certificate` object to a file — the CLI reads it.
- **Certification never blocks the calculation.** If certification is unavailable (flag off, signer missing, formula not certifiable, privacy guard tripped) you still get HTTP 200 with your `result`, plus `certificate: null` and a `certificateReason` string. See the [issuer guide](./issuer-guide.md#what-gets-refused).

Every number in `calculation` is a typed value (`type`/`value`/`scale`/`unit`) under the `vcc-decimal-v1` profile — `"percent"` means percentage points, `"ratio"` means a dimensionless fraction, and the formula manifest decides which; readers never guess.

## 3. Verify online

Send the envelope back (no auth, rate-limited):

```bash
curl -X POST "https://calcfleet.com/api/v1/verify" \
  -H "content-type: application/json" \
  -d '{"envelope": { ...paste envelope here... }}'
```

The response contains `{ l1, l2, summary }`. Or open the human-readable page — the certificate id is the hex64 tail of `subject.id`:

```
https://calcfleet.com/verify/<idHex>
```

The page shows authenticity, integrity, reproducibility and data sections separately, plus the limits text. If the certificate store is disabled, the page falls back to paste-a-certificate verification.

## 4. Verify OFFLINE (the point of the whole exercise)

Clone the repo, `npm ci`, then fetch the issuer keyset **once** and pin it:

```bash
curl -s https://calcfleet.com/.well-known/vcc-issuer.json -o issuer-keys.json

npm run vcc -- verify certificate.json --keys issuer-keys.json
npm run vcc -- inspect certificate.json
npm run vcc -- reproduce certificate.json
```

- `verify` — offline L1: decodes the payload, re-canonicalizes (RFC 8785), recomputes the content-addressed id, checks the Ed25519 signature against your pinned keyset. **No network call to CalcFleet is made or needed.**
- `inspect` — pretty-prints the statement decoded from the payload (the DSSE payload is base64, not human-readable in transit).
- `reproduce` — L2: re-runs the pinned formula version from the local registry on the certified inputs and diffs the outputs.

## 5. Reading the results

**L1 result axes** (authenticity + integrity):

| Field | One-line meaning |
|---|---|
| `cryptographicValidity` | The envelope parses, the payload is canonical, the id recomputes, and the Ed25519 signature checks out. |
| `issuerKeyStatus` | What the issuer currently says about the signing key: `active`, `retired`, `revoked`, `compromised` — or `unknown` if your keyset has no entry. |
| `certificateStatus` | What the issuer currently says about this certificate: `valid`, `superseded`, `withdrawn`, `disputed`, `issuer-key-compromised` — or `unknown` without store access. |
| `trustedAtVerificationTime` | All of the above allow trust *right now*: valid signature ∧ key `active` ∧ certificate not revoked-class. |

**L2 statuses** (reproducibility):

| Status | One-line meaning |
|---|---|
| `match` | Re-running the pinned formula version on the certified inputs reproduced every certified output at the declared scales. |
| `mismatch` | Re-execution produced different values — see `differences[]` for field-by-field expected/actual. |
| `not-reproducible` | The certificate is structurally fine but L2 cannot be attempted for it. |
| `formula-unavailable` | This verifier's local registry has no pack for that slug+version. **Not** an authenticity failure. |
| `dataset-unavailable` | A dataset the statement references is missing locally or its digest does not match. |
| `unsupported-profile` | The statement uses a numeric profile this verifier does not implement. |
| `execution-failed` | The re-run itself errored or hit the wall-clock guard. |

**The four summary booleans** — `POST /api/v1/verify` returns `summary: { authentic, intact, reproducible, trusted }`:

- `authentic` — the signature is genuinely from the issuer's key.
- `intact` — the bytes have not changed since signing (canonical form + recomputed id).
- `reproducible` — L2 re-execution matched (`null` when L2 was not attempted).
- `trusted` — authenticity *and* current key status *and* current certificate status all hold at verification time.

There is deliberately **no single `verified` boolean**, anywhere. A signature can be cryptographically perfect on a certificate the issuer has since withdrawn, or signed by a key later marked compromised; collapsing those axes into one word is how verification UIs lie. Interfaces MUST keep the axes separate ([spec §1](./spec-v0.2.md#1-what-a-vcc-proves--and-what-it-does-not), [§6](./spec-v0.2.md#6-key-discovery--trust)).

## Limits

A VCC is not a government approval, a license, an audit, or a compliance attestation of any kind. It proves the issuance and integrity of one calculation — nothing about whether the inputs were truthful or the formula appropriate for your purpose. If you share certificates, read [privacy](./privacy.md) first; if you verify them for a living, read the [verifier guide](./verifier-guide.md).
