# VCC Key Rotation Runbook

**Who this is for.** The operator of the CalcFleet deployment — the person who holds `VCC_SIGNING_KEY` and answers for what it signs. This is the procedure companion to the [issuer guide](./issuer-guide.md): normal rotation on a schedule, and the compromise procedure for when the schedule stops mattering. Design rationale in [ADR-004](../adr/ADR-004-key-management.md); what verifiers conclude from each status in the [verifier guide](./verifier-guide.md#key-status-semantics); the attack catalogue in the [threat model](./threat-model.md) (T2, T12, T20).

## What rotation changes — and what it cannot

Two facts frame every procedure below:

- **Old certificates remain cryptographically valid forever.** Ed25519 math does not expire. Rotation changes what verifiers *conclude*, not what they *compute*: a certificate signed by a now-`retired` key still passes `cryptographicValidity`; it is `trustedAtVerificationTime` that reflects the key's current status ([spec §6](./spec-v0.2.md#6-key-discovery--trust)). Never expect rotation to "invalidate" anything — that is what certificate statuses are for ([ADR-006](../adr/ADR-006-certificate-storage.md)).
- **The published keyset is the trust root.** `/.well-known/vcc-issuer.json` serves `PRODUCTION_KEYS` from `src/lib/vcc/issuer-keys.ts` — public keys only, committed on purpose: the git history *is* the rotation audit trail ([ADR-004](../adr/ADR-004-key-management.md)).

The property that makes this runbook forgiving is the **sign-time self-check** ([ADR-004 §5](../adr/ADR-004-key-management.md)): the signer derives its own public key and refuses to sign unless that key is present *and* `active` in the published keyset. A forgotten keyset update, a mistyped env value, a deploy that landed before the env swap — all of these fail safe as `certificate: null` with reason `signer-unavailable`, never as a certificate the world cannot validate. Calculation responses are unaffected throughout; that invariant holds in every scenario on this page.

## Normal rotation

Target end state: new key signs, old key `retired`, both published.

1. **Generate the new keypair offline** — on a trusted machine, not in a Vercel shell, not in CI:

   ```bash
   npm run vcc:keygen -- --key-id 2027-07-a
   ```

   The script (`scripts/vcc/generate-keypair.ts`) prints and never writes files: the `VCC_SIGNING_KEY`/`VCC_KEY_ID` lines destined for the Vercel env, and a ready-to-paste JSON public entry for the keyset. The private key is shown once and kept nowhere — do not paste it into chats, issues, or commits.

2. **Update the keyset** in `src/lib/vcc/issuer-keys.ts`: add the printed **public** entry to `PRODUCTION_KEYS` with `status: "active"`, and flip the old entry to `status: "retired"` (set its `validUntil`). Commit.

3. **Deploy** (push to `main`). From this moment the old key is `retired` in the published set, so the running signer — still holding the old private key — refuses to sign (self-check above). This window is expected, brief, and fail-safe: `certify=1` returns `certificate: null` / `signer-unavailable` until step 4 lands; calculations continue normally.

4. **Swap the env on Vercel — production scope only, never preview**: set `VCC_SIGNING_KEY` and `VCC_KEY_ID` to the new values, then trigger a redeploy (env changes apply to the next deployment, not to already-running functions).

5. **Confirm discovery**:

   ```bash
   curl -s https://calcfleet.com/.well-known/vcc-issuer.json
   ```

   The new `keyId` must appear as `active`, the old one as `retired`.

6. **Smoke test**: issue a certificate with `?certify=1`, check that `envelope.signatures[0].keyid` is the new id, and verify it offline per the [quickstart](./quickstart.md#4-verify-offline-the-point-of-the-whole-exercise).

Nothing else changes. Certificates signed by the old key keep verifying; verifiers report `issuerKeyStatus: "retired"` for them — honest history, no new signatures expected ([verifier guide](./verifier-guide.md#key-status-semantics)).

### Failure modes during rotation

All of these self-diagnose via `certificateReason` and the [issuer guide's refusal table](./issuer-guide.md#what-gets-refused); none of them affects calculations.

| Symptom | Cause | Fix |
|---|---|---|
| `signer-unavailable` after step 3, before step 4 | Old key retired in the published set; signer still holds it | Expected window — finish step 4 |
| `signer-unavailable` after step 4 | Env swapped but keyset entry missing or not `active` (forgotten step 2, or typo in `VCC_KEY_ID`) | Fix the keyset entry / key id; the self-check held the line |
| `signer-unavailable`, key looks right | `VCC_SIGNING_KEY` malformed (not single-line base64 PKCS#8 DER) | Re-paste from the keygen output; startup validation decodes, asserts Ed25519 and runs a sign+verify self-test |
| New keyid signs but verifiers report `unknown` key | Verifier's pinned keyset predates the rotation | Their refresh cadence, not your bug — see [verifier guide](./verifier-guide.md#key-status-semantics) |

## Compromise procedure

Assume compromise the moment you suspect it: env leaked, laptop lost, anything with production env access behaving oddly ([threat model](./threat-model.md) T2, T20).

1. **Mark the key `compromised` and deploy IMMEDIATELY.** This is the one step whose latency matters. Edit the key's entry in `PRODUCTION_KEYS` to `status: "compromised"`, commit, push. The well-known endpoint caches with `s-maxage=3600`, so the flip reaches cache-respecting fetchers **within one hour of the deploy** ([ADR-004](../adr/ADR-004-key-management.md)). Verifiers with pinned keysets learn it at their next refresh — which is exactly why the verifier guide tells them to refresh periodically.
2. **Rotate**: generate a new keypair offline (`npm run vcc:keygen`), add its public entry as `active` (it can ride the same deploy as step 1), swap `VCC_SIGNING_KEY`/`VCC_KEY_ID` in the production env, redeploy — steps 1–6 of normal rotation, compressed.
3. **Flag affected certificates.** If the store is enabled (`VCC_STORE_ENABLED`), set certificate status `issuer-key-compromised` for certificates issued in the affected window. There is no admin UI for this in v0.2: it is a one-off operator script against the KV store via `VccCertificateStore.setStatus` (`src/lib/vcc/storage.ts`). Statuses never delete envelopes — revocation preserves history ([ADR-006](../adr/ADR-006-certificate-storage.md)); verifiers see both the bytes and the status ([verifier guide](./verifier-guide.md#certificate-status-semantics)).
4. **Publish a note** — issuer site or repository — stating the key id, the suspected window, and what verifiers should conclude: signatures from a `compromised` key prove possession of the key, not the issuer's intent.
5. **Find the leak before relying on the new key.** The replacement lives in the same Vercel env that just failed you. Today's blast radius is deliberately small — only the pilot formulas are certifiable — but the structural fix is a KMS-backed signer; the interface and stub are shipped, the wiring is the open-P1 item tracked as T2 in the [threat model](./threat-model.md).

## Cadence

- **Yearly**, aligned with the key-id naming convention (`2026-07-a` → `2027-07-a`).
- **On tooling or personnel change**: new development machine, changes to CI or deploy pipelines that touch env handling, anyone with production env access departing. Rotation is cheap by design; suspicion alone is sufficient reason.

## Notes on the test key

`TEST_KEY_ID` (`test-2026-07`) in `issuer-keys.ts` is **deliberately public** — its private half is committed so golden vectors and offline verification examples are reproducible by anyone. It is never rotated, never trusted, and never part of the production keyset unless `VCC_ALLOW_TEST_KEY` is explicitly set, which production must never do ([issuer guide](./issuer-guide.md#environment-flags)). Anything signed with it proves nothing; treat any appearance of it outside dev/preview as a misconfiguration to fix, not a compromise to run this runbook for.
