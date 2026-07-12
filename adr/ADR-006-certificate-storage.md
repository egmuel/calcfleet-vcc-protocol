# ADR-006 — Certificate storage: content-addressed, append-only, on the existing KV pattern

Status: **Accepted** (2026-07-11)

## Context

No database exists. `src/lib/usage.ts` established the storage pattern: Upstash-compatible KV over REST when `KV_REST_API_URL`/`KV_REST_API_TOKEN` are set, in-memory fallback otherwise (explicitly surfaced as volatile). Certificates are immutable; status is not.

## Decision

1. Interface:
   ```ts
   interface VccCertificateStore {
     put(id: string, envelope: VccEnvelope): Promise<PutOutcome>; // "stored" | "already-exists"
     get(id: string): Promise<VccEnvelope | null>;
     getStatus(id: string): Promise<VccCertificateStatus | null>;
     setStatus(id: string, s: VccCertificateStatus, reason?: string): Promise<void>;
   }
   ```
2. Adapters: `KvCertificateStore` (REST, same env contract as usage.ts) and `MemoryCertificateStore` (dev/test; volatile — surfaced via `storageMode()`); selected by env, gated by `VCC_STORE_ENABLED`.
3. **Append-only & idempotent**: key `vcc:cert:<idHex>`. `put` on an existing id: byte-identical envelope ⇒ `already-exists` (idempotent success); different bytes ⇒ **hard error** (never silent overwrite). Since ids are content-addressed over the statement, differing bytes at the same id means corruption or an ID-collision attempt — logged as such.
   - **Multi-signature storage — "verified-superset-wins".** The statement id is the digest of the **statement**, not the envelope, so two envelopes over the same statement id may legitimately carry **different signature sets** (an envelope MAY hold 1..4 signatures with unique `keyid`s; see `spec-v0.2.md` §5, `trust-model.md` §2.9). When this happens, a store SHOULD keep the envelope whose **fully-verified** signature set is the **largest** — adding a countersignature (e.g. an auditor's) yields a new envelope whose signatures are a **superset** of the stored one, and that superset envelope wins. Only signatures that verify count toward the set; a bogus extra signature does not let an envelope win. (Byte-identical re-`put` remains `already-exists`; this policy governs the case where the bytes differ *only* by a superset of valid signatures.)
4. **Validation before storage**: full L1 verification must pass before `put` (the issuance pipeline self-verifies; the store also refuses envelopes > **64 KB** canonical JSON and structurally invalid ones).
5. **Status is separate state**, key `vcc:status:<idHex>`: `valid` (default when cert exists) | `superseded` | `withdrawn` | `disputed` | `issuer-key-compromised`. Revocation semantics: a status **never deletes** the historical fact that the signature was produced; `GET /certificates/{id}` keeps serving the bytes alongside the status.
6. Store disabled ⇒ issuance still works (stateless); `GET /api/v1/certificates/{id}` returns 404 with reason `store-disabled`; `/verify/{id}` falls back to paste-a-certificate verification.

## Alternatives considered

- Vercel Blob: better for large blobs, but adds a dependency/entitlement; 64 KB caps make KV strings fine. Revisit if pipeline certificates grow.
- Git-committed certificate log (transparency-log style): attractive later (P2, public auditability), operationally wrong as the primary store (deploy per certificate).
- Postgres: no DB in the project; introducing one for an MVP store violates the conservative-option rule.

## Consequences

- Same operational story as the rest of the site (works un-provisioned, upgrades to KV when env is present).
- Memory mode = certificates retrievable only until instance recycle; acceptable because certificates are self-contained and verification never *requires* the store.

## Risks

- KV is mutable by the operator (not a transparency log) — documented honestly in the spec's non-goals; append-only is an application invariant, not a storage guarantee. Public golden vectors + offline verification keep the issuer honest about *format*; a real transparency log is a documented extension point.
