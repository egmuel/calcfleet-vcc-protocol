// VCC v0.2 types needed by the standalone L1 verifier — STANDALONE COPY.
//
// A dependency-free subset of the reference `src/lib/vcc/types.ts`: only the
// shapes the L1 verifier and its result touch. Copied here so this package
// imports nothing from CalcFleet site code.

// ── Statement (spec §2) ──────────────────────────────────────────────────────

export interface VccSubject {
  /** `urn:vcc:calculation:sha256:<hex64>` — content-addressed (spec §4). */
  id: string;
  kind: "deterministic-calculation";
}

/** A value tree in calculation.inputs/outputs (structure only). */
export type VccValue =
  | { type: string; value: string; scale: number; unit?: string }
  | string
  | boolean
  | VccValue[]
  | { [key: string]: VccValue };

export interface VccStatement {
  specVersion: "0.2";
  type: "https://vcc.dev/statement/calculation/v0.2";
  subject: VccSubject;
  // The remaining fields are validated by the Zod schema but not read directly
  // by L1 beyond canonicalization/id; kept as an index signature to stay a
  // faithful-but-minimal shape.
  [key: string]: unknown;
}

// ── Envelope (DSSE, ADR-001) ─────────────────────────────────────────────────

export interface VccSignature {
  keyid: string;
  /** Standard base64 of the raw 64-byte Ed25519 signature. */
  sig: string;
}

export interface VccEnvelope {
  payloadType: "application/vnd.vcc.statement+json;version=0.2";
  /** Standard base64 (padded) of the JCS canonical statement bytes. */
  payload: string;
  signatures: VccSignature[];
}

// ── Keys (ADR-004) ───────────────────────────────────────────────────────────

export type VccKeyStatus = "active" | "retired" | "revoked" | "compromised";

export interface VccIssuerKey {
  keyId: string;
  algorithm: "ed25519";
  /** Standard base64 of the raw 32-byte Ed25519 public key. */
  publicKey: string;
  status: VccKeyStatus;
  validFrom: string;
  validUntil: string | null;
}

export interface VccIssuerKeySet {
  issuer: string;
  keys: VccIssuerKey[];
}

// ── Certificate status (ADR-006) ─────────────────────────────────────────────

export type VccCertificateStatus =
  | "valid"
  | "superseded"
  | "withdrawn"
  | "disputed"
  | "issuer-key-compromised";

// ── Verification result (spec §7) ────────────────────────────────────────────

export interface VccL1Checks {
  envelopeSchema: boolean;
  payloadType: boolean;
  payloadDecodes: boolean;
  statementSchema: boolean;
  canonicalization: boolean;
  statementId: boolean;
  keyKnown: boolean;
  algorithmSupported: boolean;
  signature: boolean;
}

export interface VccL1VerificationResult {
  cryptographicValidity: boolean;
  /** Axis 1 — the Ed25519 signature verifies over the canonical PAE, on its own. */
  signatureValid: boolean;
  /** Axis 5 — the statement decodes, matches the schema, is canonical, id matches. */
  statementIntact: boolean;
  issuerKeyStatus: VccKeyStatus | "unknown";
  certificateStatus: VccCertificateStatus | "unknown";
  /** validity ∧ key active ∧ certificate valid-or-unknown-status. */
  trustedAtVerificationTime: boolean;
  checks: VccL1Checks;
  /** Parsed statement when payload decoded + validated; absent otherwise. */
  statement?: VccStatement;
  /** hex64 content id when computable. */
  idHex?: string;
  errors: string[];
}
