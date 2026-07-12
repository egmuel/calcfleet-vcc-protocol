// @calcfleet/vcc-verifier — public entry point.
//
// A standalone, offline VCC v0.2 L1 verifier. Import `verifyVccEnvelope`, hand
// it a DSSE envelope and a published issuer keyset, and get back the per-check
// L1 result. Runs on Node 22+ and in the browser (WebCrypto Ed25519), with no
// network calls and no dependency on CalcFleet site code.

export { verifyVccEnvelope, webcryptoEd25519Available } from "./verify.js";
export { canonicalize, canonicalBytes } from "./canonicalize.js";
export {
  VCC_PAYLOAD_TYPE,
  VCC_STATEMENT_TYPE,
  VCC_CALC_URN_PREFIX,
  VCC_NUMERIC_PROFILE,
  VCC_MAX_CERTIFICATE_BYTES,
  VCC_SPEC_VERSION,
} from "./constants.js";
export { envelopeSchema, statementSchema, issuerKeySetSchema } from "./schemas.js";
export type {
  VccEnvelope,
  VccStatement,
  VccIssuerKey,
  VccIssuerKeySet,
  VccKeyStatus,
  VccCertificateStatus,
  VccL1Checks,
  VccL1VerificationResult,
  VccSignatureResult,
} from "./types.js";
