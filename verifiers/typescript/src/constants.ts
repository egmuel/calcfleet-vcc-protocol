// VCC v0.2 constants needed by the standalone L1 verifier.
//
// STANDALONE COPY (sdk/typescript): these values are copied verbatim from the
// reference `src/lib/vcc/constants.ts` so this package has ZERO dependency on
// CalcFleet site code. They are part of the frozen v0.2 wire contract; if the
// reference changes them, the conformance runner over the committed vectors is
// what catches any drift.

export const VCC_SPEC_VERSION = "0.2";

/** DSSE payloadType for calculation statements (ADR-001). */
export const VCC_PAYLOAD_TYPE =
  "application/vnd.vcc.statement+json;version=0.2";

/** Statement `type` URL for single deterministic calculations. */
export const VCC_STATEMENT_TYPE =
  "https://calcfleet.com/vcc/statement/calculation/v0.2";

export const VCC_CALC_URN_PREFIX = "urn:vcc:calculation:sha256:";

/** Numeric profile implemented by the reference engine (ADR-002). */
export const VCC_NUMERIC_PROFILE = "vcc-decimal-v1";

export const VCC_RUNTIME_PROFILE = "node-deterministic-v1";

/** Hard cap on a stored certificate's canonical JSON size (ADR-006). */
export const VCC_MAX_CERTIFICATE_BYTES = 64 * 1024;
