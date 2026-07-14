// Normative JSON Schema (Draft 2020-12) for the VCC issuer-attestation block
// added in v0.2 (spec master §42, §43). This is a portable, language-neutral
// statement of the `attestation` field's shape, for third-party implementations
// that cannot run our Zod schema (schemas.ts remains the runtime source of
// truth; this mirrors the `attestation` slice of it byte-compatibly).
//
// Scope: the attestation block only. A full JSON Schema of the whole statement
// is tracked separately (conformance-plan.md); adding attestation should not be
// gated on hand-porting the entire statement schema, which the Zod schema still
// owns. Keep this file in sync with `attestationSchema` in schemas.ts.

/** JSON Schema (Draft 2020-12) for `VccAttestation` — see types.ts / schemas.ts. */
export const VCC_ATTESTATION_JSON_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://calcfleet.com/vcc/schema/attestation/v0.2.json",
  title: "VCC Issuer Attestation (v0.2)",
  description:
    "What the issuer explicitly attests to on a receipt. Part of the signed statement when present. Additive (§42): verifiers MUST accept statements that omit the block (issued before its introduction); issuers SHOULD always include it. Each claim is a fact the issuer performed, never a claim about the world (spec master §42). `type` names the receipt category (§43).",
  type: "object",
  additionalProperties: false,
  required: ["type", "claims"],
  properties: {
    type: {
      description:
        "Receipt type (§43): execution = issuer ran the calculation; reproduction = third party re-ran and matched/diverged; review = auditor/policy engine evaluated formula/dataset/policy/methodology. CalcFleet emits only `execution`.",
      type: "string",
      enum: ["execution", "reproduction", "review"],
    },
    claims: {
      description:
        "Ordered, non-empty, duplicate-free list of facts the issuer attests to (§42). `datasets-used` appears only when datasets were referenced.",
      type: "array",
      minItems: 1,
      maxItems: 16,
      uniqueItems: true,
      items: {
        type: "string",
        enum: [
          "inputs-received",
          "formula-executed",
          "datasets-used",
          "numeric-profile-applied",
          "output-produced",
        ],
      },
    },
  },
} as const;
