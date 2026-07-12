// Runtime validation for the VCC structures L1 verification needs — STANDALONE
// COPY (sdk/typescript). Zod 4, strict objects: unknown keys are rejected
// everywhere (extra fields under a signature are an attack surface, and the
// privacy model depends on the schema being an allowlist).
//
// This is a faithful subset of the reference `src/lib/vcc/schemas.ts` covering
// exactly `statementSchema` and `envelopeSchema` (plus the sub-schemas they
// reference). Copied here so this package imports nothing from CalcFleet site
// code. The committed conformance vectors are what prove this schema accepts /
// rejects the same inputs as the reference, byte-for-byte.

import { z } from "zod";
import {
  VCC_PAYLOAD_TYPE,
  VCC_STATEMENT_TYPE,
  VCC_SPEC_VERSION,
  VCC_NUMERIC_PROFILE,
  VCC_RUNTIME_PROFILE,
} from "./constants.js";

export const SHA256_HEX = /^[0-9a-f]{64}$/;
/** Seconds-precision UTC, single canonical representation (spec §2). */
export const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** Canonical decimal string, no exponent, no leading zeros, no "-0" (ADR-002). */
export const DECIMAL_VALUE_RE = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const BASE64_STD_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const SLUG_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;
/** Bounded, printable, non-free-text strings (enum-like outputs, labels). */
export const SHORT_STRING_RE = /^[A-Za-z0-9][A-Za-z0-9 _/.,:()%+–—-]{0,63}$/;
/** Measurement units: "USD", "%", "months", "kWh", "kWh/day"… */
export const UNIT_RE = /^[%A-Za-z][%A-Za-z0-9/·°²³-]{0,15}$/;

export const digestSchema = z.strictObject({
  algorithm: z.literal("sha-256"),
  value: z.string().regex(SHA256_HEX),
});

// ── Numeric typed values ─────────────────────────────────────────────────────

export const numericKindSchema = z.enum([
  "integer",
  "decimal",
  "percent",
  "ratio",
  "money",
  "duration",
]);

export const typedValueSchema = z
  .strictObject({
    type: numericKindSchema,
    value: z.string().regex(DECIMAL_VALUE_RE).max(64),
    scale: z.number().int().min(0).max(12),
    unit: z.string().regex(UNIT_RE).optional(),
  })
  .superRefine((tv, ctx) => {
    const frac = tv.value.split(".")[1] ?? "";
    if (tv.scale === 0 && frac !== "") {
      ctx.addIssue({ code: "custom", message: "scale 0 value must have no fraction" });
    }
    if (tv.scale > 0 && frac.length !== tv.scale) {
      ctx.addIssue({
        code: "custom",
        message: `fraction must have exactly ${tv.scale} digits`,
      });
    }
    if (tv.value === "-0" || (tv.value.startsWith("-0.") && !/[1-9]/.test(tv.value))) {
      ctx.addIssue({ code: "custom", message: "negative zero is not canonical" });
    }
  });

export type CalcValue =
  | z.infer<typeof typedValueSchema>
  | string
  | boolean
  | CalcValue[]
  | { [k: string]: CalcValue };

/**
 * Value tree for calculation.inputs/outputs. Strings are bounded and
 * pattern-restricted (closed enums / labels, never free text — ADR-007).
 */
export const calcValueSchema: z.ZodType<CalcValue> = z.lazy(() =>
  z.union([
    typedValueSchema,
    z.string().regex(SHORT_STRING_RE),
    z.boolean(),
    z.array(calcValueSchema).max(1024),
    z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/), calcValueSchema),
  ]),
);

// ── Statement ────────────────────────────────────────────────────────────────

export const sourceRefSchema = z.strictObject({
  label: z.string().min(1).max(200),
  url: z.url().max(500),
});

// ── Issuer attestation (spec master §42, §43) ────────────────────────────────

export const attestationTypeSchema = z.enum([
  "execution",
  "reproduction",
  "review",
]);

export const attestationClaimSchema = z.enum([
  "inputs-received",
  "formula-executed",
  "datasets-used",
  "numeric-profile-applied",
  "output-produced",
]);

export const attestationSchema = z
  .strictObject({
    type: attestationTypeSchema,
    claims: z.array(attestationClaimSchema).min(1).max(16),
  })
  .superRefine((att, ctx) => {
    if (new Set(att.claims).size !== att.claims.length) {
      ctx.addIssue({ code: "custom", message: "attestation claims must be unique" });
    }
  });

export const statementSchema = z.strictObject({
  specVersion: z.literal(VCC_SPEC_VERSION),
  type: z.literal(VCC_STATEMENT_TYPE),
  subject: z.strictObject({
    id: z.string().regex(/^urn:vcc:calculation:sha256:[0-9a-f]{64}$/),
    kind: z.literal("deterministic-calculation"),
  }),
  issuer: z.strictObject({
    id: z.url().max(200),
    name: z.string().min(1).max(100),
    keyDiscovery: z.url().max(300),
  }),
  formula: z.strictObject({
    id: z.string().regex(/^urn:vcc:formula:[a-z0-9-]+$/),
    slug: z.string().regex(SLUG_RE).max(80),
    version: z.string().regex(SEMVER_RE),
    digest: digestSchema,
    registry: z.url().max(400),
    visibility: z.literal("open"),
  }),
  calculation: z.strictObject({
    inputs: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/), calcValueSchema),
    outputs: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/), calcValueSchema),
    numericProfile: z.literal(VCC_NUMERIC_PROFILE),
  }),
  datasets: z
    .array(
      z.strictObject({
        id: z.string().regex(/^urn:vcc:dataset:[a-z0-9-]+$/),
        name: z.string().min(1).max(100),
        version: z.string().min(1).max(40),
        digest: digestSchema,
        mediaType: z.string().min(3).max(100),
      }),
    )
    .max(16),
  evidence: z.strictObject({
    sources: z.array(sourceRefSchema).max(20),
    testsDigest: digestSchema,
  }),
  engine: z.strictObject({
    name: z.string().min(1).max(60),
    version: z.string().min(1).max(40),
    commit: z.string().regex(/^([0-9a-f]{7,40}|unknown)$/),
    runtimeProfile: z.literal(VCC_RUNTIME_PROFILE),
  }),
  attestation: attestationSchema,
  issuedAt: z.string().regex(ISSUED_AT_RE),
  context: z.strictObject({
    surface: z.enum(["api", "web", "mcp", "graph"]),
    requestId: z.string().regex(REQUEST_ID_RE).optional(),
  }),
});

// ── Envelope ─────────────────────────────────────────────────────────────────

export const envelopeSchema = z.strictObject({
  payloadType: z.literal(VCC_PAYLOAD_TYPE),
  // 64KB cap pre-decode (base64 inflates 4/3; enforced again post-decode).
  payload: z.string().regex(BASE64_STD_RE).max(90_000),
  signatures: z
    .array(
      z.strictObject({
        keyid: z.string().regex(KEY_ID_RE),
        // Ed25519 sig = 64 bytes → 88 base64 chars with padding.
        sig: z.string().regex(BASE64_STD_RE).min(86).max(90),
      }),
    )
    .min(1)
    .max(4),
});

// ── Issuer keyset ────────────────────────────────────────────────────────────

export const issuerKeySchema = z.strictObject({
  keyId: z.string().regex(KEY_ID_RE),
  algorithm: z.literal("ed25519"),
  // Raw 32-byte key → 44 base64 chars with padding.
  publicKey: z.string().regex(BASE64_STD_RE).min(42).max(46),
  status: z.enum(["active", "retired", "revoked", "compromised"]),
  validFrom: z.string().regex(ISSUED_AT_RE),
  validUntil: z.string().regex(ISSUED_AT_RE).nullable(),
});

export const issuerKeySetSchema = z.strictObject({
  issuer: z.url().max(200),
  keys: z.array(issuerKeySchema).max(32),
});
