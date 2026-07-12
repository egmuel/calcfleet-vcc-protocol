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

// ── Shared cross-language helpers (mirrored byte-for-byte in the Python verifier
//    vcc_verifier.py — see spec/trust-model.md). Any change here MUST be applied
//    there too, or the interoperability gate breaks. ────────────────────────────

/** ISO-4217 currency code shape (three uppercase letters). */
const ISO4217_RE = /^[A-Z]{3}$/;
/** Time units allowed for `duration` typed values. */
const DURATION_UNITS = new Set([
  "years", "months", "weeks", "days", "hours", "minutes", "seconds",
]);
/** A single DNS label (letters/digits/hyphen, no leading/trailing hyphen, ≤63). */
const DNS_LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DNS_HOST_RE = new RegExp(`^${DNS_LABEL}(?:\\.${DNS_LABEL})*$`);

/**
 * A safe normative URL: https only, a registrable DNS host (with a dot and an
 * alphabetic TLD), ASCII, no userinfo. This REJECTS `javascript:`, `file:`,
 * `data:`, `http:`, every IP literal (so 169.254.169.254, 127.0.0.1, [::1] …),
 * `localhost`, `*.local`. The classification is pure string work — no IP-range
 * math and no reliance on parser-specific IP normalization — so the TypeScript
 * and Python verifiers accept EXACTLY the same set (closes the audit's
 * cross-language divergence). The verifier never fetches; a fetcher MUST still
 * independently block private ranges at connect time (DNS rebinding is out of
 * scope for string validation — see spec/verifier-guide.md).
 */
export function isSafeHttpsUrl(s: unknown, maxLen: number): boolean {
  if (typeof s !== "string" || s.length === 0 || s.length > maxLen) return false;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  if (u.username !== "" || u.password !== "") return false;
  const host = u.hostname.toLowerCase();
  if (host === "" || host.includes(":")) return false; // empty or IPv6 literal
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    return false;
  }
  if (!DNS_HOST_RE.test(host)) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false; // require at least one dot
  const tld = labels[labels.length - 1];
  return /[a-z]/.test(tld); // alphabetic TLD ⇒ not an IPv4 literal
}

function isLeapYear(y: number): boolean {
  return y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
}
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * A REAL (not merely regex-shaped) UTC seconds timestamp `YYYY-MM-DDTHH:MM:SSZ`:
 * month 1-12, day valid for the month (Gregorian leap years), hour 0-23,
 * minute/second 0-59 (leap second 60 rejected for determinism). Closes the
 * audit's "2026-99-99T99:99:99Z is accepted" hole. Applied to issuedAt and to
 * key validFrom/validUntil.
 */
export function isValidUtcTimestamp(s: unknown): boolean {
  if (typeof s !== "string" || !ISSUED_AT_RE.test(s)) return false;
  const y = +s.slice(0, 4);
  const mo = +s.slice(5, 7);
  const d = +s.slice(8, 10);
  const h = +s.slice(11, 13);
  const mi = +s.slice(14, 16);
  const se = +s.slice(17, 19);
  if (mo < 1 || mo > 12) return false;
  let dim = DAYS_IN_MONTH[mo - 1];
  if (mo === 2 && isLeapYear(y)) dim = 29;
  if (d < 1 || d > dim) return false;
  return h <= 23 && mi <= 59 && se <= 59;
}

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
    // Type-dependent unit constraints (ADR-002): money carries an ISO-4217 code,
    // duration a time unit, percent only "%", ratio is dimensionless.
    if (tv.type === "money") {
      if (tv.unit === undefined || !ISO4217_RE.test(tv.unit)) {
        ctx.addIssue({ code: "custom", message: "money requires an ISO-4217 (3 uppercase letters) unit" });
      }
    } else if (tv.type === "duration") {
      if (tv.unit === undefined || !DURATION_UNITS.has(tv.unit)) {
        ctx.addIssue({ code: "custom", message: "duration requires a time unit (years…seconds)" });
      }
    } else if (tv.type === "percent") {
      if (tv.unit !== undefined && tv.unit !== "%") {
        ctx.addIssue({ code: "custom", message: "percent unit must be '%'" });
      }
    } else if (tv.type === "ratio") {
      if (tv.unit !== undefined) {
        ctx.addIssue({ code: "custom", message: "ratio is dimensionless and must not carry a unit" });
      }
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
  url: z.string().max(500).refine((v) => isSafeHttpsUrl(v, 500), {
    message: "source url must be a safe https URL",
  }),
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
    id: z.string().max(200).refine((v) => isSafeHttpsUrl(v, 200), {
      message: "issuer.id must be a safe https URL",
    }),
    name: z.string().min(1).max(100),
    keyDiscovery: z.string().max(300).refine((v) => isSafeHttpsUrl(v, 300), {
      message: "issuer.keyDiscovery must be a safe https URL",
    }),
  }),
  formula: z.strictObject({
    id: z.string().regex(/^urn:vcc:formula:[a-z0-9-]+$/),
    slug: z.string().regex(SLUG_RE).max(80),
    version: z.string().regex(SEMVER_RE),
    digest: digestSchema,
    registry: z.string().max(400).refine((v) => isSafeHttpsUrl(v, 400), {
      message: "formula.registry must be a safe https URL",
    }),
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
  issuedAt: z.string().refine(isValidUtcTimestamp, {
    message: "issuedAt is not a valid UTC timestamp",
  }),
  context: z.strictObject({
    surface: z.enum(["api", "web", "mcp", "graph"]),
    requestId: z.string().regex(REQUEST_ID_RE).optional(),
  }),
}).superRefine((st, ctx) => {
  // Cross-field semantic invariants (audit P1). None of these change the
  // canonical bytes of a valid statement; they only reject incoherent ones.

  // formula.id must be the URN of its own slug.
  if (st.formula.id !== `urn:vcc:formula:${st.formula.slug}`) {
    ctx.addIssue({
      code: "custom",
      path: ["formula", "id"],
      message: "formula.id must equal urn:vcc:formula:<slug>",
    });
  }

  // `datasets-used` is claimed IFF datasets are actually referenced (spec §).
  const claimsDatasets = st.attestation.claims.includes("datasets-used");
  const hasDatasets = st.datasets.length > 0;
  if (claimsDatasets !== hasDatasets) {
    ctx.addIssue({
      code: "custom",
      path: ["attestation", "claims"],
      message: "datasets-used must be claimed exactly when datasets are present",
    });
  }

  // Minimum claims each attestation type must carry.
  const required: Record<string, readonly string[]> = {
    execution: ["inputs-received", "formula-executed", "output-produced"],
    reproduction: ["formula-executed", "output-produced"],
    review: ["formula-executed"],
  };
  for (const claim of required[st.attestation.type] ?? []) {
    if (!st.attestation.claims.includes(claim as (typeof st.attestation.claims)[number])) {
      ctx.addIssue({
        code: "custom",
        path: ["attestation", "claims"],
        message: `${st.attestation.type} attestation must include claim "${claim}"`,
      });
    }
  }

  // A calculation must have at least one input and one output.
  if (Object.keys(st.calculation.inputs).length === 0) {
    ctx.addIssue({ code: "custom", path: ["calculation", "inputs"], message: "inputs must be non-empty" });
  }
  if (Object.keys(st.calculation.outputs).length === 0) {
    ctx.addIssue({ code: "custom", path: ["calculation", "outputs"], message: "outputs must be non-empty" });
  }
});

// ── Envelope ─────────────────────────────────────────────────────────────────

export const envelopeSchema = z
  .strictObject({
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
  })
  .superRefine((env, ctx) => {
    // Multi-signature: every signer must be distinct — a keyid may sign a
    // statement at most once in an envelope.
    const ids = env.signatures.map((s) => s.keyid);
    if (new Set(ids).size !== ids.length) {
      ctx.addIssue({ code: "custom", message: "signature keyids must be unique" });
    }
  });

// ── Issuer keyset ────────────────────────────────────────────────────────────

export const issuerKeySchema = z
  .strictObject({
    keyId: z.string().regex(KEY_ID_RE),
    algorithm: z.literal("ed25519"),
    // Raw 32-byte key → 44 base64 chars with padding.
    publicKey: z.string().regex(BASE64_STD_RE).min(42).max(46),
    status: z.enum(["active", "retired", "revoked", "compromised"]),
    validFrom: z.string().refine(isValidUtcTimestamp, { message: "validFrom invalid" }),
    validUntil: z.string().refine(isValidUtcTimestamp, { message: "validUntil invalid" }).nullable(),
  })
  .superRefine((k, ctx) => {
    if (k.validUntil !== null && k.validFrom > k.validUntil) {
      ctx.addIssue({ code: "custom", message: "validFrom must be <= validUntil" });
    }
  });

export const issuerKeySetSchema = z.strictObject({
  issuer: z.string().max(200).refine((v) => isSafeHttpsUrl(v, 200), {
    message: "keyset issuer must be a safe https URL",
  }),
  keys: z.array(issuerKeySchema).max(32),
});
