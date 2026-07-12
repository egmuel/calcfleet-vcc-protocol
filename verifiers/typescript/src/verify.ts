// Standalone VCC L1 verifier (sdk/typescript).
//
// This is the SAME L1 logic as the reference `src/lib/vcc/verify-l1.ts`, but
// re-expressed entirely on Web Platform crypto (crypto.subtle) — so it runs
// OFFLINE in Node 22 AND in the browser with zero network calls: the receipt
// and the issuer's PUBLIC key are all it touches. It is adapted from the
// reference `src/lib/vcc/verify-client.ts`, copied here with its dependencies so
// this package imports NOTHING from CalcFleet site code.
//
// It is byte-for-byte equivalent to the reference L1 on every golden and
// negative vector (see conformance-runner.ts). The JCS canonicalization, the
// DSSE PAE, the schemas and the check ordering are shared with the reference,
// not re-derived.
//
// It never throws on untrusted input: every outcome is a result object with the
// SAME per-check booleans and axes the reference returns.

import { canonicalize } from "./canonicalize.js";
import {
  VCC_CALC_URN_PREFIX,
  VCC_MAX_CERTIFICATE_BYTES,
  VCC_PAYLOAD_TYPE,
} from "./constants.js";
import { envelopeSchema, isValidUtcTimestamp, statementSchema } from "./schemas.js";
import type {
  VccCertificateStatus,
  VccEnvelope,
  VccIssuerKeySet,
  VccKeyStatus,
  VccL1Checks,
  VccL1VerificationResult,
  VccSignatureResult,
  VccStatement,
} from "./types.js";

/** Reject structures deeper/larger than this before schema validation runs. */
const MAX_STATEMENT_DEPTH = 64;
const MAX_STATEMENT_NODES = 20_000;

/**
 * Depth + node-count guard for parsed JSON, done ITERATIVELY with an explicit
 * stack so the guard itself can never overflow the call stack it protects. A
 * hostile 64KB payload can nest thousands of objects; this caps it before the
 * recursive schema/canonicalization logic ever touches it.
 */
function exceedsStructuralLimits(root: unknown): boolean {
  let nodes = 0;
  const stack: Array<[unknown, number]> = [[root, 1]];
  while (stack.length > 0) {
    const top = stack.pop() as [unknown, number];
    const v = top[0];
    const depth = top[1];
    if (depth > MAX_STATEMENT_DEPTH) return true;
    if (++nodes > MAX_STATEMENT_NODES) return true;
    if (Array.isArray(v)) {
      for (const e of v) stack.push([e, depth + 1]);
    } else if (v !== null && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      for (const k of Object.keys(obj)) stack.push([obj[k], depth + 1]);
    }
  }
  return false;
}

/** A loosely-typed key record read defensively from an untrusted keyset. */
type LooseKey = Record<string, unknown>;

/**
 * Coerce an untrusted keyset into {issuer, keys[]} without ever throwing. A
 * malformed keyset (not an object, `keys` not an array, non-object entries)
 * degrades to "no usable keys" rather than crashing (audit P0#3). We do NOT
 * enforce the key algorithm/status here — the per-check logic reports those, so
 * a deliberately non-ed25519 keyset still yields keyKnown=true,
 * algorithmSupported=false as before.
 */
function coerceKeyset(keys: unknown): { issuer: string | null; keys: LooseKey[] } {
  if (keys === null || typeof keys !== "object") return { issuer: null, keys: [] };
  const k = keys as Record<string, unknown>;
  const issuer = typeof k.issuer === "string" ? k.issuer : null;
  const arr = Array.isArray(k.keys)
    ? (k.keys.filter((e) => e !== null && typeof e === "object") as LooseKey[])
    : [];
  return { issuer, keys: arr };
}

/** True when this runtime can verify Ed25519 offline via WebCrypto. */
export function webcryptoEd25519Available(): boolean {
  return (
    typeof globalThis.crypto !== "undefined" &&
    typeof globalThis.crypto.subtle !== "undefined" &&
    typeof globalThis.crypto.subtle.verify === "function" &&
    typeof globalThis.crypto.subtle.importKey === "function" &&
    typeof globalThis.crypto.subtle.digest === "function"
  );
}

// ── Browser-safe primitives (no Buffer, no node:crypto) ──────────────────────

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_LOOKUP: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_CHARS.length; i++) t[B64_CHARS.charCodeAt(i)] = i;
  return t;
})();

/** Standard base64 → bytes. Returns null on any non-strict/invalid input. */
function base64ToBytesStrict(b64: string): Uint8Array | null {
  const len = b64.length;
  if (len === 0 || len % 4 !== 0) return null;
  let pad = 0;
  if (b64.charCodeAt(len - 1) === 61) pad++; // '='
  if (b64.charCodeAt(len - 2) === 61) pad++;
  const out = new Uint8Array((len / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < len; i += 4) {
    const c0 = b64.charCodeAt(i);
    const c1 = b64.charCodeAt(i + 1);
    const c2 = b64.charCodeAt(i + 2);
    const c3 = b64.charCodeAt(i + 3);
    const s0 = c0 < 128 ? B64_LOOKUP[c0] : -1;
    const s1 = c1 < 128 ? B64_LOOKUP[c1] : -1;
    const isPad2 = c2 === 61 && i + 4 === len;
    const isPad3 = c3 === 61 && i + 4 === len;
    const s2 = isPad2 ? 0 : c2 < 128 ? B64_LOOKUP[c2] : -1;
    const s3 = isPad3 ? 0 : c3 < 128 ? B64_LOOKUP[c3] : -1;
    if (s0 < 0 || s1 < 0 || s2 < 0 || s3 < 0) return null;
    // A padded group must not carry bits that the padding claims are absent.
    if (isPad2 && (s1 & 0x0f) !== 0) return null;
    if (isPad3 && !isPad2 && (s2 & 0x03) !== 0) return null;
    const triple = (s0 << 18) | (s1 << 12) | (s2 << 6) | s3;
    out[o++] = (triple >> 16) & 0xff;
    if (!isPad2) out[o++] = (triple >> 8) & 0xff;
    if (!isPad3) out[o++] = triple & 0xff;
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let out = "";
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    out += B64_CHARS[b0 >> 2];
    out += B64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < len ? B64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < len ? B64_CHARS[b2 & 0x3f] : "=";
  }
  return out;
}

/**
 * Strict payload decode, mirroring the reference envelope decode: the bytes must
 * round-trip back to the exact input base64 (rejects loose / whitespace /
 * base64url variants), be non-empty, and within the size cap.
 */
function decodePayloadStrict(payload: string): Uint8Array | null {
  const decoded = base64ToBytesStrict(payload);
  if (decoded === null || decoded.length === 0) return null;
  if (bytesToBase64(decoded) !== payload) return null;
  if (decoded.length > VCC_MAX_CERTIFICATE_BYTES) return null;
  return decoded;
}

/**
 * DSSE Pre-Authentication Encoding, identical to the reference buildPae:
 * "DSSEv1" SP len(type) SP type SP len(payload) SP payload
 */
function buildPaeClient(payloadType: string, payload: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  const typeBytes = enc.encode(payloadType);
  const headerBytes = enc.encode(
    `DSSEv1 ${typeBytes.length} ${payloadType} ${payload.length} `,
  );
  const out = new Uint8Array(headerBytes.length + payload.length);
  out.set(headerBytes, 0);
  out.set(payload, headerBytes.length);
  return out;
}

async function sha256HexClient(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/**
 * hex64 content id of a statement, ignoring any present subject.id — identical
 * semantics to the reference computeStatementIdHex (delete subject.id, JCS,
 * sha-256), only the hash is crypto.subtle instead of node:crypto.
 */
async function computeStatementIdHexClient(statement: VccStatement): Promise<string> {
  const clone = structuredClone(statement) as { subject: { id?: string; kind: string } };
  delete clone.subject.id;
  const bytes = new TextEncoder().encode(canonicalize(clone));
  return sha256HexClient(bytes);
}

/** Extract the hex64 part of a subject id, or null if malformed (mirror). */
function idHexFromSubjectId(subjectId: string): string | null {
  if (!subjectId.startsWith(VCC_CALC_URN_PREFIX)) return null;
  const hex = subjectId.slice(VCC_CALC_URN_PREFIX.length);
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

/** Ed25519 verify over PAE via WebCrypto. Any failure/exception → false. */
async function verifyEd25519(
  publicKeyRawB64: string,
  data: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  if (sig.length !== 64) return false;
  const rawPub = base64ToBytesStrict(publicKeyRawB64);
  if (rawPub === null || rawPub.length !== 32 || bytesToBase64(rawPub) !== publicKeyRawB64) {
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      rawPub as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      sig as BufferSource,
      data as BufferSource,
    );
  } catch {
    return false;
  }
}

/**
 * L1 verification, offline. Same result shape as the reference
 * verify-l1.ts::verifyVccEnvelope, so callers (and the golden/negative vectors)
 * get byte-identical answers whether the check ran on the reference server or
 * here.
 */
export async function verifyVccEnvelope(
  envelope: unknown,
  keys: VccIssuerKeySet,
  opts?: { certificateStatus?: VccCertificateStatus | null },
): Promise<VccL1VerificationResult> {
  const certificateStatus = opts?.certificateStatus ?? "unknown";
  try {
    return await verifyVccEnvelopeInner(envelope, keys, certificateStatus);
  } catch (err) {
    // The verifier MUST NOT throw on untrusted input (audit P0#3). Any escape
    // here is a well-formed, all-false result — never an exception.
    return {
      cryptographicValidity: false,
      signatureValid: false,
      statementIntact: false,
      issuerKeyStatus: "unknown",
      certificateStatus,
      issuerIdentityBound: false,
      keyValidAtIssuance: false,
      signatureResults: [],
      trustedAtVerificationTime: false,
      checks: {
        envelopeSchema: false,
        payloadType: false,
        payloadDecodes: false,
        statementSchema: false,
        canonicalization: false,
        statementId: false,
        keyKnown: false,
        algorithmSupported: false,
        signature: false,
      },
      errors: [
        `internal verifier error: ${err instanceof Error ? err.message : String(err)}`,
      ],
    };
  }
}

async function verifyVccEnvelopeInner(
  envelope: unknown,
  keys: unknown,
  certificateStatus: VccCertificateStatus | "unknown",
): Promise<VccL1VerificationResult> {
  const checks: VccL1Checks = {
    envelopeSchema: false,
    payloadType: false,
    payloadDecodes: false,
    statementSchema: false,
    canonicalization: false,
    statementId: false,
    keyKnown: false,
    algorithmSupported: false,
    signature: false,
  };
  const errors: string[] = [];
  let statement: VccStatement | undefined;
  let idHex: string | undefined;
  let issuerKeyStatus: VccL1VerificationResult["issuerKeyStatus"] = "unknown";
  let issuerIdentityBound = false;
  let keyValidAtIssuance = false;
  const signatureResults: VccSignatureResult[] = [];

  const fail = (msg: string): void => {
    errors.push(msg);
  };

  // 1. Envelope shape (strict: extra fields refused, keyids unique).
  const env = envelopeSchema.safeParse(envelope);
  if (env.success) {
    checks.envelopeSchema = true;
  } else {
    fail("envelope does not match the DSSE envelope schema");
  }

  // 2. payloadType binding.
  const typedEnvelope = env.success ? (env.data as VccEnvelope) : null;
  if (typedEnvelope) {
    checks.payloadType = typedEnvelope.payloadType === VCC_PAYLOAD_TYPE;
    if (!checks.payloadType) fail("unsupported payloadType");
  }

  // 3. Strict payload decode.
  let payloadBytes: Uint8Array | null = null;
  if (typedEnvelope && checks.payloadType) {
    payloadBytes = decodePayloadStrict(typedEnvelope.payload);
    if (payloadBytes) {
      checks.payloadDecodes = true;
    } else {
      fail("payload is not strict base64 within size limits");
    }
  }

  // 4. Statement schema (strict), guarded by a depth/size cap so a hostile
  //    deeply-nested payload can't overflow the stack during validation.
  if (payloadBytes) {
    try {
      // Fatal UTF-8 decode: an invalid byte sequence is REJECTED, not silently
      // replaced with U+FFFD. This matches Python's strict bytes.decode("utf-8")
      // so a payload that is not well-formed UTF-8 fails identically in both.
      const parsed: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes),
      );
      if (exceedsStructuralLimits(parsed)) {
        fail("statement structure is too deep or too large");
      } else {
        const st = statementSchema.safeParse(parsed);
        if (st.success) {
          statement = st.data as VccStatement;
          checks.statementSchema = true;
        } else {
          fail("payload JSON is not a valid v0.2 statement");
        }
      }
    } catch {
      fail("payload is not valid JSON");
    }
  }

  // 5. Canonicalization: the payload MUST be the JCS bytes of the statement.
  if (statement && payloadBytes) {
    let canonical: string | null = null;
    try {
      canonical = canonicalize(statement);
    } catch {
      canonical = null; // e.g. a lone surrogate — not canonicalizable, not a crash
    }
    checks.canonicalization =
      canonical !== null && canonical === new TextDecoder().decode(payloadBytes);
    if (!checks.canonicalization) {
      fail("payload bytes are not the canonical (RFC 8785) form of the statement");
    }
  }

  // 6. Content-addressed id.
  if (statement) {
    let expected: string | null = null;
    try {
      expected = await computeStatementIdHexClient(statement);
    } catch {
      expected = null;
    }
    const actual = idHexFromSubjectId(statement.subject.id);
    checks.statementId = expected !== null && actual !== null && expected === actual;
    if (checks.statementId) {
      idHex = expected ?? undefined;
    } else {
      fail("subject.id does not match the statement content");
    }
  }

  // Issuer binding (axis 2): the supplied keyset must belong to the issuer named
  // in the statement. A valid signature by an UNBOUND keyset proves nothing.
  const keyset = coerceKeyset(keys);
  if (keyset.keys.length === 0 && env.success) {
    fail("issuer keyset is empty or malformed");
  }
  const issuerField = (statement as Record<string, unknown> | undefined)?.issuer;
  const statementIssuerId =
    issuerField !== null &&
    typeof issuerField === "object" &&
    typeof (issuerField as { id?: unknown }).id === "string"
      ? ((issuerField as { id: string }).id)
      : null;
  if (statementIssuerId !== null && keyset.issuer !== null && keyset.issuer === statementIssuerId) {
    issuerIdentityBound = true;
  } else if (statement) {
    fail("keyset issuer is not bound to the statement's issuer.id");
  }

  // 7-9. Multi-signature: EVERY signature must resolve to a known ed25519 key
  //       and verify over the DSSE PAE. A single bad signature fails the check —
  //       a bogus signature cannot ride along a valid one, and a valid second
  //       signature is not ignored because the first is invalid (audit P1).
  if (typedEnvelope && payloadBytes) {
    const pae = buildPaeClient(VCC_PAYLOAD_TYPE, payloadBytes);
    for (const sig of typedEnvelope.signatures) {
      const key = keyset.keys.find((k) => k.keyId === sig.keyid) ?? null;
      const keyKnown = key !== null;
      const algorithmSupported = keyKnown && key.algorithm === "ed25519";
      let valid = false;
      if (algorithmSupported && typeof key.publicKey === "string") {
        const sigBytes = base64ToBytesStrict(sig.sig);
        const sigStrict = sigBytes !== null && bytesToBase64(sigBytes) === sig.sig;
        valid =
          sigStrict && (await verifyEd25519(key.publicKey, pae, sigBytes as Uint8Array));
      }
      signatureResults.push({ keyid: sig.keyid, keyKnown, algorithmSupported, valid });
    }

    checks.keyKnown = signatureResults.length > 0 && signatureResults.every((r) => r.keyKnown);
    checks.algorithmSupported =
      signatureResults.length > 0 && signatureResults.every((r) => r.algorithmSupported);
    checks.signature =
      signatureResults.length > 0 && signatureResults.every((r) => r.valid);
    if (!checks.keyKnown) fail("a signature keyid is not in the supplied keyset");
    if (checks.keyKnown && !checks.algorithmSupported) fail("unsupported signature algorithm");
    if (checks.algorithmSupported && !checks.signature) fail("an Ed25519 signature does not verify");

    // The primary (first) signature's key drives status + temporal validity.
    const primary = keyset.keys.find((k) => k.keyId === typedEnvelope.signatures[0].keyid) ?? null;
    if (primary) {
      issuerKeyStatus =
        typeof primary.status === "string"
          ? (primary.status as VccKeyStatus)
          : "unknown";
      if (statement) {
        const issuedAt = (statement as { issuedAt?: unknown }).issuedAt;
        const vf = primary.validFrom;
        const vu = primary.validUntil;
        keyValidAtIssuance =
          typeof issuedAt === "string" &&
          typeof vf === "string" &&
          isValidUtcTimestamp(vf) &&
          vf <= issuedAt &&
          (vu === null ||
            (typeof vu === "string" && isValidUtcTimestamp(vu) && issuedAt <= vu));
        if (!keyValidAtIssuance) {
          fail("signing key was not valid at the statement's issuedAt");
        }
      }
    }
  }

  const cryptographicValidity = Object.values(checks).every(Boolean);

  // Assurance-model §5.1: signature validity and statement integrity are two
  // ORTHOGONAL axes, projected purely from the checks already computed above.
  const signatureValid = checks.signature;
  const statementIntact =
    checks.payloadDecodes &&
    checks.statementSchema &&
    checks.canonicalization &&
    checks.statementId;

  const trustedAtVerificationTime =
    cryptographicValidity &&
    issuerIdentityBound &&
    keyValidAtIssuance &&
    issuerKeyStatus === "active" &&
    (certificateStatus === "valid" || certificateStatus === "unknown");

  const result: VccL1VerificationResult = {
    cryptographicValidity,
    signatureValid,
    statementIntact,
    issuerKeyStatus,
    certificateStatus,
    issuerIdentityBound,
    keyValidAtIssuance,
    signatureResults,
    trustedAtVerificationTime,
    checks,
    errors,
  };
  if (statement) result.statement = statement;
  if (idHex) result.idHex = idHex;
  return result;
}
