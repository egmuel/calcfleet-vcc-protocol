// RFC 8785 (JCS) canonicalization — STANDALONE COPY (sdk/typescript).
//
// Byte-for-byte identical algorithm to the reference
// `src/lib/vcc/canonicalize.ts`, copied here so this package imports nothing
// from CalcFleet site code. The only local change: instead of throwing the
// site's `VccError`, non-canonicalizable input throws a plain `Error` — the
// verifier catches it either way and turns it into a failed check.
//
// For data that is already plain JSON (null, boolean, finite number, string,
// array, plain object), JCS is: object keys sorted by UTF-16 code units,
// primitives serialized exactly as ECMAScript JSON.stringify does (shortest
// round-trip numbers, minimal string escaping). We therefore delegate primitive
// serialization to JSON.stringify — which IS the JCS algorithm in a conforming
// engine — and handle ordering + strict input validation here.
//
// Anything that could serialize ambiguously is rejected up front: undefined,
// functions, symbols, bigint, non-finite numbers, and non-plain objects (Date,
// Map, class instances, objects with toJSON). Silent dropping or coercion has no
// place under a signature.

function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/**
 * True if the string carries a UTF-16 lone surrogate (a high surrogate not
 * followed by a low one, or a stray low surrogate). Such a string has no valid
 * UTF-8 encoding, so it is NOT canonicalizable — we reject it rather than let
 * JSON.stringify silently emit a `\udXXX` escape (which the Python verifier
 * cannot encode: this is where the two verifiers must agree, and where the
 * Python side used to throw UnicodeEncodeError).
 */
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i++; // valid surrogate pair — skip the low half
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true; // lone low surrogate
    }
  }
  return false;
}

function assertCanonicalizable(value: unknown, path: string): void {
  if (value === null) return;
  const t = typeof value;
  if (t === "boolean") return;
  if (t === "string") {
    if (hasLoneSurrogate(value as string)) {
      throw new Error(`lone surrogate at ${path}`);
    }
    return;
  }
  if (t === "number") {
    if (!Number.isFinite(value as number)) {
      throw new Error(`non-finite number at ${path}`);
    }
    return;
  }
  if (t === "undefined" || t === "function" || t === "symbol" || t === "bigint") {
    throw new Error(`${t} at ${path}`);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      // Array holes / undefined elements must not silently become null.
      if (!(i in value) || value[i] === undefined) {
        throw new Error(`undefined element at ${path}[${i}]`);
      }
      assertCanonicalizable(value[i], `${path}[${i}]`);
    }
    return;
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    if (!isPlainObject(obj)) {
      throw new Error(`non-plain object at ${path}`);
    }
    if ("toJSON" in obj && typeof obj.toJSON === "function") {
      throw new Error(`object with toJSON at ${path}`);
    }
    for (const key of Object.keys(obj)) {
      if (obj[key] === undefined) {
        // JSON.stringify would DROP this property — reject instead.
        throw new Error(`undefined property at ${path}.${key}`);
      }
      assertCanonicalizable(obj[key], `${path}.${key}`);
    }
    return;
  }
  throw new Error(`unsupported ${t} at ${path}`);
}

function serialize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    // Primitives: JSON.stringify implements the JCS rules (ES number ToString,
    // minimal escaping with lowercase \u00xx for control chars, -0 → "0").
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => serialize(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  // Default Array.sort compares by UTF-16 code units — exactly JCS ordering.
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k])}`);
  return `{${parts.join(",")}}`;
}

/** JCS canonical form as a string. Throws on non-canonicalizable input. */
export function canonicalize(value: unknown): string {
  assertCanonicalizable(value, "$");
  return serialize(value);
}

/** JCS canonical form as UTF-8 bytes. */
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
