// Cross-language conformance runner for the standalone TypeScript VCC L1
// verifier (sdk/typescript).
//
// Loads the SAME committed corpus the in-repo conformance suite uses
// (`vectors/`), runs THIS independent verifier over every positive
// and negative vector, and asserts the result matches the pinned outcome — the
// outcome the reference verifier is pinned to in
// `src/lib/vcc/conformance.test.ts`. It is the direct TypeScript analog of
// `sdk/python/conformance_runner.py`.
//
// This is the machine-checkable half of the §50 "Interoperable" gate: an
// independent, site-decoupled verifier producing the same result on the same
// vectors. OFFLINE — only local files, no network.
//
// Exit 0 iff every vector matches. Prints a per-vector table and a summary.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalize, canonicalBytes } from "./src/canonicalize.js";
import { VCC_CALC_URN_PREFIX } from "./src/constants.js";
import { verifyVccEnvelope } from "./src/verify.js";
import type {
  VccCertificateStatus,
  VccIssuerKey,
  VccIssuerKeySet,
  VccStatement,
} from "./src/types.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the committed corpus at `vectors` by walking up from this
 * file. This works whether the runner executes from source (sdk/typescript/) or
 * from the compiled `dist/`, so the "path relative to ../../vectors"
 * contract holds without hard-coding a level count.
 */
function findVectorDir(start: string): string {
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, "vectors");
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    "could not locate vectors above " + start +
      " — run this from a checkout of the protocol repo",
  );
}

const VECTOR_DIR = findVectorDir(HERE);
const NEG_DIR = join(VECTOR_DIR, "negative");
const KEYSET_FILE = join(VECTOR_DIR, "test-key.json");

function loadJson(p: string): any {
  return JSON.parse(readFileSync(p, "utf8"));
}

function baseKeyset(): VccIssuerKeySet {
  return loadJson(KEYSET_FILE).keyset as VccIssuerKeySet;
}

/** Mirror keysetFor() in conformance.test.ts / keyset_for() in the Python runner. */
function keysetFor(name: string | null | undefined): VccIssuerKeySet {
  const ks = baseKeyset();
  if (name === "revoked") {
    return {
      issuer: ks.issuer,
      keys: ks.keys.map((k: VccIssuerKey) => ({
        ...k,
        status: "revoked" as VccIssuerKey["status"],
      })),
    };
  }
  if (name === "wrong-algorithm") {
    return {
      issuer: ks.issuer,
      keys: ks.keys.map((k: VccIssuerKey) => ({
        ...k,
        algorithm: "rsa" as VccIssuerKey["algorithm"],
      })),
    };
  }
  return ks;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}

async function computeStatementIdHex(statement: VccStatement): Promise<string> {
  const clone = structuredClone(statement) as { subject: { id?: string } };
  delete clone.subject.id;
  return sha256Hex(canonicalBytes(clone));
}

type Result = [ok: boolean, detail: string];

// ── Positive corpus ───────────────────────────────────────────────────────────

async function checkPositive(file: string): Promise<Result> {
  const v = loadJson(file);
  const exp = v.expected?.l1 ?? {};
  const res = await verifyVccEnvelope(v.envelope, baseKeyset());

  const problems: string[] = [];
  if (exp.cryptographicValidity != null && res.cryptographicValidity !== exp.cryptographicValidity) {
    problems.push(
      `cryptographicValidity=${res.cryptographicValidity} want ${exp.cryptographicValidity}`,
    );
  }
  if (
    exp.trustedAtVerificationTime != null &&
    res.trustedAtVerificationTime !== exp.trustedAtVerificationTime
  ) {
    problems.push(
      `trustedAtVerificationTime=${res.trustedAtVerificationTime} want ${exp.trustedAtVerificationTime}`,
    );
  }
  if (res.errors.length > 0) {
    problems.push(`errors not empty: ${JSON.stringify(res.errors)}`);
  }
  if (!res.cryptographicValidity && exp.cryptographicValidity !== false) {
    const failed = Object.entries(res.checks)
      .filter(([, val]) => !val)
      .map(([k]) => k);
    problems.push(`unexpected failed checks: ${JSON.stringify(failed)}`);
  }
  return [problems.length === 0, problems.join("; ")];
}

// ── Negative corpus ────────────────────────────────────────────────────────────

async function checkNegative(file: string): Promise<Result> {
  const v = loadJson(file);
  const exp = v.expected;
  const ks = keysetFor(exp.keyset);
  const certStatus = (exp.certificateStatus as VccCertificateStatus | undefined) ?? null;
  const res = await verifyVccEnvelope(v.envelope, ks, { certificateStatus: certStatus });
  const checks = res.checks as unknown as Record<string, boolean>;

  const problems: string[] = [];

  // Every pinned failed check must be false in our result.
  for (const check of exp.l1FailedChecks ?? []) {
    if (checks[check] !== false) {
      problems.push(`check ${check}=${checks[check]} want false`);
    }
  }

  if (exp.l1CryptographicValidity != null) {
    if (res.cryptographicValidity !== exp.l1CryptographicValidity) {
      problems.push(
        `cryptographicValidity=${res.cryptographicValidity} want ${exp.l1CryptographicValidity}`,
      );
    }
    if (exp.l1CryptographicValidity === false && res.errors.length === 0) {
      problems.push("expected non-empty errors");
    }
  }

  if (exp.l1TrustedAtVerificationTime != null) {
    if (res.trustedAtVerificationTime !== exp.l1TrustedAtVerificationTime) {
      problems.push(
        `trustedAtVerificationTime=${res.trustedAtVerificationTime} want ${exp.l1TrustedAtVerificationTime}`,
      );
    }
  }

  return [problems.length === 0, problems.join("; ")];
}

// ── JCS byte-parity: the load-bearing interoperability check ──────────────────
// Each positive vector carries the reference-produced canonical string
// (`canonicalStatement`) and its sha256. This verifier's JCS must reproduce BOTH
// exactly, and the content-addressed statementId must match subject.id.

async function checkJcsParity(file: string): Promise<Result> {
  const v = loadJson(file);
  const st = v.statement as VccStatement;
  const problems: string[] = [];
  if ("canonicalStatement" in v && canonicalize(st) !== v.canonicalStatement) {
    problems.push("JCS bytes differ from reference canonicalStatement");
  }
  if ("canonicalStatementSha256" in v) {
    const sha = await sha256Hex(canonicalBytes(st));
    if (sha !== v.canonicalStatementSha256) {
      problems.push("canonical sha256 differs from pinned");
    }
  }
  const idHex = await computeStatementIdHex(st);
  if (VCC_CALC_URN_PREFIX + idHex !== st.subject.id) {
    problems.push("statementId differs from subject.id");
  }
  return [problems.length === 0, problems.join("; ")];
}

async function main(): Promise<number> {
  const positives = readdirSync(VECTOR_DIR)
    .filter((f) => f.endsWith(".json") && f !== "test-key.json")
    .sort()
    .map((f) => join(VECTOR_DIR, f));
  const negatives = readdirSync(NEG_DIR)
    .filter((f) => f.endsWith(".json") && f !== "index.json")
    .sort()
    .map((f) => join(NEG_DIR, f));

  let passed = 0;
  let total = 0;
  const rows: Array<[kind: string, name: string, ok: boolean, detail: string]> = [];

  let jcsAllOk = true;
  for (const f of positives) {
    const [ok, detail] = await checkJcsParity(f);
    jcsAllOk = jcsAllOk && ok;
    total++;
    if (ok) passed++;
    rows.push(["JCS", basename(f), ok, detail]);
  }
  for (const f of positives) {
    const [ok, detail] = await checkPositive(f);
    total++;
    if (ok) passed++;
    rows.push(["POS", basename(f), ok, detail]);
  }
  for (const f of negatives) {
    const [ok, detail] = await checkNegative(f);
    total++;
    if (ok) passed++;
    rows.push(["NEG", basename(f), ok, detail]);
  }

  const width = Math.max(...rows.map((r) => r[1].length));
  console.log("VCC cross-language conformance — TypeScript SDK verifier vs pinned reference outcome");
  console.log(`corpus: ${VECTOR_DIR}`);
  console.log("-".repeat(width + 24));
  for (const [kind, name, ok, detail] of rows) {
    const mark = ok ? "PASS" : "FAIL";
    let line = `[${kind}] ${name.padEnd(width)}  ${mark}`;
    if (!ok) line += `  <- ${detail}`;
    console.log(line);
  }
  console.log("-".repeat(width + 24));
  console.log(`MATCH: ${passed}/${total} checks match the pinned (reference) outcome`);
  console.log(`JCS byte-for-byte parity with reference on all positives: ${jcsAllOk}`);
  return passed === total ? 0 : 1;
}

function basename(p: string): string {
  return p.split("/").pop() ?? p;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err);
    process.exit(2);
  });
