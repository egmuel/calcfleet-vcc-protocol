#!/usr/bin/env node
// Offline L1 verification of a single VCC receipt, using the standalone
// TypeScript verifier in verifiers/typescript (build it once with
// `npm ci && npm run build` in that directory).
//
// Usage:
//   node examples/verify-receipt.mjs <receipt.json> <keyset.json>
//
// <receipt.json> may be a `{ statement, envelope }` receipt (as in examples/)
// or a bare DSSE envelope. <keyset.json> may be a `{ keyset: ... }` document
// (as in vectors/test-key.json or /.well-known/vcc-issuer.json) or a bare keyset.
//
// Prints the verification AXES separately — there is deliberately no single
// "verified" boolean anywhere in VCC. Exit 0 iff cryptographicValidity.
// No network calls are made.

import { readFileSync } from "node:fs";
import { verifyVccEnvelope } from "../verifiers/typescript/dist/src/index.js";

const [receiptPath, keysetPath] = process.argv.slice(2);
if (!receiptPath || !keysetPath) {
  console.error("usage: node examples/verify-receipt.mjs <receipt.json> <keyset.json>");
  process.exit(2);
}

const receiptDoc = JSON.parse(readFileSync(receiptPath, "utf8"));
const envelope = receiptDoc.envelope ?? receiptDoc;
const keysetDoc = JSON.parse(readFileSync(keysetPath, "utf8"));
const keyset = keysetDoc.keyset ?? keysetDoc;

const res = await verifyVccEnvelope(envelope, keyset);

console.log("axes:");
console.log(`  signatureValid            : ${res.signatureValid}`);
console.log(`  statementIntact           : ${res.statementIntact}`);
console.log(`  issuerIdentityBound       : ${res.issuerIdentityBound}`);
console.log(`  keyValidAtIssuance        : ${res.keyValidAtIssuance}`);
console.log(`  issuerKeyStatus           : ${res.issuerKeyStatus}`);
console.log(`  certificateStatus         : ${res.certificateStatus}`);
console.log(`  cryptographicValidity     : ${res.cryptographicValidity}`);
console.log(`  trustedAtVerificationTime : ${res.trustedAtVerificationTime}`);
console.log(`checks: ${JSON.stringify(res.checks)}`);
if (res.errors.length > 0) {
  console.log(`errors: ${JSON.stringify(res.errors)}`);
}
process.exit(res.cryptographicValidity ? 0 : 1);
