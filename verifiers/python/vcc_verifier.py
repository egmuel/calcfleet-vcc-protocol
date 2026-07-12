"""Independent VCC v0.2 L1 verifier — Python, standalone, OFFLINE.

This is the SECOND independent verifier required by the "Interoperable" gate
(master-prompt-vcc-first §50): a from-scratch implementation, in a different
language, that MUST produce the SAME result as the TypeScript reference
(`src/lib/vcc/verify-l1.ts`) on every conformance vector.

Vendor-independence (§49): it reads only local files, imports no CalcFleet code,
and makes NO network calls. The caller supplies the keyset (from the published
`.well-known/vcc-issuer.json` or `vectors/test-key.json`).

What L1 verifies (mirrors verify-l1.ts, same nine per-check booleans):

  1. envelopeSchema     — DSSE envelope shape, strict (no extra fields)
  2. payloadType        — bound to application/vnd.vcc.statement+json;version=0.2
  3. payloadDecodes     — strict standard base64 within the size cap
  4. statementSchema    — v0.2 statement shape, strict
  5. canonicalization   — payload bytes ARE the JCS (RFC 8785) form of the statement
  6. statementId        — subject.id == sha256 of the statement sans subject.id
  7. keyKnown           — signature keyid is in the supplied keyset
  8. algorithmSupported — key algorithm is ed25519
  9. signature          — Ed25519 verifies over the DSSE PAE

It never throws on untrusted input: every outcome is a result object with
per-check booleans, so callers can render exactly what failed.

Dependencies: Python stdlib + `cryptography` (Ed25519 only).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ── Constants (mirror src/lib/vcc/constants.ts) ──────────────────────────────

VCC_SPEC_VERSION = "0.2"
VCC_PAYLOAD_TYPE = "application/vnd.vcc.statement+json;version=0.2"
VCC_STATEMENT_TYPE = "https://vcc.dev/statement/calculation/v0.2"
VCC_NUMERIC_PROFILE = "vcc-decimal-v1"
VCC_RUNTIME_PROFILE = "node-deterministic-v1"
VCC_CALC_URN_PREFIX = "urn:vcc:calculation:sha256:"
VCC_MAX_CERTIFICATE_BYTES = 64 * 1024

# ── Regex (mirror src/lib/vcc/schemas.ts) ────────────────────────────────────

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
ISSUED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIMAL_VALUE_RE = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?$")
BASE64_STD_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
SHORT_STRING_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _/.,:()%+–—-]{0,63}$")
UNIT_RE = re.compile(r"^[%A-Za-z][%A-Za-z0-9/·°²³-]{0,15}$")
FORMULA_ID_RE = re.compile(r"^urn:vcc:formula:[a-z0-9-]+$")
DATASET_ID_RE = re.compile(r"^urn:vcc:dataset:[a-z0-9-]+$")
SUBJECT_ID_RE = re.compile(r"^urn:vcc:calculation:sha256:[0-9a-f]{64}$")
CALC_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
ATTESTATION_TYPES = {"execution", "reproduction", "review"}
ATTESTATION_CLAIMS = {
    "inputs-received",
    "formula-executed",
    "datasets-used",
    "numeric-profile-applied",
    "output-produced",
}
NUMERIC_KINDS = {"integer", "decimal", "percent", "ratio", "money", "duration"}
KEY_STATUSES = {"active", "retired", "revoked", "compromised"}


# ── RFC 8785 JCS canonicalization ────────────────────────────────────────────
#
# Mirrors src/lib/vcc/canonicalize.ts. For plain JSON that is already
# strings/bools/None/finite-numbers/arrays/objects:
#   - object keys sorted by UTF-16 code units (Python sorts str by Unicode code
#     point, which equals the UTF-16 order for the BMP; every key in the VCC
#     model is ASCII, so the two orderings are identical here),
#   - strings serialized with JSON minimal escaping,
#   - numbers serialized with the ECMAScript "shortest round-trip" form.
#
# The statement grammar never puts a bare JSON number under the signature
# (every numeric quantity is a decimal STRING inside a typed value). We still
# implement number serialization faithfully for robustness, matching V8's
# Number.prototype.toString for the integers/short decimals that appear
# (scale, array indices are not serialized). Non-finite numbers are rejected.


def _utf16_units(s: str) -> list[int]:
    """The UTF-16 code units of a string (surrogate-aware), as ints."""
    data = s.encode("utf-16-be")
    return [(data[i] << 8) | data[i + 1] for i in range(0, len(data), 2)]


class CanonicalizationError(ValueError):
    pass


def _serialize_string(s: str) -> str:
    # json.dumps with ensure_ascii=False + no spaces produces the same minimal
    # escaping JCS/ECMAScript require (", \, and control chars as \u00xx / \b\t
    # \n\f\r); all other chars, including non-ASCII, verbatim.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))


def _serialize_number(n: float | int) -> str:
    import math

    if isinstance(n, bool):  # bool is a subclass of int — reject as ambiguous
        raise CanonicalizationError("boolean where number expected")
    if isinstance(n, int):
        return str(n)
    if not math.isfinite(n):
        raise CanonicalizationError("non-finite number")
    # ECMAScript Number ToString "shortest round-trip". Python's repr(float)
    # is also shortest round-trip; for integral floats JS drops the ".0".
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    return repr(n)


def canonicalize(value: Any) -> str:
    """JCS canonical form as a `str`. Raises CanonicalizationError on ambiguous input."""

    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str):
            return _serialize_string(v)
        if isinstance(v, (int, float)):
            return _serialize_number(v)
        if isinstance(v, list):
            return "[" + ",".join(ser(e) for e in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v.keys(), key=_utf16_units)
            parts = [f"{_serialize_string(k)}:{ser(v[k])}" for k in keys]
            return "{" + ",".join(parts) + "}"
        raise CanonicalizationError(f"unsupported value of type {type(v).__name__}")

    return ser(value)


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Statement identity (mirror src/lib/vcc/statement.ts) ──────────────────────


def compute_statement_id_hex(statement: dict[str, Any]) -> str:
    """hex64 content id of a statement, ignoring any present subject.id."""
    clone = json.loads(json.dumps(statement))  # deep copy
    clone.get("subject", {}).pop("id", None)
    return sha256_hex(canonical_bytes(clone))


def id_hex_from_subject_id(subject_id: str) -> str | None:
    if not subject_id.startswith(VCC_CALC_URN_PREFIX):
        return None
    hex_part = subject_id[len(VCC_CALC_URN_PREFIX) :]
    return hex_part if SHA256_HEX.match(hex_part) else None


# ── DSSE PAE (mirror src/lib/vcc/envelope.ts) ─────────────────────────────────


def build_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    header = f"DSSEv1 {len(type_bytes)} {payload_type} {len(payload)} ".encode("utf-8")
    return header + payload


def decode_envelope_payload(payload_b64: str) -> bytes | None:
    """Strict standard-base64 decode: re-encoding must reproduce the input
    exactly, and the size is capped. Returns None on any violation (the TS
    verifier throws here and records payloadDecodes=false)."""
    try:
        decoded = base64.b64decode(payload_b64, validate=True)
    except Exception:
        return None
    if len(decoded) == 0:
        return None
    if base64.b64encode(decoded).decode("ascii") != payload_b64:
        return None
    if len(decoded) > VCC_MAX_CERTIFICATE_BYTES:
        return None
    return decoded


# ── Ed25519 (mirror src/lib/vcc/keys.ts) ──────────────────────────────────────


def verify_signature_raw(public_key_raw_b64: str, data: bytes, sig: bytes) -> bool:
    if len(sig) != 64:
        return False
    try:
        raw = base64.b64decode(public_key_raw_b64, validate=True)
    except Exception:
        return False
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != public_key_raw_b64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, data)
        return True
    except (InvalidSignature, Exception):
        return False


# ── Strict schema validation (mirror src/lib/vcc/schemas.ts) ──────────────────
#
# Zod strictObject == "these exact keys, no extras". We replicate the subset
# that matters for the conformance corpus: presence/type/pattern of every field
# and rejection of any unknown key at every object level.


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _strict_keys(obj: Any, allowed: set[str], required: set[str]) -> bool:
    if not isinstance(obj, dict):
        return False
    ks = set(obj.keys())
    if not ks.issubset(allowed):
        return False
    return required.issubset(ks)


def _valid_digest(d: Any) -> bool:
    return (
        _strict_keys(d, {"algorithm", "value"}, {"algorithm", "value"})
        and d["algorithm"] == "sha-256"
        and _is_str(d["value"])
        and bool(SHA256_HEX.match(d["value"]))
    )


def _valid_typed_value(tv: dict[str, Any]) -> bool:
    if not _strict_keys(tv, {"type", "value", "scale", "unit"}, {"type", "value", "scale"}):
        return False
    if tv["type"] not in NUMERIC_KINDS:
        return False
    if not (_is_str(tv["value"]) and len(tv["value"]) <= 64 and DECIMAL_VALUE_RE.match(tv["value"])):
        return False
    scale = tv["scale"]
    if not (isinstance(scale, int) and not isinstance(scale, bool) and 0 <= scale <= 12):
        return False
    if "unit" in tv and not (_is_str(tv["unit"]) and UNIT_RE.match(tv["unit"])):
        return False
    frac = tv["value"].split(".")[1] if "." in tv["value"] else ""
    if scale == 0 and frac != "":
        return False
    if scale > 0 and len(frac) != scale:
        return False
    if tv["value"] == "-0" or (tv["value"].startswith("-0.") and not re.search(r"[1-9]", tv["value"])):
        return False
    return True


def _valid_calc_value(v: Any) -> bool:
    if isinstance(v, dict) and "type" in v and v.get("type") in NUMERIC_KINDS and "value" in v and "scale" in v:
        return _valid_typed_value(v)
    if isinstance(v, str):
        return bool(SHORT_STRING_RE.match(v))
    if isinstance(v, bool):
        return True
    if isinstance(v, list):
        return len(v) <= 1024 and all(_valid_calc_value(e) for e in v)
    if isinstance(v, dict):
        for k, sub in v.items():
            if not CALC_KEY_RE.match(k) or not _valid_calc_value(sub):
                return False
        return True
    return False


def _valid_source_ref(s: Any) -> bool:
    return (
        _strict_keys(s, {"label", "url"}, {"label", "url"})
        and _is_str(s["label"]) and 1 <= len(s["label"]) <= 200
        and _is_str(s["url"]) and len(s["url"]) <= 500
    )


def validate_envelope(env: Any) -> bool:
    """Strict DSSE envelope schema (envelopeSchema)."""
    if not _strict_keys(env, {"payloadType", "payload", "signatures"}, {"payloadType", "payload", "signatures"}):
        return False
    if env["payloadType"] != VCC_PAYLOAD_TYPE:
        return False
    p = env["payload"]
    if not (_is_str(p) and len(p) <= 90_000 and BASE64_STD_RE.match(p)):
        return False
    sigs = env["signatures"]
    if not (isinstance(sigs, list) and 1 <= len(sigs) <= 4):
        return False
    for s in sigs:
        if not _strict_keys(s, {"keyid", "sig"}, {"keyid", "sig"}):
            return False
        if not (_is_str(s["keyid"]) and KEY_ID_RE.match(s["keyid"])):
            return False
        if not (_is_str(s["sig"]) and 86 <= len(s["sig"]) <= 90 and BASE64_STD_RE.match(s["sig"])):
            return False
    return True


def validate_statement(st: Any) -> bool:
    """Strict v0.2 statement schema (statementSchema)."""
    top = {
        "specVersion", "type", "subject", "issuer", "formula", "calculation",
        "datasets", "evidence", "engine", "attestation", "issuedAt", "context",
    }
    if not _strict_keys(st, top, top):
        return False
    if st["specVersion"] != VCC_SPEC_VERSION or st["type"] != VCC_STATEMENT_TYPE:
        return False

    subj = st["subject"]
    if not _strict_keys(subj, {"id", "kind"}, {"id", "kind"}):
        return False
    if not (_is_str(subj["id"]) and SUBJECT_ID_RE.match(subj["id"])) or subj["kind"] != "deterministic-calculation":
        return False

    iss = st["issuer"]
    if not _strict_keys(iss, {"id", "name", "keyDiscovery"}, {"id", "name", "keyDiscovery"}):
        return False
    if not (_is_str(iss["id"]) and len(iss["id"]) <= 200):
        return False
    if not (_is_str(iss["name"]) and 1 <= len(iss["name"]) <= 100):
        return False
    if not (_is_str(iss["keyDiscovery"]) and len(iss["keyDiscovery"]) <= 300):
        return False

    f = st["formula"]
    if not _strict_keys(f, {"id", "slug", "version", "digest", "registry", "visibility"},
                        {"id", "slug", "version", "digest", "registry", "visibility"}):
        return False
    if not (_is_str(f["id"]) and FORMULA_ID_RE.match(f["id"])):
        return False
    if not (_is_str(f["slug"]) and len(f["slug"]) <= 80 and SLUG_RE.match(f["slug"])):
        return False
    if not (_is_str(f["version"]) and SEMVER_RE.match(f["version"])):
        return False
    if not _valid_digest(f["digest"]):
        return False
    if not (_is_str(f["registry"]) and len(f["registry"]) <= 400):
        return False
    if f["visibility"] != "open":
        return False

    calc = st["calculation"]
    if not _strict_keys(calc, {"inputs", "outputs", "numericProfile"},
                        {"inputs", "outputs", "numericProfile"}):
        return False
    for group in ("inputs", "outputs"):
        g = calc[group]
        if not isinstance(g, dict):
            return False
        for k, v in g.items():
            if not CALC_KEY_RE.match(k) or not _valid_calc_value(v):
                return False
    if calc["numericProfile"] != VCC_NUMERIC_PROFILE:
        return False

    ds = st["datasets"]
    if not (isinstance(ds, list) and len(ds) <= 16):
        return False
    for d in ds:
        if not _strict_keys(d, {"id", "name", "version", "digest", "mediaType"},
                            {"id", "name", "version", "digest", "mediaType"}):
            return False
        if not (_is_str(d["id"]) and DATASET_ID_RE.match(d["id"])):
            return False
        if not (_is_str(d["name"]) and 1 <= len(d["name"]) <= 100):
            return False
        if not (_is_str(d["version"]) and 1 <= len(d["version"]) <= 40):
            return False
        if not _valid_digest(d["digest"]):
            return False
        if not (_is_str(d["mediaType"]) and 3 <= len(d["mediaType"]) <= 100):
            return False

    ev = st["evidence"]
    if not _strict_keys(ev, {"sources", "testsDigest"}, {"sources", "testsDigest"}):
        return False
    if not (isinstance(ev["sources"], list) and len(ev["sources"]) <= 20 and all(_valid_source_ref(s) for s in ev["sources"])):
        return False
    if not _valid_digest(ev["testsDigest"]):
        return False

    eng = st["engine"]
    if not _strict_keys(eng, {"name", "version", "commit", "runtimeProfile"},
                        {"name", "version", "commit", "runtimeProfile"}):
        return False
    if not (_is_str(eng["name"]) and 1 <= len(eng["name"]) <= 60):
        return False
    if not (_is_str(eng["version"]) and 1 <= len(eng["version"]) <= 40):
        return False
    if not (_is_str(eng["commit"]) and re.match(r"^([0-9a-f]{7,40}|unknown)$", eng["commit"])):
        return False
    if eng["runtimeProfile"] != VCC_RUNTIME_PROFILE:
        return False

    att = st["attestation"]
    if not _strict_keys(att, {"type", "claims"}, {"type", "claims"}):
        return False
    if att["type"] not in ATTESTATION_TYPES:
        return False
    claims = att["claims"]
    if not (isinstance(claims, list) and 1 <= len(claims) <= 16):
        return False
    if any(c not in ATTESTATION_CLAIMS for c in claims):
        return False
    if len(set(claims)) != len(claims):
        return False

    if not (_is_str(st["issuedAt"]) and ISSUED_AT_RE.match(st["issuedAt"])):
        return False

    ctx = st["context"]
    if not _strict_keys(ctx, {"surface", "requestId"}, {"surface"}):
        return False
    if ctx["surface"] not in {"api", "web", "mcp", "graph"}:
        return False
    if "requestId" in ctx and not (_is_str(ctx["requestId"]) and REQUEST_ID_RE.match(ctx["requestId"])):
        return False

    return True


# ── L1 verification (mirror src/lib/vcc/verify-l1.ts) ─────────────────────────


@dataclass
class L1Checks:
    envelopeSchema: bool = False
    payloadType: bool = False
    payloadDecodes: bool = False
    statementSchema: bool = False
    canonicalization: bool = False
    statementId: bool = False
    keyKnown: bool = False
    algorithmSupported: bool = False
    signature: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {
            "envelopeSchema": self.envelopeSchema,
            "payloadType": self.payloadType,
            "payloadDecodes": self.payloadDecodes,
            "statementSchema": self.statementSchema,
            "canonicalization": self.canonicalization,
            "statementId": self.statementId,
            "keyKnown": self.keyKnown,
            "algorithmSupported": self.algorithmSupported,
            "signature": self.signature,
        }


@dataclass
class L1Result:
    cryptographicValidity: bool
    signatureValid: bool
    statementIntact: bool
    issuerKeyStatus: str
    certificateStatus: str
    trustedAtVerificationTime: bool
    checks: dict[str, bool]
    errors: list[str] = field(default_factory=list)
    statement: dict[str, Any] | None = None
    idHex: str | None = None


def find_issuer_key(keyset: dict[str, Any], keyid: str) -> dict[str, Any] | None:
    for k in keyset.get("keys", []):
        if k.get("keyId") == keyid:
            return k
    return None


def verify_vcc_envelope(
    envelope: Any,
    keyset: dict[str, Any],
    certificate_status: str | None = None,
) -> L1Result:
    checks = L1Checks()
    errors: list[str] = []
    statement: dict[str, Any] | None = None
    id_hex: str | None = None
    issuer_key_status = "unknown"

    def fail(msg: str) -> None:
        errors.append(msg)

    # 1. Envelope shape (strict).
    env_ok = validate_envelope(envelope)
    checks.envelopeSchema = env_ok
    if not env_ok:
        fail("envelope does not match the DSSE envelope schema")
    typed_envelope = envelope if env_ok else None

    # 2. payloadType binding.
    if typed_envelope is not None:
        checks.payloadType = typed_envelope["payloadType"] == VCC_PAYLOAD_TYPE
        if not checks.payloadType:
            fail("unsupported payloadType")

    # 3. Strict payload decode.
    payload_bytes: bytes | None = None
    if typed_envelope is not None and checks.payloadType:
        payload_bytes = decode_envelope_payload(typed_envelope["payload"])
        if payload_bytes is not None:
            checks.payloadDecodes = True
        else:
            fail("payload is not strict base64 within size limits")

    # 4. Statement schema (strict).
    if payload_bytes is not None:
        try:
            parsed = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            fail("payload is not valid JSON")
            parsed = None
        if parsed is not None:
            if validate_statement(parsed):
                statement = parsed
                checks.statementSchema = True
            else:
                fail("payload JSON is not a valid v0.2 statement")

    # 5. Canonicalization: payload MUST be the JCS bytes of the statement.
    if statement is not None and payload_bytes is not None:
        try:
            canonical = canonicalize(statement)
            checks.canonicalization = canonical == payload_bytes.decode("utf-8")
        except CanonicalizationError:
            checks.canonicalization = False
        if not checks.canonicalization:
            fail("payload bytes are not the canonical (RFC 8785) form of the statement")

    # 6. Content-addressed id.
    if statement is not None:
        try:
            expected = compute_statement_id_hex(statement)
            actual = id_hex_from_subject_id(statement["subject"]["id"])
            checks.statementId = actual is not None and expected == actual
        except CanonicalizationError:
            checks.statementId = False
        if checks.statementId:
            id_hex = expected
        else:
            fail("subject.id does not match the statement content")

    # 7-9. Key lookup, algorithm, signature over PAE.
    if typed_envelope is not None and payload_bytes is not None:
        sig0 = typed_envelope["signatures"][0]
        key = find_issuer_key(keyset, sig0["keyid"])
        if key is not None:
            checks.keyKnown = True
            issuer_key_status = key.get("status", "unknown")
            checks.algorithmSupported = key.get("algorithm") == "ed25519"
            if not checks.algorithmSupported:
                fail("unsupported signature algorithm")
            if checks.algorithmSupported:
                pae = build_pae(VCC_PAYLOAD_TYPE, payload_bytes)
                try:
                    sig_bytes = base64.b64decode(sig0["sig"])
                    strict = base64.b64encode(sig_bytes).decode("ascii") == sig0["sig"]
                except Exception:
                    sig_bytes = b""
                    strict = False
                checks.signature = strict and verify_signature_raw(
                    key["publicKey"], pae, sig_bytes
                )
                if not checks.signature:
                    fail("Ed25519 signature does not verify")
        else:
            fail(f'key id "{sig0["keyid"]}" is not in the supplied keyset')

    cryptographic_validity = all(checks.as_dict().values())

    signature_valid = checks.signature
    statement_intact = (
        checks.payloadDecodes
        and checks.statementSchema
        and checks.canonicalization
        and checks.statementId
    )

    cert_status = certificate_status if certificate_status is not None else "unknown"
    trusted = (
        cryptographic_validity
        and issuer_key_status == "active"
        and (cert_status == "valid" or cert_status == "unknown")
    )

    return L1Result(
        cryptographicValidity=cryptographic_validity,
        signatureValid=signature_valid,
        statementIntact=statement_intact,
        issuerKeyStatus=issuer_key_status,
        certificateStatus=cert_status,
        trustedAtVerificationTime=trusted,
        checks=checks.as_dict(),
        errors=errors,
        statement=statement,
        idHex=id_hex,
    )
