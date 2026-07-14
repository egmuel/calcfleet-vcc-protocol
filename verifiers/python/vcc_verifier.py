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
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ── Constants (mirror src/lib/vcc/constants.ts) ──────────────────────────────

VCC_SPEC_VERSION = "0.2"
VCC_PAYLOAD_TYPE = "application/vnd.vcc.statement+json;version=0.2"
VCC_STATEMENT_TYPE = "https://calcfleet.com/vcc/statement/calculation/v0.2"
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

# ── Shared cross-language helpers (mirror schemas.ts EXACTLY — the interop gate
#    depends on TS and Python accepting the same set). ──────────────────────────

ISO4217_RE = re.compile(r"^[A-Z]{3}$")
DURATION_UNITS = {"years", "months", "weeks", "days", "hours", "minutes", "seconds"}
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNS_HOST_RE = re.compile(rf"^{_DNS_LABEL}(?:\.{_DNS_LABEL})*$")
_DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def is_safe_https_url(s: Any, max_len: int) -> bool:
    """https-only, registrable DNS host, ASCII, no userinfo, no IP literals /
    localhost / *.local. Mirrors schemas.ts isSafeHttpsUrl — pure string work so
    TS and Python agree on every input (closes the cross-language divergence)."""
    if not isinstance(s, str) or len(s) == 0 or len(s) > max_len:
        return False
    if any(ord(c) > 127 for c in s):
        return False
    try:
        u = urlsplit(s)
        host = u.hostname
    except Exception:
        return False
    if u.scheme != "https":
        return False
    if u.username or u.password:
        return False
    if not host:
        return False
    host = host.lower()
    if ":" in host:  # IPv6 literal
        return False
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return False
    if not DNS_HOST_RE.match(host):
        return False
    labels = host.split(".")
    if len(labels) < 2:  # require at least one dot
        return False
    tld = labels[-1]
    return any("a" <= ch <= "z" for ch in tld)  # alphabetic TLD ⇒ not an IPv4 literal


def _is_leap_year(y: int) -> bool:
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def is_valid_utc_timestamp(s: Any) -> bool:
    """A REAL UTC seconds timestamp `YYYY-MM-DDTHH:MM:SSZ` (mirror schemas.ts)."""
    if not isinstance(s, str) or not ISSUED_AT_RE.match(s):
        return False
    y = int(s[0:4]); mo = int(s[5:7]); d = int(s[8:10])
    h = int(s[11:13]); mi = int(s[14:16]); se = int(s[17:19])
    if mo < 1 or mo > 12:
        return False
    dim = _DAYS_IN_MONTH[mo - 1]
    if mo == 2 and _is_leap_year(y):
        dim = 29
    if d < 1 or d > dim:
        return False
    return h <= 23 and mi <= 59 and se <= 59


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
    from decimal import Decimal

    if isinstance(n, bool):  # bool is a subclass of int — reject as ambiguous
        raise CanonicalizationError("boolean where number expected")
    if isinstance(n, int):
        return str(n)
    if not math.isfinite(n):
        raise CanonicalizationError("non-finite number")
    if n == 0:
        return "0"  # ECMAScript renders both 0.0 and -0.0 as "0"
    # Full ECMAScript Number::toString: Python's repr(float) gives the shortest
    # round-tripping digits; we then apply the exact ES placement/exponent rules
    # so e.g. 1e-7 → "1e-7" (not Python's "1e-07") and 1e-6 → "0.000001". This
    # makes canonicalize() genuinely RFC 8785-generic and byte-identical to the
    # TypeScript verifier's JSON.stringify on numbers (closes the audit's
    # cross-language number-serialization divergence).
    sign = "-" if n < 0 else ""
    tup = Decimal(repr(abs(n))).as_tuple()
    digits = "".join(str(d) for d in tup.digits)
    exp = tup.exponent
    stripped = digits.rstrip("0")
    if stripped == "":
        return "0"
    exp += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    point = exp + k  # ES 'n': number of digits left of the decimal point
    if k <= point <= 21:
        body = digits + "0" * (point - k)
    elif 0 < point <= 21:
        body = digits[:point] + "." + digits[point:]
    elif -6 < point <= 0:
        body = "0." + "0" * (-point) + digits
    else:
        e = point - 1
        esign = "+" if e >= 0 else "-"
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{esign}{abs(e)}"
    return sign + body


def canonicalize(value: Any) -> str:
    """JCS canonical form as a `str`. Raises CanonicalizationError on ambiguous input."""

    def ser(v: Any) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str):
            # A lone surrogate (any code point U+D800..U+DFFF, since Python stores
            # code points, never pairs) has no valid UTF-8 encoding → not
            # canonicalizable. Reject rather than crash on .encode() later; the
            # TS verifier rejects the same strings, so the two agree.
            if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
                raise CanonicalizationError("lone surrogate in string")
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
    # Type-dependent unit constraints (mirror schemas.ts typedValueSchema).
    unit = tv.get("unit")
    t = tv["type"]
    if t == "money":
        if unit is None or not ISO4217_RE.match(unit):
            return False
    elif t == "duration":
        if unit is None or unit not in DURATION_UNITS:
            return False
    elif t == "percent":
        if unit is not None and unit != "%":
            return False
    elif t == "ratio":
        if unit is not None:
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
        and is_safe_https_url(s.get("url"), 500)
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
    # Multi-signature: keyids must be unique within an envelope.
    keyids = [s["keyid"] for s in sigs]
    if len(set(keyids)) != len(keyids):
        return False
    return True


def validate_statement(st: Any) -> bool:
    """Strict v0.2 statement schema (statementSchema)."""
    top = {
        "specVersion", "type", "subject", "issuer", "formula", "calculation",
        "datasets", "evidence", "engine", "attestation", "issuedAt", "context",
    }
    # §42: additive — verifiers MUST accept pre-§42 statements without
    # attestation; issuers SHOULD always include it. When present, the block
    # is validated in full below.
    if not _strict_keys(st, top, top - {"attestation"}):
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
    if not is_safe_https_url(iss.get("id"), 200):
        return False
    if not (_is_str(iss["name"]) and 1 <= len(iss["name"]) <= 100):
        return False
    if not is_safe_https_url(iss.get("keyDiscovery"), 300):
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
    if not is_safe_https_url(f.get("registry"), 400):
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

    att = st.get("attestation")
    if att is not None:
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

    if not is_valid_utc_timestamp(st["issuedAt"]):
        return False

    ctx = st["context"]
    if not _strict_keys(ctx, {"surface", "requestId"}, {"surface"}):
        return False
    if ctx["surface"] not in {"api", "web", "mcp", "graph"}:
        return False
    if "requestId" in ctx and not (_is_str(ctx["requestId"]) and REQUEST_ID_RE.match(ctx["requestId"])):
        return False

    # Cross-field semantic invariants (mirror statementSchema.superRefine).
    if f["id"] != "urn:vcc:formula:" + f["slug"]:
        return False
    # Attestation cross-field rules apply only when the block is present
    # (§42: pre-§42 statements omit it and MUST still validate).
    if att is not None:
        claims_set = set(att["claims"])
        if ("datasets-used" in claims_set) != (len(ds) > 0):
            return False
        required_by_type = {
            "execution": {"inputs-received", "formula-executed", "output-produced"},
            "reproduction": {"formula-executed", "output-produced"},
            "review": {"formula-executed"},
        }
        if not required_by_type.get(att["type"], set()).issubset(claims_set):
            return False
    if len(calc["inputs"]) == 0 or len(calc["outputs"]) == 0:
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
    issuerIdentityBound: bool
    keyValidAtIssuance: bool
    signatureResults: list[dict[str, Any]]
    trustedAtVerificationTime: bool
    checks: dict[str, bool]
    errors: list[str] = field(default_factory=list)
    statement: dict[str, Any] | None = None
    idHex: str | None = None


MAX_STATEMENT_DEPTH = 64
MAX_STATEMENT_NODES = 20_000


def _exceeds_structural_limits(root: Any) -> bool:
    """Depth/size guard, iterative (explicit stack) so it can't itself overflow —
    mirrors verify.ts exceedsStructuralLimits (audit P0#3, deep nesting)."""
    nodes = 0
    stack: list[tuple[Any, int]] = [(root, 1)]
    while stack:
        v, depth = stack.pop()
        if depth > MAX_STATEMENT_DEPTH:
            return True
        nodes += 1
        if nodes > MAX_STATEMENT_NODES:
            return True
        if isinstance(v, list):
            for e in v:
                stack.append((e, depth + 1))
        elif isinstance(v, dict):
            for val in v.values():
                stack.append((val, depth + 1))
    return False


def _coerce_keyset(keys: Any) -> tuple[str | None, list[dict[str, Any]]]:
    """Read an untrusted keyset defensively, never throwing (audit P0#3). We do
    NOT enforce algorithm/status here — the per-check logic reports those."""
    if not isinstance(keys, dict):
        return None, []
    issuer = keys.get("issuer") if isinstance(keys.get("issuer"), str) else None
    raw = keys.get("keys")
    arr = [k for k in raw if isinstance(k, dict)] if isinstance(raw, list) else []
    return issuer, arr


def verify_vcc_envelope(
    envelope: Any,
    keyset: Any,
    certificate_status: str | None = None,
) -> L1Result:
    cert_status = certificate_status if certificate_status is not None else "unknown"
    try:
        return _verify_vcc_envelope_inner(envelope, keyset, cert_status)
    except Exception as exc:  # noqa: BLE001 — the verifier MUST NOT throw (P0#3)
        return L1Result(
            cryptographicValidity=False,
            signatureValid=False,
            statementIntact=False,
            issuerKeyStatus="unknown",
            certificateStatus=cert_status,
            issuerIdentityBound=False,
            keyValidAtIssuance=False,
            signatureResults=[],
            trustedAtVerificationTime=False,
            checks=L1Checks().as_dict(),
            errors=[f"internal verifier error: {type(exc).__name__}: {exc}"],
        )


def _verify_vcc_envelope_inner(
    envelope: Any,
    keyset: Any,
    cert_status: str,
) -> L1Result:
    checks = L1Checks()
    errors: list[str] = []
    statement: dict[str, Any] | None = None
    id_hex: str | None = None
    issuer_key_status = "unknown"
    issuer_identity_bound = False
    key_valid_at_issuance = False
    signature_results: list[dict[str, Any]] = []

    def fail(msg: str) -> None:
        errors.append(msg)

    # 1. Envelope shape (strict, keyids unique).
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

    # 4. Statement schema (strict), depth/size-capped so a hostile deeply-nested
    #    payload can't blow the stack during validation.
    if payload_bytes is not None:
        try:
            parsed = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            fail("payload is not valid JSON")
            parsed = None
        if parsed is not None:
            if _exceeds_structural_limits(parsed):
                fail("statement structure is too deep or too large")
            elif validate_statement(parsed):
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
            checks.canonicalization = False  # e.g. a lone surrogate — not a crash
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

    # Issuer binding (axis 2): the keyset must belong to the statement's issuer.
    keyset_issuer, keyset_keys = _coerce_keyset(keyset)
    if not keyset_keys and env_ok:
        fail("issuer keyset is empty or malformed")
    statement_issuer_id = None
    if isinstance(statement, dict):
        iss = statement.get("issuer")
        if isinstance(iss, dict) and isinstance(iss.get("id"), str):
            statement_issuer_id = iss["id"]
    if (
        statement_issuer_id is not None
        and keyset_issuer is not None
        and keyset_issuer == statement_issuer_id
    ):
        issuer_identity_bound = True
    elif statement is not None:
        fail("keyset issuer is not bound to the statement's issuer.id")

    def find_key(keyid: str) -> dict[str, Any] | None:
        for k in keyset_keys:
            if k.get("keyId") == keyid:
                return k
        return None

    # 7-9. Multi-signature: EVERY signature must resolve to a known ed25519 key
    #       and verify over the DSSE PAE (audit P1: no ignored/free-riding sigs).
    if typed_envelope is not None and payload_bytes is not None:
        pae = build_pae(VCC_PAYLOAD_TYPE, payload_bytes)
        for sig in typed_envelope["signatures"]:
            key = find_key(sig["keyid"])
            key_known = key is not None
            algorithm_supported = key_known and key.get("algorithm") == "ed25519"
            valid = False
            if algorithm_supported and isinstance(key.get("publicKey"), str):
                try:
                    sig_bytes = base64.b64decode(sig["sig"])
                    strict = base64.b64encode(sig_bytes).decode("ascii") == sig["sig"]
                except Exception:
                    sig_bytes = b""
                    strict = False
                valid = strict and verify_signature_raw(key["publicKey"], pae, sig_bytes)
            signature_results.append({
                "keyid": sig["keyid"],
                "keyKnown": key_known,
                "algorithmSupported": bool(algorithm_supported),
                "valid": bool(valid),
            })

        checks.keyKnown = len(signature_results) > 0 and all(r["keyKnown"] for r in signature_results)
        checks.algorithmSupported = (
            len(signature_results) > 0 and all(r["algorithmSupported"] for r in signature_results)
        )
        checks.signature = len(signature_results) > 0 and all(r["valid"] for r in signature_results)
        if not checks.keyKnown:
            fail("a signature keyid is not in the supplied keyset")
        if checks.keyKnown and not checks.algorithmSupported:
            fail("unsupported signature algorithm")
        if checks.algorithmSupported and not checks.signature:
            fail("an Ed25519 signature does not verify")

        # Primary (first) signature's key drives status + temporal validity.
        primary = find_key(typed_envelope["signatures"][0]["keyid"])
        if primary is not None:
            issuer_key_status = primary.get("status", "unknown") if isinstance(primary.get("status"), str) else "unknown"
            if isinstance(statement, dict):
                issued_at = statement.get("issuedAt")
                vf = primary.get("validFrom")
                vu = primary.get("validUntil")
                key_valid_at_issuance = (
                    isinstance(issued_at, str)
                    and isinstance(vf, str)
                    and is_valid_utc_timestamp(vf)
                    and vf <= issued_at
                    and (
                        vu is None
                        or (isinstance(vu, str) and is_valid_utc_timestamp(vu) and issued_at <= vu)
                    )
                )
                if not key_valid_at_issuance:
                    fail("signing key was not valid at the statement's issuedAt")

    cryptographic_validity = all(checks.as_dict().values())

    signature_valid = checks.signature
    statement_intact = (
        checks.payloadDecodes
        and checks.statementSchema
        and checks.canonicalization
        and checks.statementId
    )

    trusted = (
        cryptographic_validity
        and issuer_identity_bound
        and key_valid_at_issuance
        and issuer_key_status == "active"
        and (cert_status == "valid" or cert_status == "unknown")
    )

    return L1Result(
        cryptographicValidity=cryptographic_validity,
        signatureValid=signature_valid,
        statementIntact=statement_intact,
        issuerKeyStatus=issuer_key_status,
        certificateStatus=cert_status,
        issuerIdentityBound=issuer_identity_bound,
        keyValidAtIssuance=key_valid_at_issuance,
        signatureResults=signature_results,
        trustedAtVerificationTime=trusted,
        checks=checks.as_dict(),
        errors=errors,
        statement=statement,
        idHex=id_hex,
    )
