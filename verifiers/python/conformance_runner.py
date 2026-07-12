"""Cross-language conformance runner for the Python VCC L1 verifier.

Loads the SAME committed corpus the TypeScript conformance suite uses
(`src/lib/vcc/vectors/`), runs the independent Python verifier over every
positive and negative vector, and asserts the Python result matches the pinned
outcome — the outcome the TS reference verifier is pinned to in
`src/lib/vcc/conformance.test.ts`.

This is the machine-checkable half of the §50 "Interoperable" gate: two
independent verifiers, same result on the same vectors. OFFLINE — only local
files, no network.

Exit 0 iff every vector matches. Prints a per-vector table and a summary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import hashlib  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vcc_verifier import (  # noqa: E402
    canonical_bytes,
    canonicalize,
    compute_statement_id_hex,
    verify_vcc_envelope,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTOR_DIR = REPO_ROOT / "vectors"
NEG_DIR = VECTOR_DIR / "negative"
KEYSET_FILE = VECTOR_DIR / "test-key.json"


def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def base_keyset() -> dict:
    return load_json(KEYSET_FILE)["keyset"]


def keyset_for(name: str | None) -> dict:
    """Mirror keysetFor() in conformance.test.ts."""
    ks = base_keyset()
    if name == "revoked":
        keys = [dict(k, status="revoked") for k in ks["keys"]]
        return {"issuer": ks["issuer"], "keys": keys}
    if name == "wrong-algorithm":
        keys = [dict(k, algorithm="rsa") for k in ks["keys"]]
        return {"issuer": ks["issuer"], "keys": keys}
    if name == "issuer-mismatch":
        return {"issuer": "https://attacker.example", "keys": ks["keys"]}
    if name == "future-key":
        keys = [dict(k, validFrom="2099-01-01T00:00:00Z") for k in ks["keys"]]
        return {"issuer": ks["issuer"], "keys": keys}
    if name == "expired-key":
        keys = [dict(k, validUntil="2020-01-01T00:00:00Z") for k in ks["keys"]]
        return {"issuer": ks["issuer"], "keys": keys}
    return ks


# ── Positive corpus ───────────────────────────────────────────────────────────


def check_positive(file: Path) -> tuple[bool, str]:
    v = load_json(file)
    exp = v.get("expected", {}).get("l1", {})
    res = verify_vcc_envelope(v["envelope"], base_keyset())

    problems = []
    want_crypto = exp.get("cryptographicValidity")
    if want_crypto is not None and res.cryptographicValidity != want_crypto:
        problems.append(f"cryptographicValidity={res.cryptographicValidity} want {want_crypto}")
    want_trust = exp.get("trustedAtVerificationTime")
    if want_trust is not None and res.trustedAtVerificationTime != want_trust:
        problems.append(f"trustedAtVerificationTime={res.trustedAtVerificationTime} want {want_trust}")
    if res.errors:
        problems.append(f"errors not empty: {res.errors}")
    if not res.cryptographicValidity and want_crypto is not False:
        failed = [k for k, val in res.checks.items() if not val]
        problems.append(f"unexpected failed checks: {failed}")
    return (not problems, "; ".join(problems))


# ── Negative corpus ────────────────────────────────────────────────────────────


def check_negative(file: Path) -> tuple[bool, str]:
    v = load_json(file)
    exp = v["expected"]
    ks = keyset_for(exp.get("keyset"))
    cert_status = exp.get("certificateStatus")
    res = verify_vcc_envelope(v["envelope"], ks, certificate_status=cert_status)

    problems = []

    # Every pinned failed check must be false in the Python result.
    for check in exp.get("l1FailedChecks") or []:
        if res.checks.get(check) is not False:
            problems.append(f"check {check}={res.checks.get(check)} want False")

    want_crypto = exp.get("l1CryptographicValidity")
    if want_crypto is not None and res.cryptographicValidity != want_crypto:
        problems.append(f"cryptographicValidity={res.cryptographicValidity} want {want_crypto}")
        # TS also asserts errors non-empty when cryptographicValidity=false
    if want_crypto is False and not res.errors:
        problems.append("expected non-empty errors")

    want_trust = exp.get("l1TrustedAtVerificationTime")
    if want_trust is not None and res.trustedAtVerificationTime != want_trust:
        problems.append(f"trustedAtVerificationTime={res.trustedAtVerificationTime} want {want_trust}")

    want_bound = exp.get("l1IssuerIdentityBound")
    if want_bound is not None and res.issuerIdentityBound != want_bound:
        problems.append(f"issuerIdentityBound={res.issuerIdentityBound} want {want_bound}")

    want_key_valid = exp.get("l1KeyValidAtIssuance")
    if want_key_valid is not None and res.keyValidAtIssuance != want_key_valid:
        problems.append(f"keyValidAtIssuance={res.keyValidAtIssuance} want {want_key_valid}")

    return (not problems, "; ".join(problems))


# ── JCS byte-parity: the load-bearing interoperability check ──────────────────
# Each positive vector carries the TS-produced canonical string
# (`canonicalStatement`) and its sha256. Python JCS must reproduce BOTH exactly,
# and the content-addressed statementId must match subject.id. If this diverges
# on any vector, the corpus would still "verify" but the two implementations
# would NOT be interoperable — so we surface it as its own gate.


def check_jcs_parity(file: Path) -> tuple[bool, str]:
    v = load_json(file)
    st = v["statement"]
    problems = []
    if "canonicalStatement" in v and canonicalize(st) != v["canonicalStatement"]:
        problems.append("JCS bytes differ from TS canonicalStatement")
    if "canonicalStatementSha256" in v:
        py_sha = hashlib.sha256(canonical_bytes(st)).hexdigest()
        if py_sha != v["canonicalStatementSha256"]:
            problems.append("canonical sha256 differs from pinned")
    id_hex = compute_statement_id_hex(st)
    if ("urn:vcc:calculation:sha256:" + id_hex) != st["subject"]["id"]:
        problems.append("statementId differs from subject.id")
    return (not problems, "; ".join(problems))


def main() -> int:
    positives = sorted(
        f for f in VECTOR_DIR.glob("*.json") if f.name != "test-key.json"
    )
    negatives = sorted(f for f in NEG_DIR.glob("*.json") if f.name != "index.json")

    passed = 0
    total = 0
    rows = []

    jcs_all_ok = True
    for f in positives:
        ok, detail = check_jcs_parity(f)
        jcs_all_ok = jcs_all_ok and ok
        total += 1
        passed += ok
        rows.append(("JCS", f.name, ok, detail))

    for f in positives:
        ok, detail = check_positive(f)
        total += 1
        passed += ok
        rows.append(("POS", f.name, ok, detail))

    for f in negatives:
        ok, detail = check_negative(f)
        total += 1
        passed += ok
        rows.append(("NEG", f.name, ok, detail))

    width = max(len(r[1]) for r in rows)
    print(f"VCC cross-language conformance — Python verifier vs pinned TS outcome")
    print(f"corpus: {VECTOR_DIR}")
    print("-" * (width + 24))
    for kind, name, ok, detail in rows:
        mark = "PASS" if ok else "FAIL"
        line = f"[{kind}] {name.ljust(width)}  {mark}"
        if not ok:
            line += f"  <- {detail}"
        print(line)
    print("-" * (width + 24))
    print(f"MATCH: {passed}/{total} checks match the pinned (TS reference) outcome")
    print(f"JCS byte-for-byte parity with TS on all positives: {jcs_all_ok}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
