#!/usr/bin/env python3
"""Offline L1 verification of a single VCC receipt, using the independent
Python verifier in verifiers/python (install its single dependency once:
`python3 -m venv verifiers/python/.venv &&
verifiers/python/.venv/bin/pip install -r verifiers/python/requirements.txt`).

Usage:
    python3 examples/verify_receipt.py <receipt.json> <keyset.json>

<receipt.json> may be a `{ statement, envelope }` receipt (as in examples/)
or a bare DSSE envelope. <keyset.json> may be a `{ keyset: ... }` document
(as in vectors/test-key.json or /.well-known/vcc-issuer.json) or a bare keyset.

Prints the verification AXES separately — there is deliberately no single
"verified" boolean anywhere in VCC. Exit 0 iff cryptographicValidity.
No network calls are made.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifiers" / "python"))
from vcc_verifier import verify_vcc_envelope  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: python3 examples/verify_receipt.py <receipt.json> <keyset.json>", file=sys.stderr)
        return 2

    receipt_doc = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    envelope = receipt_doc.get("envelope", receipt_doc)
    keyset_doc = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    keyset = keyset_doc.get("keyset", keyset_doc)

    res = verify_vcc_envelope(envelope, keyset)

    print("axes:")
    print(f"  signatureValid            : {res.signatureValid}")
    print(f"  statementIntact           : {res.statementIntact}")
    print(f"  issuerIdentityBound       : {res.issuerIdentityBound}")
    print(f"  keyValidAtIssuance        : {res.keyValidAtIssuance}")
    print(f"  issuerKeyStatus           : {res.issuerKeyStatus}")
    print(f"  certificateStatus         : {res.certificateStatus}")
    print(f"  cryptographicValidity     : {res.cryptographicValidity}")
    print(f"  trustedAtVerificationTime : {res.trustedAtVerificationTime}")
    print(f"checks: {json.dumps(res.checks)}")
    if res.errors:
        print(f"errors: {json.dumps(res.errors)}")
    return 0 if res.cryptographicValidity else 1


if __name__ == "__main__":
    raise SystemExit(main())
