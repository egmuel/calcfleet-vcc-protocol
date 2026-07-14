# Contributing

VCC is an experimental open protocol; the most valuable contributions right now
are the adversarial ones — vectors that break a verifier, reports of
cross-language divergence, and independent implementations. Everything below is
runnable offline from a fresh clone.

## Run the verifiers and the conformance suites

**TypeScript verifier** (Node 22+):

```bash
cd verifiers/typescript
npm ci
npm run conformance     # builds, then runs every vector; exit 0 iff all match
```

**Python verifier** (Python 3.10+, single dependency `cryptography`):

```bash
cd verifiers/python
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python conformance_runner.py    # same corpus, independent implementation
.venv/bin/python test_jcs.py              # RFC 8785 edge-case self-tests
```

Both runners print a per-vector table and end with a summary line
(`MATCH: 32/32 checks match the pinned … outcome`, JCS byte parity `true`).
A green run means: every positive and negative vector produced exactly the
pinned reference outcome, and canonicalization is byte-for-byte identical.

**L2 reproduction** (Python stdlib only):

```bash
python3 l2/test_l2.py                                        # full L2 test suite
python3 l2/l2_verify.py vectors/compound-interest-calculator.json   # single vector
```

**JSON Schemas** (requires `jsonschema`, available in the Python verifier venv):

```bash
verifiers/python/.venv/bin/pip install jsonschema
verifiers/python/.venv/bin/python schema/validate.py
```

To verify a single receipt file rather than the whole corpus, use the helper
scripts documented in [`examples/README.md`](examples/README.md).

## Propose a conformance vector

Negative vectors are the immune system of the protocol. A good one encodes an
attack or an implementation trap and pins exactly which axis must fail.

1. Add `vectors/negative/<case-name>.json` with the fields the existing vectors
   use: `case`, `comment`, `derivedFrom` (which golden vector it was built
   from), `tampering` (what you changed, precisely), `envelope`, and
   `expected` — including `l1FailedChecks` (the per-check booleans that must be
   `false`), `l1CryptographicValidity`, and any trust-axis expectations.
2. Register it in `vectors/negative/index.json`.
3. Run **both** conformance runners. A vector is accepted only if the
   TypeScript and Python verifiers agree on its outcome — disagreement is
   itself a (more interesting) bug report.
4. Open a pull request explaining what real-world mistake or attack the vector
   pins down.

If you found an input on which the two verifiers **disagree**, that is the most
valuable report of all — file it even without a fix.

## Report a security issue

Do **not** open a public issue for undisclosed vulnerabilities. Follow
[`SECURITY.md`](SECURITY.md) (private report, coordinated disclosure).
Signature bypasses, canonicalization ambiguities, and parser differentials in
the verifiers are all in scope.

## Commit style

Conventional-commit style, imperative mood, scoped where useful:

```
docs: clarify L2 fail-closed behavior
vectors: add lone-surrogate negative case
verifiers(python): reject non-canonical base64 padding
spec: pin numeric profile rounding at output boundary
security(vcc): close issuer-binding gap
```

Normative spec changes need an accompanying ADR under `adr/` (problem,
proposal, alternatives, security/privacy implications, compatibility,
decision) — see [`GOVERNANCE.md`](GOVERNANCE.md).

## Licensing of contributions

Code contributions are accepted under **Apache-2.0** ([`LICENSE`](LICENSE)),
specification text under **CC-BY-4.0** ([`LICENSE-SPEC`](LICENSE-SPEC)) — the
same terms the repository ships under.
