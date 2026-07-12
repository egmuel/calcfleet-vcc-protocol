"""JCS (RFC 8785) edge-case self-tests for the Python verifier.

These harden the interoperability claim beyond the four golden vectors: they
pin the byte output for the cases where JCS implementations most often diverge
(key ordering, number ToString, minimal string escaping, unicode passthrough,
rejection of ambiguous values). Every expected value here is what a conforming
ECMAScript engine's JSON.stringify + JCS ordering produces — i.e. the TS
reference in src/lib/vcc/canonicalize.ts.

Run: python test_jcs.py  (exit 0 = all pass).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vcc_verifier import CanonicalizationError, canonicalize

CASES: list[tuple[object, str]] = [
    # key ordering by UTF-16 code units
    ({"b": 1, "a": 2, "c": 3}, '{"a":2,"b":1,"c":3}'),
    ({"z": 1, "aa": 2, "A": 3}, '{"A":3,"aa":2,"z":1}'),
    # nested + arrays preserve element order
    ({"x": [3, 1, 2], "a": {"n": True}}, '{"a":{"n":true},"x":[3,1,2]}'),
    # numbers: integral floats drop the .0 (ES Number ToString)
    (1.0, "1"),
    (0, "0"),
    (-0.0, "0"),  # JS -0 -> "0"
    (42, "42"),
    (100, "100"),
    (1.5, "1.5"),
    # strings: minimal escaping, unicode passthrough
    ("hello", '"hello"'),
    ('quote"and\\back', '"quote\\"and\\\\back"'),
    ("tab\tnewline\n", '"tab\\tnewline\\n"'),
    ("café — ünïcode ✓", '"café — ünïcode ✓"'),
    # primitives
    (None, "null"),
    (True, "true"),
    (False, "false"),
    ([], "[]"),
    ({}, "{}"),
]

REJECT: list[object] = [
    float("nan"),
    float("inf"),
    float("-inf"),
]


def main() -> int:
    failures = 0
    for value, expected in CASES:
        got = canonicalize(value)
        ok = got == expected
        if not ok:
            failures += 1
            print(f"FAIL  canonicalize({value!r}) = {got!r}  want {expected!r}")
        else:
            print(f"pass  canonicalize({value!r}) = {got!r}")

    for value in REJECT:
        try:
            canonicalize(value)
            failures += 1
            print(f"FAIL  canonicalize({value!r}) did not raise")
        except CanonicalizationError:
            print(f"pass  canonicalize({value!r}) rejected")

    print("-" * 40)
    print("JCS edge-case self-tests:", "ALL PASS" if failures == 0 else f"{failures} FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
