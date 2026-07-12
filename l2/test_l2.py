"""Runnable L2 test suite (stdlib only). Run: ``cd l2 && python test_l2.py``.

Proves:
  (a) the golden compound-interest vector REPRODUCES
      (recomputed outputs == declared outputs, exactly);
  (b) a TAMPERED statement (one output changed by 1 cent) is caught as
      reproduced=false with a precise mismatch;
  (c) an UNKNOWN formula slug is refused (formulaFound=false) and NOT executed.

Plus robustness: hostile / malformed inputs never raise.
"""

from __future__ import annotations

import copy
import json
import os
import sys

import l2_verify

_HERE = os.path.dirname(os.path.abspath(__file__))
_VECTOR = os.path.join(_HERE, "..", "vectors", "compound-interest-calculator.json")


def _load_vector() -> dict:
    with open(_VECTOR, "r", encoding="utf-8") as fh:
        return json.load(fh)


_failures = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global _failures
    status = "PASS" if condition else "FAIL"
    if not condition:
        _failures += 1
    line = f"[{status}] {name}"
    if detail:
        line += f"  -- {detail}"
    print(line)


def test_a_golden_reproduces() -> None:
    print("\n(a) golden compound-interest vector reproduces")
    vector = _load_vector()
    result = l2_verify.verify_l2(vector)

    check("formula found in local allowlist", result["formulaFound"] is True,
          f"slug={result['slug']} version={result['version']}")
    check("no error", result["error"] is None, str(result["error"]))
    check("reproduced == True", result["reproduced"] is True)
    check("zero mismatches", result["mismatches"] == [],
          f"{len(result['mismatches'])} mismatch(es)")

    # Spot-check that the reproduced headline figures equal the declared ones.
    outputs = vector["statement"]["calculation"]["outputs"]
    check("declared finalBalance is 59163.80",
          outputs["finalBalance"]["value"] == "59163.80")
    check("declared totalInterest is 19163.80",
          outputs["totalInterest"]["value"] == "19163.80")
    check("declared totalContributed is 40000.00",
          outputs["totalContributed"]["value"] == "40000.00")
    check("yearlyTable has 10 rows", len(outputs["yearlyTable"]) == 10)


def test_b_tampered_is_caught() -> None:
    print("\n(b) tampered statement (one output +1 cent) is caught")
    vector = _load_vector()
    tampered = copy.deepcopy(vector)
    # Bump finalBalance by exactly one cent: 59163.80 -> 59163.81.
    tampered["statement"]["calculation"]["outputs"]["finalBalance"]["value"] = "59163.81"

    result = l2_verify.verify_l2(tampered)

    check("formula still found", result["formulaFound"] is True)
    check("reproduced == False", result["reproduced"] is False)
    check("has at least one mismatch", len(result["mismatches"]) >= 1,
          f"{len(result['mismatches'])} mismatch(es)")

    paths = [m.get("path") for m in result["mismatches"]]
    check("mismatch points at finalBalance",
          any(p == "outputs.finalBalance" for p in paths), str(paths))
    # The recomputed (correct) value is the honest 59163.80.
    fb = next((m for m in result["mismatches"] if m.get("path") == "outputs.finalBalance"), None)
    check("recomputed value is the honest 59163.80",
          fb is not None and fb["recomputed"]["value"] == "59163.80"
          and fb["declared"]["value"] == "59163.81",
          json.dumps(fb) if fb else "no finalBalance mismatch")


def test_c_unknown_formula_refused() -> None:
    print("\n(c) unknown formula slug is refused, not executed")
    vector = _load_vector()
    unknown = copy.deepcopy(vector)
    unknown["statement"]["formula"]["slug"] = "totally-unknown-formula"
    unknown["statement"]["formula"]["id"] = "urn:vcc:formula:totally-unknown-formula"

    result = l2_verify.verify_l2(unknown)

    check("formulaFound == False", result["formulaFound"] is False)
    check("reproduced == False (nothing executed)", result["reproduced"] is False)
    check("error mentions allowlist",
          result["error"] is not None and "allowlist" in result["error"],
          str(result["error"]))

    # Also: an unknown VERSION of a known slug must be refused too.
    bad_version = copy.deepcopy(vector)
    bad_version["statement"]["formula"]["version"] = "9.9.9"
    rv = l2_verify.verify_l2(bad_version)
    check("unknown version also refused", rv["formulaFound"] is False, str(rv["error"]))


def test_d_hostile_input_never_throws() -> None:
    print("\n(d) hostile / malformed input never raises")
    hostile_cases = [
        ("None", None),
        ("empty dict", {}),
        ("string", "not-a-statement"),
        ("list", [1, 2, 3]),
        ("statement without formula", {"statement": {"calculation": {"inputs": {}, "outputs": {}}}}),
        ("formula without slug", {"statement": {"formula": {}, "calculation": {}}}),
        ("garbage input values", {"statement": {
            "formula": {"slug": "compound-interest-calculator", "version": "1.0.0"},
            "calculation": {"inputs": {"initialPrincipal": {"type": "money", "value": "NaN"}},
                            "outputs": {}}}}),
        ("deeply nested junk", {"statement": {"formula": {"slug": "x", "version": "y"},
                                              "calculation": {"inputs": {"a": {"b": {"c": {}}}}, "outputs": {}}}}),
    ]
    for name, payload in hostile_cases:
        try:
            res = l2_verify.verify_l2(payload)
            ok = isinstance(res, dict) and res.get("reproduced") is False
            check(f"no throw + safe result: {name}", ok, json.dumps(res.get("error")))
        except Exception as exc:  # pragma: no cover - this is exactly what we forbid
            check(f"no throw + safe result: {name}", False, f"RAISED {type(exc).__name__}: {exc}")


def main() -> int:
    print("=" * 64)
    print("VCC L2 reproduction tests (offline, deterministic)")
    print("=" * 64)
    test_a_golden_reproduces()
    test_b_tampered_is_caught()
    test_c_unknown_formula_refused()
    test_d_hostile_input_never_throws()
    print("\n" + "=" * 64)
    if _failures == 0:
        print("ALL TESTS PASSED")
        return 0
    print(f"{_failures} CHECK(S) FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
