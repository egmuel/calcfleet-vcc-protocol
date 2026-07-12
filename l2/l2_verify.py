"""Standalone, offline L2 verifier for VCC calculation statements.

L2 ("reproducible calculation") complements L1 ("valid signature + integrity"):

  * L1 (the two verifiers in ``verifiers/``) proves the receipt is authentically
    signed and byte-intact.
  * L2 (this file) proves the OUTPUTS FOLLOW FROM THE INPUTS under the declared
    formula, by re-executing a LOCALLY-INSTALLED, allowlisted implementation and
    comparing the recomputed outputs to the certificate's declared outputs.

Security posture (ADR-005):
  * The formula is resolved ONLY from the local allowlist (``registry.py``), keyed
    by the certificate's ``(slug, version)``. Nothing from the certificate is ever
    fetched, imported, or evaluated — no ``formula.registry`` URL is touched.
  * Fully offline and deterministic (Decimal arithmetic, fixed rounding).
  * The public entry point NEVER throws on hostile input; on any unexpected error
    it returns a well-formed, all-negative result with an ``error`` string.

Comparison is EXACT canonical typed-value equality: recomputed and declared values
must agree on ``type``, ``value`` (the decimal string), ``scale``, and ``unit``.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

import registry


# Fields of a numeric typed value that must match exactly for reproduction.
_TYPED_VALUE_KEYS = ("type", "value", "scale", "unit")


def _statement_from(payload: Any) -> Optional[dict]:
    """Accept either a full vector object ({statement: ...}) or a bare statement."""
    if not isinstance(payload, dict):
        return None
    if isinstance(payload.get("statement"), dict):
        return payload["statement"]
    if isinstance(payload.get("calculation"), dict):
        return payload
    return None


def _decode_inputs(inputs: Dict[str, Any]) -> Dict[str, Decimal]:
    """Decode the statement's typed input values to exact Decimals.

    Canonical decimal strings decode losslessly into Decimal — no float ever
    touches the value. Missing/malformed values raise, and the caller catches.
    """
    decoded: Dict[str, Decimal] = {}
    for key, tv in inputs.items():
        if not isinstance(tv, dict) or "value" not in tv:
            raise ValueError(f"input {key!r} is not a typed value")
        decoded[key] = Decimal(str(tv["value"]))
    return decoded


def _canonical_typed_value(tv: Any) -> Optional[Dict[str, Any]]:
    """Project a typed value down to the canonical comparison keys, if it is one."""
    if not isinstance(tv, dict):
        return None
    if "value" not in tv or "type" not in tv:
        return None
    return {k: tv.get(k) for k in _TYPED_VALUE_KEYS}


def _compare(
    path: str,
    declared: Any,
    recomputed: Any,
    mismatches: List[Dict[str, Any]],
) -> None:
    """Recursively compare declared vs recomputed outputs, collecting mismatches.

    Handles nested dicts (typed values or containers) and lists (e.g. yearlyTable).
    """
    # Case 1: both are typed numeric values -> exact field-by-field equality.
    dtv = _canonical_typed_value(declared)
    rtv = _canonical_typed_value(recomputed)
    if dtv is not None and rtv is not None:
        if dtv != rtv:
            mismatches.append({"path": path, "declared": dtv, "recomputed": rtv})
        return

    # Case 2: lists (rows) -> compare element-wise, flag length differences.
    if isinstance(declared, list) or isinstance(recomputed, list):
        if not isinstance(declared, list) or not isinstance(recomputed, list):
            mismatches.append({"path": path, "declared": declared, "recomputed": recomputed})
            return
        if len(declared) != len(recomputed):
            mismatches.append(
                {
                    "path": path,
                    "reason": "length mismatch",
                    "declaredLength": len(declared),
                    "recomputedLength": len(recomputed),
                }
            )
            return
        for i, (d, r) in enumerate(zip(declared, recomputed)):
            _compare(f"{path}[{i}]", d, r, mismatches)
        return

    # Case 3: plain dict containers -> compare on the union of keys.
    if isinstance(declared, dict) and isinstance(recomputed, dict):
        keys = sorted(set(declared.keys()) | set(recomputed.keys()))
        for k in keys:
            if k not in declared or k not in recomputed:
                mismatches.append(
                    {"path": f"{path}.{k}", "reason": "missing field",
                     "inDeclared": k in declared, "inRecomputed": k in recomputed}
                )
                continue
            _compare(f"{path}.{k}", declared[k], recomputed[k], mismatches)
        return

    # Case 4: anything else -> direct equality.
    if declared != recomputed:
        mismatches.append({"path": path, "declared": declared, "recomputed": recomputed})


def verify_l2(payload: Any) -> Dict[str, Any]:
    """Verify L2 reproducibility of a VCC statement. NEVER raises.

    Returns a result dict:
      {
        "formulaFound": bool,     # was (slug, version) in the local allowlist?
        "reproduced": bool,       # recomputed outputs == declared outputs (exact)?
        "mismatches": [ ... ],    # per-field diffs when not reproduced
        "slug": str | None,
        "version": str | None,
        "error": str | None,      # populated only on malformed/hostile input
      }
    """
    result: Dict[str, Any] = {
        "formulaFound": False,
        "reproduced": False,
        "mismatches": [],
        "slug": None,
        "version": None,
        "error": None,
    }
    try:
        statement = _statement_from(payload)
        if statement is None:
            result["error"] = "input is not a VCC statement"
            return result

        formula = statement.get("formula")
        if not isinstance(formula, dict):
            result["error"] = "statement has no formula block"
            return result

        slug = formula.get("slug")
        version = formula.get("version")
        result["slug"] = slug if isinstance(slug, str) else None
        result["version"] = version if isinstance(version, str) else None
        if not isinstance(slug, str) or not isinstance(version, str):
            result["error"] = "formula slug/version missing or not strings"
            return result

        # LOCAL ALLOWLIST ONLY. formula.registry (a URL) is intentionally ignored.
        compute = registry.resolve(slug, version)
        if compute is None:
            # Not in allowlist -> formula-unavailable. Do NOT execute anything.
            result["error"] = f"formula {slug}@{version} not in local allowlist"
            return result
        result["formulaFound"] = True

        calculation = statement.get("calculation")
        if not isinstance(calculation, dict):
            result["error"] = "statement has no calculation block"
            return result

        declared_inputs = calculation.get("inputs")
        declared_outputs = calculation.get("outputs")
        if not isinstance(declared_inputs, dict) or not isinstance(declared_outputs, dict):
            result["error"] = "calculation inputs/outputs missing or malformed"
            return result

        try:
            decoded = _decode_inputs(declared_inputs)
        except (ValueError, InvalidOperation, ArithmeticError) as exc:
            result["error"] = f"could not decode inputs: {exc}"
            return result

        # Re-execute the local pure formula on the decoded inputs. A pure calc
        # given schema-invalid inputs may legitimately raise (e.g. a missing
        # field); that is a reproducibility failure, not a crash.
        try:
            recomputed_outputs = compute(decoded)
        except Exception as exc:
            result["error"] = f"formula execution failed: {type(exc).__name__}: {exc}"
            return result

        # Exact field-by-field comparison of recomputed vs declared outputs.
        mismatches: List[Dict[str, Any]] = []
        _compare("outputs", declared_outputs, recomputed_outputs, mismatches)
        result["mismatches"] = mismatches
        result["reproduced"] = len(mismatches) == 0
        return result

    except Exception as exc:  # never throw on hostile input
        result["error"] = f"unexpected error: {type(exc).__name__}: {exc}"
        result["reproduced"] = False
        return result


if __name__ == "__main__":  # tiny CLI: `python l2_verify.py <statement.json>`
    import json
    import sys

    if len(sys.argv) != 2:
        print("usage: python l2_verify.py <vcc-statement-or-vector.json>", file=sys.stderr)
        sys.exit(2)
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out = verify_l2(data)
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["reproduced"] else 1)
