#!/usr/bin/env python3
"""VCC portable JSON Schema validator (dev tool).

Validates that:
  (a) the schema/examples/*.valid.json files pass their schema;
  (b) the schema/examples/*.invalid-*.json files are REJECTED by their schema;
  (c) every vectors/*.json `.statement` conforms to the statement schema
      (the re-signed corpus carries the `calcfleet.com/vcc` namespace).

Draft 2020-12. Requires `jsonschema`.

Usage:
    python schema/validate.py
Exit code 0 iff every expectation holds.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except Exception as exc:  # pragma: no cover
    print(f"ERROR: jsonschema not importable: {exc}", file=sys.stderr)
    sys.exit(2)

SCHEMA_DIR = Path(__file__).resolve().parent
REPO_DIR = SCHEMA_DIR.parent
EXAMPLES_DIR = SCHEMA_DIR / "examples"
VECTORS_DIR = REPO_DIR / "vectors"

# Which schema each example-file prefix validates against.
SCHEMA_FILES = {
    "statement": "statement-v0.2.schema.json",
    "envelope": "envelope-v0.2.schema.json",
    "issuer-keyset": "issuer-keyset-v0.2.schema.json",
    "formula-manifest": "formula-manifest-v0.2.schema.json",
    "dataset-manifest": "dataset-manifest-v0.2.schema.json",
}


def load_json(path: Path):
    with path.open() as f:
        return json.load(f)


def validator_for(schema_file: str) -> Draft202012Validator:
    schema = load_json(SCHEMA_DIR / schema_file)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def prefix_of(name: str) -> str | None:
    # longest matching known prefix wins (issuer-keyset before ... etc.)
    for pfx in sorted(SCHEMA_FILES, key=len, reverse=True):
        if name.startswith(pfx + "."):
            return pfx
    return None


def main() -> int:
    validators = {pfx: validator_for(sf) for pfx, sf in SCHEMA_FILES.items()}
    failures: list[str] = []

    # ---- (a)+(b) examples ---------------------------------------------------
    print("== Examples ==")
    example_files = sorted(EXAMPLES_DIR.glob("*.json"))
    for path in example_files:
        name = path.name
        pfx = prefix_of(name)
        if pfx is None:
            failures.append(f"{name}: no known schema prefix")
            print(f"  [??] {name}: no schema prefix")
            continue
        validator = validators[pfx]
        instance = load_json(path)
        errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
        # Naming: <prefix>.valid[-reason].json passes; <prefix>.invalid-reason.json
        # is rejected. Classify on the segment after the prefix, not substring
        # matching ("invalid" contains "valid").
        kind = name[len(pfx) + 1 :].split(".")[0]
        is_valid_example = kind == "valid" or kind.startswith("valid-")
        if is_valid_example:
            if errors:
                failures.append(f"{name}: expected VALID but got errors")
                print(f"  [FAIL] {name}: expected PASS, got:")
                for e in errors[:3]:
                    print(f"           - {list(e.path)}: {e.message}")
            else:
                print(f"  [ok]   {name}: PASS (valid, as expected)")
        else:  # invalid example -> must be rejected
            if errors:
                first = errors[0]
                print(
                    f"  [ok]   {name}: REJECTED (as expected) -- "
                    f"{list(first.path)}: {first.message[:80]}"
                )
            else:
                failures.append(f"{name}: expected REJECT but it PASSED")
                print(f"  [FAIL] {name}: expected REJECT, but it PASSED")

    # ---- (c) vectors --------------------------------------------------------
    print("\n== Vectors (.statement structure) ==")
    stmt_validator = validators["statement"]
    vector_files = sorted(VECTORS_DIR.glob("*.json"))
    for path in vector_files:
        data = load_json(path)
        stmt = data.get("statement")
        if stmt is None:
            print(f"  [--]   {path.name}: no .statement, skipped")
            continue
        errors = sorted(stmt_validator.iter_errors(stmt), key=lambda e: e.path)
        if errors:
            failures.append(f"vector {path.name}: statement failed schema")
            print(f"  [FAIL] {path.name}: statement INVALID")
            for e in errors[:5]:
                print(f"           - {list(e.path)}: {e.message}")
        else:
            print(f"  [ok]   {path.name}: statement VALID")

    # ---- summary ------------------------------------------------------------
    print("\n== Summary ==")
    if failures:
        print(f"FAILED: {len(failures)} expectation(s) not met:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All expectations met: valid examples pass, invalid examples rejected,")
    print("all vector statements conform to the statement schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
