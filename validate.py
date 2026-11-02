#!/usr/bin/env python3
"""Validate KSI evidence records against the schema and print a summary.

Usage:
    python validate.py                          # validates every *.json in samples/
    python validate.py path/to/*.json           # validates the given files
    python validate.py --checks                 # validates every check in checks/
    python validate.py --checks path/to/*.yaml  # validates the given check files

Exit code is 0 when every record (or check) is schema-valid, 1 otherwise.
A record with result=false or result=null is still schema-valid; the exit
code reflects whether the records are well-formed, not whether the KSIs pass.
Both are reported in the table so the distinction is visible.
"""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "schema" / "ksi-evidence.schema.json"
SAMPLES_DIR = ROOT / "samples"
CHECK_SCHEMA_PATH = ROOT / "checks" / "schema.json"
CHECKS_DIR = ROOT / "checks"


def load_schema():
    with SCHEMA_PATH.open() as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def load_check_schema():
    """Validator for check definitions. The check schema reuses field
    definitions from the evidence schema by $ref, so both are registered."""
    from referencing import Registry, Resource

    with SCHEMA_PATH.open() as f:
        evidence_schema = json.load(f)
    with CHECK_SCHEMA_PATH.open() as f:
        check_schema = json.load(f)
    Draft202012Validator.check_schema(check_schema)
    registry = Registry().with_resource(evidence_schema["$id"], Resource.from_contents(evidence_schema))
    return Draft202012Validator(check_schema, registry=registry, format_checker=FormatChecker())


def result_label(value):
    if value is True:
        return "PASS"
    if value is False:
        return "FAIL"
    return "NULL"


def validate_file(validator, path):
    try:
        with path.open() as f:
            record = json.load(f)
    except json.JSONDecodeError as exc:
        return {"file": path.name, "ksi_id": "?", "result": "?", "valid": False,
                "errors": [f"invalid JSON: {exc}"], "rationale": ""}

    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    return {
        "file": path.name,
        "ksi_id": record.get("ksi_id", "?"),
        "result": result_label(record.get("result")),
        "valid": not errors,
        "errors": [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors],
        "rationale": record.get("rationale", ""),
    }


def validate_check(validator, path):
    import yaml

    try:
        with path.open() as f:
            check = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        return {"file": path.name, "ksi_id": "?", "valid": False, "errors": [f"invalid YAML: {exc}"]}

    errors = sorted(validator.iter_errors(check), key=lambda e: list(e.path))
    return {
        "file": path.name,
        "ksi_id": check.get("ksi_id", "?") if isinstance(check, dict) else "?",
        "valid": not errors,
        "errors": [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors],
    }


def main_checks(argv):
    files = [Path(a) for a in argv] if argv else sorted(CHECKS_DIR.glob("*.y*ml"))
    if not files:
        print("no check definitions found", file=sys.stderr)
        return 1

    validator = load_check_schema()
    rows = [validate_check(validator, p) for p in files]

    header = f"{'KSI':<13}{'VALID':<7}FILE"
    print(header)
    print("-" * len(header))
    for r in rows:
        detail = r["file"] if r["valid"] else f"{r['file']}: {'; '.join(r['errors'])}"
        print(f"{r['ksi_id']:<13}{'yes' if r['valid'] else 'NO':<7}{detail}")

    invalid = [r for r in rows if not r["valid"]]
    print()
    print(f"{len(rows)} check definitions, {len(invalid)} schema-invalid")
    return 1 if invalid else 0


def main(argv):
    if argv and argv[0] == "--checks":
        return main_checks(argv[1:])

    files = [Path(a) for a in argv] if argv else sorted(SAMPLES_DIR.glob("*.json"))
    if not files:
        print("no records found", file=sys.stderr)
        return 1

    validator = load_schema()
    rows = [validate_file(validator, p) for p in files]

    header = f"{'KSI':<13}{'RESULT':<8}{'VALID':<7}RATIONALE"
    print(header)
    print("-" * len(header))
    for r in rows:
        rationale = r["rationale"] if r["valid"] else "; ".join(r["errors"])
        print(f"{r['ksi_id']:<13}{r['result']:<8}{'yes' if r['valid'] else 'NO':<7}{rationale}")

    invalid = [r for r in rows if not r["valid"]]
    failing = [r for r in rows if r["valid"] and r["result"] != "PASS"]
    print()
    print(f"{len(rows)} records, {len(invalid)} schema-invalid, {len(failing)} with result false or null")
    return 1 if invalid else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
