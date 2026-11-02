#!/usr/bin/env python3
"""Reference collector: turn one check definition into one KSI evidence record.

Usage:
    python collector.py checks/ksi-iam-apm.yaml

Loads the check, calls the fetch function registered for its source system,
evaluates pass_when, renders the matching rationale template, and writes one
record to stdout. Any failure to fetch or evaluate produces result null with
the null rationale; a missing record is never an outcome.

The only fetch function shipped here is a fake for the identity provider.
An engineering team replaces FETCHERS with functions that call their real
systems. Everything else stays as is.

Exit code is 0 when the emitted record is schema-valid, 1 otherwise. As with
validate.py, a false or null result is reported, not enforced.
"""

import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import yaml

from validate import load_check_schema, load_schema


class CollectionError(Exception):
    """Evidence could not be collected or evaluated. The message becomes {failure_reason}."""


# Fetch functions: fetch(source, timeout_seconds) -> parsed JSON response.
# A real fetch must enforce timeout_seconds itself and raise on expiry.

def fake_identity_provider(source, timeout_seconds):
    return {
        "policies": [
            {"id": "pol-01", "name": "workforce-default", "in_scope": True, "permitted_methods": ["fido2", "piv"]},
            {"id": "pol-02", "name": "privileged-admin", "in_scope": True, "permitted_methods": ["piv"]},
            {"id": "pol-03", "name": "break-glass", "in_scope": True, "permitted_methods": ["fido2"]},
            {"id": "pol-04", "name": "service-desk", "in_scope": True, "permitted_methods": ["fido2", "piv"]},
        ]
    }


FETCHERS = {
    "identity-provider": fake_identity_provider,
}


# Evaluators: one per KSI, implementing that check's pass_when and null_when.
# evaluator(values, parameters) -> (result, placeholders). Raise
# CollectionError for any null_when condition.

def evaluate_iam_apm(values, params):
    policies = values["in_scope_policies"]
    if not policies:
        raise CollectionError("Identity provider returned zero in-scope authentication policies")
    allowed = params["allowed_methods"]
    violations = []
    for policy in policies:
        methods = {m.lower() for m in policy.get("permitted_methods") or []}
        if not methods:
            raise CollectionError(f"Policy {policy.get('name', '?')} lists no permitted methods")
        outside = sorted(methods - set(allowed))
        if outside:
            violations.append(f"{policy['name']} permits {', '.join(outside)}")

    permitted = {m.lower() for m in values["permitted_methods"]}
    in_use = [m for m in allowed if m in permitted]
    return permitted <= set(allowed), {
        "policy_count": len(policies),
        "methods_in_use": " or ".join(params["method_labels"][m] for m in in_use),
        "violation_count": len(violations),
        "violations": "; ".join(violations),
    }


def _describe(ids, inventory):
    counts = Counter(inventory[i]["type"] for i in ids)
    return ", ".join(
        f"{n} {kind.replace('_', ' ')}{'' if n == 1 else 's'}" for kind, n in sorted(counts.items())
    )


def evaluate_piy_giv(values, params):
    cloud = {r["id"]: r for r in values["cloud_resources"]}
    iac = {r["id"]: r for r in values["iac_resources"]}
    if not cloud and not iac:
        raise CollectionError("Cloud API and IaC state both returned zero resources")
    difference = cloud.keys() ^ iac.keys()
    unexplained = difference - set(values["approved_resource_ids"])

    parts = []
    cloud_only = sorted(unexplained & cloud.keys())
    iac_only = sorted(unexplained & iac.keys())
    if cloud_only:
        parts.append(f"Cloud API reports {_describe(cloud_only, cloud)} not present in IaC state")
    if iac_only:
        parts.append(f"IaC state declares {_describe(iac_only, iac)} not reported by the cloud API")
    return not unexplained, {
        "resource_count": len(cloud.keys() | iac.keys()),
        "explained_count": len(difference) - len(unexplained),
        "drift_summary": "; ".join(parts),
    }


def evaluate_mla_osm(values, params):
    expected = set(values["in_scope_sources"])
    if not expected:
        raise CollectionError("Asset inventory returned zero in-scope log sources")
    if not values["immutability_enabled"]:
        raise CollectionError("Log store did not report its immutability setting")
    silent = sorted(expected - set(values["reporting_sources"]))
    immutable = values["immutability_enabled"][0] is True

    parts = []
    if silent:
        parts.append(
            f"{len(silent)} of {len(expected)} in-scope log sources emitted no events "
            f"in the last {params['window']} ({', '.join(silent)})"
        )
    if not immutable:
        parts.append("the log store reports immutability disabled")
    summary = " and ".join(parts)
    return not silent and immutable, {
        "source_count": len(expected),
        "window": params["window"],
        "fail_summary": summary[:1].upper() + summary[1:],
    }


EVALUATORS = {
    "KSI-IAM-APM": evaluate_iam_apm,
    "KSI-PIY-GIV": evaluate_piy_giv,
    "KSI-MLA-OSM": evaluate_mla_osm,
}


# Minimal JSONPath: $, .key, [*], and [?(@.key OP literal)] with
# OP in == != > >= < <=. Enough for the paths in checks/; anything else is
# rejected rather than guessed at.

_PATH_TOKEN = re.compile(
    r"\.(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<star>\[\*\])"
    r"|\[\?\(@\.(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>==|!=|>=|<=|>|<)\s*(?P<literal>[^)]+?)\s*\)\]"
)
_OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
}


def _literal(text):
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1]
    return json.loads(text)


def jsonpath(document, path):
    if not path.startswith("$"):
        raise ValueError(f"unsupported JSONPath {path!r}")
    nodes, pos = [document], 1
    while pos < len(path):
        m = _PATH_TOKEN.match(path, pos)
        if not m:
            raise ValueError(f"unsupported JSONPath {path!r} at offset {pos}")
        pos = m.end()
        if m["key"]:
            nodes = [n[m["key"]] for n in nodes if isinstance(n, dict) and m["key"] in n]
        elif m["star"]:
            nodes = [child for n in nodes if isinstance(n, list) for child in n]
        else:
            op, value = _OPS[m["op"]], _literal(m["literal"])
            nodes = [
                child for n in nodes if isinstance(n, list) for child in n
                if isinstance(child, dict) and m["field"] in child and op(child[m["field"]], value)
            ]
    return nodes


def parse_duration(text):
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", text)
    days, hours, minutes, seconds = (int(g or 0) for g in m.groups())
    return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def _failure_reason(exc, system):
    if isinstance(exc, CollectionError):
        reason = str(exc)
    else:
        reason = f"Collection from {system} failed with {type(exc).__name__}: {exc}"
    return reason.rstrip(".")


def missing_fetcher(source, timeout_seconds):
    raise CollectionError(f"No fetch function is registered for source system {source['system']}")


def collect(check, fetch, now=None):
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    source = {"system": check["source"]["system"], "query": check["source"]["query"]}
    evaluate = check["evaluate"]

    try:
        timeout = parse_duration(check["collect"]["timeout"]).total_seconds()
        response = fetch(dict(source), timeout)
        values = {}
        for item in evaluate["extract"]:
            if "jsonpath" not in item:
                raise CollectionError(f"Extraction {item['name']} has no jsonpath; this collector needs a custom extractor for it")
            values[item["name"]] = jsonpath(response, item["jsonpath"])
        evaluator = EVALUATORS.get(check["ksi_id"])
        if evaluator is None:
            raise CollectionError(f"No evaluator is implemented for {check['ksi_id']}")
        result, placeholders = evaluator(values, evaluate.get("parameters", {}))
        canonical = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
        source["artifact_sha256"] = hashlib.sha256(canonical).hexdigest()
    except Exception as exc:
        result, placeholders = None, {"failure_reason": _failure_reason(exc, source["system"])}

    template = check["rationale"][{True: "pass", False: "fail", None: "null"}[result]]
    return {
        "ksi_id": check["ksi_id"],
        "statement": check["statement"],
        "class": check["class"],
        "evidence_type": check["evidence_type"],
        "source": source,
        "collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "result": result,
        "rationale": template.format(**placeholders),
        "owner": check["owner"],
        "related_800_53_controls": check["related_800_53_controls"],
        "next_collection_due": (now + parse_duration(check["collect"]["interval"])).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main(argv):
    if len(argv) != 1:
        print("usage: python collector.py checks/<ksi>.yaml", file=sys.stderr)
        return 1

    with open(argv[0]) as f:
        check = yaml.safe_load(f)
    check_errors = list(load_check_schema().iter_errors(check))
    if check_errors:
        for e in check_errors:
            print(f"check definition invalid: {'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}", file=sys.stderr)
        return 1

    record = collect(check, FETCHERS.get(check["source"]["system"], missing_fetcher))
    print(json.dumps(record, indent=2))

    record_errors = list(load_schema().iter_errors(record))
    for e in record_errors:
        print(f"record invalid: {'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}", file=sys.stderr)
    return 1 if record_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
