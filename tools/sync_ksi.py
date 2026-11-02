"""Sync verbatim KSI text and 800-53 mappings against FedRAMP/rules.

Every ksi_id referenced in samples/*.json and checks/*.yaml is looked up in
the upstream fedramp-consolidated-rules.json (KSI.<theme>.indicators.<id>).
The upstream statement and controls list are compared to our statement and
related_800_53_controls. Indicators that vary by class carry no top-level
statement upstream; for those the statement for our record's class is used.

Usage:
    python tools/sync_ksi.py --check   # print differences, exit 1 if any (CI)
    python tools/sync_ksi.py --diff    # print differences only, exit 0
    python tools/sync_ksi.py --write   # update files in place, refresh upstream.lock

--write replaces only the statement line and the related_800_53_controls
block in each file's text, so YAML comments, key order, formatting, and all
other fields are preserved. Fields that already match are left untouched.
upstream.lock records the upstream commit our text was last synced against.
It is rewritten only when synced content changes, the lock is missing, or
the set of synced ksi_ids changes, so an upstream commit that touches other
parts of the rules file does not produce an empty sync PR.

Set GITHUB_TOKEN to avoid GitHub API rate limits.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
LOCK_PATH = ROOT / "upstream.lock"

REPO = "FedRAMP/rules"
BRANCH = "main"
RULES_FILE = "fedramp-consolidated-rules.json"
COMMITS_URL = f"https://api.github.com/repos/{REPO}/commits"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{sha}/{path}"
TIMEOUT = 30

CONTROLS_WRAP = 76

# Flow sequence ([...], possibly multiline) or block sequence (- item lines).
YAML_CONTROLS_FLOW = re.compile(r"^related_800_53_controls:[ \t]*\[.*?\][ \t]*$", re.M | re.S)
YAML_CONTROLS_BLOCK = re.compile(r"^related_800_53_controls:[ \t]*\n(?:[ \t]+-.*(?:\n|$))+", re.M)
YAML_STATEMENT = re.compile(r"^statement:.*$", re.M)
JSON_CONTROLS = re.compile(r'^  "related_800_53_controls":\s*\[.*?\]', re.M | re.S)
JSON_STATEMENT = re.compile(r'^  "statement":\s*"(?:[^"\\]|\\.)*"', re.M)


class SyncError(Exception):
    pass


def normalize_control(control_id):
    """Normalize to our lowercase form: "IA-2(1)", "ia-02.01" -> "ia-2.1"."""
    c = control_id.strip().lower().replace(" ", "")
    m = re.fullmatch(r"([a-z]{2})-0*(\d+)(?:[.(]0*(\d+)\)?)?", c)
    if not m:
        return c
    family, base, enhancement = m.groups()
    return f"{family}-{base}" + (f".{enhancement}" if enhancement else "")


def github_headers():
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_upstream():
    """Return (sha, rules) for the latest commit touching the rules file."""
    resp = requests.get(
        COMMITS_URL,
        params={"path": RULES_FILE, "sha": BRANCH, "per_page": 1},
        headers=github_headers(),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    commits = resp.json()
    if not commits:
        raise SyncError(f"No commits found for {RULES_FILE} in {REPO}")
    sha = commits[0]["sha"]

    # Fetch at the exact sha so the content always matches the recorded commit.
    resp = requests.get(RAW_URL.format(repo=REPO, sha=sha, path=RULES_FILE), timeout=TIMEOUT)
    resp.raise_for_status()
    return sha, resp.json()


def upstream_indicator(rules, ksi_id):
    parts = ksi_id.split("-")
    if len(parts) != 3:
        return None
    theme = rules.get("KSI", {}).get(parts[1], {})
    return theme.get("indicators", {}).get(ksi_id)


def upstream_expected(rules, ksi_id, ksi_class):
    """Return (statement, controls) upstream for this KSI and class."""
    indicator = upstream_indicator(rules, ksi_id)
    if indicator is None:
        raise SyncError(f"{ksi_id} not found upstream (renamed or retired?)")
    if "statement" in indicator:
        statement = indicator["statement"]
    else:
        level = indicator.get("varies_by_class", {}).get(str(ksi_class or "").lower())
        if level is None:
            raise SyncError(f"{ksi_id} varies by class upstream and has no statement for class {ksi_class!r}")
        statement = level["statement"]
    controls = [normalize_control(c) for c in indicator.get("controls", [])]
    return statement, controls


def load_local():
    """Return one entry per local file that carries a ksi_id."""
    entries = []
    for path in sorted((ROOT / "samples").glob("*.json")):
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "ksi_id" in data:
            entries.append({"path": path, "kind": "json", "data": data})
    for path in sorted((ROOT / "checks").glob("*.yaml")):
        data = yaml.safe_load(path.read_text())
        if isinstance(data, dict) and "ksi_id" in data:
            entries.append({"path": path, "kind": "yaml", "data": data})
    return entries


def compare(entry, rules):
    """Return a dict describing drift for one file, or None if in sync."""
    data = entry["data"]
    ksi_id = data["ksi_id"]
    statement, controls = upstream_expected(rules, ksi_id, data.get("class"))
    ours_controls = [normalize_control(c) for c in data.get("related_800_53_controls", [])]

    drift = {}
    if data.get("statement") != statement:
        drift["statement"] = (data.get("statement"), statement)
    if set(ours_controls) != set(controls):
        drift["controls"] = (
            sorted(set(controls) - set(ours_controls)),
            sorted(set(ours_controls) - set(controls)),
        )
    if not drift:
        return None
    return {"ksi_id": ksi_id, "statement": statement, "controls": controls, "drift": drift}


def format_report(results):
    lines = []
    for entry, result in results:
        rel = entry["path"].relative_to(ROOT)
        lines.append(f"{result['ksi_id']}  {rel}")
        if "statement" in result["drift"]:
            ours, theirs = result["drift"]["statement"]
            lines.append("  statement:")
            lines.append(f"  - {ours}")
            lines.append(f"  + {theirs}")
        if "controls" in result["drift"]:
            added, removed = result["drift"]["controls"]
            lines.append("  related_800_53_controls:")
            for c in added:
                lines.append(f"  + {c}")
            for c in removed:
                lines.append(f"  - {c}")
        lines.append("")
    return "\n".join(lines)


def controls_block(key, controls, indent):
    """Compact wrapped list matching the hand-written style in this repo."""
    pad = " " * (indent + 2)
    lines, current = [], ""
    for item in (json.dumps(c) for c in controls):
        candidate = f"{current}, {item}" if current else f"{pad}{item}"
        if current and len(candidate) + 1 > CONTROLS_WRAP:
            lines.append(current + ",")
            current = f"{pad}{item}"
        else:
            current = candidate
    if current:
        lines.append(current)
    return f"{' ' * indent}{key}: [\n" + "\n".join(lines) + f"\n{' ' * indent}]"


def write_file(entry, result):
    """Replace only the drifted fields in the file text, then verify by parsing."""
    path, kind = entry["path"], entry["kind"]
    text = path.read_text()

    if "statement" in result["drift"]:
        # A JSON string is also a valid YAML double-quoted scalar.
        quoted = json.dumps(result["statement"], ensure_ascii=False)
        if kind == "yaml":
            text, n = YAML_STATEMENT.subn(lambda _: f"statement: {quoted}", text, count=1)
        else:
            text, n = JSON_STATEMENT.subn(lambda _: f'  "statement": {quoted}', text, count=1)
        if n != 1:
            raise SyncError(f"{path.name}: could not locate a top-level statement")

    if "controls" in result["drift"]:
        if kind == "yaml":
            block = controls_block("related_800_53_controls", result["controls"], 0)
            text, n = YAML_CONTROLS_FLOW.subn(lambda _: block, text, count=1)
            if n != 1:
                text, n = YAML_CONTROLS_BLOCK.subn(lambda _: block + "\n", text, count=1)
        else:
            block = controls_block('"related_800_53_controls"', result["controls"], 2)
            text, n = JSON_CONTROLS.subn(lambda _: block, text, count=1)
        if n != 1:
            raise SyncError(f"{path.name}: could not locate related_800_53_controls")

    # Refuse to write anything that does not parse back to the expected values.
    parsed = yaml.safe_load(text) if kind == "yaml" else json.loads(text)
    if parsed.get("statement") != result["statement"] or (
        "controls" in result["drift"] and parsed.get("related_800_53_controls") != result["controls"]
    ):
        raise SyncError(f"{path.name}: rewritten file did not round-trip; not writing")
    path.write_text(text)


def read_lock():
    try:
        return json.loads(LOCK_PATH.read_text())
    except FileNotFoundError:
        return None


def write_lock(sha, ksi_ids):
    lock = {
        "sha": sha,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ksi_ids": ksi_ids,
    }
    LOCK_PATH.write_text(json.dumps(lock, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Sync KSI text against FedRAMP/rules.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="print differences and exit 1 if any")
    mode.add_argument("--diff", action="store_true", help="print differences only")
    mode.add_argument("--write", action="store_true", help="update files in place and refresh upstream.lock")
    args = parser.parse_args()

    try:
        sha, rules = fetch_upstream()
    except (requests.RequestException, ValueError, SyncError) as exc:
        print(f"error: could not fetch upstream {REPO}/{RULES_FILE}: {exc}", file=sys.stderr)
        return 2

    entries = load_local()
    ksi_ids = sorted({e["data"]["ksi_id"] for e in entries})

    results, errors = [], []
    for entry in entries:
        try:
            result = compare(entry, rules)
        except SyncError as exc:
            errors.append(f"{entry['path'].relative_to(ROOT)}: {exc}")
            continue
        if result:
            results.append((entry, result))

    print(f"upstream {REPO}@{sha[:12]}  {len(ksi_ids)} KSIs across {len(entries)} files")
    report = format_report(results)
    if report:
        print()
        print(report)
    for err in errors:
        print(f"error: {err}", file=sys.stderr)
    if not results and not errors:
        print("in sync")

    if args.write:
        try:
            for entry, result in results:
                write_file(entry, result)
        except SyncError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        lock = read_lock()
        if results or lock is None or lock.get("ksi_ids") != ksi_ids:
            write_lock(sha, ksi_ids)
            print(f"wrote {len(results)} file(s), {LOCK_PATH.name} at {sha[:12]}")

    if errors:
        return 1
    if args.check and results:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
