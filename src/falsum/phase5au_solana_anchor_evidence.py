"""Pinned Solana Anchor advisory evaluation material, not a security scanner."""
import argparse
import json
from pathlib import Path
import re

from .phase5aj_cross_app_evidence import git_blob, parse, require, source_bytes

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "data/phase5au-solana-anchor-protocol.json"
LOCK_BLOB = "e90406c9d7b6a6e4ba79e4c77392f8669681f710"
ADVISORY = "GHSA-c6rc-8jpp-2fgc"
CVE = "CVE-2026-45137"
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")


def protocol(path=LOCK):
    raw = path.read_bytes()
    require(git_blob(raw) == LOCK_BLOB, "Solana source protocol changed")
    return parse(raw)


def exact_version(value):
    if type(value) is not str:
        return None
    m = VERSION.fullmatch(value)
    return tuple(map(int, m.groups())) if m else None


def interval(advisory):
    require(advisory.get("id") == ADVISORY and CVE in advisory.get("aliases", [])
            and advisory.get("database_specific", {}).get("github_reviewed") is True,
            "reviewed advisory identity mismatch")
    affected = advisory["affected"]
    require(len(affected) == 1 and affected[0]["package"] ==
            {"ecosystem": "crates.io", "name": "anchor-lang"}, "advisory target changed")
    ranges = affected[0]["ranges"]
    require(len(ranges) == 1 and ranges[0]["type"] == "ECOSYSTEM"
            and ranges[0]["events"] == [{"introduced": "1.0.0"}, {"fixed": "1.0.2"}],
            "advisory interval changed")
    events = ranges[0]["events"]
    return exact_version(events[0]["introduced"]), exact_version(events[1]["fixed"])


def classify(case, bounds):
    if type(case) is not dict:
        return "INSUFFICIENT_EVIDENCE"
    if case.get("reference") not in (ADVISORY, CVE):
        return "UNKNOWN_REFERENCE"
    if (case.get("ecosystem"), case.get("package")) != ("crates.io", "anchor-lang"):
        return "UNKNOWN_TARGET"
    version = exact_version(case.get("version"))
    if version is None:
        return "INSUFFICIENT_EVIDENCE"
    return "APPLICABLE" if bounds[0] <= version < bounds[1] else "INAPPLICABLE"


def reference_only(case):
    """Naive advisory-match baseline; deliberately ignores version/target."""
    return "APPLICABLE" if case.get("reference") in (ADVISORY, CVE) else "UNKNOWN_REFERENCE"


def audit(path=LOCK, fetch=source_bytes):
    lock = protocol(path)
    raw = {}
    for source in lock["sources"]:
        body = fetch(source)
        require(git_blob(body) == source["blob"], "source blob mismatch")
        raw[source["key"]] = body
    require(len(raw) == 3, "incomplete upstream sources")
    bounds = interval(parse(raw["reviewed_advisory"]))
    fixed = raw["fixed_source_and_original_unit_tests"].decode("utf-8", "strict")
    affected = raw["advisory_cited_affected_source"].decode("utf-8", "strict")
    tests = ("program_system_rejects_non_system_account",
             "program_system_accepts_system_account",
             "program_system_rejects_non_executable_system_account",
             "program_unit_accepts_arbitrary_executable")
    require(all("fn " + t + "(" in fixed for t in tests), "missing upstream test definitions")
    require(raw["fixed_source_and_original_unit_tests"] != raw["advisory_cited_affected_source"]
            and all("fn " + t + "(" not in affected for t in tests), "unexpected source revision")
    rows = []
    for case in lock["cases"]:
        expected = case["expected"]
        rows.append({"id": case["id"], "expected": expected,
                     "reference_only": reference_only(case),
                     "source_bound": classify(case, bounds), "security_clearance": False})
    require(len(rows) == 12 and len({r["id"] for r in rows}) == 12, "case census changed")
    return {"intent": lock["intent"], "scope": lock["scope"], "sources": lock["sources"],
            "original_git_sources_verified": len(raw), "original_test_definitions_verified": len(tests),
            "upstream_tests_executed": False, "cases": len(rows),
            "reference_only_matches": sum(r["reference_only"] == r["expected"] for r in rows),
            "source_bound_matches": sum(r["source_bound"] == r["expected"] for r in rows),
            "reference_only_false_applicable": sum(r["reference_only"] == "APPLICABLE" and
                                                  r["expected"] != "APPLICABLE" for r in rows),
            "source_bound_false_applicable": sum(r["source_bound"] == "APPLICABLE" and
                                                 r["expected"] != "APPLICABLE" for r in rows),
            "security_clearance": False, "live_solana_integration": False,
            "independent_adoption": False, "model_accuracy_improvement": False, "rows": rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    report = audit()
    with a.out.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("rows", "sources")}, sort_keys=True))


if __name__ == "__main__":
    main()
