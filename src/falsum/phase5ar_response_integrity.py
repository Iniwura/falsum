"""Portable response-integrity gate and original Truvian fixture replay.

This is not a vulnerability scanner. A clean candidate is not security
clearance; recorded app fields are not the original network HTTP body.
"""
import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import sys

from .phase5aj_cross_app_evidence import (
    ROOT, protocol, source_bytes, require, MISSING_CODE, parse,
)

NO_CODE = re.compile(
    r"\bno executable code,\s*configuration files,\s*or system descriptions were supplied for review\b"
    r"|\bthe input is purely informational data\b", re.I
)
FIELDS = {"verdict", "vulnerability_count", "issues", "summary"}
CONFIRMED = {"secureUnseen", "secureQueryOnly"}
CASES = {
    "securityUsdc": "reported_scan",
    "securitySquid": "reported_scan",
    "secureUnseen": "maintainer_confirmed_live_fields",
    "secureQueryOnly": "maintainer_confirmed_live_fields",
    "securityWethNvd": "reported_live_issue_bearing_review",
    "generic": "derived_regression_not_separate_live_answer",
    "securityWethTxLensLive": "reported_live_fields_with_node_shaping",
    "wethGoPlusScan": "reported_scan_fixture",
    "honeypot": "constructed_regression",
}
DECL = re.compile(r"\bconst\s+(\w+)\s*=\s*bought\('security',\s*'SECURITY_REVIEW_GENERAL',\s*\{")
STRING = r"""(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")"""
VALUE = re.compile(r"\s*(" + STRING + r"|null|[0-9]+|\[\s*(?:" +
                   STRING + r"\s*,?\s*)*\])\s*,?\s*", re.S)
KEY = re.compile(r"\s*(verdict|vulnerability_count|issues|summary)\s*:\s*")
SPREAD = re.compile(r"\s*\.\.\.securityWethNvd\.fields!,\s*")


def assess(fields):
    """Do not equate clean-looking structured fields with sufficient evidence."""
    if type(fields) is not dict:
        return {"decision": "REVIEW", "reasons": ["NO_VALID_ANSWER"], "security_clearance": False}
    verdict = fields.get("verdict")
    count = fields.get("vulnerability_count")
    issues = fields.get("issues")
    summary = fields.get("summary")
    reasons = []
    if verdict in ("Insecure", "Needs changes"):
        return {"decision": "FLAG", "reasons": ["NEGATIVE_VERDICT"], "security_clearance": False}
    if verdict != "Secure":
        reasons.append("NO_EXPLICIT_SECURE_VERDICT")
    if type(count) is not int or count != 0:
        reasons.append("COUNT_NOT_EXACT_ZERO")
    if issues is not None and (type(issues) is not list or
                              any(type(i) is not str or not i.strip() for i in issues)):
        reasons.append("MALFORMED_ISSUES")
    elif issues:
        reasons.append("REPORTED_ISSUES_REQUIRE_REVIEW")
    if type(summary) is not str or not summary.strip() or len(summary) > 12000:
        reasons.append("MISSING_OR_INVALID_SUMMARY")
    elif MISSING_CODE.search(summary) or NO_CODE.search(summary):
        reasons.append("EXPLICIT_NO_CODE_EVIDENCE")
    return {"decision": "REVIEW" if reasons else "CLEAN_CANDIDATE",
            "reasons": reasons, "security_clearance": False}


def verdict_only(fields):
    if fields.get("verdict") == "Secure":
        return "CLEAN_CANDIDATE"
    if fields.get("verdict") in ("Insecure", "Needs changes"):
        return "FLAG"
    return "REVIEW"


def count_verdict(fields):
    v = verdict_only(fields)
    c = fields.get("vulnerability_count")
    return "REVIEW" if v == "CLEAN_CANDIDATE" and (type(c) is not int or c != 0) else v


def declarations(raw):
    """Read only a pinned, limited TypeScript literal grammar; never execute it."""
    source = raw.decode("utf-8", "strict")
    result = {}
    for m in DECL.finditer(source):
        name = m[1]
        require(name in CASES and name not in result, "unexpected/duplicate declaration")
        pos = m.end()
        values = {}
        explicit = set()
        spread = SPREAD.match(source, pos)
        if spread:
            require(name == "securityWethTxLensLive" and "securityWethNvd" in result,
                    "unexpected spread")
            values = dict(result["securityWethNvd"])
            pos = spread.end()
        while True:
            end = re.match(r"\s*\}\s*,", source[pos:])
            if end:
                break
            key = KEY.match(source, pos)
            require(key is not None and key[1] not in explicit, "unsupported/duplicate field")
            explicit.add(key[1])
            value = VALUE.match(source, key.end())
            require(value is not None, "unsupported value")
            token = value[1]
            values[key[1]] = None if token == "null" else ast.literal_eval(token)
            pos = value.end()
        require(set(values) == FIELDS, "incomplete source fields")
        require((values["verdict"] is None or type(values["verdict"]) is str) and
                (values["vulnerability_count"] is None or type(values["vulnerability_count"]) is int) and
                (values["issues"] is None or type(values["issues"]) is list) and
                type(values["summary"]) is str, "invalid source field types")
        result[name] = values
    require(set(result) == set(CASES), "incomplete original fixture census")
    return result


def evaluate_original(raw):
    rows = []
    for name, fields in declarations(raw).items():
        gate = assess(fields)
        rows.append({"fixture": name, "source_class": CASES[name],
                     "maintainer_confirmed_fields": name in CONFIRMED,
                     "verdict_only": verdict_only(fields), "count_and_verdict": count_verdict(fields),
                     "gate": gate, "issue_count": None if fields["issues"] is None else len(fields["issues"])})
    missing = [r for r in rows if "EXPLICIT_NO_CODE_EVIDENCE" in r["gate"]["reasons"]]
    summary = {"original_direct_fixtures": len(rows),
               "maintainer_confirmed": sum(r["maintainer_confirmed_fields"] for r in rows),
               "explicit_no_code_fixtures": len(missing),
               "explicit_no_code_verdict_only_clean": sum(r["verdict_only"] == "CLEAN_CANDIDATE" for r in missing),
               "explicit_no_code_count_verdict_clean": sum(r["count_and_verdict"] == "CLEAN_CANDIDATE" for r in missing),
               "explicit_no_code_gate_clean": sum(r["gate"]["decision"] == "CLEAN_CANDIDATE" for r in missing),
               "gate_decisions_all_fixtures": dict(Counter(r["gate"]["decision"] for r in rows)),
               "verdict_only_clean_all_fixtures": sum(r["verdict_only"] == "CLEAN_CANDIDATE" for r in rows)}
    require(summary["original_direct_fixtures"] == 9 and summary["maintainer_confirmed"] == 2
            and summary["explicit_no_code_fixtures"] == 3
            and summary["explicit_no_code_verdict_only_clean"] == 3
            and summary["explicit_no_code_count_verdict_clean"] == 2
            and summary["explicit_no_code_gate_clean"] == 0, "original fixture comparison changed")
    require({r["fixture"] for r in missing} == CONFIRMED | {"securityWethTxLensLive"},
            "missing-evidence fixture identities changed")
    return {"status": "PHASE5AR_ORIGINAL_APP_RESPONSE_INTEGRITY",
            "summary": summary, "fixtures": rows,
            "scope": "retrospective direct fixture declarations; not distinct independent requests",
            "external_review": "https://github.com/Iniwura/falsum/issues/97#issuecomment-7132041935",
            "limits": {"security_clearance": False, "live_inference": False,
                       "network_ranking_improvement": False, "semantic_accuracy": False,
                       "independent_integration": False, "raw_network_capture": False}}


def audit(root=ROOT):
    spec = next(s for s in protocol(root)["sources"] if s["key"] == "truvian_tests")
    report = evaluate_original(source_bytes(spec))
    report["original_source"] = spec
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stdin", action="store_true", help="read one response JSON from stdin")
    p.add_argument("--out", type=Path, help="create a replay report")
    a = p.parse_args()
    if a.stdin:
        if a.out:
            p.error("--stdin and --out are mutually exclusive")
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, "response exceeds byte limit")
        print(json.dumps(assess(parse(raw)), sort_keys=True, allow_nan=False))
        return
    if not a.out:
        p.error("provide --out for original replay, or --stdin")
    r = audit()
    with a.out.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(r, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps(r["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
