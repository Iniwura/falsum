"""Audit benchmark label provenance and selection/coverage by upstream category.

Historical metadata and observed policy predictions, not a semantic
vulnerability-localization score, live network result, or blind holdout.
"""
from collections import Counter
import argparse
import json
from pathlib import Path

from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require
from .phase5ak_external_label_baselines import (
    LOCK, PROTOCOL, load, replay, display_name,
)
from .phase5an_coverage_taxonomy import examine

UPSTREAM = {
    "key": "smartbugs_original_annotations",
    "repo": "smartbugs/smartbugs-curated",
    "commit": "230e649123477eff332742a59a1c7cc6dc286cab",
    "path": "vulnerabilities.json",
    "blob": "4771a256d0111997451dd323e6306b480da78794",
}
PREFIX = "https://github.com/smartbugs/smartbugs-curated/blob/" + UPSTREAM["commit"] + "/"
FIELDS = ("upstream", "selected", "omitted", "recorded_answers", "recorded_failures",
          "preflight_holds", "unexplained_missing", "verdict_flags",
          "count_only_pass", "selected_no_hint")


def annotation_index(records):
    require(type(records) is list, "annotations must be a list")
    out = {}
    for r in records:
        path = r["path"]
        parts = path.split("/")
        require(len(parts) == 3 and parts[0] == "dataset" and
                parts[2] == r["name"] and path not in out, "ambiguous annotation identity")
        category = parts[1]
        lines = []
        for v in r["vulnerabilities"]:
            if v["category"] == category:
                require(type(v["lines"]) is list and
                        all(type(n) is int and n > 0 for n in v["lines"]),
                        "invalid annotation line")
                lines.extend(v["lines"])
        require(bool(lines), "no primary category annotation")
        out[path] = {"category": category, "lines": sorted(set(lines)), "origin": r["source"]}
    return out


def measure(upstream, manifest, policies, coverage):
    original = annotation_index(upstream)
    policy = {c["case"]: c for c in policies}
    availability = {c["case"]: c for c in coverage}
    require(len(policy) == len(policies) and len(availability) == len(coverage)
            and set(policy) == set(availability), "ambiguous or divergent case census")
    table = {}
    for v in original.values():
        c = table.setdefault(v["category"], dict.fromkeys(FIELDS, 0))
        c["upstream"] += 1
    matched = set()
    seen = set()
    for x in manifest["items"]:
        name = display_name(x["name"])
        require(name in policy and name not in seen, "unknown or duplicate selected case")
        seen.add(name)
        if x["label"] == "audited":
            continue
        require(x["label"] == "vulnerable", "unexpected selected label")
        require(type(x["source"]) is str and x["source"].startswith(PREFIX),
                "wrong source revision")
        path = x["source"][len(PREFIX):]
        require(path in original and path not in matched, "unmatched or duplicate annotation path")
        r = original[path]
        require(type(x["lines"]) is list and
                all(type(n) is int and n > 0 for n in x["lines"]) and
                type(x["hint"]) is bool, "malformed selected metadata")
        require(x["category"] == r["category"] and
                sorted(set(x["lines"])) == r["lines"] and
                x["origin"] == r["origin"], "original annotation differs")
        matched.add(path)
        c = table[r["category"]]
        c["selected"] += 1
        c["selected_no_hint"] += int(not x["hint"])
        state = availability[name]["state"]
        field = {"RECORDED_ANSWER": "recorded_answers",
                 "RECORDED_FAILURE": "recorded_failures",
                 "INPUT_LIMIT_PREFLIGHT_HOLD": "preflight_holds",
                 "UNEXPLAINED_NO_ANSWER_RECORD": "unexplained_missing"}.get(state)
        require(field is not None, "unknown coverage state")
        c[field] += 1
        p = policy[name]
        require(p["label"] == "vulnerable" and p["hint"] == x["hint"],
                "policy label mismatch")
        c["verdict_flags"] += int(p["predictions"]["verdict_only"] == "FLAG")
        c["count_only_pass"] += int(p["predictions"]["count_only"] == "PASS")
    require(seen == set(policy), "incomplete selected census")
    for c in table.values():
        c["omitted"] = c["upstream"] - c["selected"]
        require(c["omitted"] >= 0 and c["selected"] == sum(c[k] for k in
                ("recorded_answers", "recorded_failures", "preflight_holds", "unexplained_missing")),
                "category population mismatch")
    return {"upstream_contracts": len(original), "selected_upstream_contracts": len(matched),
            "omitted_upstream_contracts": len(original) - len(matched),
            "original_metadata_matches": len(matched),
            "category_table": dict(sorted(table.items())),
            "omitted_paths": sorted(set(original) - matched)}


def audit(root=ROOT):
    raw_lock = (root / PROTOCOL).read_bytes()
    require(git_blob(raw_lock) == LOCK, "original scale protocol changed")
    lock = parse(raw_lock)
    raw = load({"sources": lock["sources"] + [UPSTREAM]})
    manifest = parse(raw["manifest"])
    summary, policies = replay(raw["ledger"], manifest, parse(raw["receipt_archive"]))
    require(summary == lock["expected"], "original scale summary changed")
    coverage = examine(raw["ledger"])
    report = measure(parse(raw[UPSTREAM["key"]]), manifest, policies, coverage["cases"])
    require((report["upstream_contracts"], report["selected_upstream_contracts"],
             report["omitted_upstream_contracts"], report["original_metadata_matches"]) ==
            (143, 107, 36, 107), "unexpected original annotation census")
    table = report["category_table"]
    require(table["unchecked_low_level_calls"] == {
        "upstream": 52, "selected": 20, "omitted": 32, "recorded_answers": 12,
        "recorded_failures": 1, "preflight_holds": 7, "unexplained_missing": 0,
        "verdict_flags": 12, "count_only_pass": 2, "selected_no_hint": 20
    }, "unexpected unchecked-call category census")
    require(sum(c["verdict_flags"] for c in table.values()) == 89 and
            sum(c["count_only_pass"] for c in table.values()) == 8 and
            sum(c["selected_no_hint"] for c in table.values()) == 76,
            "category totals disagree")
    return {"status": "PHASE5AP_UPSTREAM_ANNOTATION_SELECTION_AND_COVERAGE",
            "upstream_metadata": UPSTREAM, "scale_protocol_git_blob_sha1": LOCK,
            "report": report,
            "limits": {"selected_code_bytes_independently_verified": False,
                       "omitted_contracts_evaluated": False,
                       "vulnerability_localization_verified": False,
                       "provider_ranking_improvement_proved": False,
                       "independent_expert_gold_added": False,
                       "live_inference": False, "security_clearance_granted": False}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    report = audit()
    with args.out.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps({k: v for k, v in report["report"].items() if k != "omitted_paths"},
                     sort_keys=True))


if __name__ == "__main__":
    main()
