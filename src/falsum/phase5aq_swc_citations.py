"""Exact registry-linked CWE citation coverage on a source-defined historical subset.

No semantic accuracy, CWE hierarchy equivalence, localization, or new inference
is implied by the presence or absence of an exact citation.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from .phase5aj_cross_app_evidence import ROOT, INTENT, git_blob, parse, require
from .phase5ak_external_label_baselines import LOCK, PROTOCOL, load, replay, display_name
from .phase5an_coverage_taxonomy import histories, classify
from .phase5ap_upstream_selection import UPSTREAM, annotation_index, PREFIX

REGISTRY_COMMIT = "1b6227074ecd180b374e4844153afdda0332f979"
REGISTRY_BLOBS = {
    101: "6e62c58b5268c85fab4769116223e72eeae44e9c",
    105: "9d69b8da4abc307e06b60ce283f620486b982f6d",
    112: "7ace0e58a3a66eb8f3a12fa57d1a3f5ceece67a6",
    118: "b7cbd6c0464ef985a7a184ae679441cc757b260a",
    124: "253baa70a0876848ac392dc7a1534f28663dd69d",
}
ORIGIN = re.compile(
    r"^https://smartcontractsecurity\.github\.io/SWC-registry/docs/SWC-([0-9]+)(?:#| |$)"
)
CWE = re.compile(r"\bCWE[-\u2010-\u2015]([1-9][0-9]{0,5})\b", re.I)
RELATION = re.compile(r"\[CWE-([1-9][0-9]*): [^\]]+\]\(https?://cwe\.mitre\.org/data/definitions/([1-9][0-9]*)\.html\)")


def relationship(raw):
    text = raw.decode("utf-8", "strict")
    sections = re.findall(r"^## Relationships\s*\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    require(len(sections) == 1, "ambiguous registry relationship section")
    links = RELATION.findall(sections[0])
    require(len(links) == 1 and links[0][0] == links[0][1], "ambiguous or inconsistent registry CWE")
    return int(links[0][0])


def citation_check(expected, result):
    """Only an exact textual citation is measured, not detection correctness."""
    require(type(expected) is int and expected > 0, "invalid reference")
    if result is None:
        return {"issues": [], "summary": [], "state": "NO_RECORDED_ANSWER"}
    require(type(result) is dict, "invalid recorded answer")
    issues = result.get("issues")
    summary = result.get("summary")
    if issues is not None:
        require(type(issues) is list and all(type(i) is str for i in issues),
                "unsupported recorded issues shape")
    require(summary is None or type(summary) is str, "unsupported recorded summary shape")
    issue_ids = sorted({int(m[1]) for item in issues or [] for m in CWE.finditer(item)})
    summary_ids = sorted({int(m[1]) for m in CWE.finditer(summary or "")})
    return {"issues": issue_ids, "summary": summary_ids,
            "state": "EXACT_CITATION_PRESENT" if expected in issue_ids + summary_ids
                     else "EXACT_CITATION_NOT_OBSERVED"}


def measure(manifest, original, raw, relations):
    annotations = annotation_index(original)
    history = histories(raw)
    rows = []
    seen = set()
    for item in manifest["items"]:
        if item["label"] != "vulnerable":
            continue
        match = ORIGIN.match(item["origin"])
        if not match:
            continue
        swc = int(match[1])
        require(swc in relations, "unmapped direct SWC origin")
        require(item["source"].startswith(PREFIX), "wrong SmartBugs source revision")
        path = item["source"][len(PREFIX):]
        require(path in annotations and annotations[path]["origin"] == item["origin"] and
                annotations[path]["category"] == item["category"] and
                annotations[path]["lines"] == sorted(set(item["lines"])), "annotation provenance mismatch")
        case = display_name(item["name"])
        require(case in history and case not in seen, "missing or duplicate case")
        seen.add(case)
        decision, batch = history[case][-1]
        state = classify(decision, batch)
        evidence = [e for e in decision["evidence"] if e["intent"] == INTENT and e["ok"] is True]
        result = evidence[0]["result"] if evidence else None
        citation = citation_check(relations[swc], result)
        rows.append({"case": case, "swc": swc, "registry_cwe": relations[swc],
                     "hint": item["hint"], "availability": state,
                     "negative_verdict": result is not None and result.get("verdict") in ("Insecure", "Needs changes"),
                     "citation": citation})
    require({r["swc"] for r in rows} == set(relations), "registry selection mismatch")
    return {"cases": rows, "selected": len(rows),
            "availability": dict(Counter(r["availability"] for r in rows)),
            "citation_states": dict(Counter(r["citation"]["state"] for r in rows)),
            "negative_verdicts": sum(r["negative_verdict"] for r in rows),
            "no_hint_cases": sum(not r["hint"] for r in rows)}


def audit(root=ROOT):
    lock_bytes = (root / PROTOCOL).read_bytes()
    require(git_blob(lock_bytes) == LOCK, "scale protocol changed")
    lock = parse(lock_bytes)
    registry = [{"key": "swc-" + str(n), "repo": "SmartContractSecurity/SWC-registry",
                 "commit": REGISTRY_COMMIT, "path": "entries/docs/SWC-" + str(n) + ".md",
                 "blob": blob} for n, blob in REGISTRY_BLOBS.items()]
    raw = load({"sources": lock["sources"] + [UPSTREAM] + registry})
    manifest = parse(raw["manifest"])
    summary, _ = replay(raw["ledger"], manifest, parse(raw["receipt_archive"]))
    require(summary == lock["expected"], "scale aggregate changed")
    relations = {n: relationship(raw["swc-" + str(n)]) for n in REGISTRY_BLOBS}
    require(relations == {101:682,105:284,112:829,118:665,124:123}, "original relationship changed")
    report = measure(manifest, parse(raw[UPSTREAM["key"]]), raw["ledger"], relations)
    require(report["selected"] == 11 and report["negative_verdicts"] == 10 and
            report["no_hint_cases"] == 10 and
            report["availability"] == {"RECORDED_ANSWER":10,"INPUT_LIMIT_PREFLIGHT_HOLD":1} and
            report["citation_states"] == {"EXACT_CITATION_NOT_OBSERVED":10,"NO_RECORDED_ANSWER":1},
            "historical selected results differ")
    return {"status": "PHASE5AQ_ORIGINAL_REGISTRY_EXACT_CITATION_COVERAGE",
            "sources": registry + [UPSTREAM] + lock["sources"], "report": report,
            "registry_is_historical_not_maintained": True,
            "retrospective_selection_rule": "all vulnerable manifest entries with direct SWC registry docs URL",
            "semantic_accuracy_verified": False, "cwe_hierarchy_equivalence_evaluated": False,
            "vulnerability_localization_verified": False, "new_inference": False,
            "network_ranking_improvement_proved": False, "security_clearance_granted": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    r = audit()
    with a.out.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(r, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps({k:v for k,v in r["report"].items() if k != "cases"}, sort_keys=True))


if __name__ == "__main__":
    main()
