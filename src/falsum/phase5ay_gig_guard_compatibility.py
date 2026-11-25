"""Optional fail-closed postcondition for Gig Guard's existing shipVerdict.

Consumes its actual decision/evidence shape; never purchases intelligence.
A SHIP disposition is not security clearance. Does not replace local checks.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from . import phase5ak_external_label_baselines as historical
from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require
from .phase5ar_response_integrity import assess

PROTOCOL = ROOT / "data/phase5ay-gig-guard-compatibility-protocol.json"
LOCK = "13876608620632801caedc567acd8c98345633e4"
SEC = "SECURITY_REVIEW_GENERAL"
CODE = "CODE_REVIEW_GENERAL"


def successful(evidence, intent):
    if type(evidence) is not list or any(type(x) is not dict for x in evidence):
        return None
    matches = [x for x in evidence if x.get("intent") == intent]
    if len(matches) != 1:
        return None
    item = matches[0]
    result = item.get("result")
    if item.get("ok") is not True or type(result) is not dict or not result:
        return None
    return result


def postcondition(original, evidence):
    """Preserve original FIX/HOLD; otherwise require both reviews and integrity."""
    if original in ("FIX", "HOLD"):
        return dict(verdict=original, availability_baseline=original,
                    reason="ORIGINAL_RESTRICTION_PRESERVED", security_clearance=False)
    if original != "SHIP":
        return dict(verdict="HOLD", availability_baseline="HOLD",
                    reason="INVALID_ORIGINAL_DECISION", security_clearance=False)
    sec, code = successful(evidence, SEC), successful(evidence, CODE)
    if sec is None or code is None:
        return dict(verdict="HOLD", availability_baseline="HOLD",
                    reason="BOTH_RECORDED_REVIEWS_REQUIRED", security_clearance=False)
    gate = assess(sec)
    return dict(verdict="SHIP" if gate["decision"] == "CLEAN_CANDIDATE" else "HOLD",
                availability_baseline="SHIP", reason=gate["decision"],
                integrity_reasons=gate["reasons"], security_clearance=False)


def audit():
    raw = PROTOCOL.read_bytes()
    require(git_blob(raw) == LOCK, "compatibility protocol changed")
    spec = parse(raw)
    old_raw = (ROOT / historical.PROTOCOL).read_bytes()
    require(git_blob(old_raw) == spec["original_protocol_blob"], "historical protocol changed")
    old = parse(old_raw)
    sources = historical.load(dict(sources=old["sources"] + [
        dict(spec["source_interface"], key="interface")]))
    require(b"export function shipVerdict(sr, cr, local)" in sources["interface"],
            "original interface changed")
    metrics, original = historical.replay(sources["ledger"], parse(sources["manifest"]),
                                          parse(sources["receipt_archive"]))
    require(metrics == old["expected"], "historical source comparison changed")
    latest = {}
    for line in sources["ledger"].splitlines():
        if line.strip():
            row = parse(line)
            if row["kind"] == "decision":
                latest[row["input"]["name"]] = row
    require(set(latest) == {x["case"] for x in original}, "case census changed")
    tables = {k: Counter() for k in ("original", "dual_availability", "falsum")}
    transitions = Counter()
    reasons = Counter()
    rows = []
    for case in original:
        row = latest[case["case"]]
        v = row["verdict"]
        result = postcondition(v, row["evidence"])
        decisions = (v, result["availability_baseline"], result["verdict"])
        label = case["label"]
        for name, decision in zip(tables, decisions):
            tables[name][label + ":" + decision] += 1
        require(v == "SHIP" or decisions == (v, v, v), "original restriction lost")
        require(decisions[2] != "SHIP" or decisions[1] == v == "SHIP", "new SHIP introduced")
        transitions[label + ":" + "->".join(decisions)] += 1
        reasons[result["reason"]] += 1
        rows.append(dict(case=case["case"], label=label, original=v,
                         **result))
    require(len(rows) == 129, "incomplete original population")
    return dict(scope=spec["scope"], protocol_blob=LOCK,
                source_interface=spec["source_interface"], cases=rows,
                tables={k: dict(v) for k, v in tables.items()},
                transitions=dict(transitions), reasons=dict(reasons),
                independent_adoption=False, live_inference=False,
                semantic_accuracy=False, security_clearance=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stdin", action="store_true")
    p.add_argument("--out", type=Path)
    a = p.parse_args()
    if a.stdin:
        if a.out:
            p.error("choose one mode")
        raw = sys.stdin.buffer.read(131073)
        require(len(raw) <= 131072, "input too large")
        data = parse(raw)
        require(type(data) is dict, "expected decision object")
        print(json.dumps(postcondition(data.get("verdict"), data.get("evidence")),
                         sort_keys=True, allow_nan=False))
        return
    if not a.out:
        p.error("provide --stdin or --out")
    report = audit()
    with a.out.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps({k: report[k] for k in ("tables", "transitions", "reasons")},
                     sort_keys=True))


if __name__ == "__main__":
    main()
