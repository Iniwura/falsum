"""Optional caller-context gate for response integrity (not security clearance).

The context must be derived from the application's own request/scan pipeline,
never from the provider's answer. Availability is not evidence of review.
"""
import argparse
import json
from pathlib import Path
import sys

from .phase5ar_response_integrity import assess as legacy
from .phase5aj_cross_app_evidence import parse

STATES = ("AVAILABLE", "UNAVAILABLE", "UNKNOWN")
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "data/phase5at-constructed-request-context.json"


def assess(response, evidence_state=None):
    """Only narrow eligibility; preserve flags and existing review reasons."""
    result = legacy(response)
    if result["decision"] != "CLEAN_CANDIDATE":
        return result
    if type(evidence_state) is str and evidence_state == "AVAILABLE":
        return result
    reason = ("CALLER_EVIDENCE_UNAVAILABLE"
              if type(evidence_state) is str and evidence_state == "UNAVAILABLE"
              else "CALLER_EVIDENCE_UNKNOWN")
    return {"decision": "REVIEW", "reasons": [reason], "security_clearance": False}


def evaluate(path=FIXTURE):
    cases = parse(path.read_bytes())["rows"]
    rows = []
    for case in cases:
        old = legacy(case["response"])
        new = assess(case["response"], case["context"])
        expected = case["expected"]
        rows.append({"id": case["id"], "context": case["context"], "expected": expected,
                     "legacy": old["decision"], "context_gate": new["decision"],
                     "security_clearance": new["security_clearance"]})
    no_evidence = [r for r in rows if r["context"] in ("UNAVAILABLE", "UNKNOWN")
                   and r["expected"] == "REVIEW"]
    clean_controls = [r for r in rows if r["expected"] == "CLEAN_CANDIDATE"]
    return {"scope": "constructed author-designed policy controls; not blind or independent",
            "cases": len(rows),
            "legacy_matches": sum(r["legacy"] == r["expected"] for r in rows),
            "context_gate_matches": sum(r["context_gate"] == r["expected"] for r in rows),
            "unavailable_or_unknown_controls": len(no_evidence),
            "legacy_unsupported_clean": sum(r["legacy"] == "CLEAN_CANDIDATE" for r in no_evidence),
            "context_gate_unsupported_clean": sum(r["context_gate"] == "CLEAN_CANDIDATE" for r in no_evidence),
            "clean_controls": len(clean_controls),
            "legacy_clean_controls_preserved": sum(r["legacy"] == "CLEAN_CANDIDATE" for r in clean_controls),
            "context_gate_clean_controls_preserved": sum(r["context_gate"] == "CLEAN_CANDIDATE" for r in clean_controls),
            "independent_gold": False, "network_ranking_improvement": False,
            "external_integration_proved": False, "security_clearance": False,
            "rows": rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--stdin", action="store_true")
    g.add_argument("--out", type=Path)
    p.add_argument("--evidence-state", choices=STATES,
                   help="trusted caller context, separate from response JSON")
    a = p.parse_args()
    if a.stdin:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            p.error("response exceeds byte limit")
        print(json.dumps(assess(parse(raw), a.evidence_state), sort_keys=True, allow_nan=False))
    else:
        if a.evidence_state is not None:
            p.error("--evidence-state is only for --stdin")
        result = evaluate()
        with a.out.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n")
        print(json.dumps({k:v for k,v in result.items() if k != "rows"}, sort_keys=True))


if __name__ == "__main__":
    main()
