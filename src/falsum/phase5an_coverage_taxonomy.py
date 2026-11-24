"""Source-maintainer review follow-up: distinguish preflight holds from failures.

This is a retrospective classification of recorded application events, not a
claim about live requests, provider quality or the completeness of the logs.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from .phase5aj_cross_app_evidence import ROOT, INTENT, git_blob, parse, protocol, require
from .phase5ak_external_label_baselines import LOCK, PROTOCOL, load

HOLD_REASON = re.compile(
    r"too long to review: ([1-9][0-9]{0,8}) characters without comments, "
    r"over the 2000-character limit of the review Intents; split the deliverable or review it another way"
)
REVIEW = "https://github.com/Iniwura/falsum/issues/97#issuecomment-7126424685"


def preflight_length(decision, events):
    """Return recorded stripped-code length only for an explicit zero-cost hold.

    Absence of evidence alone never qualifies. The historical app's reason,
    all-zero cost/receipt fields and empty event batch must agree.
    """
    if (type(decision) is not dict or events
            or decision.get("verdict") != "HOLD"
            or decision.get("evidence") != []
            or decision.get("receipts") != []
            or decision.get("wasted_receipts") != []
            or type(decision.get("cost_usd")) not in (int, float)
            or decision["cost_usd"] != 0):
        return None
    reasons = decision.get("reasons")
    if type(reasons) is not list or len(reasons) != 1 or type(reasons[0]) is not str:
        return None
    match = HOLD_REASON.fullmatch(reasons[0])
    if match is None:
        return None
    length = int(match[1])
    return length if length > 2000 else None


def histories(raw):
    out = defaultdict(list)
    batch = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        event = parse(line)
        if event["kind"] in ("purchase", "error"):
            batch.append(event)
            continue
        require(event["kind"] == "decision", "unknown original event")
        name = event["input"]["name"]
        require(type(name) is str and name, "bad original case identity")
        out[name].append((event, batch))
        batch = []
    require(not batch, "orphan event batch")
    return out


def classify(decision, batch):
    evidence = [e for e in decision["evidence"] if e["intent"] == INTENT]
    purchases = [e for e in batch if e["kind"] == "purchase" and e["intent"] == INTENT]
    errors = [e for e in batch if e["kind"] == "error" and e["intent"] == INTENT]
    require(len(evidence) <= 1 and len(purchases) <= 1, "ambiguous security events")
    if evidence:
        ok = evidence[0]["ok"]
        require(type(ok) is bool, "invalid answer indicator")
        require(ok == bool(purchases) and (not ok) == bool(errors),
                "answer and event disagreement")
        return "RECORDED_ANSWER" if ok else "RECORDED_FAILURE"
    require(not purchases and not errors, "security event without decision evidence")
    return ("INPUT_LIMIT_PREFLIGHT_HOLD" if preflight_length(decision, batch) is not None
            else "UNEXPLAINED_NO_ANSWER_RECORD")


def examine(raw):
    history = histories(raw)
    latest = []
    for name, attempts in history.items():
        decision, batch = attempts[-1]
        state = classify(decision, batch)
        earlier = [classify(d, b) for d, b in attempts[:-1]]
        latest.append({"case": name, "state": state,
                       "recorded_input_length": preflight_length(decision, batch),
                       "earlier_recorded_failure": "RECORDED_FAILURE" in earlier,
                       "attempts": len(attempts)})
    counts = dict(Counter(x["state"] for x in latest))
    holds = [x for x in latest if x["state"] == "INPUT_LIMIT_PREFLIGHT_HOLD"]
    lengths = [x["recorded_input_length"] for x in holds]
    return {"latest_cases": len(latest),
            "decision_events": sum(len(a) for a in history.values()),
            "counts": counts,
            "preflight_input_length_range": [min(lengths), max(lengths)] if lengths else None,
            "preflight_cases_with_earlier_failure": sum(x["earlier_recorded_failure"] for x in holds),
            "cases": latest}


def audit(root=ROOT):
    aj = protocol(root)
    ak_raw = (root / PROTOCOL).read_bytes()
    require(git_blob(ak_raw) == LOCK, "scale protocol changed")
    ak = parse(ak_raw)
    specs = [s for s in aj["sources"] if s["key"] in ("gig_planted_ledger", "gig_audited_ledger")]
    specs += [s for s in ak["sources"] if s["key"] == "ledger"]
    require(len(specs) == 3, "wrong source roster")
    raw = load({"sources": specs})
    planted = examine(raw["gig_planted_ledger"])
    audited = examine(raw["gig_audited_ledger"])
    scale = examine(raw["ledger"])
    require(planted["counts"] == {"RECORDED_ANSWER": 2, "RECORDED_FAILURE": 10},
            "planted taxonomy differs")
    require(audited["counts"] == {"RECORDED_ANSWER": 15, "INPUT_LIMIT_PREFLIGHT_HOLD": 7}
            and audited["preflight_input_length_range"] == [2060, 4432], "audited taxonomy differs")
    require(scale["counts"] == {"RECORDED_ANSWER": 103, "RECORDED_FAILURE": 4,
                                "INPUT_LIMIT_PREFLIGHT_HOLD": 22}
            and scale["latest_cases"] == 129 and scale["decision_events"] == 158
            and scale["preflight_input_length_range"] == [2018, 6605]
            and scale["preflight_cases_with_earlier_failure"] == 22, "scale taxonomy differs")
    # Preserve the earlier failures rather than erase them in latest-case coverage.
    scale_held = {x["case"]: x for x in scale["cases"] if x["state"] == "INPUT_LIMIT_PREFLIGHT_HOLD"}
    require(all(x["case"] in scale_held and scale_held[x["case"]]["recorded_input_length"]
                == x["recorded_input_length"] for x in audited["cases"]
                if x["state"] == "INPUT_LIMIT_PREFLIGHT_HOLD"), "audited preflight cases do not reconcile")
    error_kinds = Counter()
    for line in raw["gig_planted_ledger"].splitlines():
        if not line.strip():
            continue
        r = parse(line)
        if r["kind"] == "error" and r["intent"] == INTENT:
            if r.get("status") == 500 and r.get("body") == {
                "error": "upstream call failed: context deadline exceeded"}:
                error_kinds["HTTP_500_CONTEXT_DEADLINE"] += 1
            elif r.get("error") == "fetch failed":
                error_kinds["FETCH_FAILED"] += 1
            else:
                error_kinds["OTHER"] += 1
    require(dict(error_kinds) == {"HTTP_500_CONTEXT_DEADLINE": 9, "FETCH_FAILED": 1},
            "planted failure reasons differ")
    return {"status": "PHASE5AN_MAINTAINER_REVIEW_COVERAGE_TAXONOMY",
            "original_sources": specs, "source_maintainer_review": REVIEW,
            "planted": planted, "audited": audited, "scale": scale,
            "planted_recorded_error_kinds": dict(error_kinds),
            "security_clearance_granted": False,
            "network_ranking_improvement_proved": False,
            "independent_fork_execution_proved": False,
            "external_integration_proved": False,
            "live_transport_verified": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    r = audit()
    with args.out.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(r, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({**{k: {a: b for a, b in r[k].items() if a != "cases"}
                         for k in ("planted", "audited", "scale")},
                      "planted_recorded_error_kinds": r["planted_recorded_error_kinds"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
