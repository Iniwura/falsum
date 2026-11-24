"""Compare downstream security answer policies on original outside records.

A PASS is only a policy prediction against the published dataset label, never
security clearance. The complete historical population includes missing answers.
"""
from collections import Counter
import argparse
import json
from pathlib import Path
import re
from urllib.request import urlopen

from .phase5aj_cross_app_evidence import (
    ROOT, INTENT, AuditError, require, git_blob, parse, HASH, diagnostic,
)

PROTOCOL = "data/phase5ak-external-label-baseline-protocol.json"
LOCK = "fcab9afdbdf9722e39750d887b23fe5d09121238"
MAX_BYTES = 1_000_000
POLICIES = ("count_only", "verdict_only", "strict_agreement", "falsum_consumer")


def display_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 200, "bad case name")
    return re.sub(r"0x([a-fA-F0-9]{4})[a-fA-F0-9]{32}([a-fA-F0-9]{4})",
                  r"0x\1…\2", name)


def label_index(manifest):
    out = {}
    for item in manifest["items"]:
        name = display_name(item["name"])
        require(name not in out, "ambiguous abbreviated case name")
        require(item["label"] in {"audited", "vulnerable"}
                and type(item["hint"]) is bool, "invalid case label or hint")
        out[name] = item
    return out


def predictions(result):
    """Portable bounded consumer policies; no target labels or case IDs used."""
    v = c = "UNKNOWN"
    if type(result) is dict:
        verdict = result.get("verdict")
        count = result.get("vulnerability_count")
        if verdict == "Secure":
            v = "PASS"
        elif verdict in ("Insecure", "Needs changes"):
            v = "FLAG"
        if type(count) is int and count >= 0:
            c = "PASS" if count == 0 else "FLAG"
    agree = v if v == c else "UNKNOWN"
    # A negative verdict cannot be converted to a clean prediction by zero.
    # A positive verdict with no trustworthy count, conflicting count, or
    # a known explicit missing-input contradiction is not a PASS.
    f = ("FLAG" if v == "FLAG" else
         "PASS" if v == c == "PASS" and diagnostic(result) == "UNVERIFIED"
         else "UNKNOWN")
    return dict(zip(POLICIES, (c, v, agree, f)))


def load(lock):
    result = {}
    for spec in lock["sources"]:
        url = ("https://raw.githubusercontent.com/" + spec["repo"] + "/" +
               spec["commit"] + "/" + spec["path"])
        with urlopen(url, timeout=30) as response:
            raw = response.read(MAX_BYTES + 1)
        require(0 < len(raw) <= MAX_BYTES, "source byte limit")
        require(git_blob(raw) == spec["blob"], "original source identity mismatch: " + spec["key"])
        result[spec["key"]] = raw
    return result


def replay(raw, manifest, archive):
    labels = label_index(manifest)
    receipts = {}
    for a in archive["receipts"]:
        h = a["receipt_hash"]
        require(type(h) is str and HASH.fullmatch(h) and h not in receipts,
                "invalid or duplicate archive receipt")
        require(a["status"] in {"SETTLED", "NOT_FOUND"}, "unhandled archived status")
        if a["status"] == "SETTLED":
            require(a["mismatch"] == [], "archived settlement mismatch")
        receipts[h] = a
    statuses = Counter(x["status"] for x in receipts.values())
    require(len(receipts) == archive["total"] and
            archive["settled"] == statuses["SETTLED"] and
            archive["other"] == statuses["NOT_FOUND"] and
            archive["pending"] == archive["mismatch"] == 0,
            "archive summary mismatch")
    latest = {}
    batch = []
    used = set()
    counters = Counter()
    for line in raw.splitlines():
        if not line.strip():
            continue
        r = parse(line)
        kind = r["kind"]
        if kind in ("purchase", "error"):
            counters[kind] += 1
            batch.append(r)
            continue
        require(kind == "decision", "unknown ledger event")
        counters["decision"] += 1
        name = r["input"]["name"]
        require(name in labels, "unmatched case label")
        require(r["verdict"] in ("SHIP", "FIX", "HOLD"), "unknown app decision")
        purchases = [p for p in batch if p["kind"] == "purchase"]
        errors = [p for p in batch if p["kind"] == "error" and p["intent"] == INTENT]
        ids = []
        for p in purchases:
            rr = p["receipt"]
            h = rr["receipt_hash"]
            require(h in receipts and h not in used, "unknown or reused receipt")
            a = receipts[h]
            require(a["intent"] == rr["intent"] == p["intent"] and
                    a["epoch_id"] == rr["epoch_id"] and
                    type(p["amount_uusdc"]) is int and p["amount_uusdc"] > 0 and
                    str(p["amount_uusdc"]) == rr["amount_uusdc"],
                    "receipt metadata mismatch")
            if a["status"] == "SETTLED":
                require(a["miner_id"] == rr["miner"] and
                        str(a["usdc"]) == rr["amount_uusdc"], "archived settlement mismatch")
            used.add(h)
            ids.append(h)
        require(len(r["receipts"]) == len(ids) and set(r["receipts"]) == set(ids),
                "decision purchase mismatch")
        sec = [x for x in r["evidence"] if x["intent"] == INTENT]
        paid = [p for p in purchases if p["intent"] == INTENT]
        require(len(sec) <= 1 and len(paid) <= 1, "ambiguous security answer")
        ok = len(sec) == 1 and sec[0]["ok"] is True
        fail = len(sec) == 1 and sec[0]["ok"] is False
        require(ok == (len(paid) == 1) and fail == bool(errors),
                "security availability mismatch")
        result = None
        if ok:
            require(sec[0]["miner_id"] == paid[0]["miner_id"], "registration mismatch")
            result = sec[0]["result"]
            require(type(result) is dict, "bad answer result")
        state = ("RECORDED_ANSWER" if ok else "RECORDED_FAILURE" if fail else "NO_ANSWER_RECORD")
        counters["reruns"] += int(name in latest)
        latest[name] = {"case": name, "label": labels[name]["label"],
                        "hint": labels[name]["hint"], "availability": state,
                        "predictions": predictions(result),
                        "security_clearance_granted": False}
        batch = []
    require(not batch and used == set(receipts) and set(latest) == set(labels),
            "incomplete ledger population")
    cases = list(latest.values())

    def table(items, getter):
        return dict(Counter(x["label"] + ":" + getter(x) for x in items))

    no_hint = [x for x in cases if not x["hint"]]
    return {
        "all_decisions": counters["decision"], "unique_cases": len(cases),
        "reruns": counters["reruns"], "purchases": counters["purchase"],
        "errors": counters["error"], "archived_settled": statuses["SETTLED"],
        "archived_not_found": statuses["NOT_FOUND"],
        "latest_availability": table(cases, lambda x: x["availability"]),
        "latest_metrics": {p: table(cases, lambda x: x["predictions"][p]) for p in POLICIES},
        "no_hint_cases": len(no_hint),
        "no_hint_count_only": table(no_hint, lambda x: x["predictions"]["count_only"]),
        "no_hint_falsum_consumer": table(no_hint, lambda x: x["predictions"]["falsum_consumer"]),
    }, cases


def audit(root=ROOT):
    raw = (root / PROTOCOL).read_bytes()
    require(git_blob(raw) == LOCK, "frozen protocol changed")
    lock = parse(raw)
    sources = load(lock)
    summary, cases = replay(sources["ledger"], parse(sources["manifest"]),
                            parse(sources["receipt_archive"]))
    require(summary == lock["expected"], "frozen historical comparison disagrees")
    return {"status": "PHASE5AK_EXTERNAL_LABEL_POLICY_COMPARISON",
            "source_git_objects_authenticated": len(sources),
            "protocol_git_blob_sha1": LOCK, "sources": lock["sources"],
            "summary": summary, "cases": cases, "limits": lock["limits"],
            "security_clearance_granted": False,
            "better_than_verdict_baseline": False,
            "live_settlement_verified": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    report = audit()
    with args.out.open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
