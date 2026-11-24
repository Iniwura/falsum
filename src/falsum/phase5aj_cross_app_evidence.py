"""Phase 5AJ: audit published downstream security-evidence availability.

Source-bound evaluation material, not a live network scorer, security clearance,
external adoption claim, or inference purchase.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = "data/phase5aj-cross-app-evidence-protocol.json"
PROTOCOL_BLOB = "e7d746f957b139993681fbc7167f640d118ea8f0"
INTENT = "SECURITY_REVIEW_GENERAL"
MAX_BYTES = 200_000
VERDICTS = {"SHIP", "FIX", "HOLD"}
HASH = re.compile(r"0x[0-9a-f]{64}")
MISSING_CODE = re.compile(
    r"\bno code,\s*configuration,\s*or system description was provided to evaluate\b"
    r"|\b(?:the input is merely a token contract address query with no executable code,"
    r"\s*configuration,\s*or data handling to assess)\b", re.I
)


class AuditError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def object_pairs(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON key")
        out[key] = value
    return out


def no_constant(value):
    raise AuditError("nonfinite JSON value: " + value)


def parse(raw):
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=object_pairs,
                      parse_constant=no_constant)


def protocol(root=ROOT):
    raw = (root / PROTOCOL).read_bytes()
    require(git_blob(raw) == PROTOCOL_BLOB, "preregistered source lock changed")
    return parse(raw)


def source_bytes(spec):
    url = ("https://raw.githubusercontent.com/" + spec["repo"] + "/" +
           spec["commit"] + "/" + spec["path"])
    with urlopen(url, timeout=30) as response:
        raw = response.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "oversized upstream source")
    require(git_blob(raw) == spec["blob"], "upstream Git byte identity mismatch")
    return raw


def diagnostic(fields):
    """Narrow explicit contradiction diagnostic, not a semantic accuracy score.

    An answer that does not match these two explicit phrases is unverified.
    Never infer sufficient evidence or contract safety from an absent match.
    """
    if type(fields) is not dict:
        return "UNVERIFIED"
    summary = fields.get("summary")
    if (fields.get("verdict") == "Secure"
            and type(fields.get("vulnerability_count")) is int
            and fields["vulnerability_count"] == 0
            and isinstance(summary, str) and len(summary) <= 12000
            and MISSING_CODE.search(summary)):
        return "EXPLICIT_NO_EVIDENCE_CONTRADICTION"
    return "UNVERIFIED"


def truvian(raw, spec):
    source = raw.decode("utf-8", "strict")
    results = []
    for name in spec["selected_original_response_variables"]:
        # Parse only the published literal fields inside these fixed declarations.
        # Do not evaluate the external TypeScript or copy a raw response to output.
        matches = re.findall(
            r"const " + re.escape(name) +
            r" = bought\('security', 'SECURITY_REVIEW_GENERAL', \{(.*?)\n\s*\},",
            source, flags=re.S,
        )
        require(len(matches) == 1, "selected original declaration missing/ambiguous")
        block = matches[0]
        verdict = re.findall(r"\bverdict:\s*'([^']+)'", block)
        count = re.findall(r"\bvulnerability_count:\s*(\d+)", block)
        summary = re.findall(r"\bsummary:\s*'([^'\n]+)'", block)
        require(len(verdict) == len(count) == len(summary) == 1,
                "selected original fields missing/ambiguous")
        fields = dict(verdict=verdict[0], vulnerability_count=int(count[0]),
                      summary=summary[0])
        results.append({
            "fixture_variable": name,
            "field_only_clear": fields["verdict"] == "Secure" and
                                fields["vulnerability_count"] == 0,
            "diagnostic": diagnostic(fields),
            "source_class": spec["source_class"],
            "security_clearance_granted": False,
        })
    require(sum(x["field_only_clear"] for x in results) ==
            spec["expected_field_only_clear_count"], "unexpected field-only baseline")
    require(sum(x["diagnostic"] == "EXPLICIT_NO_EVIDENCE_CONTRADICTION"
                for x in results) == spec["expected_explicit_no_evidence_contradiction_count"],
            "unexpected diagnostic result")
    return results


def audited_labels(manifest):
    items = manifest["items"]
    labels = {}
    for item in items:
        name = item["name"]
        require(name not in labels, "duplicate manifest case")
        labels[name] = item["label"]
    return {name for name, value in labels.items() if value == "audited"}


def ledger_audit(raw, archived, labels, mode, expected):
    """Join all published decisions to purchases and historical receipt checks.

    Archive settlement is not a live node recheck. The full-source Git identities
    identify precisely which outside records were measured.
    """
    rows = [parse(line) for line in raw.splitlines() if line.strip()]
    receipts = archived["receipts"]
    index = {}
    for receipt in receipts:
        ident = receipt["receipt_hash"]
        require(isinstance(ident, str) and HASH.fullmatch(ident) and ident not in index,
                "malformed/duplicate archived receipt")
        require(receipt["status"] == "SETTLED" and receipt["mismatch"] == [],
                "historical receipt not reported settled/matched")
        index[ident] = receipt
    require(archived["total"] == archived["settled"] == len(index)
            and archived["pending"] == archived["mismatch"] == archived["other"] == 0,
            "archive counts mismatch")
    counts = Counter({
        "decisions": 0, "security_answers": 0, "security_explicit_failures": 0,
        "security_absent_without_explicit_failure": 0, "all_purchases": 0,
        "all_errors": 0, "ship_without_security_answer": 0, "fix": 0,
        "hold": 0, "ship": 0,
    })
    if mode == "planted":
        counts["ship_with_known_planted_bug"] = 0
    seen = set()
    used = set()
    batch = []
    cases = []
    for row in rows:
        require(type(row) is dict, "invalid original row")
        kind = row.get("kind")
        if kind in {"purchase", "error"}:
            counts["all_purchases" if kind == "purchase" else "all_errors"] += 1
            batch.append(row)
            continue
        require(kind == "decision", "unknown ledger event")
        name = row["input"]["name"]
        require(name in labels and name not in seen, "missing/duplicate case label")
        seen.add(name)
        verdict = row["verdict"]
        require(verdict in VERDICTS, "invalid decision verdict")
        purchases = [p for p in batch if p["kind"] == "purchase"]
        ids = []
        for purchase in purchases:
            receipt = purchase["receipt"]
            ident = receipt["receipt_hash"]
            require(ident in index and ident not in used, "unknown/reused receipt")
            check = index[ident]
            require(check["intent"] == receipt["intent"] == purchase["intent"]
                    and check["epoch_id"] == receipt["epoch_id"]
                    and check["miner_id"] == receipt["miner"]
                    and type(purchase["amount_uusdc"]) is int
                    and purchase["amount_uusdc"] > 0
                    and str(check["usdc"]) == str(purchase["amount_uusdc"])
                    == receipt["amount_uusdc"],
                    "archived receipt identity, amount, epoch or Intent mismatch")
            # purchase.miner_id is registration; receipt.miner is settlement.
            # They must never be silently treated as the same namespace.
            used.add(ident)
            ids.append(ident)
        require(len(row["receipts"]) == len(ids) and set(row["receipts"]) == set(ids),
                "decision receipts do not match its purchase batch")
        sec = [x for x in row["evidence"] if x["intent"] == INTENT]
        paid = [p for p in purchases if p["intent"] == INTENT]
        errors = [p for p in batch if p["kind"] == "error" and p["intent"] == INTENT]
        require(len(sec) <= 1 and len(paid) <= 1, "ambiguous security answer")
        answer = len(sec) == 1 and sec[0]["ok"] is True
        explicit_failure = len(sec) == 1 and sec[0]["ok"] is False
        require(answer == (len(paid) == 1) and explicit_failure == bool(errors),
                "security evidence/purchase/error mismatch")
        if answer:
            require(type(sec[0].get("result")) is dict, "missing successful result")
            require(sec[0].get("miner_id") == paid[0].get("miner_id"),
                    "registration identity mismatch")
            counts["security_answers"] += 1
            availability = "RECORDED_ANSWER"
        elif explicit_failure:
            counts["security_explicit_failures"] += 1
            availability = "RECORDED_FAILURE"
        else:
            counts["security_absent_without_explicit_failure"] += 1
            availability = "NO_ANSWER_RECORD"
        counts["decisions"] += 1
        counts[verdict.lower()] += 1
        counts["ship_without_security_answer"] += int(verdict == "SHIP" and not answer)
        planted = mode == "planted" and labels[name]["bug"] is True
        if mode == "planted":
            counts["ship_with_known_planted_bug"] += int(verdict == "SHIP" and planted)
        cases.append({
            "case": name, "recorded_app_decision": verdict,
            "security_answer_availability": availability,
            "archived_receipt_count": len(ids),
            "external_label": ("PLANTED_BUG" if planted else
                               "AUTHOR_CLEAN_CONTROL" if mode == "planted" else
                               "AUDITED_CONTROL_NOT_PROVEN_BUG_FREE"),
            "security_clearance_granted": False,
        })
        batch = []
    require(not batch and used == set(index) and seen == set(labels),
            "unconsumed event, receipt or labelled case")
    require(dict(counts) == expected, "preregistered aggregate differs")
    return {"counts": dict(counts), "cases": cases,
            "archived_receipts_matched": len(used),
            "security_clearance_granted": False,
            "live_settlement_verified": False}


def audit(root=ROOT):
    lock = protocol(root)
    raw = {spec["key"]: source_bytes(spec) for spec in lock["sources"]}
    truth = {k: v for k, v in parse(raw["gig_planted_truth"]).items()
             if k != "_note"}
    require(all(type(x.get("bug")) is bool for x in truth.values()),
            "invalid planted truth labels")
    return {
        "status": "PHASE5AJ_ORIGINAL_CROSS_APP_EVIDENCE_AVAILABILITY_AUDIT",
        "intent": INTENT, "original_git_sources_authenticated": len(raw),
        "protocol_git_blob_sha1": PROTOCOL_BLOB,
        "sources": lock["sources"],
        "truvian": truvian(raw["truvian_tests"], lock["truvian"]),
        "gig_planted": ledger_audit(raw["gig_planted_ledger"],
                                    parse(raw["gig_planted_receipts"]), truth,
                                    "planted", lock["gig"]["planted"]),
        "gig_audited": ledger_audit(raw["gig_audited_ledger"],
                                    parse(raw["gig_audited_receipts"]),
                                    audited_labels(parse(raw["gig_audited_manifest"])),
                                    "audited", lock["gig"]["audited"]),
        "limits": lock["explicit_limits"],
        "security_clearance_granted": False,
        "new_network_ranking_proved": False,
        "source_class": "published third-party historical app records",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = audit()
    with args.out.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
        out.write("\n")
    print(json.dumps({
        "status": result["status"],
        "original_git_sources_authenticated": result["original_git_sources_authenticated"],
        "truvian_contradictions": sum(
            row["diagnostic"] == "EXPLICIT_NO_EVIDENCE_CONTRADICTION"
            for row in result["truvian"]),
        "gig_planted": result["gig_planted"]["counts"],
        "gig_audited": result["gig_audited"]["counts"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
