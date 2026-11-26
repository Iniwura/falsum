"""Read-only ACP v2 history adapter. No signing or settlement actions.

The caller must obtain history through its authenticated ACP client, retain the
original buyer requirement, and independently verify Telegraph purchase custody.
Local input files are never proof of a live job or a settled purchase.
"""
import argparse
import json
from pathlib import Path
import re

from . import phase5bb_acp_security_acceptance as gate
from . import phase5au_solana_anchor_evidence as anchor
from .phase5aj_cross_app_evidence import git_blob, parse, require, source_bytes

PROTOCOL = Path(__file__).resolve().parents[2] / "data/phase5bc-acp-buyer-history-protocol.json"
LOCK = "b2bf57fe8903688204cbf7fc262a2164646c31de"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
HASH = re.compile(r"0x[0-9a-fA-F]{64}")
LIFECYCLE = ["job.created", "budget.set", "job.funded", "job.submitted"]
TERMINAL = {"job.completed", "job.rejected", "job.expired"}


def protocol():
    raw = PROTOCOL.read_bytes()
    require(git_blob(raw) == LOCK, "history protocol changed")
    return parse(raw)


def verify_upstream():
    lock = protocol()["upstream"]
    sources = {s["key"]: source_bytes(dict(s, repo=lock["repo"], commit=lock["commit"]))
               for s in lock["sources"]}
    require(all(t in sources["history"] for t in (b'getHistory(Number(opts.chainId), opts.jobId)',
            b'protocol: "v2"', b'entryCount: entries.length', b'"job.submitted": "submitted"')),
            "history output schema changed")
    require(all(t in sources["skill"] for t in (b'entry.event.deliverable', b'deliverableHash',
            b'contentType:"requirement"')), "upstream guidance changed")
    return len(sources)


def evaluate(expected, history, custody, advisory_bytes):
    def hold(reason):
        return dict(recommendation="HOLD", reasons=[reason], automatic_settlement_authorized=False,
                    live_acp_job_verified=False, security_clearance=False,
                    history_digest=gate.digest(history))
    if not gate.exact_fields(expected, {"buyer", "job"}):
        return hold("INVALID_BUYER_CONTEXT")
    buyer, job = expected["buyer"], expected["job"]
    if type(buyer) is not str or not ADDRESS.fullmatch(buyer) or not gate.exact_fields(job, gate.JOB_FIELDS):
        return hold("INVALID_BUYER_CONTEXT")
    if (type(history) is not dict or history.get("protocol") != "v2" or
            history.get("status") != "submitted" or
            not gate.same(history.get("chainId"), job["chain_id"]) or
            not gate.same(history.get("jobId"), job["job_id"])):
        return hold("HISTORY_NOT_EXPECTED_SUBMITTED_V2_JOB")
    entries = history.get("entries")
    if (type(entries) is not list or type(history.get("entryCount")) is not int or
            len(entries) != history["entryCount"] or len(entries) > 1000):
        return hold("MISSING_OR_INVALID_HISTORY_ENTRIES")
    lifecycle, requirements, deliveries = [], [], []
    for index, entry in enumerate(entries):
        if type(entry) is not dict:
            return hold("INVALID_HISTORY_ENTRY")
        if entry.get("kind") == "system":
            event = entry.get("event")
            if type(event) is not dict or type(event.get("type")) is not str:
                return hold("INVALID_SYSTEM_EVENT")
            kind = event["type"]
            if kind in TERMINAL:
                return hold("TERMINAL_JOB")
            if kind in LIFECYCLE:
                lifecycle.append((index, kind))
            if kind == "job.submitted":
                deliveries.append(event)
        elif entry.get("kind") == "message":
            if entry.get("contentType") == "requirement":
                requirements.append((index, entry))
        else:
            return hold("UNKNOWN_HISTORY_ENTRY")
    if [kind for _, kind in lifecycle] != LIFECYCLE or len(deliveries) != 1:
        return hold("INCOMPLETE_OR_AMBIGUOUS_LIFECYCLE")
    if len(requirements) != 1:
        return hold("AMBIGUOUS_OR_MISSING_REQUIREMENT")
    index, req = requirements[0]
    sender, raw_req = req.get("from"), req.get("content")
    if (not lifecycle[0][0] < index < lifecycle[1][0] or type(sender) is not str or
            sender.lower() != buyer.lower() or type(raw_req) is not str or len(raw_req) > 65536):
        return hold("UNBOUND_BUYER_REQUIREMENT")
    try:
        requirement = parse(raw_req.encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return hold("MALFORMED_REQUIREMENT")
    if not gate.same(requirement, {k:job[k] for k in ("schema", "intent", "target")}):
        return hold("REQUIREMENT_MISMATCH")
    event = deliveries[0]
    raw_delivery, claimed_hash = event.get("deliverable"), event.get("deliverableHash")
    if (type(raw_delivery) is not str or not raw_delivery or len(raw_delivery) > 65536 or
            type(claimed_hash) is not str or not HASH.fullmatch(claimed_hash)):
        return hold("MISSING_INLINE_DELIVERABLE_OR_EVENT_HASH")
    try:
        delivery = parse(raw_delivery.encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return hold("MALFORMED_INLINE_DELIVERABLE")
    out = gate.evaluate(job, delivery, custody, advisory_bytes)
    out.update(history_digest=gate.digest(history), event_deliverable_hash=claimed_hash,
               event_hash_verified=False, history_authenticated_by_falsum=False)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected", type=Path, required=True)
    p.add_argument("--history", type=Path, required=True)
    p.add_argument("--trusted-custody", type=Path, required=True)
    p.add_argument("--advisory", type=Path)
    a = p.parse_args()
    def read(path):
        with path.open("rb") as f:
            raw = f.read(1048577)
        require(len(raw) <= 1048576, "input exceeds byte limit")
        return parse(raw)
    source = next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory")
    if a.advisory:
        with a.advisory.open("rb") as f:
            raw = f.read(200001)
        require(len(raw) <= 200000, "advisory exceeds byte limit")
    else:
        raw = source_bytes(source)
    print(json.dumps(evaluate(read(a.expected), read(a.history), read(a.trusted_custody), raw),
                     sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
