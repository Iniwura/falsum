"""Prepare a verification deliverable for a funded ACP v2 job, without settlement.

The outer verification job is distinct from the original security report job.
Only a local operator-controlled context and independently verified purchase
custody are trusted. ACP history is supplied by the authenticated caller; this
module does not authenticate history, verify settlement, or submit transactions.
"""
import argparse
import json
from pathlib import Path
import re

from . import phase5bb_acp_security_acceptance as gate
from . import phase5au_solana_anchor_evidence as anchor
from .phase5aj_cross_app_evidence import git_blob, parse, require, source_bytes

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "data/phase5bd-acp-provider-protocol.json"
LOCK = "2142c8458e714e1d1e9fa4593aaacd94a662f9d3"
OFFERING = "verifySecurityReport"
REQUEST_SCHEMA = "falsum.acp.verify.request.v1"
REQUEST_SCHEMA_V2 = "falsum.acp.verify.request.v2"
REPORT_SCHEMA_V2 = "falsum.acp.verify.report.v2"
BINDING_REF_SCHEMA = "falsum.telegraph.acp.binding-ref.v1"
RESULT_SCHEMA = "falsum.acp.verify.result.v1"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
ID = re.compile(r"[1-9][0-9]{0,77}")
DIGEST = re.compile(r"[0-9a-f]{64}")
LIFECYCLE = ["job.created", "budget.set", "job.funded"]
TERMINAL = {"job.submitted", "job.completed", "job.rejected", "job.expired"}
V2_REQUEST_FIELDS = {"schema", "offering", "report_job", "report", "telegraph_binding"}
V2_REPORT_FIELDS = gate.DELIVERY_FIELDS | {"source_response_sha256"}
BINDING_REF_FIELDS = {
    "schema", "request_sha256", "response_sha256", "receipt_hash", "tx_hash",
    "report_job_digest", "report_digest",
}


def protocol():
    raw = LOCK_PATH.read_bytes()
    require(git_blob(raw) == LOCK, "provider protocol changed")
    return parse(raw)


def verify_upstream():
    source = protocol()["upstream"]
    raw = source_bytes(source)
    require(all(t in raw for t in (b'.command("submit")',
        b'--deliverable <text>', b'await session.submit(opts.deliverable, transferToken)')),
        "upstream submit contract changed")
    return True


def valid_context(context):
    if not gate.exact_fields(context, {"chain_id", "job_id", "buyer", "offering", "requirement_digest"}):
        return False
    return (type(context["chain_id"]) is int and context["chain_id"] > 0
            and type(context["job_id"]) is str and ID.fullmatch(context["job_id"])
            and type(context["buyer"]) is str and ADDRESS.fullmatch(context["buyer"])
            and context["offering"] == OFFERING
            and type(context["requirement_digest"]) is str
            and DIGEST.fullmatch(context["requirement_digest"]))


def _v2_request_parts(request, binding_ref):
    """Validate the app-level v2 extension and return its gate-compatible report."""
    if not gate.exact_fields(request, V2_REQUEST_FIELDS) or request.get("schema") != REQUEST_SCHEMA_V2:
        return None
    if not gate.exact_fields(request.get("telegraph_binding"), BINDING_REF_FIELDS):
        return "TELEGRAPH_BINDING_REQUIRED"
    ref = request["telegraph_binding"]
    if ref.get("schema") != BINDING_REF_SCHEMA:
        return "TELEGRAPH_BINDING_REQUIRED"
    if binding_ref is None or binding_ref != ref:
        return "TELEGRAPH_BINDING_NOT_VERIFIED"
    report = request.get("report")
    if not gate.exact_fields(report, V2_REPORT_FIELDS) or report.get("schema") != REPORT_SCHEMA_V2:
        return "TELEGRAPH_REPORT_SCHEMA_UNSUPPORTED"
    if (not isinstance(report.get("source_response_sha256"), str)
            or not DIGEST.fullmatch(report["source_response_sha256"])
            or report["source_response_sha256"] != ref["response_sha256"]):
        return "EVALUATED_REPORT_SOURCE_RESPONSE_MISMATCH"
    base_report = dict(report)
    del base_report["source_response_sha256"]
    base_report["schema"] = gate.SCHEMA
    return base_report, ref, report


def prepare(context, history, trusted_custody, advisory_bytes, binding_ref=None):
    """Return an inline deliverable candidate, or refuse to prepare a job."""
    def stop(reason):
        return {"prepared": False, "reason": reason, "deliverable": None,
                "automatic_settlement_authorized": False, "live_acp_job_verified": False}
    if not valid_context(context):
        return stop("INVALID_LOCAL_VERIFICATION_JOB_CONTEXT")
    if (type(history) is not dict or history.get("protocol") != "v2"
            or history.get("status") != "funded"
            or not gate.same(history.get("chainId"), context["chain_id"])
            or not gate.same(history.get("jobId"), context["job_id"])):
        return stop("HISTORY_NOT_EXPECTED_FUNDED_V2_JOB")
    entries = history.get("entries")
    if (type(entries) is not list or type(history.get("entryCount")) is not int
            or len(entries) != history["entryCount"] or len(entries) > 1000):
        return stop("INVALID_HISTORY_ENTRIES")
    states, requests = [], []
    for index, entry in enumerate(entries):
        if type(entry) is not dict:
            return stop("INVALID_HISTORY_ENTRY")
        if entry.get("kind") == "system":
            event = entry.get("event")
            if type(event) is not dict or type(event.get("type")) is not str:
                return stop("INVALID_SYSTEM_EVENT")
            kind = event["type"]
            if kind in TERMINAL:
                return stop("ALREADY_SUBMITTED_OR_TERMINAL")
            if kind in LIFECYCLE:
                states.append((index, kind))
        elif entry.get("kind") == "message":
            if entry.get("contentType") == "requirement":
                requests.append((index, entry))
        else:
            return stop("UNKNOWN_HISTORY_ENTRY")
    if [kind for _, kind in states] != LIFECYCLE or len(requests) != 1:
        return stop("AMBIGUOUS_LIFECYCLE_OR_REQUIREMENT")
    index, entry = requests[0]
    sender, raw = entry.get("from"), entry.get("content")
    if (not states[0][0] < index < states[1][0]
            or type(sender) is not str or sender.lower() != context["buyer"].lower()
            or type(raw) is not str or len(raw) > 65536):
        return stop("UNBOUND_REQUIREMENT")
    try:
        request = parse(raw.encode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return stop("MALFORMED_REQUIREMENT")
    if gate.digest(request) != context["requirement_digest"]:
        return stop("REQUIREMENT_DIGEST_MISMATCH")
    if request.get("offering") != OFFERING:
        return stop("UNSUPPORTED_VERIFICATION_REQUEST")
    v2_parts = _v2_request_parts(request, binding_ref)
    if v2_parts is not None:
        if isinstance(v2_parts, str):
            return stop(v2_parts)
        report, verified_binding_ref, full_report = v2_parts
        request_version = 2
    elif gate.exact_fields(request, {"schema", "offering", "report_job", "report"}) and request["schema"] == REQUEST_SCHEMA:
        report, verified_binding_ref, full_report = request["report"], None, request["report"]
        request_version = 1
    else:
        return stop("UNSUPPORTED_VERIFICATION_REQUEST")
    report_job = request["report_job"]
    if (type(report_job) is dict and gate.same(report_job.get("chain_id"), context["chain_id"])
            and gate.same(report_job.get("job_id"), context["job_id"])):
        return stop("ORIGINAL_REPORT_AND_VERIFICATION_JOB_MUST_BE_DISTINCT")
    verdict = gate.evaluate(report_job, report, trusted_custody, advisory_bytes)
    if request_version == 2:
        verdict["source_response_sha256"] = full_report["source_response_sha256"]
        verdict["evaluated_report_digest"] = gate.digest(full_report)
    delivery = {"schema": RESULT_SCHEMA, "offering": OFFERING,
                "verification_job": {"chain_id": context["chain_id"], "job_id": context["job_id"]},
                "requirement_digest": gate.digest(request), "history_digest": gate.digest(history),
                "report_evaluation": verdict, "history_authenticated_by_falsum": False,
                "automatic_settlement_authorized": False, "live_acp_job_verified": False}
    if request_version == 2:
        delivery["telegraph_binding"] = verified_binding_ref
    return {"prepared": True, "reason": "REVIEWABLE_DELIVERABLE_ONLY", "deliverable": delivery,
            "automatic_settlement_authorized": False, "live_acp_job_verified": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--context", type=Path, required=True)
    p.add_argument("--history", type=Path, required=True)
    p.add_argument("--trusted-custody", type=Path)
    p.add_argument("--advisory", type=Path)
    a = p.parse_args()

    def read(path, limit=1048576):
        with path.open("rb") as f:
            raw = f.read(limit + 1)
        require(len(raw) <= limit, "input exceeds byte limit")
        return raw

    source = next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory")
    raw = read(a.advisory, 200000) if a.advisory else source_bytes(source)
    custody = parse(read(a.trusted_custody)) if a.trusted_custody else None
    result = prepare(parse(read(a.context)), parse(read(a.history)), custody, raw)
    print(json.dumps(result, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
