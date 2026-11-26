"""Read-only acceptance recommendation for a narrowly scoped ACP deliverable.

Caller must supply an independently obtained job contract and verified purchase
custody. The seller cannot authenticate their own receipt by supplying JSON.
No SDK, wallet, purchase or settlement action is performed by this module.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from .phase5aj_cross_app_evidence import git_blob, parse, require, source_bytes
from . import phase5au_solana_anchor_evidence as anchor
from .phase5ar_response_integrity import NO_CODE, MISSING_CODE

CONTRACT = Path(__file__).resolve().parents[2] / "data/phase5bb-acp-security-contract.json"
LOCK = "a7d3f9620d3fba991f41cc4399ff4aaf8152afc3"
SCHEMA = "falsum.acp.security.v1"
RECEIPT = re.compile(r"0x[0-9a-f]{64}")
JOB_FIELDS = {"schema", "chain_id", "job_id", "target", "intent"}
TARGET_FIELDS = {"ecosystem", "package", "version", "reference"}
DELIVERY_FIELDS = {"schema", "chain_id", "job_id", "target", "claim", "response", "receipt_hash"}
CUSTODY_FIELDS = {"status", "job_digest", "response_digest", "receipt_hash", "intent"}


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def exact_fields(obj, fields):
    return type(obj) is dict and set(obj) == fields


def same(a, b):
    return digest(a) == digest(b)


def result(decision, reasons, job, delivery, *, source_verified=False, custody_bound=False):
    return dict(schema=SCHEMA, recommendation=decision, reasons=reasons,
                job_digest=digest(job), deliverable_digest=digest(delivery),
                advisory_source_verified=source_verified,
                caller_custody_bound=custody_bound,
                scope="pinned advisory applicability only",
                settlement_verified_by_falsum=False, live_acp_job_verified=False,
                security_clearance=False, automatic_settlement_authorized=False)


def source_bound(raw):
    source = next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory")
    require(git_blob(raw) == source["blob"], "advisory source identity mismatch")
    return anchor.interval(parse(raw))


def evaluate(job, delivery, custody, advisory_bytes):
    def hold(reason, **kw):
        return result("HOLD", [reason], job, delivery, **kw)

    if not exact_fields(job, JOB_FIELDS) or job["schema"] != SCHEMA:
        return hold("INVALID_TRUSTED_JOB")
    if (type(job["chain_id"]) is not int or job["chain_id"] <= 0 or
            type(job["job_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,77}", job["job_id"]) or
            job["intent"] != "SECURITY_REVIEW_GENERAL" or
            not exact_fields(job["target"], TARGET_FIELDS)):
        return hold("UNSUPPORTED_JOB")
    if not exact_fields(delivery, DELIVERY_FIELDS) or delivery["schema"] != SCHEMA:
        return hold("INCOMPLETE_OR_UNSUPPORTED_DELIVERABLE")
    if any(not same(delivery[k], job[k]) for k in ("chain_id", "job_id", "target")):
        return hold("DELIVERABLE_JOB_BINDING_MISMATCH")
    if type(delivery["receipt_hash"]) is not str or not RECEIPT.fullmatch(delivery["receipt_hash"]):
        return hold("MISSING_RECEIPT_ID")
    if (not exact_fields(custody, CUSTODY_FIELDS) or custody["status"] != "CALLER_VERIFIED" or
            custody["job_digest"] != digest(job) or
            custody["response_digest"] != digest(delivery["response"]) or
            custody["receipt_hash"] != delivery["receipt_hash"] or
            custody["intent"] != job["intent"]):
        return hold("UNVERIFIED_OR_UNBOUND_PURCHASE_CUSTODY")
    try:
        bounds = source_bound(advisory_bytes)
    except (ValueError, KeyError, TypeError):
        return hold("ADVISORY_SOURCE_NOT_AUTHENTICATED", custody_bound=True)
    flags = dict(source_verified=True, custody_bound=True)
    expected = anchor.classify(job["target"], bounds)
    if expected not in ("APPLICABLE", "INAPPLICABLE"):
        return hold("OUTSIDE_PINNED_ADVISORY_SCOPE", **flags)
    response = delivery["response"]
    if (not exact_fields(response, {"verdict", "vulnerability_count", "issues", "summary", "claim"}) or
            delivery["claim"] not in ("APPLICABLE", "INAPPLICABLE") or
            response["claim"] != delivery["claim"]):
        return hold("MISSING_OR_UNBOUND_APPLICABILITY_CLAIM", **flags)
    if (type(response["issues"]) is not list or
            any(type(i) is not str or not i.strip() for i in response["issues"])):
        return hold("MISSING_OR_MALFORMED_ISSUES", **flags)
    if (type(response["vulnerability_count"]) is not int or response["vulnerability_count"] < 0 or
            type(response["summary"]) is not str or not response["summary"].strip() or
            len(response["summary"]) > 12000):
        return hold("INVALID_RESPONSE_FIELDS", **flags)
    if MISSING_CODE.search(response["summary"]) or NO_CODE.search(response["summary"]):
        return hold("RESPONSE_EXPLICITLY_LACKS_REVIEW_EVIDENCE", **flags)
    # A rejection means the narrowly requested applicability claim is wrong.
    # Negative security verdicts are not themselves rejected: a valid report
    # can identify an affected dependency.
    if delivery["claim"] != expected:
        return result("REJECT", ["PINNED_ADVISORY_CONTRADICTS_CLAIM"], job, delivery, **flags)
    if response["verdict"] not in ("Secure", "Insecure", "Needs changes"):
        return hold("UNKNOWN_SECURITY_VERDICT", **flags)
    if (expected == "APPLICABLE" and (response["verdict"] == "Secure" or response["vulnerability_count"] == 0 or not response["issues"])):
        return hold("CONTRADICTORY_AFFECTED_REPORT", **flags)
    if (expected == "INAPPLICABLE" and (response["verdict"] != "Secure" or response["vulnerability_count"] != 0 or response["issues"])):
        return hold("ADDITIONAL_FINDINGS_OUTSIDE_JOB_SCOPE", **flags)
    # Do not accept broader security assertions under an advisory-only contract.
    # The summary/issue contents are unverified narrative, not approved findings.
    return result("ACCEPT", ["SCOPED_APPLICABILITY_CLAIM_CORROBORATED"], job, delivery, **flags)


def contract():
    raw = CONTRACT.read_bytes()
    require(git_blob(raw) == LOCK, "frozen acceptance contract changed")
    return parse(raw)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--job", type=Path, required=True)
    p.add_argument("--deliverable", type=Path, required=True)
    p.add_argument("--trusted-custody", type=Path, required=True)
    p.add_argument("--advisory", type=Path, help="local immutable advisory blob, otherwise fetch pinned public source")
    a = p.parse_args()
    def read(path):
        raw = path.read_bytes()
        require(len(raw) <= 65536, "input exceeds byte limit")
        return parse(raw)
    contract()
    spec = next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory")
    raw = a.advisory.read_bytes() if a.advisory else source_bytes(spec)
    require(len(raw) <= 200000, "advisory exceeds byte limit")
    print(json.dumps(evaluate(read(a.job), read(a.deliverable), read(a.trusted_custody), raw),
                     sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
