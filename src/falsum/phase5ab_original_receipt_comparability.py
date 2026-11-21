"""Phase 5AB: original public receipt Intent vs request comparability census.

Every observed source is an independently published third-party Git blob whose
exact original bytes are authenticated before counting. Folder names and reported
paid status are NOT network score, expert-gold, payment settlement, or evidence of
a fair same-canonical-Intent comparison.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import (
    SOURCE_BASE, VIEW_BASE, fetch_bytes, git_blob_sha
)
from .phase5m_real_source_sensitive_model import ROOT

LOCK = "data/phase5ab-original-receipt-comparability-lock.json"
LOCK_BLOB = "40f6b52845268bef8f1517111efff1e880594169"
STATUS = "PHASE5AB_TWELVE_ORIGINAL_PUBLIC_CAPTURE_INTENT_AND_COMPARABILITY_CENSUS"
CANONICAL = "SECURITY_REVIEW_GENERAL"
SHA1 = re.compile(r"^[a-f0-9]{40}$")
HASH = re.compile(r"^0x[0-9a-fA-F]{64}$")
KIND_ROUTED = "CANONICAL_ROUTED_REQUEST_AND_RECEIPT"
KIND_DIRECT = "DIRECT_PROVIDER_CANONICAL_RECEIPT_BUT_NO_CANONICAL_REQUEST"
KIND_DIFFERENT = "SUCCESSFUL_RESPONSE_RECEIPT_IS_NOT_CANONICAL_INTENT"
KIND_FAILED = "FAILED_NO_SUCCESSFUL_RECEIPT"
ENGINE_ROUTED_URL = "https://devnode.telegraphprotocol.com/engine/v1/ask"
ENGINE_DIRECT_RE = re.compile(r"^https://devnode\.telegraphprotocol\.com/engine/v1/ask/([1-9][0-9]*)$")
LIMIT_FIELDS = (
    "folder_name_is_not_intent_proof",
    "reported_payment_not_chain_verified",
    "miner_ownership_not_verified",
    "no_new_paid_calls",
    "no_registered_evaluator",
    "no_new_independent_adoption",
    "no_expert_gold",
    "request_receipt_context_distinct_from_provider_output_semantic_accuracy",
    "no_fair_miner_ranking_without_same_canonical_request",
    "contains_original_external_responses_only_in_memory",
    "not_h2_submitted",
)


class ComparabilityError(ValueError):
    """Do not score an inauthentic or mischaracterized published response."""


def need(ok: bool, why: str) -> None:
    if not ok:
        raise ComparabilityError(why)


def frozen(root: Path = ROOT) -> dict:
    raw = (root / LOCK).read_bytes()
    need(git_blob_sha(raw) == LOCK_BLOB, "preimplementation source roster or comparison rules changed")
    obj = json.loads(raw)
    need(isinstance(obj, dict)
         and obj.get("schema_version") == 1
         and obj.get("status") == "PHASE5AB_PREIMPLEMENTATION_PUBLIC_RECEIPT_INTENT_COMPARABILITY_AUDIT_FROZEN"
         and obj.get("source_repo") == "anvithagowda098/pr-guard"
         and obj.get("source_commit") == "99d2e3c93890a8fc083947bde4f21217516b7a5f"
         and obj.get("source_prefix") == "test/fixtures/miner-responses/"
         and obj.get("claimed_directory_intent") == CANONICAL
         and obj.get("expected_original_observation_count") == 12
         and obj.get("expected_paid_http200_count") == 10
         and obj.get("expected_reported_canonical_receipts_count") == 4
         and obj.get("expected_explicit_routed_canonical_request_and_receipt_count") == 2
         and obj.get("expected_direct_canonical_receipt_with_untyped_direct_request_count") == 2
         and obj.get("expected_successful_noncanonical_receipt_count") == 6
         and obj.get("expected_failed_or_missing_receipt_count") == 2
         and obj.get("expected_genuine_byte_identical_same_canonical_request_multi_miner_pairs") == 0
         and isinstance(obj.get("scope_limits"), dict)
         and all(obj["scope_limits"].get(k) is True for k in LIMIT_FIELDS),
         "frozen receipt-population and no-ranking limits absent")
    sources = obj.get("capture_sources")
    need(isinstance(sources, list) and len(sources) == 12,
         "12 historical outside sources required")
    paths, blobs = set(), set()
    for item in sources:
        need(isinstance(item, dict) and set(item) == {"path", "git_blob_sha1"},
             "source cannot alter its frozen role")
        path, blob = item["path"], item["git_blob_sha1"]
        need(type(path) is str and
             (path.startswith("SECURITY_REVIEW_GENERAL/") or path.startswith("ROUTED/security-review-"))
             and path.endswith(".json") and ".." not in path and "/./" not in path
             and type(blob) is str and SHA1.fullmatch(blob) is not None,
             "untrusted path or Git blob identity")
        need(path not in paths and blob not in blobs, "duplicate original source observation")
        paths.add(path)
        blobs.add(blob)
    need(sum(p.startswith("SECURITY_REVIEW_GENERAL/") for p in paths) == 10
         and sum(p.startswith("ROUTED/") for p in paths) == 2,
         "source-directory population modified")
    return obj


def request_identity(request: object) -> tuple[bool, str | None, str | None]:
    """Return (canonical request schema, explicit submitted Intent, canonical digest).

    A direct provider method, even with a canonical receipt, is NEVER a
    canonical routed Intent request; same package text is not equal request.
    """
    if not isinstance(request, dict):
        return False, None, None
    if (set(request) == {"intent", "params"}
            and request.get("intent") == CANONICAL
            and isinstance(request.get("params"), dict)
            and set(request["params"]) == {"target"}
            and isinstance(request["params"]["target"], str)
            and bool(request["params"]["target"].strip())):
        raw = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return True, CANONICAL, hashlib.sha256(raw).hexdigest()
    explicit = request.get("intent")
    if explicit is None and isinstance(request.get("payload"), dict):
        explicit = request["payload"].get("intent")
    return False, explicit if type(explicit) is str else None, None


def request_transport(url: object) -> tuple[str, str | None]:
    """Prove which API endpoint the original capture records.

    Telegraph accepts canonical intent+params on BOTH /ask and /ask/{minerId}.
    Payload shape alone is therefore insufficient to assert network routing.
    This Phase 5AB historical verifier recognizes ONLY the frozen capture
    origin and exact engine paths; it is not a general network HTTP client.
    """
    need(type(url) is str, "original request transport URL absent")
    if url == ENGINE_ROUTED_URL:
        return "GENERAL_NETWORK_ROUTE", None
    match = ENGINE_DIRECT_RE.fullmatch(url)
    need(match is not None, "unrecognized request URL/host/route; cannot infer routing")
    return "DIRECT_MINER_ENDPOINT", match.group(1)


def inspect(document: object, *, path: str, original_blob_sha1: str) -> dict:
    """Classify a caller-supplied document. Only study() proves its Git origin."""
    need(type(document) is dict and type(path) is str and SHA1.fullmatch(original_blob_sha1),
         "malformed published capture input")
    request = document.get("request")
    need(isinstance(request, dict), "missing original request object")
    req_canonical, request_intent, digest = request_identity(request)
    transport, direct_endpoint_miner = request_transport(document.get("url"))
    truly_routed = req_canonical and transport == "GENERAL_NETWORK_ROUTE"
    need(document.get("paid") is True and document.get("charged") is True
         and isinstance(document.get("payment"), dict)
         and document["payment"].get("success") is True,
         "missing original reported paid flags; payment settlement NOT independently verified")
    status = document.get("status")
    need(type(status) is int and status in (200, 500),
         "unsupported original HTTP status")
    receipt = document.get("receipt")
    body = document.get("body")
    classified = KIND_FAILED
    recorded_intent = None
    reported_miner = None
    receipt_registration_miner = None
    if status == 200:
        need(isinstance(receipt, dict) and isinstance(body, dict)
             and type(receipt.get("receipt_hash")) is str
             and HASH.fullmatch(receipt["receipt_hash"]) is not None
             and type(body.get("signal_hash")) is str
             and HASH.fullmatch(body["signal_hash"]) is not None,
             "successful paid-flagged observation missing original receipt or signal")
        need(isinstance(body.get("miner_id"), (int, str))
             and str(body["miner_id"]).isdigit(),
             "missing reported original Miner identifier")
        reported_miner = str(body["miner_id"])
        if direct_endpoint_miner is not None:
            need(reported_miner == direct_endpoint_miner,
                 "response-body miner ID disagrees with original direct request URL")
        # The official Telegraph docs describe receipt.miner as the onchain
        # registration ID, NOT response.body.miner_id / direct /ask/{id}.
        # Never require their equality or invent a verified mapping.
        registration = receipt.get("miner")
        need(type(registration) in (int, str) and str(registration).isdigit(),
             "missing reported onchain Miner registration identifier")
        receipt_registration_miner = str(registration)
        recorded_intent = receipt.get("intent")
        need(type(recorded_intent) is str and len(recorded_intent) < 100,
             "no typed original receipt Intent")
        if truly_routed and recorded_intent == CANONICAL:
            classified = KIND_ROUTED
        elif recorded_intent == CANONICAL:
            classified = KIND_DIRECT
        else:
            classified = KIND_DIFFERENT
    else:
        need(receipt is None, "failed original request unexpectedly supplies a paid success receipt")
    # Never expose raw third-party response bodies, text, payment or wallet fields.
    return {
        "original_source_path": "test/fixtures/miner-responses/" + path,
        "original_git_blob_sha1": original_blob_sha1,
        "original_public_source_url": VIEW_BASE + "test/fixtures/miner-responses/" + path,
        "observed_http_status": status,
        "reported_paid_flag": True,
        "reported_charge_flag": True,
        "receipt_intent": recorded_intent,
        "original_recorded_route_class": transport,
        "original_capture_url_records_general_route": transport == "GENERAL_NETWORK_ROUTE",
        "original_direct_endpoint_miner_id": direct_endpoint_miner,
        "reported_receipt_miner_onchain_registration_id_not_body_miner_id":
            receipt_registration_miner,
        "receipt_and_body_miner_id_namespace_mapping_independently_verified": False,
        "request_explicit_intent": request_intent,
        "reported_miner_id_not_verified_owner": reported_miner,
        "request_has_canonical_routed_schema": req_canonical,
        "canonical_schema_with_recorded_general_route": truly_routed,
        "canonical_request_sha256": digest if classified == KIND_ROUTED else None,
        "capture_intent_provenance_class": classified,
        "request_and_receipt_not_proof_of_advisory_correctness": True,
        "original_source_verified_by_git_blob": False,  # only study() may promote
        "actual_paid_settlement_independently_verified": False,
    }


def same_request_candidates(observations: list[dict]) -> list[dict]:
    """Candidates only; never infer ownership, rankings or payment settlement."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in observations:
        if row["capture_intent_provenance_class"] == KIND_ROUTED:
            digest = row["canonical_request_sha256"]
            need(type(digest) is str and len(digest) == 64,
                 "canonical request must retain a stable SHA256")
            grouped[digest].append(row)
    candidates = []
    for digest, rows in grouped.items():
        if len({r["reported_miner_id_not_verified_owner"] for r in rows}) >= 2:
            candidates.append({
                "canonical_request_sha256": digest,
                "reported_distinct_miner_ids": sorted({
                    r["reported_miner_id_not_verified_owner"] for r in rows
                }),
                "provider_owner_independence_verified": False,
                "fair_independent_network_ranking_proved": False,
            })
    return sorted(candidates, key=lambda r: r["canonical_request_sha256"])


def study(*, root: Path = ROOT, download=fetch_bytes) -> dict:
    policy = frozen(root)
    original = []
    for spec in policy["capture_sources"]:
        path = spec["path"]
        uri = SOURCE_BASE + policy["source_prefix"] + path
        raw = download(uri)
        need(type(raw) is bytes and 0 < len(raw) <= 2_500_000,
             "original Git capture missing/oversized")
        need(git_blob_sha(raw) == spec["git_blob_sha1"],
             "original third-party capture Git SHA1 changed or is forged")
        obj = json.loads(raw.decode("utf-8", "strict"))
        row = inspect(obj, path=path, original_blob_sha1=spec["git_blob_sha1"])
        # Source authentication only here; caller-provided JSON can never set it.
        row["original_source_verified_by_git_blob"] = True
        original.append(row)
    need(len(original) == 12 and all(x["original_source_verified_by_git_blob"] for x in original),
         "original Git proof incomplete")
    counts = Counter(x["capture_intent_provenance_class"] for x in original)
    need(counts == {KIND_ROUTED: 2, KIND_DIRECT: 2,
                    KIND_DIFFERENT: 6, KIND_FAILED: 2},
         "source-recorded receipt/request classifications changed")
    need(sum(x["observed_http_status"] == 200 for x in original) == 10
         and sum(x["receipt_intent"] == CANONICAL for x in original) == 4,
         "original HTTP/receipt counts changed")
    need(sum(x["request_has_canonical_routed_schema"] for x in original) == 2
         and sum(x["original_capture_url_records_general_route"] for x in original) == 2
         and sum(x["canonical_schema_with_recorded_general_route"]
                 for x in original) == 2,
         "canonical request envelope and independently recorded transport disagree")
    need(all(
         (row["original_direct_endpoint_miner_id"] is not None)
         == (row["original_recorded_route_class"] == "DIRECT_MINER_ENDPOINT")
         and row["receipt_and_body_miner_id_namespace_mapping_independently_verified"] is False
         for row in original),
         "recorded direct URL or unsupported Miner identity mapping")
    candidates = same_request_candidates(original)
    need(len(candidates) == 0 and
         len({x["canonical_request_sha256"] for x in original
              if x["capture_intent_provenance_class"] == KIND_ROUTED}) == 2,
         "expected absent same-canonical-request multi-Miner comparability changed")
    return {
        "schema_version": 1,
        "status": STATUS,
        "original_external_repository": policy["source_repo"],
        "original_git_commit": policy["source_commit"],
        "preimplementation_protocol_git_blob_sha1": LOCK_BLOB,
        "original_outside_git_authenticated_capture_count": len(original),
        "observed_reported_paid_http200_count": 10,
        "original_receipts_reporting_canonical_intent_count": 4,
        "original_captures_record_general_route_count": 2,
        "original_captures_record_direct_endpoint_count": 10,
        "receipt_miner_onchain_registration_id_to_body_miner_mapping_verified": False,
        "original_explicit_canonical_routed_request_and_receipt_count": counts[KIND_ROUTED],
        "original_direct_noncanonical_request_with_canonical_receipt_count": counts[KIND_DIRECT],
        "original_paid_http200_with_noncanonical_receipt_count": counts[KIND_DIFFERENT],
        "original_failed_requests_without_successful_receipts_count": counts[KIND_FAILED],
        "same_canonical_request_multi_miner_candidates": candidates,
        "same_canonical_request_multi_miner_candidate_count": 0,
        "genuine_external_captures_newly_created_by_falsum": 0,
        "original_full_third_party_response_body_republished": False,
        "independent_miner_ownership_verified": False,
        "reported_payment_settlement_independently_verified": False,
        "semantic_security_accuracy_gold": 0,
        "registered_evaluator": False,
        "ranking_change_proved": False,
        "independent_developer_adoption_proved": False,
        "official_h2_submitted": False,
        "source_provenance_observations": original,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify original Git receipts and reject false same-Intent Miner comparisons")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        need(args.out.suffix == ".json" and not args.out.exists()
             and not args.out.is_symlink(), "report must be fresh write-once JSON")
        result = study()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status": STATUS,
            "original_git_verified_captures": 12,
            "canonical_routed_request_and_receipt": 2,
            "only_direct_canonical_receipt": 2,
            "successful_noncanonical_receipts": 6,
            "failed_without_receipt": 2,
            "genuine_identical_canonical_request_multi_miner_candidates": 0,
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        parser.exit(1, "PHASE5AB FAIL-CLOSED ORIGINAL RECEIPT CENSUS: "
                    + str(exc)[:280] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
