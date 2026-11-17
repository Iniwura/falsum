"""Phase 4L: read-only, link-only audit of external PR Guard paid-response captures.

Pinned *public* GitHub blobs are fetched transiently, checked at byte level,
and reduced to structural facts. No third-party response body, advice, payer
address, hidden evaluation labels or own-miner output is copied or scored.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen

REPO = "anvithagowda098/pr-guard"
COMMIT = "99d2e3c93890a8fc083947bde4f21217516b7a5f"
SOURCE_BASE = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
VIEW_BASE = f"https://github.com/{REPO}/blob/{COMMIT}/"
EXTERNAL_REPORT = "https://github.com/telegraphprotocol/bounties/issues/187"
EXCLUDED_MINERS = frozenset({"731001"})
MAX_BLOB = 2_500_000
HEX64 = re.compile(r"^0x[0-9a-fA-F]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
STATUS = "PINNED_EXTERNAL_PAID_RESPONSE_CAPTURE_STRUCTURE_NOT_GOLD"

SPECS = {
    "routed_security": {
        "path": "test/fixtures/miner-responses/ROUTED/security-review-diff-77003-off-target.json",
        "blob": "90088128cb12c4b55966e72165c6a8b311fdbfb2",
        "miner_id": "77003",
        "intent": "SECURITY_REVIEW_GENERAL",
        "shape": "raw",
        "channel": "canonical-routed",
    },
    "direct_verity": {
        "path": "test/fixtures/miner-responses/SECURITY_REVIEW_GENERAL/5530-review-sqli-eval-diff-200-paid.json",
        "blob": "97931d0c376b8bc590f9dab73e5e2c2b29fcac94",
        "miner_id": "5530",
        "intent": "SECURITY_REVIEW",
        "shape": "raw",
        "channel": "direct-family-intent",
    },
    "routed_code": {
        "path": "test/fixtures/miner-responses/ROUTED/code-review-sqli-eval-diff-302-intent.json",
        "blob": "535166ec24b0d40d1ef5e72c2b080d929ac85262",
        "miner_id": "302",
        "intent": "CODE_REVIEW_GENERAL",
        "shape": "intent",
        "channel": "cross-intent-routed-context-only",
    },
}


class EvidenceError(ValueError):
    """Source authenticity, request identity or narrow structural check failed."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceError(reason)


def git_blob_sha(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def fetch_bytes(url: str) -> bytes:
    require(url.startswith(SOURCE_BASE), "unexpected external source URL")
    req = Request(url, headers={"Accept": "application/json",
                                "User-Agent": "FALSUM-phase4l-public-capture-check/1.0"})
    with urlopen(req, timeout=20) as response:
        require(response.status == 200 and response.geturl() == url,
                "source unavailable or redirected")
        raw = response.read(MAX_BLOB + 1)
    require(0 < len(raw) <= MAX_BLOB, "external source exceeds fixed byte cap")
    return raw


def _input_for(role: str, request: object) -> tuple[str, str]:
    require(isinstance(request, dict), "missing request envelope")
    if role == "routed_security":
        require(request.get("intent") == "SECURITY_REVIEW_GENERAL",
                "wrong security routing intent")
        raw = request.get("params")
        require(isinstance(raw, dict), "invalid security target container")
        target = raw.get("target")
        return target, "SECURITY_REVIEW_GENERAL"
    if role == "routed_code":
        require(request.get("intent") == "CODE_REVIEW_GENERAL",
                "cross-Intent response misrepresented as SECURITY_REVIEW_GENERAL")
        raw = request.get("params")
        require(isinstance(raw, dict), "invalid code review target container")
        target = raw.get("code")
        return target, "CODE_REVIEW_GENERAL"
    if role == "direct_verity":
        require(request.get("method") == "POST" and request.get("endpoint") == "/v1/intent",
                "direct Verity request envelope changed")
        raw = request.get("payload")
        require(isinstance(raw, dict) and raw.get("intent") == "SECURITY_REVIEW",
                "direct Verity uses SECURITY_REVIEW family, not the canonical routed Intent")
        inp = raw.get("input")
        require(isinstance(inp, dict), "direct Verity input missing")
        return inp.get("code"), "SECURITY_REVIEW"
    raise EvidenceError("unsupported external capture role")


def inspect_fixture(role: str, spec: dict, raw: bytes) -> dict:
    require(role in SPECS and isinstance(spec, dict), "unapproved fixture role")
    require(isinstance(raw, bytes), "fixture must be bytes")
    require(GIT_SHA.fullmatch(spec.get("blob", "")) is not None,
            "invalid pinned Git blob")
    require(git_blob_sha(raw) == spec["blob"],
            "pinned external blob does not match bytes")
    require(spec.get("miner_id") not in EXCLUDED_MINERS,
            "PR Guard Sentinel #731001 must never enter comparisons")
    require(spec.get("miner_id") == SPECS[role]["miner_id"],
            "unexpected miner identity")
    require(spec.get("intent") == SPECS[role]["intent"] and
            spec.get("shape") == SPECS[role]["shape"] and
            spec.get("channel") == SPECS[role]["channel"] and
            spec.get("path") == SPECS[role]["path"],
            "unapproved external fixture mapping")
    try:
        doc = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, ValueError) as exc:
        raise EvidenceError("invalid external fixture JSON") from exc
    require(isinstance(doc, dict), "fixture JSON not an object")
    target, request_intent = _input_for(role, doc.get("request"))
    require(request_intent == spec["intent"], "request Intent mapping mismatch")
    require(isinstance(target, str) and target.startswith("diff --git a/src/users.js") and
            len(target) <= 16_000, "not the expected published diff")
    require(doc.get("paid") is True and doc.get("ok") is True and
            doc.get("charged") is True and doc.get("status") == 200,
            "paid/response flags not present")
    require(isinstance(doc.get("payment"), dict) and doc["payment"].get("success") is True,
            "payment is not reported successful")
    body, receipt = doc.get("body"), doc.get("receipt")
    require(isinstance(body, dict) and isinstance(receipt, dict), "missing response/receipt fields")
    require(str(body.get("miner_id")) == spec["miner_id"],
            "response miner differs from expected or excluded miner")
    require(str(body.get("miner_id")) not in EXCLUDED_MINERS,
            "excluded contributor-owned miner in response")
    require(body.get("result_shape") == spec["shape"],
            "unexpected response format")
    require(isinstance(body.get("signal_hash"), str) and
            HEX64.fullmatch(body["signal_hash"]) is not None,
            "missing signal hash")
    require(isinstance(receipt.get("receipt_hash"), str) and
            HEX64.fullmatch(receipt["receipt_hash"]) is not None,
            "missing receipt hash")
    require(isinstance(receipt.get("miner"), str) and
            isinstance(receipt.get("intent"), str), "missing receipt routing metadata")

    result = body.get("result")
    if role == "routed_security":
        require(isinstance(result, list) and len(result) == 100,
                "source capture not the 100-entry advisory-feed response")
        require(all(isinstance(item, dict) and
                    isinstance(item.get("ghsa_id"), str) and
                    item["ghsa_id"].startswith("GHSA-") for item in result),
                "not an advisory-list response")
        observed = "100-item-GHSA-feed-not-target-specific-review"
        finding_count = None
    elif role == "direct_verity":
        require(isinstance(result, dict) and isinstance(result.get("answer"), dict),
                "Verity response structure not as recorded")
        findings = result["answer"].get("findings")
        require(isinstance(findings, list), "missing direct Verity findings")
        rules = {f.get("rule_id") for f in findings if isinstance(f, dict)}
        require({"sql-injection-risk", "dynamic-code-execution"} <= rules,
                "recorded Verity source-relevant finding identifiers missing")
        observed = "two-target-relevant-heuristic-rule-identifiers"
        finding_count = len(findings)
    else:
        require(isinstance(result, dict) and
                isinstance(result.get("findings"), list) and
                isinstance(result.get("verdict"), str),
                "ChainSight routed intent-shaped answer missing")
        findings = result["findings"]
        require(all(isinstance(s, str) for s in findings), "invalid ChainSight findings list")
        flat = " ".join(findings).casefold()
        require("sql injection" in flat and "code injection" in flat,
                "expected risk concepts absent from ChainSight's recorded response")
        observed = "target-relevant-findings-in-different-intent"
        finding_count = len(findings)

    return {
        "role": role,
        "source_url": VIEW_BASE + spec["path"],
        "source_git_blob_sha1_verified": spec["blob"],
        "request_intent": request_intent,
        "request_channel": spec["channel"],
        "request_input_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        "captured_response_miner_id": spec["miner_id"],
        "captured_result_shape": spec["shape"],
        "observed_response_structure": observed,
        "recorded_findings_count_not_validated_accuracy": finding_count,
        "public_recorded_signal_hash": body["signal_hash"],
        "public_recorded_receipt_hash": receipt["receipt_hash"],
        "recorded_payment_flags_present": True,
        "receipt_miner_field_matches_body_miner_id": receipt["miner"] == spec["miner_id"],
        "receipt_intent_field_matches_request_intent": receipt["intent"] == request_intent,
        "receipt_metadata_semantics_or_chain_validated": False,
        "expert_gold_label": None,
        "accuracy_score": None,
        "training_or_ranking_use_allowed": False,
    }


def report(fetch=fetch_bytes, specs: dict | None = None) -> dict:
    definitions = SPECS if specs is None else specs
    require(set(definitions) == set(SPECS), "only three precommitted roles are allowed")
    rows = []
    for role in ("routed_security", "direct_verity", "routed_code"):
        spec = definitions[role]
        require(isinstance(spec, dict) and
                spec.get("miner_id") not in EXCLUDED_MINERS,
                "excluded owner-operated miner is forbidden")
        rows.append(inspect_fixture(role, spec, fetch(SOURCE_BASE + spec["path"])))
    hashes = {r["request_input_sha256"] for r in rows}
    require(len(hashes) == 1, "not the same exact input diff across all three captures")
    return {
        "schema_version": 1,
        "status": STATUS,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "external_bounty_integration_report": EXTERNAL_REPORT,
        "external_source_repository": f"https://github.com/{REPO}",
        "external_pinned_git_commit": COMMIT,
        "case_group": "one_same_input_diff_three_different_request_paths",
        "same_request_input_sha256": rows[0]["request_input_sha256"],
        "comparison_roles": rows,
        "captured_paid_response_records": 3,
        "same_intent_equal_router_comparison": False,
        "cross_intent_chain_sight_not_ranking_candidate": True,
        "excluded_owner_operated_miner_ids": sorted(EXCLUDED_MINERS),
        "excluded_miner_answers_loaded_or_scored": False,
        "public_external_response_bodies_copied_into_falsum": False,
        "raw_payments_wallet_addresses_or_row_identifiers_in_report": False,
        "quality_gold_labels": 0,
        "trained_evaluator_improvement_established": False,
        "receipt_cryptographic_or_onchain_verification_established": False,
        "permission_for_retraining_or_republication_granted": False,
        "interpretation": (
            "Pinned captures substantiate a practical target/format mismatch and "
            "two target-relevant reference responses, not independently validated "
            "security correctness or a same-Intent model ranking. The direct Verity "
            "receipt has different recorded Intent metadata and all three receipt "
            "miner fields differ from response miner IDs; semantics remain unresolved."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only external paid-capture structural audit")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error("refuse to overwrite an earlier public-source witness")
    try:
        result = report()
    except (EvidenceError, OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(1, f"Phase 4L: public-source verification did not complete ({type(exc).__name__}); no evidence report published.\n")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except OSError as exc:
        parser.exit(1, f"Phase 4L: cannot create evidence report ({type(exc).__name__}).\n")
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    print(json.dumps({
        "status": result["status"],
        "same_input_across_three_public_fixtures": True,
        "external_source_commit": COMMIT,
        "cross_intent_chain_sight_not_ranking_candidate": True,
        "excluded_miner_answers_loaded_or_scored": False,
        "quality_gold_labels": 0,
        "receipt_cryptographic_or_onchain_verification_established": False,
        "report_file_written": str(args.out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
