"""Phase 4B: source-grounded, *offline reference judge*, NOT a Telegraph LoRA.

Verifies narrow GHSA package-version claims using frozen, independently fetched
GitHub Advisory Database and published PyPI evidence from Phase 3Z. Refuses
deployment-exploit conclusions and missing/contradictory provenance. This is an
auditable evaluation-material tool; never a network-registered scoring adapter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase4a_real_model_probe import load_source, SOURCE_SHA256
from .phase4a_recorded_evidence import check as check_old_model

STATUS = "PHASE4B_SOURCE_GROUNDED_REFERENCE_JUDGE_OFFLINE_RESEARCH_ONLY"
RESULTS = ("SUPPORTED", "CONTRADICTED", "ABSTAIN")
CLAIMS = ("IN_NAMED_GHSA_RANGE", "OUTSIDE_NAMED_GHSA_RANGE",
          "CONFIRMED_PRODUCTION_EXPLOIT", "GUARANTEED_APPLICATION_SAFE")
MAX_REQUESTS = 100


class ReferenceJudgeError(ValueError):
    """Fail closed if public source, claim schema, or claims are unsafe."""


def require(ok, message):
    if not ok:
        raise ReferenceJudgeError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def lookup(source: dict) -> dict:
    """Reject ambiguous provenance even after exact source SHA verification."""
    require(isinstance(source, dict), "missing verified source")
    provenance = source.get("provenance")
    cases = source.get("cases")
    require(isinstance(provenance, list) and len(provenance) == 3
            and isinstance(cases, list) and len(cases) == 6,
            "incorrect source provenance or case count")
    index = {}
    for provenance_row in provenance:
        package = provenance_row["package"]
        ghsa = provenance_row["ghsa"]
        require(isinstance(package, str) and isinstance(ghsa, str)
                and (package, ghsa) not in index, "ambiguous package/advisory identity")
        by_version = {}
        for rel in provenance_row["verified_pypi_releases"]:
            require(rel["not_yanked_at_verification"] is True
                    and rel["release"] not in by_version,
                    "ambiguous or yanked verified release")
            by_version[rel["release"]] = rel
        require(len(by_version) == 2, "expected exactly two source-verified releases")
        index[(package, ghsa)] = {
            "advisory_sha256": provenance_row["pinned_advisory_json_sha256"],
            "source_advisory_url": provenance_row["pinned_advisory_raw_url"],
            "versions": by_version, "expected": {},
        }
    for case in cases:
        key = (case["source_package"], case["advisory"])
        entry = index.get(key)
        require(entry is not None, "case has no pinned source")
        version = case["source_release"]
        require(version in entry["versions"] and version not in entry["expected"],
                "case version has no unique published release evidence")
        expected = case["mechanically_source_derived_preference"]
        require(expected in ("A", "B"), "unapproved source-fact preference")
        entry["expected"][version] = expected == "A"
    require(all(len(entry["expected"]) == 2 for entry in index.values()),
            "source cases and release provenance incomplete")
    return index


def claim_for(source: dict, case: dict, claim: str) -> dict:
    """Create a faithful input fixture from real signed-off source metadata."""
    index = lookup(source)
    key = (case["source_package"], case["advisory"])
    info = index[key]
    release = info["versions"][case["source_release"]]
    return {
        "package": case["source_package"],
        "version": case["source_release"],
        "advisory": case["advisory"],
        "claim_type": claim,
        "evidence": {
            "pinned_advisory_sha256": info["advisory_sha256"],
            "pypi_release_metadata_sha256": release["actual_pypi_release_metadata_sha256"],
            "pypi_release_url": release["release_url"],
        },
    }


def judge(source: dict, review: dict, *, index=None) -> dict:
    """Classify an already structured fact claim: supported/contradicted/abstain.

    No NLP: neither freeform reviews nor production exploitability are certified.
    """
    require(isinstance(review, dict), "review must be an object")
    require(set(review) == {"package", "version", "advisory", "claim_type", "evidence"},
            "review must contain only canonical structured fields")
    require(all(isinstance(review[k], str) and 0 < len(review[k]) <= 128
                for k in ("package", "version", "advisory", "claim_type")),
            "review identifiers invalid or unbounded")
    evidence = review["evidence"]
    require(isinstance(evidence, dict), "evidence must be an object")
    require(set(evidence) <= {
        "pinned_advisory_sha256", "pypi_release_metadata_sha256", "pypi_release_url"
    }, "unexpected evidence fields")

    result = {
        "package": review["package"], "version": review["version"],
        "advisory": review["advisory"],
        "claim_type": review["claim_type"],
        "verdict": "ABSTAIN",
        "reason": "UNSUPPORTED_SOURCE_IDENTITY",
        "limited_to_named_public_advisory": True,
        "deployment_exploitability_assessed": False,
        "other_vulnerabilities_excluded": False,
        "independent_expert_label": False,
        "network_eligible": False,
        "registered_evaluator": False,
    }
    records = index if index is not None else lookup(source)
    key = (review["package"], review["advisory"])
    if key not in records:
        return result
    entry = records[key]
    version = review["version"]
    if version not in entry["expected"]:
        result["reason"] = "VERSION_NOT_VERIFIED_IN_FROZEN_SOURCE"
        return result
    release = entry["versions"][version]
    if (evidence.get("pinned_advisory_sha256") != entry["advisory_sha256"]
            or evidence.get("pypi_release_metadata_sha256")
                != release["actual_pypi_release_metadata_sha256"]
            or evidence.get("pypi_release_url") != release["release_url"]):
        result["reason"] = "MISSING_OR_MISMATCHED_PRIMARY_EVIDENCE"
        return result
    if review["claim_type"] not in CLAIMS[:2]:
        result["reason"] = "DEPLOYMENT_OR_GLOBAL_SAFETY_NOT_ESTABLISHED"
        return result
    assertion_in_range = review["claim_type"] == "IN_NAMED_GHSA_RANGE"
    actual_in_range = entry["expected"][version]
    result["verdict"] = "SUPPORTED" if assertion_in_range == actual_in_range else "CONTRADICTED"
    result["reason"] = "PINNED_NAMED_ADVISORY_VERSION_INTERVAL_ONLY"
    result["verified_releases_only"] = True
    result["source_catalogue_fact"] = "IN_RANGE" if actual_in_range else "OUTSIDE_RANGE"
    return result


def build_stress_suite(source: dict) -> list[dict]:
    """36 public-safe examples; no private holdout or new accepted labels."""
    index = lookup(source)
    requests = []
    for case in source["cases"]:
        fact = case["mechanically_source_derived_preference"]
        right = "IN_NAMED_GHSA_RANGE" if fact == "A" else "OUTSIDE_NAMED_GHSA_RANGE"
        wrong = "OUTSIDE_NAMED_GHSA_RANGE" if fact == "A" else "IN_NAMED_GHSA_RANGE"
        for kind, claim, expect in (
            ("matching_source_fact", right, "SUPPORTED"),
            ("contradicting_source_fact", wrong, "CONTRADICTED"),
            ("unsupported_exploit_claim", "CONFIRMED_PRODUCTION_EXPLOIT", "ABSTAIN"),
            ("unsupported_global_safety_claim", "GUARANTEED_APPLICATION_SAFE", "ABSTAIN"),
        ):
            requests.append({
                "test_id": case["case_id"] + ":" + kind,
                "expected": expect, "claim": claim_for(source, case, claim),
            })
        tampered = claim_for(source, case, right)
        tampered["evidence"]["pinned_advisory_sha256"] = "0"*64
        requests.append({
            "test_id": case["case_id"] + ":tampered_provenance",
            "expected": "ABSTAIN", "claim": tampered,
        })
        unsupported = claim_for(source, case, right)
        unsupported["version"] += ".999"
        requests.append({
            "test_id": case["case_id"] + ":unverified_version",
            "expected": "ABSTAIN", "claim": unsupported,
        })
    require(len(requests) == 36 and len({x["test_id"] for x in requests}) == 36,
            "stress-test coverage lost")
    return requests


def run(source_raw: bytes, *, claims=None, old_model=None) -> dict:
    try:
        source = load_source(source_raw)
    except (TypeError, ValueError, KeyError) as e:
        raise ReferenceJudgeError("official source artifact integrity failed") from e
    index = lookup(source)
    examples = build_stress_suite(source) if claims is None else claims
    require(isinstance(examples, list) and 1 <= len(examples) <= MAX_REQUESTS,
            "missing or oversized evaluation request set")
    ids = set()
    rows = []
    for item in examples:
        require(isinstance(item, dict) and set(item) in (
                {"test_id", "claim"}, {"test_id", "claim", "expected"}),
                "evaluation request schema invalid")
        ident = item["test_id"]
        require(isinstance(ident, str) and 1 <= len(ident) <= 160
                and ident not in ids, "duplicate/invalid review identity")
        ids.add(ident)
        judgement = judge(source, item["claim"], index=index)
        record = {"test_id": ident, "judgement": judgement}
        if "expected" in item:
            require(item["expected"] in RESULTS, "expected finding invalid")
            record["fixture_expectation"] = item["expected"]
            record["matches_source_derived_fixture"] = (
                judgement["verdict"] == item["expected"])
        rows.append(record)

    fixture_checked = all("matches_source_derived_fixture" in x for x in rows)
    if fixture_checked:
        require(all(x["matches_source_derived_fixture"] for x in rows),
                "source-grounded reference check failed on a canonical scenario")
    result = {
        "schema_version": 1, "status": STATUS,
        "source_sha256": sha(source_raw),
        "verified_advisory_package_projects": len(index),
        "total_claims": len(rows),
        "supported": sum(x["judgement"]["verdict"] == "SUPPORTED" for x in rows),
        "contradicted": sum(x["judgement"]["verdict"] == "CONTRADICTED" for x in rows),
        "abstained": sum(x["judgement"]["verdict"] == "ABSTAIN" for x in rows),
        "source_derived_fixture_agreement": sum(
            x.get("matches_source_derived_fixture") is True for x in rows),
        "source_derived_fixture_count": len(rows) if fixture_checked else 0,
        "published_package_version_claims_only": True,
        "not_a_semantic_security_review_model": True,
        "not_telegraph_network_adapter": True,
        "not_an_independent_or_blind_model_quality_test": True,
        "independent_expert_labels": 0,
        "network_eligible_rows": 0, "registered_evaluator": False,
        "model_training_or_release_authorized": False,
        "cases": rows,
        "notice": (
            "Deterministic reference check over previously verified public advisory "
            "version facts. It is correct *by construction* on its own source-derived "
            "fixtures; this is not learned security-reasoning accuracy or a network-"
            "compatible hybrid LoRA. Unsupported deployments and missing evidence abstain."
        ),
    }
    if old_model is not None:
        try:
            baseline = check_old_model(old_model)
        except (ValueError, TypeError, KeyError) as e:
            raise ReferenceJudgeError("historical actual-model comparison is unverified") from e
        result["historical_old_model"] = {
            "actual_foundation_score_bits": baseline["actual_score_bits"],
            "verified_source_fact_matches": baseline["observed_matches"],
            "total_binary_comparisons": 6,
            "complete_version_fact_reversals": baseline["complete_version_reversals"],
            "model_release_authorized": False,
            "not_comparable_to_abstention_stress_tests": True,
            "not_an_improved_trained_model": True,
        }
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline evidence-grounded source-fact reviewer, NOT a Telegraph adapter")
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--claims", type=Path, help="Optional structured claims JSON array; omit for 36-case stress replay")
    p.add_argument("--old-model-ledger", type=Path,
                   help="Optional actual original-Foundation score ledger for honest six-case comparison")
    args = p.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink(), "refuse output overwrite")
        raw = args.source.read_bytes()
        require(len(raw) <= 250000, "source exceeds allowed byte limit")
        claims = None
        if args.claims:
            data = args.claims.read_bytes()
            require(len(data) <= 100000, "claims exceed permitted byte limit")
            claims = json.loads(data)
        old = json.loads(args.old_model_ledger.read_text()) if args.old_model_ledger else None
        result = run(raw, claims=claims, old_model=old)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: result[k] for k in (
            "status", "total_claims", "supported", "contradicted", "abstained",
            "source_derived_fixture_agreement", "registered_evaluator"
        )}, indent=2))
        return 0
    except (OSError, ValueError, UnicodeError, TypeError, KeyError) as e:
        p.exit(1, "PHASE4B OFFLINE REFERENCE JUDGE BLOCKED: " + str(e) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
