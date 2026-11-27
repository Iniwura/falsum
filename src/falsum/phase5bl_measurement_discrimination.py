"""Phase 5BL: cross-source discriminative measurement audit.

This joins four already authenticated source studies into one predeclared
comparison surface.  It adds a new, repeatable analysis of safety-relevant
contrasts across original external application fixtures, independently
reviewed advisory intervals, a published application ledger, and a fresh
provider holdout.  It does not treat any one source as human AppSec gold.

The result is deliberately asymmetric: it records where FALSUM beats weaker
accept/count-only policies, where it ties a competent version-aware baseline,
and where it does not beat verdict-only.  No ranking, recall, adoption or
security-clearance claim is inferred from the comparisons.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import phase5ak_external_label_baselines as phase5ak
from . import phase5ar_response_integrity as phase5ar
from . import phase5bi_measurement_scorecard as phase5bi
from . import phase5bj_fresh_provider_holdout as phase5bj


STATUS = "PHASE5BL_CROSS_SOURCE_DISCRIMINATIVE_MEASUREMENT_AUDIT"


class MeasurementDiscriminationError(ValueError):
    """Raised when a source study is missing, forged or over-interpreted."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise MeasurementDiscriminationError(reason)


def _count(table: dict[str, Any], key: str) -> int:
    # The historical report omits zero-valued cells; absence is a measured
    # zero, not permission to infer an unbounded or unknown count.
    value = table.get(key, 0)
    need(type(value) is int and value >= 0, f"invalid count: {key}")
    return value


def _validate_phase5ar(report: dict[str, Any]) -> dict[str, Any]:
    need(report.get("status") == "PHASE5AR_ORIGINAL_APP_RESPONSE_INTEGRITY",
         "Phase 5AR status changed")
    summary = report.get("summary")
    need(isinstance(summary, dict), "Phase 5AR summary missing")
    expected = {
        "original_direct_fixtures": 9,
        "maintainer_confirmed": 2,
        "explicit_no_code_fixtures": 3,
        "explicit_no_code_verdict_only_clean": 3,
        "explicit_no_code_count_verdict_clean": 2,
        "explicit_no_code_gate_clean": 0,
    }
    for key, value in expected.items():
        need(summary.get(key) == value, f"Phase 5AR metric changed: {key}")
    limits = report.get("limits")
    need(isinstance(limits, dict)
         and limits.get("semantic_accuracy") is False
         and limits.get("independent_integration") is False
         and limits.get("network_ranking_improvement") is False,
         "Phase 5AR limitations were weakened")
    return {
        "denominator": 3,
        "falsum_review": 3,
        "verdict_only_clean": 3,
        "count_verdict_clean": 2,
        "maintainer_confirmed_fixtures": 2,
    }


def _validate_phase5ak(report: dict[str, Any]) -> dict[str, Any]:
    need(report.get("status") == "PHASE5AK_EXTERNAL_LABEL_POLICY_COMPARISON",
         "Phase 5AK status changed")
    summary = report.get("summary")
    need(isinstance(summary, dict)
         and summary.get("unique_cases") == 129
         and summary.get("all_decisions") == 158
         and summary.get("archived_settled") == 201
         and summary.get("archived_not_found") == 1,
         "Phase 5AK population changed")
    metrics = summary.get("latest_metrics")
    need(isinstance(metrics, dict), "Phase 5AK metrics missing")
    count_only = metrics.get("count_only")
    verdict_only = metrics.get("verdict_only")
    falsum = metrics.get("falsum_consumer")
    for row in (count_only, verdict_only, falsum):
        need(isinstance(row, dict), "Phase 5AK policy table incomplete")
    # The source-defined vulnerable/audited labels are retained, but audited
    # controls are not silently promoted to proven clean expert gold.
    need(_count(count_only, "vulnerable:PASS") == 8
         and _count(falsum, "vulnerable:PASS") == 0
         and _count(verdict_only, "vulnerable:PASS") == 0,
         "Phase 5AK vulnerable-label comparison changed")
    need(falsum == verdict_only,
         "FALSUM was incorrectly promoted above verdict-only")
    need(_count(falsum, "audited:FLAG") == 5
         and _count(count_only, "audited:FLAG") == 1,
         "Phase 5AK audited-control trade-off changed")
    need(report.get("better_than_verdict_baseline") is False
         and report.get("live_settlement_verified") is False,
         "Phase 5AK negative findings were weakened")
    return {
        "unique_cases": 129,
        "vulnerable_cases": 107,
        "audited_cases": 22,
        "falsum_vulnerable_pass": 0,
        "count_only_vulnerable_pass": 8,
        "verdict_only_vulnerable_pass": 0,
        "falsum_audited_flags": 5,
        "count_only_audited_flags": 1,
        "verdict_only_audited_flags": 5,
        "ties_verdict_only": True,
    }


def _validate_phase5bi(report: dict[str, Any]) -> dict[str, Any]:
    need(report.get("status") == phase5bi.STATUS, "Phase 5BI status changed")
    baseline = report.get("baseline")
    gate = report.get("falsum_gate")
    need(isinstance(baseline, dict) and isinstance(gate, dict),
         "Phase 5BI policy sections missing")
    need(baseline.get("reference_instances_displayed") == 12
         and baseline.get("known_inapplicable_instances_displayed") == 2
         and gate.get("reference_instances_displayed") == 10
         and gate.get("known_inapplicable_instances_displayed") == 0,
         "Phase 5BI 12/10/2 comparison changed")
    limits = report.get("limitations")
    need(isinstance(limits, list)
         and any("human appsec gold" in item.lower() for item in limits)
         and any("does not claim independent developer adoption" in item.lower() for item in limits),
         "Phase 5BI limitations missing")
    return {
        "denominator": 12,
        "accept_all_known_inapplicable": 2,
        "falsum_known_inapplicable": 0,
        "falsum_reviewed_precision": "10/10",
    }


def _validate_phase5bj(report: dict[str, Any]) -> dict[str, Any]:
    need(report.get("status") == phase5bj.STATUS, "Phase 5BJ status changed")
    aggregate = report.get("aggregate")
    need(isinstance(aggregate, dict)
         and aggregate.get("reported_reference_count") == 66
         and aggregate.get("source_resolved_reference_count") == 38
         and aggregate.get("source_applicable_reference_count") == 27
         and aggregate.get("source_uncertain_or_unknown_count") == 39
         and aggregate.get("falsum_baseline_disagreement_count") == 0,
         "Phase 5BJ fresh holdout changed")
    interpretation = report.get("interpretation")
    need(isinstance(interpretation, dict)
         and interpretation.get("measurement_improvement_claimed") is False
         and interpretation.get("new_paid_telegraph_execution") is False,
         "Phase 5BJ negative interpretation was weakened")
    return {
        "denominator": 66,
        "source_resolved": 38,
        "source_applicable": 27,
        "unknown_or_insufficient": 39,
        "falsum_baseline_agreement": 66,
        "competent_baseline_superiority": False,
    }


def score_reports(phase5ar_report: dict[str, Any], phase5ak_report: dict[str, Any],
                  phase5bi_report: dict[str, Any], phase5bj_report: dict[str, Any]) -> dict[str, Any]:
    """Derive a cross-source measurement report from validated study outputs."""
    ar = _validate_phase5ar(phase5ar_report)
    ak = _validate_phase5ak(phase5ak_report)
    bi = _validate_phase5bi(phase5bi_report)
    bj = _validate_phase5bj(phase5bj_report)
    return {
        "schema_version": 1,
        "status": STATUS,
        "measurement_scope": {
            "source_studies": ["Phase 5AR", "Phase 5AK", "Phase 5BI", "Phase 5BJ"],
            "new_analysis": "Predeclared cross-source comparison of evidence-sensitive policy contrasts and fair baselines; no underlying source row is relabeled.",
            "security_review_family": "SECURITY_REVIEW",
            "historical_child_intent": "SECURITY_REVIEW_GENERAL",
        },
        "reference_evidence_tiers": [
            {
                "tier": "EXTERNAL_MAINTAINER_CORROBORATED",
                "source": "Truvian original fixture source and maintainer review",
                "cases": ar["denominator"],
                "maintainer_confirmed_cases": ar["maintainer_confirmed_fixtures"],
                "role": "Defensible response-integrity checks, not semantic AppSec gold.",
            },
            {
                "tier": "INDEPENDENTLY_REVIEWED_ADVISORY_SOURCE",
                "source": "Pinned GitHub Advisory Database records",
                "instances": bi["denominator"],
                "applicable_instances": 10,
                "inapplicable_instances": 2,
                "role": "Exact package/version reference facts, not full recall or human gold.",
            },
            {
                "tier": "PUBLISHED_EXTERNAL_APPLICATION_LABELS",
                "source": "Gig Guard complete published scale ledger",
                "cases": ak["unique_cases"],
                "vulnerable_labeled_cases": ak["vulnerable_cases"],
                "audited_labeled_cases": ak["audited_cases"],
                "role": "Independent of FALSUM policy code, but audited controls are not proven bug-free.",
            },
            {
                "tier": "FRESH_PUBLIC_PROVIDER_HOLDOUT",
                "source": "Pinned public PR Guard fixtures plus pinned advisory source",
                "instances": bj["denominator"],
                "source_resolved": bj["source_resolved"],
                "role": "Unseen provider evidence with a separately implemented competent baseline.",
            },
        ],
        "fair_comparisons": {
            "missing_evidence_contrast": {
                "denominator": ar["denominator"],
                "falsum_review_not_clean": ar["falsum_review"],
                "verdict_only_clean": ar["verdict_only_clean"],
                "count_verdict_clean": ar["count_verdict_clean"],
                "contrastive_result": "FALSUM rejects 3/3 clean-looking answers that explicitly lack reviewable code/configuration evidence; verdict-only accepts 3/3 and count-plus-verdict accepts 2/3.",
            },
            "version_boundary_contrast": {
                "denominator": bi["denominator"],
                "accept_all_known_inapplicable": bi["accept_all_known_inapplicable"],
                "falsum_known_inapplicable": bi["falsum_known_inapplicable"],
                "contrastive_result": "FALSUM suppresses both independently reviewed version-inapplicable references while the recorded accept-all policy displays both.",
            },
            "published_external_policy_population": {
                "cases": ak["unique_cases"],
                "falsum_vulnerable_label_pass": ak["falsum_vulnerable_pass"],
                "count_only_vulnerable_label_pass": ak["count_only_vulnerable_pass"],
                "verdict_only_vulnerable_label_pass": ak["verdict_only_vulnerable_pass"],
                "falsum_audited_control_flags": ak["falsum_audited_flags"],
                "verdict_only_audited_control_flags": ak["verdict_only_audited_flags"],
                "contrastive_result": "FALSUM removes 8 vulnerable-label PASS outcomes versus count-only, but ties verdict-only and flags 5/22 audited controls; no superiority claim is made.",
            },
            "fresh_provider_competent_baseline": {
                "denominator": bj["denominator"],
                "falsum_baseline_agreement": bj["falsum_baseline_agreement"],
                "competent_baseline_superiority": bj["competent_baseline_superiority"],
                "contrastive_result": "FALSUM agrees 66/66 with the separately implemented exact-target interval baseline; this validates reproducibility, not superiority.",
            },
        },
        "measurement_conclusion": {
            "weaker_policy_contrasts_demonstrated": 2,
            "competent_baseline_ties": 1,
            "verdict_only_superiority": False,
            "independent_human_appsec_gold": 0,
            "ranking_improvement": False,
            "security_clearance": False,
            "new_paid_telegraph_execution": False,
            "summary": "FALSUM demonstrates two source-bound, safety-relevant contrasts against weaker policies, ties a competent version-aware baseline on fresh evidence, and preserves the negative finding that it does not beat verdict-only on the published application population.",
        },
        "limits": [
            "The cross-source report is a new analysis of authenticated prior studies, not a claim that every underlying case is an unseen blind holdout.",
            "External maintainer corroboration and GitHub-reviewed advisory records are defensible checks, not qualified human AppSec gold.",
            "Published application labels are external records; audited controls are not proven bug-free and archived settlement metadata is not live settlement proof.",
            "The fresh-provider comparison has no FALSUM-versus-baseline delta and therefore proves no ranking superiority.",
            "No independent customer adoption, registered network evaluator, maintainer acceptance, or H2 submission is claimed.",
        ],
    }


def study() -> dict[str, Any]:
    return score_reports(
        phase5ar.audit(), phase5ak.audit(), phase5bi.study(), phase5bj.study()
    )


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(),
         "measurement audit output must be a fresh JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = study()
        _write_once(args.out, report)
        print(json.dumps({
            "status": report["status"],
            "weaker_policy_contrasts_demonstrated": report["measurement_conclusion"]["weaker_policy_contrasts_demonstrated"],
            "competent_baseline_ties": report["measurement_conclusion"]["competent_baseline_ties"],
            "verdict_only_superiority": False,
            "independent_human_appsec_gold": 0,
        }, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, AssertionError) as exc:
        parser.exit(1, "PHASE5BL MEASUREMENT AUDIT FAILED CLOSED: " + str(exc)[:300] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
