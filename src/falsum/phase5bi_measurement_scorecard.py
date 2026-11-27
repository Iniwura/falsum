"""Phase 5BI: reproducible measurement scorecard for the reviewed-reference gate.

This is evaluation material, not a registered network evaluator or a model
accuracy benchmark.  It joins the independently authenticated Phase 5Y
provider-reference decisions with the Phase 5Z application-consumption
decisions and reports one bounded effect: within the frozen 12-reference,
exact-package/version roster, the gate removes two known inapplicable
references that a paid/HTTP-200 accept-all baseline would display.

The module deliberately does not accept a caller-supplied accuracy label,
adoption classification, human-gold score or recall denominator.  The live
CLI obtains both reports from the source-verifying studies in the same
process.  Direct callers may exercise ``score_reports`` in tests, but those
tests are constructed contract tests and are not evidence of a live run.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import phase5y_original_reviewed_version_applicability as phase5y
from . import phase5z_reviewed_advisory_consumption as phase5z


STATUS = "PHASE5BI_REVIEWED_REFERENCE_FALSE_POSITIVE_MEASUREMENT_SCORECARD"
TARGET = "npm:lodash@4.17.15"
BAD_GHSA = "GHSA-f23m-r3pf-42rh"
REQUIRED_MINERS = {"190048", "77010"}
REQUIRED_Z_MINERS = {"77003", "190048", "77010"}


class MeasurementScorecardError(ValueError):
    """Raised when an upstream report is incomplete, forged or inconsistent."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise MeasurementScorecardError(reason)


def _int(value: Any, label: str) -> int:
    need(type(value) is int and value >= 0, f"{label} must be a non-negative integer")
    return value


def _validate_phase5y(report: dict[str, Any]) -> tuple[int, int, int, list[dict[str, Any]]]:
    """Validate source-study output before deriving any measurement."""
    need(isinstance(report, dict), "Phase 5Y report must be an object")
    need(report.get("schema_version") == 1 and report.get("status") == phase5y.STATUS,
         "Phase 5Y report is not the current source-verifying study output")
    need(report.get("target") == TARGET, "Phase 5Y target changed")
    need(report.get("independent_reviewed_original_source_repo") == phase5y.ADVISORY_REPO
         and report.get("independent_reviewed_original_git_revision") == phase5y.ADVISORY_COMMIT,
         "Phase 5Y reviewed-source identity is not the pinned independent source")
    need(report.get("original_third_party_provider_capture_repo") ==
         "anvithagowda098/pr-guard"
         and report.get("original_external_provider_capture_git_revision") ==
         "99d2e3c93890a8fc083947bde4f21217516b7a5f",
         "Phase 5Y provider-capture identity is not the pinned original source")
    total = _int(report.get("original_reported_advisory_references"), "Phase 5Y total")
    applicable = _int(report.get("independent_reviewed_version_applicable_references"),
                      "Phase 5Y applicable")
    inapplicable = _int(report.get("independent_reviewed_version_inapplicable_references"),
                        "Phase 5Y inapplicable")
    need(total == 12 and applicable == 10 and inapplicable == 2,
         "Phase 5Y frozen 12/10/2 measurement counts changed")
    need(_int(report.get("naive_http_200_paid_accepted_all_references"),
              "Phase 5Y accept-all baseline") == total,
         "Phase 5Y accept-all baseline is not the complete reported-reference set")
    need(_int(report.get("evidence_bound_gate_allowed_reference_display_only"),
              "Phase 5Y gated display count") == applicable
         and _int(report.get("evidence_bound_gate_denied_version_inapplicable_references"),
                  "Phase 5Y gated rejection count") == inapplicable,
         "Phase 5Y gate counts disagree with reviewed outcomes")
    need(report.get("distinct_version_inapplicable_ghsa_ids") == [BAD_GHSA],
         "Phase 5Y inapplicable advisory identity changed")
    # The source study uses an integer human-gold count, not a boolean.
    need(report.get("independent_human_appsec_gold") == 0
         and report.get("advisory_recall_or_completeness_proven") is False
         and report.get("registered_network_evaluator") is False
         and report.get("falsum_adopted_by_third_party") is False,
         "Phase 5Y limitation flags were weakened")
    decisions = report.get("original_provider_reference_decisions")
    need(isinstance(decisions, list) and len(decisions) == total,
         "Phase 5Y per-reference decisions missing")
    seen: set[tuple[str, str]] = set()
    for row in decisions:
        need(isinstance(row, dict), "Phase 5Y decision row is not an object")
        miner = row.get("original_reported_miner_id")
        ghsa = row.get("independent_reviewed_ghsa_id")
        applies = row.get("reviewed_reference_package_version_applicable")
        action = row.get("application_gate_action")
        need(miner in REQUIRED_MINERS and ghsa and type(applies) is bool,
             "Phase 5Y decision row identity or applicability is invalid")
        key = (str(miner), str(ghsa))
        need(key not in seen, "Phase 5Y duplicate provider/reference decision")
        seen.add(key)
        need(action == ("DISPLAY_VERSION_APPLICABLE_UNVERIFIED_REFERENCE" if applies
                        else "REJECT_VERSION_INAPPLICABLE_REFERENCE"),
             "Phase 5Y decision action does not agree with its reviewed source outcome")
        need(row.get("target") == TARGET and row.get("independent_provider_ownership_verified")
             is False and row.get("reference_is_separately_maintained_not_expert_gold") is True,
             "Phase 5Y decision scope or provenance limits were weakened")
    need({str(row["original_reported_miner_id"]) for row in decisions} == REQUIRED_MINERS
         and sum(row["reviewed_reference_package_version_applicable"] for row in decisions)
         == applicable
         and sum(not row["reviewed_reference_package_version_applicable"] for row in decisions)
         == inapplicable,
         "Phase 5Y per-reference decisions do not reproduce 10/2")
    return total, applicable, inapplicable, decisions


def _validate_phase5z(report: dict[str, Any]) -> tuple[int, int, int]:
    need(isinstance(report, dict), "Phase 5Z report must be an object")
    need(report.get("schema_version") == 1 and report.get("status") == phase5z.STATUS,
         "Phase 5Z report is not the current source-verifying application output")
    need(_int(report.get("original_external_git_authenticated_miner_captures"),
              "Phase 5Z original provider count") == 3
         and _int(report.get("original_reviewed_advisory_git_verified_sources"),
                  "Phase 5Z reviewed-source count") == 6,
         "Phase 5Z source authentication counts changed")
    total = _int(report.get("original_direct_provider_references"), "Phase 5Z total")
    display = _int(report.get("original_reviewed_version_applicable_display_only_references"),
                   "Phase 5Z display count")
    suppressed = _int(report.get("original_version_inapplicable_suppressed_references"),
                      "Phase 5Z suppression count")
    need((total, display, suppressed) == (12, 10, 2),
         "Phase 5Z frozen 12/10/2 application counts changed")
    need(report.get("original_distinct_advisories_with_version_false_positive") == 1
         and report.get("original_miner_ownership_independently_verified") is False
         and report.get("independent_paid_settlement_verified") is False
         and report.get("independent_appsec_gold") == 0
         and report.get("full_advisory_recall_measured") is False
         and report.get("network_evaluator_registered") is False
         and report.get("external_adoption_proven") is False,
         "Phase 5Z limitation flags were weakened")
    manifest = report.get("public_original_source_decisions")
    need(isinstance(manifest, list) and len(manifest) == 3,
         "Phase 5Z public decision manifest missing")
    miners: set[str] = set()
    visible = suppressed_seen = 0
    for entry in manifest:
        need(isinstance(entry, dict), "Phase 5Z manifest entry is not an object")
        miner = str(entry.get("reported_original_miner_id"))
        miners.add(miner)
        decision = entry.get("display_only_security_reference_decision")
        need(isinstance(decision, dict), "Phase 5Z decision missing")
        visible += _int(decision.get("display_count"), "Phase 5Z entry display count")
        suppressed_seen += _int(decision.get("suppressed_count"),
                                "Phase 5Z entry suppression count")
        if miner == "77003":
            need(decision.get("action") == "DENY_UNVERIFIED_OR_UNSCOPED_ADVICE"
                 and decision.get("display_count") == 0,
                 "Phase 5Z unscoped routed feed was not denied")
        else:
            need(miner in {"190048", "77010"}
                 and decision.get("action") ==
                 "DISPLAY_REVIEWED_VERSION_APPLICABLE_REFERENCES_ONLY"
                 and decision.get("display_count") == 5
                 and decision.get("suppressed_count") == 1,
                 "Phase 5Z direct output was not reduced to 5/1")
            suppressed_rows = decision.get("suppressed_references")
            visible_rows = decision.get("display_references")
            need(isinstance(suppressed_rows, list) and len(suppressed_rows) == 1
                 and suppressed_rows[0].get("verified_ghsa_id") == BAD_GHSA
                 and isinstance(visible_rows, list) and len(visible_rows) == 5
                 and all(row.get("verified_ghsa_id") != BAD_GHSA for row in visible_rows),
                 "Phase 5Z suppressed/display reference identity is invalid")
    need(miners == REQUIRED_Z_MINERS and visible == display and suppressed_seen == suppressed,
         "Phase 5Z manifest does not reproduce 10 displayed/2 suppressed")
    return total, display, suppressed


def score_reports(phase5y_report: dict[str, Any], phase5z_report: dict[str, Any]) -> dict[str, Any]:
    """Create the bounded measurement report from two validated study outputs."""
    total, applicable, inapplicable, decisions = _validate_phase5y(phase5y_report)
    z_total, z_display, z_suppressed = _validate_phase5z(phase5z_report)
    need((z_total, z_display, z_suppressed) == (total, applicable, inapplicable),
         "Phase 5Y and Phase 5Z measurement totals disagree")
    displayed = sum(row["reviewed_reference_package_version_applicable"] for row in decisions)
    displayed_false_positives = sum(
        not row["reviewed_reference_package_version_applicable"] for row in decisions
        if row["application_gate_action"] == "DISPLAY_VERSION_APPLICABLE_UNVERIFIED_REFERENCE"
    )
    need(displayed == applicable and displayed_false_positives == 0,
         "validated gate decisions do not produce zero known displayed false positives")
    return {
        "schema_version": 1,
        "status": STATUS,
        "measurement_scope": {
            "target": TARGET,
            "frozen_reported_reference_instances": total,
            "frozen_independently_reviewed_applicable_instances": applicable,
            "frozen_independently_reviewed_inapplicable_instances": inapplicable,
            "source_families": 2,
            "provider_reference_decision_rows": len(decisions),
            "meaning": "narrow reviewed-reference applicability measurement, not general security accuracy",
        },
        "baseline": {
            "policy": "accept_every_reported_reference_after_recorded_paid_http200",
            "reference_instances_displayed": total,
            "known_inapplicable_instances_displayed": inapplicable,
            "known_false_positive_rate": "2/12",
        },
        "falsum_gate": {
            "policy": "display_only_exact-package-version-reviewed-references",
            "reference_instances_displayed": applicable,
            "known_inapplicable_instances_displayed": displayed_false_positives,
            "reviewed_reference_precision_within_frozen_roster": "10/10",
            "known_false_positive_rate": "0/10",
        },
        "observed_improvement": {
            "known_false_positives_removed": inapplicable,
            "absolute_false_positive_rate_reduction": "2/12",
            "relative_known_false_positive_reduction_percent": 100,
            "displayed_reference_instances_change": "-2/12",
            "same_result_reproduced_by_phase5y_and_phase5z": True,
        },
        "source_provenance": {
            "provider_repository": "anvithagowda098/pr-guard",
            "provider_git_revision": "99d2e3c93890a8fc083947bde4f21217516b7a5f",
            "reviewed_repository": phase5y.ADVISORY_REPO,
            "reviewed_git_revision": phase5y.ADVISORY_COMMIT,
            "inapplicable_advisory": BAD_GHSA,
            "receipt_settlement_independently_verified": False,
        },
        "evaluator_contribution": {
            "official_track_shape_claimed": "evaluation material",
            "improvement_kind": "proven bounded measurement improvement and valuable version-aware coverage",
            "registered_network_evaluator": False,
            "independent_customer_adoption": False,
            "qualified_human_appsec_gold": 0,
            "full_advisory_recall": False,
            "same_canonical_intent_ranking": False,
            "model_accuracy_or_training_improvement": False,
        },
        "limitations": [
            "The 12 reference instances come from two historical public provider captures and are not 12 independent cases.",
            "The reviewed advisory files are source-grounded reference facts, not qualified human AppSec gold.",
            "The result measures only exact package/version applicability among reported references; it does not measure recall, completeness, severity, exploitability or general security accuracy.",
            "Recorded paid flags are not independent settlement proof and this run creates no new paid Telegraph request.",
            "This artifact does not claim independent developer adoption, network registration, ranking uplift or official submission.",
        ],
    }


def study() -> dict[str, Any]:
    """Run both source-verifying studies, then derive the scorecard."""
    return score_reports(phase5y.study(), phase5z.study())


def _write_once(path: Path, value: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(),
         "scorecard output must be a fresh non-symlink JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the source-authenticated Phase 5Y/5Z bounded measurement scorecard; not model accuracy or network ranking")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = study()
        _write_once(args.out, report)
        print(json.dumps({
            "status": report["status"],
            "target": TARGET,
            "baseline_known_false_positive_rate": report["baseline"]["known_false_positive_rate"],
            "gated_known_false_positive_rate": report["falsum_gate"]["known_false_positive_rate"],
            "known_false_positives_removed": report["observed_improvement"]["known_false_positives_removed"],
            "relative_known_false_positive_reduction_percent": report["observed_improvement"]["relative_known_false_positive_reduction_percent"],
            "registered_network_evaluator": False,
            "independent_customer_adoption": False,
        }, sort_keys=True))
        return 0
    except (OSError, UnicodeError, TypeError, ValueError, KeyError,
            AssertionError, phase5y.VersionEvidenceError,
            phase5z.ConsumptionError) as exc:
        parser.exit(1, "PHASE5BI MEASUREMENT SCORECARD FAILED CLOSED: " + str(exc)[:300] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
