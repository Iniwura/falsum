"""Adversarial contracts for the cross-source measurement audit."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from falsum import phase5ak_external_label_baselines as phase5ak
from falsum import phase5ar_response_integrity as phase5ar
from falsum import phase5bi_measurement_scorecard as phase5bi
from falsum import phase5bj_fresh_provider_holdout as phase5bj
from falsum import phase5bl_measurement_discrimination as phase5bl


def fixtures():
    ar = {
        "status": "PHASE5AR_ORIGINAL_APP_RESPONSE_INTEGRITY",
        "summary": {
            "original_direct_fixtures": 9,
            "maintainer_confirmed": 2,
            "explicit_no_code_fixtures": 3,
            "explicit_no_code_verdict_only_clean": 3,
            "explicit_no_code_count_verdict_clean": 2,
            "explicit_no_code_gate_clean": 0,
        },
        "limits": {"semantic_accuracy": False, "independent_integration": False,
                   "network_ranking_improvement": False},
    }
    ak = {
        "status": "PHASE5AK_EXTERNAL_LABEL_POLICY_COMPARISON",
        "summary": {
            "unique_cases": 129, "all_decisions": 158,
            "archived_settled": 201, "archived_not_found": 1,
            "latest_metrics": {
                "count_only": {"vulnerable:PASS": 8, "audited:FLAG": 1},
                "verdict_only": {"vulnerable:PASS": 0, "audited:FLAG": 5},
                "falsum_consumer": {"vulnerable:PASS": 0, "audited:FLAG": 5},
            },
        },
        "better_than_verdict_baseline": False,
        "live_settlement_verified": False,
    }
    bi = {
        "status": phase5bi.STATUS,
        "baseline": {"reference_instances_displayed": 12,
                      "known_inapplicable_instances_displayed": 2},
        "falsum_gate": {"reference_instances_displayed": 10,
                         "known_inapplicable_instances_displayed": 0},
        "limitations": ["not human AppSec gold", "This artifact does not claim independent developer adoption"],
    }
    bj = {
        "status": phase5bj.STATUS,
        "aggregate": {"reported_reference_count": 66,
                       "source_resolved_reference_count": 38,
                       "source_applicable_reference_count": 27,
                       "source_uncertain_or_unknown_count": 39,
                       "falsum_baseline_disagreement_count": 0},
        "interpretation": {"measurement_improvement_claimed": False,
                           "new_paid_telegraph_execution": False},
    }
    return ar, ak, bi, bj


class MeasurementDiscriminationTests(unittest.TestCase):
    def test_cross_source_report_preserves_contrasts_and_negative_findings(self):
        report = phase5bl.score_reports(*fixtures())
        conclusion = report["measurement_conclusion"]
        self.assertEqual(conclusion["weaker_policy_contrasts_demonstrated"], 2)
        self.assertEqual(conclusion["competent_baseline_ties"], 1)
        self.assertFalse(conclusion["verdict_only_superiority"])
        self.assertEqual(conclusion["independent_human_appsec_gold"], 0)
        self.assertEqual(
            report["fair_comparisons"]["missing_evidence_contrast"]["falsum_review_not_clean"], 3,
        )

    def test_forged_verdict_only_superiority_is_rejected(self):
        ar, ak, bi, bj = fixtures()
        forged = deepcopy(ak)
        forged["summary"]["latest_metrics"]["falsum_consumer"]["vulnerable:PASS"] = 1
        with self.assertRaises(phase5bl.MeasurementDiscriminationError):
            phase5bl.score_reports(ar, forged, bi, bj)

    def test_forged_fresh_baseline_delta_is_rejected(self):
        ar, ak, bi, bj = fixtures()
        forged = deepcopy(bj)
        forged["aggregate"]["falsum_baseline_disagreement_count"] = 1
        with self.assertRaises(phase5bl.MeasurementDiscriminationError):
            phase5bl.score_reports(ar, ak, bi, forged)

    def test_forged_reference_strength_cannot_promote_gold(self):
        ar, ak, bi, bj = fixtures()
        forged = deepcopy(ar)
        forged["summary"]["maintainer_confirmed"] = 9
        with self.assertRaises(phase5bl.MeasurementDiscriminationError):
            phase5bl.score_reports(forged, ak, bi, bj)

    def test_public_report_does_not_contain_raw_or_financial_artifacts(self):
        raw = json.dumps(phase5bl.score_reports(*fixtures()), sort_keys=True).lower()
        self.assertNotIn("private_key", raw)
        self.assertNotIn("response_body", raw)
        self.assertNotIn("receipt", raw)


if __name__ == "__main__":
    unittest.main()
