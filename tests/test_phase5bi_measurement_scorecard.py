"""Adversarial contract tests for the bounded Phase 5BI measurement artifact.

The dictionaries below are constructed policy fixtures.  They validate that
the scorecard cannot silently turn caller-supplied labels into gold, change a
baseline denominator, or promote adoption/ranking claims.  The live source
evidence is produced only by the Phase 5Y/5Z source-verifying studies and CI.
"""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from falsum import phase5bi_measurement_scorecard as m


APPLICABLE = [
    "GHSA-29mw-wpgm-hmr9", "GHSA-35jh-r3h4-6jhm", "GHSA-p6mc-m468-83gw",
    "GHSA-r5fr-rjxr-66jc", "GHSA-xxjr-mmjv-4gpg",
]


def phase5y_fixture() -> dict:
    rows = []
    for miner in ("190048", "77010"):
        for ghsa in APPLICABLE + [m.BAD_GHSA]:
            applies = ghsa != m.BAD_GHSA
            rows.append({
                "original_reported_miner_id": miner,
                "independent_reviewed_ghsa_id": ghsa,
                "reviewed_reference_package_version_applicable": applies,
                "application_gate_action": (
                    "DISPLAY_VERSION_APPLICABLE_UNVERIFIED_REFERENCE" if applies
                    else "REJECT_VERSION_INAPPLICABLE_REFERENCE"
                ),
                "target": m.TARGET,
                "independent_provider_ownership_verified": False,
                "reference_is_separately_maintained_not_expert_gold": True,
            })
    return {
        "schema_version": 1,
        "status": "PHASE5Y_AUTHENTIC_REVIEWED_ADVISORY_VERSION_APPLICABILITY_ON_TWO_ORIGINAL_PAID_MINER_CAPTURES",
        "target": m.TARGET,
        "independent_reviewed_original_source_repo": "github/advisory-database",
        "independent_reviewed_original_git_revision": "76955defc62d048f8f7cc68bc39a2f6dd1899ebe",
        "original_third_party_provider_capture_repo": "anvithagowda098/pr-guard",
        "original_external_provider_capture_git_revision": "99d2e3c93890a8fc083947bde4f21217516b7a5f",
        "original_reported_advisory_references": 12,
        "independent_reviewed_version_applicable_references": 10,
        "independent_reviewed_version_inapplicable_references": 2,
        "naive_http_200_paid_accepted_all_references": 12,
        "evidence_bound_gate_allowed_reference_display_only": 10,
        "evidence_bound_gate_denied_version_inapplicable_references": 2,
        "distinct_version_inapplicable_ghsa_ids": [m.BAD_GHSA],
        "independent_human_appsec_gold": 0,
        "advisory_recall_or_completeness_proven": False,
        "registered_network_evaluator": False,
        "falsum_adopted_by_third_party": False,
        "original_provider_reference_decisions": rows,
    }


def phase5z_fixture() -> dict:
    def direct(miner: str) -> dict:
        visible = [{"verified_ghsa_id": ghsa} for ghsa in APPLICABLE]
        return {
            "action": "DISPLAY_REVIEWED_VERSION_APPLICABLE_REFERENCES_ONLY",
            "display_count": 5,
            "suppressed_count": 1,
            "display_references": visible,
            "suppressed_references": [{"verified_ghsa_id": m.BAD_GHSA}],
        }

    return {
        "schema_version": 1,
        "status": "PHASE5Z_ORIGINAL_THREE_MINER_SAFE_REFERENCE_CONSUMPTION",
        "original_external_git_authenticated_miner_captures": 3,
        "original_reviewed_advisory_git_verified_sources": 6,
        "original_direct_provider_references": 12,
        "original_reviewed_version_applicable_display_only_references": 10,
        "original_version_inapplicable_suppressed_references": 2,
        "original_distinct_advisories_with_version_false_positive": 1,
        "original_miner_ownership_independently_verified": False,
        "independent_paid_settlement_verified": False,
        "independent_appsec_gold": 0,
        "full_advisory_recall_measured": False,
        "network_evaluator_registered": False,
        "external_adoption_proven": False,
        "public_original_source_decisions": [
            {"reported_original_miner_id": "77003",
             "display_only_security_reference_decision": {
                 "action": "DENY_UNVERIFIED_OR_UNSCOPED_ADVICE",
                 "display_count": 0, "suppressed_count": 0}},
            {"reported_original_miner_id": "190048",
             "display_only_security_reference_decision": direct("190048")},
            {"reported_original_miner_id": "77010",
             "display_only_security_reference_decision": direct("77010")},
        ],
    }


class MeasurementScorecardContract(unittest.TestCase):
    def setUp(self):
        self.y = phase5y_fixture()
        self.z = phase5z_fixture()

    def test_scorecard_reports_bounded_measured_improvement(self):
        report = m.score_reports(self.y, self.z)
        self.assertEqual(report["status"], m.STATUS)
        self.assertEqual(report["baseline"]["known_false_positive_rate"], "2/12")
        self.assertEqual(report["falsum_gate"]["known_false_positive_rate"], "0/10")
        self.assertEqual(report["falsum_gate"]["reviewed_reference_precision_within_frozen_roster"], "10/10")
        self.assertEqual(report["observed_improvement"]["known_false_positives_removed"], 2)
        self.assertEqual(report["observed_improvement"]["relative_known_false_positive_reduction_percent"], 100)
        self.assertTrue(report["observed_improvement"]["same_result_reproduced_by_phase5y_and_phase5z"])
        self.assertFalse(report["evaluator_contribution"]["registered_network_evaluator"])
        self.assertFalse(report["evaluator_contribution"]["independent_customer_adoption"])
        self.assertFalse(report["evaluator_contribution"]["full_advisory_recall"])

    def test_caller_supplied_applicability_label_cannot_change_measurement(self):
        forged = deepcopy(self.y)
        forged["original_provider_reference_decisions"][0][
            "reviewed_reference_package_version_applicable"] = False
        forged["original_provider_reference_decisions"][0][
            "application_gate_action"] = "REJECT_VERSION_INAPPLICABLE_REFERENCE"
        with self.assertRaises(m.MeasurementScorecardError):
            m.score_reports(forged, self.z)

    def test_caller_cannot_change_accept_all_denominator(self):
        forged = deepcopy(self.y)
        forged["naive_http_200_paid_accepted_all_references"] = 10
        with self.assertRaises(m.MeasurementScorecardError):
            m.score_reports(forged, self.z)

    def test_duplicate_provider_reference_row_is_rejected(self):
        forged = deepcopy(self.y)
        forged["original_provider_reference_decisions"].append(
            deepcopy(forged["original_provider_reference_decisions"][0]))
        with self.assertRaises(m.MeasurementScorecardError):
            m.score_reports(forged, self.z)

    def test_tampered_application_manifest_is_rejected(self):
        forged = deepcopy(self.z)
        forged["public_original_source_decisions"][1][
            "display_only_security_reference_decision"]["display_references"].append(
                {"verified_ghsa_id": m.BAD_GHSA})
        with self.assertRaises(m.MeasurementScorecardError):
            m.score_reports(self.y, forged)

    def test_adoption_and_gold_claims_are_never_derived_from_caller_flags(self):
        for key in ("falsum_adopted_by_third_party", "registered_network_evaluator"):
            forged = deepcopy(self.y)
            forged[key] = True
            with self.subTest(key=key):
                with self.assertRaises(m.MeasurementScorecardError):
                    m.score_reports(forged, self.z)
        forged = deepcopy(self.z)
        forged["external_adoption_proven"] = True
        with self.assertRaises(m.MeasurementScorecardError):
            m.score_reports(self.y, forged)

    def test_output_does_not_republish_provider_response_body(self):
        encoded = json.dumps(m.score_reports(self.y, self.z), sort_keys=True)
        self.assertNotIn('"result"', encoded)
        self.assertNotIn('"payment"', encoded)
        self.assertNotIn('"receipt"', encoded)


if __name__ == "__main__":
    unittest.main()
