"""Phase 4B fixture tests. Mock source is NOT external verification or model accuracy."""
import copy
import json
import unittest
from unittest.mock import patch

from falsum import phase4b_reference_judge as m
from falsum.phase4a_real_model_probe import CASE_PINS


def synthetic_source():
    packages = {}
    cases = []
    for ident, package, version, ghsa, chosen in CASE_PINS:
        if package not in packages:
            packages[package] = {
                "package": package, "ghsa": ghsa,
                "pinned_advisory_json_sha256": package[0]*64,
                "pinned_advisory_raw_url": "https://raw.githubusercontent.com/pinned/" + ghsa,
                "verified_pypi_releases": [],
            }
        packages[package]["verified_pypi_releases"].append({
            "release": version,
            "not_yanked_at_verification": True,
            "actual_pypi_release_metadata_sha256": version[0]*64,
            "release_url": f"https://pypi.org/pypi/{package}/{version}/json",
        })
        cases.append({
            "case_id": ident, "source_package": package,
            "source_release": version, "advisory": ghsa,
            "mechanically_source_derived_preference": chosen,
        })
    return {"provenance": list(packages.values()), "cases": cases}


class Phase4BReferenceJudgeTests(unittest.TestCase):
    def setUp(self):
        self.source = synthetic_source()
        self.raw = b"EXPLICIT-MOCK-SOURCE-NOT-A-REAL-GHSA"
        self.patched = patch.object(m, "load_source", lambda raw: self.source)
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def test_public_fact_replay_rejects_unsupported_claims(self):
        result = m.run(self.raw)
        self.assertEqual(result["total_claims"], 36)
        self.assertEqual(result["supported"], 6)
        self.assertEqual(result["contradicted"], 6)
        self.assertEqual(result["abstained"], 24)
        self.assertEqual(result["source_derived_fixture_agreement"], 36)
        self.assertEqual(result["source_derived_fixture_count"], 36)
        self.assertTrue(result["not_a_semantic_security_review_model"])
        self.assertTrue(result["not_telegraph_network_adapter"])
        self.assertTrue(result["not_an_independent_or_blind_model_quality_test"])
        self.assertFalse(result["registered_evaluator"])
        self.assertFalse(result["model_training_or_release_authorized"])
        self.assertEqual(result["independent_expert_labels"], 0)
        self.assertEqual(result["network_eligible_rows"], 0)

    def test_contradiction_and_source_specific_fixed_version(self):
        first, patched = self.source["cases"][:2]
        inside = m.claim_for(self.source, first, "IN_NAMED_GHSA_RANGE")
        outside = m.claim_for(self.source, patched, "OUTSIDE_NAMED_GHSA_RANGE")
        self.assertEqual(m.judge(self.source, inside)["verdict"], "SUPPORTED")
        self.assertEqual(m.judge(self.source, outside)["verdict"], "SUPPORTED")
        self.assertEqual(m.judge(self.source, m.claim_for(
            self.source, patched, "IN_NAMED_GHSA_RANGE"))["verdict"], "CONTRADICTED")
        self.assertEqual(m.judge(self.source, m.claim_for(
            self.source, first, "OUTSIDE_NAMED_GHSA_RANGE"))["verdict"], "CONTRADICTED")
        self.assertFalse(m.judge(self.source, outside)["other_vulnerabilities_excluded"])

    def test_missing_or_swapped_primary_evidence_fail_closed(self):
        case = self.source["cases"][0]
        original = m.claim_for(self.source, case, "IN_NAMED_GHSA_RANGE")
        for kind in ("no_advisory", "wrong_release_sha", "wrong_url", "no_evidence"):
            with self.subTest(kind=kind):
                x = copy.deepcopy(original)
                if kind == "no_advisory":
                    x["evidence"].pop("pinned_advisory_sha256")
                elif kind == "wrong_release_sha":
                    x["evidence"]["pypi_release_metadata_sha256"] = "0"*64
                elif kind == "wrong_url":
                    x["evidence"]["pypi_release_url"] = "https://evil.example/test"
                else:
                    x["evidence"] = {}
                verdict = m.judge(self.source, x)
                self.assertEqual(verdict["verdict"], "ABSTAIN")
                self.assertEqual(verdict["reason"], "MISSING_OR_MISMATCHED_PRIMARY_EVIDENCE")

    def test_other_ghsa_unseen_version_and_production_overclaim_abstain(self):
        case = self.source["cases"][2]
        for kind in ("unknown GHSA", "new version", "exploit", "safe", "freeform"):
            with self.subTest(kind=kind):
                claim = m.claim_for(self.source, case, "IN_NAMED_GHSA_RANGE")
                if kind == "unknown GHSA":
                    claim["advisory"] = "GHSA-0000-0000-0000"
                if kind == "new version":
                    claim["version"] = "99.99.99"
                if kind == "exploit":
                    claim["claim_type"] = "CONFIRMED_PRODUCTION_EXPLOIT"
                if kind == "safe":
                    claim["claim_type"] = "GUARANTEED_APPLICATION_SAFE"
                if kind == "freeform":
                    claim["claim_type"] = "this application is definitely exploited"
                verdict = m.judge(self.source, claim)
                self.assertEqual(verdict["verdict"], "ABSTAIN")
                self.assertFalse(verdict["deployment_exploitability_assessed"])
                self.assertFalse(verdict["registered_evaluator"])

    def test_invalid_fields_and_incoherent_source_fail_closed(self):
        base = m.claim_for(self.source, self.source["cases"][0], "IN_NAMED_GHSA_RANGE")
        for kind in ("injected", "missing_evidence", "not_object", "bad_identifier"):
            x = copy.deepcopy(base)
            if kind == "injected":
                x["registered"] = True
            if kind == "missing_evidence":
                del x["evidence"]
            if kind == "not_object":
                x["evidence"] = 42
            if kind == "bad_identifier":
                x["package"] = ""
            with self.subTest(kind=kind), self.assertRaises(m.ReferenceJudgeError):
                m.judge(self.source, x)
        corrupted = copy.deepcopy(self.source)
        corrupted["provenance"][0]["verified_pypi_releases"].pop()
        with self.assertRaises(m.ReferenceJudgeError):
            m.lookup(corrupted)
        duplicated = copy.deepcopy(self.source)
        duplicated["cases"][1]["source_release"] = duplicated["cases"][0]["source_release"]
        with self.assertRaises(m.ReferenceJudgeError):
            m.lookup(duplicated)

    def test_no_fake_quality_approval_from_model_comparison(self):
        fake_baseline = {"observed_matches":3, "complete_version_reversals":0,
                         "actual_score_bits":12}
        with patch.object(m, "check_old_model", lambda record: fake_baseline):
            r = m.run(self.raw, old_model={"explicit":"synthetic-test"})
        self.assertEqual(r["historical_old_model"]["verified_source_fact_matches"], 3)
        self.assertFalse(r["historical_old_model"]["model_release_authorized"])
        self.assertTrue(r["historical_old_model"]["not_an_improved_trained_model"])
        self.assertTrue(r["historical_old_model"]["not_comparable_to_abstention_stress_tests"])

    def test_cannot_claim_fixture_success_on_different_or_forged_expected_verdict(self):
        examples = m.build_stress_suite(self.source)
        examples[0]["expected"] = "CONTRADICTED"
        with self.assertRaises(m.ReferenceJudgeError):
            m.run(self.raw, claims=examples)
        duplicates = m.build_stress_suite(self.source)[:2]
        duplicates[1]["test_id"] = duplicates[0]["test_id"]
        with self.assertRaises(m.ReferenceJudgeError):
            m.run(self.raw, claims=duplicates)
        with self.assertRaises(m.ReferenceJudgeError):
            m.run(self.raw, claims=examples*4)

    def test_custom_requests_do_not_get_false_gold_labels(self):
        case = self.source["cases"][0]
        result = m.run(self.raw, claims=[{
            "test_id": "user-case",
            "claim": m.claim_for(self.source, case, "OUTSIDE_NAMED_GHSA_RANGE"),
        }])
        self.assertEqual(result["contradicted"], 1)
        self.assertEqual(result["source_derived_fixture_count"], 0)
        self.assertEqual(result["source_derived_fixture_agreement"], 0)


if __name__ == "__main__":
    unittest.main()
