"""Adversarial regression tests for the corrected Phase 5BN holdout."""
from __future__ import annotations

from copy import deepcopy
import inspect
import json
from pathlib import Path
from unittest.mock import patch
import unittest

from falsum import phase5bn_corrected_independent_holdout as m


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / m.PROTOCOL
RESULT_PATH = ROOT / "data/phase5bn-corrected-independent-holdout-result.json"


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class CorrectedIndependentHoldoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol = read_json(PROTOCOL_PATH)
        cls.result = read_json(RESULT_PATH)

    def test_protocol_is_separate_from_phase5bm_and_uses_external_labels(self):
        self.assertEqual(self.protocol["schema_version"], 2)
        self.assertEqual(self.protocol["status"], m.FROZEN_STATUS)
        self.assertTrue(self.protocol["selection"]["layout_seed_selected_without_reference_labels"])
        self.assertEqual(self.protocol["dataset"]["external_resolvers"], {
            "PyPI": "packaging==26.4", "npm": "semver@7.8.6",
        })
        self.assertNotIn("candidate_status", inspect.getsource(m._build_protocol))

    def test_reference_stage_has_no_candidate_dependency(self):
        protocol = {
            "records": [{"id": "GHSA-test", "ecosystem": "PyPI", "package": "pkg"}],
            "cases": [{
                "case_id": "case", "advisory_id": "GHSA-test",
                "target": {"version": "1.0.0"},
                "reference": {"label": m.APPLICABLE},
            }],
        }
        source = {"id": "GHSA-test"}
        with patch.object(m, "_external_statuses", return_value=[m.APPLICABLE]), \
                patch.object(m, "candidate_status", side_effect=AssertionError("candidate called")):
            labels = m._reference_stage(protocol, {"GHSA-test": source})
        self.assertEqual(labels, {"case": m.APPLICABLE})

    def test_audit_executes_reference_stage_before_candidate(self):
        events = []
        sources = {record["id"]: {} for record in self.protocol["records"]}

        def reference_stage(protocol, _sources):
            events.append("reference")
            return {case["case_id"]: case["reference"]["label"] for case in protocol["cases"]}

        def candidate(_advisory, _target):
            events.append("candidate")
            return m.APPLICABLE

        with patch.object(m, "_load_protocol", return_value=self.protocol), \
                patch.object(m, "_load_sources_and_metadata", return_value=(sources, {})), \
                patch.object(m, "_load_external_libraries", return_value=(None, None, None)), \
                patch.object(m, "_reference_stage", side_effect=reference_stage), \
                patch.object(m, "candidate_status", side_effect=candidate):
            report = m.audit()
        self.assertTrue(report["reference_stage_completed_before_candidate"])
        self.assertEqual(events[0], "reference")
        self.assertIn("candidate", events[1:])

    def test_index_and_answer_token_leakage_are_computed_adversarially(self):
        clean = deepcopy(self.protocol["cases"])
        clean_audit = m._leakage_audit(clean)
        self.assertFalse(clean_audit["label_leakage_detected"])
        self.assertEqual(set(clean_audit["metrics"]), {
            "case_index_parity", "case_index_mod_3", "answer_position", "answer_token",
        })

        index_forgery = deepcopy(clean)
        for case in index_forgery:
            case["reference"]["label"] = (
                m.APPLICABLE if case["case_index"] % 2 == 0 else m.INAPPLICABLE
            )
        self.assertTrue(m._leakage_audit(index_forgery)["label_leakage_detected"])

        token_forgery = deepcopy(clean)
        for case in token_forgery:
            case["reference"]["label"] = (
                m.APPLICABLE if case["reference"]["correct_answer_token"] == "ref-rhea"
                else m.INAPPLICABLE
            )
        self.assertTrue(m._leakage_audit(token_forgery)["label_leakage_detected"])

    def test_meaningful_competing_answers_are_not_placeholder_surfaces(self):
        audit = self.result["answer_surface_audit"]
        self.assertTrue(audit["meaningful_competing_answers"])
        self.assertFalse(audit["placeholder_a_or_b_only"])
        self.assertGreaterEqual(audit["minimum_option_text_length"], 120)
        self.assertEqual(audit["distinct_option_texts"], 48)
        for case in self.protocol["cases"]:
            self.assertNotEqual(case["options"][0]["text"], case["options"][1]["text"])
            for option in case["options"]:
                self.assertIn(case["target"]["package"], option["text"])
                self.assertIn(option["action"], {"block_or_upgrade", "no_action_for_this_record"})
                self.assertEqual(option["scope"], "version_applicability_only")

    def test_external_resolver_is_competent_additional_baseline(self):
        self.assertEqual(self.result["policies"]["external_resolver_reference"], {
            "correct": 24, "incorrect": 0, "denominator": 24,
        })
        self.assertFalse(self.result["interpretation"]["falsum_beats_external_resolver"])
        for record in self.protocol["records"]:
            self.assertRegex(record["metadata_sha256"], r"^[0-9a-f]{64}$")
        for record in self.protocol["records"]:
            self.assertEqual(len(record["verified_versions"]), 2)
            self.assertTrue(all(isinstance(version, str) and version for version in record["verified_versions"]))

    def test_unrelated_registry_release_does_not_invalidate_frozen_pair(self):
        record = {
            "ecosystem": "npm",
            "package": "tar",
            "verified_versions": ["7.5.18", "7.5.19"],
            "metadata_sha256": "a" * 64,
        }
        current = {
            "versions": {
                "7.5.18": {"name": "tar", "version": "7.5.18"},
                "7.5.19": {"name": "tar", "version": "7.5.19"},
                "7.5.20": {"name": "tar", "version": "7.5.20"},
            }
        }
        current["name"] = "tar"
        self.assertIsNone(m._verify_frozen_versions_present(record, current))

        wrong_package = dict(current, name="not-tar")
        with self.assertRaisesRegex(m.CorrectedHoldoutError, "package identity changed"):
            m._verify_frozen_versions_present(record, wrong_package)

        missing_frozen = {"name": "tar", "versions": {"7.5.18": {}, "7.5.20": {}}}
        with self.assertRaisesRegex(m.CorrectedHoldoutError, "no longer exists: tar@7.5.19"):
            m._verify_frozen_versions_present(record, missing_frozen)

    def test_malformed_registry_version_map_fails_closed(self):
        record = {
            "ecosystem": "PyPI", "package": "sample",
            "verified_versions": ["1.0", "1.1"], "metadata_sha256": "b" * 64,
        }
        with self.assertRaisesRegex(m.CorrectedHoldoutError, "no releases map"):
            m._verify_frozen_versions_present(record, {"info": {"name": "sample"}, "releases": []})

    def test_wrong_pypi_package_identity_fails_closed(self):
        record = {
            "ecosystem": "PyPI", "package": "sample",
            "verified_versions": ["1.0", "1.1"], "metadata_sha256": "b" * 64,
        }
        metadata = {"info": {"name": "other"}, "releases": {"1.0": [], "1.1": []}}
        with self.assertRaisesRegex(m.CorrectedHoldoutError, "package identity changed"):
            m._verify_frozen_versions_present(record, metadata)

    def test_corrected_discrimination_preserves_negative_result(self):
        self.assertEqual(self.result["policies"]["falsum"], {
            "correct": 22, "incorrect": 2, "denominator": 24,
        })
        self.assertTrue(self.result["interpretation"]["meaningful_quality_discrimination"])
        self.assertFalse(self.result["interpretation"]["independent_human_appsec_gold"])
        self.assertFalse(self.result["interpretation"]["new_paid_telegraph_execution"])


if __name__ == "__main__":
    unittest.main()
