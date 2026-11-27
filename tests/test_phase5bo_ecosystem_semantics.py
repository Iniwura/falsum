"""Adversarial tests for Phase5BO ecosystem-native semantics."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch
import unittest

from falsum import phase5bo_ecosystem_semantics as m


ROOT = Path(__file__).resolve().parents[1]


def pypi_advisory(events, *, range_type="ECOSYSTEM"):
    return {
        "id": "GHSA-test-test-test",
        "database_specific": {"github_reviewed": True},
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "ranges": [{"type": range_type, "events": events}],
        }],
    }


def npm_advisory(events):
    return {
        "id": "GHSA-test-test-test",
        "database_specific": {"github_reviewed": True},
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo"},
            "ranges": [{"type": "ECOSYSTEM", "events": events}],
        }],
    }


class EcosystemSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (ROOT / m.PROTOCOL).open(encoding="utf-8") as handle:
            cls.protocol = json.load(handle)
        with (ROOT / "data/phase5bo-ecosystem-semantics-result.json").open(encoding="utf-8") as handle:
            cls.result = json.load(handle)

    def test_snapshot_backed_audit_never_reads_live_registry(self):
        with patch.object(m, "_fetch", side_effect=AssertionError("live fetch used during audit")):
            report = m.audit(ROOT)
        self.assertTrue(report["offline_snapshot_only"])
        self.assertEqual(report["registry_snapshot_verification"]["live_registry_reads"], 0)
        self.assertEqual(report["registry_snapshot_verification"]["claimed_versions_verified"], 14)

    def test_legacy_and_prerelease_regressions_are_resolved(self):
        self.assertEqual(self.result["policies"]["improved_candidate"], {
            "correct": 14, "incorrect": 0, "denominator": 14,
        })
        regression_targets = {
            ("PyPI", "pymongo", "0.1pre"),
            ("PyPI", "setuptools", "0.6c11"),
        }
        rows = {(row["target"]["ecosystem"], row["target"]["package"], row["target"]["version"]): row
                for row in self.result["cases"]}
        for target in regression_targets:
            self.assertIn(target, rows)
            self.assertTrue(rows[target]["candidate_correct"])
            self.assertNotEqual(rows[target]["candidate_decision"], m.UNKNOWN)

    def test_additional_unseen_cases_and_claim_actions_are_scored(self):
        self.assertEqual(self.result["coverage"]["additional_unseen_cases"], 12)
        self.assertEqual(self.result["coverage"]["prerelease_cases"], 4)
        self.assertEqual(self.result["policies"]["answer_claim_action_selection"], {
            "correct": 14, "incorrect": 0, "denominator": 14,
        })
        self.assertTrue(self.result["answer_surface_audit"]["selection_by_candidate_claim_and_action"])
        self.assertFalse(self.result["answer_surface_audit"]["reference_label_to_token_mapping_used"])
        for case in self.protocol["cases"]:
            self.assertEqual(len(case["options"]), 3)
            self.assertNotIn("correct_answer_token", case["reference"])
            self.assertEqual({option["claim"]["decision"] for option in case["options"]},
                             {m.APPLICABLE, m.INAPPLICABLE, m.UNKNOWN})

    def test_answer_selection_uses_candidate_claim_not_reference_label(self):
        case = next(case for case in self.protocol["cases"] if case["reference"]["label"] == m.INAPPLICABLE)
        selected = m._select_answer(case["options"], m.APPLICABLE)
        self.assertEqual(selected["claim"]["decision"], m.APPLICABLE)
        self.assertEqual(case["reference"]["label"], m.INAPPLICABLE)

    def test_pypi_disjoint_intervals_and_boundaries(self):
        advisory = pypi_advisory([
            {"introduced": "0"}, {"fixed": "1.0"},
            {"introduced": "2.0"}, {"last_affected": "3.0"},
        ])
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "0.6c11"), m.APPLICABLE)
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "1.5"), m.INAPPLICABLE)
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "2.5"), m.APPLICABLE)
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "3.0"), m.APPLICABLE)
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "3.1"), m.INAPPLICABLE)

    def test_npm_prerelease_interval_is_semver_aware(self):
        advisory = npm_advisory([
            {"introduced": "1.7.2"}, {"fixed": "2.1.2"},
        ])
        self.assertEqual(m._candidate_status(advisory, "npm", "demo", "2.0.0-rc1"), m.APPLICABLE)
        self.assertEqual(m._candidate_status(advisory, "npm", "demo", "2.1.2"), m.INAPPLICABLE)

    def test_unsupported_range_fails_closed(self):
        advisory = pypi_advisory([
            {"introduced": "0"}, {"fixed": "1.0"},
        ], range_type="GIT")
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "0.5"), m.UNKNOWN)
        self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "2.0"), m.UNKNOWN)
        self.assertEqual(m._pypi_reference_status(advisory, "demo", "0.5"), m.UNKNOWN)

    def test_candidate_semantics_do_not_call_reference_resolver(self):
        advisory = pypi_advisory([{ "introduced": "0" }, {"fixed": "1.0"}])
        with patch.object(m, "_reference_status", side_effect=AssertionError("reference used by candidate")):
            self.assertEqual(m._candidate_status(advisory, "PyPI", "demo", "0.5"), m.APPLICABLE)

    def test_snapshot_manifest_has_hashes_for_every_registry_and_advisory(self):
        self.assertEqual(len(self.protocol["registries"]), 6)
        self.assertEqual(len(self.protocol["advisories"]), 6)
        for item in list(self.protocol["registries"].values()) + list(self.protocol["advisories"].values()):
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(item["snapshot"].startswith("data/phase5bo-registry-snapshots/"))


if __name__ == "__main__":
    unittest.main()
