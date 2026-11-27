"""Adversarial tests for the independent balanced holdout."""
from __future__ import annotations

from copy import deepcopy
import unittest

from falsum import phase5bm_independent_balanced_holdout as m


def advisory(identifier: str, package: str, ecosystem: str):
    return {
        "id": identifier,
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": package},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        }],
        "database_specific": {"github_reviewed": True},
    }


def synthetic_sources():
    return {identifier: advisory(identifier, package, ecosystem)
            for identifier, (ecosystem, package, _path, _digest) in m.RECORDS.items()}


class IndependentBalancedHoldoutTests(unittest.TestCase):
    def test_frozen_protocol_and_roster_are_new_and_balanced(self):
        protocol = m.frozen_protocol()
        self.assertEqual(protocol["status"], "PHASE5BM_INDEPENDENT_BALANCED_HOLDOUT_FROZEN")
        self.assertEqual(len(protocol["records"]), 12)
        self.assertIn("12 applicable", protocol["selection"]["balance"])
        self.assertEqual(len(set(m.RECORDS)), 12)

    def test_shortcut_audited_result_is_not_label_or_order_dependent(self):
        report = m.score_documents(synthetic_sources())
        self.assertEqual(report["balance"], {
            "total": 24, "applicable": 12, "inapplicable": 12,
            "package_families": 6, "ecosystems": {"PyPI": 12, "npm": 12},
        })
        self.assertEqual(report["shortcut_audit"]["correct_side_counts"], {"left": 12, "right": 12})
        self.assertTrue(report["shortcut_audit"]["equal_answer_length"])
        self.assertFalse(report["shortcut_audit"]["label_leakage_detected"])

    def test_competent_baseline_is_independent_and_citation_only_is_weaker(self):
        report = m.score_documents(synthetic_sources())
        self.assertEqual(report["policies"]["falsum"]["correct"], 24)
        self.assertEqual(report["policies"]["independent_interval"]["correct"], 24)
        self.assertEqual(report["policies"]["citation_only"]["correct"], 12)
        self.assertFalse(report["interpretation"]["falsum_beats_competent_baseline"])
        self.assertEqual(report["pairwise_discrimination"]["falsum_vs_citation_only"]["falsum_wins"], 12)

    def test_competent_baseline_does_not_call_falsum_parsing_helpers(self):
        source = synthetic_sources()[next(iter(m.RECORDS))]
        target = {"ecosystem": "PyPI", "package": "pymongo", "version": "1.0.0"}
        original = (m._numbers, m._compare, m._matching_ranges)
        try:
            m._numbers = lambda _value: (_ for _ in ()).throw(AssertionError("shared parser used"))
            m._compare = lambda _left, _right: (_ for _ in ()).throw(AssertionError("shared comparator used"))
            m._matching_ranges = lambda _advisory, _ecosystem, _package: (_ for _ in ()).throw(AssertionError("shared matcher used"))
            self.assertEqual(m.independent_interval_status(source, target), m.APPLICABLE)
        finally:
            m._numbers, m._compare, m._matching_ranges = original

    def test_unsupported_and_withdrawn_evidence_fail_closed(self):
        target = {"ecosystem": "npm", "package": "pkg", "version": "2.0.0"}
        unsupported = advisory("GHSA-test-test-test", "pkg", "npm")
        unsupported["affected"][0]["ranges"][0]["events"][1]["fixed"] = "2.0.0-beta1"
        self.assertEqual(m.falsum_status(unsupported, target), m.UNKNOWN)
        withdrawn = advisory("GHSA-test-test-test", "pkg", "npm")
        withdrawn["withdrawn"] = "2026-01-01T00:00:00Z"
        self.assertEqual(m.falsum_status(withdrawn, target), m.UNKNOWN)

    def test_tampered_target_cannot_be_promoted(self):
        forged = deepcopy(synthetic_sources())
        identifier = next(iter(forged))
        forged[identifier]["affected"][0]["package"]["name"] = "other"
        with self.assertRaises(m.BalancedHoldoutError):
            m.score_documents(forged)


if __name__ == "__main__":
    unittest.main()
