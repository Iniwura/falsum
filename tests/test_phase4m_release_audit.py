"""Phase 4M: adversarial release-copy and bit-exact old-model evidence gates.

Synthetic mutations here are intentionally NOT external expert adjudications.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase4m_release_audit as gate


class H2SubmissionIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = {p: (gate.ROOT / p).read_text(encoding="utf-8")
                    for p in gate.DOCUMENTS}

    def modified(self, path, old, new):
        altered = dict(self.base)
        self.assertIn(old, altered[path], "mutation anchor missing in public document")
        altered[path] = altered[path].replace(old, new)
        return altered

    def test_real_public_docs_allow_no_fabricated_submission_status(self):
        check = gate.inspect_public_docs(self.base, gate.ROOT)
        self.assertTrue(check["solo_builder_public_copy"])
        self.assertTrue(check["official_entry_not_falsely_marked_submitted"])
        self.assertTrue(check["historical_20_ui_vs_zero_live_node_discrepancy_disclosed"])
        self.assertGreater(check["local_document_links_verified"], 10)

    def test_rejects_fabricated_submitted_entry(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "**STATUS: NOT SUBMITTED.**",
                             "**STATUS: SUBMITTED.**")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "not-submitted"):
            gate.inspect_public_docs(docs)

    def test_rejects_plural_authorship_in_h2_entry(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "I uploaded 20", "We uploaded 20")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "collective"):
            gate.inspect_public_docs(docs)

    def test_rejects_plural_authorship_in_readme(self):
        docs = self.modified("README.md",
                             "The failing research checkpoints remain quarantined.",
                             "We keep the failing research checkpoints quarantined.")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "collective"):
            gate.inspect_public_docs(docs)

    def test_rejects_plural_authorship_in_judge_guide(self):
        docs = self.modified("docs/H2_EVALUATORS_JUDGE_PACK.md",
                             "Solo-builder target:", "Our target:")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "collective"):
            gate.inspect_public_docs(docs)

    def test_rejects_removed_live_zero_record_discrepancy(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "zero rows", "unknown result")
        docs["docs/H2_FINAL_ENTRY_DRAFT.md"] = docs[
            "docs/H2_FINAL_ENTRY_DRAFT.md"].replace("zero records", "unknown records")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "zero-row"):
            gate.inspect_public_docs(docs)

    def test_rejects_outdated_nov17_internal_target(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "Sunday, November 22", "Tuesday, November 17")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "target"):
            gate.inspect_public_docs(docs)

    def test_rejects_unexplained_historical_eligible_claim(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "unresolved", "approved")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "discrepancy"):
            gate.inspect_public_docs(docs)

    def test_rejects_model_baseline_erasure(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "4/8 constant-choice controls", "unbeatable new model")
        docs["docs/H2_FINAL_ENTRY_DRAFT.md"] = docs[
            "docs/H2_FINAL_ENTRY_DRAFT.md"].replace("4/8**", "99/99**")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "baseline"):
            gate.inspect_public_docs(docs)

    def test_rejects_external_comparison_disappearing(self):
        docs = self.modified("docs/H2_FINAL_ENTRY_DRAFT.md",
                             "**17 November program audit:**", "**Review:**")
        docs["docs/H2_FINAL_ENTRY_DRAFT.md"] = docs[
            "docs/H2_FINAL_ENTRY_DRAFT.md"].replace("Phase 4L", "Phase X")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "PR Guard"):
            gate.inspect_public_docs(docs)

    def test_rejects_broken_relative_file_link(self):
        docs = self.modified("README.md",
                             "(docs/PHASE4I_JUDGE_COMPARISON.md)",
                             "(docs/NO_SUCH_SOURCE_PROOF.md)")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "broken"):
            gate.inspect_public_docs(docs, gate.ROOT)

    def test_rejects_relative_link_traversal(self):
        docs = self.modified("README.md",
                             "(docs/PHASE4I_JUDGE_COMPARISON.md)",
                             "(../../../../etc/passwd)")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "unsafe"):
            gate.inspect_public_docs(docs, gate.ROOT)

    def test_rejects_document_missing_from_release(self):
        docs = dict(self.base)
        docs.pop("README.md")
        with self.assertRaisesRegex(gate.ReleaseAuditError, "document"):
            gate.inspect_public_docs(docs)

    def test_source_model_recorded_bits_are_immutable_and_original(self):
        report = gate.run()
        self.assertEqual(report["status"], gate.STATUS)
        self.assertEqual(report["methodology_verified"]["frozen_real_original_model_bits"], 16)
        self.assertEqual(report["methodology_verified"]["researcher_interpreted_source_matches"], 5)
        self.assertEqual(report["methodology_verified"]["complete_correct_parent_to_fix_reversals"], 1)
        self.assertFalse(report["methodology_verified"]["new_model_or_adapter"])
        self.assertFalse(report["methodology_verified"]["quality_improvement_proven"])
        self.assertFalse(report["released_ready"])
        self.assertEqual(report["methodology_verified"]["expert_independent_gold_labels"], 0)
        self.assertGreater(len(report["qualification_blockers_still_unverified"]), 0)

    def test_cannot_silently_change_research_model_score_to_perfect(self):
        original = gate.real_source_comparison()
        changed = copy.deepcopy(original)
        changed["model_source_author_matches"] = 8
        with patch.object(gate, "real_source_comparison", return_value=changed):
            with self.assertRaisesRegex(gate.ReleaseAuditError, "evidence drift"):
                gate.run()

    def test_cannot_promote_independent_expert_gold_without_evidence(self):
        original = gate.real_source_comparison()
        changed = copy.deepcopy(original)
        changed["independent_expert_gold_labels"] = 2
        with patch.object(gate, "real_source_comparison", return_value=changed):
            with self.assertRaisesRegex(gate.ReleaseAuditError, "evidence drift"):
                gate.run()

    def test_cannot_silently_claim_registered_adapter(self):
        original = gate.real_source_comparison()
        changed = copy.deepcopy(original)
        changed["model_registered"] = True
        with patch.object(gate, "real_source_comparison", return_value=changed):
            with self.assertRaisesRegex(gate.ReleaseAuditError, "evidence drift"):
                gate.run()

    def test_cannot_change_a_single_model_reversal_after_aggregation(self):
        original = gate.real_source_comparison()
        changed = copy.deepcopy(original)
        changed["groups"][0]["complete_source_consistent_reversal"] = False
        with patch.object(gate, "real_source_comparison", return_value=changed):
            with self.assertRaisesRegex(gate.ReleaseAuditError, "per-source"):
                gate.run()

    def test_diagnostic_cli_success_is_not_submission_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "phase4m-audit.json"
            self.assertEqual(gate.main(["--out", str(path)]), 0)
            report = json.loads(path.read_text())
            self.assertFalse(report["released_ready"])
            self.assertEqual(report["methodology_verified"]["expert_independent_gold_labels"], 0)
            with self.assertRaises(SystemExit):
                gate.main(["--out", str(path)])


if __name__ == "__main__":
    unittest.main()
