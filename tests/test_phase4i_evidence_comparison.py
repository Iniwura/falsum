"""Phase 4I: source-and-model-bound comparison and standalone web build."""
import json
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase4i_evidence_comparison import (
    ROOT, LOCK, LEDGER, TEMPLATE, report, render, write, ComparisonError, STATUS,
)
from falsum.phase4c_release import build


class ComparisonEvidenceTests(unittest.TestCase):
    def test_exact_actual_model_and_source_baselines(self):
        d=report()
        self.assertEqual(d["status"],STATUS)
        self.assertTrue(d["real_official_foundation_score_recording"])
        self.assertTrue(d["original_quarantined_lora"])
        self.assertFalse(d["current_live_inference"])
        self.assertFalse(d["model_trained_or_improved_in_phase4i"])
        self.assertFalse(d["model_registered"])
        self.assertFalse(d["training_allowed"])
        self.assertEqual(d["independent_expert_gold_labels"],0)
        self.assertEqual(d["network_eligible_rows_created"],0)
        self.assertFalse(d["model_quality_improvement_established"])
        self.assertEqual(d["case_count"],8)
        self.assertEqual(d["project_count"],4)
        self.assertEqual(d["model_f32_inputs"],16)
        self.assertEqual(d["genuine_repeated_inferences"],32)
        self.assertEqual(d["model_source_author_matches"],5)
        self.assertEqual(d["model_complete_reversals"],1)
        self.assertEqual(d["model_preference_changes"],1)
        self.assertEqual(d["constant_A_matches"],4)
        self.assertEqual(d["constant_B_matches"],4)
        self.assertEqual(d["content_invariant_rule_max_possible_matches"],4)
        self.assertEqual(d["source_aware_oracle_author_agreement"],8)
        self.assertTrue(d["source_aware_oracle_is_hardcoded_from_author_hypotheses"])
        self.assertEqual(d["source_test_files_unchanged_by_fix"],2)
        self.assertEqual([g["id"] for g in d["groups"]],
                         ["pyjwt","werkzeug","mcp-python","pillow"])
        self.assertEqual([g["complete_source_consistent_reversal"] for g in d["groups"]],
                         [True,False,False,False])

    def test_stable_answer_texts_per_revision_and_exact_model_bits(self):
        d=report()
        for g in d["groups"]:
            self.assertEqual(len(g["revisions"]),2)
            a,b=g["revisions"]
            self.assertEqual([a["source_expected_author_only"],b["source_expected_author_only"]],
                             ["A","B"])
            self.assertEqual([a["revision"],b["revision"]],["parent","fixed"])
            self.assertNotEqual(a["source_anchor"],b["source_anchor"])
            for rev in (a,b):
                self.assertTrue(rev["source_url"].startswith("https://github.com/"))
                self.assertTrue(rev["test_url"].startswith("https://github.com/"))
                self.assertEqual(len(rev["score_a_f32"]),10)
                self.assertEqual(len(rev["score_b_f32"]),10)
                self.assertTrue(rev["source_expected_author_only"] in ("A","B"))
                self.assertIsNone(rev["independent_gold_label"])
            self.assertNotEqual(g["answer_a"],g["answer_b"])
        self.assertFalse(d["groups"][1]["chosen_test_file_changed_by_fix"])
        self.assertFalse(d["groups"][3]["chosen_test_file_changed_by_fix"])

    def test_markup_escapes_script_termination_and_remains_offline(self):
        d=report()
        template=TEMPLATE.read_text(encoding="utf-8")
        markup=render(d,template)
        self.assertEqual(markup.count('id="comparison-data"'),1)
        self.assertNotIn("__FALSUM_PHASE4I_DATA__",markup)
        for anchor in ("THE CODE","DID THE MODEL?","5/8","1/4","4/8","16",
                       'data-case="3"','data-revision="1"','id="case-question"',
                       'id="score-a"','id="score-b"','id="source-link"',
                       'id="advisory-link"','id="model-answer"','id="source-answer"',
                       'prefers-reduced-motion','max-width:360px',
                       'NO VERIFIED EXPERT GOLD','not a sealed pretraining holdout'):
            self.assertIn(anchor.lower(),markup.lower())
        self.assertNotIn("fetch(",markup)
        self.assertNotIn("https://cdn.",markup)
        changed=json.loads(json.dumps(d))
        changed["groups"][0]["answer_a"]="</script><script>alert(7)</script>"
        escaped=render(changed,template)
        self.assertNotIn("</script><script>alert(7)",escaped)
        self.assertIn("\\u003c/script\\u003e",escaped)

    def test_release_rejects_changed_model_score_and_frozen_source(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for relative in (LOCK.relative_to(ROOT),LEDGER.relative_to(ROOT)):
                target=root/relative
                target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/relative,target)
            self.assertEqual(report(root)["model_source_author_matches"],5)
            target=root/LEDGER.relative_to(ROOT)
            forged=json.loads(target.read_text())
            forged["score_hex_by_input"]["pyjwt-parent--A"]="0x00000000"
            target.write_text(json.dumps(forged))
            with self.assertRaises(ValueError):
                report(root)
            shutil.copyfile(ROOT/LEDGER.relative_to(ROOT),target)
            target=root/LOCK.relative_to(ROOT)
            forged=json.loads(target.read_text())
            forged["cases"][0]["question_before"]="tampered"
            target.write_text(json.dumps(forged))
            with self.assertRaises(ValueError):
                report(root)

    def test_real_static_release_adds_third_route_without_network(self):
        with tempfile.TemporaryDirectory() as td:
            destination=Path(td)/"release"
            with patch.object(socket.socket,"connect",side_effect=AssertionError("network in build")):
                summary=build(destination)
            self.assertEqual(summary["phase4i_model_fact_matches"],5)
            self.assertEqual(summary["phase4i_model_complete_reversals"],1)
            self.assertEqual(summary["phase4i_frozen_source_conditions"],8)
            self.assertTrue((destination/"index.html").is_file())
            self.assertTrue((destination/"proof/index.html").is_file())
            self.assertTrue((destination/"compare/index.html").is_file())
            body=(destination/"compare/index.html").read_text()
            self.assertIn('aria-label="Choose source project"',body)
            self.assertIn('href="/proof/"',body)
            self.assertIn('href="/compare/"',(destination/"index.html").read_text())
            self.assertIn('href="/compare/"',(destination/"proof/index.html").read_text())
            d=json.loads((destination/"compare/ACTUAL-PHASE4H-FROZEN-SOURCE-MODEL-COMPARISON.json").read_text())
            self.assertEqual(d["model_source_author_matches"],5)
            self.assertEqual(d["independent_expert_gold_labels"],0)
            with self.assertRaisesRegex(ValueError,"refuse to overwrite"):
                write(destination/"compare")


if __name__=="__main__":
    unittest.main()
