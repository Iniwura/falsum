"""Final release: authentic score-bit page, source provenance and safe build tests."""
import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.phase4c_judge_proof import (
    read_validated, render, write, JudgeProofError, STATUS, ROOT, TEMPLATE,
)
from falsum.phase4c_release import build


class Phase4CJudgeReleaseTests(unittest.TestCase):
    def test_verifiable_real_model_proof_has_exact_supported_measurement_limits(self):
        report=read_validated()
        self.assertEqual(report["status"], STATUS)
        self.assertEqual(report["real_model_score_inputs"], 12)
        self.assertEqual(report["real_repeated_foundation_inferences"], 24)
        self.assertEqual(report["model_matches_narrow_source_facts"], 3)
        self.assertEqual(report["model_matches_total"], 6)
        self.assertEqual(report["complete_factual_reversals"], 0)
        self.assertEqual(report["reversal_groups_total"], 3)
        self.assertEqual(report["constant_A_baseline"], 3)
        self.assertTrue(report["recorded_inference_not_live"])
        self.assertFalse(report["model_registered_to_telegraph"])
        self.assertFalse(report["independently_expert_adjudicated"])
        self.assertFalse(report["model_security_accuracy_certified"])
        self.assertEqual([c["project"] for c in report["cases"]],
                         ["docling-core","hydra-core","python-multipart"])
        for pair in report["cases"]:
            self.assertEqual(len(pair["versions"]),2)
            old,new=pair["versions"]
            self.assertEqual([old["source_expected"],new["source_expected"]],["A","B"])
            self.assertEqual([old["model_selected"],new["model_selected"]],["A","A"])
            self.assertTrue(old["model_match"])
            self.assertFalse(new["model_match"])
            for row in (old,new):
                self.assertEqual(len(row["score_a_f32_bits"]),10)
                self.assertEqual(len(row["score_b_f32_bits"]),10)
                self.assertTrue(row["score_a"]>row["score_b"])

    def test_markup_is_single_safe_inert_evidence_slot_and_has_reachable_controls(self):
        report=read_validated()
        template=TEMPLATE.read_text(encoding="utf-8")
        markup=render(report,template)
        self.assertNotIn("__FALSUM_REAL_EVIDENCE__",markup)
        self.assertEqual(markup.count('id="proof-data"'),1)
        for text in ("THE MODEL","MISSED THE FIX", 'aria-label="Choose package"',
                     'aria-label="Choose a version"', 'id="version-0"', 'id="version-1"',
                     'id="advisory-link"', 'id="score-a"', 'id="score-b"',
                     'id="verdict"', 'type="application/json"', 'prefers-reduced-motion',
                     'max-width:360px', "Not a registered evaluator", "0/3"):
            self.assertIn(text,markup)
        self.assertNotIn("fetch(",markup)
        self.assertNotIn("https://cdn.",markup)
        self.assertNotIn("api/evalpool/submissions/mine",markup)
        self.assertNotIn("wallet",markup.lower())

    def test_render_refuses_forced_better_accuracy_and_escaped_interpolation(self):
        report=read_validated()
        template=TEMPLATE.read_text()
        altered=copy.deepcopy(report)
        altered["complete_factual_reversals"]=3
        with self.assertRaises(JudgeProofError):
            render(altered,template)
        with self.assertRaises(JudgeProofError):
            render(report,template.replace("__FALSUM_REAL_EVIDENCE__","NO_SLOT"))
        altered=copy.deepcopy(report)
        altered["cases"][0]["project"]="</script><script>alert('injection')</script>"
        output=render(altered,template)
        self.assertNotIn("</script><script>alert",output)
        self.assertIn("\\u003c/script\\u003e",output)

    def test_source_or_f32_tampering_blocks_page_generation(self):
        real_root=ROOT
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)
            for path in ("evidence/phase4a-2026-11-12-real-original-model-failure.json",
                         "evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json"):
                target=fake/path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((real_root/path).read_bytes())
            baseline=read_validated(fake)
            self.assertEqual(baseline["model_matches_narrow_source_facts"],3)
            original=fake/"evidence/phase4a-2026-11-12-real-original-model-failure.json"
            data=json.loads(original.read_text())
            data["score_hex_by_input"]["hydra-core-1-3-8--A"]="0xc0000000"
            original.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                read_validated(fake)
            original.write_bytes((real_root/"evidence/phase4a-2026-11-12-real-original-model-failure.json").read_bytes())
            source=fake/"evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json"
            data=json.loads(source.read_text())
            data["source_release_facts"][0]["fixed_release"]="999.0.0"
            source.write_text(json.dumps(data))
            with self.assertRaises(JudgeProofError):
                read_validated(fake)

    def test_full_deployment_build_preserves_both_real_and_synthetic_truths(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/"public"
            with patch.object(socket.socket,"connect",side_effect=AssertionError("network used in local static build")):
                output=build(target)
            self.assertEqual(output["root_synthetic_cases"],3)
            self.assertEqual(output["root_real_python_fixture_pairs"],6)
            self.assertEqual(output["real_model_fact_matches"],3)
            self.assertEqual(output["real_model_complete_reversals"],0)
            self.assertFalse(output["registered_evaluator"])
            self.assertTrue((target/"ACTUAL-SYNTHETIC-RUNTIME-PROOF.json").is_file())
            self.assertTrue((target/"index.html").is_file())
            self.assertTrue((target/"proof/index.html").is_file())
            page=(target/"index.html").read_text()
            self.assertIn('href="/proof/"',page)
            report=json.loads((target/"proof/ACTUAL-RECORDED-FOUNDATION-MODEL-SCORES.json").read_text())
            self.assertEqual(report["model_matches_narrow_source_facts"],3)
            self.assertFalse(report["model_registered_to_telegraph"])
            with self.assertRaisesRegex(ValueError,"refuse to overwrite"):
                build(target)


if __name__=="__main__":
    unittest.main()
