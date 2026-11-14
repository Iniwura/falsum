"""Adversarial permanent Phase4H score ledger checks; not live model scoring."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from falsum.phase4h_recorded_evidence import (
    validate_ledger,validate_original_report,verify_archive,EvidenceError,STATUS
)

LEDGER=(Path(__file__).resolve().parents[1]
  /"evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json")

class GenuineFrozenResultTests(unittest.TestCase):
    def setUp(self):
        self.ledger=json.loads(LEDGER.read_text())

    def test_real_16_score_bits_5_of_8_1_of_4_and_no_release(self):
        report=validate_ledger(self.ledger)
        self.assertEqual(report["status"],STATUS)
        self.assertEqual(report["real_score_bits_verified"],16)
        self.assertEqual(report["source_research_matches"],5)
        self.assertEqual(report["complete_source_fact_reversals"],1)
        self.assertEqual(report["model_preference_change_groups"],1)
        self.assertEqual(report["constant_A_baseline"],4)
        self.assertEqual(report["constant_B_baseline"],4)
        self.assertEqual(report["expert_gold_labels"],0)
        self.assertTrue(report["model_release_veto"])

    def test_wrong_score_bits_or_output_or_tie_rejected(self):
        for name,value in (
            ("pyjwt-fixed--B","0x00000000"),
            ("pillow-fixed--A","0x7f800000"),
            ("werkzeug-parent--A","not-an-official-score"),
            ("mcp-python-parent--A","0x00000000"),
        ):
            with self.subTest(name=name):
                fake=copy.deepcopy(self.ledger)
                fake["score_hex_by_input"][name]=value
                with self.assertRaises(EvidenceError):
                    validate_ledger(fake)
        fake=copy.deepcopy(self.ledger)
        fake["score_hex_by_input"].pop("pyjwt-parent--A")
        with self.assertRaises(EvidenceError):
            validate_ledger(fake)

    def test_false_expert_model_training_or_registration_rejected(self):
        for key,val in (
            ("independent_security_expert_labels",8),
            ("not_blind_or_pretraining_disjoint",False),
            ("new_anjoman_eligible_rows",8),
            ("no_model_training_or_improvement_performed",False),
            ("registered_evaluator",True),
            ("automatic_registration_permitted",True),
            ("original_model_release_veto",False),
            ("source_revision_fact_matches",8),
            ("complete_researcher_source_reversals",4),
            ("run_id",99999),
            ("source_report_sha256","0"*64),
        ):
            with self.subTest(key=key):
                fake=copy.deepcopy(self.ledger)
                fake[key]=val
                with self.assertRaises(EvidenceError):
                    validate_ledger(fake)

    def test_fake_archive_is_not_authentic_scoring(self):
        with self.assertRaises(EvidenceError):
            validate_original_report(self.ledger,b'{"status":"looks official"}')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"fake.zip"
            with zipfile.ZipFile(p,"w") as z:
                z.writestr("results/ACTUAL-NEW-FOUR-PROJECTS-ORIGINAL-MODEL-REPORT.json",
                           json.dumps({"status":"simulated score"}))
            with self.assertRaises(EvidenceError):
                verify_archive(self.ledger,p)

if __name__=="__main__":
    unittest.main()
