"""Negative real-scoring evidence integrity; not a replacement for official inference."""
import copy
import json
from pathlib import Path
import unittest

from falsum.phase4a_recorded_evidence import check, LedgerMismatch

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "evidence/phase4a-2026-11-12-real-original-model-failure.json"


class RealPhase4AFailureTests(unittest.TestCase):
    def setUp(self):
        self.ledger = json.loads(LEDGER.read_text())

    def test_permanent_real_scorebits_recompute_the_negative_result(self):
        self.assertEqual(check(self.ledger), {
            "observed_matches": 3, "complete_version_reversals": 0,
            "actual_score_bits": 12, "release_authorized": False,
        })

    def test_false_improvement_or_forged_identity_fails_closed(self):
        for mode in ("fake6of6", "fake_reversal", "fake_preference",
                     "other_source", "other_foundation", "other_model",
                     "other_results", "missing_bit", "score_forced_B",
                     "not_independent", "registered", "auto_register",
                     "tamper_holdout", "invent_network_rows"):
            with self.subTest(mode=mode):
                value = copy.deepcopy(self.ledger)
                if mode == "fake6of6":
                    value["source_fact_matches"] = 6
                elif mode == "fake_reversal":
                    value["complete_version_reversals"] = 3
                elif mode == "fake_preference":
                    value["observed_choice_sequence"][1] = "B"
                elif mode == "other_source":
                    value["source_report_sha256"] = "0"*64
                elif mode == "other_foundation":
                    value["foundation_sha256"] = "f"*64
                elif mode == "other_model":
                    value["original_model_sha256"] = "f"*64
                elif mode == "other_results":
                    value["actual_results_json_sha256"] = "f"*64
                elif mode == "missing_bit":
                    del value["score_hex_by_input"]["hydra-core-1-3-7--A"]
                elif mode == "score_forced_B":
                    value["score_hex_by_input"]["hydra-core-1-3-8--A"] = "0xc0000000"
                elif mode == "not_independent":
                    value["truth_boundaries"]["expert_adjudicated_labels"] = 5
                elif mode == "registered":
                    value["truth_boundaries"]["registered_adapter"] = True
                elif mode == "auto_register":
                    value["truth_boundaries"]["automatic_registration_authorized"] = True
                elif mode == "tamper_holdout":
                    value["truth_boundaries"]["public_cases_not_blind_holdout"] = False
                elif mode == "invent_network_rows":
                    value["truth_boundaries"]["new_anjoman_rows"] = 20
                with self.assertRaises(LedgerMismatch):
                    check(value)


if __name__ == "__main__":
    unittest.main()
