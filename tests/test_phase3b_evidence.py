"""Fact-check Phase3B genuine official new delta package without pretending validation."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class DeltaEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads((ROOT/"evidence/phase3b-2026-11-01.json").read_text(encoding="utf-8"))

    def test_final_real_build_package_and_official_hashes(self):
        d=self.d
        self.assertEqual(d["actual_export_and_official_check_run"],
                         "https://github.com/Iniwura/falsum/actions/runs/41304788714")
        self.assertEqual(d["artifact_id"],13082304092)
        pkg=d["real_structurally_checked_adapter"]
        self.assertEqual(pkg["intent"],"SECURITY_REVIEW")
        self.assertEqual(pkg["class"],"hybrid")
        self.assertEqual(pkg["abi"],"lora-v1")
        self.assertEqual(pkg["rank"],8)
        self.assertEqual(pkg["tensors"],178)
        self.assertEqual(pkg["max_tokens"],512)
        self.assertEqual(pkg["size_bytes"],6776908)
        self.assertEqual(pkg["sha256"],"3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc")
        self.assertEqual(pkg["keccak256"],"0xf8f94708f30ed31b6f0825dbffb235fa60b0e71b76fde39dbc696cf277ef8aa7")
        self.assertTrue(pkg["official_stage1_parser_passed"])

    def test_tokenizer_change_only_safe_truncation_max_and_original_unchanged(self):
        d=self.d["tokenizer_compatibility"]
        self.assertTrue(d["full_parsed_json_matches_except_truncation"])
        self.assertEqual(d["old_truncation"],{
            "direction":"Right","max_length":512,"strategy":"LongestFirst","stride":0
        })
        self.assertEqual(d["official_truncation"],{
            "direction":"Right","max_length":1536,"strategy":"LongestFirst","stride":0
        })
        self.assertEqual(d["official_node_input_max_tokens"],512)
        self.assertTrue(d["original_adapter_bytes_never_modified"])
        self.assertTrue(d["official_tokenizer_bytes_substituted_only_in_separate_export_copy"])

    def test_still_unreviewed_unscored_unregistered_and_not_network_eligible(self):
        p=self.d["real_structurally_checked_adapter"]
        for field in ("actually_loaded_and_scored_with_foundation",
                      "runner_smoke_scored","network_hidden_evaluation_passed",
                      "actively_registered","network_eligible"):
            self.assertFalse(p[field])
        research=self.d["experimental_quality"]
        self.assertEqual(research["old_three_external_project_diagnostic_correct_context_families"],"0/3")
        self.assertFalse(research["model_generalization_not_demonstrated"] is False)
        self.assertEqual(research["independent_human_security_labels"],0)
        self.assertEqual(research["accepted_anjoman_pool_rows"],0)


if __name__=="__main__":
    unittest.main()
