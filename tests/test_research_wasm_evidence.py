"""Guard the permanent research-only WASM manifest against false release claims.

The real model score and official build are evidenced in the linked Actions runs;
this test checks this source-control snapshot is internally honest, not that
the upstream logs are an independent network attestation.
"""
import hashlib
import json
import math
import re
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "evidence/research-wasm-runtime-2026-10-30.json"


class ResearchWasmEvidenceTests(unittest.TestCase):
    def test_technical_build_is_real_but_explicitly_not_a_submission(self):
        row = json.loads(PATH.read_text(encoding="utf-8"))
        self.assertEqual(row["status"], "QUARANTINED_RESEARCH_WASI_RUNTIME_EXECUTED_NOT_NETWORK_ELIGIBLE")
        source, build, smoke, approval = (row[k] for k in (
            "source", "official_build", "real_wasi_smoke", "approval"))
        self.assertEqual(source["official_kit_commit"], "5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e")
        self.assertEqual(build["intent"], "SECURITY_REVIEW_GENERAL")
        self.assertEqual(build["class"], "hybrid")
        self.assertEqual(build["runtime"], "onnx_f32")
        self.assertEqual(build["abi_version"], 2)
        self.assertEqual(build["max_tokens"], 512)
        self.assertTrue(build["structurally_verified_by_packager"])
        self.assertEqual(build["reproducibility"]["builds"], 2)
        self.assertIs(build["reproducibility"]["identical_sha256"], True)
        self.assertEqual(build["reproducibility"]["sha256s"], [build["sha256"], build["sha256"]])
        self.assertRegex(build["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(build["onnx_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(build["keccak256"], r"^0x[0-9a-f]{64}$")
        self.assertGreater(build["wasm_bytes"], 500_000_000)
        self.assertGreater(build["onnx_bytes"], 500_000_000)
        self.assertTrue(math.isclose(abs(smoke["pytorch_fp32_reference"] -
                                         smoke["actual_wasi_f32"]),
                                         smoke["absolute_delta"], abs_tol=1e-12))
        self.assertLess(smoke["absolute_delta"], 1e-6)
        self.assertTrue(smoke["matched_one_fixed_input"])
        self.assertIs(smoke["model_accuracy_measured"], False)
        self.assertIs(smoke["network_node_execution_verified"], False)
        self.assertIs(source["underlying_data_independently_reviewed"], False)
        self.assertEqual(source["underlying_model_pr_validation_fraction"], 0.25)
        self.assertEqual(approval["accepted_human_review_labels"], 0)
        self.assertEqual(approval["anjoman_eligible_rows"], 0)
        self.assertIsNone(approval["registration_id"])
        self.assertIs(approval["live_on_network"], False)
        self.assertIs(approval["registration_authorized"], False)
        self.assertIs(approval["model_quality_validated"], False)

    def test_build_and_runtime_links_are_primary_evidence(self):
        r = json.loads(PATH.read_text(encoding="utf-8"))["source"]
        self.assertEqual(r["official_build_run_url"],
                         "https://github.com/Iniwura/falsum/actions/runs/41132003351")
        self.assertEqual(r["real_wasi_score_run_url"],
                         "https://github.com/Iniwura/falsum/actions/runs/41132583676")


if __name__ == "__main__":
    unittest.main()
