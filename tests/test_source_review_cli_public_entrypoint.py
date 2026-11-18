"""Zero-credential public CLI check; a typed source-fact gate, not model inference."""
from pathlib import Path
import json
import tempfile
import unittest

from falsum.cli import main

ROOT=Path(__file__).resolve().parents[1]
INDEX=ROOT/"evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
LOCK=ROOT/"data/phase4p-three-project-open-review-lock.json"
EXAMPLES=ROOT/"examples/source-review-witness-claims.json"


class SourceWitnessCLIIntegration(unittest.TestCase):
    def test_developer_command_is_in_normal_installable_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"examples.json"
            status=main([
                "verify-source-review",
                "--index",str(INDEX),
                "--source-lock",str(LOCK),
                "--requests",str(EXAMPLES),
                "--out",str(output),
            ])
            self.assertEqual(status,0)
            r=json.loads(output.read_text())
            self.assertEqual((r["supported"],r["contradicted"],r["abstained"]),(2,2,3))
            self.assertEqual(r["constructed_fixture_matches"],7)
            self.assertFalse(r["trained_model_improvement_proven"])
            self.assertEqual(r["independent_appsec_expert_labels"],0)
            self.assertFalse(r["official_hackathon_submission_confirmed"])

    def test_default_generated_safety_controls_not_confused_with_model_accuracy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"controls.json"
            self.assertEqual(main([
                "verify-source-review",
                "--index",str(INDEX),
                "--source-lock",str(LOCK),
                "--out",str(path),
            ]),0)
            r=json.loads(path.read_text())
            self.assertEqual(r["claims_evaluated"],32)
            self.assertEqual((r["supported"],r["contradicted"],r["abstained"]),(8,8,16))
            self.assertTrue(r["not_a_semantic_or_neural_security_evaluator"])
            self.assertTrue(r["not_a_telegraph_network_adapter"])
            self.assertEqual(r["constructed_fixture_matches"],32)

    def test_missing_public_source_does_not_create_successful_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"should-not-exist.json"
            with self.assertRaises(SystemExit):
                main([
                    "verify-source-review",
                    "--index",str(Path(tmp)/"not-evidence.json"),
                    "--source-lock",str(LOCK),
                    "--out",str(output),
                ])
            self.assertFalse(output.exists())

    def test_refuses_overwrite_of_existing_source_evaluation_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"prior.json"
            output.write_text("do not erase history")
            with self.assertRaises(SystemExit):
                main([
                    "verify-source-review",
                    "--index",str(INDEX),
                    "--source-lock",str(LOCK),
                    "--out",str(output),
                ])
            self.assertEqual(output.read_text(),"do not erase history")


if __name__=="__main__":
    unittest.main()
