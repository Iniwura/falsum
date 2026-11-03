"""Guard FALSUM's public Evidence Lab release against accidental private data."""
from pathlib import Path
import json
import tempfile
import unittest

from falsum.phase3q_mission_lab import capture, write_outputs

ROOT = Path(__file__).resolve().parents[1]


class PublicDemoReleaseReadiness(unittest.TestCase):
    def test_deployment_configuration_is_static_and_reproducible(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        self.assertIsNone(config["framework"])
        self.assertEqual(config["outputDirectory"], "public")
        self.assertEqual(
            config["buildCommand"],
            "PYTHONPATH=src python3 -m falsum.phase3q_mission_lab --out-dir public",
        )
        self.assertEqual(config["installCommand"], "python3 --version")
        self.assertEqual(config["headers"][0]["source"], "/(.*)")
        headers = {h["key"]: h["value"] for h in config["headers"][0]["headers"]}
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_real_executed_proof_generates_index_which_is_only_public_demo(self):
        with tempfile.TemporaryDirectory() as t:
            output = Path(t) / "public"
            report = capture()
            write_outputs(output, report)
            self.assertEqual(sorted(x.name for x in output.iterdir()),
                             ["ACTUAL-SYNTHETIC-RUNTIME-PROOF.json", "index.html"])
            html = (output / "index.html").read_text()
            raw = (output / "ACTUAL-SYNTHETIC-RUNTIME-PROOF.json").read_text()
            for content in (html, raw):
                self.assertNotIn("0x9cBA6Cf", content)
                self.assertNotIn("PRIVATE-EVALPOOL-ROWS", content)
                self.assertNotIn("EIP191-MESSAGE-TO-SIGN", content)
                self.assertNotIn("issuecomment-6588168396", content)
                self.assertNotIn("source_kind: llm", content)
            self.assertIn("FALSUM — Evidence Lab", html)
            self.assertIn("Public synthetic evidence lab", html)
            self.assertIn("Explore measured results", html)
            self.assertIn("https://github.com/Iniwura/falsum", html)
            self.assertIn("How to reproduce + verify", html)
            self.assertEqual(report["actual_third_party_mission_apps_verified"], 0)
            self.assertFalse(report["actual_evaluator_model_scoring_executed"])

    def test_static_public_page_does_not_falsely_promise_live_scores(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t) / "public"
            write_outputs(directory, capture())
            data = (directory / "index.html").read_text()
            self.assertIn("not</b> a deployed product audit, trained AI scorer", data)
            self.assertIn("No deployed agents, live secrets, web requests", data)
            self.assertNotIn("fetch(", data)
            self.assertNotIn("WebSocket", data)
            self.assertNotIn("localStorage", data)


if __name__ == "__main__":
    unittest.main()
