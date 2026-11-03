"""Firma-inspired editorial FALSUM demo: truthful interaction contract, no leaked eval data.

The HTML uses a self-contained, accessible data-driven interface. These
checks are NOT screenshots or a substitute for cross-browser click QA.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3q_mission_lab import _page, capture, write_outputs, MissionProofError


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src/falsum/templates/firma_editorial_evidence_lab.html"


class EditorialEvidenceLabTests(unittest.TestCase):
    def test_single_file_accessible_guided_review_structure_and_responsive_layout(self):
        template = TEMPLATE.read_text(encoding="utf-8")
        self.assertEqual(template.count("__FALSUM_DATA__"), 1)
        for expected in (
            "color-scheme:dark",
            "--bg:#0a0d15",
            'font-family:var(--serif)',
            "AI can sound certain.",
            "The proof decides.",
            "Which security review should pass?",
            "These are short, written-for-demo examples",
            "@media(max-width:1000px)",
            "@media(max-width:670px)",
            "prefers-reduced-motion:reduce",
            'data-answer="0"',
            'data-answer="1"',
            'id="show-proof"',
            'id="next-case"',
            'id="try-again"',
            'id="proof-before-title"',
            'id="proof-after-title"',
            'id="hash-before"',
            'id="hash-after"',
            'id="code-before"',
            'id="code-after"',
            'aria-live="polite"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, template)
        self.assertNotIn("@import", template)
        self.assertNotIn("<img", template)
        self.assertNotIn("https://fonts.", template)
        self.assertNotIn("fetch(", template)
        self.assertNotIn("WebSocket(", template)

    def test_local_capture_populates_real_exact_function_sources_and_fingerprints(self):
        report = capture()
        self.assertEqual(len(report["cases"]), 3)
        for case in report["cases"]:
            self.assertEqual(
                hashlib.sha256(case["before_code"].encode("utf-8")).hexdigest(),
                case["before_source_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(case["after_code"].encode("utf-8")).hexdigest(),
                case["after_source_sha256"],
            )
            self.assertNotEqual(case["before_code"], case["after_code"])
            self.assertTrue(case["before"]["unsafe_action_accepted"])
            self.assertFalse(case["after"]["unsafe_action_accepted"])

    def test_executable_output_embeds_actual_data_but_does_not_expose_private_questions(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "public"
            report = capture()
            write_outputs(target, report)
            html = (target / "index.html").read_text(encoding="utf-8")
            body = json.loads((target / "ACTUAL-SYNTHETIC-RUNTIME-PROOF.json").read_text())
            self.assertNotIn("__FALSUM_DATA__", html)
            self.assertEqual(body, report)
            self.assertIn('"before_code":', html)
            self.assertIn('"after_code":', html)
            self.assertIn("does <strong>not</strong> run a live AI evaluator", html)
            self.assertIn("public fictional example", html.lower())
            self.assertEqual(report["actual_third_party_mission_apps_verified"], 0)
            self.assertFalse(report["actual_evaluator_model_scoring_executed"])
            for sensitive in (
                "PRIVATE-EVALPOOL-ROWS", "X-Evalpool-Signature", "0x9cBA6Cf",
                "issuecomment-6588168396", "source_kind: llm",
            ):
                self.assertNotIn(sensitive, html)

    def test_untrusted_python_source_never_terminates_inert_json_script(self):
        report = capture()
        report["cases"][0]["before_code"] += '\n</script><script>evil()</script>&'
        page = _page(report)
        self.assertEqual(page.count('id="proof-data"'), 1)
        self.assertNotIn("</script><script>evil()", page)
        self.assertIn('\\u003c/script\\u003e', page)
        self.assertIn('\\u0026', page)

    def test_missing_template_placeholder_fails_closed(self):
        with patch.object(Path, "read_text", return_value="<html>missing marker</html>"):
            with self.assertRaisesRegex(MissionProofError, "exactly one safe data-placeholder"):
                _page(capture())

    def test_no_network_needed_to_capture_or_export_and_all_buttons_are_wired(self):
        import socket
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network not allowed")):
            with tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "site"
                write_outputs(target, capture())
                page = (target / "index.html").read_text()
        self.assertIn('button.addEventListener("click"', page)
        self.assertIn("matchMedia(", page)
        self.assertIn('data-answer="1"', page)
        self.assertIn("scrollIntoView", page)


if __name__ == "__main__":
    unittest.main()
