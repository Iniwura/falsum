"""Real production can be attested only by exact HTTPS match, not offline fixtures."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase5e_production_freshness as p
from falsum import phase4v_real_source_witness_site as site

ROOT = Path(__file__).resolve().parents[1]


class FiveSourcePublicReleaseFreshnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = site.assemble()
        cls.html = site.render(cls.expected, site.TEMPLATE.read_text(encoding="utf-8")).encode()
        cls.document = (json.dumps(cls.expected, sort_keys=True) + "\n").encode()

    def test_exact_locally_built_five_source_fixture_never_proves_public_release(self):
        report = p.compare(self.expected, self.document, self.html, live=False)
        self.assertEqual(report["status"], p.STATUS_OFFLINE)
        self.assertFalse(report["actual_production_content_verified"])
        self.assertEqual(report["input_provenance"], "OFFLINE_UNTRUSTED_FIXTURE")
        self.assertIsNone(report["production_alias"])
        self.assertEqual(report["constructed_source_checks"],80)
        self.assertEqual(report["original_source_fix_stages"],5)
        self.assertEqual(report["distinct_source_repositories"],4)
        self.assertEqual(report["by_construction_verdict_counts"],
                         {"SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":60})
        self.assertEqual(report["independent_human_appsec_gold_labels"],0)
        self.assertFalse(report["registered_telegraph_scorer"])
        self.assertFalse(report["official_h2_entry_submitted"])

    def test_original_live_exact_source_content_requires_explicit_live_flag(self):
        report = p.compare(self.expected,self.document,self.html,live=True)
        self.assertEqual(report["status"],p.STATUS_LIVE)
        self.assertTrue(report["actual_production_content_verified"])
        self.assertEqual(report["production_alias"],p.BASE)
        self.assertEqual(report["local_authenticated_source_report_sha256"],
                         report["served_source_report_sha256"])

    def test_four_source_deployment_stale_even_when_old_model_page_works(self):
        older=copy.deepcopy(self.expected)
        older["source_fix_stage_count"]=4
        older["upstream_project_count"]=3
        older["precomputed_python_evaluations"]=64
        older["cases"].pop()
        older["by_construction_verdict_counts"]={
            "SUPPORTED":8,"CONTRADICTED":8,"ABSTAIN":48
        }
        with self.assertRaisesRegex(p.FreshnessError,"STALE"):
            p.compare(self.expected,json.dumps(older).encode(),self.html,live=True)

    def test_same_case_count_but_changed_silent_test_receipt_fails(self):
        changed=copy.deepcopy(self.expected)
        changed["cases"][-1]["original_execution_receipt_sha256"]="0"*64
        with self.assertRaisesRegex(p.FreshnessError,"STALE"):
            p.compare(self.expected,json.dumps(changed).encode(),self.html,live=True)

    def test_html_must_be_actual_populated_five_case_page(self):
        for html in (
            b"<html><body>200 OK</body></html>",
            self.html.replace(b"FIVE PINNED PATCH STAGES",b"FOUR PINNED PATCH STAGES"),
            self.html.replace(b"__notpresent__",b"missing"),
            self.html.replace(b'id="witness-data"',b'id="wrong-data"'),
            self.html+b'\n<div id="witness-data"></div>',
        ):
            if html == self.html:
                continue
            with self.subTest(html=html[:35]),self.assertRaises(p.FreshnessError):
                p.compare(self.expected,self.document,html,live=True)

    def test_null_and_tampered_source_case_rejected(self):
        for invalid in (b"",b"{}",b"null",b"invalid",b"["+(b"a"*p.MAX_JSON)+b"]"):
            with self.subTest(raw=invalid[:30]),self.assertRaises(p.FreshnessError):
                p.compare(self.expected,invalid,self.html,live=True)

    def test_faked_locally_modified_expected_cannot_imply_original_source_gold(self):
        changed=copy.deepcopy(self.expected)
        changed["independent_appsec_expert_gold_labels"]=1
        with self.assertRaisesRegex(p.FreshnessError,"local build"):
            p.compare(changed,json.dumps(changed).encode(),self.html,live=True)
        changed=copy.deepcopy(self.expected)
        changed["network_evaluator_registered"]=True
        with self.assertRaisesRegex(p.FreshnessError,"local build"):
            p.compare(changed,json.dumps(changed).encode(),self.html,live=True)

    def test_live_http_attestation_only_main_push_or_manual_and_bounded_retries(self):
        workflow = (ROOT / ".github/workflows/phase5e-live-production-source-freshness.yml").read_text()
        expected_gate = (
            "if: github.event_name == 'workflow_dispatch' || "
            "(github.event_name == 'push' && github.ref == 'refs/heads/main')"
        )
        self.assertIn(expected_gate, workflow)
        # Main deploys happen even when only judge docs/README change.
        # No path filter can silently skip a production content check.
        main_trigger = workflow.split("  push:", 1)[1].split("  workflow_dispatch:", 1)[0]
        self.assertIn("branches: [main]", main_trigger)
        self.assertNotIn("paths:", main_trigger)

        self.assertIn("python -m falsum.phase5e_production_freshness", workflow)
        self.assertIn("if [ \"$attempt\" -ge 6 ]; then", workflow)
        self.assertIn("sleep 15", workflow)
        self.assertIn("if: success()", workflow)
        self.assertIn("FALSUM-PHASE5E-PRODUCTION-FIVE-SOURCE-EXACT-MATCH", workflow)

    def test_public_fetch_strictly_limits_endpoint_paths(self):
        with self.assertRaisesRegex(p.FreshnessError,"limited"):
            p._read_public("https://other.example.org/credential",1000)
        with self.assertRaisesRegex(p.FreshnessError,"limited"):
            p._read_public("/witness/../../evil",1000)

    def test_live_cli_uses_its_real_fetcher_and_offline_mode_not_implicitly_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            out=root/"production.json"
            with patch.object(p,"_read_public",side_effect=[self.document,self.html]) as network:
                self.assertEqual(p.main(["--root",str(ROOT),"--out",str(out)]),0)
                self.assertEqual(network.call_count,2)
            live=json.loads(out.read_text())
            self.assertTrue(live["actual_production_content_verified"])
            with self.assertRaises(SystemExit):
                p.main(["--root",str(ROOT),"--out",str(out)])
            fixture=root/"fixture.json"
            page=root/"page.html"
            fixture.write_bytes(self.document)
            page.write_bytes(self.html)
            out2=root/"offline.json"
            self.assertEqual(p.main([
                "--root",str(ROOT),"--offline-json",str(fixture),
                "--offline-html",str(page),"--out",str(out2)
            ]),0)
            offline=json.loads(out2.read_text())
            self.assertFalse(offline["actual_production_content_verified"])
            self.assertEqual(offline["status"],p.STATUS_OFFLINE)

    def test_remote_fetch_failure_cannot_produce_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"no-success.json"
            with patch.object(p,"_read_public",side_effect=p.FreshnessError("quota-stale")):
                with self.assertRaises(SystemExit):
                    p.main(["--root",str(ROOT),"--out",str(out)])
            self.assertFalse(out.exists())

    def test_extra_offline_flag_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"blocked.json"
            with self.assertRaises(SystemExit):
                p.main(["--root",str(ROOT),"--offline-json",str(ROOT/"README.md"),
                        "--out",str(out)])
            self.assertFalse(out.exists())

if __name__ == "__main__":
    unittest.main()
