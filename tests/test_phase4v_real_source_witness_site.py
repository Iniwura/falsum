"""Real-upstream browser workbench: signed-off source and static UI truth gates."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum import phase4v_real_source_witness_site as v
from falsum.phase4c_release import build

ROOT = v.ROOT


class ActualSourceWitnessBrowserTests(unittest.TestCase):
    def test_80_precomputed_verdicts_from_authenticated_upstream_source_evidence(self):
        result = v.assemble()
        self.assertEqual(result["status"],v.STATUS)
        self.assertEqual(result["intent"],"SECURITY_REVIEW_GENERAL")
        self.assertEqual(result["source_fix_stage_count"],5)
        self.assertEqual(result["upstream_project_count"],4)
        self.assertEqual(result["precomputed_python_evaluations"],80)
        self.assertEqual(result["by_construction_verdict_counts"],{
            "SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":60})
        self.assertEqual(result["independent_appsec_expert_gold_labels"],0)
        self.assertEqual(result["new_anjoman_eligible_rows"],0)
        self.assertFalse(result["trained_model_improvement_proven"])
        self.assertFalse(result["network_evaluator_registered"])
        self.assertFalse(result["official_h2_submission_confirmed"])
        self.assertTrue(result["no_live_browser_tests_or_model_inference"])
        self.assertEqual(len(result["cases"]),5)
        self.assertEqual(len({c["repository"] for c in result["cases"]}),4)

    def test_every_case_tracks_real_public_git_parent_fix_and_exact_test_source(self):
        data=v.assemble()
        for c in data["cases"]:
            with self.subTest(case=c["id"]):
                self.assertEqual(len(c["parent_commit"]),40)
                self.assertEqual(len(c["fixed_commit"]),40)
                self.assertNotEqual(c["parent_commit"],c["fixed_commit"])
                self.assertNotEqual(c["parent_source_blob_sha1"],c["fixed_source_blob_sha1"])
                self.assertEqual(len(c["new_regression_test_blob_sha1"]),40)
                self.assertEqual(len(c["original_execution_receipt_sha256"]),64)
                self.assertIn("/blob/"+c["parent_commit"]+"/",c["source_parent_url"])
                self.assertIn("/blob/"+c["fixed_commit"]+"/",c["source_fixed_url"])
                self.assertIn("/blob/"+c["fixed_commit"]+"/",c["upstream_test_url"])
                self.assertTrue(c["actions_run_url"].startswith(
                    "https://github.com/Iniwura/falsum/actions/runs/"))
                self.assertEqual(len(c["decisions"]),16)

    def test_verdicts_are_source_reversed_and_unsafe_deployment_claims_abstain(self):
        data=v.assemble()
        for c in data["cases"]:
            d=c["decisions"]
            with self.subTest(case=c["id"]):
                self.assertEqual(d["parent|UPSTREAM_REGRESSION_FAILS|original"]["verdict"],
                                 "SUPPORTED")
                self.assertEqual(d["parent|UPSTREAM_REGRESSION_PASSES|original"]["verdict"],
                                 "CONTRADICTED")
                self.assertEqual(d["fixed|UPSTREAM_REGRESSION_PASSES|original"]["verdict"],
                                 "SUPPORTED")
                self.assertEqual(d["fixed|UPSTREAM_REGRESSION_FAILS|original"]["verdict"],
                                 "CONTRADICTED")
                for role in ("parent","fixed"):
                    for claim in v.CLAIMS:
                        wrong=d[f"{role}|{claim}|tampered"]
                        self.assertEqual(wrong["verdict"],"ABSTAIN")
                        self.assertEqual(wrong["reason"],
                                         "INCOMPLETE_OR_TAMPERED_PRIMARY_EVIDENCE")
                    for claim in v.CLAIMS[2:]:
                        verdict=d[f"{role}|{claim}|original"]
                        self.assertEqual(verdict["verdict"],"ABSTAIN")
                        self.assertEqual(verdict["reason"],
                                         "DEPLOYED_IMPACT_OR_GLOBAL_SECURITY_NOT_TESTED")

    def test_render_is_safe_against_inert_json_script_breakout_and_template_mutation(self):
        report=v.assemble()
        template=v.TEMPLATE.read_text(encoding="utf-8")
        page=v.render(report,template)
        self.assertEqual(page.count('id="witness-data"'),1)
        self.assertNotIn(v.STATUS+"\"__FALSUM_REAL_WITNESS_DATA__",page)
        self.assertNotIn("__FALSUM_REAL_WITNESS_DATA__",page)
        for text in ('id="hero-title"','id="case-list"','id="claim-list"',
                     'id="revision-parent"','id="revision-fixed"',
                     'id="integrity-original"','id="integrity-tampered"',
                     'id="verdict"','id="verify"','aria-live="polite"',
                     'prefers-reduced-motion','type="application/json"',
                     "not live AI inference","No private Anjoman questions"):
            self.assertIn(text.lower(),page.lower())
        self.assertNotIn("fetch(",page)
        self.assertNotIn("https://cdn",page)
        self.assertNotIn("api/evalpool/submissions/mine",page)
        self.assertNotIn("0xd2f5949c",page.lower())
        self.assertNotIn("0x9cba6cf9",page.lower())
        with self.assertRaisesRegex(v.BrowserWitnessError,"one inert"):
            v.render(report,template.replace("__FALSUM_REAL_WITNESS_DATA__",""))
        with self.assertRaisesRegex(v.BrowserWitnessError,"one inert"):
            v.render(report,template.replace("__FALSUM_REAL_WITNESS_DATA__",
                                             "__FALSUM_REAL_WITNESS_DATA____FALSUM_REAL_WITNESS_DATA__"))
        poisoned=copy.deepcopy(report)
        poisoned["cases"][0]["title"]="</script><script>window.attack=1</script>"
        safe=v.render(poisoned,template)
        self.assertIn("\\u003c/script\\u003e",safe)
        self.assertNotIn("</script><script>window.attack",safe)

    def test_refuse_fake_model_accuracy_or_third_party_security_gold(self):
        report=v.assemble()
        template=v.TEMPLATE.read_text()
        for name,value in [
            ("independent_appsec_expert_gold_labels",2),
            ("network_evaluator_registered",True),
            ("trained_model_improvement_proven",True),
            ("precomputed_python_evaluations",100),
            ("by_construction_verdict_counts",{"SUPPORTED":64}),
        ]:
            new=copy.deepcopy(report);new[name]=value
            with self.subTest(field=name),self.assertRaises(v.BrowserWitnessError):
                v.render(new,template)

    def test_wrong_index_blob_refuses_to_build_an_impressive_but_unsupported_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for path in (v.LOCK,v.INDEX,v.FLASK_LOCK,v.FLASK_ARCHIVE):
                file=root/path;file.parent.mkdir(parents=True,exist_ok=True)
                file.write_bytes((ROOT/path).read_bytes())
            normal=v.assemble(root)
            self.assertEqual(normal["precomputed_python_evaluations"],80)
            source=root/v.INDEX
            corrupt=json.loads(source.read_text())
            corrupt["receipts"][0]["original_source_git_blob"]="0"*40
            source.write_text(json.dumps(corrupt))
            with self.assertRaises(ValueError):
                v.assemble(root)
            self.assertFalse((root/"witness/index.html").exists())

    def test_full_static_release_contains_real_source_page_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"public"
            with patch.object(socket.socket,"connect",
                              side_effect=AssertionError("unexpected network during public build")):
                release=build(output)
            self.assertEqual(release["real_upstream_source_stages"],5)
            self.assertEqual(release["precomputed_source_witness_verdicts"],80)
            self.assertEqual(release["independent_witness_expert_labels"],0)
            self.assertTrue(release["no_live_source_scoring"])
            self.assertFalse(release["registered_evaluator"])
            root=(output/"index.html").read_text()
            self.assertIn('href="/witness/"',root)
            html=(output/"witness/index.html").read_text()
            self.assertIn("AUTHENTIC",html.upper())
            self.assertEqual(html.count('id="witness-data"'),1)
            self.assertIn('href="/compare/"',html)
            self.assertTrue((output/"proof/index.html").is_file())
            self.assertTrue((output/"compare/index.html").is_file())
            report=json.loads((output/"witness/FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json").read_text())
            self.assertEqual(report["precomputed_python_evaluations"],80)
            with self.assertRaisesRegex(ValueError,"refuse to overwrite"):
                build(output)

    def test_write_only_new_destination_and_preserve_upstream_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest=Path(tmp)/"witness"
            r=v.write(dest)
            self.assertEqual(r["source_fix_stage_count"],5)
            self.assertTrue((dest/"index.html").is_file())
            self.assertTrue((dest/"FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json").is_file())
            with self.assertRaisesRegex(v.BrowserWitnessError,"refuse overwrite"):
                v.write(dest)


if __name__=="__main__":
    unittest.main()
