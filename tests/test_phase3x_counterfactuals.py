"""Phase 3X internal-only counterfactual material test gates.

Synthetic report objects are fixtures for parser tests, not observed source proof.
The separate GitHub Actions source-checkout job runs the real pinned source
functions and publishes actual, provenance-checked measurement JSON.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unittest

from falsum.phase3x_hard_cases import build, validate_report, STATUS

ROOT = Path(__file__).resolve().parents[1]


def mock_axios_report():
    base = "https://allowed.example/v1"
    target = "https://other.example/transfer"
    items = [
        ("configured baseURL + absolute target + strict false",base,target,False,
         "https://other.example","https://allowed.example"),
        ("configured baseURL + absolute target + default option",base,target,"omitted",
         "https://other.example","https://other.example"),
        ("configured baseURL + absolute target + explicit true",base,target,True,
         "https://other.example","https://other.example"),
        ("configured baseURL + relative target + strict false",base,"/account",False,
         "https://allowed.example","https://allowed.example"),
        ("missing baseURL + absolute target + strict false",None,target,False,
         "https://other.example","https://other.example"),
        ("configured baseURL + protocol-relative target + strict false",base,
         "//other.example/transfer",False,"https://other.example","https://allowed.example")
    ]
    return {
        "schema_version":1,
        "status":"SOURCE_EXECUTED_AXIOS_TARGETED_BASEURL_COUNTERFACTUAL",
        "parent_commit":"8603e677c09fb81bd106999c194308dd230bc596",
        "fixed_commit":"02c3c69ced0f8fd86407c23203835892313d7fde",
        "primary_source_blobs_verified":True,
        "helper_source_blobs_verified":True,
        "full_axios_client_or_network_execution":False,
        "only_real_pinned_buildFullPath_helper_executed":True,
        "tested_scenarios":6,
        "changed_origin_cases":2,
        "scenarios":[
            {"case":name,"configured_baseURL":b,"requested_target":t,
             "allowAbsoluteUrls":allow,
             "parent_origin":pre,"patched_origin":post,
             "parent_result":t, "patched_result":t if pre==post else b+"/other.example/transfer"}
            for (name,b,t,allow,pre,post) in items
        ]
    }


def mock_django_report():
    def value(outcome, leading=False):
        return {"outcome":outcome,"starts_with_comma":None if outcome=="RecursionError" else leading}
    return {
        "schema_version":1,
        "status":"SOURCE_EXECUTED_DJANGO_INT_COMMA_SAFE_LONG_INPUT_COUNTERFACTUAL",
        "parent_commit":"9cefdfc43f0bae696b56fa5a0bf22346f85affff",
        "fixed_commit":"55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9",
        "primary_source_blobs_verified":True,
        "actual_pinned_function_extracted_and_executed":True,
        "full_installed_django_runtime":False,
        "http_server_or_production_dos_executed":False,
        "localization_disabled_for_isolation":True,
        "patched_12_digit_localization_disabled_leading_comma_observed":True,
        "cases":[
            {"digits":13,"before":value("returned"),"after":value("returned"),
             "before_matches_grouping_oracle":True,"after_matches_grouping_oracle":True},
            {"digits":12,"before":value("returned"),"after":value("returned",True),
             "before_matches_grouping_oracle":True,"after_matches_grouping_oracle":False},
            {"digits":3601,"before":value("RecursionError"),"after":value("returned"),
             "before_matches_grouping_oracle":False,"after_matches_grouping_oracle":True}
        ]
    }


class Phase3XHardDiagnosticTests(unittest.TestCase):
    def test_balanced_technical_counterfactuals_without_trainable_claims(self):
        r=build(mock_axios_report(),mock_django_report())
        self.assertEqual(r["status"],STATUS)
        self.assertEqual(len(r["cases"]),18)
        self.assertEqual(r["source_families"],2)
        self.assertEqual(r["question_count"],18)
        self.assertTrue(r["known_not_blind"])
        self.assertTrue(r["candidate_responses_researcher_authored"])
        self.assertFalse(r["model_answers_or_scores_newly_generated"])
        self.assertFalse(r["actual_model_scoring_run"])
        self.assertEqual(r["independent_human_labels"],0)
        self.assertEqual(r["trainable_pairs"],[])
        self.assertFalse(r["registered_evaluator"])
        self.assertFalse(r["network_eligible"])
        self.assertTrue(all(c["independent_expert_label"] is None and
                            c["training_authorized"] is False for c in r["cases"]))
        self.assertTrue(all(len(c["candidate_answers"])==2 for c in r["cases"]))

    def test_required_changed_fact_reversals_are_present(self):
        r=build(mock_axios_report(),mock_django_report())
        selected=[c for c in r["cases"] if c["family"]=="axios-buildFullPath" and
                  c.get("runtime_context")=="configured baseURL + absolute target + strict false"]
        self.assertEqual([c["research_source_expected"] for c in selected],["A","B"])
        django=[c for c in r["cases"] if c.get("runtime_context")=="3601 digits"]
        self.assertEqual([c["research_source_expected"] for c in django],["B","A"])
        odd=[c for c in r["cases"] if c["id"].startswith("django-12-digit-leading-comma-")]
        self.assertEqual([c["research_source_expected"] for c in odd],["A","B"])
        self.assertEqual(sum(c["research_source_expected"]=="ABSTAIN" for c in r["cases"]),2)
        for case in r["cases"]:
            texts=[a["text"] for a in case["candidate_answers"]]
            # A and B should both be plausible concrete statements, not one
            # deliberately overconfident universal assertion ("always", "never").
            for text in texts:
                self.assertNotIn("every deployment",text.lower())
                self.assertNotIn("always vulnerable",text.lower())

    def test_tampered_provenance_or_invented_new_release_refused(self):
        good_ax=mock_axios_report()
        good_dj=mock_django_report()
        for name, mutate in (
            ("unverified blob",lambda a,d:a.__setitem__("primary_source_blobs_verified",False)),
            ("invented live client",lambda a,d:a.__setitem__("full_axios_client_or_network_execution",True)),
            ("changed oracle",lambda a,d:a["scenarios"][0].__setitem__("patched_origin","https://other.example")),
            ("invented other change",lambda a,d:a["scenarios"][1].__setitem__("patched_origin","https://allowed.example")),
            ("unverified old Django",lambda a,d:d["cases"][2]["before"].__setitem__("outcome","returned")),
            ("false Django format fix",lambda a,d:d["cases"][1]["after"].__setitem__("starts_with_comma",False)),
            ("fake installed Django",lambda a,d:d.__setitem__("full_installed_django_runtime",True)),
        ):
            with self.subTest(name=name):
                a,d=copy.deepcopy(good_ax),copy.deepcopy(good_dj)
                mutate(a,d)
                with self.assertRaises(ValueError):
                    build(a,d)

    def test_pinned_actual_source_probes_in_repo(self):
        axios=(ROOT/"tests/phase3x_axios_source_probe.cjs").read_text()
        django=(ROOT/"tests/phase3x_django_source_probe.py").read_text()
        ci=(ROOT/".github/workflows/phase3x-targeted-source-probes.yml").read_text()
        self.assertIn("8603e677c09fb81bd106999c194308dd230bc596",axios)
        self.assertIn("02c3c69ced0f8fd86407c23203835892313d7fde",axios)
        self.assertIn("gitBlobHash",axios)
        self.assertIn("Refuse to overwrite earlier evidence",axios)
        self.assertIn("normalized_child_recursion_limit",django)
        self.assertIn("source_function(path)",django)
        self.assertIn("ast.FunctionDef",django)
        self.assertIn("MAX_INPUT_DIGITS = 3601",django)
        self.assertIn("RecursionError",django)
        self.assertIn("sparse-checkout-cone-mode: false",ci)
        self.assertIn("actions/upload-artifact@v4",ci)
        self.assertIn("actual_model_scoring_run",ci)
        self.assertNotIn("accepted_expert_labels",ci)


if __name__=="__main__":
    unittest.main()
