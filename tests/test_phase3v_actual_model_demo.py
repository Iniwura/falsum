"""Verify genuine recorded real model decisions, tamper resistance and release veto.

This never calls a model or uses confidential Anjoman evaluation material.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3v_recorded_model_demo import (
    ROOT, FAMILIES, MODEL_CI, MODEL_SHA256,
    RecordedModelEvidenceError, STATUS, capture, render, write,
    _float_from_bits,
)


class Phase3VActualModelEvidence(unittest.TestCase):
    def test_actual_official_recorded_foundation_scores_and_counterfactuals(self):
        r = capture()
        self.assertEqual(r["status"], STATUS)
        self.assertEqual(r["official_inference_workflow"], MODEL_CI)
        self.assertEqual(r["model_package_sha256"], MODEL_SHA256)
        self.assertEqual(r["unique_model_scored_inputs"], 8)
        self.assertEqual(r["recorded_actual_model_inference_calls"], 16)
        self.assertEqual(r["provisional_context_matches"], 2)
        self.assertEqual(r["families_with_correct_changed_fact_reversal"], 0)
        self.assertEqual(len(r["families"]), 2)
        self.assertEqual(r["contexts"], 4)
        self.assertTrue(r["recorded_inference_not_live"])
        self.assertTrue(r["candidate_answers_researcher_authored"])
        self.assertTrue(r["input_families_known_and_not_blind"])
        self.assertTrue(r["labels_provisional_not_expert_approved"])
        self.assertEqual(r["independent_expert_labels"], 0)
        self.assertFalse(r["model_registered"])
        self.assertFalse(r["security_accuracy_certified"])
        self.assertFalse(r["user_private_eligible_pool_rows_used"])
        self.assertTrue(r["this_is_not_a_new_network_contribution"])
        self.assertEqual(r["source_record_sha256"], hashlib.sha256(
            (ROOT/"evidence/phase3j-2026-11-02.json").read_bytes()).hexdigest())

    def test_preferred_answer_stays_the_same_while_runtime_expected_flips(self):
        r = capture()
        for actual, source in zip(r["families"], FAMILIES):
            with self.subTest(family=actual["id"]):
                self.assertEqual(actual["id"], source["id"])
                self.assertEqual(len(actual["contexts"]), 2)
                affected, fixed = actual["contexts"]
                self.assertEqual(affected["model_selected"], fixed["model_selected"])
                self.assertNotEqual(affected["provisional_expected"], fixed["provisional_expected"])
                self.assertEqual(sum(c["model_matches_provisional"] for c in actual["contexts"]), 1)
                self.assertFalse(affected["independent_expert_adjudication"])
                for c in actual["contexts"]:
                    self.assertEqual(len(c["candidate_answers"]), 2)
                    self.assertTrue(all(a["authored_not_model_generated"] for a in c["candidate_answers"]))
                    self.assertEqual(c["candidate_answers"][0]["id"], source["answers"][0][0])
                    self.assertEqual(c["candidate_answers"][1]["id"], source["answers"][1][0])

    def test_recorded_score_bits_are_valid_and_not_synthesized(self):
        actual = json.loads((ROOT/"evidence/phase3j-2026-11-02.json").read_text())
        bits = actual["observed"]["float32_score_bits_by_input"]
        observed = capture()
        for f in observed["families"]:
            for c in f["contexts"]:
                for a in c["candidate_answers"]:
                    key=f["id"]+"--"+c["id"]+"--"+a["id"]
                    self.assertEqual(a["score_hex"],bits[key])
                    self.assertEqual(a["score_float32"],_float_from_bits(bits[key]))
        with self.assertRaises(RecordedModelEvidenceError):
            _float_from_bits("0x7fc00000")  # NaN
        with self.assertRaises(RecordedModelEvidenceError):
            _float_from_bits("1.0")

    def test_tampered_winner_and_fake_success_refused(self):
        old = json.loads((ROOT/"evidence/phase3j-2026-11-02.json").read_text())
        variants=[]
        fake=copy.deepcopy(old)
        fake["observed"]["families"][0]["contexts"][0]["model_preferred"]="outside-path-blocked"
        variants.append(fake)
        fake=copy.deepcopy(old)
        fake["observed"]["families"][0]["ranking_reversed"]=True
        variants.append(fake)
        fake=copy.deepcopy(old)
        fake["registered_evaluator"]=True
        variants.append(fake)
        fake=copy.deepcopy(old)
        fake["observed"]["float32_score_bits_by_input"]["starlette-path-boundary--affected--outside-path-blocked"]="0x7f800000"
        variants.append(fake)
        fake=copy.deepcopy(old)
        del fake["observed"]["float32_score_bits_by_input"]["requests-proxy-auth--fixed--https-auth-present"]
        variants.append(fake)
        for mutated in variants:
            with self.subTest(status=mutated["observed"].get("families",[{}])[0].get("family")):
                # only override the exact JSON evidence read (runtime anchors remain pinned).
                from unittest.mock import patch
                original_read = Path.read_text
                def read(p, *args, **kwargs):
                    if str(p).endswith("phase3j-2026-11-02.json"):
                        return json.dumps(mutated)
                    return original_read(p,*args,**kwargs)
                with patch.object(Path,"read_text",read):
                    with self.assertRaises(RecordedModelEvidenceError):
                        capture()

    def test_public_html_is_static_and_uses_only_source_bound_data(self):
        r=capture()
        html=render(r)
        self.assertIn("The model didn't",html)
        self.assertIn('id="recorded-data"',html)
        self.assertIn("Recorded model score",html)
        self.assertIn("researcher-written",html)
        self.assertNotIn("__REAL_RECORDED_MODEL_DATA__",html)
        for secret in ("PRIVATE-EVALPOOL-ROWS","0x9cBA6Cf","EIP191-MESSAGE-TO-SIGN"):
            self.assertNotIn(secret,html)
        self.assertNotIn("fetch(",html)
        self.assertNotIn("WebSocket",html)
        self.assertNotIn("@import",html)
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/"model-judge-preview"
            write(out,r)
            self.assertEqual(sorted(p.name for p in out.iterdir()),
                             ["index.html","recorded-model-evidence.json"])
            self.assertEqual(json.loads((out/"recorded-model-evidence.json").read_text()),r)
            with self.assertRaisesRegex(RecordedModelEvidenceError,"output directory must be new"):
                write(out,r)

    def test_json_script_breakout_never_executes_source(self):
        r=capture()
        r["families"][0]["contexts"][0]["candidate_answers"][0]["text"]+="</script><script>evil()</script>&"
        html=render(r)
        self.assertNotIn("</script><script>evil()",html)
        self.assertIn("\\u003c/script\\u003e",html)
        self.assertIn("\\u0026",html)


if __name__=="__main__":
    unittest.main()
