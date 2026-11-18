"""Phase 4O adversarial checks are synthetic; genuine Git sources are checked in CI."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from falsum.phase3f_multifamily_material import generate
from falsum.phase4g_reasoning_puzzles import build
from falsum import phase4o_multibaseline_shortcut_audit as o
from test_phase3f_multifamily_material import inputs, mock_commit


def raw(x: dict) -> bytes:
    return (json.dumps(x,sort_keys=True,separators=(",",":"))+"\n").encode()


class ShortcutRosterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=generate(*inputs(),fetcher=mock_commit)
        cls.casebook,cls.old=build(cls.source)
        cls.sraw=raw(cls.source)
        cls.craw=raw(cls.casebook)

    def test_real_seven_source_identity_pipeline_fixture_and_all_roster_rules(self):
        evidence=o.audit(self.sraw,self.craw)
        self.assertEqual(evidence["source_cases"],7)
        self.assertEqual(evidence["author_written_reasoning_conditions"],14)
        self.assertEqual(evidence["exact_AB_presentations"],28)
        self.assertEqual(evidence["shortcuts"],14)
        self.assertEqual(len(evidence["baselines"]),14)
        self.assertEqual([x["baseline"] for x in evidence["baselines"]],
                         list(o.EXPECTED_ROSTER_NAMES))
        self.assertEqual(evidence["status"],o.STATUS)
        self.assertEqual(evidence["audit_design"],o.ROSTER_STATUS)
        self.assertEqual(evidence["source_report_sha256"],o.sha256(self.sraw))
        self.assertEqual(evidence["casebook_sha256"],o.sha256(self.craw))
        self.assertEqual(evidence["original_phase4g_simple_cue_rule_agreement_out_of_14"],
                         self.old["language_shortcut_author_agreements"])
        self.assertEqual(evidence["independent_appsec_gold_labels"],0)
        self.assertFalse(evidence["foundation_model_called"])
        self.assertFalse(evidence["model_improvement_or_network_ranking_proven"])
        self.assertFalse(evidence["trained_evaluator"])
        self.assertFalse(evidence["registered_evaluator"])
        self.assertTrue(evidence["expert_source_review_still_needed"])
        self.assertFalse(evidence["no_new_project_holdout"] is False)

    def test_a_b_constants_cannot_gamble_better_than_seven_original_or_fourteen_swaps(self):
        result=o.audit(self.sraw,self.craw)
        for name in ("constant_A","constant_B"):
            rule=next(r for r in result["baselines"] if r["baseline"]==name)
            self.assertEqual(rule["author_hypothesis_agreements_across_14_original_displays"],7)
            self.assertEqual(rule["author_hypothesis_agreements_across_28_swapped_displays"],14)
            self.assertEqual(rule["same_answer_chosen_after_AB_swap_out_of_14"],0)

    def test_score_concept_remains_researcher_hypothesis_not_expert_accuracy(self):
        result=o.audit(self.sraw,self.craw)
        for rule in result["baselines"]:
            self.assertIn("author_hypothesis_agreements",str(rule))
            self.assertTrue(rule["not_security_accuracy"])
            self.assertGreaterEqual(rule["author_hypothesis_agreements_across_28_swapped_displays"],0)
            self.assertLessEqual(rule["author_hypothesis_agreements_across_28_swapped_displays"],28)
            self.assertLessEqual(rule["same_answer_chosen_after_AB_swap_out_of_14"],14)
        self.assertTrue(result["old_public_sources_previously_studied"])
        self.assertFalse(result["model_improvement_or_network_ranking_proven"])
        self.assertEqual(result["new_anjoman_rows"],0)

    def test_no_prompt_answer_or_known_author_winner_leaks_into_summary(self):
        report=json.dumps(o.audit(self.sraw,self.craw),sort_keys=True)
        for case in self.casebook["cases"]:
            self.assertNotIn(case["question"],report)
            for present in case["presentations"]:
                for answer in present["candidate_answers"]:
                    self.assertNotIn(answer["text"],report)
        for marker in ("expert_label","training_allowed","author_correct","true_positive"):
            self.assertNotIn('"'+marker+'"',report)

    def test_change_answers_fails_even_if_attacker_updates_sha_and_swaps(self):
        v=copy.deepcopy(self.casebook)
        for present in v["cases"][0]["presentations"]:
            a=present["candidate_answers"][0]
            a["text"]="This fake new answer is not source-backed. "*4
            a["sha256"]=hashlib.sha256(a["text"].encode()).hexdigest()
        with self.assertRaisesRegex((ValueError,TypeError),"casebook differs"):
            o.audit(self.sraw,raw(v))

    def test_change_source_or_published_identity_fails_closed(self):
        v=copy.deepcopy(self.source)
        v["review_packets"][0]["fix_commit"]="0"*40
        with self.assertRaises((ValueError,TypeError,KeyError)):
            o.audit(raw(v),self.craw)
        v=copy.deepcopy(self.source)
        v["independent_human_labels"]=1
        with self.assertRaises((ValueError,TypeError,KeyError)):
            o.audit(raw(v),self.craw)

    def test_fake_expert_label_fails(self):
        v=copy.deepcopy(self.casebook)
        v["cases"][0]["expert_label"]="A"
        with self.assertRaises((ValueError,TypeError,KeyError)):
            o.audit(self.sraw,raw(v))

    def test_unapproved_score_or_network_promotion_fails(self):
        v=copy.deepcopy(self.casebook)
        v["registered_evaluator"]=True
        with self.assertRaises(ValueError):
            o.audit(self.sraw,raw(v))
        v=copy.deepcopy(self.casebook)
        v["new_independent_human_gold_labels"]=1
        with self.assertRaises(ValueError):
            o.audit(self.sraw,raw(v))

    def test_changed_swap_candidate_ids_fail(self):
        v=copy.deepcopy(self.casebook)
        v["cases"][0]["presentations"][1]["candidate_answers"].reverse()
        with self.assertRaises(ValueError):
            o.audit(self.sraw,raw(v))

    def test_no_extra_or_missing_case_is_allowed(self):
        v=copy.deepcopy(self.casebook)
        v["cases"].pop()
        with self.assertRaises(ValueError):
            o.audit(self.sraw,raw(v))
        v=copy.deepcopy(self.casebook)
        v["cases"].append(copy.deepcopy(v["cases"][0]))
        with self.assertRaises(ValueError):
            o.audit(self.sraw,raw(v))

    def test_stale_or_empty_source_and_noncanonical_text_fail(self):
        for source,casebook in (
            (b"",self.craw), (self.sraw,b""), (self.sraw,b"INVALID JSON"),
            (b"{}",self.craw), (self.sraw,raw([])),
        ):
            with self.subTest(source_len=len(source),cb_len=len(casebook)):
                with self.assertRaises((ValueError,TypeError,KeyError)):
                    o.audit(source,casebook)

    def test_tie_default_is_position_biased_and_exposed(self):
        q="What is the exact security boundary?"
        answers=[
            {"position":"A","text":"Security path is conditional."},
            {"position":"B","text":"Requires version and evidence."},
        ]
        for field in ("characters","words","qualifying_cues","strong_certainty_cues"):
            val1=o.feature_vector(q,answers[0]["text"])[field]
            val2=o.feature_vector(q,answers[1]["text"])[field]
            if val1==val2:
                rule=("synthetic",field,"min")
                self.assertEqual(o.choose(q,answers,rule),"A")
                self.assertEqual(o.choose(q,[dict(answers[1],position="A"),
                                               dict(answers[0],position="B")],rule),"A")

    def test_cannot_open_wrong_output_on_top_of_source_or_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            src=root/"source.json"; src.write_bytes(self.sraw)
            cb=root/"casebook.json"; cb.write_bytes(self.craw)
            out=root/"audit.json"
            self.assertEqual(o.main(["--source",str(src),"--casebook",str(cb),
                                     "--out",str(out)]),0)
            data=json.loads(out.read_text())
            self.assertEqual(data["independent_appsec_gold_labels"],0)
            self.assertEqual(data["shortcuts"],14)
            with self.assertRaises(SystemExit):
                o.main(["--source",str(src),"--casebook",str(cb),"--out",str(out)])
            with self.assertRaises(SystemExit):
                o.main(["--source",str(src),"--casebook",str(cb),"--out",str(src)])
            self.assertEqual(src.read_bytes(),self.sraw)

    def test_roster_and_precommitted_warning_threshold_cannot_be_silently_weakened(self):
        self.assertEqual(o.THRESHOLD_OUT_OF_14,11)
        self.assertEqual(o.ROSTER[0],("constant_A",None,"A"))
        self.assertEqual(o.ROSTER[1],("constant_B",None,"B"))
        self.assertEqual(tuple(r[0] for r in o.ROSTER),o.EXPECTED_ROSTER_NAMES)
        data=o.audit(self.sraw,self.craw)
        expected=[r["baseline"] for r in data["baselines"]
                  if r["author_hypothesis_agreements_across_14_original_displays"]>=11
                  or r["author_hypothesis_agreements_across_28_swapped_displays"]>=22]
        self.assertEqual(data["flagged_baselines"],expected)
        self.assertEqual(data["flags_high_shortcut_risk"],bool(expected))


if __name__=="__main__":
    unittest.main()
