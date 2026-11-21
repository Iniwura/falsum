"""Phase 5S source-blind upper bound, four-way reversal, exact frozen source."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5s_counterbalanced_source_invariance as s
from falsum import phase5p_raw_code_evaluator as p5
from falsum.phase5m_real_source_sensitive_model import ROOT, DiagnosticError, sha, canonical_json


def synthetic_original():
    """Offline stub for scorer tests ONLY; not actual upstream authentication."""
    p,source=p5.frozen()
    rows=[]
    refs={}
    for spec,case in zip(p["project_specs"],source["cases"]):
        project=spec["key"]
        for cond,revision in (("code-a","parent"),
                              ("code-b","fixed"),("source-omitted",None)):
            key=p5.ident(project,cond)
            code=("[SOURCE FILE OMITTED: no revision or implementation is provided]"
                  if revision is None else
                  "def test_historical_source_control():\n    return "+
                  repr("prior source" if revision=="parent" else "fixed source"))
            rows.append({
                "id":key,"project":project,
                "source_git_commit":(case[revision] if revision else None),
                "source_excerpt":code,"source_excerpt_sha256":sha(code.encode()),
            })
            refs[key]="ABSTAIN" if revision is None else "A"
    return ({
        "schema_version":1,"status":p5.ST_PREP,
        "frozen_protocol_git_blob_sha1":p5.PROTOCOL_BLOB,
        "source_lock_git_blob_sha1":p5.SOURCE_BLOB,
        "source_files_downloaded_git_blob_verified":True,
        "reference_is_public_researcher_derived":True,
        "independent_appsec_gold":0,
        "questions":rows,
    },refs)


class FourWaySourceInvarianceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge,cls.labels=s.build(source_build=synthetic_original)
        cls.index={r["id"]:r for r in cls.challenge["questions"]}

    def test_frozen_protocol_is_true_separate_preinference_blob(self):
        self.assertEqual(s.p5.git_blob((ROOT/s.LOCK_PATH).read_bytes()),s.LOCK_SHA1)
        f=s.frozen()
        self.assertEqual(f["max_input_tokens"],1024)
        self.assertEqual(f["number_of_tasks"],24)
        self.assertEqual(f["source_blind_best_possible_total_matches"],16)
        self.assertEqual(f["source_blind_primary_complete_reversal_upper_bound"],0)
        self.assertTrue(f["no_hidden_model_holdout"])
        self.assertEqual(f["independent_appsec_gold"],0)

    def test_source_version_plus_option_swap_class_balance(self):
        self.assertEqual(len(self.challenge["questions"]),24)
        self.assertEqual(Counter(self.labels.values()),
                         {"A":8,"B":8,"ABSTAIN":8})
        self.assertEqual(len(self.index),24)
        for project in s.PROJECTS:
            for pos in s.POSITIONS:
                a=self.labels[s.ident(project,"parent",pos)]
                b=self.labels[s.ident(project,"fixed",pos)]
                self.assertNotEqual(a,b)
                self.assertEqual(self.labels[s.ident(project,"source-omitted",pos)],
                                 "ABSTAIN")

    def test_masked_prompt_has_no_revision_channel(self):
        for project in s.PROJECTS:
            for pos in s.POSITIONS:
                original=self.index[s.ident(project,"parent",pos)]["messages"][1]["content"]
                fixed=self.index[s.ident(project,"fixed",pos)]["messages"][1]["content"]
                cp=("def test_historical_source_control():\n    return 'prior source'")
                cf=("def test_historical_source_control():\n    return 'fixed source'")
                self.assertIn(cp,original)
                self.assertIn(cf,fixed)
                self.assertEqual(original.replace(cp,"[SOURCE MASKED]"),
                                 fixed.replace(cf,"[SOURCE MASKED]"))
        for q in self.challenge["questions"]:
            self.assertEqual(set(q),{"id","messages","prompt_sha256"})
            self.assertEqual(q["prompt_sha256"],sha(q["messages"][1]["content"].encode()))
            self.assertNotIn("source_git_commit",q)
            self.assertNotIn("project",q)

    def test_no_source_avoids_answer_on_both_position_orders(self):
        for project in s.PROJECTS:
            for pos in s.POSITIONS:
                content=self.index[s.ident(project,"source-omitted",pos)]["messages"][1]["content"]
                self.assertIn("[SOURCE FILE OMITTED:",content)
                self.assertIn("ABSTAIN",content)
                self.assertEqual(self.labels[s.ident(project,"source-omitted",pos)],
                                 "ABSTAIN")

    def test_source_blind_baseline_max_16_and_no_fully_correct_reversals(self):
        predictions=s.source_blind_baseline()
        scored=s.score(self.labels,predictions,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(scored["matches_to_public_researcher_references"],16)
        self.assertEqual(scored["source_present_matches"],8)
        self.assertEqual(scored["correct_no_source_abstentions"],8)
        self.assertEqual(scored["complete_correct_four_way_source_and_position_reversals"],0)
        self.assertEqual(scored["source_blind_prompt_only_upper_bound_total_matches"],16)
        self.assertEqual(scored["source_blind_prompt_only_upper_bound_four_way_reversals"],0)
        self.assertTrue(scored["public_answer_key_lookup_attacker_can_cheat"])
        self.assertEqual(scored["independent_appsec_gold"],0)

    def test_synthetic_oracle_perfect_and_always_abstain_control(self):
        scored=s.score(self.labels,self.labels,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(scored["matches_to_public_researcher_references"],24)
        self.assertEqual(scored["complete_correct_four_way_source_and_position_reversals"],4)
        self.assertEqual(scored["source_present_matches"],16)
        self.assertEqual(scored["correct_no_source_abstentions"],8)
        blank={k:"ABSTAIN" for k in self.labels}
        result=s.score(self.labels,blank,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(result["matches_to_public_researcher_references"],8)
        self.assertEqual(result["unnecessary_abstentions_with_code"],16)
        self.assertEqual(result["complete_correct_four_way_source_and_position_reversals"],0)
        bad={k:"INVALID" for k in self.labels}
        invalid=s.score(self.labels,bad,origin="DISCLOSED_SYNTHETIC_BASELINE")
        self.assertEqual(invalid["invalid_outputs"],24)
        self.assertEqual(invalid["matches_to_public_researcher_references"],0)

    def test_strict_candidate_protocol_and_no_pretend_adoption(self):
        template=s.response_template(self.challenge)
        self.assertTrue(all(r["choice"] is None for r in template["decisions"]))
        filled=deepcopy(template)
        for row in filled["decisions"]:
            row["choice"]="ABSTAIN"
        checked=s.validate_responses(self.challenge,filled)
        self.assertEqual(len(checked),24)
        operations=[
            lambda d:d["decisions"].pop(),
            lambda d:d["decisions"].reverse(),
            lambda d:d["decisions"][0].update(choice="INVALID"),
            lambda d:d["decisions"][0].update(choice=None),
            lambda d:d["decisions"][0].update(extra="expert-approved"),
            lambda d:d.update(challenge_sha256="0"*64),
            lambda d:d.update(status="INDEPENDENT_GOLD"),
        ]
        for transform in operations:
            wrong=deepcopy(filled)
            transform(wrong)
            with self.assertRaises((DiagnosticError,ValueError,TypeError)):
                s.validate_responses(self.challenge,wrong)

    def test_unknown_revisions_predictions_and_model_identity_blocked(self):
        with self.assertRaises((DiagnosticError,ValueError)):
            s.ident("new-project","parent","original-order")
        with self.assertRaises((DiagnosticError,ValueError)):
            s.score(self.labels,{k:"A" for k in list(self.labels)[:23]},
                    origin="DISCLOSED_SYNTHETIC_BASELINE")
        with self.assertRaises((DiagnosticError,ValueError)):
            s.score(self.labels,self.labels,origin="QUALIFIED_HUMAN_GOLD")

    def test_sha_mutation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            a=root/s.LOCK_PATH
            a.parent.mkdir(parents=True)
            a.write_bytes((ROOT/s.LOCK_PATH).read_bytes()+b"\n")
            with self.assertRaises((DiagnosticError,ValueError)):
                s.frozen(root)


if __name__=="__main__":
    unittest.main()
