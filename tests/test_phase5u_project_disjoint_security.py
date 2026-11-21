"""Phase 5U: new project-disjoint original upstream source lock and source-blind proof."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5u_project_disjoint_security as u
from falsum.phase5m_real_source_sensitive_model import ROOT, DiagnosticError, sha, canonical_json
from falsum.phase5l_pymdown_upstream_replay import git_blob


def synthetic_labels():
    return {
        u.ident(project,revision,position):
            ("ABSTAIN" if revision=="source-omitted"
             else ("A" if (revision=="parent")==(position=="original-order") else "B"))
        for project in u.PROJECTS
        for revision in u.REVISIONS
        for position in u.POSITIONS
    }


def synthetic_challenge():
    return {"status":u.ST_CHALLENGE,
            "questions":[{"id":x,"messages":[{"role":"user","content":"synthetic"}]}
                         for x in synthetic_labels()]}


class ProjectDisjointSourceTest(unittest.TestCase):
    def test_frozen_git_blob_and_prior_source_exclusion(self):
        p=u.frozen()
        self.assertEqual(git_blob((ROOT/u.LOCK).read_bytes()),u.LOCK_GIT_BLOB)
        self.assertEqual(p["total_prompts"],24)
        self.assertEqual(p["new_historical_security_fix_count"],4)
        self.assertEqual(p["source_project_count"],4)
        self.assertEqual(p["new_source_file_revision_count"],8)
        self.assertEqual(p["new_upstream_test_file_revision_count"],8)
        self.assertEqual(p["independent_appsec_gold_count"],0)
        self.assertFalse(p["full_original_upstream_regression_tests_executed_by_this_stage"])
        self.assertFalse(p["hidden_private_holdout"])
        self.assertFalse(p["model_pretraining_disjoint"])
        self.assertTrue(p["researcher_authored_reference_choices"])
        self.assertEqual(tuple(x["key"] for x in p["cases"]),u.PROJECTS)
        self.assertEqual(tuple(x["repository"] for x in p["cases"]),u.KNOWN_REPOS)
        prior={"pyjwt","werkzeug","mcp-python","pillow","koa-redirect",
               "hono-csrf","langchain-path","langchain-symlink","flask"}
        self.assertFalse(prior & set(u.PROJECTS))

    def test_every_new_original_source_and_test_blob_sha_is_distinct(self):
        p=u.frozen()
        for case in p["cases"]:
            with self.subTest(project=case["key"]):
                self.assertNotEqual(case["parent_commit"],case["fixed_commit"])
                self.assertNotEqual(case["parent_source_blob"],case["fixed_source_blob"])
                self.assertNotEqual(case["parent_test_blob"],case["fixed_test_blob"])
                self.assertEqual(len(case["source_path"].split("/"))<=3,True)
                self.assertTrue(case["fixed_test_anchor"])
                self.assertTrue(case["advisory"].startswith("GHSA-"))

    def test_balanced_reference_and_source_blind_upper_bound(self):
        references=synthetic_labels()
        self.assertEqual(len(references),24)
        self.assertEqual(Counter(references.values()),{"A":8,"B":8,"ABSTAIN":8})
        score=u.score(references,u.baseline(),
                      origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")
        self.assertEqual(score["matches_to_researcher_derived_public_references"],16)
        self.assertEqual(score["source_present_matches"],8)
        self.assertEqual(score["source_absent_correct_abstention"],8)
        self.assertEqual(score["complete_correct_four_way_source_and_answer_reversals"],0)
        self.assertEqual(score["prompt_only_source_hidden_maximum_matches"],16)
        self.assertEqual(score["prompt_only_source_hidden_maximum_complete_four_way"],0)
        self.assertFalse(score["new_model_inference_verified"])
        self.assertEqual(score["independent_appsec_gold"],0)

    def test_perfect_constructed_answer_key_not_independent_gold(self):
        references=synthetic_labels()
        score=u.score(references,references,
                      origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")
        self.assertEqual(score["matches_to_researcher_derived_public_references"],24)
        self.assertEqual(score["complete_correct_four_way_source_and_answer_reversals"],4)
        self.assertFalse(score["new_model_inference_verified"])
        self.assertTrue(score["public_lookup_attacker_not_excluded"])

    def test_always_abstain_weak_and_wrong_constant_controls(self):
        refs=synthetic_labels()
        for constant,correct in (("A",8),("B",8),("ABSTAIN",8)):
            score=u.score(refs,{k:constant for k in refs},
                          origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")
            self.assertEqual(score["matches_to_researcher_derived_public_references"],correct)
            self.assertEqual(score["complete_correct_four_way_source_and_answer_reversals"],0)

    def test_source_excerpt_requires_original_verified_anchor(self):
        js="\n".join(["var opts = options;"]*12+
                     ["    this.idx = {};"]+
                     ["some_other_line();"]*20)
        result=u._excerpt(js,"this.idx = {};")
        self.assertIn("this.idx = {};",result)
        with self.assertRaises((DiagnosticError,ValueError)):
            u._excerpt(js,"not an original source anchor")
        source="\n".join(["noop();"]*12+
                        ["guard();"]+
                        ["noop();"]*12+
                        ["function isConstructorOrProto (obj, key) {"]+
                        ["return true;"]*3)
        out=u._excerpt(source,"guard();",
                       "function isConstructorOrProto (obj, key) {")
        self.assertIn("function isConstructorOrProto",out)
        with self.assertRaises((DiagnosticError,ValueError)):
            u._excerpt(source,"guard();","missing helper")

    def test_write_once_and_forged_candidates_fail(self):
        doc=synthetic_challenge()
        empty=u.template(doc)
        self.assertEqual(len(empty["decisions"]),24)
        self.assertTrue(all(x["choice"] is None for x in empty["decisions"]))
        selected=deepcopy(empty)
        for item in selected["decisions"]:
            item["choice"]="ABSTAIN"
        verified=u.validated_candidate(doc,selected)
        self.assertEqual(len(verified),24)
        variants=[
            lambda p:p["decisions"].pop(),
            lambda p:p["decisions"].reverse(),
            lambda p:p["decisions"][0].update(choice=None),
            lambda p:p["decisions"][0].update(choice="APPSEC_EXPERT_APPROVED"),
            lambda p:p["decisions"][0].update(extra="gold"),
            lambda p:p.update(challenge_sha256="0"*64),
            lambda p:p.update(status="INDEPENDENT_APPSEC_GOLD"),
        ]
        for edit in variants:
            response=deepcopy(selected)
            edit(response)
            with self.assertRaises((DiagnosticError,ValueError,TypeError)):
                u.validated_candidate(doc,response)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"source-proof.json"
            u._write(path,{"safe":True})
            with self.assertRaises((DiagnosticError,ValueError)):
                u._write(path,{"safe":False})

    def test_original_preregistered_freeze_bytes_tampered_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            p=root/u.LOCK
            p.parent.mkdir(parents=True)
            p.write_bytes((ROOT/u.LOCK).read_bytes()+b" ")
            with self.assertRaises((DiagnosticError,ValueError)):
                u.frozen(root)

    def test_unknown_project_revision_or_origin_cannot_forge_score(self):
        with self.assertRaises((DiagnosticError,ValueError)):
            u.ident("invented","parent","original-order")
        with self.assertRaises((DiagnosticError,ValueError)):
            u.ident("minimist-constructor","future","original-order")
        refs=synthetic_labels()
        with self.assertRaises((DiagnosticError,ValueError)):
            u.score(refs,refs,origin="QUALIFIED_EXPERT_GOLD")
        with self.assertRaises((DiagnosticError,ValueError)):
            u.score(refs,{k:"INVALID" for k in list(refs)[:23]},
                    origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")


if __name__=="__main__":
    unittest.main()
