"""Research training split, reversible candidates and release-quarantine tests."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3k_intervention import (
    InterventionError, SOURCE_PROJECTS, TRANSFER_EXCLUDED, VARIANTS,
    make_experiment, validate_base,
)
from falsum.phase3k_transfer_compare import assess, Phase3KCompareError

ROOT=Path(__file__).resolve().parents[1]


def base_rows():
    return [
        {"prompt":f"Original research-only advisory prompt {i} with deployment details.",
         "chosen":f"Original better historical research answer {i}.",
         "rejected":f"Original opposite historical research answer {i}."}
        for i in range(52)
    ]


def fake_pairs():
    return [(
        {"case_id":f"{project}-{i}","question":"synthetic task","candidate_a":"answer a","candidate_b":"answer b"},
        {"case_id":f"{project}-{i}","source_project":project,"ai_proposed_kind":"finding" if i==0 else "conditional"}
    ) for project in TRANSFER_EXCLUDED for i in range(2)]


class Phase3KResearchBoundary(unittest.TestCase):
    def test_52_base_rows_required(self):
        validate_base(base_rows())
        with self.assertRaises(InterventionError):
            validate_base(base_rows()[:-1])

    def test_balanced_train_pairs_with_exact_answer_swaps(self):
        rows,manifest=make_experiment(ROOT,base_rows())
        self.assertEqual(len(rows),60)
        self.assertEqual(manifest["known_runtime_context_training_pairs"],8)
        self.assertEqual(manifest["seen_training_projects"],list(SOURCE_PROJECTS))
        self.assertEqual(manifest["already_inspected_transfer_projects_excluded"],list(TRANSFER_EXCLUDED))
        self.assertFalse(manifest["network_eligible"])
        self.assertTrue(manifest["previously_scored_starlette_requests_no_longer_valid_as_holdouts"])
        additions=rows[52:]
        for j in range(0,8,2):
            self.assertEqual(additions[j]["chosen"],additions[j+1]["rejected"])
            self.assertEqual(additions[j]["rejected"],additions[j+1]["chosen"])
            self.assertNotEqual(additions[j]["prompt"],additions[j+1]["prompt"])

    def test_no_synthetic_data_claimed_independent_human_label(self):
        _,d=make_experiment(ROOT,base_rows())
        self.assertEqual(d["independent_human_approved_labels"],0)
        self.assertFalse(d["training_or_labels_authorized_for_submittable_network_module"])
        self.assertFalse(d["source_separated_transfer_previously_inspected_not_sealed"] is False)
        self.assertTrue(d["original_model_release_veto_remains"])

    def test_duplicate_prompt_or_negative_in_baseline_fails(self):
        for key in ("prompt","rejected"):
            with self.subTest(key=key):
                rows=base_rows()
                rows[1][key]=rows[0][key]
                with self.assertRaises(InterventionError):
                    make_experiment(ROOT,rows)

    def test_source_provenance_field_is_original_pinned_run(self):
        _,d=make_experiment(ROOT,base_rows())
        self.assertEqual(d["source_runtime_evidence"]["phase3h_runtime_workflow"],
                         "https://github.com/Iniwura/falsum/actions/runs/41409503521")
        self.assertEqual(d["source_runtime_evidence"]["phase3i_runtime_workflow"],
                         "https://github.com/Iniwura/falsum/actions/runs/41410209502")

    def test_training_bytes_have_unique_prompts_and_opposite_responses(self):
        rows,_=make_experiment(ROOT,base_rows())
        self.assertEqual(len({r["prompt"] for r in rows}),60)
        self.assertEqual(len({r["rejected"] for r in rows}),60)
        self.assertTrue(all(r["chosen"]!=r["rejected"] for r in rows))

    def test_transfer_report_allows_negative_scores_with_no_eligibility_claim(self):
        _,new=make_experiment(ROOT,base_rows())
        with patch("falsum.phase3k_transfer_compare.verify",return_value=fake_pairs()):
            result=assess({}, {}, {}, new,
                          {"family_count":3,"total_ai_proposals":6,
                           "ai_proposals_matched":2,"families_matching_both_ai_proposals":0},
                          {"family_count":3,"total_ai_proposals":6,
                           "ai_proposals_matched":1,"families_matching_both_ai_proposals":0},
                          {"sha256":"a"*64},{"sha256":"b"*64})
        self.assertEqual(result["observed_delta_context_matches"],-1)
        self.assertFalse(result["model_accuracy_independently_certified"])
        self.assertTrue(result["original_release_veto_still_applies"])
        self.assertFalse(result["network_eligible"])

    def test_transfer_requires_disjoint_sources_not_a_blind_accuracy_claim(self):
        _,new=make_experiment(ROOT,base_rows())
        bad=copy.deepcopy(new)
        bad["seen_training_projects"]=[TRANSFER_EXCLUDED[0],SOURCE_PROJECTS[1]]
        with patch("falsum.phase3k_transfer_compare.verify",return_value=fake_pairs()):
            with self.assertRaises(Phase3KCompareError):
                assess({}, {}, {}, bad,
                       {"family_count":3,"total_ai_proposals":6,"ai_proposals_matched":3,"families_matching_both_ai_proposals":1},
                       {"family_count":3,"total_ai_proposals":6,"ai_proposals_matched":4,"families_matching_both_ai_proposals":1},
                       {"sha256":"a"*64},{"sha256":"b"*64})

    def test_identical_model_artifact_must_not_be_called_new(self):
        _,new=make_experiment(ROOT,base_rows())
        scores={"family_count":3,"total_ai_proposals":6,"ai_proposals_matched":3,
                "families_matching_both_ai_proposals":1}
        with patch("falsum.phase3k_transfer_compare.verify",return_value=fake_pairs()):
            with self.assertRaises(Phase3KCompareError):
                assess({}, {}, {}, new, scores,scores,{"sha256":"a"*64},{"sha256":"a"*64})


if __name__=="__main__":
    unittest.main()
