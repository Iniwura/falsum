"""Adversarial tests for a fictional, UNREVIEWED PR-scoring challenge."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.pr_benchmark import (PRBenchmarkError, SurfaceNaiveBayes,
                                 baseline_report, load_verified)

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / 'data/draft-pr-benchmark.json'
SOURCE = ROOT / 'data/draft-scenarios.json'


class PRBenchmarkTests(unittest.TestCase):
    def test_all_twelve_reconstructed_and_source_checked(self):
        data = load_verified(BENCH, SOURCE)
        self.assertEqual(len(data['cases']), 12)
        self.assertEqual({x['split'] for x in data['cases']}, {'train', 'validation', 'holdout'})
        self.assertEqual(len({x['rule_family'] for x in data['cases']}), 6)
        self.assertTrue(all(x['review_status'] == 'draft' for x in data['cases']))

    def test_competing_answers_swap_labels_per_scenario_family(self):
        data = load_verified(BENCH, SOURCE)
        groups = {}
        for case in data['cases']:
            groups.setdefault(case['rule_family'], []).append(case)
        for pair in groups.values():
            self.assertEqual(pair[0]['contrast_chosen'], pair[1]['contrast_rejected'])
            self.assertEqual(pair[0]['contrast_rejected'], pair[1]['contrast_chosen'])

    def test_answer_only_baseline_detects_original_style_tell(self):
        data = load_verified(BENCH, SOURCE)
        original = baseline_report(data['cases'])
        self.assertEqual(original['results']['validation']['pairwise_fraction'], 1.0)
        self.assertEqual(original['results']['holdout']['pairwise_fraction'], 1.0)

    def test_counterfactual_baseline_cannot_win_without_context(self):
        data = load_verified(BENCH, SOURCE)
        blind = baseline_report(data['cases'], use_contrast=True)
        for split in ('validation', 'holdout'):
            self.assertEqual(blind['results'][split]['pairwise_fraction'], 0.5)

    def test_training_rejects_non_training_rows(self):
        data = load_verified(BENCH, SOURCE)
        model = SurfaceNaiveBayes()
        with self.assertRaises(PRBenchmarkError):
            model.fit(data['cases'])

    def test_model_refuses_score_before_fit(self):
        with self.assertRaises(PRBenchmarkError):
            SurfaceNaiveBayes().score('example answer')

    def test_modified_source_casebook_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'casebook.json'
            path.write_bytes(SOURCE.read_bytes() + b' ')
            with self.assertRaises(PRBenchmarkError):
                load_verified(BENCH, path)

    def _tamper(self, callback):
        data = json.loads(BENCH.read_text(encoding='utf-8'))
        callback(data)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'pr.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            with self.assertRaises(PRBenchmarkError):
                load_verified(path, SOURCE)

    def test_premature_review_claim_rejected(self):
        self._tamper(lambda b: b['cases'][0].update(review_status='reviewed'))

    def test_missing_diff_context_rejected(self):
        self._tamper(lambda b: b['cases'][0].update(prompt='Return security verdict.'))

    def test_wrong_label_on_context_rejected(self):
        self._tamper(lambda b: b['cases'][0].update(chosen=b['cases'][0]['rejected']))

    def test_unswapped_counterfactual_is_rejected(self):
        self._tamper(lambda b: b['cases'][1].update(contrast_chosen='We guarantee safety here, no matter what facts.' * 2))

    def test_cross_split_source_leak_rejected(self):
        self._tamper(lambda b: b['cases'][0].update(split='holdout'))

    def test_duplicate_patch_rejected(self):
        self._tamper(lambda b: b['cases'][1].update(patch=b['cases'][0]['patch'],
                    prompt=b['cases'][1]['prompt']+b['cases'][0]['patch']))

    def test_public_credential_pattern_rejected(self):
        self._tamper(lambda b: b['cases'][0].update(patch=b['cases'][0]['patch']+'\n+secret=ghp_'+'A'*38,
                           prompt=b['cases'][0]['prompt']+'\n+secret=ghp_'+'A'*38))

    def test_contaminated_blind_test_does_not_fit(self):
        data = load_verified(BENCH, SOURCE)
        train = [x for x in data['cases'] if x['split'] == 'train']
        heldout = [x for x in data['cases'] if x['split'] == 'holdout']
        self.assertFalse(set(x['rule_family'] for x in train) & set(x['rule_family'] for x in heldout))


if __name__ == '__main__':
    unittest.main()
