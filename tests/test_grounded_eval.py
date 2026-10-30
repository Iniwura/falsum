"""Offline synthetic advisory fixtures: not real/security-reviewed cases."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.grounded_eval import (GroundingError, build_grounded, diagnostic_report,
                                  evaluate_scores, _range_evidence)
from test_review_gate import fixture


class GroundingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'source'
        self.root.mkdir()
        self.queue,self.corpus=fixture(self.root)
        self.benchmark=build_grounded(self.queue,self.corpus,self.root)

    def test_explicit_boundaries_provided_in_every_prompt(self):
        self.assertEqual(len(self.benchmark['grounded']),64)
        self.assertTrue(all('introduced (inclusive): 0' in row['prompt']
                            and 'fixed (exclusive): 2.4.1' in row['prompt']
                            for row in self.benchmark['grounded']))
        self.assertTrue(all(row['review_status']=='draft' for row in self.benchmark['grounded']))

    def test_missing_evidence_challenges_instead_of_groundless_claims(self):
        self.assertEqual(len(self.benchmark['insufficient_evidence']),32)
        for row in self.benchmark['insufficient_evidence']:
            self.assertNotIn('fixed (exclusive)', row['prompt'])
            self.assertIn('cannot be classified', row['chosen'])
            self.assertIn('confirmed affected', row['rejected'])
            self.assertNotIn('affected-version bounds', row['prompt'])

    def test_case_splits_preserved(self):
        report=diagnostic_report(self.benchmark)
        self.assertEqual(report['grounded_by_split'],{'train':52,'validation':6,'holdout':6})
        self.assertEqual(report['unique_advisories'],32)
        self.assertFalse(report['network_accepted'])
        self.assertFalse(report['model_evaluated'])

    def test_grounded_corpus_can_not_be_marked_reviewed(self):
        edited=copy.deepcopy(self.corpus)
        edited['cases'][0]['review_status']='reviewed'
        with self.assertRaises(Exception):
            build_grounded(self.queue,edited,self.root)

    def test_multiple_disjoint_ranges_preserved(self):
        record={'id':'GHSA-aaaa-bbbb-cccc','affected':[{'package':{'ecosystem':'npm','name':'pkg'},
            'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.4.1'}]},
                      {'type':'ECOSYSTEM','events':[{'introduced':'3.0.0'},{'fixed':'3.2.1'}]}]}]}
        evidence=_range_evidence(record,'npm','pkg','2.4.0')
        self.assertIn('2.4.1',evidence)
        self.assertIn('3.2.1',evidence)

    def test_all_five_ranges_from_multi_branch_advisory_are_kept(self):
        record={'id':'GHSA-aaaa-bbbb-cccc','affected':[
            {'package':{'ecosystem':'npm','name':'pkg'},
             'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':str(i)+'.0.0'},
                     {'fixed':str(i)+'.1.0'}]}]} for i in range(1,6)]}
        output=_range_evidence(record,'npm','pkg','2.0.1')
        self.assertEqual(output.count('fixed (exclusive)'),5)
        self.assertIn('5.1.0',output)

    def test_reject_prerelease_boundary(self):
        record={'id':'GHSA-aaaa-bbbb-cccc','affected':[{'package':{'ecosystem':'npm','name':'pkg'},
            'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.4.1rc1'}]}]}]}
        with self.assertRaisesRegex(GroundingError,'unsupported version'):
            _range_evidence(record,'npm','pkg','2.4.0')

    def test_reject_missing_source_snapshot(self):
        (self.root/'snapshots'/f"{self.queue['advisories'][0]['id']}.json").unlink()
        with self.assertRaises(Exception):
            build_grounded(self.queue,self.corpus,self.root)

    def test_reject_tampered_source(self):
        path=self.root/'snapshots'/f"{self.queue['advisories'][0]['id']}.json"
        path.write_text(path.read_text()+'x')
        with self.assertRaises(Exception):
            build_grounded(self.queue,self.corpus,self.root)

    def test_evaluate_scores_ties_and_unseen_splits(self):
        cases=self.benchmark['grounded']
        scores={x['id']:(1.0,0.0) if x['split']=='train' else (0.0,0.0) for x in cases}
        report=evaluate_scores(cases,scores)
        self.assertEqual(report['by_split']['train']['pairwise_accuracy'],1.0)
        self.assertEqual(report['by_split']['holdout']['pairwise_accuracy'],0.5)

    def test_missing_scores_denied(self):
        with self.assertRaisesRegex(GroundingError,'every'):
            evaluate_scores(self.benchmark['grounded'],{})

    def test_nonfinite_scores_denied(self):
        scores={x['id']:(1.0,0.0) for x in self.benchmark['grounded']}
        scores[self.benchmark['grounded'][0]['id']]=(float('nan'), 0.0)
        with self.assertRaisesRegex(GroundingError,'finite'):
            evaluate_scores(self.benchmark['grounded'],scores)

    def test_no_label_change_on_benchmark(self):
        for old,new in zip(self.corpus['cases'],self.benchmark['grounded']):
            self.assertEqual((old['id'],old['chosen'],old['rejected'],old['split']),
                             (new['id'],new['chosen'],new['rejected'],new['split']))


if __name__=='__main__':
    unittest.main()
