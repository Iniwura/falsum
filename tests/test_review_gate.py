"""Fail-closed provenance tests; mocked vulnerabilities are NOT accepted data."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.advisory_corpus import build_corpus
from falsum.review_gate import (ReviewGateError, audit_reproducibility,
                                blind_review_packet, write_review_packet)


def fixture(base):
    queue={'schema_version':1,'advisories':[]}
    docs={}
    for i in range(32):
        id=f'GHSA-{i:04x}-bbbb-cccc'
        package=f'fictional-test-lib-{i}'
        split='train' if i<26 else 'validation' if i<29 else 'holdout'
        queue['advisories'].append({'id':id,'ecosystem':'npm','package':package,
                                    'month':'2025/03','split':split})
        doc={'id':id,'summary':f'Fictional security advisory {i}',
             'affected':[{'package':{'ecosystem':'npm','name':package},
                          'ranges':[{'type':'ECOSYSTEM',
                                     'events':[{'introduced':'0'},{'fixed':'2.4.1'}]}]}]}
        raw=json.dumps(doc).encode()
        docs[id]=(doc,raw)
    (base/'snapshots').mkdir()
    for id,(_,raw) in docs.items():
        (base/'snapshots'/f'{id}.json').write_bytes(raw)
    return queue, build_corpus(queue, docs)


class ReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'corpus'
        self.root.mkdir()
        self.queue,self.corpus=fixture(self.root)

    def test_exact_reconstruction_passes(self):
        r=audit_reproducibility(self.queue,self.corpus,self.root)
        self.assertEqual(r['pairs'],64)
        self.assertFalse(r['telegraph_eligible'])
        self.assertFalse(r['model_training_authorized'])

    def test_reversed_preference_detected(self):
        c=copy.deepcopy(self.corpus)
        p=c['cases'][0]
        p['chosen'],p['rejected']=p['rejected'],p['chosen']
        with self.assertRaisesRegex(ReviewGateError,'case\\[0\\]'):
            audit_reproducibility(self.queue,c,self.root)

    def test_modified_prompt_detected(self):
        c=copy.deepcopy(self.corpus)
        c['cases'][5]['prompt']+=' Altered prompt.'
        with self.assertRaisesRegex(ReviewGateError,'case\\[5\\]'):
            audit_reproducibility(self.queue,c,self.root)

    def test_omitted_case_detected(self):
        c=copy.deepcopy(self.corpus)
        c['cases'].pop()
        with self.assertRaisesRegex(ReviewGateError,'count/order'):
            audit_reproducibility(self.queue,c,self.root)

    def test_forged_source_url_detected(self):
        c=copy.deepcopy(self.corpus)
        c['sources'][0]['url']='https://example.org/forged'
        with self.assertRaisesRegex(ReviewGateError,'sources differs'):
            audit_reproducibility(self.queue,c,self.root)

    def test_source_hash_forged_detected(self):
        c=copy.deepcopy(self.corpus)
        c['sources'][0]['sha256']='f'*64
        with self.assertRaisesRegex(ReviewGateError,'tampering'):
            audit_reproducibility(self.queue,c,self.root)

    def test_split_change_detected(self):
        c=copy.deepcopy(self.corpus)
        c['cases'][0]['split']='holdout'
        with self.assertRaises(ReviewGateError):
            audit_reproducibility(self.queue,c,self.root)

    def test_no_fake_review_claim(self):
        c=copy.deepcopy(self.corpus)
        c['cases'][0]['review_status']='reviewed'
        with self.assertRaises(ReviewGateError):
            audit_reproducibility(self.queue,c,self.root)

    def test_blinded_choices_counterbalanced(self):
        q,key=blind_review_packet(self.queue,self.corpus,self.root)
        self.assertEqual(len(q),64)
        self.assertEqual(len(key),64)
        self.assertGreater(sum(x['expected_preferred']=='A' for x in key), 15)
        self.assertGreater(sum(x['expected_preferred']=='B' for x in key), 15)
        self.assertNotIn('chosen',q[0])
        self.assertNotIn('expected_status',q[0])
        self.assertNotIn('expected_preferred',q[0])
        for question,truth,case in zip(q,key,self.corpus['cases']):
            self.assertEqual(question['candidate_'+truth['expected_preferred'].lower()],case['chosen'])

    def test_review_key_written_separately(self):
        review=Path(self.tmp.name)/'review'; private=Path(self.tmp.name)/'sealed'
        report=write_review_packet(self.queue,self.corpus,self.root,review,private)
        self.assertEqual(report['questions'],64)
        self.assertEqual(set(x.name for x in review.iterdir()), {'BLIND-QUESTIONS.jsonl','REVIEW-INSTRUCTIONS.md'})
        self.assertEqual(set(x.name for x in private.iterdir()),{'DO-NOT-SHARE-ANSWER-KEY.jsonl'})
        self.assertNotIn('expected_preferred',(review/'BLIND-QUESTIONS.jsonl').read_text())
        with self.assertRaisesRegex(ReviewGateError,'not empty'):
            write_review_packet(self.queue,self.corpus,self.root,review,private)

    def test_reject_nested_public_private(self):
        r=Path(self.tmp.name)/'review'
        with self.assertRaisesRegex(ReviewGateError,'overlap'):
            write_review_packet(self.queue,self.corpus,self.root,r,r/'private')

    def test_reject_review_output_inside_source_root(self):
        with self.assertRaisesRegex(ReviewGateError,'outside'):
            write_review_packet(self.queue,self.corpus,self.root,self.root/'review',Path(self.tmp.name)/'private')

if __name__=='__main__':
    unittest.main()
