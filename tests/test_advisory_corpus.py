"""Draft corpus builder tests; fabricated records are never eligible evidence."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.advisory_corpus import (CorpusError, boundary_versions, build_corpus,
    path_for_advisory, pinned_url, validate_corpus, validate_queue, _before_fixed)

QUEUE = Path(__file__).resolve().parents[1] / 'data' / 'advisory-queue.json'


def fake_doc(ghsa='GHSA-aaaa-bbbb-cccc', package='safe-test-lib'):
    return {'id':ghsa,'aliases':['CVE-2025-12345'], 'summary':'A hypothetical input-validation issue',
            'affected':[{'package':{'ecosystem':'npm','name':package},
                         'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'2.4.1'}]}]}]}


class AdvisoryCorpusTests(unittest.TestCase):
    def test_real_research_queue_split_is_disjoint(self):
        q=json.loads(QUEUE.read_text())
        self.assertEqual(validate_queue(q), [])
        self.assertEqual(len(q['advisories']),32)
        self.assertEqual(sum(x['split']=='train' for x in q['advisories']),26)
        self.assertEqual(sum(x['split']=='validation' for x in q['advisories']),3)
        self.assertEqual(sum(x['split']=='holdout' for x in q['advisories']),3)
        self.assertEqual(len({x['id'] for x in q['advisories']}),32)

    def test_immutable_source_url(self):
        row={'id':'GHSA-aaaa-bbbb-cccc','month':'2025/03'}
        self.assertEqual(path_for_advisory(row['id'],row['month']),
            'advisories/github-reviewed/2025/03/GHSA-aaaa-bbbb-cccc/GHSA-aaaa-bbbb-cccc.json')
        self.assertIn('/4af30eafd57e3bd9a0b4865dee2ced6f611de33f/', pinned_url(row))

    def test_reject_advisory_path_traversal(self):
        for ghsa,month in [('GHSA-../../../../.','2025/03'),('GHSA-aaaa-bbbb-cccc','../2025')]:
            with self.assertRaises(CorpusError):
                path_for_advisory(ghsa,month)

    def test_affected_and_patched_boundary_verified(self):
        self.assertEqual(boundary_versions(fake_doc(),'npm','safe-test-lib'),('2.4.0','2.4.1'))

    def test_unsupported_fixed_boundary_is_rejected(self):
        with self.assertRaises(CorpusError):
            _before_fixed('2.7.0-rc1')

    def test_no_unsafe_label_from_ambiguous_ranges(self):
        d=fake_doc()
        d['affected'][0]['ranges'][0]['type']='GIT'
        with self.assertRaises(CorpusError):
            boundary_versions(d,'npm','safe-test-lib')

    def test_dataset_integrity_and_status(self):
        base={'schema_version':1,'advisories':[]}
        docs={}
        for i in range(32):
            ghsa=f'GHSA-{i:04x}-bbbb-cccc'
            package=f'safe-test-lib-{i}'
            split='train' if i<26 else 'validation' if i<29 else 'holdout'
            row={'id':ghsa,'ecosystem':'npm','package':package,'month':'2025/03','split':split}
            base['advisories'].append(row)
            doc=fake_doc(ghsa,package)
            docs[ghsa]=(doc,json.dumps(doc).encode())
        corpus=build_corpus(base,docs)
        self.assertEqual(len(corpus['cases']),64)
        self.assertEqual(sum(x['split']=='train' for x in corpus['cases']),52)
        self.assertEqual({x['review_status'] for x in corpus['cases']},{'draft'})
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'snapshots').mkdir()
            for sid,(doc,raw) in docs.items():
                (root/f'snapshots/{sid}.json').write_bytes(raw)
            self.assertEqual(validate_corpus(corpus,root),[])
            tamper=root/f'snapshots/{next(iter(docs))}.json'
            tamper.write_bytes(b'bad')
            self.assertTrue(any('tampering' in x for x in validate_corpus(corpus,root)))

    def test_package_leakage_rejected(self):
        q=json.loads(QUEUE.read_text())
        q['advisories'][1]['split']='holdout'
        self.assertTrue(any('package leakage' in x for x in validate_queue(q)))

    def test_duplicate_ghsa_rejected(self):
        q=json.loads(QUEUE.read_text())
        q['advisories'][1]['id']=q['advisories'][0]['id']
        self.assertTrue(any('duplicate' in x for x in validate_queue(q)))

    def test_draft_only_artifact_is_not_eligible(self):
        q=json.loads(QUEUE.read_text())
        self.assertIn('draft',q['provenance'].lower())


if __name__=='__main__': unittest.main()
