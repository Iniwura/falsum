"""Fabricated tests for research-only input validation; never eligible data."""
from __future__ import annotations
import copy
import json
import tempfile
import unittest
from pathlib import Path
from falsum.research_pilot import PilotError, audit, main


def build(root: Path):
    (root / 'grounded').mkdir()
    queue = {'schema_version': 1, 'advisories': []}
    benchmark = {'status': 'QUARANTINED_DRAFT_ONLY', 'independent_human_reviews': 0,
                 'telegraph_eligible': False, 'trained_model': False,
                 'grounded': [], 'insufficient_evidence': []}
    for i in range(30):
        gid = f'GHSA-{i:04x}-{i:04x}-{i:04x}'
        split = 'train' if i < 26 else 'validation' if i < 28 else 'holdout'
        queue['advisories'].append({'id': gid, 'split': split, 'package': f'lib-{i}', 'ecosystem': 'npm'})
        for status in ('affected', 'unaffected'):
            benchmark['grounded'].append({
                'id': gid.lower() + '-' + status, 'advisory_id': gid,
                'split': split, 'review_status': 'draft', 'expected_status': status,
                'evidence_availability': 'present', 'source_sha256': 'a'*64,
                'prompt': f'Published affected-version events: fixed 1.0.0, library {i} {status} and details of review.',
                'chosen': f'Correct technical explanation of the fictional package version and its advisory {status}.',
                'rejected': f'Incorrect technical explanation of the fictional package version and its advisory {status}.'})
        benchmark['insufficient_evidence'].append({'id': gid.lower()+'-affected-missing-evidence',
            'advisory_id': gid, 'split': split, 'review_status': 'draft', 'evidence_availability': 'absent'})
    queue_path = root / 'queue.json'
    queue_path.write_text(json.dumps(queue))
    (root / 'grounded' / 'DRAFT-grounded-benchmark.json').write_text(json.dumps(benchmark))
    for part in ('train', 'validation', 'holdout'):
        p = root / 'grounded' / f'DRAFT-grounded-{part}.jsonl'
        p.write_text(''.join(json.dumps({k:r[k] for k in ('prompt','chosen','rejected')})+'\n'
                for r in benchmark['grounded'] if r['split']==part))
    return queue_path, benchmark


class ResearchPilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.queue_path, self.benchmark = build(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_complete_pilot_succeeds_without_eligibility_claim(self):
        r = audit(self.queue_path, self.root)
        self.assertEqual(r['advisories'], 30)
        self.assertEqual([r['partitions'][s]['cases'] for s in ('train','validation','holdout')], [52,4,4])
        self.assertFalse(r['network_eligible'])
        self.assertEqual(r['human_reviews'], 0)
        self.assertEqual(r['missing_evidence_controls_not_trained'], 30)

    def test_jsonl_tampering_rejected(self):
        f = self.root/'grounded'/'DRAFT-grounded-train.jsonl'
        f.write_text(f.read_text().replace('Correct technical', 'Confident claim', 1))
        with self.assertRaisesRegex(PilotError, 'does not match'):
            audit(self.queue_path, self.root)

    def test_missing_row_rejected(self):
        self.benchmark['grounded'].pop()
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'count'):
            audit(self.queue_path, self.root)

    def test_status_promotion_rejected(self):
        self.benchmark['grounded'][0]['review_status']='reviewed'
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'non-draft'):
            audit(self.queue_path, self.root)

    def test_unknown_advisory_rejected(self):
        self.benchmark['grounded'][0]['advisory_id']='GHSA-9999-9999-9999'
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'wrong split or advisory'):
            audit(self.queue_path, self.root)

    def test_package_leakage_rejected(self):
        queue = json.loads(self.queue_path.read_text())
        queue['advisories'][-1]['package']=queue['advisories'][0]['package']
        self.queue_path.write_text(json.dumps(queue))
        with self.assertRaisesRegex(PilotError, 'package family crosses'):
            audit(self.queue_path, self.root)

    def test_false_network_claim_rejected(self):
        self.benchmark['telegraph_eligible']=True
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'research-only'):
            audit(self.queue_path, self.root)

    def test_missing_control_rejected(self):
        self.benchmark['insufficient_evidence'].pop()
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'control count'):
            audit(self.queue_path, self.root)

    def test_wrong_grounded_evidence_rejected(self):
        self.benchmark['grounded'][0]['prompt']='no source is provided; please guess.'
        self._save_book()
        with self.assertRaisesRegex(PilotError, 'published range evidence'):
            audit(self.queue_path, self.root)

    def test_manifest_written_once(self):
        p = self.root / 'manifest.json'
        self.assertEqual(main([str(self.queue_path),str(self.root),'--manifest',str(p)]),0)
        self.assertTrue(p.is_file())
        with self.assertRaises(SystemExit):
            main([str(self.queue_path),str(self.root),'--manifest',str(p)])

    def _save_book(self):
        (self.root/'grounded'/'DRAFT-grounded-benchmark.json').write_text(json.dumps(self.benchmark))


if __name__=='__main__':
    unittest.main()
