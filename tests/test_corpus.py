"""Pinned public-advisory draft corpus must pass all offline source checks.

These examples are NOT uploaded/eligible Telegraph evaluation material.
"""
from pathlib import Path
import unittest

from falsum.ledger import load_ledger, export_pairs
from falsum.osv import audit_ledger_snapshots, verify_snapshot, version_status

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / 'data' / 'draft-ledger.json'
SNAPSHOTS = ROOT / 'data' / 'snapshots'


class TestPublishedDraftCorpus(unittest.TestCase):
    def test_source_digest_and_version_boundaries(self):
        ledger = load_ledger(LEDGER)
        self.assertGreaterEqual(len(ledger['evidence']), 6)
        self.assertGreaterEqual(len(ledger['pairs']), 6)
        self.assertEqual(audit_ledger_snapshots(ledger, SNAPSHOTS, include_drafts=True), [])
        for evidence in ledger['evidence']:
            with self.subTest(evidence=evidence['id']):
                record, _ = verify_snapshot(SNAPSHOTS / (evidence['advisory_id'] + '.json'), evidence['advisory_id'])
                self.assertEqual(version_status(record, evidence['ecosystem'], evidence['package'], evidence['version']), evidence['verdict'])

    def test_no_human_review_claimed(self):
        ledger = load_ledger(LEDGER)
        self.assertTrue(all(item['review_status'] == 'draft' for item in ledger['evidence']))
        self.assertTrue(all(item['review_status'] == 'draft' for item in ledger['pairs']))
        for split in ('train', 'validation', 'holdout'):
            with self.assertRaisesRegex(Exception, 'no reviewed pairs'):
                export_pairs(ledger, split)


if __name__ == '__main__':
    unittest.main()
