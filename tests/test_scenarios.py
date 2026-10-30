"""Application scenario comparison tests are NOT Telegraph-eligible assessments."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.scenarios import ScenarioError, export_reviewed, read_casebook, readiness_report, validate_casebook, verify_source_snapshots
from falsum.cli import main

BOOK_PATH = Path(__file__).resolve().parents[1] / 'data' / 'draft-scenarios.json'


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.book = read_casebook(BOOK_PATH)

    def test_draft_corpus_passes_structure(self):
        self.assertEqual(validate_casebook(self.book), [])
        r = readiness_report(self.book)
        self.assertEqual(r['count'], 12)
        self.assertEqual(r['reviewed'], 0)
        self.assertFalse(r['submission_ready'])
        self.assertEqual(r['by_split'], {'train': 6, 'validation': 4, 'holdout': 2})
        self.assertEqual(len(r['by_category']), 5)
        self.assertEqual(len(r['by_outcome']), 3)

    def test_non_deceptive_export_blocked(self):
        with self.assertRaisesRegex(ScenarioError, 'unreviewed'):
            export_reviewed(self.book, 'train', base_dir=BOOK_PATH.parent)

    def test_cli_reports_not_eligible(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(['check-scenarios', str(BOOK_PATH)]), 0)
            self.assertEqual(main(['export-scenarios', str(BOOK_PATH), '--split', 'train', '--out', str(Path(d) / 'triplets.jsonl')]), 1)
            self.assertFalse((Path(d) / 'triplets.jsonl').exists())

    def test_wrong_intent_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][0]['intent_id'] = 'CODE_REVIEW_GENERAL'
        self.assertTrue(any('wrong child Intent' in e for e in validate_casebook(b)))

    def test_unverified_source_pin_rejected(self):
        b = copy.deepcopy(self.book)
        b['sources'][0]['state'] = 'pinned'
        b['sources'][0]['sha256'] = ''
        self.assertTrue(any('checksum' in e for e in validate_casebook(b)))

    def test_split_leak_on_rule_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][1]['split'] = 'holdout'
        self.assertTrue(any('rule family' in e for e in validate_casebook(b)))

    def test_split_leak_on_source_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][1]['rule_family'] = 'unique-case-family'
        b['cases'][1]['split'] = 'validation'
        self.assertTrue(any('source django-checklist' in e for e in validate_casebook(b)))

    def test_duplicate_negative_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][1]['rejected'] = b['cases'][0]['rejected']
        self.assertTrue(any('repeated negative' in e for e in validate_casebook(b)))

    def test_answer_length_shortcut_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][0]['rejected'] = b['cases'][0]['rejected'] * 12
        self.assertTrue(any('answer-length ratio' in e for e in validate_casebook(b)))

    def test_reused_prompt_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][1]['prompt'] = b['cases'][0]['prompt']
        self.assertTrue(any('too similar' in e for e in validate_casebook(b)))

    def test_real_credential_pattern_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][0]['context'] += ' AKIA' + 'Q' * 16
        self.assertTrue(any('credential' in e for e in validate_casebook(b)))

    def test_malformed_source_host_rejected(self):
        b = copy.deepcopy(self.book)
        b['sources'][0]['url'] = 'http://example.test/document'
        self.assertTrue(any('HTTPS' in e for e in validate_casebook(b)))

    def test_unknown_source_rejected(self):
        b = copy.deepcopy(self.book)
        b['cases'][0]['source_ids'] = ['missing']
        self.assertTrue(any('unknown source' in e for e in validate_casebook(b)))

    def test_verified_source_bytes_required(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            name = 'approved.txt'
            body = b'Official-snapshot-placeholder-for-integrity-test'
            (folder / name).write_bytes(body)
            b = {'sources': [{'id':'s','state':'pinned','snapshot_path':name,'sha256':hashlib.sha256(body).hexdigest()}]}
            self.assertEqual(verify_source_snapshots(b,folder),[])
            (folder / name).write_bytes(body+b'bad')
            self.assertTrue(any('mismatch' in e for e in verify_source_snapshots(b,folder)))

    def test_source_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            b = {'sources': [{'id':'s','state':'pinned','snapshot_path':'../../etc/hosts','sha256':'0'*64}]}
            self.assertTrue(any('escapes' in e for e in verify_source_snapshots(b,Path(d))))

    def test_reviewed_requires_real_calendar_date(self):
        b = copy.deepcopy(self.book)
        b['cases'][0]['review_status'] = 'reviewed'
        b['cases'][0]['reviewer'] = 'unit-test-reviewer'
        b['cases'][0]['reviewed_on'] = '2026-02-30'
        self.assertTrue(any('real ISO date' in e for e in validate_casebook(b)))

    def test_draft_disclosures_are_not_verification(self):
        self.assertTrue(all(x['review_status'] == 'draft' for x in self.book['cases']))
        self.assertTrue(all(x['state'] == 'pinned' for x in self.book['sources']))
        self.assertTrue(all('FAKE' not in x['chosen'] for x in self.book['cases']))


    def test_pinned_guidance_integrity_and_honest_status(self):
        self.assertEqual(verify_source_snapshots(self.book, BOOK_PATH.parent), [])
        result = readiness_report(self.book, base_dir=BOOK_PATH.parent)
        self.assertEqual(result['pinned_sources'], 4)
        self.assertTrue(result['source_integrity_ok'])
        self.assertFalse(result['local_export_ready'])
        self.assertFalse(result['submission_ready'])
        self.assertEqual(result['network_eligibility'], 'unverified')

    def test_guidance_audit_cli(self):
        self.assertEqual(main(['audit-scenarios', str(BOOK_PATH)]), 0)

    def test_tampered_excerpt_fails_even_after_rehash(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = copy.deepcopy(self.book['sources'][0])
            src = BOOK_PATH.parent / sample['snapshot_path']
            dst = Path(folder) / sample['snapshot_path']
            dst.parent.mkdir(parents=True)
            excerpt = json.loads(src.read_text(encoding='utf-8'))
            excerpt['immutable_url'] = 'https://example.org/incorrect'
            raw = (json.dumps(excerpt, indent=2) + '\n').encode('utf-8')
            dst.write_bytes(raw)
            sample['sha256'] = hashlib.sha256(raw).hexdigest()
            errors = verify_source_snapshots({'sources':[sample]}, Path(folder))
            self.assertTrue(any('provenance mismatch' in x for x in errors))

    def test_unlocated_snapshot_is_never_ready(self):
        result = readiness_report(self.book)
        self.assertFalse(result['source_integrity_ok'])
        self.assertFalse(result['submission_ready'])
        self.assertFalse(result['local_export_ready'])

    def test_missing_real_excerpt_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertTrue(verify_source_snapshots(self.book, Path(folder)))

if __name__ == '__main__':
    unittest.main()
