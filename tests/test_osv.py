"""Offline, mocked OSV tests. Examples are illustrative, not submissions."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from falsum.cli import main
from falsum.osv import SourceError, _cmp, _in_semver_range, audit_ledger_snapshots, parse_osv, verify_snapshot, version_status
from falsum.sources import fetch_osv

ID = 'GHSA-aaaa-bbbb-cccc'
URL = f'https://api.osv.dev/v1/vulns/{ID}'


def record():
    return {
        'id': ID,
        'aliases': ['CVE-2026-12345'],
        'summary': 'Mocked library security issue for unit tests only.',
        'details': 'Affects certain versions of the fictional library.',
        'affected': [{
            'package': {'ecosystem': 'npm', 'name': 'fixture-lib'},
            'ranges': [{'type': 'SEMVER', 'events': [
                {'introduced': '0'}, {'fixed': '1.2.0'},
                {'introduced': '2.0.0'}, {'last_affected': '2.1.0'},
            ]}],
        }],
    }


def raw_record():
    return json.dumps(record(), sort_keys=True).encode()


class Response:
    def __init__(self, raw, url=URL):
        self.data, self.url = raw, url
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def geturl(self):
        return self.url
    def read(self, limit):
        return self.data[:limit]


class Client:
    def __init__(self, response):
        self.response = response
        self.calls = 0
    def open(self, request, timeout=15):
        self.calls += 1
        return self.response


class TestOSV(unittest.TestCase):
    def test_pre_release_precedence(self):
        self.assertLess(_cmp('1.0.0-rc.2', '1.0.0-rc.10'), 0)
        self.assertLess(_cmp('1.0.0-rc.1', '1.0.0'), 0)
        self.assertEqual(_cmp('1.0.0+build.4', '1.0.0'), 0)

    def test_semver_strict_and_fail_closed(self):
        for version in ('v1.2.0', '1.2', '1.2.3.4', '01.2.3', '1.2.3-01'):
            self.assertEqual(version_status(record(), 'npm', 'fixture-lib', version), 'unknown')

    def test_discontinuous_ranges(self):
        expected = {'0.9.0': 'affected', '1.1.9': 'affected', '1.2.0': 'unaffected',
                    '1.9.9': 'unaffected', '2.0.0': 'affected', '2.1.0': 'affected',
                    '2.1.1': 'unaffected', '2.1.0-rc.1': 'affected'}
        for version, result in expected.items():
            with self.subTest(version=version):
                self.assertEqual(version_status(record(), 'npm', 'fixture-lib', version), result)

    def test_last_affected_inclusive_fixed_exclusive(self):
        ev1 = {'events': [{'introduced': '1.0.0'}, {'fixed': '1.2.0'}]}
        ev2 = {'events': [{'introduced': '1.0.0'}, {'last_affected': '1.2.0'}]}
        self.assertFalse(_in_semver_range('1.2.0', ev1))
        self.assertTrue(_in_semver_range('1.2.0', ev2))

    def test_unknown_on_unsupported_range(self):
        r = record(); r['affected'][0]['ranges'].append({'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]})
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '1.9.0'), 'unknown')
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '1.1.0'), 'affected')

    def test_unknown_for_wrong_package_or_missing_ranges(self):
        self.assertEqual(version_status(record(), 'npm', 'other', '1.0.0'), 'unknown')
        r = record(); r['affected'][0]['ranges'] = []
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '1.8.0'), 'unknown')

    def test_explicit_versions_affected(self):
        r = record(); r['affected'][0]['ranges'] = []; r['affected'][0]['versions'] = ['4.0.0']
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '4.0.0'), 'affected')
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '4.0.1'), 'unknown')

    def test_unordered_or_malformed_events_unknown(self):
        r = record(); r['affected'][0]['ranges'][0]['events'] = [{'introduced': '2.0.0'}, {'fixed': '1.0.0'}]
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '1.5.0'), 'unknown')
        r['affected'][0]['ranges'][0]['events'] = [{'fixed': '1.2.0'}]
        self.assertEqual(version_status(r, 'npm', 'fixture-lib', '1.0.0'), 'unknown')

    def test_advisory_identity(self):
        self.assertEqual(parse_osv(raw_record(), 'CVE-2026-12345')['id'], ID)
        with self.assertRaises(SourceError):
            parse_osv(raw_record(), 'CVE-2026-99999')

    def test_withdrawn_entry_rejected(self):
        r = record(); r['withdrawn'] = '2026-08-01T00:00:00Z'
        with self.assertRaises(SourceError):
            parse_osv(json.dumps(r).encode(), ID)

    def test_empty_ledger_fails_audit(self):
        self.assertTrue(audit_ledger_snapshots({'evidence': []}, Path('/tmp')))

    def test_oversized_and_invalid(self):
        with self.assertRaises(SourceError):
            parse_osv(b'x' * 3_000_001, ID)
        with self.assertRaises(SourceError):
            parse_osv(b'garbage', ID)

    def test_fetch_and_immutable_reuse(self):
        client = Client(Response(raw_record()))
        with tempfile.TemporaryDirectory() as d:
            path = fetch_osv(ID, Path(d), opener=client)
            self.assertEqual(path.read_bytes(), raw_record())
            self.assertEqual(client.calls, 1)
            self.assertEqual(fetch_osv(ID, Path(d), opener=client), path)
            self.assertEqual(client.calls, 1)
            rec, meta = verify_snapshot(path, ID)
            self.assertEqual(rec['id'], ID)
            self.assertEqual(meta['sha256'], hashlib.sha256(raw_record()).hexdigest())

    def test_reject_wrong_url_and_bad_alias(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SourceError):
                fetch_osv(ID, Path(d), opener=Client(Response(raw_record(), 'https://evil.test/snapshot')))
            with self.assertRaises(SourceError):
                fetch_osv('not/a/valid/id', Path(d), opener=Client(Response(raw_record())))

    def test_detect_tampering_and_partial_snapshots(self):
        with tempfile.TemporaryDirectory() as d:
            p = fetch_osv(ID, Path(d), opener=Client(Response(raw_record())))
            p.write_bytes(p.read_bytes() + b' ')
            with self.assertRaises(SourceError):
                verify_snapshot(p, ID)
            with self.assertRaises(SourceError):
                fetch_osv(ID, Path(d), opener=Client(Response(raw_record())))

    def test_ledger_audit_matches_source(self):
        with tempfile.TemporaryDirectory() as d:
            p = fetch_osv(ID, Path(d), opener=Client(Response(raw_record())))
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            evidence = {'id':'e1','ecosystem':'npm','package':'fixture-lib','version':'1.1.0',
                        'advisory_id':ID,'verdict':'affected','source_url':URL,
                        'source_excerpt':'Mocked library security issue',
                        'source_sha256':sha,'review_status':'reviewed'}
            ledger = {'evidence':[evidence]}
            self.assertEqual(audit_ledger_snapshots(ledger, Path(d)), [])
            evidence['verdict'] = 'unaffected'
            self.assertTrue(any('conflicts' in x for x in audit_ledger_snapshots(ledger, Path(d))))
            evidence['verdict'] = 'affected'; evidence['source_sha256'] = '0' * 64
            self.assertTrue(any('SHA-256' in x for x in audit_ledger_snapshots(ledger, Path(d))))

    def test_cli_source_status(self):
        with tempfile.TemporaryDirectory() as d:
            p = fetch_osv(ID, Path(d), opener=Client(Response(raw_record())))
            params = ['check-osv', str(p), '--advisory', ID, '--ecosystem', 'npm',
                      '--package', 'fixture-lib', '--version', '1.2.0']
            self.assertEqual(main(params + ['--expect', 'unaffected']), 0)
            self.assertEqual(main(params + ['--expect', 'affected']), 2)
            self.assertEqual(main(params[:]) , 0)


if __name__ == '__main__':
    unittest.main()
