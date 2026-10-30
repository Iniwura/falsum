"""Focused fail-closed tests for real-world OSV range and source shapes."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from falsum.osv import SourceError, audit_ledger_snapshots, version_status, verify_snapshot

GHSA = 'GHSA-cpwx-vrp4-4pq7'
PIN = '4af30eafd57e3bd9a0b4865dee2ced6f611de33f'
URL = f'https://raw.githubusercontent.com/github/advisory-database/{PIN}/advisories/github-reviewed/2025/03/{GHSA}/{GHSA}.json'


def jinja_record():
    return {'id':GHSA, 'aliases':['CVE-2025-27516'], 'summary':'Jinja2 vulnerable to sandbox breakout',
            'details':'Attacker controls the template content and uses the attr filter.',
            'affected':[{'package':{'ecosystem':'PyPI','name':'jinja2'},
                         'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'3.1.6'}]}],
                         'versions':['3.1.5','3.0.1']}]}


class TestRealEvidence(unittest.TestCase):
    def test_jinja_real_advisory_boundary(self):
        r=jinja_record()
        self.assertEqual(version_status(r,'PyPI','jinja2','3.1.5'),'affected')
        self.assertEqual(version_status(r,'PyPI','jinja2','3.1.6'),'unaffected')
        self.assertEqual(version_status(r,'PyPI','jinja2','3.2.0'),'unaffected')
        self.assertEqual(version_status(r,'PyPI','jinja2','3.1.6rc1'),'unknown')
        self.assertEqual(version_status(r,'PyPI','jinja2','2.0'),'unknown')
        self.assertEqual(version_status(r,'PyPI','jinja2','2.0.0'),'affected')

    def test_axios_version_boundary(self):
        r=jinja_record(); r['affected']=[{'package':{'ecosystem':'npm','name':'axios'},
          'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'1.0.0'},{'fixed':'1.8.2'}]}]}]
        self.assertEqual(version_status(r,'npm','axios','1.8.1'),'affected')
        self.assertEqual(version_status(r,'npm','axios','1.8.2'),'unaffected')
        self.assertEqual(version_status(r,'npm','axios','1.8.2-rc.1'),'unknown')
        self.assertEqual(version_status(r,'npm','axios','0.29.0'),'unaffected')  # mock only defines 1.x range

    def test_ecosystem_cannot_safely_order_special_versions(self):
        r=jinja_record()
        r['affected'][0]['ranges'][0]['events'][1]={'fixed':'3.1.6rc1'}
        self.assertEqual(version_status(r,'PyPI','jinja2','3.1.6'),'unknown')
        self.assertEqual(version_status(r,'PyPI','jinja2','3.1.5'),'affected')  # enumerated positive

    def test_non_ecosystem_package_unknown(self):
        r=jinja_record()
        self.assertEqual(version_status(r,'Maven','jinja2','3.1.6'),'unknown')

    def test_source_tampering_and_exact_pinned_url(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            rec=jinja_record()
            raw=json.dumps(rec,ensure_ascii=False).encode()
            p=root/f'{GHSA}.json'; p.write_bytes(raw)
            meta={'requested_id':GHSA,'canonical_id':GHSA,'source_url':URL,'sha256':hashlib.sha256(raw).hexdigest(),'byte_size':len(raw)}
            m=root/f'{GHSA}.meta.json'; m.write_text(json.dumps(meta))
            self.assertEqual(verify_snapshot(p,GHSA)[0]['id'],GHSA)
            draft={'evidence':[{'id':'e1','advisory_id':GHSA,'ecosystem':'PyPI','package':'jinja2','version':'3.1.5',
                'review_status':'draft','verdict':'affected','source_url':URL,'source_sha256':meta['sha256'],
                'source_excerpt':rec['summary']}]}
            self.assertEqual(audit_ledger_snapshots(draft,root,include_drafts=True),[])
            self.assertTrue(audit_ledger_snapshots(draft,root))
            meta['source_url']='https://evil.example.org/advisory.json'; m.write_text(json.dumps(meta))
            with self.assertRaises(SourceError):verify_snapshot(p,GHSA)
            meta['source_url']=URL; m.write_text(json.dumps(meta)); p.write_bytes(raw+b'\n')
            with self.assertRaises(SourceError):verify_snapshot(p,GHSA)

    def test_unpinned_github_source_fails(self):
        self.assertIsNotNone(version_status(jinja_record(),'PyPI','jinja2','3.1.5'))
