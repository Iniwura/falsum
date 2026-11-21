"""Phase 5Z: local author-constructed adversarial contract tests.

These are NOT additional genuine external Miner outputs or expert gold.
Real Git byte authenticity is checked only in the separate original CI job.
"""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from falsum import phase5z_reviewed_advisory_consumption as z
from falsum.phase5y_original_reviewed_version_applicability import frozen as y_frozen
from falsum.phase5m_real_source_sensitive_model import ROOT


def cases():
    originals=y_frozen()["original_advisory_sources"]
    src_url="https://github.com/github/advisory-database/blob/76955defc62d048f8f7cc68bc39a2f6dd1899ebe/"
    return [{
        "ghsa_id":s["id"],
        "cve_alias":s["original_cve_alias"],
        "reviewed_original_git_blob_sha1":s["original_git_blob_sha1"],
        "reviewed_original_source_url":src_url+s["source_path"],
        "exact_package_ecosystem":"npm/lodash",
        "reviewed_introduced_inclusive":s["original_lodash_range_introduced"],
        "reviewed_fixed_exclusive":s["original_lodash_range_fixed_exclusive"],
        "original_reference_applicable_to_lodash_4_17_15":
            s["expected_applicable_to_npm_lodash_4_17_15"],
        "not_universal_security_assurance":True,
    } for s in originals]


def direct(role,rs):
    if role=="direct_deps_dev_ghsa":
        req={"method":"GET","endpoint":"/query","payload":{
            "system":"npm","pkg":"lodash","ver":"4.17.15"}}
        body={"miner_id":"190048","result_shape":"raw",
              "result":{"versionKey":{"name":"lodash","system":"NPM","version":"4.17.15"},
                        "advisoryKeys":[{"id":row["ghsa_id"]} for row in rs]}}
    else:
        req={"method":"GET","endpoint":"/query","payload":{
            "pkg":"lodash","ver":"4.17.15"}}
        body={"miner_id":"77010","result_shape":"raw","result":{
            "package":{"name":"lodash","system":"NPM"},
            "version":{"version":"4.17.15","advisories":[
                {"source":"OSV","aliases":[row["cve_alias"]]} for row in rs]}}}
    return req,body


class SourceReviewedApplicationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.refs=cases()

    def test_original_contract_before_implementation(self):
        p=z.frozen()
        self.assertEqual(z.git_blob_sha((ROOT/z.LOCK).read_bytes()),z.LOCK_BLOB)
        self.assertEqual(p["original_external_published_records"],3)
        self.assertEqual(p["original_reviewed_advisory_records"],6)
        self.assertEqual(p["expected_total_display_only_reference_instances"],10)
        self.assertEqual(p["expected_distinct_version_inapplicable_ghsa"],[z.BAD_GHSA])
        self.assertTrue(p["explicit_limits"]["not_automated_security_approval"])
        self.assertTrue(p["explicit_limits"]["not_same_canonical_intent_competition"])

    def test_six_author_constructed_reference_properties_are_internally_consistent(self):
        ghsa,cve=z.reviewed_index(self.refs)
        self.assertEqual(len(ghsa),6)
        self.assertEqual(len(cve),6)
        self.assertEqual(sum(r["original_reference_applicable_to_lodash_4_17_15"]
                             for r in ghsa.values()),5)

    def test_original_two_direct_input_shapes_get_exactly_five_display_only_references(self):
        for role in z.ROLES[1:]:
            with self.subTest(role=role):
                request,response=direct(role,self.refs)
                d=z.consume(role,request,response,self.refs)
                self.assertEqual(d["action"],z.ALLOW)
                self.assertEqual(d["display_count"],5)
                self.assertEqual(d["suppressed_count"],1)
                self.assertEqual({r["verified_ghsa_id"] for r in d["suppressed_references"]},
                                 {z.BAD_GHSA})
                self.assertTrue(all(r["reference_meaning"]==z.NO_APPROVAL
                                    for r in d["display_references"]))
                self.assertFalse(d["original_external_capture_git_verified"])
                self.assertTrue(d["no_automatic_security_clearance"])
                self.assertFalse(d["same_canonical_intent_network_ranking_proved"])
                self.assertNotIn("body",d)
                self.assertNotIn("payment",d)
                self.assertNotIn("original_response",d)

    def test_original_canonical_unscoped_100_ghsa_list_never_autodisplayed(self):
        request={"intent":"SECURITY_REVIEW_GENERAL",
                 "params":{"target":"npm package lodash version 4.17.15"}}
        body={"miner_id":"77003","result_shape":"raw",
              "result":[{"ghsa_id":f"GHSA-abcd-efgh-{i:04d}"} for i in range(100)]}
        result=z.consume(z.ROLES[0],request,body,self.refs)
        self.assertEqual(result["action"],z.DENY)
        self.assertEqual(result["display_count"],0)
        self.assertEqual(result["reason"],"UNSCOPED_100_ADVISORY_FEED_NOT_PACKAGE_BOUND")
        self.assertFalse(result["original_external_capture_git_verified"])

    def test_wrong_target_version_miner_and_missing_proof_are_denied(self):
        for role in z.ROLES[1:]:
            req,body=direct(role,self.refs)
            changes=[]
            wrong=deepcopy(req);wrong["payload"]["ver"]="4.17.14";changes.append((wrong,body))
            wrong=deepcopy(req);wrong["payload"]["pkg"]="lodash-es";changes.append((wrong,body))
            wrong=deepcopy(req);wrong["endpoint"]="/unsupported";changes.append((wrong,body))
            wrong=deepcopy(body);wrong["miner_id"]="731001";changes.append((req,wrong))
            wrong=deepcopy(body);wrong["result_shape"]="plaintext";changes.append((req,wrong))
            wrong=deepcopy(body);wrong["result"]={};changes.append((req,wrong))
            for a,b in changes:
                with self.subTest(role=role):
                    decision=z.consume(role,a,b,self.refs)
                    self.assertEqual(decision["action"],z.DENY)
                    self.assertEqual(decision["display_count"],0)

    def test_unknown_or_repeated_identifiers_do_not_allow_partial_display(self):
        for role in z.ROLES[1:]:
            req,body=direct(role,self.refs)
            new=deepcopy(body)
            if role=="direct_deps_dev_ghsa":
                new["result"]["advisoryKeys"][0]["id"]="GHSA-1111-2222-3333"
            else:
                new["result"]["version"]["advisories"][0]["aliases"]=["CVE-2099-99999999"]
            self.assertEqual(z.consume(role,req,new,self.refs)["action"],z.DENY)
            copy=deepcopy(body)
            if role=="direct_deps_dev_ghsa":
                copy["result"]["advisoryKeys"][0]=copy["result"]["advisoryKeys"][1]
            else:
                copy["result"]["version"]["advisories"][0]=copy["result"]["version"]["advisories"][1]
            self.assertEqual(z.consume(role,req,copy,self.refs)["action"],z.DENY)

    def test_incorrect_original_upstream_sha_or_malformed_ranges_rejected(self):
        mutations=[
            ("reviewed_original_git_blob_sha1","f"*40),
            ("cve_alias","CVE-2099-123456"),
            ("exact_package_ecosystem","npm/lodash.unset"),
            ("reviewed_introduced_inclusive","4.19.99"),
            ("reviewed_fixed_exclusive","4.17.10"),
            ("original_reference_applicable_to_lodash_4_17_15",False),
            ("reviewed_original_source_url","https://example.test/forged"),
            ("not_universal_security_assurance",False)
        ]
        for k,v in mutations:
            records=deepcopy(self.refs);records[0][k]=v
            with self.subTest(field=k):
                with self.assertRaises(ValueError):
                    z.reviewed_index(records)

    def test_duplicate_reviewed_source_or_missing_source_denied(self):
        orig=deepcopy(self.refs)
        orig[0]=deepcopy(orig[1])
        with self.assertRaises(ValueError):
            z.reviewed_index(orig)
        with self.assertRaises(ValueError):
            z.reviewed_index(self.refs[:-1])

    def test_untrusted_inputs_cannot_claim_independently_captured_paid_response(self):
        for role in z.ROLES[1:]:
            req,body=direct(role,self.refs)
            req["original_external_capture_git_verified"]=True
            self.assertEqual(z.consume(role,req,body,self.refs)["action"],z.DENY)
            req,body=direct(role,self.refs)
            body["original_external_capture_git_verified"]=True
            result=z.consume(role,req,body,self.refs)
            self.assertFalse(result["original_external_capture_git_verified"])

    def test_freeze_byte_mutation_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            f=root/z.LOCK;f.parent.mkdir(parents=True)
            f.write_bytes((ROOT/z.LOCK).read_bytes()+b" ")
            with self.assertRaises(ValueError):
                z.frozen(root)


if __name__=="__main__":
    unittest.main()
