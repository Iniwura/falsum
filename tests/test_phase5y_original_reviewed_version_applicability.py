"""Phase 5Y: adversarial version-bounded original reviewed advisory decision tests.

Synthetic dictionaries below ONLY test the policy contract. They are not
original Miner output or independently authenticated source receipts. Actual
origin verification is a separate GitHub Actions job fetching exact public bytes.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5y_original_reviewed_version_applicability as y
from falsum.phase4l_external_receipt_evidence import git_blob_sha
from falsum.phase5m_real_source_sensitive_model import ROOT


def fake_advisory(*,introduced="4.17.23",fixed="4.18.1",
                  include_subpackage=True):
    affected=[{
        "package":{"name":"lodash","ecosystem":"npm"},
        "ranges":[{"type":"ECOSYSTEM","events":[
            {"introduced":introduced},{"fixed":fixed}]}],
    }]
    if include_subpackage:
        affected.append({"package":{"name":"lodash.unset","ecosystem":"npm"},
                         "ranges":[{"type":"ECOSYSTEM","events":[
                             {"introduced":"0"},{"fixed":"4.18.0"}]}]})
    return {"schema_version":"1.4.0","id":"GHSA-f23m-r3pf-42rh",
            "aliases":["CVE-2026-2950"],"affected":affected}


def fake_original_miner(role:str,refs:list[dict]):
    spec=y.frozen()["original_provider_captures"][0 if role=="direct_deps_dev_ghsa" else 1]
    if role=="direct_deps_dev_ghsa":
        request={"method":"GET","endpoint":"/query","payload":{
            "system":"npm","pkg":"lodash","ver":"4.17.15"}}
        response={"versionKey":{"name":"lodash","system":"NPM","version":"4.17.15"},
                  "advisoryKeys":[{"id":x["id"]} for x in refs]}
    else:
        request={"method":"GET","endpoint":"/query","payload":{
            "pkg":"lodash","ver":"4.17.15"}}
        response={"package":{"name":"lodash","system":"NPM"},
                  "version":{"version":"4.17.15","advisories":[
                      {"source":"OSV","aliases":[x["original_cve_alias"]]}
                      for x in refs]}}
    return {"spec":{"role":role,"path":spec["path"],
                    "git_blob_sha1":spec["original_git_blob_sha1"],
                    "reported_miner_id":spec["reported_miner_id"]},
            "document":{"request":request,"status":200,"paid":True,
                        "charged":True,"body":{"result":response}}}


class ReviewedVersionApplicabilityContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy=y.frozen()

    def test_original_frozen_independent_source_and_claim_limits(self):
        self.assertEqual(git_blob_sha((ROOT/y.LOCK).read_bytes()),
                         y.LOCK_GIT_BLOB_SHA1)
        self.assertEqual(self.policy["primary_reference_source"],y.ADVISORY_REPO)
        self.assertEqual(self.policy["primary_reference_original_git_commit"],
                         y.ADVISORY_COMMIT)
        self.assertEqual(len(self.policy["original_advisory_sources"]),6)
        self.assertEqual(len(self.policy["original_provider_captures"]),2)
        self.assertEqual(self.policy["actual_raw_reported_advisory_references"],12)
        self.assertEqual(self.policy["expected_12_original_provider_reference_matches"],
                         {"applicable":10,"inapplicable":2})
        self.assertEqual(self.policy["qualified_human_appsec_gold_count"],0)
        self.assertFalse(self.policy["true_same_canonical_intent_comparison"])
        self.assertFalse(self.policy["independent_provider_ownership_verified"])
        self.assertFalse(self.policy["no_registered_network_evaluator"] is False)

    def test_frozen_original_six_advisory_ids_unique_and_separate_source(self):
        sources=self.policy["original_advisory_sources"]
        self.assertEqual(len(set(x["id"] for x in sources)),6)
        self.assertEqual(len(set(x["original_cve_alias"] for x in sources)),6)
        self.assertEqual(len(set(x["original_git_blob_sha1"] for x in sources)),6)
        self.assertEqual(sum(x["expected_applicable_to_npm_lodash_4_17_15"]
                             for x in sources),5)
        self.assertEqual([x["id"] for x in sources
                          if not x["expected_applicable_to_npm_lodash_4_17_15"]],
                         ["GHSA-f23m-r3pf-42rh"])

    def test_semver_numeric_tuple_not_lexicographic(self):
        self.assertEqual(y.semver("4.17.23"),(4,17,23))
        self.assertTrue(y.semver("4.17.9")<y.semver("4.17.15"))
        self.assertTrue(y.semver("4.17.23")<y.semver("4.18.0"))
        self.assertEqual(y.semver("0"),(0,0,0))
        for invalid in ("", "1.2", "v4.17.15","4.17.15-beta", "1.2.3.4",
                        "-1.2.3","4.17.x",None,{}, "1234567.3.4"):
            with self.subTest(invalid=invalid):
                with self.assertRaises((ValueError,TypeError)):
                    y.semver(invalid)

    def test_real_2026_advisory_affected_range_boundaries(self):
        events=[{"introduced":"4.17.23"},{"fixed":"4.18.1"}]
        for tested,expected in [
            ("4.17.15",False),
            ("4.17.22",False),
            ("4.17.23",True),
            ("4.18.0",True),
            ("4.18.1",False),
            ("4.18.2",False),
        ]:
            with self.subTest(version=tested):
                self.assertIs(y.interval(tested,events),expected)

    def test_fixed_boundary_is_exclusive_last_affected_inclusive(self):
        self.assertTrue(y.interval("4.17.19",[
            {"introduced":"4.0.0"},{"last_affected":"4.17.19"}]))
        self.assertFalse(y.interval("4.17.20",[
            {"introduced":"4.0.0"},{"last_affected":"4.17.19"}]))
        self.assertFalse(y.interval("4.17.21",[
            {"introduced":"4.0.0"},{"fixed":"4.17.21"}]))
        self.assertTrue(y.interval("4.17.20",[
            {"introduced":"4.0.0"},{"fixed":"4.17.21"}]))

    def test_exact_lodash_version_cannot_inherit_lodash_unset_subpackage_interval(self):
        record=fake_advisory(include_subpackage=True)
        applies,bounds=y.advisory_applies(record,version="4.17.15")
        self.assertFalse(applies)
        self.assertEqual(bounds["introduced"],"4.17.23")
        # Distinct npm package lodash.unset *may* have earlier start, but it
        # does not authorize the unrelated lodash package name.
        applies_unset,_=y.advisory_applies(record,package="lodash.unset",
                                         version="4.17.15")
        self.assertTrue(applies_unset)

    def test_malformed_or_ambiguous_advisory_intervals_fail_closed(self):
        variants=[
            [],
            [{"introduced":"4.17.23"}],
            [{"introduced":"4.17.23"},{"fixed":"4.18.1"},{"last_affected":"4.18.2"}],
            [{"foo":"0"},{"fixed":"4.18.1"}],
            [{"introduced":"4.19.0"},{"fixed":"4.18.1"}],
            [{"introduced":"4.17.23"},{"fixed":"4.18.1","other":True}],
        ]
        for bad in variants:
            with self.subTest(bad=str(bad)):
                with self.assertRaises((ValueError,TypeError)):
                    y.interval("4.17.15",bad)
        for mutation in ("wrong-package","duplicate-package","wrong-ecosystem","no-range"):
            d=fake_advisory()
            if mutation=="wrong-package":
                d["affected"][0]["package"]["name"]="lodash-es"
            elif mutation=="duplicate-package":
                d["affected"].append(deepcopy(d["affected"][0]))
            elif mutation=="wrong-ecosystem":
                d["affected"][0]["package"]["ecosystem"]="PyPI"
            else:
                d["affected"][0]["ranges"]=[]
            with self.subTest(mutation=mutation):
                with self.assertRaises((ValueError,TypeError)):
                    y.advisory_applies(d)

    def test_genuine_source_sha_cannot_be_replaced_by_tampered_mock(self):
        source=self.policy["original_advisory_sources"][2]
        document=fake_advisory()
        raw=(__import__("json").dumps(document)).encode()
        self.assertNotEqual(git_blob_sha(raw),source["original_git_blob_sha1"])
        def fake_download(url):
            self.assertEqual(url,y.REVIEWED_PREFIX+
                             self.policy["original_advisory_sources"][0]["source_path"])
            return raw
        with self.assertRaises((ValueError,TypeError)):
            y.load_reviewed(download=fake_download)

    def test_synthetic_provider_advisory_shape_matches_frozen_semantics(self):
        references=self.policy["original_advisory_sources"]
        for role in y.ROLES:
            source=fake_original_miner(role,references)
            found,aliases=y._actual_provider_items(source,self.policy)
            self.assertEqual(found,role)
            self.assertEqual(len(aliases),6)
            self.assertEqual(len(set(aliases)),6)
            if role=="direct_deps_dev_ghsa":
                self.assertEqual(aliases[2],"GHSA-f23m-r3pf-42rh")
            else:
                self.assertEqual(aliases[2],"CVE-2026-2950")

    def test_forged_original_miner_target_and_receipt_rejected(self):
        references=self.policy["original_advisory_sources"]
        for role in y.ROLES:
            original=fake_original_miner(role,references)
            bads=[]
            altered=deepcopy(original)
            altered["document"]["request"]["payload"]["ver"]="4.17.23"
            bads.append(altered)
            altered=deepcopy(original)
            altered["document"]["status"]=500
            bads.append(altered)
            altered=deepcopy(original)
            altered["spec"]["git_blob_sha1"]="0"*40
            bads.append(altered)
            altered=deepcopy(original)
            if role=="direct_deps_dev_ghsa":
                altered["document"]["body"]["result"]["advisoryKeys"].pop()
            else:
                altered["document"]["body"]["result"]["version"]["advisories"][0]["aliases"]=[]
            bads.append(altered)
            for bad in bads:
                with self.subTest(role=role):
                    with self.assertRaises((ValueError,TypeError)):
                        y._actual_provider_items(bad,self.policy)

    def test_frozen_byte_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            file=root/y.LOCK
            file.parent.mkdir(parents=True)
            file.write_bytes((ROOT/y.LOCK).read_bytes()+b" ")
            with self.assertRaises((ValueError,TypeError)):
                y.frozen(root)


if __name__=="__main__":
    unittest.main()
