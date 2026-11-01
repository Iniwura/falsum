"""Verify third-party dependency declarations never imply installed versions or exploits."""
import copy
import json
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError
from falsum.phase3a_external_sources import git_blob
from falsum.phase3a_dependency_manifests import (
    validate, _constraint_semantics, read_profile, audit,
)

ROOT=Path(__file__).resolve().parents[1]


def contract():
    return json.loads((ROOT/"data/phase3a-dependency-manifests.json").read_text())


class IndependentDependencyTests(unittest.TestCase):
    def test_four_manifest_profiles_from_three_pinned_projects(self):
        rows=validate(contract())
        self.assertEqual(len(rows),4)
        self.assertEqual(len({x["repository"] for x in rows}),3)
        self.assertEqual([x["declared_requirement"] for x in rows],
            ["aiohttp>=2,<4","aiohttp>=3.13.5","aiohttp==3.13.3","aiohttp>=3,<4"])
        self.assertEqual(len({x["profile"] for x in rows}),4)
        self.assertFalse(contract()["trust_boundary"]["installed_versions_verified"])
        self.assertFalse(contract()["trust_boundary"]["dependency_solver_executed"])

    def test_dependency_bounds_support_not_actual_install(self):
        result=[_constraint_semantics(x["declared_requirement"],"3.9.2")
                for x in validate(contract())]
        self.assertEqual(result,[
            "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE",
            "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE",
            "DECLARATION_REQUIRES_AT_LEAST_FIXED",
            "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE"
        ])

    def test_refuse_other_advisory_or_patched_threshold(self):
        for field,value in (("patched_version","3.8.0"),
                            ("upstream_advisory","GHSA-unknown"),
                            ("research_only",False),
                            ("external_application_code_executed",True)):
            with self.subTest(field=field):
                d=contract();d[field]=value
                with self.assertRaises(ProofError):
                    validate(d)

    def test_dependency_file_and_blob_mutation_refused(self):
        for field,value in (("repository","bad/repo"),("commit","0"*40),
                            ("path","setup.py"),("git_blob_sha1","a"*40),
                            ("line",111),("declared_requirement","aiohttp>=1"),
                            ("profile","fake")):
            with self.subTest(field=field):
                d=contract();d["profiles"][0][field]=value
                with self.assertRaises(ProofError):
                    validate(d)

    def test_separate_deployment_profiles_cannot_be_combined(self):
        d=contract();d["trust_boundary"]["profiles_are_not_single_deployment_environment"]=False
        with self.assertRaises(ProofError):
            validate(d)
        d=contract();d["profiles"][1],d["profiles"][2]=d["profiles"][2],d["profiles"][1]
        with self.assertRaises(ProofError):
            validate(d)

    def test_do_not_fabricate_installed_version_or_eligible_pairs(self):
        for field,value in (("installed_versions_verified",True),
                            ("dependency_solver_executed",True),
                            ("code_imported",True),
                            ("network_eligible",True),
                            ("security_labels_approved",1),
                            ("vulnerabilities_confirmed",1),
                            ("accepted_anjoman_evaluation_rows",1)):
            with self.subTest(field=field):
                d=contract();d["trust_boundary"][field]=value
                with self.assertRaises(ProofError):
                    validate(d)

    def test_git_blob_changed_versus_expected_manifest_rejected(self):
        row=validate(contract())[0]
        with self.assertRaisesRegex(ProofError,"pinned Git blob"):
            read_profile(row,fetcher=lambda url:b"[project]\nname='forged'\n")

    def test_toml_optional_dependency_extracted_without_running_any_package(self):
        data=b'[project]\nname = "illustrative"\n[project.optional-dependencies]\naiohttp = ["aiohttp>=2,<4"]\n'
        row=copy.deepcopy(validate(contract())[0])
        row["git_blob_sha1"]=git_blob(data)
        row["line"]=4
        x=read_profile(row,fetcher=lambda u:data)
        self.assertEqual(x["declared_requirement"],"aiohttp>=2,<4")
        self.assertFalse(x["is_installed_runtime_version"])
        self.assertFalse(x["is_deployed_application_version"])
        self.assertFalse(x["confirmed_vulnerability"])

    def test_requirements_text_only_checks_plain_aiohttp_not_aiohttp_cors(self):
        data=b"aiohttp-cors==0.7.0\naiohttp>=3.13.5\n"
        row=copy.deepcopy(validate(contract())[1])
        row["git_blob_sha1"]=git_blob(data)
        row["line"]=2
        x=read_profile(row,fetcher=lambda u:data)
        self.assertEqual(x["declared_historic_advisory_range"],
                         "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE")
        self.assertFalse(x["dependency_environment_resolved"])

    def test_multiple_or_unknown_aiohttp_manifest_specs_fail_closed(self):
        data=b"aiohttp>=3.13.5\naiohttp==3.13.3\n"
        row=copy.deepcopy(validate(contract())[1])
        row["git_blob_sha1"]=git_blob(data)
        row["line"]=1
        with self.assertRaisesRegex(ProofError,"ambiguous"):
            read_profile(row,fetcher=lambda u:data)
        with self.assertRaises(ProofError):
            _constraint_semantics("aiohttp~=3.9","3.9.2")

    def test_numeric_range_math_and_unsupported_constraints(self):
        self.assertEqual(_constraint_semantics("aiohttp>=3.9.2,<4","3.9.2"),
                         "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE")
        self.assertEqual(_constraint_semantics("aiohttp==3.9.1","3.9.2"),
                         "DECLARATION_PINS_AFFECTED_VERSION")
        with self.assertRaises(ProofError):
            _constraint_semantics("aiohttp>=4,<3","3.9.2")
        with self.assertRaises(ProofError):
            _constraint_semantics("aiohttp>=weird","3.9.2")


if __name__=="__main__":
    unittest.main()
