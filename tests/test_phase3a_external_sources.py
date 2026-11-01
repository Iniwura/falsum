"""Phase 3A: third-party source remains immutable, unexecuted and unreviewed."""
import copy
import json
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError
from falsum.phase3a_external_sources import (
    SOURCE_PINS, STATUS, audit, fetch_verified, git_blob,
    inspect_python, raw_url, validate_contract,
)

ROOT=Path(__file__).resolve().parents[1]


def contract():
    return json.loads((ROOT/"data/phase3a-external-source-cases.json").read_text())


def static_row(code:str,expected:list[str],lines:list[int]):
    row=copy.deepcopy(contract()["source_projects"][0])
    data=code.encode()
    row["git_blob_sha1"]=git_blob(data)
    row["expected_values"]=expected
    row["expected_call_lines"]=lines
    return row,data


class ExternalApplicationTrustTests(unittest.TestCase):
    def test_three_distinct_external_repositories_are_exactly_pinned(self):
        rows=validate_contract(contract())
        self.assertEqual(len(rows),3)
        self.assertEqual(len(set(r["repository"] for r in rows)),3)
        self.assertEqual(len(set(r["commit"] for r in rows)),3)
        self.assertEqual(len(set(r["git_blob_sha1"] for r in rows)),3)
        self.assertEqual([len(r["expected_values"]) for r in rows],[2,2,1])
        self.assertEqual([x["expected_values"] for x in rows],[
            ["EXPLICIT_TRUE","OMITTED_OPTION"],
            ["EXPLICIT_FALSE","EXPLICIT_FALSE"],["OMITTED_OPTION"]
        ])
        self.assertFalse(contract()["external_app_execution_authorized"])

    def test_url_is_immutable_https_raw_git_source(self):
        row=validate_contract(contract())[0]
        url=raw_url(row)
        self.assertEqual(url,"https://raw.githubusercontent.com/perspective-dev/perspective/"
                         "444865accd46bcfdeb552960ce4f63fe8286de42/"
                         "examples/python-aiohttp/server.py")
        self.assertNotIn("main/",url)

    def test_research_status_cannot_promote_to_release_or_label(self):
        for field,value in (("research_only",False),
                            ("external_app_execution_authorized",True),
                            ("status","SECURITY_APPROVED")):
            with self.subTest(field=field):
                x=contract();x[field]=value
                with self.assertRaises(ProofError):
                    validate_contract(x)
        for field,value in (("network_eligible",True),
                            ("affected_dependency_version_proven",True),
                            ("runtime_import_binding_proven",True),
                            ("real_security_exploits_proven",1),
                            ("independent_human_labels",1),
                            ("accepted_anjoman_rows",1)):
            with self.subTest(field=field):
                x=contract();x["trust_boundary"][field]=value
                with self.assertRaises(ProofError):
                    validate_contract(x)

    def test_cannot_replace_sources_with_synthetic_repo_or_reordered_entry(self):
        for key,value in (("repository","attacker/private"),
                          ("commit","0"*40),
                          ("git_blob_sha1","1"*40),
                          ("path","../../secrets.py")):
            with self.subTest(key=key):
                x=contract();x["source_projects"][0][key]=value
                with self.assertRaises(ProofError):
                    validate_contract(x)
        x=contract();x["source_projects"].reverse()
        with self.assertRaises(ProofError):
            validate_contract(x)

    def test_false_expected_source_calls_cannot_be_laundered(self):
        x=contract();x["source_projects"][0]["expected_values"]=["EXPLICIT_FALSE","OMITTED_OPTION"]
        with self.assertRaises(ProofError):
            validate_contract(x)
        x=contract();x["source_projects"][0]["expected_call_lines"]=[1,2]
        with self.assertRaises(ProofError):
            validate_contract(x)
        x=contract();x["source_projects"][0]["reviewed"]=True
        with self.assertRaises(ProofError):
            validate_contract(x)

    def test_fake_download_and_tamper_detected_by_git_hash(self):
        row=validate_contract(contract())[0]
        with self.assertRaisesRegex(ProofError,"pinned Git blob"):
            fetch_verified(row,fetcher=lambda u:b"from aiohttp import web\n")

    def test_reject_oversized_binary_and_nonbytes(self):
        row=validate_contract(contract())[0]
        for val in (b"",b"x"*96001,"from aiohttp import web",None):
            with self.subTest(val=str(type(val))),self.assertRaises(ProofError):
                fetch_verified(row,fetcher=lambda u:val)

    def test_test_raw_blob_sha_is_not_app_runtime_attestation(self):
        data=b"from aiohttp import web\n"
        self.assertEqual(len(git_blob(data)),40)
        self.assertNotEqual(git_blob(data),git_blob(data+b"modified"))
        self.assertNotEqual(git_blob(data),__import__("hashlib").sha256(data).hexdigest())

    def test_exact_syntax_true_false_and_omitted_is_not_a_security_verdict(self):
        code=("from aiohttp import web\n"
              "app.router.add_static('/t', path, follow_symlinks=True)\n"
              "app.router.add_static('/f', path, follow_symlinks=False)\n"
              "app.router.add_static('/o', path)\n")
        row,data=static_row(code,["EXPLICIT_TRUE","EXPLICIT_FALSE","OMITTED_OPTION"],[2,3,4])
        d=inspect_python(row,data)
        self.assertEqual(len(d["static_router_calls"]),3)
        self.assertEqual([x["observed_keyword_syntax"] for x in d["static_router_calls"]],
                         ["EXPLICIT_TRUE","EXPLICIT_FALSE","OMITTED_OPTION"])
        self.assertFalse(d["external_runtime_tested"])
        self.assertFalse(d["dependency_version_proven"])
        self.assertFalse(d["independently_expert_adjudicated"])
        self.assertTrue(all(x["applicability_conclusion"]=="UNRESOLVED_NO_DEPLOYMENT_OR_VERSION_PROOF"
                            for x in d["static_router_calls"]))
        self.assertTrue(all(not x["call_executed"] for x in d["static_router_calls"]))

    def test_keyword_expansion_never_certified_as_false(self):
        code="from aiohttp import web\napp.router.add_static('/x',path,follow_symlinks=False,**overrides)\n"
        row,data=static_row(code,["KEYWORD_EXPANSION_UNRESOLVED"],[2])
        d=inspect_python(row,data)
        self.assertEqual(d["static_router_calls"][0]["observed_keyword_syntax"],
                         "KEYWORD_EXPANSION_UNRESOLVED")

    def test_dynamic_python_expression_is_not_true_or_false(self):
        code="from aiohttp import web\napp.router.add_static('/x',path,follow_symlinks=config.follow)\n"
        row,data=static_row(code,["DYNAMIC_OR_NONBOOLEAN_UNRESOLVED"],[2])
        d=inspect_python(row,data)
        self.assertEqual(d["static_router_calls"][0]["observed_keyword_syntax"],
                         "DYNAMIC_OR_NONBOOLEAN_UNRESOLVED")

    def test_similar_named_unrelated_method_does_not_prove_runtime_callee(self):
        code="from aiohttp import web\nfake.router.add_static('/x',path,follow_symlinks=True)\n"
        row,data=static_row(code,["EXPLICIT_TRUE"],[2])
        d=inspect_python(row,data)
        call=d["static_router_calls"][0]
        self.assertFalse(call["receiver_identity_verified"])
        self.assertFalse(call["framework_version_verified"])
        self.assertEqual(call["applicability_conclusion"],"UNRESOLVED_NO_DEPLOYMENT_OR_VERSION_PROOF")

    def test_python_source_is_only_parsed_never_executed(self):
        code=("from aiohttp import web\n"
              "raise RuntimeError('this must never execute')\n"
              "app.router.add_static('/o',path)\n")
        row,data=static_row(code,["OMITTED_OPTION"],[3])
        d=inspect_python(row,data)
        self.assertFalse(d["source_code_executed"])
        self.assertEqual(len(d["static_router_calls"]),1)

    def test_unknown_import_or_fabricated_call_site_rejected(self):
        code="other.router.add_static('/x',path)\n"
        row,data=static_row(code,["OMITTED_OPTION"],[1])
        with self.assertRaisesRegex(ProofError,"import"):
            inspect_python(row,data)
        code="from aiohttp import web\napp.router.add_static('/x',path)\n"
        row,data=static_row(code,["EXPLICIT_TRUE"],[2])
        with self.assertRaisesRegex(ProofError,"differ"):
            inspect_python(row,data)

    def test_malformed_python_fails_closed(self):
        code="from aiohttp import web\napp.router.add_static('/x'\n"
        row,data=static_row(code,["OMITTED_OPTION"],[2])
        with self.assertRaisesRegex(ProofError,"parsed"):
            inspect_python(row,data)


if __name__=="__main__":
    unittest.main()
