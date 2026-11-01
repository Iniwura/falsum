"""Phase 2Y: forged machine packets and fake framework-lookalikes abstain."""
import copy
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError, validate_catalog
from falsum.phase2w_capture import capture_claims
from falsum.phase2y_bindings import analyze
from falsum.phase2y_claim_guard import guard,STATUS
from test_phase2w_proof_gate import inputs

AIO="real-aiohttp-static-traversal"
TOR="fresh-tornado-cookie-attribute"
WEB="fresh-websockets-deflate-limit"


class BoundClaimGuardTests(unittest.TestCase):
    def setUp(self):
        self.catalog,self.sources=inputs()
        self.rules=validate_catalog(self.catalog,self.sources)
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.path=self.root/"app.py"

    def check(self,text,case=AIO,req="follow_symlinks_enabled",claim="present",line=None):
        self.path.write_text(text,encoding="utf-8")
        binding=analyze(self.catalog,self.sources,case,self.root,["app.py"])
        lines=text.splitlines()
        if line is None: line=len(lines)
        captured=capture_claims(self.rules[case],self.root,[{
            "requirement_id":req,"claim":claim,"path":"app.py",
            "line_start":line,"line_end":line
        }])
        batch={"schema_version":1,"status":"UNREVIEWED_APPLICATION_EVIDENCE_BATCH",
               "research_only":True,"scenarios":[captured]}
        result=guard(self.catalog,self.sources,batch,self.root,[binding])
        self.assertEqual(result["status"],STATUS)
        self.assertFalse(result["network_eligible"])
        self.assertFalse(result["actual_framework_runtime_binding_verified"])
        self.assertEqual(result["actual_exploits_proven"],0)
        self.assertEqual(result["human_approved_labels"],0)
        return result,binding,batch

    def test_real_module_declared_aiohttp_false_claim_is_flagged(self):
        text="from aiohttp import web\napp=web.Application()\napp.router.add_static('/x',path,follow_symlinks=False)\n"
        r,_,_=self.check(text)
        self.assertEqual(r["local_source_syntax_conflicts"],1)
        self.assertTrue(r["cases"][0]["requires_review_for_local_syntax_conflict"])
        self.assertEqual(r["cases"][0]["decision"],
                         "STATIC_SYNTAX_CONTRADICTION_HUMAN_REVIEW_REQUIRED")
        self.assertEqual(r["cases"][0]["details"][0]["binding_declaration"],
                         "AIOHTTP_APP_CONSTRUCTOR_DECLARED")

    def test_unimported_fake_method_is_not_a_conflict(self):
        text="dummy.router.add_static('/x',path,follow_symlinks=False)\n"
        r,packet,_=self.check(text)
        self.assertEqual(packet["bound_syntactic_calls"],[])
        self.assertEqual(r["local_source_syntax_conflicts"],0)
        self.assertEqual(r["cases"][0]["decision"],
                         "ABSTAIN_NO_BINDING_QUALIFIED_CONTRADICTION")

    def test_import_bound_but_uninvoked_setup_stays_unresolved(self):
        text=("from aiohttp import web\napp=web.Application()\n"
              "def setup():\n    app.router.add_static('/x',path,follow_symlinks=False)\n")
        r,_,_=self.check(text)
        self.assertEqual(r["local_source_syntax_conflicts"],0)
        self.assertEqual(r["unresolved_scoped_call_sites"],1)
        self.assertEqual(r["cases"][0]["details"][0]["review_verdict"],
                         "UNRESOLVED_STATIC_INVOCATION_PATH")

    def test_dynamic_boolean_never_forces_a_contradiction(self):
        text=("from aiohttp import web\napp=web.Application()\n"
              "app.router.add_static('/x',path,follow_symlinks=config.enabled)\n")
        r,_,_=self.check(text)
        self.assertEqual(r["local_source_syntax_conflicts"],0)
        self.assertEqual(r["cases"][0]["details"][0]["review_verdict"],
                         "DYNAMIC_OR_UNDETERMINED_AST_LITERAL")

    def test_direct_local_function_invocation_supported(self):
        text=("from aiohttp import web\napp=web.Application()\n"
              "def setup():\n    app.router.add_static('/x',path,follow_symlinks=False)\n"
              "setup()\n")
        r,_,_=self.check(text,line=4)
        self.assertEqual(r["local_source_syntax_conflicts"],1)
        self.assertEqual(r["cases"][0]["details"][0]["invocation_path"],
                         "DIRECT_MODULE_CALL_TO_LOCAL_FUNCTION_SYNTAX")

    def test_from_import_websocket_alias_is_checked(self):
        text=("from websockets import serve as ws_start\n"
              "ws_start(handler,'localhost',8765,compression=None)\n")
        r,_,_=self.check(text,WEB,"compression_negotiated","present")
        self.assertEqual(r["local_source_syntax_conflicts"],1)
        self.assertEqual(r["cases"][0]["details"][0]["binding_declaration"],
                         "WEBSOCKETS_SERVE_FROM_IMPORT")

    def test_tornado_subclass_call_is_flagged_only_as_local_syntax(self):
        text=("from tornado.web import RequestHandler\n"
              "class H(RequestHandler):\n"
              "    def get(self):\n"
              "        self.set_cookie('a','b',max_age=3600)\n")
        r,_,_=self.check(text,TOR,"untrusted_noninteger_max_age","present")
        self.assertEqual(r["local_source_syntax_conflicts"],1)
        self.assertEqual(r["cases"][0]["details"][0]["invocation_path"],
                         "FRAMEWORK_CALLBACK_EXECUTION_UNVERIFIED")
        self.assertFalse(r["actual_framework_runtime_binding_verified"])

    def test_matching_claim_is_not_upgraded_to_expert_label(self):
        text="from aiohttp import web\napp=web.Application()\napp.router.add_static('/x',path,follow_symlinks=False)\n"
        r,_,_=self.check(text,claim="absent")
        self.assertEqual(r["local_source_syntax_conflicts"],0)
        self.assertEqual(r["cases"][0]["details"][0]["review_verdict"],
                         "LOCAL_STATIC_SYNTAX_AGREES_WITH_ASSERTION")
        self.assertEqual(r["accepted_anjoman_rows"],0)
        self.assertFalse(r["cases"][0]["confirmed_vulnerability"])

    def test_forged_binding_evidence_refused(self):
        text="from aiohttp import web\napp=web.Application()\napp.router.add_static('/x',path,follow_symlinks=False)\n"
        _,pkt,batch=self.check(text)
        fake=copy.deepcopy(pkt)
        fake["bound_syntactic_calls"][0]["literal_keyword_implication"]="SYNTACTIC_PRESENT"
        with self.assertRaisesRegex(ProofError,"did not reproduce"):
            guard(self.catalog,self.sources,batch,self.root,[fake])

    def test_stale_file_hash_refused(self):
        text="from aiohttp import web\napp=web.Application()\napp.router.add_static('/x',path,follow_symlinks=False)\n"
        _,pkt,batch=self.check(text)
        self.path.write_text(text.replace("False","True"))
        with self.assertRaises(ProofError):
            guard(self.catalog,self.sources,batch,self.root,[pkt])

    def test_duplicate_or_approval_spoofed_binding_report_refused(self):
        text="from aiohttp import web\napp=web.Application()\napp.router.add_static('/x',path,follow_symlinks=False)\n"
        _,pkt,batch=self.check(text)
        with self.assertRaises(ProofError):
            guard(self.catalog,self.sources,batch,self.root,[pkt,pkt])
        for field,value in (("network_eligible",True),("runtime_imports_loaded",True),
                            ("accepted_security_labels",1)):
            with self.subTest(field=field):
                fake=copy.deepcopy(pkt);fake[field]=value
                with self.assertRaises(ProofError):
                    guard(self.catalog,self.sources,batch,self.root,[fake])

    def test_empty_bound_report_is_abstention_not_safety(self):
        text="dummy.router.add_static('/x',path,follow_symlinks=False)\n"
        _,pkt,batch=self.check(text)
        r=guard(self.catalog,self.sources,batch,self.root,[])
        self.assertEqual(r["cases"][0]["decision"],
                         "ABSTAIN_NO_BINDING_QUALIFIED_CONTRADICTION")
        self.assertEqual(r["recomputed_binding_reports"],0)


if __name__=="__main__":
    unittest.main()
