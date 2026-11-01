"""Phase 2Y: verify precise syntactic import and reachability evidence boundaries."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError
from falsum.phase2y_bindings import analyze, STATUS
from test_phase2w_proof_gate import inputs

AIO="real-aiohttp-static-traversal"
TOR="fresh-tornado-cookie-attribute"
WEB="fresh-websockets-deflate-limit"


class StaticBindingTests(unittest.TestCase):
    def setUp(self):
        self.catalog,self.sources=inputs()
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.file=self.root/"app.py"

    def obs(self,source,case=AIO,rel="app.py"):
        self.file.write_text(source,encoding="utf-8")
        report=analyze(self.catalog,self.sources,case,self.root,[rel])
        self.assertEqual(report["status"],STATUS)
        self.assertFalse(report["network_eligible"])
        self.assertFalse(report["runtime_imports_loaded"])
        self.assertFalse(report["runtime_calls_executed"])
        self.assertFalse(report["verified_exploitability"])
        self.assertEqual(report["accepted_security_labels"],0)
        return report["bound_syntactic_calls"]

    def test_aiohttp_literal_false_with_constructor_and_module_expression(self):
        src=("from aiohttp import web as my_web\n"
             "app = my_web.Application()\n"
             "app.router.add_static('/x',path,follow_symlinks=False)\n")
        calls=self.obs(src)
        self.assertEqual(len(calls),1)
        c=calls[0]
        self.assertEqual(c["import_declaration_binding"],"AIOHTTP_APP_CONSTRUCTOR_DECLARED")
        self.assertEqual(c["syntactic_invocation_path"],"MODULE_TOP_LEVEL_CALL_SYNTAX")
        self.assertEqual(c["literal_keyword_implication"],"SYNTACTIC_ABSENT")
        self.assertEqual(c["line_start"],3)
        self.assertFalse(c["runtime_callee_identity_verified"])
        self.assertFalse(c["actual_call_execution_verified"])
        self.assertFalse(c["version_and_exposure_verified"])

    def test_aiohttp_true_is_still_not_proof_of_exploitation(self):
        x=self.obs("from aiohttp import web\napp=web.Application()\n"
                   "app.router.add_static('/x',path,follow_symlinks=True)\n")
        self.assertEqual(x[0]["literal_keyword_implication"],"SYNTACTIC_PRESENT")
        self.assertFalse(x[0]["application_wide_security_proven"])

    def test_aiohttp_without_import_is_unresolved(self):
        self.assertEqual(self.obs("app=web.Application()\napp.router.add_static('/x',x,follow_symlinks=False)\n"),[])

    def test_aiohttp_without_constructor_is_unresolved(self):
        self.assertEqual(self.obs("from aiohttp import web\napp=object()\napp.router.add_static('/x',x,follow_symlinks=False)\n"),[])

    def test_aiohttp_constructor_rebind_abstains(self):
        src=("from aiohttp import web\napp=web.Application()\napp=Fake()\n"
             "app.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(self.obs(src),[])

    def test_import_alias_shadowing_abstains(self):
        src=("from aiohttp import web as w\n"
             "def bad(w):\n    pass\n"
             "app=w.Application()\napp.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(self.obs(src),[])

    def test_import_declaration_redefinition_abstains(self):
        src=("from aiohttp import web\nfrom unrelated import web\n"
             "app=web.Application()\napp.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(self.obs(src),[])

    def test_star_import_abstains(self):
        src=("from aiohttp import web\nfrom other import *\n"
             "app=web.Application()\napp.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(self.obs(src),[])

    def test_global_dynamic_alias_abstains(self):
        src=("from aiohttp import web\n"
             "app=web.Application()\n"
             "def mutate():\n    global web\n    web = get_library()\n"
             "app.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(self.obs(src),[])

    def test_uncalled_function_is_not_module_reachable(self):
        src=("from aiohttp import web\napp=web.Application()\n"
             "def setup():\n    app.router.add_static('/x',x,follow_symlinks=False)\n")
        calls=self.obs(src)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["syntactic_invocation_path"],
                         "UNINVOKED_FUNCTION_OR_DYNAMIC_CALL_UNDETERMINED")

    def test_local_function_direct_module_call_is_syntactically_linked(self):
        src=("from aiohttp import web\napp=web.Application()\n"
             "def setup():\n    app.router.add_static('/x',x,follow_symlinks=False)\n"
             "setup()\n")
        calls=self.obs(src)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["syntactic_invocation_path"],
                         "DIRECT_MODULE_CALL_TO_LOCAL_FUNCTION_SYNTAX")
        self.assertFalse(calls[0]["actual_call_execution_verified"])

    def test_conditional_invocation_is_not_direct_path(self):
        src=("from aiohttp import web\napp=web.Application()\n"
             "def setup():\n    app.router.add_static('/x',x,follow_symlinks=False)\n"
             "if DEBUG:\n    setup()\n")
        calls=self.obs(src)
        self.assertEqual(calls[0]["syntactic_invocation_path"],
                         "UNINVOKED_FUNCTION_OR_DYNAMIC_CALL_UNDETERMINED")

    def test_guarded_static_route_abstains_reachability(self):
        src=("from aiohttp import web\napp=web.Application()\n"
             "if ENABLED:\n    app.router.add_static('/x',x,follow_symlinks=False)\n")
        calls=self.obs(src)
        self.assertEqual(calls[0]["syntactic_invocation_path"],
                         "GUARDED_OR_NESTED_EXECUTION_UNDETERMINED")

    def test_websockets_alias_import_is_traced_syntactically(self):
        src=("import websockets as ws\n"
             "ws.serve(handler,'localhost',8765,compression=None)\n")
        calls=self.obs(src,WEB)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["import_declaration_binding"],
                         "WEBSOCKETS_MODULE_IMPORT")
        self.assertEqual(calls[0]["literal_keyword_implication"],"SYNTACTIC_ABSENT")
        self.assertFalse(calls[0]["runtime_callee_identity_verified"])

    def test_websockets_from_import_as_alias(self):
        src=("from websockets import serve as webserve\n"
             "webserve(handler,'localhost',8765,compression='deflate')\n")
        calls=self.obs(src,WEB)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["import_declaration_binding"],
                         "WEBSOCKETS_SERVE_FROM_IMPORT")
        self.assertEqual(calls[0]["literal_keyword_implication"],"UNDETERMINED")

    def test_websockets_unimported_name_not_trusted(self):
        calls=self.obs("websockets.serve(handler,'localhost',8765,compression=None)\n",WEB)
        self.assertEqual(calls,[])

    def test_websockets_shadowed_function_parameter_abstains(self):
        src=("import websockets as ws\n"
             "def handler(ws):\n    ws.serve(None,'localhost',8765,compression=None)\n")
        self.assertEqual(self.obs(src,WEB),[])

    def test_websockets_other_serve_not_trusted(self):
        self.assertEqual(self.obs("import websockets\nother.serve(handler,'x',1,compression=None)\n",WEB),[])

    def test_tornado_request_handler_subclass_syntax_only(self):
        src=("from tornado.web import RequestHandler as RH\n"
             "class Demo(RH):\n"
             "    def get(self):\n"
             "        self.set_cookie('session','value',max_age=3600)\n")
        calls=self.obs(src,TOR)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["import_declaration_binding"],
                         "TORNADO_REQUEST_HANDLER_BASE_DECLARED")
        self.assertEqual(calls[0]["syntactic_invocation_path"],
                         "FRAMEWORK_CALLBACK_EXECUTION_UNVERIFIED")
        self.assertEqual(calls[0]["literal_keyword_implication"],"SYNTACTIC_ABSENT")
        self.assertFalse(calls[0]["actual_call_execution_verified"])

    def test_tornado_non_subclass_not_assumed_to_be_handler(self):
        src=("class Fake:\n"
             "    def get(self):\n        self.set_cookie('x','y',max_age=3600)\n")
        self.assertEqual(self.obs(src,TOR),[])

    def test_tornado_redefined_base_or_self_abstains(self):
        src=("from tornado.web import RequestHandler as RH\n"
             "RH=type('Fake',(object,),{})\n"
             "class Foo(RH):\n"
             "    def get(self):\n        self.set_cookie('x','y',max_age=3600)\n")
        self.assertEqual(self.obs(src,TOR),[])

    def test_tornado_decorated_method_abstains(self):
        src=("from tornado.web import RequestHandler\n"
             "class Handler(RequestHandler):\n"
             "    @decorator\n"
             "    def get(self):\n        self.set_cookie('x','y',max_age=3600)\n")
        self.assertEqual(self.obs(src,TOR),[])

    def test_tornado_dynamic_argument_stays_unknown(self):
        src=("from tornado.web import RequestHandler\n"
             "class Handler(RequestHandler):\n"
             "    def get(self):\n        self.set_cookie('x','y',max_age=self.request.args['age'])\n")
        calls=self.obs(src,TOR)
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]["literal_keyword_implication"],"UNDETERMINED")

    def test_nonmatching_source_family_rejected(self):
        self.file.write_text("pass\n")
        with self.assertRaises(ProofError):
            analyze(self.catalog,self.sources,"real-requests-proxy-auth",self.root,["app.py"])

    def test_symlink_and_traversal_refused(self):
        self.file.write_text("pass\n")
        (self.root/"link.py").symlink_to(self.file)
        for p in (["link.py"],["../escape.py"],["app.py","app.py"]):
            with self.subTest(p=p),self.assertRaises(ProofError):
                analyze(self.catalog,self.sources,AIO,self.root,p)

    def test_invalid_syntax_and_oversize_refused(self):
        for content in ("def broken(\n","x"*130000):
            self.file.write_text(content)
            with self.assertRaises(ProofError):
                analyze(self.catalog,self.sources,AIO,self.root,["app.py"])

    def test_inactive_module_not_proven_executed(self):
        x=self.obs("from aiohttp import web\napp=web.Application()\n"
                   "app.router.add_static('/x',x,follow_symlinks=False)\n")
        self.assertEqual(x[0]["syntactic_invocation_path"],"MODULE_TOP_LEVEL_CALL_SYNTAX")
        self.assertFalse(x[0]["actual_call_execution_verified"])

if __name__=="__main__":
    unittest.main()
