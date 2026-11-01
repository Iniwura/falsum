"""Phase 2Y: narrowly bounded Python import declarations and syntactic invocation paths.

A static import declaration is NOT runtime symbol identity. A top-level call
or direct top-level function invocation is NOT proof that production executes.
All positive matches are research observations, not exploit predicates.
Ambiguous shadowing, star imports, decorators, branches and computed callees
abstain. Never execute submitted Python.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import ProofError, _canonical, _inside, validate_catalog, MAX_BYTES
from .phase2x_ast_observer import METHODS, _classify, MAX_FILES, MAX_OBSERVATIONS

STATUS="PHASE2Y_BOUNDED_IMPORT_AND_INVOCATION_SYNTAX_RESEARCH_ONLY"


def _imports(module:ast.Module, case_id:str)->dict[str,str]:
    found={}
    for node in module.body:
        if isinstance(node,ast.ImportFrom) and any(x.name=="*" for x in node.names):
            return {}
        if isinstance(node,ast.Import):
            for alias in node.names:
                if case_id=="fresh-websockets-deflate-limit" and alias.name=="websockets":
                    found[alias.asname or "websockets"]="WEBSOCKETS_MODULE_IMPORT"
        if isinstance(node,ast.ImportFrom):
            for alias in node.names:
                name=alias.asname or alias.name
                if (case_id=="real-aiohttp-static-traversal"
                        and node.level==0 and node.module=="aiohttp" and alias.name=="web"):
                    found[name]="AIOHTTP_WEB_FROM_IMPORT"
                if case_id=="fresh-tornado-cookie-attribute" and node.level==0 and node.module=="tornado.web" and alias.name=="RequestHandler":
                    found[name]="TORNADO_REQUEST_HANDLER_FROM_IMPORT"
                if case_id=="fresh-websockets-deflate-limit" and node.level==0 and node.module=="websockets" and alias.name=="serve":
                    found[name]="WEBSOCKETS_SERVE_FROM_IMPORT"
    return found


def _binding_count(tree:ast.Module, name:str)->int:
    count=0
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            count+=sum((a.asname or a.name.split(".")[0])==name for a in node.names)
        elif isinstance(node,ast.ImportFrom):
            count+=sum((a.asname or a.name)==name for a in node.names)
        elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            count+=int(node.name==name)
        elif isinstance(node,ast.arg):
            count+=int(node.arg==name)
        elif isinstance(node,ast.ExceptHandler) and node.name is not None:
            count+=int(node.name==name)
        elif isinstance(node,ast.Name) and node.id==name and isinstance(node.ctx,(ast.Store,ast.Del)):
            count+=1
    return count


def _store_count(tree:ast.Module, name:str)->int:
    """Count assignments, deletions and named expression stores in every scope.

    Overconservative: local shadowing in a different function also abstains.
    That is preferable to claiming import identity when aliasing is uncertain.
    """
    return sum(isinstance(n,ast.Name) and n.id==name and
               isinstance(n.ctx,(ast.Store,ast.Del)) for n in ast.walk(tree))


def _dynamic_global(tree:ast.Module)->bool:
    for n in ast.walk(tree):
        if isinstance(n,(ast.Global,ast.Nonlocal,ast.NamedExpr)):
            return True
        if isinstance(n,ast.Attribute) and isinstance(n.ctx,(ast.Store,ast.Del)):
            return True  # conservative: monkeypatching any module/class attribute
        if (isinstance(n,ast.Call) and isinstance(n.func,ast.Name)
                and n.func.id in {"exec","eval","setattr","delattr",
                                  "globals","locals","vars","__import__"}):
            return True  # dynamic rebinding cannot be resolved statically
    return False


def _identity(call:ast.Call,case_id:str,bindings:dict[str,str],app_vars:set[str],tornado_self:str|None)->tuple[str,str]:
    fn=call.func
    if case_id=="real-aiohttp-static-traversal":
        if (isinstance(fn,ast.Attribute) and fn.attr=="add_static"
                and isinstance(fn.value,ast.Attribute) and fn.value.attr=="router"
                and isinstance(fn.value.value,ast.Name) and fn.value.value.id in app_vars):
            return "STATIC_CONSTRUCTOR_AND_RECEIVER_CHAIN","AIOHTTP_APP_CONSTRUCTOR_DECLARED"
        return "UNRESOLVED_CALLEE","NO_BINDING"
    if case_id=="fresh-tornado-cookie-attribute":
        if (isinstance(fn,ast.Attribute) and fn.attr=="set_cookie"
                and isinstance(fn.value,ast.Name) and fn.value.id==tornado_self
                and tornado_self is not None):
            return "STATIC_TORNADO_SUBCLASS_METHOD","TORNADO_REQUEST_HANDLER_BASE_DECLARED"
        return "UNRESOLVED_CALLEE","NO_BINDING"
    if case_id=="fresh-websockets-deflate-limit":
        if isinstance(fn,ast.Name) and bindings.get(fn.id)=="WEBSOCKETS_SERVE_FROM_IMPORT":
            return "STATIC_WEBSOCKETS_FROM_IMPORT","WEBSOCKETS_SERVE_FROM_IMPORT"
        if (isinstance(fn,ast.Attribute) and fn.attr=="serve"
                and isinstance(fn.value,ast.Name)
                and bindings.get(fn.value.id)=="WEBSOCKETS_MODULE_IMPORT"):
            return "STATIC_WEBSOCKETS_MODULE_IMPORT","WEBSOCKETS_MODULE_IMPORT"
        return "UNRESOLVED_CALLEE","NO_BINDING"
    raise ProofError("unsupported scoped static identity")


def _function_invoked(module:ast.Module, owner:ast.FunctionDef)->bool:
    if owner.decorator_list or owner.args.args or owner.args.posonlyargs or owner.args.kwonlyargs:
        return False
    defs=[n for n in module.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==owner.name]
    if len(defs)!=1 or _binding_count(module,owner.name)!=1:
        return False
    invocations=[n for n in module.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
                 and isinstance(n.value.func,ast.Name) and n.value.func.id==owner.name
                 and not n.value.args and not n.value.keywords]
    return len(invocations)==1 and module.body.index(invocations[0])>module.body.index(owner)


def _site_path(node:ast.Call, parent:dict, module:ast.Module, case_id:str)->str:
    """Only straight-line Expr calls can receive a syntactic invocation path."""
    cur=node
    while cur in parent:
        prev=parent[cur]
        if isinstance(prev,(ast.If,ast.Try,ast.While,ast.For,ast.AsyncFor,
                            ast.With,ast.AsyncWith,ast.IfExp,ast.Lambda,
                            ast.BoolOp,ast.Match,ast.comprehension)):
            return "GUARDED_OR_NESTED_EXECUTION_UNDETERMINED"
        if isinstance(prev,(ast.ClassDef,ast.AsyncFunctionDef)):
            return "FRAMEWORK_CALLBACK_OR_ASYNC_EXECUTION_UNDETERMINED"
        if isinstance(prev,ast.FunctionDef):
            # Could be straight-line function in module, with no decorators
            # and exactly one module-level direct call. Only an Expr call.
            if not isinstance(cur,ast.Expr) or cur not in prev.body:
                return "NESTED_FUNCTION_EXECUTION_UNDETERMINED"
            return ("DIRECT_MODULE_CALL_TO_LOCAL_FUNCTION_SYNTAX"
                    if _function_invoked(module,prev)
                    else "UNINVOKED_FUNCTION_OR_DYNAMIC_CALL_UNDETERMINED")
        if isinstance(prev,ast.Module):
            return "MODULE_TOP_LEVEL_CALL_SYNTAX" if isinstance(cur,ast.Expr) else "MODULE_NESTED_EXPRESSION_UNDETERMINED"
        cur=prev
    return "UNDETERMINED"


def _tornado_method_info(node:ast.Call,parent:dict,tree:ast.Module,imports:dict)->str|None:
    curr=node
    fn=None
    klass=None
    while curr in parent:
        curr=parent[curr]
        if isinstance(curr,ast.FunctionDef) and fn is None:
            fn=curr
        elif isinstance(curr,ast.ClassDef) and fn is not None:
            klass=curr
            break
    if fn is None or klass is None or fn not in klass.body or klass not in tree.body:
        return None
    if fn.decorator_list or klass.decorator_list or klass.keywords or len(klass.bases)!=1:
        return None
    if not fn.args.args or fn.args.args[0].arg!="self":
        return None
    base=klass.bases[0]
    if not (isinstance(base,ast.Name) and imports.get(base.id)=="TORNADO_REQUEST_HANDLER_FROM_IMPORT"):
        return None
    if _binding_count(tree,base.id)!=1 or _binding_count(tree,klass.name)!=1:
        return None
    # self explicitly rebound anywhere in method (including nested scopes):
    if any(isinstance(n,ast.Name) and n.id=="self" and
           isinstance(n.ctx,(ast.Store,ast.Del)) for n in ast.walk(fn)):
        return None
    return "self"


def analyze(catalog:dict,sources:list[dict],case_id:str,root:Path,paths:list[str])->dict:
    rules=validate_catalog(catalog,sources)
    if case_id not in METHODS or case_id not in rules:
        raise ProofError("Phase 2Y only supports the three narrowly checked source families")
    if (not isinstance(paths,list) or not 1<=len(paths)<=MAX_FILES
            or len(set(paths))!=len(paths)):
        raise ProofError("invalid explicit local Python source selection")
    results=[]
    audited=[]
    for rel in paths:
        file=_inside(root,rel)
        if file.suffix!=".py" or file.stat().st_size>MAX_BYTES:
            raise ProofError("only bounded Python files supported")
        raw=file.read_bytes()
        try:
            body=raw.decode("utf-8")
            tree=ast.parse(body,filename=rel)
        except (UnicodeDecodeError,SyntaxError,ValueError) as exc:
            raise ProofError("unreadable or malformed Python source; abstain") from exc
        filehash=hashlib.sha256(raw).hexdigest()
        bindings=_imports(tree,case_id)
        dynamic=_dynamic_global(tree)
        # Every import alias must remain unassigned in every scope. If a
        # name is shadowed, remove it instead of claiming the imported callee.
        bindings={k:v for k,v in bindings.items() if _binding_count(tree,k)==1 and not dynamic}
        app_vars=set()
        if case_id=="real-aiohttp-static-traversal":
            for item in tree.body:
                if not (isinstance(item,ast.Assign) and len(item.targets)==1
                        and isinstance(item.targets[0],ast.Name)
                        and isinstance(item.value,ast.Call) and not item.value.args
                        and not item.value.keywords):
                    continue
                constructor=item.value.func
                if (isinstance(constructor,ast.Attribute) and constructor.attr=="Application"
                        and isinstance(constructor.value,ast.Name)
                        and bindings.get(constructor.value.id)=="AIOHTTP_WEB_FROM_IMPORT"
                        and _binding_count(tree,item.targets[0].id)==1):
                    app_vars.add(item.targets[0].id)
        parents={child:node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        lines=body.splitlines()
        audited.append({"path":rel,"sha256":filehash,"python_ast_parsed":True,
                        "observed_import_names":sorted(bindings),
                        "static_aiohttp_constructor_targets":sorted(app_vars),
                        "runtime_imports_executed":False})
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):
                continue
            tornado_self=_tornado_method_info(node,parents,tree,bindings) if case_id=="fresh-tornado-cookie-attribute" else None
            site,binding=_identity(node,case_id,bindings,app_vars,tornado_self)
            if site=="UNRESOLVED_CALLEE":
                continue
            if node.end_lineno is None or node.end_lineno-node.lineno>14 or node.end_lineno>len(lines):
                raise ProofError("unbounded source call: refuse incomplete evidence")
            syntax,implication=_classify(node,case_id)
            if case_id=="fresh-tornado-cookie-attribute":
                path="FRAMEWORK_CALLBACK_EXECUTION_UNVERIFIED"
            else:
                path=_site_path(node,parents,tree,case_id)
            # A lexical binding only demonstrates the selected syntax and
            # source path. Actual import resolution/execution remains unproven.
            results.append({
                "case_id":case_id,"path":rel,"sha256":filehash,
                "line_start":node.lineno,"line_end":node.end_lineno,
                "quote":"\n".join(lines[node.lineno-1:node.end_lineno]),
                "ast_sha256":hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest(),
                "import_declaration_binding":binding,
                "local_receiver_structure":site,
                "syntactic_invocation_path":path,
                "literal_keyword_observation":syntax,
                "literal_keyword_implication":implication,
                "runtime_callee_identity_verified":False,
                "actual_call_execution_verified":False,
                "version_and_exposure_verified":False,
                "application_wide_security_proven":False
            })
            if len(results)>MAX_OBSERVATIONS:
                raise ProofError("too many import-bound call observations")
    return {
        "schema_version":1,"status":STATUS,"case_id":case_id,
        "repository":rules[case_id]["repository"],
        "source_commit":rules[case_id]["source_commit"],
        "source_catalog_sha256":hashlib.sha256(_canonical(catalog)).hexdigest(),
        "scanned_files":audited,"bound_syntactic_calls":results,
        "research_only":True,"network_eligible":False,"human_reviewed":False,
        "runtime_imports_loaded":False,"runtime_calls_executed":False,
        "verified_exploitability":False,"accepted_security_labels":0,
        "note":"Only local static import and call-shape provenance plus tightly bounded syntactic paths. Runtime package bindings, actual invocation, deployed versions, attacker control and full application reachability are NOT proven."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Conservative local Python import/receiver and invocation-shape analyzer")
    for x in ("catalog","old-queue","train-queue","fresh-spec","root","selection","out"):
        p.add_argument("--"+x,type=Path,required=True)
    p.add_argument("--case-id",required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ProofError("refuse to overwrite prior source evidence")
        from .real_fix_corpus import load_queue
        old=load_queue(a.old_queue)["cases"]
        train=load_queue(a.train_queue)["cases"]
        fresh=json.loads(a.fresh_spec.read_text())
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False):
            raise ProofError("fresh historical source status was promoted")
        selection=json.loads(a.selection.read_text())
        if not isinstance(selection,dict) or set(selection)!={"status","files"} or selection["status"]!="EXPLICIT_AST_FILE_SELECTION_UNREVIEWED":
            raise ProofError("unexpected source-selection schema")
        catalog=json.loads(a.catalog.read_text())
        result=analyze(catalog,old+train+fresh["cases"],a.case_id,a.root,selection["files"])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(result))
        print(json.dumps({"status":STATUS,"files":len(result["scanned_files"]),
                          "bound_call_shapes":len(result["bound_syntactic_calls"]),
                          "runtime_callee_identity_verified":False,
                          "network_eligible":False},indent=2))
        return 0
    except (ProofError,ValueError,OSError,TypeError,KeyError) as exc:
        p.exit(1,f"FALSUM 2Y STATIC BINDING ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
