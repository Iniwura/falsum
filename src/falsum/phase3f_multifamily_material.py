"""Phase 3F: independent, diverse upstream SECURITY_REVIEW material.

Seven non-aiohttp vulnerability families. Sources are the actual historical
upstream repair commits and their regression test patches, verified by
FALSUM real_fix_corpus.verify_commit against full commit, parent, file Git
blob IDs, and source+test diff hashes. Output is prospective HUMAN review
material only. No alleged deployed exploit, verified label or network row.

The prior three fresh Phase2U projects stay excluded, as do Phase3D
counterfactual prompts. This is NOT a fresh blind holdout for any model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import ProofError, _canonical, validate_catalog
from .real_fix_corpus import load_queue, assemble, STATUS as SOURCE_STATUS

STATUS="PHASE3F_SEVEN_DISTINCT_PUBLIC_SECURITY_PATCH_REVIEW_CASES_UNADJUDICATED"
PINS=(
    ("real-requests-proxy-auth","psf/requests",
     "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5",
     "dbcf2a7b0ee2898b72714b756e4b27fbbad4beab",
     "b420c44d73cde0c2ab7e7aa0e5182b345436f718"),
    ("real-jinja-attr-sandbox","pallets/jinja",
     "065334d1ee5b7210e1a0a93c37238c86858f2af7",
     "2bcba4fbd3c660edb1166fcad6ef6fc9a4f6a1e5",
     "3a13781926e45e598dc8df936b7df7fcbc1a449e"),
    ("real-axios-absolute-baseurl","axios/axios",
     "02c3c69ced0f8fd86407c23203835892313d7fde",
     "553cffcb5e26bebe93577adae7c1f73f6cd0f293",
     "ecf9ee730bf504f7faad3578e1ca53566aca3da3"),
    ("real-starlette-commonprefix-traversal","Kludex/starlette",
     "1797de464124b090f10cf570441e8292936d63e3",
     "4c856063c2945d93f1b79505f9d8de7919b947aa",
     "23d0b57fc2b23fbc5f23734ce856980a3d4ae064"),
    ("real-urllib3-redirect-header-case","urllib3/urllib3",
     "adb358f8e06865406d1f05e581a16cbea2136fbc",
     "a13149b1bce41d543b272789557d8c427e7bdded",
     "de0b9172d932678fd6b11c6b0b7159fabcacf4f5"),
    ("real-django-intcomma-recursive-dos","django/django",
     "55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9",
     "2c26f8944a78da3cc378196d185a34cfd3e17d2c",
     "a78bbadafd895975b6e9f7750afbc786061f28d3"),
    ("real-express-malformed-redirect-host","expressjs/express",
     "0b746953c4bd8e377123527db11f9cd866e39f94",
     "dd7b3c8201d24c47a537b85f6615a967392f8691",
     "c80b38de6b8f64b6478ee2a0abbb3ad2bdf2801b"),
)

# Each pair deliberately includes a plausible but overgeneralized answer.
# A/B order alternates; none of these author judgments is ground truth.
PROMPTS={
    "real-requests-proxy-auth":(
        "The historical repair concerns Proxy-Authorization during HTTPS redirects. "
        "What conditions are required to apply this finding to a specific caller?",
        "A",(
            "The patch highlights a credentialed-proxy plus HTTPS-redirect boundary. "
            "Verify that both occur for an affected installed version and that secrets "
            "reach a redirect before escalating from a source-risk candidate.",
            "Any use of requests.get with allow_redirects=True leaks proxy credentials "
            "because redirects automatically reveal passwords. A proxy password and "
            "a real HTTPS redirect path need not be established.",
        )
    ),
    "real-jinja-attr-sandbox":(
        "The published Jinja attr-filter sandbox fix changes security checks. Does "
        "passing an untrusted variable into a fixed template prove the bypass?",
        "B",(
            "A user-controlled variable is sufficient to trigger the historical attr "
            "filter sandbox escape in any otherwise fixed server-side template. "
            "No evidence of attacker-controlled template source is needed.",
            "An attacker-controlled template source and affected sandbox attr path "
            "must be established. Variable values in a fixed template alone do not "
            "prove this particular sandbox-escape precondition.",
        )
    ),
    "real-axios-absolute-baseurl":(
        "The Axios patch changes absolute URL handling despite baseURL. How should "
        "the caller reason about absolute targets from untrusted input?",
        "B",(
            "Configuring baseURL guarantees an allowlist for every absolute URL even "
            "if a downstream client accepts attacker-controlled absolute targets. "
            "The added option cannot affect the request destination.",
            "An absolute supplied URL can override the intended baseURL depending "
            "on version and allowAbsoluteUrls configuration. Inspect the actual "
            "client options, target control and network behavior; don't infer SSRF "
            "solely from having a baseURL.",
        )
    ),
    "real-starlette-commonprefix-traversal":(
        "Starlette changed the static root check from lexical commonprefix to "
        "path-aware commonpath. What deployment evidence is needed?",
        "A",(
            "A lexically shared filename prefix is not proof of a contained path. "
            "Check the installed historical StaticFiles behavior, a reachable "
            "route and a readable sibling sharing the root prefix before claiming "
            "a real traversal exposure.",
            "String commonprefix correctly enforces filesystem directory ancestry. "
            "Any sibling path beginning with the same letters is already inside "
            "the static root and needs no path-aware containment check.",
        )
    ),
    "real-urllib3-redirect-header-case":(
        "urllib3 changed removal of authorization headers on cross-origin "
        "redirects. Does header casing matter in the historical path?",
        "B",(
            "Cross-origin redirect handling that removes exactly cased "
            "Authorization is already sufficient for every header spelling, "
            "so casing and redirect configuration cannot affect credential handling.",
            "Historically a differently cased authorization header could avoid "
            "exact-case removal. Verify a credential-bearing caller, redirect "
            "destination, actual casing and stripping policy; a generic redirect "
            "alone does not prove a leak.",
        )
    ),
    "real-django-intcomma-recursive-dos":(
        "The Django humanize intcomma patch changes recursive formatting of very "
        "long numbers. Does any ordinary call constitute a demonstrated DoS?",
        "A",(
            "The relevant boundary involves unusually long, effectively unbounded "
            "numeric input reaching the affected formatter. Establish attacker "
            "control, effective limits and installed version; ordinary bounded "
            "formatting is not a demonstrated resource-exhaustion attack.",
            "Using the intcomma filter on even a fixed short numeric string is "
            "sufficient evidence of an attacker-triggerable recursive DoS, regardless "
            "of request input control or numeric length limits.",
        )
    ),
    "real-express-malformed-redirect-host":(
        "Express changed redirect Location URL handling for malformed inputs. "
        "When can an application-level host allowlist be bypassed?",
        "A",(
            "Compare the actual allowlist parser and emitted Location encoding, "
            "especially malformed attacker-controlled URLs. A parser disagreement "
            "may affect a caller, but does not prove all res.redirect uses are unsafe.",
            "Any res.redirect invocation bypasses every host allowlist by default. "
            "Whether the requester controls the target or the two parsers disagree "
            "on malformed URLs cannot change this conclusion.",
        )
    ),
}


def generate(original:dict,training:dict,catalog:dict,fetcher=None)->dict:
    if (not isinstance(original,dict) or original.get("status")!=SOURCE_STATUS
        or not isinstance(training,dict) or training.get("status")!=SOURCE_STATUS):
        raise ProofError("both source corpora must retain draft-only status")
    # The same checked-in source identity lists are independently validated
    # before any access to public upstream commits.
    old=original.get("cases"); train=training.get("cases")
    if not isinstance(old,list) or not isinstance(train,list) or len(old)!=4 or len(train)!=4:
        raise ProofError("expected four original and four training sources")
    if set(PROMPTS)!={x[0] for x in PINS}:
        raise ProofError("not all source families have explicit question design")
    actual_rows=old+train
    sources={row["id"]:row for row in actual_rows}
    if len(sources)!=8 or len(set(row["repository"] for row in actual_rows))!=8:
        raise ProofError("eight unique upstream public sources required")
    for ident,repo,commit,src_blob,test_blob in PINS:
        row=sources.get(ident)
        if (row is None or row["repository"]!=repo or row["commit"]!=commit
            or row["source_blob"]!=src_blob or row["test_blob"]!=test_blob):
            raise ProofError("pinned historical source identity changed")
    if any(row["id"].startswith("fresh-") for row in actual_rows):
        raise ProofError("exclude fresh Phase2U source-separated diagnostic projects")
    # Source pinned Phase2W hypotheses remain unapproved.
    # Match their versioned source identities instead of silently using
    # arbitrary rule explanations as reviewed ground truth.
    if (not isinstance(catalog,dict)
        or catalog.get("status")!="RESEARCH_SOURCE_PINNED_APPLICABILITY_RULES_NOT_SECURITY_CERTIFICATION"
        or catalog.get("research_only") is not True
        or catalog.get("independent_human_reviews")!=0
        or catalog.get("network_eligible") is not False
        or not isinstance(catalog.get("rules"),list)
        or len(catalog["rules"])!=11):
        raise ProofError("applicability metadata falsely claims external validation")
    rule_map={r.get("case_id"):r for r in catalog["rules"] if isinstance(r,dict)}
    if len(rule_map)!=11:
        raise ProofError("duplicate applicability rule identity")
    for ident,repo,commit,source_blob,test_blob in PINS:
        rule=rule_map.get(ident)
        original_row=sources[ident]
        if (not isinstance(rule,dict)
            or rule.get("repository")!=repo
            or rule.get("source_commit")!=commit
            or rule.get("source_blob")!=source_blob
            or rule.get("source_path")!=original_row["source_path"]
            or rule.get("source_advisory")!=original_row["advisory"]
            or not isinstance(rule.get("requirements"),list)
            or len(rule["requirements"])!=2
            or any(not isinstance(x,dict) or
                   set(x)!={"id","explanation"} for x in rule["requirements"])):
            raise ProofError("AI-authored prerequisite rule source changed or is incomplete")
    # Verify the upstream *actual* Git commit, one parent, and source AND
    # regression-test modified-file blob objects/diff hashes. No execution.
    old_report=assemble(original,fetcher=fetcher)
    train_report=assemble(training,fetcher=fetcher)
    for report,n in ((old_report,4),(train_report,4)):
        if (report["status"]!="SOURCE_VERIFIED_LABELS_UNREVIEWED"
            or report["source_verified"]!=n
            or report["independent_human_reviews"]!=0
            or report["training_authorized"] is not False
            or report["network_eligible"] is not False):
            raise ProofError("source verification output was promoted to approved")
    verified={r["id"]:r for r in old_report["cases"]+train_report["cases"]}
    if len(verified)!=8:
        raise ProofError("source verification omitted or duplicated project")
    # Unlike a live exploit validation, these pinned post-fix commits only
    # establish published patch text and test changes.
    questions=[]
    for ident,repo,commit,source_blob,test_blob in PINS:
        item=verified[ident]
        if (item["repository"]!=repo or item["commit"]!=commit
            or item["source"]["post_fix_blob"]!=source_blob
            or item["regression_test"]["post_fix_blob"]!=test_blob
            or item["external_review_status"]!="NOT_REVIEWED"
            or item["proposed_preference_label"] is not None
            or item["training_authorized"] is not False
            or item["network_eligible"] is not False):
            raise ProofError("verified patch source was altered or falsely labeled")
        prompt,author_expected,answers=PROMPTS[ident]
        if (len(answers)!=2 or author_expected not in ("A","B")
            or len(set(answers))!=2):
            raise ProofError("invalid candidate question design")
        questions.append({
            "packet_id":ident,
            "security_family":item["family"],
            "cve":item["cve"],"advisory":item["advisory"],
            "repository":repo,
            "fix_commit":commit,"pre_fix_commit":item["parent"],
            "fix_commit_url":item["commit_url"],
            "advisory_url":item["advisory_url"],
            "source_file":item["source"]["file_path"],
            "source_post_fix_git_blob_sha1":source_blob,
            "source_patch_sha256":item["source"]["sha256"],
            "regression_test_file":item["regression_test"]["file_path"],
            "regression_test_post_fix_git_blob_sha1":test_blob,
            "regression_test_patch_sha256":item["regression_test"]["sha256"],
            "source_url":(
                f"https://github.com/{repo}/blob/{commit}/"
                f"{item['source']['file_path']}"
            ),
            "test_url":(
                f"https://github.com/{repo}/blob/{commit}/"
                f"{item['regression_test']['file_path']}"
            ),
            "review_question":prompt,
            "source_pinned_unreviewed_prerequisites":[
                {"id":x["id"],"question":x["explanation"],
                 "status":"AUTHOR_HYPOTHESIS_NOT_HUMAN_VERIFIED"}
                for x in rule_map[ident]["requirements"]
            ],
            "unreviewed_candidates":[
                {"id":"A","text":answers[0],"sha256":hashlib.sha256(answers[0].encode()).hexdigest()},
                {"id":"B","text":answers[1],"sha256":hashlib.sha256(answers[1].encode()).hexdigest()},
            ],
            # Internal draft polarity supports balanced review design.
            # It is NOT a label; must not feed training or be in public
            # results. Deliberately do not put author_expected into packet.
            "human_preference":None,
            "human_review_verified":False,
            "candidate_order_human_randomized":False,
            "source_patch_is_exploit_proof":False,
            "production_app_version_known":False,
            "production_traffic_exposure_known":False,
            "network_eligible":False,
            "training_authorized":False,
            "label_status":"AUTHOR_DRAFT_WITH_REAL_SOURCE_NOT_ADJUDICATED",
            "review_guidance":"Inspect both actual upstream patch and regression test plus advisory; challenge the draft answers. State any missing application/version/attacker precondition and abstain if neither answer is well supported. The presence of a fix is not proof of production exploitability."
        })
    if len(questions)!=7 or len({x["security_family"] for x in questions})!=7:
        raise ProofError("seven distinct non-aiohttp vulnerability families required")
    return {
        "schema_version":1,
        "status":STATUS,
        "intent":"SECURITY_REVIEW_GENERAL",
        "external_source_revisions_verified":8,
        "external_source_and_test_file_blob_pairs_verified":8,
        "review_packets":questions,
        "review_cases":7,
        "distinct_security_families":7,
        "source_selection":"SEVEN_PRIOR_SOURCE_PROJECTS_NOT_FRESH_HOLDOUT",
        "research_only":True,
        "fresh_project_holdout_reused":False,
        "independent_human_labels":0,
        "accepted_training_pairs":0,
        "network_eligible":False,
        "registered_evaluator":False,
        "full_application_execution":False,
        "actual_production_exploits_verified":0,
        "original_queue_sha256":hashlib.sha256(_canonical(original)).hexdigest(),
        "training_queue_sha256":hashlib.sha256(_canonical(training)).hexdigest(),
        "catalog_sha256":hashlib.sha256(_canonical(catalog)).hexdigest(),
        "notice":"Authentic immutable upstream source AND regression test patches for seven different public security fixes. The paired answer texts and review questions are still FALSUM authored and UNADJUDICATED. Neither patch identity nor a model's preference is an independent security-accuracy label."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Generate seven distinct Git-reverified upstream review questions, not trainer-ready labels")
    for n in ("old-queue","train-queue","catalog","out"):
        p.add_argument("--"+n,required=True,type=Path)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ProofError("refuse to overwrite prior public review material")
        result=generate(
            load_queue(a.old_queue),load_queue(a.train_queue),
            json.loads(a.catalog.read_text(encoding="utf-8"))
        )
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(result))
        print(json.dumps({
            "status":STATUS,"source_commit_and_test_pairs_verified":8,
            "unique_review_vulnerability_families":7,
            "independent_human_labels":0,"accepted_training_pairs":0,
            "network_eligible":False
        },indent=2))
        return 0
    except (ProofError,ValueError,TypeError,KeyError,OSError) as exc:
        p.exit(1,f"FALSUM DIVERSE REVIEW MATERIAL ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
