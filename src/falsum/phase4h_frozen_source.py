"""Phase 4H: reverify FOUR newly selected upstream projects from a pre-score lock.

This checks exact Git source/test blobs and commit parents, not production
exploitability, human expert gold labels, executed upstream tests, or ML quality.
Source selection was frozen in an earlier Git commit BEFORE any scoring jobs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen

STATUS = "PHASE4H_FOUR_PUBLIC_NEW_PROJECT_SOURCE_COMMITS_AND_TESTS_VERIFIED_NOT_GOLD"
LOCK_STATUS = "PHASE4H_SOURCE_SELECTION_FROZEN_BEFORE_REAL_MODEL_SCORING"
LOCK_GIT_BLOB = "9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2"
PINNED_PROJECTS = ("pyjwt", "werkzeug", "mcp-python", "pillow")
PRIOR = frozenset(("aiohttp","requests","jinja","axios","starlette","urllib3",
                    "django","express","tornado","undici","websockets",
                    "docling-core","hydra-core","python-multipart"))
SHA40 = re.compile(r"^[0-9a-f]{40}$")
IDENT = re.compile(r"^[a-z][a-z-]*$")
MAX_BYTES = 800_000


class SourceError(ValueError):
    pass


def require(ok: bool, message: str):
    if not ok:
        raise SourceError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def validate_lock(raw: bytes) -> dict:
    require(git_blob(raw) == LOCK_GIT_BLOB, "source selection was changed AFTER freeze")
    d = json.loads(raw)
    require(isinstance(d, dict)
            and d.get("status") == LOCK_STATUS
            and d.get("schema_version") == 1
            and d.get("intent") == "SECURITY_REVIEW_GENERAL"
            and d.get("source_cases") == 4
            and d.get("revision_conditions") == 8
            and d.get("source_fact_pair_reversals") == 4
            and d.get("model_score_inputs_planned") == 16
            and d.get("source_based_researcher_expected_A") == 4
            and d.get("source_based_researcher_expected_B") == 4
            and d.get("not_model_pretraining_disjoint") is True
            and d.get("not_private_blind_holdout") is True
            and d.get("independent_appsec_adjudicated_labels") == 0
            and d.get("source_change_verification_required") is True
            and d.get("upstream_tests_not_rerun_by_manifest") is True
            and d.get("no_model_training_allowed") is True
            and d.get("no_network_evaluator_registration") is True,
            "frozen manifest research-only and project counts do not match")
    cases = d.get("cases")
    require(isinstance(cases, list) and len(cases) == 4
            and tuple(c.get("key") for c in cases) == PINNED_PROJECTS,
            "different source project count or order")
    names, repos, families = set(), set(), set()
    for row in cases:
        require(isinstance(row, dict), "malformed source case")
        name, repo, family = row.get("key"), row.get("repository"), row.get("family")
        require(isinstance(name, str) and IDENT.fullmatch(name)
                and isinstance(repo, str) and repo.count("/") == 1
                and isinstance(family, str) and family
                and name not in names and repo not in repos and family not in families
                and name not in PRIOR
                and repo.lower().split("/")[-1] not in PRIOR,
                "project overlaps earlier public FALSUM research or duplicated")
        names.add(name); repos.add(repo); families.add(family)
        require(all(isinstance(row.get(k),str) and SHA40.fullmatch(row[k])
            for k in ("parent","fixed","parent_source_blob","fixed_source_blob",
                      "parent_test_blob","fixed_test_blob"))
            and row["parent"] != row["fixed"]
            and row["parent_source_blob"] != row["fixed_source_blob"],
            "invalid commit SHA or unchanged source claimed as patch")
        require(all(isinstance(row.get(k),str) and row[k]
                    and ".." not in row[k] and not row[k].startswith("/")
                    for k in ("source_path","test_path","before_anchor","after_anchor"))
                and isinstance(row.get("advisory"),str)
                and row["advisory"].startswith("https://github.com/advisories/GHSA-")
                and row.get("test_changed_in_fix") is
                    (row["parent_test_blob"] != row["fixed_test_blob"])
                and (row.get("test_added_anchor") is None or
                     isinstance(row["test_added_anchor"], str)),
                "source or test path/identity/delta claim invalid")
        require(row.get("source_preference_before")=="A"
                and row.get("source_preference_after")=="B"
                and isinstance(row.get("question_before"),str)
                and isinstance(row.get("question_after"),str)
                and len(row["question_before"])>100
                and len(row["question_after"])>100
                and isinstance(row.get("a"),str) and len(row["a"])>60
                and isinstance(row.get("b"),str) and len(row["b"])>60
                and row["a"] != row["b"],
                "unbalanced, missing or trivial source task")
    return d


def source_url(row: dict, revision: str, kind: str) -> str:
    require(revision in ("parent","fixed") and kind in ("source","test"),
            "unexpected source selector")
    part = row["source_path"] if kind == "source" else row["test_path"]
    return ("https://raw.githubusercontent.com/" + row["repository"]
            + "/" + row[revision] + "/" + part)


def bounded_fetch(url: str) -> bytes:
    require(url.startswith("https://raw.githubusercontent.com/")
            or url.startswith("https://api.github.com/repos/"),
            "external domain not allowed")
    headers = {"User-Agent":"FALSUM-phase4h-locked-source-reproduction/1",
               "Accept":"application/vnd.github+json"}
    if url.startswith("https://api.github.com/repos/") and os.getenv("GITHUB_TOKEN"):
        headers["Authorization"]="Bearer "+os.environ["GITHUB_TOKEN"]
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=30) as resp:
            require(resp.status == 200 and resp.geturl() == url, "external redirect/HTTP failure")
            payload = resp.read(MAX_BYTES+1)
    except OSError as e:
        raise SourceError("unable to fetch pinned public source " + url) from e
    require(0 < len(payload) <= MAX_BYTES, "source download over size limit")
    return payload


def verify_locked_source(raw: bytes, fetcher=bounded_fetch) -> dict:
    manifest = validate_lock(raw)
    verified = []
    for row in manifest["cases"]:
        name, repo = row["key"], row["repository"]
        commit_url = f"https://api.github.com/repos/{repo}/commits/{row['fixed']}"
        commit = json.loads(fetcher(commit_url))
        require(commit.get("sha") == row["fixed"]
                and len(commit.get("parents", [])) >= 1
                and commit["parents"][0].get("sha") == row["parent"],
                "fixed commit or claimed direct parent mismatch " + name)
        changed_paths = {
            x.get("filename") for x in commit.get("files", [])
            if isinstance(x,dict) and x.get("status") in ("modified","added","removed","renamed")
        }
        require(row["source_path"] in changed_paths
                and (row["test_path"] in changed_paths) is row["test_changed_in_fix"],
                "fix does not modify source/test as declared " + name)
        proof = {}
        texts = {}
        for revision in ("parent","fixed"):
            for kind in ("source","test"):
                url = source_url(row,revision,kind)
                content = fetcher(url)
                expected = row[revision+"_"+kind+"_blob"]
                require(git_blob(content) == expected, "Git source blob mismatch: "+url)
                proof[revision+"_"+kind] = {
                    "pinned_git_blob_sha1": expected,
                    "downloaded_bytes_sha256":sha256(content),
                    "bytes":len(content), "url":url,
                }
                texts[(revision,kind)] = content.decode("utf-8")
        require(row["before_anchor"] in texts[("parent","source")]
                and row["after_anchor"] in texts[("fixed","source")]
                and row["after_anchor"] not in texts[("parent","source")],
                "patch-specific source branch not verified " + name)
        if row["test_added_anchor"] is not None:
            require(row["test_changed_in_fix"]
                    and row["test_added_anchor"] in texts[("fixed","test")]
                    and row["test_added_anchor"] not in texts[("parent","test")],
                    "claimed new regression test is absent or pre-existing " + name)
        verified.append({
            "project":name,"upstream_repository":repo,
            "family":row["family"],"advisory":row["advisory"],
            "fixed_commit_api_url":commit_url,
            "fix_commit":row["fixed"],"direct_parent_commit":row["parent"],
            "source_file_modified_in_pinned_fix":True,
            "selected_test_file_modified_in_pinned_fix":row["test_changed_in_fix"],
            "source_before_and_after_anchor_verified":True,
            "test_added_anchor_verified":row["test_added_anchor"] is not None,
            "source_and_test_blobs":proof,
        })
    return {
        "schema_version":1,"status":STATUS,
        "frozen_selection_git_blob":LOCK_GIT_BLOB,
        "frozen_selection_sha256":sha256(raw),
        "source_repositories_verified":4,
        "source_revision_conditions":8,
        "source_parent_and_fix_file_blob_checks":16,
        "source_patches_verified":4,
        "selected_test_files_changed_in_fix":sum(x["selected_test_file_modified_in_pinned_fix"] for x in verified),
        "selected_test_files_unchanged_in_fix":sum(not x["selected_test_file_modified_in_pinned_fix"] for x in verified),
        "commits_real_and_parent_verified":True,
        "downloaded_public_patches_executed":False,
        "independent_appsec_gold_labels":0,
        "new_eligible_anjoman_rows":0,
        "registered_evaluator":False,
        "model_scores_observed":False,
        "public_new_to_repo_not_blind_or_pretraining_disjoint":True,
        "projects":verified,
        "notice":"Exact public Git source and regression-test file blobs verified. Two of four selected test files are UNCHANGED by the security fix commit. Source verification alone does not run the upstream tests, prove deployed exploitability or certify author expectations."
    }


def main(argv=None):
    p=argparse.ArgumentParser(description="Verify precommitted four new public source revisions")
    p.add_argument("--lock",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink(), "refuse output overwrite")
        proof=verify_locked_source(args.lock.read_bytes())
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:proof[k] for k in (
            "status","source_repositories_verified","source_patches_verified",
            "selected_test_files_changed_in_fix","selected_test_files_unchanged_in_fix",
            "independent_appsec_gold_labels")},indent=2))
        return 0
    except (ValueError,KeyError,TypeError,IndexError,OSError,UnicodeError) as e:
        p.exit(1, "PHASE4H FROZEN SOURCE REJECTED: "+str(e)+"\n")

if __name__=="__main__":
    raise SystemExit(main())
