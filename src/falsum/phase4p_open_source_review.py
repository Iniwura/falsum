"""Phase 4P: new project-disjoint, open-response source challenge pack.

Three NEVER PREVIOUSLY SCORED BY FALSUM upstream projects, four historical
source+regression-test changes. This is public source-grounded review material:
not blinded gold, a trained evaluator, a production exploitation claim,
an accepted Anjoman contributor row, or official model improvement.

Lock file was committed *before* this verifier (git blob asserted below).
The verifier downloads exact public GitHub commit API records and source/test
bytes at BOTH parent and fixed revisions and checks Git's actual blob hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request

from .phase3f_multifamily_material import PINS
from .real_fix_corpus import fetch_github_commit

LOCK_BLOB_SHA1 = "feedebd09adf193271a01e19a7213e223314a04d"
LOCK_STATUS = "PHASE4P_FROZEN_THREE_NEW_PUBLIC_PROJECTS_OPEN_REVIEW_NOT_GOLD"
STATUS = "PHASE4P_FOUR_SOURCE_TEST_PATCHES_VERIFIED_THREE_OPEN_REVIEW_PROJECTS_NOT_GOLD"
ID_ORDER = (
    "phase4p-koa-referer-redirect",
    "phase4p-langchain-prompt-path",
    "phase4p-hono-hyperlink-csrf",
)
STAGE_IDS = (
    ("origin-check-guard",),
    ("initial-default-path-validation", "followup-resolved-symlink-suffix"),
    ("text-ping-csrf-content-type",),
)
GITHUB_SHA = re.compile(r"^[a-f0-9]{40}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GHSA = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$")
PRIOR_SCORED_REPOSITORIES = frozenset((
    "jpadilla/pyjwt", "pallets/werkzeug",
    "modelcontextprotocol/python-sdk", "python-pillow/Pillow",
))
MAX_LOCK = 25_000
MAX_RAW_FILE = 160_000


class NewReviewError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise NewReviewError(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def verify_blob(raw: bytes, expected: str) -> dict:
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RAW_FILE,
            "missing, nonbinary or oversized fetched upstream file")
    require(GITHUB_SHA.fullmatch(expected) is not None and git_blob_sha1(raw) == expected,
            "pinned Git parent/fix source or regression-test blob mismatch")
    return {"git_blob_sha1": expected, "sha256": digest(raw), "bytes": len(raw)}


def load_lock(raw: bytes) -> dict:
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LOCK,
            "source selection lock missing or oversized")
    require(git_blob_sha1(raw) == LOCK_BLOB_SHA1,
            "source selection lock Git blob changed since pre-review commitment")
    try:
        x = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise NewReviewError("invalid frozen source selection JSON") from exc
    require(isinstance(x, dict)
            and x.get("schema_version") == 1
            and x.get("status") == LOCK_STATUS
            and x.get("intent") == "SECURITY_REVIEW_GENERAL"
            and x.get("frozen_prior_to_any_falsum_model_scoring_on_these_cases") is True
            and x.get("no_answer_candidates_or_author_golden_verdicts") is True
            and x.get("open_ended_not_A_B") is True
            and x.get("no_expert_labels") is True
            and x.get("not_a_sealed_or_model_pretraining_blind_holdout") is True
            and x.get("no_new_anjoman_rows") is True
            and x.get("registered_evaluator") is False,
            "frozen no-label, no-scoring source-lock contract violated")
    rows = x.get("cases")
    require(isinstance(rows, list) and len(rows) == 3
            and tuple(c.get("id") for c in rows) == ID_ORDER,
            "three exact source-disjoint cases and their order required")
    forbidden = {r[1].lower() for r in PINS} | {r.lower() for r in PRIOR_SCORED_REPOSITORIES}
    seen_repos, seen_fix_shas, families = set(), set(), set()
    for idx, row in enumerate(rows):
        require(isinstance(row, dict), "case must be an object")
        repo = row.get("repository")
        fam = row.get("security_family")
        require(isinstance(repo, str) and REPO.fullmatch(repo) is not None
                and repo.lower() not in forbidden and repo.lower() not in seen_repos,
                "reused scored project or invalid source repository")
        require(isinstance(fam, str) and 12 <= len(fam) <= 96
                and fam not in families,
                "duplicate security family or malformed category")
        seen_repos.add(repo.lower()); families.add(fam)
        advisory = row.get("advisory_url")
        require(isinstance(advisory, str) and advisory.startswith(
            f"https://github.com/{repo}/security/advisories/")
            and GHSA.fullmatch(advisory.rsplit("/", 1)[-1]) is not None,
            "not canonical public upstream advisory URL")
        questions = row.get("questions")
        require(isinstance(questions, list) and len(questions) == 2
                and all(isinstance(q, str) and 90 <= len(q) <= 700
                        for q in questions)
                and all("?" in q or "explain" in q.lower() or "what" in q.lower()
                        for q in questions), "two substantive open-ended questions required")
        require(set(row) == {"id", "repository", "advisory_url", "security_family",
                             "language", "questions", "patches"},
                "public review source lock contains answer key or undeclared case field")
        stages = row.get("patches")
        require(isinstance(stages, list)
                and tuple(stage.get("stage") for stage in stages) == STAGE_IDS[idx],
                "exact staged source and follow-up patch identities required")
        for stage in stages:
            require(set(stage) == {"stage", "parent", "fix", "source_path",
                                   "test_path", "parent_source_blob", "fixed_source_blob",
                                   "parent_test_blob", "fixed_test_blob"},
                    "undeclared patch labels or unexpected metadata forbidden")
            for key in ("parent", "fix", "parent_source_blob", "fixed_source_blob",
                        "parent_test_blob", "fixed_test_blob"):
                require(isinstance(stage.get(key), str)
                        and GITHUB_SHA.fullmatch(stage[key]) is not None,
                        "source/test full Git SHA is missing")
            require(stage["fix"] not in seen_fix_shas and stage["fix"] != stage["parent"],
                    "source commit reused or self-parent")
            seen_fix_shas.add(stage["fix"])
            for kind in ("source", "test"):
                path = stage.get(kind + "_path")
                require(isinstance(path, str) and SAFE_PATH.fullmatch(path) is not None
                        and ".." not in path.split("/"),
                        "unsafe or missing pinned upstream source/test path")
                require(stage["parent_" + kind + "_blob"] !=
                        stage["fixed_" + kind + "_blob"],
                        "declared source or regression test was unchanged")
            require(stage["source_path"] != stage["test_path"],
                    "cannot call source patch its own independent regression test")
    langchain = rows[1]["patches"]
    require(langchain[0]["fixed_source_blob"] == langchain[1]["parent_source_blob"]
            and langchain[0]["fixed_test_blob"] == langchain[1]["parent_test_blob"],
            "LangChain initial and follow-up source/test Git blobs do not connect")
    return x


def check_commit(stage: dict, repo: str, commit: dict) -> dict:
    require(isinstance(commit, dict)
            and commit.get("sha") == stage["fix"]
            and commit.get("html_url") == f"https://github.com/{repo}/commit/{stage['fix']}",
            "noncanonical GitHub source commit")
    parents = commit.get("parents")
    require(isinstance(parents, list) and len(parents) == 1
            and parents[0].get("sha") == stage["parent"],
            "historical source fix direct Git parent mismatch")
    files = commit.get("files")
    require(isinstance(files, list) and len(files) <= 200,
            "Git commit patch file list missing or incomplete")
    result = {}
    for kind in ("source", "test"):
        path, blob = stage[kind + "_path"], stage["fixed_" + kind + "_blob"]
        matches = [f for f in files if f.get("filename") == path]
        require(len(matches) == 1, "source/test file not uniquely present in patch")
        f = matches[0]
        additions, deletions = f.get("additions"), f.get("deletions")
        require(f.get("status") == "modified" and f.get("sha") == blob
                and type(additions) is int and type(deletions) is int
                and additions >= 0 and deletions >= 0
                and additions + deletions > 0
                and (kind != "test" or additions > 0),
                "expected edited source/test Git blob not present in upstream patch")
        patch = f.get("patch")
        require(isinstance(patch, str) and len(patch) < 100_000
                and patch.startswith("@@ ")
                and (
                    (kind == "test" and any(
                        line.startswith("+") and not line.startswith("+++")
                        for line in patch.splitlines()))
                    or (kind == "source" and any(
                        (line.startswith("+") and not line.startswith("+++"))
                        or (line.startswith("-") and not line.startswith("---"))
                        for line in patch.splitlines()))
                ),
                "source/test patch evidence missing or empty")
        result[kind] = {
            "git_blob_sha1": blob, "patch_sha256": digest(patch.encode("utf-8")),
            "line_additions": f["additions"], "line_deletions": f["deletions"],
            "modified_in_same_upstream_commit": True,
        }
    return result


def raw_file(repo: str, commit: str, path: str) -> bytes:
    require(REPO.fullmatch(repo) is not None and GITHUB_SHA.fullmatch(commit) is not None
            and SAFE_PATH.fullmatch(path) is not None
            and ".." not in path.split("/"),
            "unsafe pinned raw source URI")
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.netloc == "raw.githubusercontent.com",
            "unapproved raw source host")
    request = urllib.request.Request(url, headers={
        "Accept": "text/plain", "User-Agent": "FALSUM-phase4p-source-proof/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            final = urllib.parse.urlsplit(response.geturl())
            require((final.scheme, final.netloc, final.path) ==
                    (parsed.scheme, parsed.netloc, parsed.path)
                    and not final.query and not final.fragment,
                    "Git raw content redirected outside exact pinned public file")
            data = response.read(MAX_RAW_FILE + 1)
    except OSError as exc:
        raise NewReviewError("unable to fetch exact public upstream source file") from exc
    require(len(data) <= MAX_RAW_FILE, "public source exceeded allowed byte limit")
    return data


def generate(lock_raw: bytes, *, commit_fetcher=None, file_fetcher=None) -> dict:
    lock = load_lock(lock_raw)
    get_commit = commit_fetcher or fetch_github_commit
    get_file = file_fetcher or raw_file
    verified = []
    for row in lock["cases"]:
        stages = []
        repo = row["repository"]
        for stage in row["patches"]:
            url = f"https://api.github.com/repos/{repo}/commits/{stage['fix']}"
            commit = get_commit(url)
            proof = check_commit(stage, repo, commit)
            blob_checks = {}
            for rev in ("parent", "fixed"):
                for kind in ("source", "test"):
                    ref = stage["parent"] if rev == "parent" else stage["fix"]
                    path = stage[kind + "_path"]
                    expected = stage[f"{rev}_{kind}_blob"]
                    blob_checks[f"{rev}_{kind}"] = verify_blob(
                        get_file(repo, ref, path), expected)
            stages.append({
                "stage": stage["stage"], "fix_commit": stage["fix"],
                "direct_parent": stage["parent"],
                "source_url": f"https://github.com/{repo}/blob/{stage['fix']}/{stage['source_path']}",
                "test_url": f"https://github.com/{repo}/blob/{stage['fix']}/{stage['test_path']}",
                "fix_source_patch": proof["source"],
                "fix_test_patch": proof["test"],
                "four_parent_and_fixed_source_test_blobs": blob_checks,
            })
        verified.append({
            "case_id": row["id"], "upstream_repository": repo,
            "security_family": row["security_family"],
            "advisory_url": row["advisory_url"],
            "language": row["language"],
            "open_questions": row["questions"],
            "verified_patch_stages": stages,
            "answer_key": None,
            "independent_expert_label": None,
            "independent_expert_review_verified": False,
            "reviewer_required_to_inspect_primary_source": True,
            "training_authorized": False,
            "network_eligible": False,
            "full_deployment_exploitability_proven": False,
        })
    return {
        "schema_version": 1, "status": STATUS,
        "frozen_selection_git_blob_sha1": LOCK_BLOB_SHA1,
        "frozen_selection_sha256": digest(lock_raw),
        "intent_id": "SECURITY_REVIEW_GENERAL",
        "distinct_new_upstream_projects": 3,
        "distinct_security_families": 3,
        "commit_parent_paths_and_test_changes_verified": 4,
        "raw_parent_and_fixed_source_and_test_blob_pairs_verified": 16,
        "open_ended_review_questions": 6,
        "answer_candidates_present": 0,
        "precommit_source_disjoint_from_prior_scored_projects": True,
        "not_a_blind_holdout_of_model_pretraining": True,
        "public_sources_are_not_independent_gold": True,
        "expert_verified_reviewers": 0,
        "new_anjoman_eligible_rows": 0,
        "actual_telegraph_foundation_inference": False,
        "trained_evaluator_registered": False,
        "ready_to_train_or_claim_model_improvement": False,
        "upstream_advisory_content_live_verified": False,
        "actual_published_upstream_test_suite_executed": False,
        "actual_deployed_exploits": 0,
        "cases": verified,
        "notice": (
            "Four exact public Git fixes (three project-disjoint security families), "
            "six unlabeled open-response source review prompts. Checks upstream "
            "Git parent, commit file patches and all 16 actual source/test Git blobs. "
            "This does not verify advisory text content, expert truth, production "
            "exploitation or a sealed model holdout. No private Anjoman material."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify precommitted novel-source review pack, not expert gold")
    p.add_argument("--lock", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        require(args.lock.resolve() != args.out.resolve(), "output aliases input")
        require(not args.out.exists() and not args.out.is_symlink(),
                "refuse overwriting earlier public source proof")
        raw = args.lock.read_bytes()
        report = generate(raw)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({
            "status": report["status"],
            "new_source_projects": report["distinct_new_upstream_projects"],
            "source_and_test_parent_fix_blobs": report["raw_parent_and_fixed_source_and_test_blob_pairs_verified"],
            "open_unlabeled_questions": report["open_ended_review_questions"],
            "independent_expert_reviewers": 0,
            "model_scoring_performed": False,
            "output": str(args.out),
        }, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, IndexError) as exc:
        p.exit(1, "PHASE 4P PINNED SOURCE VERIFICATION BLOCKED: " + str(exc)[:210] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
