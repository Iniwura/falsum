"""Authenticate a new public upstream Flask security regression at exact Git commits.

One researcher-selected public source-project-disjoint case, NOT a blind model
holdout, independent AppSec gold, an accepted Telegraph evaluator or proof of
production exploitability. Requires real upstream pytest execution in CI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

STATUS = "PHASE4Z_FLASK_NEW_PROJECT_REAL_UPSTREAM_PARENT_FAIL_FIX_PASS_NOT_MODEL_GOLD"
PIN = {
    "schema_version": 1,
    "status": "PHASE4Z_RESEARCHER_SELECTED_PUBLIC_FLASK_CASE_NOT_BLIND_EXPERT_GOLD",
    "selection_date": "2026-11-19",
    "intent": "SECURITY_REVIEW_GENERAL",
    "case_id": "flask-session-cookie-vary",
    "repository": "pallets/flask",
    "security_family": "session-cookie-response-cache-variation",
    "advisory": "GHSA-m2qf-hxjv-5gpq",
    "fixed_commit": "8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d",
    "direct_parent": "9532cba45d2339e90ebf04f178b1e4f2064e7328",
    "source_path": "src/flask/sessions.py",
    "test_path": "tests/test_basic.py",
    "parent_source_blob": "1334184eb0110d400fd741e8e3b80c0ee9b5c725",
    "fixed_source_blob": "e5650d6862ba235cda3f935e21679cc9d866958c",
    "parent_test_blob": "32b41b637810f10a139657a5e02d950733cbf41f",
    "fixed_test_blob": "ca373dcae35d60b23c70cfd1a473d59616c1c1f5",
    "original_upstream_test_selector": "tests/test_basic.py::test_session_vary_cookie",
    "new_upstream_security_regression_selector": "tests/test_basic.py::test_session_refresh_vary",
}
FACTS = {
    "fix_source_changes_vary_cookie_on_permanent_session_refresh": True,
    "synthetic_in_process_flask_test_client_only": True,
    "external_network_and_customer_data_used": False,
    "researcher_selected_not_external_independent": True,
    "no_blind_trained_model_holdout_claim": True,
    "independent_human_gold_labels": 0,
    "new_anjoman_evaluation_rows": 0,
    "network_evaluator_registered": False,
}
MAX_LOG = 2_500_000
MAX_FILE = 160_000


class FlaskEvidenceError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise FlaskEvidenceError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def read(path: Path, maximum: int) -> bytes:
    require(path.is_file() and not path.is_symlink(), "missing or symlinked source/test/log file")
    require(0 < path.stat().st_size <= maximum, "missing/oversized source/test/log file")
    return path.read_bytes()


def load_lock(raw: bytes) -> dict:
    require(isinstance(raw, bytes) and 0 < len(raw) <= 15_000, "missing or oversized pinned lock")
    try:
        lock = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise FlaskEvidenceError("invalid JSON source selection") from exc
    require(isinstance(lock, dict) and set(lock) == set(PIN) | {"facts"},
            "wrong source selection fields")
    for key, expected in PIN.items():
        require(lock.get(key) == expected and type(lock.get(key)) is type(expected),
                "unapproved upstream revision or source/test identity: " + key)
    require(lock["facts"] == FACTS and
            all(type(lock["facts"][key]) is type(expected)
                for key, expected in FACTS.items()),
            "source evidence incorrectly upgraded to model/expert gold")
    return lock


def _git(worktree: Path, *args: str) -> str:
    require(worktree.is_dir() and not worktree.is_symlink(), "not a real worktree")
    try:
        p = subprocess.run(["git", "-C", str(worktree), *args],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=12, check=True)
        return p.stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise FlaskEvidenceError("unable to authenticate original upstream Git object") from exc


def inspect_tree(lock: dict, root: Path, revision: str, *, overlay: bool) -> dict:
    require(revision in ("parent", "fixed"), "invalid revision role")
    commit = lock["direct_parent"] if revision == "parent" else lock["fixed_commit"]
    require(_git(root, "rev-parse", "HEAD") == commit,
            "live checked out commit differs from pinned direct parent/fix")
    if revision == "fixed":
        raw_object = _git(root, "cat-file", "-p", "HEAD")
        parents = [line[7:] for line in raw_object.split("\n\n", 1)[0].splitlines()
                   if line.startswith("parent ")]
        require(parents == [lock["direct_parent"]],
                "fixed commit is not the original single-parent upstream fix")
    source = read(root / lock["source_path"], MAX_FILE)
    test = read(root / lock["test_path"], MAX_FILE)
    expected_source = lock[f"{revision}_source_blob"]
    expected_test = lock["fixed_test_blob"] if overlay else lock[f"{revision}_test_blob"]
    require(git_blob(source) == expected_source,
            "upstream source bytes not authentic to pinned Git blob")
    require(git_blob(test) == expected_test,
            "upstream test bytes not authentic to pinned original regression")
    return {
        "commit": commit,
        "source_blob_sha1": expected_source,
        "executed_test_blob_sha1": expected_test,
        "source_sha256": sha(source),
        "test_sha256": sha(test),
        "security_test_overlaid_from_exact_fixed_upstream": overlay,
        "verified_from_actual_upstream_git_worktree": True,
    }


def verify_log_evidence(original: str, parent_reg: str, fixed_reg: str,
                        exits: tuple[int, int, int]) -> None:
    require(exits[0] == 0 and exits[1] != 0 and exits[2] == 0,
            "must observe original parent PASS, new regression parent FAIL, new regression fix PASS")
    require("test_session_vary_cookie" in original and "passed" in original.lower(),
            "original upstream session behavior test did not pass")
    # The test name itself includes "vary": it MUST NOT satisfy the
    # assertion evidence. Require the missing header in an actual failure
    # diagnostic line instead of merely co-occurring in the pytest output.
    assertion_lines = [
        line.strip() for line in parent_reg.splitlines()
        if re.search(r"(?:keyerror|assertionerror)", line, re.IGNORECASE)
    ]
    vary_assertion = any(
        re.search(r"\\b(?:keyerror|assertionerror)\\b", line, re.IGNORECASE)
        and re.search(r"\\bvary\\b", line, re.IGNORECASE)
        for line in assertion_lines
    )
    require("test_session_refresh_vary" in parent_reg and
            ("failed" in parent_reg.lower() or "failures" in parent_reg.lower())
            and vary_assertion,
            "parent failed for a setup/import error rather than session Vary assertion")
    require("test_session_refresh_vary" in fixed_reg and
            re.search(r"\b1 passed\b", fixed_reg.lower()) is not None
            and "failed" not in fixed_reg.lower(),
            "fixed original upstream security regression did not pass")


def _exit(path: Path) -> int:
    raw = read(path, 10).decode("ascii").strip()
    require(re.fullmatch(r"[0-9]{1,3}", raw) is not None, "malformed test exit record")
    code = int(raw)
    require(0 <= code <= 255, "invalid recorded process exit status")
    return code


def inspect(lock_raw: bytes, parent_dir: Path, fixed_dir: Path, logs: Path) -> dict:
    lock = load_lock(lock_raw)
    require(parent_dir.resolve() != fixed_dir.resolve(),
            "parent/fix worktrees must be separate")
    parent = inspect_tree(lock, parent_dir, "parent", overlay=True)
    fixed = inspect_tree(lock, fixed_dir, "fixed", overlay=False)
    names = ("parent-original", "parent-regression", "fixed-regression")
    exits = tuple(_exit(logs / (x + ".exit")) for x in names)
    log_bytes = [read(logs / (x + ".log"), MAX_LOG) for x in names]
    log_texts = [s.decode("utf-8", "replace") for s in log_bytes]
    verify_log_evidence(*log_texts, exits)
    return {
        "schema_version": 1,
        "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "repository": lock["repository"],
        "case_id": lock["case_id"],
        "advisory": lock["advisory"],
        "upstream_parent_git_commit": lock["direct_parent"],
        "upstream_fix_git_commit": lock["fixed_commit"],
        "original_upstream_regression_test_sha1": lock["fixed_test_blob"],
        "parent_with_fixed_regression_overlay": parent,
        "original_fixed_upstream_test": fixed,
        "test_exit_statuses": dict(zip(names, exits)),
        "original_upstream_parent_test_passed": True,
        "parent_failed_fixed_upstream_security_test_expected_assertion": True,
        "fixed_passed_same_original_upstream_security_test": True,
        "raw_test_log_sha256": dict(zip(names, map(sha, log_bytes))),
        "real_upstream_pytest_processes_run": True,
        "selected_new_public_project_not_from_four_case_index": True,
        "researcher_selected_case_not_independent_review": True,
        "independent_human_security_gold": 0,
        "new_anjoman_rows": 0,
        "old_lora_model_quality_improvement_measured": False,
        "new_model_generalization_proven": False,
        "registered_network_evaluator": False,
        "production_exploitability_demonstrated": False,
        "official_h2_entry_submitted": False,
        "limitations": (
            "Real public Flask upstream original parent PASS, fixed author's new "
            "session Vary header regression FAIL on original parent for the expected "
            "assertion, fixed source PASS. This was researcher-selected, not a blind "
            "or independent human-adjudicated evaluation. It does not prove a "
            "real-world shared-cache cookie disclosure, model scoring improvement, "
            "Telegraph registration, a new Anjoman row, or official H2 acceptance."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Reproduce exact original upstream Flask Vary: Cookie fix")
    p.add_argument("--lock", type=Path, required=True)
    p.add_argument("--parent", type=Path, required=True)
    p.add_argument("--fixed", type=Path, required=True)
    p.add_argument("--logs", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink() and
                args.out.resolve() not in {
                    args.lock.resolve(), args.parent.resolve(), args.fixed.resolve(),
                    args.logs.resolve(),
                }, "output must be write-once, separate from evidence")
        result = inspect(read(args.lock, 15_000), args.parent, args.fixed, args.logs)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status": result["status"],
            "real_upstream_parent_failed_new_test_for_expected_assertion": True,
            "fixed_upstream_test_passed": True,
            "independent_human_gold": 0,
            "new_model_generalization_proven": False,
        }))
        return 0
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, IndexError) as exc:
        p.exit(1, "FALSUM PHASE4Z FLASK REAL SOURCE PROOF REJECTED: " + str(exc)[:220] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
