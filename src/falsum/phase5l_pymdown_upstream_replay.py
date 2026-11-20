"""Replay a sixth, source-project-disjoint REAL upstream security test in CI.

The exact public case selection was frozen in an earlier commit before this
runner existed. Real actions/checkout Git worktrees + the upstream author's
test are required. Static JSON fixtures and passing unit tests alone cannot
establish that an upstream test actually executed. Not a blind model holdout,
independently reviewed gold label, general language security evaluator,
Anjoman Eligible submission or registered Telegraph scorer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = "data/phase5l-pymdown-original-upstream-source-lock.json"
LOCK_BLOB = "79e27d78376dde9cdd9d4e628a95cc3cc7ae63ee"
STATUS = "PHASE5L_REAL_AUTHENTIC_UPSTREAM_TEST_RUN_NOT_TRAINED_MODEL_GOLD"
SUMMARY_STATUS = "PHASE5L_SIXTH_ORIGINAL_SOURCE_STAGE_PARENT_FAIL_FIXED_PASS_EVIDENCE"
STAGES = ("parent-original", "parent-regression", "fixed-regression")
RUNTIMES = ("3.11", "3.13")
MAX_LOG = 100_000


class ReplayError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ReplayError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in items:
        require(name not in result, "duplicate JSON evidence property: " + name)
        result[name] = value
    return result


def read_json(raw: bytes) -> dict:
    try:
        result = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError) as exc:
        raise ReplayError("invalid source proof JSON") from exc
    require(isinstance(result, dict), "source proof must be JSON object")
    return result


def load_lock(root: Path = ROOT) -> dict:
    raw = (root / LOCK_PATH).read_bytes()
    require(0 < len(raw) < 8000 and git_blob(raw) == LOCK_BLOB,
            "precommitted case-selection Git blob changed")
    lock = read_json(raw)
    require(lock.get("schema_version") == 1
            and type(lock["schema_version"]) is int
            and lock.get("repository") == "facelessuser/pymdown-extensions"
            and lock.get("intent") == "SECURITY_REVIEW_GENERAL"
            and lock.get("advisory") == "GHSA-62q4-447f-wv8h"
            and lock.get("status") ==
            "PHASE5L_FROZEN_RESEARCHER_SELECTED_NEW_PROJECT_BEFORE_REPLAY_NOT_BLIND_GOLD"
            and lock["original_fix_commit"] ==
                "63b7835776d703d6c339cf2110d9888f676efc0c"
            and lock["direct_vulnerable_parent"] ==
                "3d185501daaa1424c4a8d42124112c44ef6ab635"
            and lock["original_parent_source_blob_sha1"] ==
                "305c7c0aae68516f4aad77c2430234762e981688"
            and lock["original_fixed_source_blob_sha1"] ==
                "b808d7b929fec0962c4b41ca0a70ed4e696d0fc5"
            and lock["parent_original_test_blob_sha1"] ==
                "11ef10b8d7c65c23c20f11341b39db2ba8e8699e"
            and lock["fixed_original_upstream_test_blob_sha1"] ==
                "da1f2cd3c893c1e1257511339ca1e7e706d32bfc"
            and lock["fixed_original_upstream_fixture_blob_sha1"] ==
                "528c55e3ae5ab31701e42285503ea9538f175afb"
            and lock["author_selected_public_historical_case_not_independent_review"] is True
            and type(lock["independent_human_appsec_gold_labels"]) is int
            and lock["independent_human_appsec_gold_labels"] == 0
            and lock["trained_model_scored"] is False
            and lock["official_h2_entry_submitted"] is False,
            "unapproved source selection or promoted gold")
    return lock


def git(worktree: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(worktree), *args],
        capture_output=True, text=True, timeout=30, check=False,
    )
    require(proc.returncode == 0, "Git source verification failed: " + " ".join(args))
    return proc.stdout.strip()


def verify_worktree(worktree: Path, expected_commit: str, lock: dict,
                    *, overlay: bool) -> None:
    require(worktree.is_dir() and not worktree.is_symlink(),
            "missing real Git upstream working tree")
    require(git(worktree, "rev-parse", "HEAD") == expected_commit,
            "upstream HEAD does not match frozen original commit")
    source = worktree / lock["source_path"]
    test = worktree / lock["test_path"]
    require(source.is_file() and test.is_file()
            and not source.is_symlink() and not test.is_symlink(),
            "source or original upstream-authored regression test missing")
    fixed = expected_commit == lock["original_fix_commit"]
    expected_source = lock[
        "original_fixed_source_blob_sha1" if fixed
        else "original_parent_source_blob_sha1"
    ]
    expected_test = lock[
        "fixed_original_upstream_test_blob_sha1" if fixed or overlay
        else "parent_original_test_blob_sha1"
    ]
    require(git_blob(source.read_bytes()) == expected_source,
            "executed Git source file no longer exact parent/fix original")
    require(git_blob(test.read_bytes()) == expected_test,
            "executed test not the exact upstream maintainer-authored blob")
    fixture = worktree / lock["new_test_fixture_path"]
    if fixed or overlay:
        require(fixture.is_file() and not fixture.is_symlink()
                and git_blob(fixture.read_bytes()) ==
                lock["fixed_original_upstream_fixture_blob_sha1"],
                "executed original upstream test fixture Git blob changed")
    else:
        require(not fixture.exists(), "original parent baseline must be unmodified")


def _log_checks(stage: str, exit_code: int, log: bytes) -> None:
    require(stage in STAGES and 0 < len(log) < MAX_LOG,
            "unapproved stage or missing/bloated real subprocess log")
    body = log.decode("utf-8", errors="replace")
    if stage == "parent-regression":
        require(exit_code == 1 and "1 failed" in body
                and "SnippetMissingError not raised" in body
                and "FAILED tests/test_extensions/test_snippets.py::"
                "TestSnippetsNested::test_restricted_directory_traversal" in body
                and "1 error" not in body.lower(),
                "vulnerable source did not fail exact original regression assertion")
    else:
        require(exit_code == 0 and re.search(r"\b1 passed\b", body) is not None
                and "1 failed" not in body and "1 skipped" not in body,
                "fixed source or baseline did not actually PASS original test")


def expected(stage: str, lock: dict) -> tuple[str, str, bool, str]:
    require(stage in STAGES, "unknown staged original upstream execution")
    is_fixed = stage == "fixed-regression"
    overlay = stage == "parent-regression"
    return (
        lock["original_fix_commit"] if is_fixed else lock["direct_vulnerable_parent"],
        lock["original_fixed_source_blob_sha1"] if is_fixed else
            lock["original_parent_source_blob_sha1"],
        overlay,
        lock["upstream_unmodified_parent_control"] if stage == "parent-original"
        else lock["upstream_authored_new_security_regression"],
    )


def execute(worktree: Path, lock: dict, stage: str, python_version: str,
            output: Path, log_out: Path) -> dict:
    require(stage in STAGES and python_version in RUNTIMES,
            "unapproved Python or source-test stage")
    require(output.resolve() != log_out.resolve()
            and not output.exists() and not log_out.exists(),
            "replay evidence must be write-once and paths distinct")
    require(git(worktree, "rev-parse", "HEAD") == lock["original_fix_commit"],
            "starting upstream worktree must be the exact original fixed Git commit")
    require(git(worktree, "show", "-s", "--format=%P", "HEAD") ==
            lock["direct_vulnerable_parent"],
            "selected original upstream patch is not a direct parent/fix pair")
    verify_worktree(worktree, lock["original_fix_commit"], lock, overlay=False)
    full_fixed_test = (worktree / lock["test_path"]).read_bytes()
    full_fixed_fixture = (worktree / lock["new_test_fixture_path"]).read_bytes()
    commit, source_sha, overlay, test_name = expected(stage, lock)
    if stage != "fixed-regression":
        git(worktree, "checkout", "--detach", lock["direct_vulnerable_parent"])
        verify_worktree(worktree, commit, lock, overlay=False)
        if overlay:
            (worktree / lock["test_path"]).write_bytes(full_fixed_test)
            fixture = worktree / lock["new_test_fixture_path"]
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_bytes(full_fixed_fixture)
    verify_worktree(worktree, commit, lock, overlay=overlay)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(worktree.resolve())
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        done = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", test_name],
            cwd=worktree, env=env, capture_output=True, timeout=110,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReplayError("real upstream original test timed out") from exc
    log = done.stdout + b"\n" + done.stderr
    # On failed assertions print enough for CI diagnosis but do not accept
    # import errors, setup failures, skipped tests or environment exceptions.
    if done.returncode not in (0, 1):
        print(log.decode(errors="replace")[-4000:], file=sys.stderr)
    _log_checks(stage, done.returncode, log)
    assert python_version == f"{sys.version_info.major}.{sys.version_info.minor}", (
        "runner Python version did not match requested CI matrix"
    )
    evidence = {
        "schema_version": 1,
        "status": STATUS,
        "selection_lock_git_blob": LOCK_BLOB,
        "repository": lock["repository"],
        "advisory": lock["advisory"],
        "stage": stage,
        "python": python_version,
        "original_upstream_commit": commit,
        "source_blob_sha1": source_sha,
        "executed_original_upstream_test_blob_sha1": (
            lock["fixed_original_upstream_test_blob_sha1"]
            if stage != "parent-original" else
            lock["parent_original_test_blob_sha1"]
        ),
        "original_upstream_test_fixture_blob_sha1": (
            lock["fixed_original_upstream_fixture_blob_sha1"]
            if stage != "parent-original" else None
        ),
        "fixed_original_regression_test_overlaid_on_parent_only": overlay,
        "actual_pytest_subprocess_exit_code": done.returncode,
        "actual_upstream_test_log_sha256": digest(log),
        "original_git_worktree_and_source_test_blobs_verified": True,
        "expected_original_assertion_failure_proven": stage == "parent-regression",
        "researcher_selected_not_external_holdout": True,
        "independent_human_appsec_gold_labels": 0,
        "trained_evaluator_scored": False,
        "telegraph_new_eligible_rows": 0,
        "official_h2_entry_submitted": False,
    }
    for path, raw in ((log_out, log), (output, json.dumps(
        evidence, sort_keys=True, indent=2
    ).encode() + b"\n")):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "wb") as file:
            file.write(raw)
    print(json.dumps({
        "stage": stage, "python": python_version,
        "exit_code": done.returncode, "source_git_commit": commit,
        "log_sha256": evidence["actual_upstream_test_log_sha256"],
        "actual_upstream_process": True, "independent_gold": 0,
    }, sort_keys=True))
    return evidence


def verify_receipt(report: dict, raw_log: bytes, lock: dict, *,
                   stage: str, python_version: str) -> None:
    commit, source_sha, overlay, _ = expected(stage, lock)
    fields = {
        "schema_version", "status", "selection_lock_git_blob", "repository",
        "advisory", "stage", "python", "original_upstream_commit",
        "source_blob_sha1", "executed_original_upstream_test_blob_sha1",
        "original_upstream_test_fixture_blob_sha1",
        "fixed_original_regression_test_overlaid_on_parent_only",
        "actual_pytest_subprocess_exit_code",
        "actual_upstream_test_log_sha256",
        "original_git_worktree_and_source_test_blobs_verified",
        "expected_original_assertion_failure_proven",
        "researcher_selected_not_external_holdout",
        "independent_human_appsec_gold_labels",
        "trained_evaluator_scored", "telegraph_new_eligible_rows",
        "official_h2_entry_submitted",
    }
    require(set(report) == fields and type(report["schema_version"]) is int
            and report["schema_version"] == 1
            and report["status"] == STATUS
            and report["selection_lock_git_blob"] == LOCK_BLOB
            and report["repository"] == lock["repository"]
            and report["advisory"] == lock["advisory"]
            and report["stage"] == stage and report["python"] == python_version
            and report["original_upstream_commit"] == commit
            and report["source_blob_sha1"] == source_sha
            and report["executed_original_upstream_test_blob_sha1"] == lock[
                "fixed_original_upstream_test_blob_sha1"
                if stage != "parent-original" else
                "parent_original_test_blob_sha1"
            ]
            and report["original_upstream_test_fixture_blob_sha1"] == (
                lock["fixed_original_upstream_fixture_blob_sha1"]
                if stage != "parent-original" else None
            )
            and report["fixed_original_regression_test_overlaid_on_parent_only"]
                is overlay
            and report["actual_pytest_subprocess_exit_code"] ==
                lock["expected_real_test_exit_codes"][
                    {"parent-original": "parent_original_control",
                     "parent-regression": "parent_fixed_test_overlay",
                     "fixed-regression": "fixed_original_test"}[stage]
                ]
            and type(report["actual_pytest_subprocess_exit_code"]) is int
            and report["actual_upstream_test_log_sha256"] == digest(raw_log)
            and report["original_git_worktree_and_source_test_blobs_verified"]
                is True
            and report["expected_original_assertion_failure_proven"] is
                (stage == "parent-regression")
            and report["researcher_selected_not_external_holdout"] is True
            and type(report["independent_human_appsec_gold_labels"]) is int
            and report["independent_human_appsec_gold_labels"] == 0
            and report["trained_evaluator_scored"] is False
            and type(report["telegraph_new_eligible_rows"]) is int
            and report["telegraph_new_eligible_rows"] == 0
            and report["official_h2_entry_submitted"] is False,
            "unapproved original upstream source-test execution receipt")
    _log_checks(stage, report["actual_pytest_subprocess_exit_code"], raw_log)


def aggregate(root: Path, lock: dict) -> dict:
    records = []
    for runtime in RUNTIMES:
        for stage in STAGES:
            stem = f"phase5l-{stage}-PY{runtime}"
            record_path = root / f"{stem}/{stem}.json"
            log_path = root / f"{stem}/{stem}.log"
            require(record_path.is_file() and log_path.is_file()
                    and not record_path.is_symlink() and not log_path.is_symlink(),
                    "actual original source GitHub Actions job artifact missing")
            require(record_path.stat().st_size < 9000 and
                    0 < log_path.stat().st_size < MAX_LOG,
                    "upstream source execution evidence exceeds bounds")
            result = read_json(record_path.read_bytes())
            verify_receipt(result, log_path.read_bytes(), lock,
                           stage=stage, python_version=runtime)
            records.append(result)
    require(len(records) == 6, "all six original upstream stage/runtime checks required")
    return {
        "schema_version": 1,
        "status": SUMMARY_STATUS,
        "original_frozen_selection_git_blob_sha1": LOCK_BLOB,
        "advisory": lock["advisory"],
        "new_source_project": lock["repository"],
        "new_original_upstream_security_fix_stages": 1,
        "original_source_fix_stages_in_prior_five_case_workbench": 5,
        "original_source_fix_stages_including_this_separate_replay": 6,
        "distinct_original_upstream_projects_including_this_case": 5,
        "actual_upstream_pytest_runs": len(records),
        "python_versions": list(RUNTIMES),
        "stage_exit_codes_by_python": {
            runtime: {r["stage"]: r["actual_pytest_subprocess_exit_code"]
                      for r in records if r["python"] == runtime}
            for runtime in RUNTIMES
        },
        "proof_records": records,
        "not_admitted_into_legacy_five_witness_checker": True,
        "new_semantic_model_evaluations": 0,
        "independent_human_appsec_gold_labels": 0,
        "blind_new_case_holdout": False,
        "new_anjoman_eligible_rows": 0,
        "trained_model_improvement_proven": False,
        "registered_telegraph_evaluator": False,
        "official_h2_entry_submitted": False,
        "limitation": (
            "Original upstream Git source and maintainer-authored regression tests "
            "were run in actual GitHub Actions jobs, with exact Git blob pins and "
            "raw process logs. This source-project-disjoint case was found by "
            "the FALSUM researcher through a PUBLIC disclosed advisory. It is "
            "not independently selected or blind and cannot score semantic "
            "reviewer accuracy or establish trained model improvement. This "
            "receipt is not authentic without its source GitHub Actions run."
        ),
    }


def _write(path: Path, obj: dict) -> None:
    require(not path.exists() and not path.is_symlink(), "cannot overwrite evidence output")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(obj, stream, sort_keys=True, indent=2)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute genuine upstream regression or aggregate its Actions job logs")
    sub = parser.add_subparsers(dest="mode", required=True)
    e = sub.add_parser("execute")
    e.add_argument("--stage", choices=STAGES, required=True)
    e.add_argument("--python", choices=RUNTIMES, required=True)
    e.add_argument("--worktree", type=Path, required=True)
    e.add_argument("--record-out", type=Path, required=True)
    e.add_argument("--log-out", type=Path, required=True)
    a = sub.add_parser("aggregate")
    a.add_argument("--artifacts-dir", type=Path, required=True)
    a.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        lock = load_lock()
        if args.mode == "execute":
            execute(args.worktree, lock, args.stage, args.python,
                    args.record_out, args.log_out)
        else:
            _write(args.out, aggregate(args.artifacts_dir, lock))
            print(json.dumps({"upstream_original_source_test_runs": 6,
                              "new_distinct_project": "pymdown-extensions",
                              "actual_model_scores": 0, "human_gold": 0}))
        return 0
    except (ReplayError, OSError, KeyError, TypeError, UnicodeError,
            subprocess.SubprocessError) as exc:
        parser.exit(1, "FALSUM PHASE5L REAL UPSTREAM SOURCE REPLAY BLOCKED: "
                    + str(exc)[:250] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
