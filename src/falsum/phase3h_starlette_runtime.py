"""Phase 3H: actual installed Starlette behavior before and after a historical patch.

Uses only two exact versions and a three-file synthetic temp directory. No
socket, outside service, user repository, credentials or arbitrary path input.
This is a controlled library behavior delta, NOT model accuracy or eligibility.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import tempfile

from .real_fix_corpus import load_queue

STATUS = "PHASE3H_REAL_INSTALLED_STARLETTE_BEHAVIOR_DELTA_RESEARCH_ONLY"
CASE = "real-starlette-commonprefix-traversal"
REPO = "Kludex/starlette"
FIX_COMMIT = "1797de464124b090f10cf570441e8292936d63e3"
SOURCE_BLOB = "4c856063c2945d93f1b79505f9d8de7919b947aa"
TEST_BLOB = "23d0b57fc2b23fbc5f23734ce856980a3d4ae064"
ADVISORY = "GHSA-v5gw-mw7f-84px"
CVE = "CVE-2023-29159"
VERSIONS = {"0.26.1": ("commonprefix", True), "0.27.0": ("commonpath", False)}
FIXTURE = "harmless-falsum-review-fixture-not-sensitive"
REQUESTS = (
    ("inside", "/index.txt"),
    ("missing", "/does-not-exist.txt"),
    ("nonmatching_sibling", "/../other_folder/review-fixture.txt"),
    ("sameprefix_sibling", "/../public_sibling/review-fixture.txt"),
)
EXPECTED = {
    "0.26.1": {"inside": 200, "missing": 404, "nonmatching_sibling": 404, "sameprefix_sibling": 200},
    "0.27.0": {"inside": 200, "missing": 404, "nonmatching_sibling": 404, "sameprefix_sibling": 404},
}


class RuntimeError3H(ValueError):
    """Refuse invalid source/runtime claims or an unproven behavior delta."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_source_queue(path: Path) -> dict:
    queue = load_queue(path)
    if len(queue["cases"]) != 4:
        raise RuntimeError3H("expected existing four-project historical source queue")
    rows = [r for r in queue["cases"] if r["id"] == CASE]
    if len(rows) != 1:
        raise RuntimeError3H("Starlette case missing/duplicated")
    row = rows[0]
    required = {
        "repository": REPO, "commit": FIX_COMMIT,
        "source_blob": SOURCE_BLOB, "test_blob": TEST_BLOB,
        "source_path": "starlette/staticfiles.py",
        "test_path": "tests/test_staticfiles.py",
        "advisory": ADVISORY, "cve": CVE,
    }
    if any(row.get(k) != v for k, v in required.items()):
        raise RuntimeError3H("upstream source or regression test provenance changed")
    return row


async def _observe(app, label: str, uri: str, intended_path: Path | None) -> dict:
    """In-process real StaticFiles.get_response: zero HTTP requests or sockets."""
    from starlette.exceptions import HTTPException
    from starlette.responses import FileResponse
    # Real get_path is part of the library and retains the intended .. segment.
    path = app.get_path({"path": uri})
    try:
        response = await app.get_response(path, {"type": "http", "method": "GET", "headers": []})
    except HTTPException as exc:
        if exc.status_code != 404:
            raise RuntimeError3H(f"{label}: unexpected HTTPException {exc.status_code}") from exc
        return {"name": label, "status": 404, "matched_expected_fixture": False}
    if not isinstance(response, FileResponse) or response.status_code != 200:
        raise RuntimeError3H(f"{label}: unexpected response class/status")
    resolved = Path(response.path).resolve()
    if intended_path is None or resolved != intended_path.resolve():
        raise RuntimeError3H(f"{label}: runtime returned file outside allowlisted synthetic fixture")
    return {"name": label, "status": 200, "matched_expected_fixture": True}


def validate_report(report: dict) -> None:
    if not isinstance(report, dict):
        raise RuntimeError3H("invalid report object")
    version = report.get("installed_version")
    if not isinstance(version, str) or version not in VERSIONS:
        raise RuntimeError3H("unapproved Starlette release")
    boundary, exposed = VERSIONS[version]
    expected_fields = {
        "schema_version", "status", "intent", "case_id", "advisory", "cve",
        "upstream_fix_commit", "upstream_source_post_fix_blob", "upstream_test_post_fix_blob",
        "installed_version", "runtime_source_sha256", "runtime_source_outside_repo",
        "actual_installed_framework_executed", "lookup_path_boundary", "synthetic_fixtures_only",
        "in_process_no_network", "real_user_files_read", "results",
        "sameprefix_sibling_visible", "controls_passed", "independent_human_labels",
        "accepted_training_pairs", "accepted_network_evaluation_rows", "model_scored",
        "network_eligible", "evaluator_registered",
    }
    if set(report) != expected_fields:
        raise RuntimeError3H("report fields changed")
    if (type(report["schema_version"]) is not int or report["schema_version"] != 1
            or report["status"] != STATUS or report["intent"] != "SECURITY_REVIEW_GENERAL"
            or report["case_id"] != CASE or report["advisory"] != ADVISORY
            or report["cve"] != CVE or report["upstream_fix_commit"] != FIX_COMMIT
            or report["upstream_source_post_fix_blob"] != SOURCE_BLOB
            or report["upstream_test_post_fix_blob"] != TEST_BLOB
            or report["lookup_path_boundary"] != boundary
            or report["runtime_source_outside_repo"] is not True
            or report["actual_installed_framework_executed"] is not True
            or report["synthetic_fixtures_only"] is not True
            or report["in_process_no_network"] is not True
            or report["real_user_files_read"] != 0
            or report["sameprefix_sibling_visible"] is not exposed
            or report["controls_passed"] is not True
            or report["independent_human_labels"] != 0
            or report["accepted_training_pairs"] != 0
            or report["accepted_network_evaluation_rows"] != 0
            or report["model_scored"] is not False
            or report["network_eligible"] is not False
            or report["evaluator_registered"] is not False):
        raise RuntimeError3H("historical behavior report is false, incomplete, or promoted")
    digest = report.get("runtime_source_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise RuntimeError3H("missing actual installed source fingerprint")
    results = report.get("results")
    if (not isinstance(results, list) or len(results) != len(REQUESTS)
            or [x.get("name") for x in results if isinstance(x, dict)] != [x[0] for x in REQUESTS]):
        raise RuntimeError3H("not exactly four controlled checks")
    for row in results:
        if set(row) != {"name", "status", "matched_expected_fixture"}:
            raise RuntimeError3H("unexpected result fields")
        if type(row["status"]) is not int or row["status"] != EXPECTED[version][row["name"]]:
            raise RuntimeError3H("runtime behavior mismatch")
        if row["matched_expected_fixture"] is not (row["status"] == 200):
            raise RuntimeError3H("runtime fixture evidence inconsistent")


def run_installed(version: str, queue_path: Path, repo_root: Path) -> dict:
    if version not in VERSIONS:
        raise RuntimeError3H("only allow the predeclared affected/patched Starlette pair")
    verify_source_queue(queue_path)
    from starlette.staticfiles import StaticFiles
    from starlette import __version__ as loaded_version
    installed_version = importlib.metadata.version("starlette")
    if version != installed_version or version != loaded_version:
        raise RuntimeError3H("actual imported Starlette release does not match exact pin")
    implementation_file = Path(inspect.getfile(StaticFiles)).resolve(strict=True)
    if implementation_file.is_relative_to(repo_root.resolve()) or not implementation_file.is_file():
        raise RuntimeError3H("must use real installed library outside FALSUM repo")
    source = inspect.getsource(StaticFiles.lookup_path)
    op = VERSIONS[version][0]
    if f"os.path.{op}(" not in source or f"os.path.{'commonpath' if op == 'commonprefix' else 'commonprefix'}(" in source:
        raise RuntimeError3H("actual StaticFiles implementation does not match published patch boundary")
    with tempfile.TemporaryDirectory(prefix="falsum-3h-public-fixtures-") as temporary:
        base = Path(temporary).resolve()
        public = base / "public"
        sibling = base / "public_sibling"
        other = base / "other_folder"
        for folder in (public, sibling, other):
            folder.mkdir()
        inside_file = public / "index.txt"
        sibling_file = sibling / "review-fixture.txt"
        unrelated_file = other / "review-fixture.txt"
        for file in (inside_file, sibling_file, unrelated_file):
            file.write_text(FIXTURE, encoding="utf-8")
        app = StaticFiles(directory=public, check_dir=True)
        targets = {"inside": inside_file, "sameprefix_sibling": sibling_file, "nonmatching_sibling": unrelated_file}
        async def run_all():
            out = []
            for label, path in REQUESTS:
                out.append(await _observe(app, label, path, targets.get(label)))
            return out
        results = asyncio.run(run_all())
    report = {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "case_id": CASE, "advisory": ADVISORY, "cve": CVE,
        "upstream_fix_commit": FIX_COMMIT, "upstream_source_post_fix_blob": SOURCE_BLOB,
        "upstream_test_post_fix_blob": TEST_BLOB, "installed_version": version,
        "runtime_source_sha256": _sha(implementation_file.read_bytes()),
        "runtime_source_outside_repo": True, "actual_installed_framework_executed": True,
        "lookup_path_boundary": op, "synthetic_fixtures_only": True,
        "in_process_no_network": True, "real_user_files_read": 0, "results": results,
        "sameprefix_sibling_visible": results[-1]["status"] == 200,
        "controls_passed": all(r["status"] == EXPECTED[version][r["name"]] for r in results),
        "independent_human_labels": 0, "accepted_training_pairs": 0,
        "accepted_network_evaluation_rows": 0, "model_scored": False,
        "network_eligible": False, "evaluator_registered": False,
    }
    validate_report(report)
    return report


def compare(old: dict, fixed: dict) -> dict:
    validate_report(old)
    validate_report(fixed)
    if old["installed_version"] != "0.26.1" or fixed["installed_version"] != "0.27.0":
        raise RuntimeError3H("comparison requires one actual observed pre-fix and patched version")
    if old["runtime_source_sha256"] == fixed["runtime_source_sha256"]:
        raise RuntimeError3H("two installed versions unexpectedly have identical source files")
    names = [x[0] for x in REQUESTS]
    old_results = dict(zip(names, old["results"]))
    fixed_results = dict(zip(names, fixed["results"]))
    changed = [name for name in names if old_results[name]["status"] != fixed_results[name]["status"]]
    if changed != ["sameprefix_sibling"]:
        raise RuntimeError3H("only the published same-prefix directory-escape scenario may reverse")
    return {
        "schema_version": 1, "status": "PHASE3H_ACTUAL_VULNERABLE_FIXED_LIBRARY_BEHAVIOR_CONTRAST_VERIFIED",
        "intent": "SECURITY_REVIEW_GENERAL", "advisory": ADVISORY, "case_id": CASE,
        "before_version": "0.26.1", "after_version": "0.27.0",
        "isolated_runtime_scenarios_per_version": 4,
        "controlled_sibling_visible_before": True,
        "controlled_sibling_blocked_after": True,
        "unchanged_safe_and_negative_controls": 3,
        "source_change_proven_by_upstream_patch": FIX_COMMIT,
        "trained_model_tested": False,
        "independently_validated_expert_labels": 0,
        "accepted_anjoman_rows": 0, "network_eligible": False, "evaluator_registered": False,
        "warning": "Observed behavior for exactly two historic installed releases and harmless local fixture paths, not a third-party app exploit, blind model benchmark, expert labels or Telegraph eligibility.",
    }


def _write_new(path: Path, doc: dict) -> None:
    if path.exists():
        raise RuntimeError3H("refuse to overwrite earlier evidence")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(doc))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Source-pinned Starlette 0.26.1 vs 0.27.0 in-process behavior, never model labels")
    cmds = parser.add_subparsers(dest="cmd", required=True)
    single = cmds.add_parser("run")
    single.add_argument("--version", choices=sorted(VERSIONS), required=True)
    single.add_argument("--queue", type=Path, required=True)
    single.add_argument("--repo-root", type=Path, required=True)
    single.add_argument("--out", type=Path, required=True)
    both = cmds.add_parser("compare")
    both.add_argument("--old", type=Path, required=True)
    both.add_argument("--fixed", type=Path, required=True)
    both.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "run":
            doc = run_installed(args.version, args.queue, args.repo_root)
        else:
            doc = compare(json.loads(args.old.read_text()), json.loads(args.fixed.read_text()))
        _write_new(args.out, doc)
        print(json.dumps({"status": doc["status"], "runtime": doc.get("installed_version"),
                          "case_id": CASE, "model_scored": False, "network_eligible": False}, indent=2))
        return 0
    except (RuntimeError3H, ValueError, TypeError, KeyError, OSError) as exc:
        parser.exit(1, f"FALSUM 3H REAL INSTALLED RUNTIME GATE FAILED: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
