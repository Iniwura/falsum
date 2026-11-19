"""Source-test verifier extension for real Flask provenance, NOT semantic model scoring.

Admits an exact previously executed, repository-independent Flask source case
ONLY with the immutable original Actions artifact ZIP and exact Git SHA source
lock. The old Phase 4U source index remains immutable. It creates 40 source-
derived consistency controls, not model accuracy, blind tests, or expert gold.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

from . import source_review_witness_gate as original
from .phase4z_flask_upstream_runtime import load_lock as load_flask_lock

STATUS = "PHASE5C_FIVE_SOURCE_TEST_WITNESSES_DETERMINISTIC_NOT_NEW_MODEL_GOLD"
ARCHIVE_SHA256 = "d2bd64dd1d893bc2367ef5664e119bb484a2db1898c643936a57933c5d3431ef"
REPORT_SHA256 = "65150bc4d196d715386bd758d37ad0b41dc8b2f242bd8628825b3158da15efb5"
ARCHIVE_NAME = "phase4z-flask-actual-upstream-test-proof.json"
RUN_ID = 44524997174
ARTIFACT_ID = 14529512891
ARTIFACT_URL = "https://github.com/Iniwura/falsum/actions/runs/44524997174"
ARTIFACT_RUN_HEAD_SHA = "bb297042151f028e90efebcd2ab2e5df74048a65"
MAX_RECEIPT_B64 = 12000


class ExtensionError(ValueError):
    """Untrusted or noncanonical source proof cannot be used for judging."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ExtensionError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_artifact(b64_raw: bytes, flask_lock_raw: bytes) -> tuple[dict, dict]:
    """Consume the unmodified archival ZIP from a single known real Actions run.

    This validates the exact bytes downloaded from GitHub on Nov 19, not an
    unverifiable user-declared execution. SHA pin stays independent of input.
    """
    lock = load_flask_lock(flask_lock_raw)
    require(isinstance(b64_raw, bytes) and 0 < len(b64_raw) <= MAX_RECEIPT_B64,
            "missing or oversized real archived proof")
    try:
        zip_raw = base64.b64decode(b64_raw.strip(), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ExtensionError("malformed base64 source evidence") from exc
    require(len(zip_raw) == 1580 and sha(zip_raw) == ARCHIVE_SHA256,
            "source proof does not match exact original GitHub artifact ZIP digest")
    try:
        with zipfile.ZipFile(io.BytesIO(zip_raw)) as zipped:
            require(zipped.namelist() == [ARCHIVE_NAME],
                    "upstream execution proof archive member set modified")
            file = zipped.getinfo(ARCHIVE_NAME)
            require(file.file_size == 3087, "unexpected or expanded proof record")
            raw = zipped.read(ARCHIVE_NAME)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ExtensionError("invalid archived original Actions proof ZIP") from exc
    require(sha(raw) == REPORT_SHA256,
            "unapproved original Flask execution proof JSON SHA")
    try:
        report = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ExtensionError("unparsable authenticated runtime proof") from exc
    require(isinstance(report, dict) and set(report) == {
        "advisory", "case_id", "fixed_passed_same_original_upstream_security_test",
        "independent_human_security_gold", "intent", "limitations",
        "new_anjoman_rows", "new_model_generalization_proven",
        "official_h2_entry_submitted", "old_lora_model_quality_improvement_measured",
        "original_fixed_upstream_test", "original_upstream_parent_test_passed",
        "original_upstream_regression_test_sha1",
        "parent_failed_fixed_upstream_security_test_expected_assertion",
        "parent_with_fixed_regression_overlay", "production_exploitability_demonstrated",
        "raw_test_log_sha256", "real_upstream_pytest_processes_run",
        "registered_network_evaluator", "repository",
        "researcher_selected_case_not_independent_review", "schema_version",
        "selected_new_public_project_not_from_four_case_index", "status",
        "test_exit_statuses", "upstream_fix_git_commit", "upstream_parent_git_commit",
    }, "archived proof shape not original upstream schema")
    from .phase4z_flask_upstream_runtime import STATUS as FLASK_STATUS
    require(
        type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["status"] == FLASK_STATUS
        and report["intent"] == "SECURITY_REVIEW_GENERAL"
        and report["repository"] == lock["repository"]
        and report["case_id"] == lock["case_id"]
        and report["advisory"] == lock["advisory"]
        and report["upstream_parent_git_commit"] == lock["direct_parent"]
        and report["upstream_fix_git_commit"] == lock["fixed_commit"]
        and report["original_upstream_regression_test_sha1"] == lock["fixed_test_blob"]
        and report["test_exit_statuses"] == {
            "parent-original": 0, "parent-regression": 1, "fixed-regression": 0
        }
        and report["original_upstream_parent_test_passed"] is True
        and report["parent_failed_fixed_upstream_security_test_expected_assertion"] is True
        and report["fixed_passed_same_original_upstream_security_test"] is True
        and report["real_upstream_pytest_processes_run"] is True
        and report["selected_new_public_project_not_from_four_case_index"] is True
        and report["researcher_selected_case_not_independent_review"] is True
        and report["independent_human_security_gold"] == 0
        and type(report["independent_human_security_gold"]) is int
        and report["new_anjoman_rows"] == 0
        and report["new_model_generalization_proven"] is False
        and report["production_exploitability_demonstrated"] is False
        and report["official_h2_entry_submitted"] is False
        and report["old_lora_model_quality_improvement_measured"] is False
        and report["registered_network_evaluator"] is False,
        "original upstream source execution was not verified or was promoted into model gold"
    )
    for name, revision, overlay in (
        ("parent_with_fixed_regression_overlay", "parent", True),
        ("original_fixed_upstream_test", "fixed", False),
    ):
        item = report[name]
        expected_commit = (lock["direct_parent"] if revision == "parent"
                           else lock["fixed_commit"])
        require(isinstance(item, dict) and set(item) == {
            "commit", "executed_test_blob_sha1", "security_test_overlaid_from_exact_fixed_upstream",
            "source_blob_sha1", "source_sha256", "test_sha256",
            "verified_from_actual_upstream_git_worktree",
        }, "invalid original parent/fixed Git worktree proof")
        require(item["commit"] == expected_commit
                and item["source_blob_sha1"] == lock[revision + "_source_blob"]
                and item["executed_test_blob_sha1"] == lock["fixed_test_blob"]
                and item["security_test_overlaid_from_exact_fixed_upstream"] is overlay
                and item["verified_from_actual_upstream_git_worktree"] is True
                and isinstance(item["source_sha256"], str)
                and isinstance(item["test_sha256"], str)
                and len(item["source_sha256"]) == len(item["test_sha256"]) == 64,
                "original source/test Git identities and actual worktree proof disagree")
    logs = report["raw_test_log_sha256"]
    require(isinstance(logs, dict)
            and set(logs) == {"parent-original", "parent-regression", "fixed-regression"}
            and all(isinstance(value, str) and len(value) == 64 for value in logs.values()),
            "missing actual original upstream test log digests")
    return lock, report


def source_index(original_index_raw: bytes, original_lock_raw: bytes,
                 flask_lock_raw: bytes, archive_b64: bytes) -> dict:
    """Admit exactly one new source project, leave four legacy receipts unchanged."""
    old = original.validated_index(original_index_raw, original_lock_raw)
    lock, record = load_artifact(archive_b64, flask_lock_raw)
    require(len(old) == 4 and lock["case_id"] not in old
            and lock["repository"] not in {row["repository"] for row in old.values()},
            "Flask extension does not add a distinct original source project")
    accepted = dict(old)
    accepted[lock["case_id"]] = {
        "id": lock["case_id"],
        "repository": lock["repository"],
        "stage": "session-refresh-vary-header",
        "original_git_commit": lock["direct_parent"],
        "fixed_git_commit": lock["fixed_commit"],
        "original_source_git_blob": lock["parent_source_blob"],
        "fixed_source_git_blob": lock["fixed_source_blob"],
        "same_fixed_upstream_regression_test_git_blob": lock["fixed_test_blob"],
        "raw_source_runtime_receipt_sha256": REPORT_SHA256,
        "run_url": ARTIFACT_URL,
        "original_upstream_test_passed": True,
        "original_source_with_fixed_security_regression_failed_expected_assertion": True,
        "fixed_source_with_same_regression_passed": True,
        "independent_human_gold": False,
    }
    require(record["parent_with_fixed_regression_overlay"]["executed_test_blob_sha1"] ==
            accepted[lock["case_id"]]["same_fixed_upstream_regression_test_git_blob"],
            "overlay security test not identical between parent and fixed source")
    return accepted


def constructed_controls(index: dict) -> list[dict]:
    old = {key: index[key] for key in original.EXPECTED_IDS}
    result = original.stress_cases(old)
    # Build independent deterministic controls for the new, source-PINNED fifth
    # stage, not a researcher/AI answer-key preference or trained-model test.
    new = index["flask-session-cookie-vary"]
    for revision, correct, incorrect in (
        ("parent", "UPSTREAM_REGRESSION_FAILS", "UPSTREAM_REGRESSION_PASSES"),
        ("fixed", "UPSTREAM_REGRESSION_PASSES", "UPSTREAM_REGRESSION_FAILS"),
    ):
        for suffix, claim, label in (
            ("source-supported",correct,"SUPPORTED"),
            ("source-contradicted",incorrect,"CONTRADICTED"),
            ("production-impact-not-established","CONFIRMED_PRODUCTION_EXPLOIT","ABSTAIN"),
            ("universal-safety-not-established","GUARANTEED_UNIVERSAL_APPLICATION_SAFETY","ABSTAIN"),
        ):
            result.append({
                "test_id": new["id"] + ":" + revision + ":" + suffix,
                "claim": original.canonical_claim(new, revision, claim),
                "expected": label,
            })
    require(len(result) == 40 and len({x["test_id"] for x in result}) == 40,
            "five case source construction controls changed")
    return result


def run(index_raw: bytes, source_raw: bytes, flask_raw: bytes,
        archive_b64: bytes, *, examples: list | None = None) -> dict:
    index = source_index(index_raw, source_raw, flask_raw, archive_b64)
    internal = examples is None
    items = constructed_controls(index) if internal else examples
    require(isinstance(items, list) and 1 <= len(items) <= original.MAX_REQUESTS,
            "missing or unbounded requests")
    seen, outcomes = set(), []
    for item in items:
        require(isinstance(item, dict) and set(item) in (
            {"test_id", "claim"}, {"test_id", "claim", "expected"}
        ), "unsupported source-review request fields")
        ident = item["test_id"]
        require(isinstance(ident, str) and 1 <= len(ident) <= 160 and ident not in seen,
                "duplicate or malformed test case")
        seen.add(ident)
        decision = original.evaluate(index, item["claim"])
        row = {"test_id": ident, "judgement": decision}
        if "expected" in item:
            require(item["expected"] in original.RESULTS,
                    "unrecognized expected verdict")
            if internal:
                row["constructed_source_expectation"] = item["expected"]
                row["matches_constructed_source_expectation"] = (
                    item["expected"] == decision["verdict"]
                )
            else:
                row["unverified_caller_expected_verdict"] = item["expected"]
                row["matches_unverified_caller_expectation"] = (
                    item["expected"] == decision["verdict"]
                )
        outcomes.append(row)
    if internal:
        require(all(row["matches_constructed_source_expectation"] for row in outcomes),
                "internally derived source evidence consistency failed")
    return {
        "schema_version": 1,
        "status": STATUS,
        "source_case_count": len(index),
        "distinct_upstream_projects": len({x["repository"] for x in index.values()}),
        "legacy_four_witness_sha256": sha(index_raw),
        "legacy_four_source_selection_sha256": sha(source_raw),
        "new_flask_source_lock_sha256": sha(flask_raw),
        "new_flask_original_actions_archive_sha256": ARCHIVE_SHA256,
        "new_flask_original_actions_report_sha256": REPORT_SHA256,
        "new_flask_original_actions_run_url": ARTIFACT_URL,
        "new_flask_original_actions_artifact_id": ARTIFACT_ID,
        "new_flask_original_actions_head_sha": ARTIFACT_RUN_HEAD_SHA,
        "new_source_case_selected_by_researcher": True,
        "public_original_source_executions_not_model_scoring": True,
        "claims_evaluated": len(outcomes),
        "supported": sum(x["judgement"]["verdict"] == "SUPPORTED" for x in outcomes),
        "contradicted": sum(x["judgement"]["verdict"] == "CONTRADICTED" for x in outcomes),
        "abstained": sum(x["judgement"]["verdict"] == "ABSTAIN" for x in outcomes),
        "internally_constructed_controls": len(outcomes) if internal else 0,
        "internally_constructed_controls_matching": len(outcomes) if internal else 0,
        "unverified_caller_expectations_seen": (
            0 if internal else sum("expected" in x for x in items)
        ),
        "expected_answer_origin": (
            "INTERNAL_SOURCE_DERIVED_CONTROLS" if internal
            else "UNVERIFIED_CALLER_EXPECTATIONS"
        ),
        "independent_human_expert_gold_labels": 0,
        "new_anjoman_eligible_rows": 0,
        "learned_model_generalization_scored": False,
        "truly_blind_new_case_evaluation": False,
        "registered_telegraph_evaluator": False,
        "official_h2_submission_confirmed": False,
        "freeform_review_scoring_supported": False,
        "scope_warning": (
            "The fifth source project is new to this precise typed witness checker and "
            "anchored to its genuine historical public GitHub Actions archive, but was "
            "selected by the researcher. Forty controls are deterministic by construction, "
            "not model accuracy, independently adjudicated human gold, a blind holdout, "
            "a registered evaluator or evidence of deployed exploitation."
        ),
        "cases": outcomes,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Run five historical source-test claim checks, not an ML/Telegraph scorer"
    )
    for name in ("index", "source-lock", "flask-lock", "flask-proof-b64", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--requests", type=Path,
                   help="optional external typed claims, expected labels remain unverified")
    args = p.parse_args(argv)
    try:
        paths = (args.index, args.source_lock, args.flask_lock, args.flask_proof_b64)
        if args.requests is not None:
            paths += (args.requests,)
        require(not args.out.exists() and not args.out.is_symlink()
                and args.out.resolve() not in {x.resolve() for x in paths},
                "output must be write-once and not overwrite original evidence")
        original_index = original.read(args.index, 30_000)
        original_lock = original.read(args.source_lock, 15_000)
        flask_lock = original.read(args.flask_lock, 15_000)
        archived = original.read(args.flask_proof_b64, MAX_RECEIPT_B64)
        requests = (json.loads(original.read(args.requests, 200_000))
                    if args.requests is not None else None)
        result = run(original_index, original_lock, flask_lock, archived,
                     examples=requests)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, sort_keys=True, indent=2)
            out.write("\n")
        print(json.dumps({
            "source_stages": 5,
            "upstream_projects": 4,
            "supported": result["supported"], "contradicted": result["contradicted"],
            "abstained": result["abstained"],
            "learned_model_accuracy": None, "independent_expert_gold": 0,
        }, sort_keys=True))
        return 0
    except (ExtensionError, original.SourceWitnessError,
            ValueError, KeyError, OSError, TypeError, UnicodeError) as exc:
        p.exit(1, "FALSUM PHASE5C SOURCE EXTENSION BLOCKED: " + str(exc)[:250] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
