"""Phases 4V/5D: browser interface to *pre-evaluated*, real source-test claims.

Nothing on the page performs or impersonates a fresh security test, model
inference, independent expert certification or Anjoman network request.
All 80 possible case/revision/claim/evidence combinations are evaluated by
FALSUM's exact source-review witness Python checker at *build time*, after
verifying the four original digests and the exact real Flask proof ZIP SHA.

Static browser only presents these immutable, source-bound results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .phase4p_open_source_review import load_lock
from .phase4z_flask_upstream_runtime import load_lock as load_flask_lock
from .phase5c_fifth_source_witness import source_index
from .source_review_witness_gate import (
    CLAIMS, STATUS as GATE_STATUS, canonical_claim, evaluate, read,
    validated_index,
)

ROOT = Path(__file__).resolve().parents[2]
INDEX = "evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
LOCK = "data/phase4p-three-project-open-review-lock.json"
FLASK_LOCK = "data/phase4z-flask-new-source-lock.json"
FLASK_ARCHIVE = "evidence/phase5c-original-phase4z-github-artifact.zip.b64"
TEMPLATE = Path(__file__).parent / "templates" / "phase4v_real_source_witness.html"
STATUS = "PHASE5D_STATIC_FIVE_REAL_SOURCE_EXECUTIONS_PRECOMPUTED_CLAIMS_NOT_MODEL_ACCURACY"

CASE_COPY = {
    "koa-redirect": {
        "label": "Koa", "short": "Redirect origin",
        "title": "When a redirect becomes an escape.",
        "plain": "A protocol-relative Referrer such as //evil.com/login can look local while pointing to another host.",
        "question": "Did the new double-slash redirect security regression pass at this revision?",
        "regression": "should fix Trailing Double-Slash security issue",
        "boundary": "The upstream regression checks a redirect location. It does not prove universal same-origin safety or deployed exploitability.",
        "tag": "OPEN REDIRECT",
    },
    "hono-csrf": {
        "label": "Hono", "short": "CSRF edge case",
        "title": "A content type outside the guard.",
        "plain": "A cross-origin text/ping request bypassed the historical CSRF content-type filter, reaching a handler when the new test expected a block.",
        "question": "Did the new text/ping security regression pass at this revision?",
        "regression": "hyperlink auditing",
        "boundary": "The upstream request tests are simulated HTTP requests, not a deployed browser attack or universal CSRF guarantee.",
        "tag": "CSRF",
    },
    "langchain-path": {
        "label": "LangChain", "short": "Prompt path guard",
        "title": "Trust should not follow the path.",
        "plain": "The initial fix restricted absolute and parent-traversal prompt-template paths by default.",
        "question": "Did the new absolute/.. path security regression pass at this revision?",
        "regression": "test_load_template_rejects_absolute_path / test_load_template_rejects_traversal",
        "boundary": "The test establishes a narrow default file-path validation branch; an explicit dangerous-path opt-in exists.",
        "tag": "FILE PATH",
    },
    "langchain-symlink": {
        "label": "LangChain", "short": "Symlink follow-up",
        "title": "A symlink changes what the file means.",
        "plain": "A later, distinct fix checks a resolved symlink's target suffix, rather than only its apparent filename.",
        "question": "Did the new symlink-target security regression pass at this revision?",
        "regression": "test_symlink_txt_to_py_is_blocked",
        "boundary": "Checking resolved file suffix is not proof that every possible directory or symlink escape is blocked.",
        "tag": "SYMLINK",
    },
    "flask-session-cookie-vary": {
        "label": "Flask", "short": "Session cache header",
        "title": "A silent session refresh matters.",
        "plain": "Flask's historical permanent-session refresh could set a cookie without adding Vary: Cookie to the response.",
        "question": "Did the new session-refresh Vary header security regression pass at this revision?",
        "regression": "test_session_refresh_vary",
        "boundary": "An in-process Flask test does not establish that a production shared cache exposed user session cookies.",
        "tag": "CACHE HEADER",
    },
}

REASON_COPY = {
    "REAL_PARENT_FAILS_FIXED_PASSES_TEST_WITNESS":
        "The regression record provides a direct PASS/FAIL answer for this exact Git revision.",
    "INCOMPLETE_OR_TAMPERED_PRIMARY_EVIDENCE":
        "The provided execution receipt digest does not match the original upstream CI artifact. A verdict cannot be trusted.",
    "DEPLOYED_IMPACT_OR_GLOBAL_SECURITY_NOT_TESTED":
        "A source-level regression does not establish what happened in a deployed application or prove universal safety.",
}

CLAIM_COPY = {
    "UPSTREAM_REGRESSION_PASSES": "The security regression passes.",
    "UPSTREAM_REGRESSION_FAILS": "The security regression fails.",
    "CONFIRMED_PRODUCTION_EXPLOIT": "This proves a production exploit.",
    "GUARANTEED_UNIVERSAL_APPLICATION_SAFETY": "This proves the application is safe.",
}


class BrowserWitnessError(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise BrowserWitnessError(why)


def assemble(root: Path = ROOT) -> dict:
    raw_index = read(root / INDEX)
    raw_lock = read(root / LOCK)
    flask_lock_raw = read(root / FLASK_LOCK)
    flask_archive_raw = read(root / FLASK_ARCHIVE)
    source = source_index(raw_index, raw_lock, flask_lock_raw, flask_archive_raw)
    canonical = load_lock(raw_lock)
    flask_lock = load_flask_lock(flask_lock_raw)
    require(tuple(source) == tuple(CASE_COPY), "case order or upstream evidence set changed")
    cases = []
    totals = {"SUPPORTED": 0, "CONTRADICTED": 0, "ABSTAIN": 0}
    for cid, witness in source.items():
        public = CASE_COPY[cid]
        if cid == flask_lock["case_id"]:
            stage = {
                "source_path": flask_lock["source_path"],
                "test_path": flask_lock["test_path"],
                "parent": flask_lock["direct_parent"],
                "fix": flask_lock["fixed_commit"],
                "parent_source_blob": flask_lock["parent_source_blob"],
                "fixed_source_blob": flask_lock["fixed_source_blob"],
                "fixed_test_blob": flask_lock["fixed_test_blob"],
            }
        else:
            rows = [x for x in canonical["cases"] if x["repository"] == witness["repository"]]
            require(len(rows) == 1, "multiple or missing upstream project rows")
            stages = [x for x in rows[0]["patches"] if x["stage"] == witness["stage"]]
            require(len(stages) == 1, "missing precise public patch stage")
            stage = stages[0]
        decisions: dict[str, dict] = {}
        for revision in ("parent", "fixed"):
            for claim_type in CLAIMS:
                for integrity in ("original", "tampered"):
                    request = canonical_claim(witness, revision, claim_type)
                    if integrity == "tampered":
                        request["evidence"]["actual_execution_receipt_sha256"] = "0" * 64
                    verdict = evaluate(source, request)
                    key = f"{revision}|{claim_type}|{integrity}"
                    require(verdict["verdict"] in totals
                            and verdict["not_independent_appsec_gold"] is True
                            and verdict["trained_model_accuracy_measurement"] is False
                            and verdict["not_network_eligible"] is True,
                            "source-bound verdict crossed model-quality boundary")
                    if integrity == "tampered":
                        require(verdict["verdict"] == "ABSTAIN"
                                and verdict["reason"] == "INCOMPLETE_OR_TAMPERED_PRIMARY_EVIDENCE",
                                "tampered CI execution digest was not rejected")
                    elif claim_type in CLAIMS[:2]:
                        expected = "SUPPORTED" if (
                            (revision == "fixed") == (claim_type == "UPSTREAM_REGRESSION_PASSES")
                        ) else "CONTRADICTED"
                        require(verdict["verdict"] == expected,
                                "historical upstream branch observation disagrees with source checker")
                    else:
                        require(verdict["verdict"] == "ABSTAIN",
                                "untested real-world exploit/security claim unexpectedly certified")
                    totals[verdict["verdict"]] += 1
                    decisions[key] = {
                        "verdict": verdict["verdict"],
                        "reason": verdict["reason"],
                        "explanation": REASON_COPY.get(
                            verdict["reason"], "No verified source/test witness supports this claim."
                        ),
                        "observed": "PASSES" if revision == "fixed" else "FAILS",
                    }
        require(len(decisions) == 16, "16 distinct structured claim conditions per source missing")
        cases.append({
            "id": cid,
            **public,
            "repository": witness["repository"],
            "source_path": stage["source_path"],
            "test_path": stage["test_path"],
            "parent_commit": stage["parent"],
            "fixed_commit": stage["fix"],
            "parent_source_blob_sha1": stage["parent_source_blob"],
            "fixed_source_blob_sha1": stage["fixed_source_blob"],
            "new_regression_test_blob_sha1": stage["fixed_test_blob"],
            "original_execution_receipt_sha256": witness["raw_source_runtime_receipt_sha256"],
            "source_parent_url": (
                f"https://github.com/{witness['repository']}/blob/{stage['parent']}/"
                f"{stage['source_path']}"
            ),
            "source_fixed_url": (
                f"https://github.com/{witness['repository']}/blob/{stage['fix']}/"
                f"{stage['source_path']}"
            ),
            "upstream_test_url": (
                f"https://github.com/{witness['repository']}/blob/{stage['fix']}/"
                f"{stage['test_path']}"
            ),
            "actions_run_url": witness["run_url"],
            "decisions": decisions,
        })
    require(len(cases) == 5 and totals == {
        "SUPPORTED": 10, "CONTRADICTED": 10, "ABSTAIN": 60
    }, "80 source-evidence evaluations changed or absent")
    return {
        "schema_version": 1,
        "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "verification_method": GATE_STATUS,
        "source_provenance": "four original upstream fixes plus one separately archived original Flask test regression",
        "replay_proof_url": "https://github.com/Iniwura/falsum/actions/runs/44356563508",
        "no_live_browser_tests_or_model_inference": True,
        "trained_model_improvement_proven": False,
        "independent_appsec_expert_gold_labels": 0,
        "new_anjoman_eligible_rows": 0,
        "network_evaluator_registered": False,
        "official_h2_submission_confirmed": False,
        "upstream_project_count": 4,
        "source_fix_stage_count": 5,
        "precomputed_python_evaluations": 80,
        "by_construction_verdict_counts": totals,
        "claim_options": [
            {"value": k, "label": CLAIM_COPY[k]} for k in CLAIMS
        ],
        "cases": cases,
    }


def render(report: dict, template: str) -> str:
    require(report.get("status") == STATUS
            and report.get("source_fix_stage_count") == 5
            and report.get("precomputed_python_evaluations") == 80
            and report.get("by_construction_verdict_counts") ==
            {"SUPPORTED": 10, "CONTRADICTED": 10, "ABSTAIN": 60}
            and report.get("independent_appsec_expert_gold_labels") == 0
            and report.get("network_evaluator_registered") is False
            and report.get("trained_model_improvement_proven") is False,
            "browser report cannot promote unsupported source or ML claim")
    marker = "__FALSUM_REAL_WITNESS_DATA__"
    require(template.count(marker) == 1,
            "web template must have exactly one inert provenance data slot")
    blob = json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    blob = (blob.replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))
    return template.replace(marker, blob)


def write(out_dir: Path, root: Path = ROOT) -> dict:
    require(not out_dir.exists() and not out_dir.is_symlink(),
            "refuse overwrite of existing public witness release")
    report = assemble(root)
    html = render(report, TEMPLATE.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=True, exist_ok=False)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    (out_dir / "FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build static, actual-source-backed reviewer workbench")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = write(args.out_dir)
        print(json.dumps({
            "status": output["status"],
            "historical_real_source_stages": 5,
            "precomputed_python_verdicts": 80,
            "independent_gold": 0,
            "trained_model_gain": False,
            "site": str(args.out_dir / "index.html"),
        }, indent=2))
        return 0
    except (BrowserWitnessError, OSError, ValueError, TypeError, KeyError) as e:
        parser.exit(1, "FALSUM PUBLIC SOURCE WORKBENCH BLOCKED: " + str(e)[:190] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
