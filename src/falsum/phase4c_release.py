"""Build FALSUM's original public review challenge and truthful real-model proof.

Build-time only; no live AI inference, network accounts, keys, hidden evaluation
material or third-party mission activity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from .phase3q_mission_lab import capture, write_outputs
from .phase4c_judge_proof import write as write_real_proof, STATUS
from .phase4i_evidence_comparison import write as write_model_comparison, STATUS as COMPARISON_STATUS


def build(out_dir: Path) -> dict:
    if out_dir.exists() or out_dir.is_symlink():
        raise ValueError("refuse to overwrite an existing web release")
    lab = capture()
    if (lab.get("status") != "PHASE3Q_EXECUTABLE_PUBLIC_SYNTHETIC_MISSION_PROOF_NOT_REAL_APP"
            or lab.get("synthetic_before_after_executions") != 6
            or lab.get("actual_third_party_mission_apps_verified") != 0
            or lab.get("actual_evaluator_model_scoring_executed") is not False
            or lab.get("evaluator_model_registered") is not False):
        raise ValueError("synthetic lab evidence boundary changed")
    write_outputs(out_dir, lab)
    recorded = write_real_proof(out_dir / "proof")
    if (recorded["status"] != STATUS
            or recorded["model_matches_narrow_source_facts"] != 3
            or recorded["complete_factual_reversals"] != 0
            or recorded["model_registered_to_telegraph"] is not False):
        raise ValueError("model proof misrepresented before deploying")
    comparison = write_model_comparison(out_dir / "compare")
    if (comparison["status"] != COMPARISON_STATUS
            or comparison["model_source_author_matches"] != 5
            or comparison["model_complete_reversals"] != 1
            or comparison["constant_A_matches"] != 4
            or comparison["constant_B_matches"] != 4
            or comparison["independent_expert_gold_labels"] != 0
            or comparison["model_registered"] is not False):
        raise ValueError("source comparison evidence misrepresented before deploying")
    return {
        "phase4i_source_comparison_project_count": 4,
        "phase4i_frozen_source_conditions": 8,
        "phase4i_model_fact_matches": 5,
        "phase4i_model_complete_reversals": 1,
        "source_comparison": str(out_dir / "compare/index.html"),
        "web_status": "FALSUM_SYNTHETIC_LAB_PLUS_AUTHENTIC_RECORDED_MODEL_PROOF_NOT_NETWORK_EVALUATOR",
        "root_synthetic_cases": 3,
        "root_real_python_fixture_pairs": 6,
        "real_model_score_cases_at_proof_path": 6,
        "real_model_fact_matches": 3,
        "real_model_complete_reversals": 0,
        "registered_evaluator": False,
        "new_anjoman_rows": 0,
        "independent_expert_labels": 0,
        "root": str(out_dir / "index.html"),
        "recorded_model": str(out_dir / "proof/index.html"),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build honest judge-ready FALSUM web release")
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        print(json.dumps(build(args.out_dir), indent=2))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as e:
        p.exit(1, "FALSUM JUDGE RELEASE BLOCKED: " + str(e) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
