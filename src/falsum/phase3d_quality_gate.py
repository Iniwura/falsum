"""Phase 3D release veto. Never confuse a well-running model with a good judge."""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from .phase3d_counterfactual_report import STATUS as REAL_SCORE_STATUS


class QualityGateError(ValueError):
    pass


def assess(real_scores:dict)->dict:
    if (not isinstance(real_scores,dict)
        or real_scores.get("status")!=REAL_SCORE_STATUS
        or real_scores.get("actual_official_foundation_loaded") is not True
        or real_scores.get("repeat_float32_bits_identical") is not True
        or real_scores.get("real_inference_calls_including_repeats")!=16
        or real_scores.get("families_tested")!=2
        or real_scores.get("rule_derived_not_independent_accuracy") is not True
        or real_scores.get("labels_human_adjudicated")!=0
        or real_scores.get("network_eligible") is not False
        or real_scores.get("registered_evaluator") is not False):
        raise QualityGateError("refuse unverified real-inference or promoted model evaluation")
    families=real_scores.get("counterfactual_families")
    if (not isinstance(families,list) or len(families)!=2
        or [x.get("family") for x in families]!=["installed-version","symlink-flag"]
        or any(not isinstance(f.get("contexts"),list) or len(f["contexts"])!=2 for f in families)):
        raise QualityGateError("source version and flag family results missing")
    count_reversal=sum(x["ranking_reverses_when_one_deployment_fact_changes"] is True for x in families)
    count_correct=sum(x["both_context_preferences_match_provisional_rule"] is True for x in families)
    context_correct=sum(r.get("diagnostic_matches_provisional_rule") is True for x in families for r in x["contexts"])
    if (real_scores.get("families_with_preference_reversal")!=count_reversal
        or real_scores.get("families_matching_both_provisional_expected_preferences")!=count_correct):
        raise QualityGateError("counterfactual summary inconsistent with actual reported model results")
    return {
        "schema_version":1,
        "status":"PHASE3D_RELEASE_VETO_COUNTERFACTUAL_MODEL_QUALITY",
        "real_model_foundation_inference_verified":True,
        "context_families":2,
        "contexts":4,
        "families_reversing":count_reversal,
        "families_matching_both_provisional_rules":count_correct,
        "contexts_matching_provisional_rules":context_correct,
        "diagnostic_model_failed_context_test":count_correct<2,
        "automatic_registration_permitted":False,
        "exported_model_can_be_called_competition_ready":False,
        "must_obtain_independent_human_labels":True,
        "must_pass_project_separated_holdout":True,
        "registered_evaluator":False,
        "network_eligible":False,
        "action":"BLOCK_MODEL_RELEASE_AND_REGISTRATION_PENDING_QUALITY_REMEDIATION",
        "notice":"Even 2/2 on these researcher-designed cases would not authorize release: no blind holdout, expert adjudication, eligible Anjoman rows or endpoint. The actual failed score margins are preserved in the input report."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Machine-readable veto after real Foundation counterfactual quality results")
    p.add_argument("--results",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise QualityGateError("refuse previous decision overwrite")
        report=assess(json.loads(a.results.read_text()))
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        print(json.dumps({"action":report["action"],
                          "families_reversing":report["families_reversing"],
                          "contexts_matching":report["contexts_matching_provisional_rules"],
                          "network_eligible":False},indent=2))
        return 0
    except (QualityGateError,OSError,ValueError,TypeError,KeyError) as e:
        p.exit(1,f"FALSUM COUNTERFACTUAL VETO ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
