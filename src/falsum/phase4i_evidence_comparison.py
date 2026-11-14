"""Phase 4I: honest, source-bound comparison of the original recorded LoRA.

This compares genuine float32 Foundation score decisions with constant-choice
and source-revision-aware *by-construction* research controls. No re-training,
sealing, external adjudication, accepted new rows or evaluator registration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase4h_frozen_source import validate_lock
from .phase4h_recorded_evidence import validate_ledger, f32

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "data/phase4h-frozen-four-new-source-projects.json"
LEDGER = ROOT / "evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json"
TEMPLATE = Path(__file__).with_name("templates") / "phase4i_evidence_comparison.html"
STATUS = "PHASE4I_FOUR_PROJECT_RECORDED_MODEL_COMPARISON_NOT_INDEPENDENT_ACCURACY"


class ComparisonError(ValueError):
    pass


def require(condition: bool, message: str):
    if not condition:
        raise ComparisonError(message)


def load(root: Path = ROOT) -> tuple[dict,dict,bytes,bytes]:
    lock_bytes = (root / LOCK.relative_to(ROOT)).read_bytes()
    ledger_bytes = (root / LEDGER.relative_to(ROOT)).read_bytes()
    locked = validate_lock(lock_bytes)
    ledger = json.loads(ledger_bytes)
    validate_ledger(ledger)  # exact 16 ORIGINAL model score bits, not aggregates only
    require(ledger["frozen_selection_sha256"] == hashlib.sha256(lock_bytes).hexdigest(),
            "frozen before/after source identities have drifted")
    return locked,ledger,lock_bytes,ledger_bytes


def report(root: Path = ROOT) -> dict:
    source,ledger,raw_lock,raw_ledger = load(root)
    groups=[]
    for case in source["cases"]:
        revisions=[]
        for rev,expected in (("parent","A"),("fixed","B")):
            xa=ledger["score_hex_by_input"][case["key"]+"-"+rev+"--A"]
            xb=ledger["score_hex_by_input"][case["key"]+"-"+rev+"--B"]
            sa,sb=f32(xa),f32(xb)
            chosen="A" if sa>sb else "B" if sb>sa else "TIE"
            revisions.append({
                "revision":rev,
                "revision_label":"Before fix" if rev=="parent" else "After fix",
                "commit":case[rev],
                "source_url":f"https://github.com/{case['repository']}/blob/{case[rev]}/{case['source_path']}",
                "test_url":f"https://github.com/{case['repository']}/blob/{case[rev]}/{case['test_path']}",
                "question":case["question_before"] if rev=="parent" else case["question_after"],
                "source_anchor":case["before_anchor"] if rev=="parent" else case["after_anchor"],
                "source_expected_author_only":expected,
                "model_chose":chosen,
                "matches_researcher_source_expectation":chosen==expected,
                "score_a":round(sa,8),
                "score_b":round(sb,8),
                "score_margin_a_minus_b":round(sa-sb,8),
                "score_a_f32":xa,"score_b_f32":xb,
                "independent_gold_label":None,
            })
        before,after = revisions
        correct = before["matches_researcher_source_expectation"] and after["matches_researcher_source_expectation"]
        swapped = before["model_chose"] != after["model_chose"] and "TIE" not in (before["model_chose"],after["model_chose"])
        groups.append({
            "id":case["key"],
            "name":{"pyjwt":"PyJWT","werkzeug":"Werkzeug",
                    "mcp-python":"MCP Python SDK","pillow":"Pillow"}[case["key"]],
            "issue": {
                "pyjwt":"Exception handling",
                "werkzeug":"Multipart buffering",
                "mcp-python":"Redirect boundaries",
                "pillow":"Decompression limit",
            }[case["key"]],
            "security_family":case["family"],
            "advisory":case["advisory"],
            "fix_url":f"https://github.com/{case['repository']}/commit/{case['fixed']}",
            "repository":case["repository"],
            "chosen_test_file_changed_by_fix":case["test_changed_in_fix"],
            "answer_a":case["a"],"answer_b":case["b"],
            "revisions":revisions,
            "model_changed_preference":swapped,
            "complete_source_consistent_reversal":correct,
        })
    fact = sum(r["matches_researcher_source_expectation"] for g in groups for r in g["revisions"])
    reversals = sum(g["complete_source_consistent_reversal"] for g in groups)
    changed = sum(g["model_changed_preference"] for g in groups)
    require([g["id"] for g in groups]==["pyjwt","werkzeug","mcp-python","pillow"]
            and fact==5 and reversals==1 and changed==1,
            "the real model's observed source-fact outcome has changed")
    # Source-aware oracle is intentionally given the exact frozen researcher
    # expectations, which makes it *not an independent competing model*.
    return {
        "schema_version":1,"status":STATUS,
        "original_quarantined_lora":True,
        "real_official_foundation_score_recording":True,
        "current_live_inference":False,
        "model_trained_or_improved_in_phase4i":False,
        "model_registered":False,
        "training_allowed":False,
        "independent_expert_gold_labels":0,
        "network_eligible_rows_created":0,
        "source_selection_frozen_before_scoring":True,
        "not_sealed_or_pretraining_disjoint":True,
        "case_count":8,
        "project_count":4,
        "model_f32_inputs":16,
        "genuine_repeated_inferences":32,
        "model_source_author_matches":fact,
        "model_complete_reversals":reversals,
        "model_preference_changes":changed,
        "constant_A_matches":4,
        "constant_B_matches":4,
        "constant_A_reversals":0,
        "constant_B_reversals":0,
        "content_invariant_rule_max_possible_matches":4,
        "content_invariant_rule_max_possible_reversals":0,
        "source_aware_oracle_author_agreement":8,
        "source_aware_oracle_reversals":4,
        "source_aware_oracle_is_hardcoded_from_author_hypotheses":True,
        "model_quality_improvement_established":False,
        "source_test_files_unchanged_by_fix":2,
        "source_lock_sha256":hashlib.sha256(raw_lock).hexdigest(),
        "authentic_f32_ledger_sha256":hashlib.sha256(raw_ledger).hexdigest(),
        "model_sha256":ledger["original_quarantined_lora_sha256"],
        "model_inference_url":ledger["run_url"],
        "score_proof_url":"https://github.com/Iniwura/falsum/blob/main/evidence/phase4h-2026-11-14-actual-original-model-source-8-conditions.json",
        "source_frozen_url":"https://github.com/Iniwura/falsum/blob/main/data/phase4h-frozen-four-new-source-projects.json",
        "groups":groups,
        "notice":"Measured comparisons use researcher-interpreted PUBLIC source facts; 0 independent AppSec gold labels, no sealed holdout. A source-aware oracle is correct by construction, not a trained evaluator and not comparable evidence of AI accuracy. Original LoRA unchanged and not registered.",
    }


def render(data:dict, template:str)->str:
    key="__FALSUM_PHASE4I_DATA__"
    require(template.count(key)==1 and data.get("status")==STATUS
            and data.get("model_source_author_matches")==5
            and data.get("model_complete_reversals")==1
            and data.get("source_aware_oracle_is_hardcoded_from_author_hypotheses") is True
            and data.get("model_registered") is False
            and data.get("independent_expert_gold_labels")==0,
            "unsafe template or misrepresented original model")
    encoded=json.dumps(data,ensure_ascii=False,separators=(",",":"))
    for letter,escaped in (("&","\\u0026"),("<","\\u003c"),(">","\\u003e")):
        encoded=encoded.replace(letter,escaped)
    return template.replace(key,encoded)


def write(out_dir:Path,root:Path=ROOT)->dict:
    require(not out_dir.exists() and not out_dir.is_symlink(),
            "refuse to overwrite the public source comparison")
    data=report(root)
    template=(root / TEMPLATE.relative_to(ROOT)).read_text(encoding="utf-8")
    markup=render(data,template)
    out_dir.mkdir(parents=True,exist_ok=False)
    (out_dir/"index.html").write_text(markup,encoding="utf-8")
    (out_dir/"ACTUAL-PHASE4H-FROZEN-SOURCE-MODEL-COMPARISON.json").write_text(
        json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return data


def main(argv=None):
    p=argparse.ArgumentParser(description="Build real source-controlled original-model comparison, not trained accuracy")
    p.add_argument("--out-dir",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        data=write(args.out_dir)
        print(json.dumps({k:data[k] for k in
            ("status","project_count","case_count","model_source_author_matches",
             "model_complete_reversals","independent_expert_gold_labels",
             "model_registered")},indent=2))
        return 0
    except (ValueError,KeyError,TypeError,IndexError,OSError) as e:
        p.exit(1,"PHASE 4I COMPARISON BUILD BLOCKED: "+str(e)+"\n")


if __name__=="__main__":
    raise SystemExit(main())
