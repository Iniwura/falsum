"""Permanent authentic Phase 4H old-model f32-bit evidence, no registration."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import zipfile

STATUS="PHASE4H_GENUINE_UNCHANGED_ORIGINAL_MODEL_FOUR_NEW_PUBLIC_PROJECTS"
RUN=43530363990
ARTIFACT=14087002554
LOCK_GIT="9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2"
LOCK_SHA="9a642084003c633dc8a7bd68189634b37e9665fa7c65f6b3b73f8c239ef877eb"
SOURCE_SHA="295625b4bac3504d5c82e56a66f805339b09e244fc5e41104c9d2494cb127260"
INPUT_SHA="24d5d0a8b3b3db49e0dded1c8598b50625e336094dfbc6f0b93efc12fcfa43a6"
RESULT_SHA="7b7c59b7b6ff3b1ea40a4f18bbad1eb6b85a712d2693589e7a468d51672bf0b5"
MODEL_SHA="3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc"
FOUNDATION_SHA="0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6"
TOKENIZER_SHA="67bc76f8b9386efba1a761c1c8e5ad439fd0eaf1c2826e9dd1a205c7af4dc456"
GROUPS=("pyjwt","werkzeug","mcp-python","pillow")
EXPECTED_SCORE_BITS = {
    "mcp-python-fixed--A": "0xbfaac074",
    "mcp-python-fixed--B": "0xbf911984",
    "mcp-python-parent--A": "0xbf86d966",
    "mcp-python-parent--B": "0xbf84d2ba",
    "pillow-fixed--A": "0xbf4f51b7",
    "pillow-fixed--B": "0xbf294cb4",
    "pillow-parent--A": "0xbf4ebd3a",
    "pillow-parent--B": "0xbf379a5e",
    "pyjwt-fixed--A": "0xbf93ad6c",
    "pyjwt-fixed--B": "0xbf917a5d",
    "pyjwt-parent--A": "0xbf8d8722",
    "pyjwt-parent--B": "0xbf8e7507",
    "werkzeug-fixed--A": "0xbea837d7",
    "werkzeug-fixed--B": "0xbe26ed78",
    "werkzeug-parent--A": "0xbf19f6cc",
    "werkzeug-parent--B": "0xbee0c7a0",
}


class EvidenceError(ValueError):
    pass

def require(flag,reason):
    if not flag:
        raise EvidenceError(reason)

def sha(raw:bytes):
    return hashlib.sha256(raw).hexdigest()

def f32(hexscore):
    require(isinstance(hexscore,str) and re.fullmatch(r"0x[0-9a-f]{8}",hexscore),
            "invalid float32 score bits")
    val=struct.unpack("!f",bytes.fromhex(hexscore[2:]))[0]
    require(math.isfinite(val),"non-finite actual score")
    return val

def validate_ledger(d:dict):
    pins={
      "schema_version":1,"status":STATUS,
      "actual_official_foundation_inference":True,"run_id":RUN,
      "run_url":"https://github.com/Iniwura/falsum/actions/runs/"+str(RUN),
      "genuine_score_artifact_id":ARTIFACT,
      "original_quarantined_lora_sha256":MODEL_SHA,
      "official_foundation_sha256":FOUNDATION_SHA,
      "official_tokenizer_sha256":TOKENIZER_SHA,
      "frozen_selection_git_blob":LOCK_GIT,
      "frozen_selection_sha256":LOCK_SHA,
      "source_report_sha256":SOURCE_SHA,
      "frozen_inputs_canonical_sha256":INPUT_SHA,
      "original_results_file_sha256":RESULT_SHA,
      "genuine_model_score_inputs":16,"repeat_verified_inference_calls":32,
      "source_revision_conditions":8,"total_source_reversal_groups":4,
      "constant_A_source_fact_matches":4,"constant_B_source_fact_matches":4,
      "independent_security_expert_labels":0,
      "not_blind_or_pretraining_disjoint":True,
      "new_anjoman_eligible_rows":0,
      "no_model_training_or_improvement_performed":True,
      "registered_evaluator":False,
      "automatic_registration_permitted":False,
      "original_model_release_veto":True,
    }
    require(isinstance(d,dict) and all(
        type(d.get(k)) is type(v) and d[k]==v for k,v in pins.items()),
        "model/source identity or no-registration boundary altered")
    scores=d.get("score_hex_by_input")
    ids={p+"-"+r+"--"+a for p in GROUPS for r in ("parent","fixed") for a in ("A","B")}
    require(isinstance(scores,dict) and len(scores)==16 and set(scores)==ids,
            "exact sixteen official scores missing")
    require(scores == EXPECTED_SCORE_BITS,
            "one or more original official float32 score bits were altered")
    decisions={}
    agreements=0
    reversed_groups=[]
    count_changed=0
    for p in GROUPS:
        for r,expected in (("parent","A"),("fixed","B")):
            va=f32(scores[p+"-"+r+"--A"])
            vb=f32(scores[p+"-"+r+"--B"])
            selected="A" if va>vb else "B" if vb>va else "TIE"
            decisions[p+"-"+r]=selected
            agreements+=selected==expected
        before,after=decisions[p+"-parent"],decisions[p+"-fixed"]
        if before=="A" and after=="B":
            reversed_groups.append(p)
        count_changed+=before!=after and "TIE" not in (before,after)
    require(decisions==d.get("expected_model_preference_by_case")
            and agreements==d.get("source_revision_fact_matches")==5
            and len(reversed_groups)==d.get("complete_researcher_source_reversals")==1
            and reversed_groups==d.get("source_reversal_groups_correct")==["pyjwt"]
            and d.get("source_reversal_groups_not_correct")==["werkzeug","mcp-python","pillow"]
            and count_changed==d.get("model_preference_reversal_count")==1,
            "recorded real result differs from exact published float32-bit choices")
    return {"status":STATUS,"real_score_bits_verified":16,
            "source_research_matches":agreements,
            "complete_source_fact_reversals":len(reversed_groups),
            "model_preference_change_groups":count_changed,
            "constant_A_baseline":4,"constant_B_baseline":4,
            "expert_gold_labels":0,"model_release_veto":True}

def validate_original_report(d:dict,raw:bytes):
    require(sha(raw)==RESULT_SHA,"original genuine score-report bytes have changed")
    actual=json.loads(raw)
    fixed={
      "status":"PHASE4H_REAL_ORIGINAL_QUARANTINED_LORA_NEW_PROJECTS_NOT_NETWORK_QUALITY",
      "actual_official_foundation_inference":True,
      "original_quarantined_lora_sha256":MODEL_SHA,
      "official_foundation_sha256":FOUNDATION_SHA,
      "official_tokenizer_sha256":TOKENIZER_SHA,
      "frozen_lock_git_blob":LOCK_GIT,
      "frozen_selection_sha256":LOCK_SHA,
      "real_source_verification_sha256":SOURCE_SHA,
      "frozen_token_inputs_sha256":INPUT_SHA,
      "true_official_score_inputs":16,
      "actual_repeated_inference_calls":32,
      "source_author_agreements":5,
      "complete_author_source_fact_reversals":1,
      "model_preference_reversal_count":1,
      "model_release_veto":True,
      "registered_evaluator":False,
      "independent_appsec_gold_labels":0,
    }
    require(all(actual.get(k)==v for k,v in fixed.items())
            and actual.get("actual_score_hex_by_input")==d["score_hex_by_input"],
            "permanent result ledger differs from real official scoring artifact")

def verify_archive(d:dict,p:Path):
    with zipfile.ZipFile(p) as z:
        report="results/ACTUAL-NEW-FOUR-PROJECTS-ORIGINAL-MODEL-REPORT.json"
        require(z.namelist().count(report)==1,"one real report required in ZIP")
        validate_original_report(d,z.read(report))
        source=z.read("source/ACTUAL-FOUR-UNSEEN-REPOSITORY-FIX-AND-TEST-BLOB-PROOF.json")
        require(sha(source)==SOURCE_SHA,"real upstream source proof altered")
        tokens=z.read("results/FROZEN-EIGHT-SOURCE-REVISION-TOKEN-INPUTS.json")
        token=json.loads(tokens)
        require(sha(json.dumps(token,sort_keys=True,separators=(",",":")).encode())
                 ==INPUT_SHA,"exact source-bound official token IDs were changed")

def main(argv=None):
    p=argparse.ArgumentParser(description="Verify actual original LoRA f32 scores, not model accuracy")
    p.add_argument("--ledger",type=Path,required=True)
    p.add_argument("--archive",type=Path)
    a=p.parse_args(argv)
    try:
        ledger=json.loads(a.ledger.read_text(encoding="utf-8"))
        summary=validate_ledger(ledger)
        if a.archive:
            verify_archive(ledger,a.archive)
            summary["original_real_scoring_archive_verified"]=True
        print(json.dumps(summary,indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError,zipfile.BadZipFile) as e:
        p.exit(1,"PHASE4H REAL ORIGINAL MODEL EVIDENCE BLOCKED: "+str(e)+"\n")

if __name__=="__main__":
    raise SystemExit(main())
