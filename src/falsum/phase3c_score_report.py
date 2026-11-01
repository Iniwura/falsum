"""Phase 3C: audit real official foundation-runtime score packets.

Only the CURRENT official adapterbuild outputs are accepted, and stage1-only
results are rejected. The system records score bits, never pretends preferred
responses were independently adjudicated and never registers an evaluator.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import re
import struct
from pathlib import Path

from .phase3c_score_inputs import STATUS as INPUT_STATUS, TOKENIZER_SHA256

STATUS="PHASE3C_REAL_FOUNDATION_MODEL_LOADED_SCORED_TWICE_PER_ANSWER_RESEARCH_ONLY"
MODEL_SHA="3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc"
MODEL_KECCAK="0xf8f94708f30ed31b6f0825dbffb235fa60b0e71b76fde39dbc696cf277ef8aa7"
FOUNDATION_SHA="0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6"
FOUNDATION_VERSION="modernbert-base-lora16-v1"
HEX=re.compile(r"(?:0x)?[0-9a-fA-F]{8}\Z")

class ScoreProofError(ValueError):
    pass


def _score(out:dict,expected_name:str)->dict:
    if not isinstance(out,dict) or set(out).isdisjoint({"manifest","score_hex"}):
        raise ScoreProofError("official node output missing")
    m=out.get("manifest")
    if not isinstance(m,dict):
        raise ScoreProofError("official runtime manifest absent")
    f=m.get("foundation") or {}
    v=m.get("verification") or {}
    if not all((
        out.get("intent")=="SECURITY_REVIEW",out.get("class")=="hybrid",
        out.get("sha256")==MODEL_SHA,out.get("keccak256")==MODEL_KECCAK,
        out.get("bytes")==6776908,
        m.get("intent")=="SECURITY_REVIEW",m.get("class")=="hybrid",
        m.get("abi")=="lora-v1",m.get("rank")==8,
        m.get("max_tokens")==512,
        m.get("tokenizer_hash")==TOKENIZER_SHA256,
        f.get("hash")==FOUNDATION_SHA,f.get("version")==FOUNDATION_VERSION,
        v.get("stage1") is True,v.get("loaded") is True,
        v.get("repeats")==2,
        isinstance(out.get("score_hex"),str),
        v.get("score_hex")==out.get("score_hex"),
    )):
        raise ScoreProofError("actual foundation load, repeat, package or tokenizer provenance incomplete")
    score=out["score_hex"]
    if not HEX.fullmatch(score):
        raise ScoreProofError("invalid native f32 score-bits hex")
    bits=int(score.removeprefix("0x"),16)
    value=struct.unpack(">f",struct.pack(">I",bits))[0]
    if not math.isfinite(value):
        raise ScoreProofError("model score NaN or Infinity")
    return {"candidate":expected_name,"float32_score_hex":score,"float32_value":value,
            "real_foundation_loaded":True,"repeat_scores_bit_identical":True}


def report(inputs:dict,first:dict,second:dict)->dict:
    if (not isinstance(inputs,dict) or inputs.get("status")!=INPUT_STATUS
        or inputs.get("research_only") is not True
        or inputs.get("network_eligible") is not False
        or inputs.get("independent_human_labels")!=0
        or inputs.get("official_tokenizer_sha256")!=TOKENIZER_SHA256
        or not isinstance(inputs.get("candidates"),list)
        or len(inputs["candidates"])!=2
        or [x.get("name") for x in inputs["candidates"]]!=["cautious","overclaim"]):
        raise ScoreProofError("unapproved, leaked or spoofed model input")
    a=_score(first,"cautious")
    b=_score(second,"overclaim")
    return {
        "schema_version":1,"status":STATUS,
        "model_sha256":MODEL_SHA,"model_keccak256":MODEL_KECCAK,
        "foundation_sha256":FOUNDATION_SHA,
        "tokenizer_sha256":TOKENIZER_SHA256,
        "official_go_builder_stage1_passed":True,
        "official_node_runtime_foundation_loaded":True,
        "input_count":2,"actual_repeated_inferences":4,
        "repeat_bit_consistency_verified":True,
        "answers":[a,b],
        "observed_score_margin_cautious_minus_overclaim":a["float32_value"]-b["float32_value"],
        "diagnostic_only_not_expert_accuracy":True,
        "human_approved_labels":0,
        "source_training_quality_certified":False,
        "real_world_exploit_detection_established":False,
        "accepted_anjoman_rows":0,"network_eligible":False,
        "evaluator_registered":False,
        "note":"Authentic loaded Foundation scores on a single synthetic research question. A higher score for either answer is a diagnostic observation, NOT accuracy validation; no network hidden evaluation was performed.",
        "scoring_input_sha256":hashlib.sha256(
            json.dumps(inputs,sort_keys=True,separators=(",",":")).encode()
        ).hexdigest()
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Prove official runtime score bits exist and remain deterministic; never approve model accuracy")
    for k in ("inputs","cautious","overclaim","out"):
        p.add_argument("--"+k,required=True,type=Path)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ScoreProofError("refuse overwriting prior model-score evidence")
        data=report(json.loads(a.inputs.read_text()),json.loads(a.cautious.read_text()),
                    json.loads(a.overclaim.read_text()))
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(data,sort_keys=True,indent=2)+"\n")
        print(json.dumps({"status":STATUS,"actual_inferences":4,"score_bits":{r["candidate"]:r["float32_score_hex"] for r in data["answers"]},
                          "foundation_loaded":True,"quality_certified":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ScoreProofError) as e:
        p.exit(1,f"FALSUM REAL FOUNDATION SCORE PROOF FAILED: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
