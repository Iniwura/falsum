"""Phase 3D real Foundation-model counterfactual inputs, no accuracy laundering.

Within each 2-context family the two complete answer strings are BYTE
IDENTICAL. Only the task's stated dependency version or route flag changes.
The 'preferred' response is a provisional rule-based diagnostic expectation,
NOT expert-adjudicated ground truth or an official network evaluation label.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .phase3c_score_inputs import TOKENIZER_SHA256, validate

STATUS="PHASE3D_VERSION_AND_FLAG_COUNTERFACTUAL_RESEARCH_ONLY"
MAX_TOKENS=192

FAMILIES=(
    {
        "family":"installed-version",
        "fixed_answers":(
            ("not-affected",
             "This installation is outside the historical CVE-2024-23334 affected version range. "
             "Do not assert this CVE applies; separately inspect unrelated file-routing risks."),
            ("potentially-affected",
             "This installation predates the aiohttp 3.9.2 fix and has the symlink-following option enabled. "
             "Treat the CVE as potentially applicable; verify public route reachability and symlink paths before declaring an exploit."),
        ),
        "contexts":(
            ("affected","The installed version is aiohttp 3.9.1. The registered public static route uses follow_symlinks=True. "
             "For CVE-2024-23334, which review interpretation matches the stated deployment facts?","potentially-affected"),
            ("patched","The installed version is aiohttp 3.10.11. The registered public static route uses follow_symlinks=True. "
             "For CVE-2024-23334, which review interpretation matches the stated deployment facts?","not-affected"),
        ),
    },
    {
        "family":"symlink-flag",
        "fixed_answers":(
            ("flag-not-met",
             "The source explicitly disables following symlinks on this registered route. "
             "The follow_symlinks=True prerequisite of the historical advisory is not shown for this call; review other routes separately."),
            ("flag-met",
             "The source explicitly enables following symlinks on this registered route and the installed aiohttp predates the fix. "
             "The advisory prerequisites are plausible; inspect route reachability and attacker-influenced symlinks before asserting exploitability."),
        ),
        "contexts":(
            ("disabled","The installed version is aiohttp 3.9.1. The public static route is registered with follow_symlinks=False. "
             "For CVE-2024-23334, which review interpretation matches the stated route configuration?","flag-not-met"),
            ("enabled","The installed version is aiohttp 3.9.1. The public static route is registered with follow_symlinks=True. "
             "For CVE-2024-23334, which review interpretation matches the stated route configuration?","flag-met"),
        ),
    },
)


class CounterfactualInputError(ValueError):
    pass


def construct(tokenizer_bytes:bytes,encode)->dict:
    validate(tokenizer_bytes)
    rows=[]
    for fam in FAMILIES:
        if len(fam["contexts"])!=2 or len(fam["fixed_answers"])!=2:
            raise CounterfactualInputError("exactly one paired context and two fixed answers per family")
        answer_ids=[a[0] for a in fam["fixed_answers"]]
        if len(set(answer_ids))!=2:
            raise CounterfactualInputError("duplicate fixed answer identities")
        if [c[2] for c in fam["contexts"]]!=[answer_ids[1],answer_ids[0]]:
            raise CounterfactualInputError("expected counterfactual reversal must be explicit")
        for context_id,task,preferred in fam["contexts"]:
            for answer_id,answer in fam["fixed_answers"]:
                ident=fam["family"]+"--"+context_id+"--"+answer_id
                rendered="### Task:\n"+task+"\n\n### Answer:\n"+answer
                ids=encode(rendered)
                if (not isinstance(ids,list) or not 8<=len(ids)<=MAX_TOKENS or
                        any(type(v) is not int or v<0 or v>=50368 for v in ids) or
                        ids[0]!=50281 or ids[-1]!=50282):
                    raise CounterfactualInputError("bad canonical token framing/length; do NOT truncate")
                rows.append({
                    "id":ident,
                    "family":fam["family"],"context":context_id,
                    "answer_id":answer_id,
                    "task_sha256":hashlib.sha256(task.encode()).hexdigest(),
                    "answer_sha256":hashlib.sha256(answer.encode()).hexdigest(),
                    "rendered_input_sha256":hashlib.sha256(rendered.encode()).hexdigest(),
                    "input_ids":ids,"token_count":len(ids),
                    "provisional_rule_based_preferred_answer":preferred,
                    "approved_expert_label":False,
                })
    if len(rows)!=8 or len({r["id"] for r in rows})!=8:
        raise CounterfactualInputError("expected exactly eight unique input identities")
    for fam in FAMILIES:
        frows=[r for r in rows if r["family"]==fam["family"]]
        for answer_id,_ in fam["fixed_answers"]:
            hashes={r["answer_sha256"] for r in frows if r["answer_id"]==answer_id}
            if len(hashes)!=1:
                raise CounterfactualInputError("answer changed across context; invalid reversal test")
        if len({r["task_sha256"] for r in frows})!=2:
            raise CounterfactualInputError("two genuinely distinct contexts required")
    return {
        "schema_version":1,"status":STATUS,
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "actual_node_token_cap":512,"bounded_counterfactual_token_cap":MAX_TOKENS,
        "research_only":True,"training_data_source":"AI_PROVISIONAL_NOT_HUMAN_REVIEWED",
        "rule_anchoring":"aiohttp GHSA-5h86-8mv2-jq9f fixed in 3.9.2; true symlink-following static route flag is a necessary precondition, not exploit proof",
        "candidate_answer_bytes_fixed_within_each_family":True,
        "context_counterfactual_families":2,"total_contexts":4,"inputs":rows,
        "independent_expert_labels":0,"network_eligible":False,
        "unseen_or_blind_holdout":False,
        "note":"Provisional diagnostics only. Source facts and task construction were selected by FALSUM researchers. Neither positive preference margins nor 2/2 reversals would certify security accuracy."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Create exact tokenizer security-version and route-flag counterfactual pairs")
    p.add_argument("--tokenizer",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise CounterfactualInputError("refuse existing evidence overwrite")
        data=a.tokenizer.read_bytes()
        validate(data)
        from tokenizers import Tokenizer
        tk=Tokenizer.from_str(data.decode())
        result=construct(data,lambda text:tk.encode(text,add_special_tokens=True).ids)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        for row in result["inputs"]:
            target=a.out.parent/("SCORE-"+row["id"]+".json")
            if target.exists():
                raise CounterfactualInputError("refuse existing test input overwrite")
            target.write_text(json.dumps({
                "input_ids":row["input_ids"],"attention_mask":[1]*row["token_count"]
            },separators=(",",":"))+"\n",encoding="utf-8")
        a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":STATUS,"contexts":4,"model_inputs":8,
                          "lengths":[r["token_count"] for r in result["inputs"]],
                          "independent_accuracy_certified":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,CounterfactualInputError) as e:
        p.exit(1,f"FALSUM COUNTERFACTUAL INPUT GATE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
