"""Phase 3C: deterministic real-model smoke inputs using the node's exact tokenizer.

Only a bounded, explicitly source-owned, research-only synthetic security
prompt pair is scored. This is NOT expert-reviewed preference ground truth.
The scorer can rank either response; correctness is NOT assumed or asserted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

STATUS="PHASE3C_REAL_FOUNDATION_SCORE_INPUTS_AI_PROVISIONAL_NOT_ACCURACY"
TOKENIZER_SHA256="67bc76f8b9386efba1a761c1c8e5ad439fd0eaf1c2826e9dd1a205c7af4dc456"
TOKEN_CAP=160
TASK=("Review aiohttp Python static routing. The actual installed package is aiohttp 3.10.11. "
      "The route uses follow_symlinks=True. Is CVE-2024-23334 confirmed?")
CANDIDATES=(
  ("cautious","No. The documented fix was released in aiohttp 3.9.2, so 3.10.11 is patched "
   "for that issue. Review other file and route risks separately; do not claim a confirmed exploit."),
  ("overclaim","Yes, follow_symlinks=True always proves CVE-2024-23334 is exploitable. "
   "A patched aiohttp version cannot matter and this application is definitely vulnerable."),
)
class InputError(ValueError):
    pass


def validate(tokenizer_bytes:bytes)->None:
    if not isinstance(tokenizer_bytes,bytes) or hashlib.sha256(tokenizer_bytes).hexdigest()!=TOKENIZER_SHA256:
        raise InputError("refuse noncanonical tokenizer bytes; Foundation tokenizer drift")


def make_inputs(tokenizer_bytes:bytes,encode)->dict:
    validate(tokenizer_bytes)
    out=[]
    for label,answer in CANDIDATES:
        rendered="### Task:\n"+TASK+"\n\n### Answer:\n"+answer
        ids=encode(rendered)
        if (not isinstance(ids,list) or not 8<=len(ids)<=TOKEN_CAP
                or any(type(i) is not int or not 0<=i<50368 for i in ids)
                or ids[0]!=50281 or ids[-1]!=50282):
            raise InputError("bad ModernBERT task-answer encoded token framing or cap")
        out.append({"name":label,"input_ids":ids,"token_count":len(ids),
                    "rendered_input_sha256":hashlib.sha256(rendered.encode()).hexdigest(),
                    "research_only":True})
    if out[0]["input_ids"]==out[1]["input_ids"]:
        raise InputError("model input candidates must be different")
    return {"schema_version":1,"status":STATUS,"research_only":True,
            "official_tokenizer_sha256":TOKENIZER_SHA256,
            "token_cap_for_smoke":TOKEN_CAP,
            "actual_node_token_cap":512,
            "security_task":TASK,
            "candidates":out,
            "model_preference_known_in_advance":False,
            "independent_human_labels":0,
            "confirmed_exploits":0,
            "network_eligible":False,
            "note":"Only scores research-owned texts. Different scores are not evidence of correct vulnerability judgment. Node's actual tokenizer was verified by SHA256."}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Generate real node-tokenizer task/answer ids for isolated Foundation score smoke")
    p.add_argument("--tokenizer",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.out.exists():
            raise InputError("refuse to overwrite existing scoring evidence")
        raw=args.tokenizer.read_bytes()
        validate(raw)
        from tokenizers import Tokenizer
        tk=Tokenizer.from_str(raw.decode())
        # The exact node uses right truncation with a 512-token maximum.
        # Keep this research smoke <=160, no premature truncate.
        def encode(text):
            return tk.encode(text,add_special_tokens=True).ids
        result=make_inputs(raw,encode)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        for item in result["candidates"]:
            path=args.out.parent/("SCORE-"+item["name"]+"-TOKEN-INPUT.json")
            if path.exists():
                raise InputError("refuse to overwrite scoring input")
            path.write_text(json.dumps({"input_ids":item["input_ids"],
                                        "attention_mask":[1]*item["token_count"]},
                                       separators=(",",":"))+"\n")
        print(json.dumps({"status":STATUS,
                          "inputs":len(result["candidates"]),
                          "token_lengths":[x["token_count"] for x in result["candidates"]],
                          "independent_security_accuracy":False},indent=2))
        return 0
    except (OSError,ValueError,InputError,UnicodeDecodeError) as exc:
        p.exit(1,f"FALSUM OFFICIAL FOUNDATION INPUT ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
