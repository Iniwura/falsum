"""Phase 3J: freeze *research-only*, runtime-anchored model-context comparisons.

Two historical families with real Phase 3H/3I installed-runtime evidence.
This is NOT an untouched cross-project holdout, nor a human-labeled dataset.
Each family has two byte-identical answers across two contrasting contexts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase3c_score_inputs import TOKENIZER_SHA256, validate as validate_tokenizer

STATUS = "PHASE3J_FROZEN_KNOWN_FAMILY_COUNTERFACTUAL_MODEL_DIAGNOSTIC_NOT_HOLDOUT"
MAX_TOKENS = 192
FAMILIES = (
    {
        "id": "starlette-path-boundary",
        "advisory": "GHSA-v5gw-mw7f-84px",
        "runtime_evidence": "evidence/phase3h-2026-11-02.json",
        "answers": (
            ("outside-path-blocked",
             "The stated Starlette StaticFiles release rejects the synthetic same-prefix outside-root sibling with a 404. The historical directory-boundary behavior is patched in this controlled check."),
            ("outside-path-exposed",
             "The stated Starlette StaticFiles release returns the synthetic same-prefix outside-root sibling with a 200. The historical directory-boundary behavior is present in this controlled check."),
        ),
        "contexts": (
            ("affected",
             "The installed Starlette version is 0.26.1, with a public static directory and a harmless outside-root sibling sharing its name prefix. The real isolated StaticFiles check returned HTTP 200 for that sibling. Which answer matches the observed historical library behavior?",
             "outside-path-exposed"),
            ("fixed",
             "The installed Starlette version is 0.27.0, with a public static directory and a harmless outside-root sibling sharing its name prefix. The real isolated StaticFiles check returned HTTP 404 for that sibling. Which answer matches the observed historical library behavior?",
             "outside-path-blocked"),
        ),
    },
    {
        "id": "requests-proxy-auth",
        "advisory": "GHSA-j8r2-6x86-q33q",
        "runtime_evidence": "evidence/phase3i-2026-11-02.json",
        "answers": (
            ("https-auth-absent",
             "For the stated installed Requests version, rebuilding the synthetic credentialed HTTPS proxy request does not add Proxy-Authorization to the prepared request. This is an in-memory observation, not proof of live traffic safety."),
            ("https-auth-present",
             "For the stated installed Requests version, rebuilding the synthetic credentialed HTTPS proxy request adds Proxy-Authorization to the prepared request. This is an in-memory observation, not proof of live credential exfiltration."),
        ),
        "contexts": (
            ("affected",
             "The installed Requests version is 2.30.0. A synthetic credentialed proxy was configured and the real in-memory rebuild_proxies method ran on an HTTPS PreparedRequest. The controlled result had a Proxy-Authorization header. Which answer fits this observation?",
             "https-auth-present"),
            ("fixed",
             "The installed Requests version is 2.31.0. A synthetic credentialed proxy was configured and the real in-memory rebuild_proxies method ran on an HTTPS PreparedRequest. The controlled result lacked a Proxy-Authorization header. Which answer fits this observation?",
             "https-auth-absent"),
        ),
    },
)


class Phase3JError(ValueError):
    pass


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def proof(root: Path) -> dict:
    """Provenance anchor to *already executed* controlled runtime reports."""
    h = json.loads((root / "evidence/phase3h-2026-11-02.json").read_text())
    i = json.loads((root / "evidence/phase3i-2026-11-02.json").read_text())
    if (h.get("status") != "PHASE3H_REAL_INSTALLED_HISTORICAL_STARLETTE_RUNTIME_DELTA_VERIFIED_RESEARCH_ONLY"
        or h.get("workflow_conclusion") != "success"
        or h.get("successful_workflow_url") != "https://github.com/Iniwura/falsum/actions/runs/41409503521"
        or h.get("historical_case", {}).get("upstream_security_fix_commit") != "1797de464124b090f10cf570441e8292936d63e3"
        or h.get("real_runtime", {}).get("controls") != {
            "inside_file":{"vulnerable_http_status":200,"patched_http_status":200},
            "missing_file":{"vulnerable_http_status":404,"patched_http_status":404},
            "unrelated_sibling":{"vulnerable_http_status":404,"patched_http_status":404},
            "same_prefix_outside_root_sibling":{"vulnerable_http_status":200,"patched_http_status":404},
        }
        or i.get("status") != "PHASE3I_REAL_INSTALLED_REQUESTS_PROXY_AUTH_BOUNDARY_VERIFIED_RESEARCH_ONLY"
        or i.get("verification") != "success"
        or i.get("verified_workflow_url") != "https://github.com/Iniwura/falsum/actions/runs/41410209502"
        or i.get("case", {}).get("fix_commit") != "74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5"
        or i.get("installed_runtime", {}).get("observations", {}).get("https_credentialed_proxy") != {
            "affected_header_present":True,"fixed_header_present":False,
        }
        or h.get("verification", {}).get("independent_human_approved_labels") != 0
        or i.get("validation", {}).get("independent_human_approved_labels") != 0
        or h.get("verification", {}).get("network_eligible") is not False
        or i.get("validation", {}).get("network_eligible") is not False):
        raise Phase3JError("source-reported behavior provenance is not exactly verified and unreviewed")
    return {
        "phase3h_evidence_sha256": hashlib.sha256((root / "evidence/phase3h-2026-11-02.json").read_bytes()).hexdigest(),
        "phase3i_evidence_sha256": hashlib.sha256((root / "evidence/phase3i-2026-11-02.json").read_bytes()).hexdigest(),
        "phase3h_runtime_workflow": h["successful_workflow_url"],
        "phase3i_runtime_workflow": i["verified_workflow_url"],
    }


def render(family: dict, context: tuple, answer: tuple) -> str:
    return "### Task:\n" + context[1] + "\n\n### Answer:\n" + answer[1]


def construct(root: Path, tokenizer_bytes: bytes, encode) -> dict:
    validate_tokenizer(tokenizer_bytes)
    provenance = proof(root)
    outputs = []
    for f in FAMILIES:
        if len(f["contexts"]) != 2 or len(f["answers"]) != 2:
            raise Phase3JError("not exactly two contexts and stable candidate answers")
        answer_ids = {a[0] for a in f["answers"]}
        if {c[2] for c in f["contexts"]} != answer_ids:
            raise Phase3JError("no deterministic two-context expected reversal")
        for context in f["contexts"]:
            for answer in f["answers"]:
                body = render(f, context, answer)
                tokens = encode(body)
                if (not isinstance(tokens, list) or not 8 <= len(tokens) <= MAX_TOKENS
                    or tokens[0] != 50281 or tokens[-1] != 50282
                    or any(type(t) is not int or not 0 <= t < 50368 for t in tokens)):
                    raise Phase3JError("invalid pinned tokenizer framing or input over 192 tokens; never truncate")
                outputs.append({
                    "id": f["id"] + "--" + context[0] + "--" + answer[0],
                    "family": f["id"], "context": context[0], "answer_id": answer[0],
                    "task_sha256": sha(context[1]), "answer_sha256": sha(answer[1]),
                    "rendered_sha256": sha(body),
                    "input_ids": tokens, "token_count": len(tokens),
                    "provisional_runtime_rule_preferred": context[2],
                    "human_expert_approved": False,
                })
    if len(outputs) != 8 or len({o["id"] for o in outputs}) != 8:
        raise Phase3JError("exactly eight unique task-answer pairs required")
    for family in FAMILIES:
        rows = [o for o in outputs if o["family"] == family["id"]]
        for answer in family["answers"]:
            if len({o["answer_sha256"] for o in rows if o["answer_id"] == answer[0]}) != 1:
                raise Phase3JError("answer bytes changed across opposite factual contexts")
    return {
        "schema_version":1, "status":STATUS, "official_tokenizer_sha256":TOKENIZER_SHA256,
        "model_family_count":2,"context_count":4,"score_input_count":8,
        "source_provenance":provenance,
        "frozen_known_historical_families":True, "unseen_blind_holdout":False,
        "training_material_generated":False, "independent_expert_labels":0,
        "eligible_anjoman_rows":0, "network_eligible":False,
        "existing_model_release_veto_still_applies":True,
        "inputs":outputs,
        "notice":"Real already-observed historical runtime evidence anchors researcher-authored paired scoring tasks. This is NOT a new heldout project, independent human label, accepted eval row, model accuracy measure or permission to register."
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Research-only historical behavior context-pair inputs")
    p.add_argument("--tokenizer", required=True, type=Path)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if args.out.exists():
            raise Phase3JError("refuse to overwrite prior model evidence")
        raw = args.tokenizer.read_bytes()
        from tokenizers import Tokenizer
        tokenizer = Tokenizer.from_str(raw.decode("utf-8"))
        report = construct(args.root, raw, lambda value: tokenizer.encode(value, add_special_tokens=True).ids)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        for item in report["inputs"]:
            path = args.out.parent / ("SCORE-" + item["id"] + ".json")
            if path.exists():
                raise Phase3JError("refuse to overwrite score input")
            path.write_text(json.dumps({
                "input_ids":item["input_ids"],"attention_mask":[1]*item["token_count"],
            }, separators=(",",":")) + "\n")
        args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        print(json.dumps({"status":STATUS,"model_inputs":8,
             "max_token_count":max(o["token_count"] for o in report["inputs"]),
             "eligible_anjoman_rows":0,"blind_holdout":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        p.exit(1, f"FALSUM PHASE 3J INPUT BOUNDARY FAILED: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
