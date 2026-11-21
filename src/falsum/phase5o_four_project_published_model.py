"""Phase 5O: frozen, genuine published-model diagnostic across four public projects.

The historical source *summaries* are authored open-book material, not raw code
read by the model, hidden holdout, or independent AppSec gold. A successful
unit test does not imply real inference; only the Actions CPU run does.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from .phase4h_frozen_source import validate_lock
from .phase5l_pymdown_upstream_replay import git_blob
from .phase5m_real_source_sensitive_model import ROOT, require, read_json, canonical_json, sha, DiagnosticError
from .phase5n_published_candidate_runner import (
    MODEL_REPO, SHA40, WHITELIST, get_sha256_file, parse_choice, write_once,
)

PROTOCOL_PATH = "data/phase5o-four-project-frozen-model-protocol.json"
PROTOCOL_GIT_BLOB_SHA1 = "07d41d2f12c7b9ececac299c72785faae0ef85ea"
SOURCE_PATH = "data/phase4h-frozen-four-new-source-projects.json"
SOURCE_GIT_BLOB_SHA1 = "9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2"
MODEL_REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
MODEL_SAFETENSORS_SHA256 = "fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe"
STATUS_INPUT = "PHASE5O_FROZEN_PUBLIC_FOUR_PROJECT_MODEL_PROMPTS"
STATUS_RAW = "PHASE5O_PUBLISHED_MODEL_CPU_ACTUAL_COMPLETIONS_RESEARCHER_OPERATED"
STATUS_RESULT = "PHASE5O_PUBLIC_SOURCE_SUMMARY_MODEL_DIAGNOSTIC_NOT_EXPERT_GOLD"
LABELS = ("A", "B", "ABSTAIN")
CONDITIONS = ("parent-summary", "fixed-summary", "source-omitted")
PROJECTS = ("pyjwt", "werkzeug", "mcp-python", "pillow")


def freeze(root: Path = ROOT) -> tuple[dict, dict]:
    raw = (root / PROTOCOL_PATH).read_bytes()
    require(git_blob(raw) == PROTOCOL_GIT_BLOB_SHA1,
            "Phase 5O experiment was changed after pre-inference freeze")
    p = read_json(raw)
    require(p.get("status") ==
            "PHASE5O_PREINFERENCE_FROZEN_FOUR_PROJECT_OPEN_SOURCE_DIAGNOSTIC_NOT_BLIND_GOLD"
            and p.get("schema_version") == 1
            and p.get("intended_intent") == "SECURITY_REVIEW_GENERAL"
            and p.get("model_repository") == MODEL_REPO
            and p.get("model_revision") == MODEL_REVISION
            and p.get("total_questions") == 12 and p.get("cases") == 4
            and p.get("conditions_per_case") == list(CONDITIONS)
            and p.get("truth_distribution") == {"A": 4, "B": 4, "ABSTAIN": 4}
            and p.get("upstream_source_selection_git_blob_sha1") == SOURCE_GIT_BLOB_SHA1
            and p.get("generation_max_new_tokens") == 12
            and p.get("max_input_tokens") == 1024
            and p.get("generate_do_sample") is False
            and p.get("no_new_model_selection_or_prompt_tuning") is True
            and p.get("independent_appsec_gold_labels") == 0
            and p.get("external_developer_adoption") == 0
            and p.get("eligible_anjoman_new_rows") == 0
            and p.get("network_registered_evaluator") is False
            and p.get("official_h2_submitted") is False,
            "unfrozen or misleading experiment protocol")
    original = (root / SOURCE_PATH).read_bytes()
    require(git_blob(original) == SOURCE_GIT_BLOB_SHA1,
            "original multi-project source selection was changed")
    selection = validate_lock(original)
    require(tuple(c["key"] for c in selection["cases"]) == PROJECTS,
            "source project identities drifted")
    return p, selection


def row_id(project: str, condition: str) -> str:
    return hashlib.sha256(
        ("falsum/phase5o/frozen/"+project+"/"+condition).encode()
    ).hexdigest()[:32]


def prepare(root: Path = ROOT) -> tuple[dict, dict[str, str]]:
    p, manifest = freeze(root)
    rows: list[dict] = []
    expected: dict[str, str] = {}
    for index, case in enumerate(manifest["cases"]):
        swapped = index % 2 == 1
        # Different original version orders stop a naive fixed-parent=A rule
        # from getting every code-present condition correct.
        option_a = case["b"] if swapped else case["a"]
        option_b = case["a"] if swapped else case["b"]
        for condition in CONDITIONS:
            ident = row_id(case["key"], condition)
            if condition == "source-omitted":
                question = (
                    "The particular historical source revision and code/test "
                    "excerpt for "+case["repository"]+" have not been supplied. "
                    "The only topic is "+case["family"]+". Which outcome, if "
                    "either, is established by the evidence given here?"
                )
                expected[ident] = "ABSTAIN"
            else:
                question = (case["question_before"] if
                            condition == "parent-summary" else
                            case["question_after"])
                # Prevent easily reading a parent/fixed answer from role tags.
                # Other behavioral clues remain because the prompt is an
                # intentionally source-described open-book reasoning exercise.
                question = re.sub(r"\b(parent|fixed|fix)\b",
                                  "selected", question, flags=re.IGNORECASE)
                original_answer = ("A" if condition == "parent-summary" else "B")
                expected[ident] = (
                    ("B" if original_answer == "A" else "A")
                    if swapped else original_answer
                )
                require(not re.search(r"\b(parent|fixed|fix)\b", question, re.I),
                        "source role still explicitly leaked")
            user = (
                "Public historical source-summary exercise, not a proof of "
                "a real-world exploit.\n" + question +
                "\n\nA. " + option_a + "\nB. " + option_b +
                "\n\nChoose exactly A, B or ABSTAIN."
            )
            require(120 < len(user) < 3200 and ident not in user,
                    "source question damaged or label leaked")
            rows.append({
                "id": ident,
                "project": case["key"],
                "messages": [
                    {"role": "system", "content": p["model_system_instruction"]},
                    {"role": "user", "content": user},
                ],
                "question_sha256": sha(user.encode()),
            })
    require(len(rows) == 12 and len({r["id"] for r in rows}) == 12
            and Counter(expected.values()) == {"A": 4, "B": 4, "ABSTAIN": 4},
            "source-balanced twelve-task protocol drift")
    return {
        "schema_version": 1,
        "status": STATUS_INPUT,
        "frozen_protocol_git_blob_sha1": PROTOCOL_GIT_BLOB_SHA1,
        "source_selection_git_blob_sha1": SOURCE_GIT_BLOB_SHA1,
        "model_repository": MODEL_REPO,
        "model_revision": MODEL_REVISION,
        "intent": "SECURITY_REVIEW_GENERAL",
        "questions": rows,
        "question_count": 12,
        "distinct_upstream_projects": 4,
        "source_provided_summary_conditions": 8,
        "source_omitted_controls": 4,
        "role_position_counterbalanced": True,
        "reference_labels_included": False,
        "original_source_summary_open_book_not_raw_code": True,
        "independent_expert_gold": 0,
        "external_developer_adoption": False,
        "network_registered_evaluator": False,
        "trained_model_improvement": False,
        "real_model_inference_yet": False,
    }, expected


def validate_prepared(given: dict, original: dict) -> None:
    require(type(given.get("schema_version")) is int and given == original,
            "prepared public prompts or source truth changed")


def controls(expected: dict[str, str]) -> dict:
    guesses = {}
    for mode in ("always-A", "always-B", "always-ABSTAIN", "parent-is-A-and-omit-is-ABSTAIN"):
        result = {}
        for project in PROJECTS:
            for condition in CONDITIONS:
                ident = row_id(project, condition)
                if mode == "parent-is-A-and-omit-is-ABSTAIN":
                    guess = {"parent-summary": "A", "fixed-summary": "B",
                             "source-omitted": "ABSTAIN"}[condition]
                else:
                    guess = mode.removeprefix("always-")
                result[ident] = guess
        guesses[mode] = sum(result[k] == expected[k] for k in expected)
    require(guesses == {
        "always-A": 4, "always-B": 4, "always-ABSTAIN": 4,
        "parent-is-A-and-omit-is-ABSTAIN": 8,
    }, "counterbalanced synthetic baseline changed")
    return guesses


def score_choices(choices: dict[str, str], expected: dict[str, str]) -> dict:
    require(set(choices) == set(expected) and len(choices) == 12
            and all(v in LABELS + ("INVALID",) for v in choices.values()),
            "missing or unknown real model predictions")
    matrix = {
        true: {guess: 0 for guess in LABELS + ("INVALID",)}
        for true in LABELS
    }
    for ident, truth in expected.items():
        matrix[truth][choices[ident]] += 1
    exact = sum(matrix[k][k] for k in LABELS)
    per_class = {k: round(matrix[k][k] / 4, 6) for k in LABELS}
    correct_reversals = 0
    changed_revisions = 0
    omitted_abstentions = 0
    by_project = {}
    for project in PROJECTS:
        a,b,c = (choices[row_id(project, condition)] for condition in CONDITIONS)
        wanted_a, wanted_b = (
            expected[row_id(project, condition)] for condition in CONDITIONS[:2]
        )
        pair_ok = a == wanted_a and b == wanted_b
        changed = a != b and a in ("A", "B") and b in ("A", "B")
        correct_reversals += int(pair_ok)
        changed_revisions += int(changed)
        omitted_abstentions += int(c == "ABSTAIN")
        by_project[project] = {
            "parent_choice": a, "fixed_choice": b,
            "source_omitted_choice": c,
            "exact_parent_fixed_reversal": pair_ok,
            "nonabstaining_source_revision_choice_changed": changed,
            "source_omitted_abstained": c == "ABSTAIN",
        }
    return {
        "questions": 12,
        "source_projects": 4,
        "reference_class_distribution": {"A": 4, "B": 4, "ABSTAIN": 4},
        "confusion_matrix_true_rows_predicted_columns": matrix,
        "exact_source_summary_reference_matches": exact,
        "raw_match_fraction": round(exact / 12, 6),
        "macro_class_recall": round(sum(per_class.values()) / 3, 6),
        "per_class_recall": per_class,
        "correct_complete_parent_fixed_reversals": correct_reversals,
        "nonabstaining_source_revision_choice_changes": changed_revisions,
        "source_omitted_abstentions": omitted_abstentions,
        "unnecessary_abstentions_on_code_present_tasks":
            matrix["A"]["ABSTAIN"] + matrix["B"]["ABSTAIN"],
        "unsupported_confident_guesses_on_missing_source":
            matrix["ABSTAIN"]["A"] + matrix["ABSTAIN"]["B"],
        "invalid_raw_responses": sum(matrix[k]["INVALID"] for k in LABELS),
        "per_project": by_project,
        "synthetic_disclosed_no_model_baseline_matches": controls(expected),
        "independent_expert_gold_labels": 0,
        "statistically_valid_accuracy_or_generalization": False,
    }


def audit(actual: dict, prepared: dict, expected: dict[str, str]) -> dict:
    original, generated_expected = prepare()
    validate_prepared(prepared, original)
    require(expected == generated_expected,
            "scorer answer key differs from frozen original source selection")
    require(isinstance(actual, dict)
            and actual.get("schema_version") == 1
            and actual.get("status") == STATUS_RAW
            and actual.get("model_repository") == MODEL_REPO
            and actual.get("model_revision") == MODEL_REVISION
            and actual.get("frozen_protocol_git_blob_sha1") == PROTOCOL_GIT_BLOB_SHA1
            and actual.get("prepared_prompt_sha256") == sha(canonical_json(prepared))
            and actual.get("pretrained_published_weights_loaded") is True
            and actual.get("greedy_cpu_forward_passes") == 12
            and actual.get("no_training_or_prompt_tuning") is True
            and actual.get("researcher_operated_not_independent_adoption") is True
            and actual.get("source_labels_not_used_in_generation") is True
            and actual.get("network_registered_evaluator") is False
            and actual.get("independent_expert_gold") == 0
            and actual.get("official_h2_entry_submitted") is False,
            "model run envelope conflicts with frozen experiment")
    hashes = actual.get("downloaded_publisher_files_sha256")
    require(isinstance(hashes, dict) and len(hashes) >= 3
            and hashes.get("model.safetensors") == MODEL_SAFETENSORS_SHA256
            and isinstance(hashes.get("config.json"), str)
            and isinstance(hashes.get("tokenizer.json"), str)
            and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                    for v in hashes.values()),
            "original published-model file fingerprint missing")
    predictions = actual.get("predictions")
    require(isinstance(predictions, list) and len(predictions) == 12
            and [x.get("id") for x in predictions] ==
            [x["id"] for x in prepared["questions"]],
            "model did not answer the exact twelve precommitted questions")
    for row in predictions:
        require(isinstance(row, dict)
                and set(row) == {
                    "id", "raw_completion", "parsed_choice",
                    "input_tokens", "output_tokens",
                }
                and isinstance(row["raw_completion"], str)
                and len(row["raw_completion"]) < 2000
                and row["parsed_choice"] == parse_choice(row["raw_completion"])
                and type(row["input_tokens"]) is int
                and 0 < row["input_tokens"] <= 1024
                and type(row["output_tokens"]) is int
                and 0 < row["output_tokens"] <= 12,
                "unverifiable or modified model response")
    scored = score_choices({x["id"]: x["parsed_choice"] for x in predictions}, expected)
    return {
        "schema_version": 1, "status": STATUS_RESULT,
        "intent": "SECURITY_REVIEW_GENERAL",
        "model_repository": MODEL_REPO, "model_revision": MODEL_REVISION,
        "frozen_protocol_git_blob_sha1": PROTOCOL_GIT_BLOB_SHA1,
        "prepared_prompt_sha256": sha(canonical_json(prepared)),
        "original_github_run_url": actual.get("github_run_url"),
        "downloaded_publisher_files_sha256": hashes,
        "model_inference_claim_requires_github_run_artifact_verification": True,
        "researcher_operated_published_model_not_external_adoption": True,
        "source_summary_open_book_not_raw_source_code_reading": True,
        "source_roles_masked_but_facts_still_leading": True,
        "test_set_known_public_not_pretraining_disjoint": True,
        "score": scored, "original_raw_outputs": predictions,
        "registered_telegraph_evaluator": False,
        "independent_expert_gold_labels": 0,
        "real_independent_external_developer_adoption": False,
        "trained_model_improvement_proven": False,
        "anjoman_eligible_new_rows": 0,
        "official_h2_entry_submitted": False,
        "limitations": (
            "Researcher-selected published historical source summaries from four projects; "
            "some prompts describe the distinguishing code behavior, so this is a diagnostic "
            "of evidence-conditioned output, not blind security code analysis. No outside "
            "expert adjudication, actual customer integration, holdout, network scorer or "
            "generalization evidence. Exact real weights/outputs must be verified in Actions."
        ),
    }


def actual_inference(prepared: dict) -> dict:
    """Load immutable public checkpoint and execute every precommitted input."""
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoModelForCausalLM, AutoTokenizer

    frozen, _ = freeze()
    location = Path(snapshot_download(
        repo_id=MODEL_REPO, revision=MODEL_REVISION,
        allow_patterns=list(WHITELIST), max_workers=2,
    ))
    hashes = {}
    for file in sorted(location.iterdir()):
        if file.is_file() and (
            file.name in (
                "config.json", "generation_config.json", "tokenizer.json",
                "tokenizer_config.json", "special_tokens_map.json",
                "vocab.json", "merges.txt", "model.safetensors",
                "model.safetensors.index.json",
            ) or re.fullmatch(r"model-[0-9]+-of-[0-9]+\.safetensors", file.name)
        ):
            hashes[file.name] = get_sha256_file(file)
    require(hashes.get("model.safetensors") == MODEL_SAFETENSORS_SHA256
            and "config.json" in hashes and "tokenizer.json" in hashes,
            "publisher weights do not match actual verified Phase 5N checkpoint")
    torch.set_num_threads(2)
    model = AutoModelForCausalLM.from_pretrained(
        str(location), trust_remote_code=False, local_files_only=True,
        use_safetensors=True, torch_dtype=torch.float32,
    ).eval()
    tokenizer = AutoTokenizer.from_pretrained(
        str(location), trust_remote_code=False, local_files_only=True,
    )
    records = []
    for row in prepared["questions"]:
        inputs = tokenizer.apply_chat_template(
            row["messages"], add_generation_prompt=True, return_tensors="pt",
        )
        n = int(inputs.shape[-1])
        require(0 < n <= frozen["max_input_tokens"],
                "original prompt exceeds frozen token cap; no silent clipping")
        with torch.inference_mode():
            output = model.generate(
                inputs, max_new_tokens=frozen["generation_max_new_tokens"],
                do_sample=False, pad_token_id=tokenizer.eos_token_id,
            )
        produced = output[0, inputs.shape[-1]:]
        raw = tokenizer.decode(produced, skip_special_tokens=True)
        records.append({
            "id": row["id"], "raw_completion": raw,
            "parsed_choice": parse_choice(raw),
            "input_tokens": n, "output_tokens": int(produced.numel()),
        })
    require(len(records) == 12, "partial inference forbidden")
    return {
        "schema_version": 1, "status": STATUS_RAW,
        "model_repository": MODEL_REPO, "model_revision": MODEL_REVISION,
        "frozen_protocol_git_blob_sha1": PROTOCOL_GIT_BLOB_SHA1,
        "prepared_prompt_sha256": sha(canonical_json(prepared)),
        "downloaded_publisher_files_sha256": hashes,
        "pretrained_published_weights_loaded": True,
        "greedy_cpu_forward_passes": 12,
        "no_training_or_prompt_tuning": True,
        "source_labels_not_used_in_generation": True,
        "researcher_operated_not_independent_adoption": True,
        "network_registered_evaluator": False,
        "independent_expert_gold": 0,
        "official_h2_entry_submitted": False,
        "github_run_url": (
            "https://github.com/Iniwura/falsum/actions/runs/" + os.environ["GITHUB_RUN_ID"]
            if "GITHUB_RUN_ID" in os.environ else None
        ),
        "predictions": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Actual Qwen CPU inference on four open-book upstream security source summaries")
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("prepare").add_argument("--out", type=Path, required=True)
    run = commands.add_parser("execute")
    run.add_argument("--inputs", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    review = commands.add_parser("audit")
    review.add_argument("--inputs", type=Path, required=True)
    review.add_argument("--actual", type=Path, required=True)
    review.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        prepared, expected = prepare()
        if args.mode == "prepare":
            write_once(args.out, prepared)
            print(json.dumps({"prepared_public_questions": 12, "projects": 4,
                              "real_inference_performed": False}))
        else:
            given = read_json(args.inputs.read_bytes())
            validate_prepared(given, prepared)
            if args.mode == "execute":
                out = actual_inference(prepared)
                write_once(args.out, out)
                print(json.dumps({"immutable_model_revision": MODEL_REVISION,
                                  "raw_model_predictions": [r["parsed_choice"]
                                                            for r in out["predictions"]]}))
            else:
                actual = read_json(args.actual.read_bytes())
                result = audit(actual, prepared, expected)
                write_once(args.out, result)
                print(json.dumps({"exact_matches": result["score"]["exact_source_summary_reference_matches"],
                                  "correct_reversals": result["score"]["correct_complete_parent_fixed_reversals"],
                                  "independent_gold": 0}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, DiagnosticError, UnicodeError) as exc:
        parser.exit(1, "PHASE5O PUBLIC FOUR PROJECT MODEL EXPERIMENT FAILED CLOSED: "
                    + str(exc)[:270] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
