"""Phase 3X harder, source-grounded internal diagnostic questions.

The source functions are genuinely executed in separate upstream-pinned probes.
This builder deliberately emits NO accepted labels, training pairs, network
evaluation rows or independent judge scores. These are PUBLIC RESEARCH examples
from only two previously known libraries, not a blind holdout.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

STATUS = "PHASE3X_INTERNAL_SOURCE_COUNTERFACTUAL_DIAGNOSTICS_UNADJUDICATED"
AXIOS_STATUS = "SOURCE_EXECUTED_AXIOS_TARGETED_BASEURL_COUNTERFACTUAL"
DJANGO_STATUS = "SOURCE_EXECUTED_DJANGO_INT_COMMA_SAFE_LONG_INPUT_COUNTERFACTUAL"

TARGET_ORIGIN = "https://other.example"
BASE_ORIGIN = "https://allowed.example"


def validate_report(axios: dict, django: dict) -> None:
    if (
        axios.get("schema_version") != 1
        or axios.get("status") != AXIOS_STATUS
        or axios.get("parent_commit") != "8603e677c09fb81bd106999c194308dd230bc596"
        or axios.get("fixed_commit") != "02c3c69ced0f8fd86407c23203835892313d7fde"
        or axios.get("primary_source_blobs_verified") is not True
        or axios.get("helper_source_blobs_verified") is not True
        or axios.get("full_axios_client_or_network_execution") is not False
        or axios.get("only_real_pinned_buildFullPath_helper_executed") is not True
        or axios.get("tested_scenarios") != 6
        or axios.get("changed_origin_cases") != 2
        or len(axios.get("scenarios", [])) != 6
    ):
        raise ValueError("Axios report missing original verified real source execution")
    rows = {r.get("case"): r for r in axios["scenarios"]}
    if len(rows) != 6 or len(set(rows)) != 6:
        raise ValueError("Axios scenario identities changed")
    for r in axios["scenarios"]:
        if r.get("parent_origin") not in (TARGET_ORIGIN, BASE_ORIGIN):
            raise ValueError("Unexpected Axios parent origin")
        if r.get("patched_origin") not in (TARGET_ORIGIN, BASE_ORIGIN):
            raise ValueError("Unexpected Axios patched origin")
        if r.get("case") in ("configured baseURL + absolute target + strict false",
                             "configured baseURL + protocol-relative target + strict false"):
            if (r["parent_origin"], r["patched_origin"]) != (TARGET_ORIGIN, BASE_ORIGIN):
                raise ValueError("Expected configured strict change not observed")
        elif r["parent_origin"] != r["patched_origin"]:
            raise ValueError("Unverified additional Axios destination change")
    if (
        django.get("schema_version") != 1
        or django.get("status") != DJANGO_STATUS
        or django.get("parent_commit") != "9cefdfc43f0bae696b56fa5a0bf22346f85affff"
        or django.get("fixed_commit") != "55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9"
        or django.get("primary_source_blobs_verified") is not True
        or django.get("actual_pinned_function_extracted_and_executed") is not True
        or django.get("full_installed_django_runtime") is not False
        or django.get("http_server_or_production_dos_executed") is not False
        or django.get("localization_disabled_for_isolation") is not True
        or len(django.get("cases", [])) != 3
        or [c.get("digits") for c in django["cases"]] != [13, 12, 3601]
        or django["cases"][0]["before"]["outcome"] != "returned"
        or django["cases"][0]["after"]["outcome"] != "returned"
        or django["cases"][0]["before_matches_grouping_oracle"] is not True
        or django["cases"][0]["after_matches_grouping_oracle"] is not True
        or django["cases"][1]["before"]["outcome"] != "returned"
        or django["cases"][1]["after"]["outcome"] != "returned"
        or django["cases"][1]["before"]["starts_with_comma"] is not False
        or django["cases"][1]["after"]["starts_with_comma"] is not True
        or django["cases"][1]["before_matches_grouping_oracle"] is not True
        or django["cases"][1]["after_matches_grouping_oracle"] is not False
        or django["cases"][2]["before"]["outcome"] != "RecursionError"
        or django["cases"][2]["after"]["outcome"] != "returned"
        or django["cases"][2]["after_matches_grouping_oracle"] is not True
        or django.get("patched_12_digit_localization_disabled_leading_comma_observed") is not True
    ):
        raise ValueError("Django report lacks verified bounded pre/post source behavior")


def build(axios: dict, django: dict) -> dict:
    validate_report(axios, django)
    cases = []
    candidates_axios = [
        {
            "id": "A",
            "text": "The isolated URL helper produces a result under the supplied target origin."
        },
        {
            "id": "B",
            "text": "The isolated URL helper produces a result under the configured base origin."
        },
    ]
    chosen = [
        s for s in axios["scenarios"]
        if s["case"] in (
            "configured baseURL + absolute target + strict false",
            "configured baseURL + absolute target + default option",
            "configured baseURL + absolute target + explicit true",
            "configured baseURL + protocol-relative target + strict false",
        )
    ]
    if len(chosen) != 4:
        raise ValueError("Four intentionally comparable Axios source conditions missing")
    for scenario in chosen:
        for version, field in (("parent", "parent_origin"), ("patched", "patched_origin")):
            origin = scenario[field]
            expected = "A" if origin == TARGET_ORIGIN else "B"
            cases.append({
                "id": "axios-" + str(len(cases) + 1).zfill(2),
                "family": "axios-buildFullPath",
                "upstream_version": version,
                "changed_fact": "source revision plus allowAbsoluteUrls setting",
                "question": ("For the pinned " + version + " helper, with baseURL=" +
                             json.dumps(scenario["configured_baseURL"]) +
                             ", requestedURL=" + json.dumps(scenario["requested_target"]) +
                             ", allowAbsoluteUrls=" + json.dumps(scenario["allowAbsoluteUrls"]) +
                             ", which result is supported by the *source-executed helper*?"),
                "candidate_answers": candidates_axios,
                "research_source_expected": expected,
                "observed_output": scenario[version + "_result"],
                "runtime_context": scenario["case"],
                "independent_expert_label": None,
                "training_authorized": False
            })
    candidates_django = [
        {"id":"A", "text":"The isolated formatter returns the correctly comma-grouped value for this input."},
        {"id":"B", "text":"The isolated formatter raises a recursion error before producing a value."}
    ]
    for item in django["cases"]:
        for version, field in (("parent", "before"), ("patched", "after")):
            output = item[field]["outcome"]
            expected = "A" if output == "returned" else "B"
            cases.append({
                "id": "django-" + str(item["digits"]) + "-" + version,
                "family": "django-intcomma",
                "upstream_version": version,
                "changed_fact": "pinned source revision and fixed ASCII-string input length",
                "question": ("For the pinned " + version + " Django intcomma *function only*, "
                             "with use_l10n=False and a " + str(item["digits"]) +
                             "-digit ASCII numeric string, what did the bounded source test observe?"),
                "candidate_answers": candidates_django,
                "research_source_expected": expected,
                "observed_output": output,
                "runtime_context": str(item["digits"]) + " digits",
                "independent_expert_label": None,
                "training_authorized": False
            })
    # A separate, observable correctness mismatch: with localization disabled,
    # this exact pinned fixed source revision prefixes 12-digit output with a comma.
    # This is NOT an installed-Django release claim and is not the recursion test.
    for version, field in (("parent", "before"), ("patched", "after")):
        observed = django["cases"][1][field]["starts_with_comma"]
        cases.append({
            "id": "django-12-digit-leading-comma-" + version,
            "family": "django-intcomma",
            "upstream_version": version,
            "changed_fact": "source revision, same 12-digit input, localization disabled",
            "question": ("For the pinned " + version + " intcomma source function with "
                         "use_l10n=False, what was the first character "
                         "of the returned, grouped 12-digit string?"),
            "candidate_answers": [
                {"id":"A", "text":"The output begins with the first digit of the original number."},
                {"id":"B", "text":"The output begins with a separator before its first digit."}
            ],
            "research_source_expected": "B" if observed else "A",
            "observed_first_character_is_comma": observed,
            "independent_expert_label":None,
            "training_authorized":False
        })
    # An ABSTAIN is appropriate when the code probe doesn't establish claims
    # about the real deployed system. Neither alternative is evidence-backed.
    cases.extend([
        {
            "id":"axios-deployment-unsupported",
            "family":"axios-buildFullPath",
            "upstream_version":"unknown production version",
            "question":"Does the local buildFullPath source-function test prove that a production Axios client sent a real external request?",
            "candidate_answers":[
                {"id":"A","text":"Yes: it demonstrates a real external HTTP request was dispatched."},
                {"id":"B","text":"No: it proves the production network request could never be dispatched."}
            ],
            "research_source_expected":"ABSTAIN",
            "reason":"The isolated helper neither sends HTTP nor certifies the production network behavior.",
            "independent_expert_label":None, "training_authorized":False
        },
        {
            "id":"django-deployment-unsupported",
            "family":"django-intcomma",
            "upstream_version":"unknown deployment",
            "question":"Does the bounded isolated intcomma function test establish a customer-facing denial of service?",
            "candidate_answers":[
                {"id":"A","text":"Yes: it proves a real web service was unavailable to customers."},
                {"id":"B","text":"No: it proves no deployment could have been affected."}
            ],
            "research_source_expected":"ABSTAIN",
            "reason":"Only one source function was executed in a sandbox; application reachability and limits were not tested.",
            "independent_expert_label":None, "training_authorized":False
        }
    ])
    return {
        "schema_version":1,
        "status":STATUS,
        "source_families":2,
        "question_count":len(cases),
        "known_not_blind":True,
        "candidate_responses_researcher_authored":True,
        "model_answers_or_scores_newly_generated":False,
        "actual_model_scoring_run":False,
        "independent_human_labels":0,
        "trainable_pairs":[],
        "registered_evaluator":False,
        "network_eligible":False,
        "cases":cases,
        "notice":"These are harder INTERNAL source-derived diagnostics, not new verified expert labels, network contributions, a blind holdout, or evidence that any evaluator has improved."
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--axios", type=Path, required=True)
    parser.add_argument("--django", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args=parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error("Refuse to overwrite previous diagnostic evidence")
    report = build(json.loads(args.axios.read_text()), json.loads(args.django.read_text()))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({"status":STATUS,"diagnostic_examples":len(report["cases"]),
                      "accepted_independent_labels":0,"actual_model_scoring":False},indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
