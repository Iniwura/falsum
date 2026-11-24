"""Offline judge view of recorded CI aggregates, never a live evaluator."""
from html import escape
import json
from pathlib import Path
from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require, protocol
from .phase5ak_external_label_baselines import PROTOCOL, LOCK

RECORD = "evidence/phase5am-2026-11-24-recorded-application-aggregates.json"
BLOB = "977203cdb8d24475834aae68d0d94afef5e74bc3"
TEMPLATE = ROOT / "src/falsum/templates/phase5am_application_evidence.html"


def read_validated(root=ROOT):
    raw = (root / RECORD).read_bytes()
    require(git_blob(raw) == BLOB, "recorded application aggregate changed")
    report = parse(raw)
    aj = protocol(root)
    scale_raw = (root / PROTOCOL).read_bytes()
    require(git_blob(scale_raw) == LOCK, "scale protocol changed")
    ak = parse(scale_raw)
    cross = report["cross_app"]["aggregate"]
    scale = report["scale"]["aggregate"]
    require(report["status"] == "RECORDED_CI_AGGREGATE_NOT_LIVE_EVALUATION"
            and report["schema_version"] == 1, "wrong record type")
    require(cross["gig_planted"] == aj["gig"]["planted"]
            and cross["gig_audited"] == aj["gig"]["audited"]
            and cross["truvian_contradictions"] == aj["truvian"]["expected_explicit_no_evidence_contradiction_count"]
            and cross["original_git_sources_authenticated"] == len(aj["sources"]),
            "recorded cross-app aggregate disagrees")
    require(scale == ak["expected"], "recorded scale aggregate disagrees")
    require(set(report["limits"]) == {
        "security_clearance_granted", "independent_adoption_proved",
        "independent_expert_gold_proved", "registered_network_evaluator",
        "network_ranking_improvement_proved", "live_settlement_verified",
        "live_inference", "better_than_verdict_baseline", "blind_holdout"
    } and all(v is False for v in report["limits"].values()), "claim boundary changed")
    for key, run, job, artifact, digest in (
        ("cross_app", 45356083445, 138314253994, 14902790850,
         "sha256:45f3df543b674e1ec9f811bdec8f31c22697d7887d06cee32c13b05908b3427b"),
        ("scale", 45356819921, 138316636056, 14901884473,
         "sha256:61be36e839f1a80d2196d59cd6b2b1cf956a7c9c599957f9f08427e00a5982de"),
    ):
        item = report[key]
        require((item["run_id"], item["job_id"], item["artifact_id"], item["artifact_sha256"])
                == (run, job, artifact, digest), "original run identity changed")
    return report


def row(label, stats, population):
    # Missing keys are zero counts in Counter's serialized sparse result.
    parts = [stats.get(population + ":" + x, 0) for x in ("FLAG", "PASS", "UNKNOWN")]
    return '<tr><th scope="row">' + escape(label) + '</th>' + "".join(
        '<td>' + str(x) + '</td>' for x in parts) + '</tr>'


def render(report, template):
    scale = report["scale"]["aggregate"]
    metrics = scale["latest_metrics"]
    names = [("Count only", "count_only"), ("Verdict only", "verdict_only"),
             ("Strict agreement", "strict_agreement"), ("FALSUM policy", "falsum_consumer")]
    slots = {
        "__VULNERABLE_ROWS__": "".join(row(label, metrics[key], "vulnerable") for label, key in names),
        "__AUDITED_ROWS__": "".join(row(label, metrics[key], "audited") for label, key in names),
        "__NO_HINT_ROWS__": "".join(row(label, scale[key], "vulnerable") for label, key in
                                  [("Count only", "no_hint_count_only"), ("FALSUM policy", "no_hint_falsum_consumer")]),
    }
    for slot, value in slots.items():
        require(template.count(slot) == 1, "invalid template slot")
        template = template.replace(slot, value)
    return template


def write(out_dir: Path):
    report = read_validated()
    html = render(report, TEMPLATE.read_text(encoding="utf-8"))
    out_dir.mkdir(parents=False, exist_ok=False)
    (out_dir / "index.html").write_text(html, encoding="utf-8", newline="\n")
    with (out_dir / "RECORDED-APPLICATION-AGGREGATES.json").open("x", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    return report
