"""Evaluate order sensitivity in a public scanner scorer, not scanner accuracy.

Upstream RealVuln (Apache-2.0, Kolega) is fetched at immutable Git identities.
All findings and labels remain outside this repository. Only aggregates leave CI.
"""
import argparse
from collections import Counter
from dataclasses import asdict
import importlib
import json
from pathlib import Path
import random
import sys
import tempfile

from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require
from . import phase5ak_external_label_baselines as historical

LOCK = "4c433b63641a16cd77d6f5f5514683f0caa19fea"
PROTOCOL = ROOT / "data/phase5az-realvuln-protocol.json"


def canonical_findings(findings):
    return sorted(findings, key=lambda f: json.dumps(asdict(f), sort_keys=True,
                                                    ensure_ascii=True))


def maximum_pairs(left, right, compatible):
    """Maximum cardinality bipartite matching; deterministic on sorted inputs."""
    adjacency = {i: [j for j in range(len(right)) if compatible(f, right[j])]
                 for i, f in enumerate(left)}
    owner = {}

    def augment(i, seen):
        for j in adjacency[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in owner or augment(owner[j], seen):
                owner[j] = i
                return True
        return False

    for i in sorted(adjacency, key=lambda i: (len(adjacency[i]), i)):
        augment(i, set())
    return {i: j for j, i in owner.items()}


def optimal_positive(findings, gt, matcher):
    f = canonical_findings(findings)
    entries = sorted(gt["findings"], key=lambda e: e["id"])
    require(len({e["id"] for e in entries}) == len(entries), "duplicate GT IDs")
    scored = [e for e in entries if not matcher.is_non_scoring(e)]
    ns = [e for e in entries if matcher.is_non_scoring(e)]
    positives = [e for e in scored if e["is_vulnerable"]]
    traps = [e for e in scored if not e["is_vulnerable"]]
    p = maximum_pairs(f, positives, matcher._finding_matches_gt)
    leftover = [f[i] for i in range(len(f)) if i not in p]
    t = maximum_pairs(leftover, traps, matcher._finding_matches_gt)
    withheld = sum(matcher._first_non_scoring_hit(item, ns) is not None
                   for i, item in enumerate(leftover) if i not in t)
    return {"TP": len(p), "FN": len(positives) - len(p),
            "FP": len(leftover) - withheld, "TN": len(traps) - len(t),
            "NS": withheld + len(ns)}


def count_matches(results):
    c = Counter(r.classification for r in results)
    return {k: c[k] for k in ("TP", "FN", "FP", "TN", "NS")}


def f3(c):
    numerator = 10 * c["TP"]
    denom = numerator + 9 * c["FN"] + c["FP"]
    return round(100 * numerator / denom, 6) if denom else 0.0


def audit():
    raw = PROTOCOL.read_bytes()
    require(git_blob(raw) == LOCK, "frozen protocol changed")
    spec = parse(raw)
    sources = historical.load({"sources": [
        dict(key=path, repo=spec["source"], commit=spec["commit"],
             path=path, blob=blob) for path, blob in spec["files"].items()
    ]})
    # Execute only the three audited pinned parser/matcher modules, not target code.
    with tempfile.TemporaryDirectory(prefix="falsum-realvuln-") as tmp:
        root = Path(tmp)
        for name in ("parsers", "scorer"):
            (root / name).mkdir()
            (root / name / "__init__.py").write_text("", encoding="utf-8")
        for path, data in sources.items():
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        sys.path.insert(0, tmp)
        try:
            matcher = importlib.import_module("scorer.matcher")
            parser = importlib.import_module("parsers.semgrep")
            require(Path(matcher.__file__).is_relative_to(root), "wrong matcher module")
            require(Path(parser.__file__).is_relative_to(root), "wrong parser module")
            manifest = parse(sources["benchmark-manifest.json"])
            rows = []
            for target in spec["targets"]:
                gt = matcher.load_ground_truth(str(root / "ground-truth" / target / "ground-truth.json"))
                entry = manifest["repos"][target]
                require(gt["commit_sha"] == entry["commit_sha"], "target commit mismatch")
                require(sum(e["is_vulnerable"] and not matcher.is_non_scoring(e)
                            for e in gt["findings"]) == entry["vulnerable_findings"], "positive census mismatch")
                require(sum(not e["is_vulnerable"] and not matcher.is_non_scoring(e)
                            for e in gt["findings"]) == entry["false_positive_traps"], "trap census mismatch")
                for scanner in spec["scanners"]:
                    path = root / "scan-results" / target / scanner / "results.json"
                    data = parse(path.read_bytes())
                    require(type(data.get("results")) is list, "missing scan results")
                    findings = parser.SemgrepParser(scanner).parse(str(path))
                    original = count_matches(matcher.match_findings(findings, gt))
                    sorted_gt = dict(gt, findings=sorted(gt["findings"], key=lambda e: e["id"]))
                    sorted_greedy = count_matches(matcher.match_findings(canonical_findings(findings), sorted_gt))
                    candidate = optimal_positive(findings, gt, matcher)
                    variants = [original]
                    for seed in spec["seeds"]:
                        rng = random.Random(seed)
                        fs, es = list(findings), list(gt["findings"])
                        rng.shuffle(fs)
                        rng.shuffle(es)
                        gs = dict(gt, findings=es)
                        variants.append(count_matches(matcher.match_findings(fs, gs)))
                        require(optimal_positive(fs, gs, matcher) == candidate,
                                "candidate order dependence")
                        cg = count_matches(matcher.match_findings(canonical_findings(fs),
                                             dict(gs, findings=sorted(es, key=lambda e: e["id"]))))
                        require(cg == sorted_greedy, "sorted control order dependence")
                    require(candidate["TP"] >= max(v["TP"] for v in variants + [sorted_greedy]),
                            "maximum-positive matching lost credit")
                    rows.append(dict(target=target, scanner=scanner,
                                     normalized_findings=len(findings),
                                     original=original, sorted_greedy=sorted_greedy,
                                     maximum_positive=candidate,
                                     original_f3=f3(original),
                                     sorted_greedy_f3=f3(sorted_greedy),
                                     maximum_positive_f3=f3(candidate),
                                     original_variants=len({tuple(sorted(v.items())) for v in variants}),
                                     original_tp_min=min(v["TP"] for v in variants),
                                     original_tp_max=max(v["TP"] for v in variants),
                                     original_f3_min=min(f3(v) for v in variants),
                                     original_f3_max=max(f3(v) for v in variants)))
            require(len(rows) == 10, "incomplete report census")
        finally:
            sys.path.remove(tmp)
    summary = dict(reports=len(rows), findings=sum(r["normalized_findings"] for r in rows),
                   order_sensitive=sum(r["original_variants"] > 1 for r in rows),
                   candidate_order_sensitive=0,
                   more_tp_than_original=sum(r["maximum_positive"]["TP"] > r["original"]["TP"] for r in rows),
                   more_tp_than_sorted_greedy=sum(r["maximum_positive"]["TP"] > r["sorted_greedy"]["TP"] for r in rows),
                   f3_higher_than_original=sum(r["maximum_positive_f3"] > r["original_f3"] for r in rows),
                   f3_lower_than_original=sum(r["maximum_positive_f3"] < r["original_f3"] for r in rows),
                   f3_higher_than_sorted=sum(r["maximum_positive_f3"] > r["sorted_greedy_f3"] for r in rows),
                   f3_lower_than_sorted=sum(r["maximum_positive_f3"] < r["sorted_greedy_f3"] for r in rows))
    return dict(source=spec["source"], commit=spec["commit"], protocol_blob=LOCK,
                summary=summary, reports=rows, selection=spec["selection"],
                semantic_accuracy=False, independent_adoption=False,
                network_ranking_improvement=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    report = audit()
    with a.out.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps(report["summary"], sort_keys=True))
    for row in report["reports"]:
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
