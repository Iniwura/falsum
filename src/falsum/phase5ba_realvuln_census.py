"""Disjoint expansion of the frozen RealVuln scorer comparison.

Only immutable external scorer modules already reviewed in Phase 5AZ execute.
No target application code, scanner invocation, or credentials.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
from urllib.request import urlopen

from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require
from . import phase5az_realvuln_order_invariance as pilot

LOCK = "fdbabeabdc2b2140ec077b5a3de8b95ac1268aa0"
PROTOCOL = ROOT / "data/phase5ba-realvuln-census-protocol.json"
MAX_BYTES = 8_000_000


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   timeout=180)


def target_ids(manifest, excluded):
    return sorted(k for k, v in manifest["repos"].items()
                  if v["language"] == "python" and v["authorship"] == "human_authored"
                  and k not in excluded)


def fetch(spec, path, blob):
    url = "https://raw.githubusercontent.com/" + spec["source"] + "/" + spec["commit"] + "/" + path
    with urlopen(url, timeout=60) as response:
        raw = response.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES and git_blob(raw) == blob,
            "immutable source mismatch or size limit: " + path)
    return raw


def compare(findings, gt, matcher, seeds):
    original = pilot.count_matches(matcher.match_findings(findings, gt))
    def sorted_greedy(fs, es):
        return pilot.count_matches(matcher.match_findings(
            pilot.canonical_findings(fs), dict(gt, findings=sorted(es, key=lambda e: e["id"]))))
    sorted_result = sorted_greedy(findings, gt["findings"])
    candidate = pilot.optimal_positive(findings, gt, matcher)
    variants = [original]
    for seed in seeds:
        rng = random.Random(seed)
        fs, es = list(findings), list(gt["findings"])
        rng.shuffle(fs)
        rng.shuffle(es)
        gs = dict(gt, findings=es)
        variants.append(pilot.count_matches(matcher.match_findings(fs, gs)))
        require(pilot.optimal_positive(fs, gs, matcher) == candidate, "candidate order dependence")
        require(sorted_greedy(fs, es) == sorted_result, "sorted baseline order dependence")
    require(candidate["TP"] >= max(v["TP"] for v in variants + [sorted_result]),
            "maximum matching lost positive credit")
    return dict(findings=len(findings), original=original, sorted_greedy=sorted_result,
                maximum_positive=candidate, original_f3=pilot.f3(original),
                sorted_f3=pilot.f3(sorted_result), maximum_f3=pilot.f3(candidate),
                original_f3_min=min(pilot.f3(v) for v in variants),
                original_f3_max=max(pilot.f3(v) for v in variants),
                order_sensitive=len({tuple(sorted(v.items())) for v in variants}) > 1)


def audit():
    raw = PROTOCOL.read_bytes()
    require(git_blob(raw) == LOCK, "frozen expansion protocol changed")
    spec = parse(raw)
    old_raw = pilot.PROTOCOL.read_bytes()
    require(git_blob(old_raw) == spec["previous_protocol_blob"] == pilot.LOCK,
            "pilot protocol changed")
    old = parse(old_raw)
    require(old["commit"] == spec["commit"] and old["source"] == spec["source"],
            "upstream identity changed")
    with tempfile.TemporaryDirectory(prefix="realvuln-census-") as tmp:
        root = Path(tmp)
        tree = root / "tree"
        tree.mkdir()
        git(tree, "init", "--bare", "-q")
        git(tree, "remote", "add", "origin", "https://github.com/" + spec["source"] + ".git")
        git(tree, "config", "remote.origin.promisor", "true")
        git(tree, "config", "remote.origin.partialclonefilter", "blob:none")
        git(tree, "fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin", spec["commit"])
        require(git(tree, "rev-parse", "FETCH_HEAD").decode().strip() == spec["commit"], "commit mismatch")
        entries = {}
        for line in git(tree, "ls-tree", "-r", "-z", spec["commit"]).split(b"\0"):
            if not line:
                continue
            meta, path = line.decode("utf-8").split("\t", 1)
            mode, kind, blob = meta.split()
            if kind == "blob" and mode in ("100644", "100755"):
                entries[path] = blob
        for path in ("benchmark-manifest.json", "parsers/base.py", "parsers/semgrep.py", "scorer/matcher.py"):
            require(entries.get(path) == old["files"][path], "previously audited file changed")
        manifest = parse(fetch(spec, "benchmark-manifest.json", spec["manifest_blob"]))
        targets = target_ids(manifest, old["targets"])
        require(len(targets) == spec["expected_targets"], "target census changed")
        paths = ["parsers/base.py", "parsers/semgrep.py", "scorer/matcher.py"]
        missing = []
        for target in targets:
            paths.append("ground-truth/" + target + "/ground-truth.json")
            for scanner in spec["scanners"]:
                path = "scan-results/" + target + "/" + scanner + "/results.json"
                if path not in entries:
                    missing.append(dict(target=target, scanner=scanner, reason="ABSENT_FROM_PINNED_TREE"))
                else:
                    paths.append(path)
        require(all(p in entries for p in paths), "missing required source")
        def download(path):
            dest = root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(fetch(spec, path, entries[path]))
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(download, paths))
        for name in ("parsers", "scorer"):
            (root / name / "__init__.py").write_text("", encoding="utf-8")
        sys.path.insert(0, tmp)
        try:
            matcher = importlib.import_module("scorer.matcher")
            parser = importlib.import_module("parsers.semgrep")
            require(Path(matcher.__file__).is_relative_to(root) and
                    Path(parser.__file__).is_relative_to(root), "wrong external modules")
            rows = []
            for target in targets:
                gt = matcher.load_ground_truth(str(root / "ground-truth" / target / "ground-truth.json"))
                entry = manifest["repos"][target]
                require(gt["commit_sha"] == entry["commit_sha"], "target revision mismatch")
                require(sum(e["is_vulnerable"] and not matcher.is_non_scoring(e) for e in gt["findings"])
                        == entry["vulnerable_findings"], "positive census mismatch")
                require(sum(not e["is_vulnerable"] and not matcher.is_non_scoring(e) for e in gt["findings"])
                        == entry["false_positive_traps"], "trap census mismatch")
                for scanner in spec["scanners"]:
                    path = root / "scan-results" / target / scanner / "results.json"
                    if not path.is_file():
                        continue
                    require(type(parse(path.read_bytes()).get("results")) is list, "invalid result schema")
                    findings = parser.SemgrepParser(scanner).parse(str(path))
                    rows.append(dict(target=target, scanner=scanner,
                                     **compare(findings, gt, matcher, spec["seeds"])))
        finally:
            sys.path.remove(tmp)
        require(len(rows) + len(missing) == spec["expected_slots"], "incomplete scanner census")
    summary = dict(targets=len(targets), reports=len(rows), missing=len(missing),
                   findings=sum(r["findings"] for r in rows),
                   order_sensitive=sum(r["order_sensitive"] for r in rows),
                   candidate_order_sensitive=0,
                   more_tp_than_original=sum(r["maximum_positive"]["TP"] > r["original"]["TP"] for r in rows),
                   more_tp_than_sorted=sum(r["maximum_positive"]["TP"] > r["sorted_greedy"]["TP"] for r in rows),
                   f3_higher_than_sorted=sum(r["maximum_f3"] > r["sorted_f3"] for r in rows),
                   f3_lower_than_sorted=sum(r["maximum_f3"] < r["sorted_f3"] for r in rows),
                   f3_higher_than_original=sum(r["maximum_f3"] > r["original_f3"] for r in rows),
                   f3_lower_than_original=sum(r["maximum_f3"] < r["original_f3"] for r in rows))
    return dict(summary=summary, reports=rows, missing=missing, protocol_blob=LOCK,
                source_commit=spec["commit"], source_blobs={p: entries[p] for p in paths},
                selection=spec["selection"], independent_adoption=False,
                network_ranking_improvement=False, scanner_accuracy_improvement=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    report = audit()
    with args.out.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True, allow_nan=False)
        f.write("\n")
    print(json.dumps(report["summary"], sort_keys=True))
    for row in report["reports"]:
        print(json.dumps(row, sort_keys=True))
    print(json.dumps({"missing": report["missing"]}, sort_keys=True))


if __name__ == "__main__":
    main()
