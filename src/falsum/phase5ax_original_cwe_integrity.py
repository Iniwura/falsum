"""Evaluate explicit CWE identifier/title integrity on real published answers.

A registry title conflict is not a finding about contract safety or semantic accuracy.
The same registry and answer text are supplied to both checks.
"""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import unicodedata
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET
import zipfile

from .phase5aj_cross_app_evidence import ROOT, git_blob, parse, require
from . import phase5ak_external_label_baselines as historical

PROTOCOL = ROOT / "data/phase5ax-original-cwe-integrity-protocol.json"
LOCK = "ce36b460698683c912d881a0e5d6e43e653de845"
DASH = r"[-‐‑‒–—−]"
PAIR = re.compile(r"\(CWE\s*" + DASH + r"\s*([1-9][0-9]{0,5})\s*(?::\s*|\s+)([^()\r\n]{1,180})\)", re.I)
LIMIT = 32_000_000


def norm(s):
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def registry(raw, spec):
    require(len(raw) <= LIMIT, "oversized registry ZIP")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        files = [i for i in z.infolist() if not i.is_dir()]
        require(len(files) == 1 and files[0].filename.endswith(".xml")
                and 0 < files[0].file_size <= LIMIT, "unexpected registry ZIP shape")
        xml = z.read(files[0])
    require(b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(),
            "unexpected XML DTD/entity")
    root = ET.fromstring(xml)
    require(root.tag.rsplit("}", 1)[-1] == "Weakness_Catalog"
            and root.attrib.get("Version") == spec["version"], "registry version mismatch")
    names = {}
    aliases = {}
    all_ids = set()
    for item in root.iter():
        kind = item.tag.rsplit("}", 1)[-1]
        if kind not in {"Weakness", "Category", "View"}:
            continue
        key, name = item.attrib.get("ID"), item.attrib.get("Name")
        require(isinstance(key, str) and key.isascii() and key.isdecimal()
                and isinstance(name, str) and name.strip(), "bad registry entry")
        require(key not in all_ids, "duplicate registry ID")
        all_ids.add(key)
        if kind == "Weakness":
            names[key] = name
            aliases.setdefault(norm(name), set()).add(key)
    require(len(names) >= 800, "incomplete weakness catalog")
    require(all(names.get(k) == v for k, v in spec["known_names"].items()),
            "known canonical registry names changed")
    return names, aliases, all_ids


def classify(key, title, names, aliases, all_ids):
    matches = aliases.get(norm(title), set())
    if key not in all_ids:
        return "UNKNOWN_ID"
    if key in names and norm(names[key]) == norm(title):
        return "CANONICAL_TITLE_MATCH"
    if len(matches) == 1 and key not in matches:
        return "OTHER_WEAKNESS_TITLE"
    return "UNRESOLVED_TITLE"


def audit():
    raw = PROTOCOL.read_bytes()
    require(git_blob(raw) == LOCK, "comparison protocol changed")
    spec = parse(raw)
    old_raw = (ROOT / spec["ledger_protocol"]).read_bytes()
    require(git_blob(old_raw) == spec["ledger_protocol_git_blob"], "historical protocol changed")
    old = parse(old_raw)
    source = historical.load(old)
    metrics, original = historical.replay(source["ledger"], parse(source["manifest"]),
                                           parse(source["receipt_archive"]))
    require(metrics == old["expected"], "original corpus changed")
    request = Request(spec["registry"]["url"], headers={"User-Agent": "FALSUM-public-evaluation/1.0"})
    with urlopen(request, timeout=45) as response:
        zipped = response.read(LIMIT + 1)
    names, aliases, all_ids = registry(zipped, spec["registry"])
    latest = {}
    for line in source["ledger"].splitlines():
        if line.strip():
            row = parse(line)
            if row["kind"] == "decision":
                latest[row["input"]["name"]] = row
    require(set(latest) == {x["case"] for x in original}, "case census mismatch")
    cases = []
    counts = Counter()
    for label in original:
        row = latest[label["case"]]
        answers = [x["result"] for x in row["evidence"]
                   if x["intent"] == spec["intent"] and x["ok"] is True]
        require(len(answers) <= 1, "ambiguous recorded answer")
        entries = []
        if answers:
            counts["recorded_answers"] += 1
            summary = answers[0].get("summary")
            if isinstance(summary, str):
                for m in PAIR.finditer(summary):
                    key, title = m.groups()
                    decision = classify(key, title, names, aliases, all_ids)
                    baseline = "KNOWN_ID" if key in all_ids else "UNKNOWN_ID"
                    counts[decision] += 1
                    counts["explicit_pairs"] += 1
                    counts["known_id_baseline"] += int(baseline == "KNOWN_ID")
                    entries.append({"claimed_id": key, "title": title, "id_baseline": baseline,
                                    "title_diagnostic": decision,
                                    "canonical_title": names.get(key),
                                    "registry_title_ids": sorted(aliases.get(norm(title), set()))})
            counts["answers_with_explicit_pairs"] += bool(entries)
            counts["answers_with_title_conflict"] += any(e["title_diagnostic"] ==
                                                          "OTHER_WEAKNESS_TITLE" for e in entries)
        else:
            counts["missing_answers"] += 1
        cases.append({"case": label["case"], "availability": label["availability"],
                      "pairs": entries, "security_clearance": False})
    require(len(cases) == 129 and counts["recorded_answers"] == 103
            and counts["missing_answers"] == 26, "incomplete historical census")
    return {"intent": spec["intent"], "protocol_blob": LOCK,
            "registry": {"version": spec["registry"]["version"],
                         "archive_sha256": hashlib.sha256(zipped).hexdigest(),
                         "weakness_count": len(names), "source_url": spec["registry"]["url"]},
            "summary": dict(counts), "cases": cases, "semantic_accuracy": False,
            "network_ranking_improvement": False, "independent_adoption": False,
            "security_clearance": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    report = audit()
    with a.out.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write("\n")
    print(json.dumps({"summary": report["summary"], "registry": report["registry"]}, sort_keys=True))


if __name__ == "__main__":
    main()
