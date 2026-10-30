"""Research-only pinned-GHSA version-boundary benchmark builder.

Curates *hypothetical* dependency lockfiles from independently published GHSA
range metadata. GitHub-reviewed advisories are not human review of our pairs.
Never use this output for training or Telegraph submission without an actual
independent review and held-out security-domain evaluation.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .osv import SourceError, parse_osv, version_status
from .preflight import diagnostic_metrics

PIN = "4af30eafd57e3bd9a0b4865dee2ced6f611de33f"
ROOT = "https://raw.githubusercontent.com/github/advisory-database/"
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)
STABLE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SPLITS = {"train", "validation", "holdout"}
MAX_BYTES = 300_000


class CorpusError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CorpusError("pinned-source redirect refused")


def path_for_advisory(ghsa: str, month: str) -> str:
    if not GHSA.fullmatch(ghsa) or not re.fullmatch(r"20\d\d/(?:0[1-9]|1[0-2])", month):
        raise CorpusError("unsupported advisory id or year/month")
    return f"advisories/github-reviewed/{month}/{ghsa}/{ghsa}.json"


def validate_queue(queue: object) -> list[str]:
    if not isinstance(queue, dict) or queue.get("schema_version") != 1:
        return ["queue must be schema_version=1 object"]
    records = queue.get("advisories")
    if not isinstance(records, list) or not records:
        return ["advisories must be a nonempty array"]
    errors, seen, packages = [], set(), defaultdict(set)
    for i, row in enumerate(records):
        tag = f"advisories[{i}]"
        if not isinstance(row, dict):
            errors.append(f"{tag}: expected object")
            continue
        ghsa, package, eco, split = (row.get(k) for k in ("id", "package", "ecosystem", "split"))
        if not isinstance(ghsa, str) or not GHSA.fullmatch(ghsa):
            errors.append(f"{tag}: invalid GHSA id")
            continue
        if ghsa.casefold() in seen:
            errors.append(f"{tag}: duplicate GHSA id")
        seen.add(ghsa.casefold())
        if eco not in ("npm", "PyPI") or not isinstance(package, str) or not package.strip():
            errors.append(f"{tag}: unsupported package/ecosystem")
        if split not in SPLITS:
            errors.append(f"{tag}: invalid split")
        if isinstance(package, str) and eco in ("npm", "PyPI") and split in SPLITS:
            packages[(eco.lower(), package.casefold())].add(split)
        try:
            path_for_advisory(ghsa, row.get("month"))
        except CorpusError as exc:
            errors.append(f"{tag}: {exc}")
    for key, splits in packages.items():
        if len(splits) > 1:
            errors.append(f"package leakage: {key} across {sorted(splits)}")
    counts = Counter(row.get("split") for row in records if isinstance(row, dict))
    if counts["train"] < 26:
        errors.append("need at least 26 independent training advisory families for 52 counterbalanced pairs")
    if counts["validation"] < 2 or counts["holdout"] < 2:
        errors.append("validation and holdout each need at least 2 advisory families")
    return errors


def _before_fixed(fixed: str) -> str:
    """Select a synthetic earlier version; the source range is authoritative.

    A synthetic version is NOT a claim that it actually exists in a registry.
    """
    m = STABLE.fullmatch(fixed)
    if not m:
        raise CorpusError(f"unsupported fixed boundary {fixed!r}")
    major, minor, patch = map(int, m.groups())
    if patch > 0:
        return f"{major}.{minor}.{patch-1}"
    if minor > 0:
        return f"{major}.{minor-1}.0"
    if major > 0:
        return f"{major-1}.0.0"
    raise CorpusError("cannot select predecessor of 0.0.0")


def boundary_versions(record: dict, ecosystem: str, package: str) -> tuple[str, str]:
    """Choose conservative covered version boundaries from a single OSV range."""
    for entry in record.get("affected", []):
        pkg = entry.get("package", {}) if isinstance(entry, dict) else {}
        if not isinstance(pkg, dict) or pkg.get("ecosystem", "").casefold() != ecosystem.casefold() or pkg.get("name", "").casefold() != package.casefold():
            continue
        for block in entry.get("ranges", []):
            if not isinstance(block, dict) or block.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = block.get("events", [])
            if not isinstance(events, list):
                continue
            fixes = [event.get("fixed") for event in events if isinstance(event, dict) and "fixed" in event]
            for fixed in fixes:
                if not isinstance(fixed, str) or not STABLE.fullmatch(fixed):
                    continue
                # The original record, not our assumed predecessor, decides status.
                candidates = [_before_fixed(fixed)]
                introductions = [event.get("introduced") for event in events if isinstance(event, dict) and "introduced" in event]
                candidates += [v for v in introductions if isinstance(v, str) and STABLE.fullmatch(v)]
                for affected in candidates:
                    if (version_status(record, ecosystem, package, affected) == "affected" and
                            version_status(record, ecosystem, package, fixed) == "unaffected"):
                        return affected, fixed
    raise CorpusError(f"no supported affected/fixed stable boundaries for {package}")


def pinned_url(row: dict, commit: str = PIN) -> str:
    return f"{ROOT}{commit}/{path_for_advisory(row['id'], row['month'])}"


def fetch_pinned(row: dict, *, opener=None, commit: str = PIN) -> tuple[dict, bytes]:
    """HTTPS allowlisted by construction; no arbitrary URL or redirects."""
    url = pinned_url(row, commit)
    client = opener or build_opener(_NoRedirect())
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "falsum-research/0.3"})
    try:
        with client.open(request, timeout=20) as response:
            if response.geturl() != url:
                raise CorpusError("source URL changed")
            raw = response.read(MAX_BYTES + 1)
    except (OSError, TimeoutError) as exc:
        raise CorpusError(f"unable to acquire {row['id']}: {exc}") from exc
    if len(raw) > MAX_BYTES:
        raise CorpusError("oversized advisory source")
    try:
        doc = parse_osv(raw, row["id"])
    except SourceError as exc:
        raise CorpusError(f"invalid pinned advisory: {exc}") from exc
    if doc.get("id", "").casefold() != row["id"].casefold():
        raise CorpusError("advisory id mismatch")
    boundary_versions(doc, row["ecosystem"], row["package"])
    return doc, raw


def _answer(ghsa: str, package: str, version: str, status: str, template: int) -> str:
    """Counterbalanced evidence claims: no answer-only style or length signal.

    Every advisory produces one affected and one patched example. In the
    matched chosen/rejected answers, only the equal-length semantic predicate
    changes; the same predicates occur on both sides of the full corpus.
    """
    predicate = "inside" if status == "affected" else "beyond"
    if template % 2 == 0:
        return (f"The version {package}@{version} lies {predicate} the affected range "
                f"published in {ghsa}. This assesses dependency range status, "
                "not whether the installed deployment is exploitable.")
    return (f"For advisory {ghsa}, the dependency {package} version {version} "
            f"falls {predicate} the affected range. Report the source-bound "
            "version determination without inventing exploit conditions.")


def _pair(row: dict, doc: dict, version: str, status: str, template: int) -> dict:
    good = _answer(row['id'], row['package'], version, status, template)
    bad = _answer(row['id'], row['package'], version, 'unaffected' if status == 'affected' else 'affected', template)
    summary = str(doc.get('summary', '')).strip().replace('\n', ' ')[:155]
    if template % 2 == 0:
        prompt = (f"A hypothetical lockfile lists {row['package']}=={version} ({row['ecosystem']}). "
                  f"Check the exact version boundary in {row['id']} about '{summary}'. "
                  "Is this version covered by this advisory? Do not infer actual exploitability.")
    else:
        prompt = (f"Security triage exercise: the deployment declares {row['ecosystem']} dependency "
                  f"{row['package']} at {version}. The relevant advisory is {row['id']} "
                  f"('{summary}'). Decide range applicability only; distinguish it from a demonstrated exploit.")
    return {'id':f"{row['id'].lower()}-{status}", 'intent_id':'SECURITY_REVIEW_GENERAL',
            'split':row['split'], 'review_status':'draft', 'advisory_id':row['id'],
            'source_url':pinned_url(row), 'package':row['package'], 'ecosystem':row['ecosystem'],
            'version':version, 'expected_status':status, 'prompt':prompt, 'chosen':good, 'rejected':bad}


def build_corpus(queue: dict, documents: dict[str, tuple[dict, bytes]]) -> dict:
    errs = validate_queue(queue)
    if errs:
        raise CorpusError('; '.join(errs))
    cases, sources = [], []
    for row in queue['advisories']:
        if row['id'] not in documents:
            raise CorpusError(f"missing pinned advisory {row['id']}")
        doc, raw = documents[row['id']]
        parse_osv(raw, row['id'])
        if json.loads(raw) != doc:
            raise CorpusError('document bytes/parsed metadata disagree')
        affected, fixed = boundary_versions(doc, row['ecosystem'], row['package'])
        for i, (v, state) in enumerate(((affected,'affected'),(fixed,'unaffected'))):
            cases.append(_pair(row, doc, v, state, i))
        sources.append({'id':row['id'], 'url':pinned_url(row), 'sha256':hashlib.sha256(raw).hexdigest(),
                        'snapshot':f"snapshots/{row['id']}.json",'package':row['package'],
                        'ecosystem':row['ecosystem'],'split':row['split'], 'status':'pinned-unreviewed'})
    return {'schema_version':1, 'status':'DRAFT_ONLY_NOT_REVIEWED', 'upstream_commit':PIN,
            'sources':sources,'cases':cases}


def validate_corpus(corpus: dict, directory: str | Path) -> list[str]:
    problems = []
    if corpus.get('status') != 'DRAFT_ONLY_NOT_REVIEWED':
        problems.append('unrecognized draft status')
    root = Path(directory).resolve()
    cases = corpus.get('cases', [])
    seen, groups, packages = set(), defaultdict(set), defaultdict(set)
    for row in cases:
        if row['id'] in seen:
            problems.append('repeated case id')
        seen.add(row['id'])
        if row['review_status'] != 'draft':
            problems.append('non-draft material is not permitted in this pipeline')
        groups[row['advisory_id']].add(row['split'])
        packages[(row['ecosystem'].lower(),row['package'].casefold())].add(row['split'])
        if not 0.68 <= len(row['chosen'].split()) / max(1,len(row['rejected'].split())) <= 1.50:
            problems.append(f"unbalanced answer length: {row['id']}")
    for key, splits in list(groups.items()) + list(packages.items()):
        if len(splits) > 1:
            problems.append(f"train/holdout leakage: {key}")
    for src in corpus.get('sources', []):
        target = (root / src['snapshot']).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            problems.append(f"missing or escaping snapshot: {src['id']}")
            continue
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != src['sha256']:
            problems.append(f"source tampering: {src['id']}")
            continue
        try:
            doc = parse_osv(raw,src['id'])
            for row in (x for x in cases if x['advisory_id']==src['id']):
                actual = version_status(doc,row['ecosystem'],row['package'],row['version'])
                if actual != row['expected_status']:
                    problems.append(f"false label for {row['id']}: {actual}")
        except SourceError as exc:
            problems.append(f"source invalid {src['id']}: {exc}")
    return problems


def save_diagnostics(queue: dict, directory: str | Path, *, opener=None) -> dict:
    """Downloads pinned source records and writes research-only artifacts."""
    issues=validate_queue(queue)
    if issues:
        raise CorpusError('; '.join(issues))
    directory=Path(directory)
    documents={}
    for row in queue['advisories']:
        documents[row['id']] = fetch_pinned(row,opener=opener)
    corpus=build_corpus(queue,documents)
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'snapshots').mkdir(exist_ok=True)
    for src in corpus['sources']:
        (directory/src['snapshot']).write_bytes(documents[src['id']][1])
    issues=validate_corpus(corpus,directory)
    if issues:
        raise CorpusError('integrity audit failed: '+ '; '.join(issues))
    (directory/'DRAFT-ONLY-corpus.json').write_text(json.dumps(corpus,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    splits=Counter(row['split'] for row in corpus['cases'])
    for split in SPLITS:
        rows=[{k:case[k] for k in ('prompt','chosen','rejected')} for case in corpus['cases'] if case['split']==split]
        (directory/f'DRAFT-ONLY-{split}.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows),encoding='utf-8')
    metrics=diagnostic_metrics([{k:c[k] for k in ('prompt','chosen','rejected')} for c in corpus['cases'] if c['split']=='train'])
    metrics.update({'advisories':len(documents),'cases':len(corpus['cases']),'by_split':dict(splits),
                    'independent_human_reviews':0,'telegraph_eligible':False,'trainable':False,
                    'artifact_status':'QUARANTINED_RESEARCH_ONLY'})
    (directory/'STATUS-RESEARCH-ONLY.json').write_text(json.dumps(metrics,indent=2)+'\n')
    return metrics


def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('queue',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args(argv)
    data=json.loads(args.queue.read_text(encoding='utf-8'))
    report=save_diagnostics(data,args.out)
    print(json.dumps(report,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
