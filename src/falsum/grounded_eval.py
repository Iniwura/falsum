"""Draft-only evidence-present vs evidence-absent evaluator diagnostics.

The existing benchmark names a GHSA but omits the version range needed to
reason about it. Here the published event range is in the TASK, where the
Telegraph V2 reward model actually sees it. No claim of model performance,
human review, or Telegraph acceptance is made.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .advisory_corpus import STABLE
from .osv import parse_osv, version_status
from .review_gate import audit_reproducibility


class GroundingError(ValueError):
    """Unverifiable or ambiguous evidence must not become a training label."""


def _range_evidence(record: dict, ecosystem: str, package: str, version: str) -> str:
    """Render all stable, contiguous published ranges without discarding branches.

    Complex or non-stable events fail rather than inventing a version boundary.
    """
    matching = []
    for affected in record.get('affected', []):
        pkg = affected.get('package', {}) if isinstance(affected, dict) else {}
        if not isinstance(pkg, dict):
            raise GroundingError('invalid OSV package record')
        if (pkg.get('name', '').casefold(), pkg.get('ecosystem', '').casefold()) != (package.casefold(), ecosystem.casefold()):
            continue
        if affected.get('versions'):
            raise GroundingError('explicit version enumerations cannot be reduced to one interval')
        matching.extend(affected.get('ranges', []))
    if not matching or len(matching) > 8:
        raise GroundingError(f'unsupported number of published ranges: {len(matching)}')
    rendered=[]
    for block in matching:
        if not isinstance(block, dict) or block.get('type') not in ('SEMVER', 'ECOSYSTEM'):
            raise GroundingError('unsupported OSV range family')
        events = block.get('events')
        if not (isinstance(events, list) and len(events) == 2
                and isinstance(events[0], dict) and set(events[0]) == {'introduced'}
                and isinstance(events[1], dict) and set(events[1]) == {'fixed'}):
            raise GroundingError('ambiguous or noncontiguous OSV range')
        introduced, fixed = events[0]['introduced'], events[1]['fixed']
        if not (isinstance(introduced, str) and (introduced == '0' or STABLE.fullmatch(introduced))
                and isinstance(fixed, str) and STABLE.fullmatch(fixed)
                and isinstance(version, str) and STABLE.fullmatch(version)):
            raise GroundingError('unstable or unsupported version syntax')
        rendered.append(f'Range type: {block["type"]}; introduced (inclusive): {introduced}; fixed (exclusive): {fixed}.')
    if version_status(record, ecosystem, package, version) == 'unknown':
        raise GroundingError('unknown version status')
    # Literal OSV event facts, NOT an assertion of exploitability.
    return ' '.join(rendered)


def build_grounded(queue: dict, corpus: dict, source_directory: str | Path) -> dict:
    """Produce an auditable research benchmark, never an eligible dataset."""
    audit_reproducibility(queue, corpus, source_directory)
    root = Path(source_directory).resolve()
    sources = {s['id']: s for s in corpus['sources']}
    grounded, missing = [], []
    # Read and validate actual archived bytes; do not trust user-supplied labels.
    for case in corpus['cases']:
        source = sources[case['advisory_id']]
        path = (root / source['snapshot']).resolve()
        if not path.is_relative_to(root):
            raise GroundingError('snapshot escapes source directory')
        record = parse_osv(path.read_bytes(), case['advisory_id'])
        evidence = _range_evidence(record, case['ecosystem'], case['package'], case['version'])
        status = version_status(record, case['ecosystem'], case['package'], case['version'])
        if status != case['expected_status']:
            raise GroundingError(f'published boundary disagrees with {case["id"]}')
        summary = ' '.join(str(record.get('summary', '')).split())[:160]
        task = (f'You are reviewing a dependency finding. This archived advisory record was '
                f'archived at {source["url"]}.\n'
                f'Advisory: {case["advisory_id"]}; package: {case["ecosystem"]}/{case["package"]}; '
                f'installed version: {case["version"]}.\n'
                f'Published affected-version events: {evidence}\n'
                f'Advisory topic: {summary}.\n'
                'Decide only whether the installed version falls in the published range. '
                'Do not assert that the deployed system is exploitable.')
        grounded.append({**case, 'prompt':task, 'evidence_availability':'present',
                         'review_status':'draft', 'source_sha256':source['sha256']})
        # Source-blind control: same advisory but *no* affected-range evidence.
        # The correct choice is to request evidence, not guess based on GHSA ID.
        if case['expected_status'] == 'affected':
            ambiguous = (f'A hypothetical lockfile names {case["ecosystem"]}/{case["package"]} '
                         f'version {case["version"]} and mentions {case["advisory_id"]}, '
                         'but provides no advisory body, range events, or reference excerpt. '
                         'Is the deployed dependency proven affected by this evidence alone?')
            no_evidence = (f'The provided prompt does not include the affected-version bounds for '
                           f'{case["advisory_id"]}. This version cannot be classified from these '
                           'facts alone; obtain the advisory before asserting a finding.')
            hallucinated = (f'The provided prompt does not include the affected-version bounds for '
                            f'{case["advisory_id"]}. This version is confirmed affected from these '
                            'facts alone; report the finding without the advisory.')
            missing.append({'id': case['id'] + '-missing-evidence', 'split':case['split'],
                            'prompt':ambiguous, 'chosen':no_evidence, 'rejected':hallucinated,
                            'review_status':'draft', 'advisory_id':case['advisory_id'],
                            'evidence_availability':'absent'})
    if len(grounded) != len(corpus['cases']):
        raise GroundingError('not all source cases reconstructed')
    return {'schema_version':1,'status':'QUARANTINED_DRAFT_ONLY','grounded':grounded,
            'insufficient_evidence':missing, 'independent_human_reviews':0,
            'telegraph_eligible':False, 'trained_model':False}


def diagnostic_report(benchmark: dict) -> dict:
    grounded=benchmark['grounded']
    controls=benchmark['insufficient_evidence']
    by_split=Counter(x['split'] for x in grounded)
    return {'status':'RESEARCH_ONLY_NOT_ELIGIBLE','grounded_pairs':len(grounded),
            'missing_evidence_controls':len(controls),'grounded_by_split':dict(sorted(by_split.items())),
            'unique_advisories':len({x['advisory_id'] for x in grounded}),
            'human_reviews':0,'model_evaluated':False,'network_accepted':False}


def evaluate_scores(rows: list[dict], scores: dict[str, tuple[float,float]]) -> dict:
    """Metrics for future model scores (chosen, rejected), with ties as 1/2.

    Refuse missing or non-finite scores. Never claim accuracy for absent scores.
    Score pair IDs must match exactly, so no silently dropped difficult cases.
    """
    import math
    required={x['id'] for x in rows}
    if not required or len(required)!=len(rows) or set(scores)!=required:
        raise GroundingError('scores must cover every unique benchmark case exactly')
    totals={}
    for part in sorted({x['split'] for x in rows}):
        subset=[x for x in rows if x['split']==part]
        outcomes=[]
        for row in subset:
            a,b=scores[row['id']]
            if not isinstance(a,(int,float)) or not isinstance(b,(int,float)) or not (math.isfinite(a) and math.isfinite(b)):
                raise GroundingError('scores must be finite numbers')
            outcomes.append(1.0 if a>b else 0.5 if a==b else 0.0)
        totals[part]={'n':len(subset),'pairwise_accuracy':round(sum(outcomes)/len(outcomes),6)}
    return {'by_split':totals,'overall':{'n':len(rows),
            'pairwise_accuracy':round(sum(x['pairwise_accuracy']*x['n'] for x in totals.values())/len(rows),6)}}


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description='Build source-grounded DRAFT benchmark, not eligible data')
    p.add_argument('queue',type=Path)
    p.add_argument('corpus',type=Path)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args(argv)
    queue=json.loads(args.queue.read_text(encoding='utf-8'))
    corpus=json.loads(args.corpus.read_text(encoding='utf-8'))
    benchmark=build_grounded(queue,corpus,args.corpus.parent)
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'DRAFT-grounded-benchmark.json').write_text(json.dumps(benchmark,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    for split in ('train','validation','holdout'):
        rows=[{k:x[k] for k in ('prompt','chosen','rejected')} for x in benchmark['grounded'] if x['split']==split]
        (args.out/f'DRAFT-grounded-{split}.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows),encoding='utf-8')
    (args.out/'RESEARCH-ONLY-report.json').write_text(json.dumps(diagnostic_report(benchmark),indent=2)+'\n',encoding='utf-8')
    print(json.dumps(diagnostic_report(benchmark),indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
